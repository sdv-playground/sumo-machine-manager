//! The factory-reset engine: the `POST {base}/operations/factory-reset/executions`
//! handler a node mounts in [`sovd_router`](crate::sovd_router)'s factory-reset
//! slot (build it with [`route`]).
//!
//! Wipes all device-mutable state (NV store, HSM keystore, vm/hsm bank
//! dirs, log dir contents) so the next boot serves a fresh CSR and the
//! device is ready for re-provisioning. The resident machine manager
//! (`mmgr/`) is preserved.
//!
//! The sequence is fixed here: precheck, authorize (a HighConsequence
//! `FactoryReset` token), clear in-flight flash sessions, resolve the targets,
//! the device's before-wipe work, stop the guests, the synchronous wipe (in the
//! order of [`execute_wipe`], the log dir last), then schedule the shutdown and
//! answer `{ok, wiped, errors}` (200, or 500 if anything failed). The node
//! supplies its device through [`ResetHooks`]: the targets from its config
//! (the wipe-root is its policy), its before-wipe work and whether the node
//! must reboot, how its guests stop, and how it shuts down.

use std::path::{Component as PathComponent, Path, PathBuf};
use std::sync::Arc;

use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use component_factory::ComponentSpec;
use serde::Serialize;
use sovd_api::{AccessRequest, Authorizer, Capability};

// ---------------------------------------------------------------------------
// Wipe target resolution
// ---------------------------------------------------------------------------

/// Concrete set of paths to wipe, derived from the node's config by its
/// [`ResetHooks::resolve`] (the component dirs with [`component_dirs`]).
///
/// Each target is resolved at handler-invocation time so config changes
/// between provisioning and reset are honoured.
#[derive(Debug, Clone)]
pub struct WipeTargets {
    /// The wipe-root the node chose (e.g. `/mnt/common-rw`). Every other
    /// target must live under this.
    pub root: PathBuf,
    /// `mmgr/nv-store.bin` — single file.
    pub nv_store: PathBuf,
    /// `mmgr/images/` — wipe contents only.
    pub images_dir: Option<PathBuf>,
    /// HSM keystore (`vhsm/keys/`) — wipe contents only. Wiping the
    /// device identity key here is intentional: a fresh CSR is generated
    /// on next boot.
    pub hsm_keystore: PathBuf,
    /// VM component directories (e.g. `vm1/`, `vm2/`) — for each, wipe
    /// `bank_a/*`, `bank_b/*`, the `current` symlink, and the set's staging
    /// state (`staging-<bank>.cbor`, `staging/`).
    pub vm_dirs: Vec<PathBuf>,
    /// HSM-component bank state dir (`hsm/`) — wipe `bank_a/*`, `bank_b/*`,
    /// and the set's staging state.
    pub hsm_state_dir: Option<PathBuf>,
    /// Log dir — wipe contents only. None ⇒ skip.
    pub log_dir: Option<PathBuf>,
    /// Node-level boot-selector dir (file backend) — wipe its slots so the
    /// next boot's seed regenerates them clean (gen 1) from the reset
    /// NvBootState. `None` for non-file backends: a future raw-partition
    /// writer zeros its own sectors, which a path wipe can't reach.
    pub boot_selector_dir: Option<PathBuf>,
    /// Guest RW eMMC partitions (raw block-device paths, e.g.
    /// `/dev/emmc0.qnx6.guest1-rw`) — the guests' OWN persistent storage
    /// (vm1 /var+/opt, vm2 /persist container store). These are handed raw to
    /// the guests, so they live OUTSIDE the wipe-root and CANNOT be path-wiped;
    /// they are cleared by zeroing each device's leading region (superblock),
    /// which drops the filesystem so the guest self-reformats on next boot
    /// (guest IFS does `chkqnx6fs || mkqnx6fs`; autosd does `x-systemd.makefs`).
    /// Without this, a factory reset left ALL guest-internal state intact — the
    /// gap this closes. Device data the node supplies; empty ⇒ skip.
    pub guest_rw_partitions: Vec<String>,
    /// Every declared part device of every component, both banks, from the
    /// profile (`parts:`); raw block-device
    /// paths, e.g. `/dev/emmc4.lnxdata.host-appl`. A factory reset must DROP THE
    /// DEVICE TO THE TIER-1 RECOVERY FLOOR: it wipes VM/hsm banks + the selector,
    /// but the bootable Tier-2 host image lives on this raw partition — if it
    /// survives, host-boot.sh re-mounts it and the device reboots straight back
    /// into Tier-2 (now advertising vm1/vm2 with empty banks). Zeroing a host-appl
    /// partition head makes host-boot's mount of THAT bank fail → it falls back to
    /// the resident Tier-1 MM (mmgr/bank_a). Same mechanism as prepare-device.sh's
    /// SOVD-down break-glass wipe. Best-effort per device: the RUNNING bank's
    /// device is loopback-mounted by the running node manager and refuses the write with
    /// EBUSY (benign — see the step-7b note for the residual and why we don't tear
    /// the loopback down from inside the running process), so only the inactive
    /// SIBLING zeroes here. Empty when no component declares parts (an
    /// emulated/container device has no raw bank).
    pub host_bank_partitions: Vec<String>,
}

/// The component dirs a reset wipes, from the running config's components and
/// the provisioned-banks manifest + fallback scan under `root`: the VM / bank
/// dirs (`bank` and `hpc` components, then the extra ones, deduped) and the
/// HSM-component bank state dir. `app` components' install dirs are preserved.
pub fn component_dirs(
    root: &Path,
    nv_store: &Path,
    components: &[ComponentSpec],
) -> (Vec<PathBuf>, Option<PathBuf>) {
    let mut vm_dirs = Vec::new();
    let mut hsm_state_dir = None;
    for comp in components {
        let Some(storage_path) = &comp.storage_path else {
            continue;
        };
        let subdir = comp.storage_subdir.as_deref().unwrap_or(comp.id.as_str());
        match comp.component_type.as_str() {
            "bank" | "hpc" => vm_dirs.push(storage_path.join(subdir)),
            "hsm" => hsm_state_dir = Some(storage_path.join(subdir)),
            _ => {} // app — install dir is preserved
        }
    }

    // The running config only knows ITS OWN components. A factory reset from
    // the Tier-1 recovery MM (config.provisioning.yaml = host/hsm/rt) would
    // therefore leave vm1/vm2 — provisioned by Tier-2 — untouched. Two extra
    // sources give the recovery tier the full picture:
    //   (a) the provisioned-banks MANIFEST (mmgr/provisioned-banks) that Tier-2
    //       writes on startup, listing the component subdirs IT provisioned;
    //   (b) a FALLBACK SCAN of <root>/*/bank_{a,b} for a stale/missing manifest.
    // Both are merged into vm_dirs (deduped). BOTH EXCLUDE `mmgr` — that dir is
    // the RESIDENT MM (the recovery floor) and MUST survive the reset; a scan
    // that wiped it would delete the thing performing the reset. Every entry is
    // still gated by ensure_under_root at wipe time.
    for extra in manifest_and_scanned_component_dirs(root, nv_store) {
        if !vm_dirs.contains(&extra) {
            vm_dirs.push(extra);
        }
    }
    (vm_dirs, hsm_state_dir)
}

/// Name of the provisioned-banks manifest, under `mmgr/`. Tier-2 (the full MM)
/// writes it on startup (see `write_provisioned_banks`); factory_reset reads it so
/// a reset from the Tier-1 recovery MM still knows which component banks Tier-2
/// provisioned. Newline-separated `<root>`-relative dirs (e.g. `vm1`, `vm2`, `os`).
pub const PROVISIONED_BANKS_FILE: &str = "provisioned-banks";

/// The resident-MM dir name under the wipe-root. NEVER a wipe target — it holds
/// the Tier-1 recovery floor (`mmgr/bank_a`, the bootloader `start.sh`, the boot
/// selector, nv-store) that must survive a factory reset. The manifest and the
/// fallback scan both skip it.
const RESIDENT_MM_DIR: &str = "mmgr";

/// Component bank dirs to wipe BEYOND the running config's own components, from
/// two sources, so a Tier-1 reset also clears Tier-2-provisioned banks (vm1/vm2):
///   1. the provisioned-banks manifest (`mmgr/PROVISIONED_BANKS_FILE`), and
///   2. a fallback scan of `<root>/*/bank_{a,b}` (for a stale/missing manifest).
///
/// Returns absolute dirs under `root`. EXCLUDES `mmgr` (the resident MM — see
/// `RESIDENT_MM_DIR`). Best-effort: unreadable manifest / unscannable root yield
/// what they can; `ensure_under_root` re-checks each at wipe time.
fn manifest_and_scanned_component_dirs(root: &Path, nv_store: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut push_unique = |p: PathBuf| {
        if !out.contains(&p) {
            out.push(p);
        }
    };

    // (1) manifest — mmgr/<PROVISIONED_BANKS_FILE>. mmgr = nv_store's parent.
    if let Some(mmgr) = nv_store.parent() {
        let manifest = mmgr.join(PROVISIONED_BANKS_FILE);
        if let Ok(content) = std::fs::read_to_string(&manifest) {
            for line in content.lines() {
                let entry = line.trim();
                // Skip blanks/comments and anything that isn't a single relative
                // dir component (defence: no absolute paths, no `..`, no `mmgr`).
                if entry.is_empty() || entry.starts_with('#') {
                    continue;
                }
                let rel = Path::new(entry);
                let single = rel.components().count() == 1
                    && rel
                        .components()
                        .all(|c| matches!(c, PathComponent::Normal(_)));
                if !single || entry == RESIDENT_MM_DIR {
                    continue;
                }
                push_unique(root.join(entry));
            }
        }
    }

    // (2) fallback scan — any <root>/<dir>/bank_{a,b}, dir != mmgr. Catches banks
    // a stale/missing manifest omits. Only dirs that actually contain a bank_*
    // subdir are treated as component dirs (skips log/, etc.).
    if let Ok(entries) = std::fs::read_dir(root) {
        for e in entries.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name == RESIDENT_MM_DIR {
                continue; // NEVER wipe the resident MM
            }
            let dir = e.path();
            if !dir.is_dir() {
                continue;
            }
            if dir.join("bank_a").is_dir() || dir.join("bank_b").is_dir() {
                push_unique(dir);
            }
        }
    }

    out
}

/// Write the provisioned-banks manifest (`mmgr/PROVISIONED_BANKS_FILE`) listing
/// the component subdirs THIS config provisions — one `<root>`-relative dir per
/// line. Called at startup by the full (Tier-2) MM so a later factory reset from
/// the Tier-1 recovery MM knows to clear vm1/vm2 (which the Tier-1 config doesn't
/// list). Best-effort: a write failure is logged, never fatal. `mmgr` is never
/// listed (it's the resident MM, preserved by reset).
pub fn write_provisioned_banks(nv_store: &Path, components: &[ComponentSpec]) {
    let Some(mmgr) = nv_store.parent() else {
        tracing::warn!("provisioned-banks: cannot derive mmgr dir from nv_store; skipping");
        return;
    };
    let mut dirs: Vec<String> = Vec::new();
    for comp in components {
        if comp.storage_path.is_none() {
            continue;
        }
        let subdir = comp
            .storage_subdir
            .clone()
            .unwrap_or_else(|| comp.id.clone());
        // A single relative component, never the resident MM.
        if subdir.contains('/') || subdir == RESIDENT_MM_DIR || subdir.is_empty() {
            continue;
        }
        if !dirs.contains(&subdir) {
            dirs.push(subdir);
        }
    }
    let body = format!(
        "# provisioned component bank dirs (relative to {}), written by the MM at\n\
         # startup so a Tier-1 factory reset knows what to clear. See factory_reset.rs.\n{}\n",
        mmgr.parent()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        dirs.join("\n"),
    );
    let path = mmgr.join(PROVISIONED_BANKS_FILE);
    match std::fs::write(&path, body) {
        Ok(()) => {
            tracing::info!(path = %path.display(), banks = ?dirs, "wrote provisioned-banks manifest")
        }
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "provisioned-banks: write failed (non-fatal)")
        }
    }
}

/// Reject targets that escape the wipe-root, lexically. Catches
/// misconfiguration like `storage_path: /` from wiping the host.
pub fn ensure_under_root(root: &Path, target: &Path) -> Result<(), String> {
    if !target.is_absolute() {
        return Err(format!("target not absolute: {}", target.display()));
    }
    if !target.starts_with(root) {
        return Err(format!(
            "target {} escapes root {}",
            target.display(),
            root.display()
        ));
    }
    if let Ok(rel) = target.strip_prefix(root) {
        for c in rel.components() {
            if matches!(c, PathComponent::ParentDir) {
                return Err(format!(
                    "target {} contains parent-dir traversal",
                    target.display()
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Wipe execution
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct WipeOutcome {
    pub wiped: Vec<PathBuf>,
    pub errors: Vec<String>,
}

pub fn execute_wipe(targets: &WipeTargets) -> WipeOutcome {
    let mut out = WipeOutcome::default();
    let root = &targets.root;

    // 1. nv-store file
    remove_file_under(root, &targets.nv_store, "nv_store", &mut out);

    // 2. images dir contents
    if let Some(d) = &targets.images_dir {
        wipe_dir_contents(root, d, "images_dir", &mut out);
    }

    // 3. HSM keystore contents (incl. device identity key)
    wipe_dir_contents(root, &targets.hsm_keystore, "hsm_keystore", &mut out);

    // 4. VM dirs: each bank_* contents + current symlink + staging state
    for vm_dir in &targets.vm_dirs {
        let cur = vm_dir.join("current");
        // remove_file works for symlinks (does NOT follow); .symlink_metadata
        // catches broken symlinks too.
        if cur.symlink_metadata().is_ok() {
            remove_file_under(
                root,
                &cur,
                &format!("{}/current", vm_dir.display()),
                &mut out,
            );
        }
        for bank in ["bank_a", "bank_b"] {
            let bd = vm_dir.join(bank);
            wipe_dir_contents(root, &bd, &format!("{}/{bank}", vm_dir.display()), &mut out);
        }
        wipe_staging_under(root, vm_dir, &vm_dir.display().to_string(), &mut out);
    }

    // 5. HSM state: bank_a/*, bank_b/*, staging state
    if let Some(hsm_dir) = &targets.hsm_state_dir {
        for bank in ["bank_a", "bank_b"] {
            let bd = hsm_dir.join(bank);
            wipe_dir_contents(
                root,
                &bd,
                &format!("{}/{bank}", hsm_dir.display()),
                &mut out,
            );
        }
        wipe_staging_under(root, hsm_dir, &hsm_dir.display().to_string(), &mut out);
    }

    // 6. Boot-selector slots: wipe so the next boot's seed regenerates them
    //    clean (gen 1) from the reset NvBootState. None for non-file backends.
    if let Some(d) = &targets.boot_selector_dir {
        wipe_dir_contents(root, d, "boot_selector", &mut out);
    }

    // 7. Guest RW partitions: invalidate the filesystem so the guest
    //    self-reformats on next boot. These are raw block devices OUTSIDE the
    //    wipe-root (the guests' own /var //opt //persist), handed to the guests
    //    exclusively — so we can't path-wipe them, and the QNX host can't
    //    mkfs.ext4 vm2's Linux partition anyway. Zeroing the leading region
    //    drops the superblock; each guest reformats in its OWN native way on
    //    next boot (vm1 IFS: chkqnx6fs || mkqnx6fs; vm2 autosd: fstab
    //    x-systemd.makefs). Runs AFTER stop_guests (handle step 6) so qvm
    //    no longer holds them. Best-effort per device.
    for dev in &targets.guest_rw_partitions {
        zero_partition_head(dev, &mut out);
    }

    // 7b. Host-appl (Tier-2 OS) A/B partitions: zero their heads so the node DROPS
    //     TO THE TIER-1 RECOVERY FLOOR on the post-reset reboot. Without this the
    //     bootable Tier-2 image survives on its raw partition, host-boot.sh
    //     re-mounts it, and the device reboots straight back into Tier-2 (now
    //     advertising vm1/vm2 with the empty banks this reset just cleared) instead
    //     of the resident Tier-1 MM. Same mechanism as prepare-device.sh's SOVD-down
    //     break-glass, and paired with the forced REBOOT in step 8 (only a reboot
    //     re-runs host-boot.sh to re-select the tier; an exit-respawn re-execs the
    //     same mounted bank).
    //
    //     SCOPE (deliberate — see tasks): this runs INSIDE the running node manager, which
    //     is itself executing from the CURRENTLY-RUNNING bank's loopback
    //     (/dev/hostbank0 on /tmp/host-app). We therefore do NOT tear that loopback
    //     down here (unmount + slay devb-loopback would pull the fs out from under
    //     the running process — the running-from-loopback deadlock). So the write to
    //     the ACTIVE bank is refused "resource busy" (best-effort, skipped), and only
    //     the INACTIVE SIBLING bank zeroes now. RESIDUAL: if the post-reset host-boot
    //     re-selects the still-intact running bank, it could still mount Tier-2 —
    //     verify on-device. If insufficient, the both-banks teardown belongs in a
    //     reset-specific reboot path (after the node manager commits to dying), NOT here.
    //     `zero_partition_head` skips an absent device (emulated/container: no raw
    //     host bank).
    for dev in &targets.host_bank_partitions {
        zero_partition_head(dev, &mut out);
    }

    // 8. Log dir contents (last — keeps log trail until the moment of wipe)
    if let Some(d) = &targets.log_dir {
        wipe_dir_contents(root, d, "log_dir", &mut out);
    }

    out
}

/// Invalidate a raw partition's filesystem by zeroing its leading region.
///
/// Writes 64 KiB of zeros at offset 0 — enough to clear the ext4 primary
/// superblock (offset 1024) and the qnx6 superblock, so `blkid` / `chkqnx6fs`
/// find no filesystem and the guest reformats. We deliberately do NOT touch the
/// GPT (the partition DEFINITION survives) and do NOT try to mkfs from the host
/// (ext4 vs qnx6 is guest-specific — each guest owns its format). NOT gated by
/// `ensure_under_root`: these are `/dev/*` block devices, intentionally outside
/// the wipe-root. Best-effort — a missing device (layout without it) is skipped,
/// not an error.
fn zero_partition_head(dev: &str, out: &mut WipeOutcome) {
    use std::io::Write;
    let path = Path::new(dev);
    // Guard: only ever write to /dev block-device paths, never a regular file
    // or a wipe-root path — this bypasses ensure_under_root, so be strict.
    if !dev.starts_with("/dev/") {
        out.errors
            .push(format!("zero_partition_head {dev}: refusing non-/dev path"));
        return;
    }
    if path.symlink_metadata().is_err() {
        // Device absent (e.g. interim layout lacks a target-layout partition).
        tracing::info!("factory_reset: partition {dev} absent — skipping");
        return;
    }
    // 64 KiB of zeros: covers ext4 superblock@1024 + qnx6 header with margin.
    const ZERO_LEN: usize = 64 * 1024;
    match std::fs::OpenOptions::new().write(true).open(path) {
        Ok(mut f) => {
            let zeros = vec![0u8; ZERO_LEN];
            match f.write_all(&zeros).and_then(|_| f.flush()) {
                Ok(()) => {
                    let _ = std::process::Command::new("sync").status();
                    tracing::warn!(
                        "factory_reset: zeroed fs head of {dev} (guest reformats on boot)"
                    );
                    out.wiped.push(path.to_path_buf());
                }
                Err(e) => out
                    .errors
                    .push(format!("zero_partition_head {dev}: write zeros: {e}")),
            }
        }
        // EBUSY is EXPECTED + BENIGN for the CURRENTLY-RUNNING host-appl bank: it's
        // loopback-mounted by the running node manager, so it can't be opened for write —
        // and it doesn't need zeroing here (the forced reboot + the sibling-bank
        // zero drop the node to Tier-1; a guest RW partition is released by
        // stop_guests before this runs). Treat it as a best-effort SKIP (log,
        // don't error), same class as "device absent" — otherwise the running bank's
        // expected busy fails the whole factory reset (ok:false / HTTP 500) even
        // though the reset did everything it could.
        Err(e) if e.raw_os_error() == Some(libc::EBUSY) => {
            tracing::info!(
                "factory_reset: partition {dev} busy (mounted/in-use) — skipping head-zero \
                 (expected for the running host-appl bank)"
            );
        }
        Err(e) => out
            .errors
            .push(format!("zero_partition_head {dev}: open: {e}")),
    }
}

fn remove_file_under(root: &Path, path: &Path, label: &str, out: &mut WipeOutcome) {
    if let Err(e) = ensure_under_root(root, path) {
        out.errors.push(format!("{label}: {e}"));
        return;
    }
    if path.symlink_metadata().is_err() {
        return; // doesn't exist — nothing to do
    }
    match std::fs::remove_file(path) {
        Ok(()) => out.wiped.push(path.to_path_buf()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => out
            .errors
            .push(format!("{label}: remove_file({}): {e}", path.display())),
    }
}

/// Forget a file-bank set's staging state (`staging-<bank>.cbor` + their temp
/// files, `staging/`), so a reset device starts no transfer from a resume
/// point. The bank dirs are wiped separately.
fn wipe_staging_under(root: &Path, set_dir: &Path, label: &str, out: &mut WipeOutcome) {
    if let Err(e) = ensure_under_root(root, set_dir) {
        out.errors.push(format!("{label}: {e}"));
        return;
    }
    if let Err(e) = component_mgr::bank_provider::wipe_staging(set_dir) {
        out.errors
            .push(format!("{label}: wipe_staging({}): {e}", set_dir.display()));
    }
}

fn wipe_dir_contents(root: &Path, dir: &Path, label: &str, out: &mut WipeOutcome) {
    if let Err(e) = ensure_under_root(root, dir) {
        out.errors.push(format!("{label}: {e}"));
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            out.errors
                .push(format!("{label}: read_dir({}): {e}", dir.display()));
            return;
        }
    };
    for entry in entries.flatten() {
        let p = entry.path();
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let r = if is_dir {
            std::fs::remove_dir_all(&p)
        } else {
            std::fs::remove_file(&p)
        };
        match r {
            Ok(()) => out.wiped.push(p),
            Err(e) => out
                .errors
                .push(format!("{label}: remove({}): {e}", p.display())),
        }
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownKind {
    /// Clean exit — start-managed.sh's respawn loop brings the node manager
    /// back up with the wiped state. Fast path, ~5 s round-trip.
    Exit,
    /// Full host reboot via `sync && reboot` (QNX) / `shutdown -r now`
    /// (Linux). Required when the M7 was running pre-reset — the only
    /// way to actually stop it on this hardware. ~60 s round-trip.
    Reboot,
}

/// Function returning whether *any* registered ComponentBackend has a flash
/// session in flight. Built from the per-component probes exposed by
/// `component_factory::BuiltComponent::flash_probe`.
pub type FlashInProgressProbe = Arc<dyn Fn() -> bool + Send + Sync>;

/// Drop in-flight flash-session state across every registered
/// component (RAM only — does not roll back finalized installs).
/// Built from `component_factory::BuiltComponent::flash_clear`.
pub type ClearFlashSessions = Arc<dyn Fn() + Send + Sync>;

/// What a node supplies to the engine: its device. Called in the order of
/// [`handle`]'s sequence; see the module docs.
#[async_trait::async_trait]
pub trait ResetHooks: Send + Sync {
    /// Before anything else, the token included: `Err(status)` answers that
    /// bare status and nothing runs. Default: no gate.
    fn precheck(&self) -> Result<(), StatusCode> {
        Ok(())
    }

    /// The wipe targets, from the node's config at request time (so config
    /// changes between provisioning and reset are honoured). An `Err` answers
    /// 500 `resolve targets: {e}` before anything is wiped.
    fn resolve(&self) -> Result<WipeTargets, String>;

    /// The device's work before the guests stop and the wipe runs (its log
    /// lines still land in the log dir before that is wiped). May add to the
    /// response's errors. Returns whether the node must reboot
    /// ([`ShutdownKind::Reboot`]) rather than exit ([`ShutdownKind::Exit`]).
    fn before_wipe(&self, errors: &mut Vec<String>) -> bool;

    /// Stop the running guests (best effort) so they release the devices the
    /// wipe zeroes. Default: nothing to stop.
    async fn stop_guests(&self) {}

    /// Start the post-response shutdown. Called BEFORE the response is
    /// returned, so it must not block: arm the reset and fire it from a
    /// detached task after a short flush delay, so the response leaves first.
    fn schedule_shutdown(&self, kind: ShutdownKind);
}

pub struct FactoryResetState {
    pub flash_in_progress: FlashInProgressProbe,
    pub clear_flash_sessions: ClearFlashSessions,
    /// Authorizes the wipe: a HighConsequence `FactoryReset` token bound to this
    /// ECU's id, verified against the HSM-provisioned issuer anchors.
    pub authorizer: Arc<dyn Authorizer>,
    pub hooks: Arc<dyn ResetHooks>,
}

#[derive(Serialize)]
struct Response {
    ok: bool,
    wiped: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<String>,
}

/// `path` is the executions path the request came in on (`/v1/...` or
/// `/vehicle/v1/...`), so the authz request names the tree actually used.
pub async fn handle(
    state: Arc<FactoryResetState>,
    headers: HeaderMap,
    path: &str,
) -> axum::response::Response {
    if let Err(status) = state.hooks.precheck() {
        return status.into_response();
    }

    // Auth: a HighConsequence `FactoryReset` token bound to this ECU's id.
    // Replaces the old UDS programming-session + level-1 security gate — the
    // capability/tier model now governs who may wipe the device. The token must
    // be signed by an issuer trusted for the HighConsequence tier and carry the
    // `factory-reset` scope with `aud` == this ECU's HSM id.
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let req = AccessRequest {
        bearer,
        method: &axum::http::Method::POST,
        path,
        component: None,
        capability: Capability::FactoryReset,
    };
    if let Err(e) = state.authorizer.authorize(&req).await {
        let e = crate::auth_error_message(&e);
        tracing::warn!("factory-reset denied: {e}");
        return (StatusCode::FORBIDDEN, format!("factory-reset denied: {e}")).into_response();
    }

    // 3. Drop any in-flight flash sessions across all components.
    //
    // factory_reset's whole purpose is to recover to a known-clean state,
    // so refusing on a stale RAM-only flash session would defeat the point
    // (the in-progress upload was the very thing we're trying to recover
    // from). We clear them here before the wipe — the bank directories and
    // NV are about to be erased anyway, so any partially-staged upload
    // would be invalidated regardless. We log if anything was active so
    // operators can spot orphaned flash sessions in the timeline.
    if (state.flash_in_progress)() {
        tracing::warn!("factory_reset: clearing in-flight flash session(s) before wipe");
    }
    (state.clear_flash_sessions)();

    // 4. Resolve targets.
    let targets = match state.hooks.resolve() {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("resolve targets: {e}"),
            )
                .into_response();
        }
    };
    tracing::warn!(
        root = %targets.root.display(),
        "factory_reset: starting wipe"
    );

    // 5. The device's work before the wipe (e.g. an M7 query + erase), so its
    //    log lines land in the log dir before execute_wipe deletes it.
    let mut errors = Vec::new();
    let reboot = state.hooks.before_wipe(&mut errors);

    // 6. Stop running guests (best-effort).
    state.hooks.stop_guests().await;

    // 7. Execute wipe.
    let mut outcome = execute_wipe(&targets);
    errors.append(&mut outcome.errors);
    outcome.errors = errors;
    tracing::warn!(
        wiped = outcome.wiped.len(),
        errors = outcome.errors.len(),
        "factory_reset: wipe complete"
    );

    let body = Response {
        ok: outcome.errors.is_empty(),
        wiped: outcome
            .wiped
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        errors: outcome.errors.clone(),
    };
    let status = if body.ok {
        StatusCode::OK
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };

    // 8. Schedule the post-response shutdown: REBOOT when the device's
    //    before-wipe work says so, else exit-respawn.
    let kind = if reboot {
        ShutdownKind::Reboot
    } else {
        ShutdownKind::Exit
    };
    state.hooks.schedule_shutdown(kind);

    (status, axum::Json(body)).into_response()
}

/// The handler builder for [`sovd_router`](crate::sovd_router)'s factory-reset
/// slot: a `POST` handler for the executions path it is mounted at on each tree.
/// ECU-level operation per ISO 17978-3 §7.14 (operations.executions): wiping
/// NV + HSM + bank dirs is a whole-ECU op, not a component op. POST creates an
/// execution; the wipe runs synchronously then schedules the shutdown.
pub fn route(fr_state: Arc<FactoryResetState>) -> impl Fn(&str) -> axum::routing::MethodRouter {
    move |path: &str| {
        let fr_state = fr_state.clone();
        let path = path.to_string();
        axum::routing::post(move |headers: axum::http::HeaderMap| {
            let st = fr_state.clone();
            let path = path.clone();
            async move { handle(st, headers, &path).await }
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    use async_trait::async_trait;
    use axum::body::to_bytes;
    use axum::http::StatusCode;
    use sovd_api::ClientContext;

    const FR_PATH: &str = "/vehicle/v1/operations/factory-reset/executions";

    // Test authorizers — the handler only cares Ok/Err, so these ignore the token.
    struct AllowAuth;
    #[async_trait]
    impl Authorizer for AllowAuth {
        async fn authorize(
            &self,
            _req: &AccessRequest<'_>,
        ) -> Result<ClientContext, sovd_api::AuthError> {
            Ok(ClientContext {
                subject: "test".into(),
                scopes: Vec::new(),
            })
        }
        fn is_open(&self) -> bool {
            true
        }
    }
    struct DenyAuth;
    #[async_trait]
    impl Authorizer for DenyAuth {
        async fn authorize(
            &self,
            _req: &AccessRequest<'_>,
        ) -> Result<ClientContext, sovd_api::AuthError> {
            Err("test: denied".into())
        }
        fn is_open(&self) -> bool {
            false
        }
    }

    /// Denies, recording the `path` it was asked to authorize.
    struct RecordingDenyAuth(Mutex<Option<String>>);
    #[async_trait]
    impl Authorizer for RecordingDenyAuth {
        async fn authorize(
            &self,
            req: &AccessRequest<'_>,
        ) -> Result<ClientContext, sovd_api::AuthError> {
            *self.0.lock().unwrap() = Some(req.path.to_string());
            Err("test: denied".into())
        }
        fn is_open(&self) -> bool {
            false
        }
    }

    // -------------- pure unit tests --------------

    #[test]
    fn ensure_under_root_accepts_subpath() {
        assert!(ensure_under_root(
            Path::new("/mnt/common-rw"),
            Path::new("/mnt/common-rw/mmgr/nv-store.bin"),
        )
        .is_ok());
    }

    #[test]
    fn ensure_under_root_rejects_outside() {
        assert!(ensure_under_root(Path::new("/mnt/common-rw"), Path::new("/etc/passwd"),).is_err());
    }

    #[test]
    fn ensure_under_root_rejects_traversal() {
        assert!(ensure_under_root(
            Path::new("/mnt/common-rw"),
            Path::new("/mnt/common-rw/../etc"),
        )
        .is_err());
    }

    #[test]
    fn ensure_under_root_rejects_relative() {
        assert!(
            ensure_under_root(Path::new("/mnt/common-rw"), Path::new("relative/path")).is_err()
        );
    }

    // -------------- guest RW partition wipe --------------

    #[test]
    fn zero_partition_head_refuses_non_dev_path() {
        // The wipe bypasses ensure_under_root, so it MUST hard-refuse anything
        // that isn't a /dev block device — never zero a regular file.
        let mut out = WipeOutcome::default();
        zero_partition_head("/mnt/common-rw/mmgr/nv-store.bin", &mut out);
        assert!(out.wiped.is_empty());
        assert_eq!(out.errors.len(), 1);
        assert!(out.errors[0].contains("refusing non-/dev path"));
    }

    #[test]
    fn zero_partition_head_skips_absent_device() {
        // A target-layout partition absent on the interim device is skipped,
        // not an error (best-effort).
        let mut out = WipeOutcome::default();
        zero_partition_head("/dev/emmc-does-not-exist-xyz", &mut out);
        assert!(out.wiped.is_empty());
        assert!(
            out.errors.is_empty(),
            "absent device must be silent: {:?}",
            out.errors
        );
    }

    // -------------- handler tests with TempDir + test hooks --------------

    /// What a node's config names for the wipe: here, the fixture's.
    struct Layout {
        root: PathBuf,
        nv_store: PathBuf,
        images_dir: PathBuf,
        hsm_keystore: PathBuf,
        components: Vec<ComponentSpec>,
        log_dir: PathBuf,
        boot_selector_dir: PathBuf,
    }

    impl Layout {
        fn targets(&self) -> Result<WipeTargets, String> {
            let (vm_dirs, hsm_state_dir) =
                component_dirs(&self.root, &self.nv_store, &self.components);
            Ok(WipeTargets {
                root: self.root.clone(),
                nv_store: self.nv_store.clone(),
                images_dir: Some(self.images_dir.clone()),
                hsm_keystore: self.hsm_keystore.clone(),
                vm_dirs,
                hsm_state_dir,
                log_dir: Some(self.log_dir.clone()),
                boot_selector_dir: Some(self.boot_selector_dir.clone()),
                guest_rw_partitions: Vec::new(),
                host_bank_partitions: Vec::new(),
            })
        }
    }

    /// A component spec as a profile declares it.
    fn spec(yaml: &str) -> ComponentSpec {
        serde_yaml::from_str(yaml).unwrap()
    }

    /// Build a temp-dir fake of `/mnt/common-rw` that our handler will wipe.
    /// Returns (TempDir, Layout). The TempDir is the `root`; under it:
    ///   mmgr/{nv-store.bin, images/IMAGE, A/keep.bin, B/keep.bin, current,
    ///         start.sh}
    ///   vhsm/keys/device.key
    ///   vm1/{bank_a/boot.img, bank_b/boot.img, current → bank_a}
    ///   vm2/{bank_a/boot.img, bank_b/boot.img, current → bank_b}
    ///   hsm/{bank_a/blob.bin, bank_b/blob.bin}
    ///   {vm1,vm2,hsm}/{staging-bank_a.cbor, staging/bank_a/x.part}
    ///   log/node.log
    fn make_layout() -> (tempfile::TempDir, Layout) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        let mmgr = root.join("mmgr");
        std::fs::create_dir_all(mmgr.join("images")).unwrap();
        std::fs::create_dir_all(mmgr.join("A")).unwrap();
        std::fs::create_dir_all(mmgr.join("B")).unwrap();
        std::fs::write(mmgr.join("nv-store.bin"), b"nv-data").unwrap();
        std::fs::write(mmgr.join("images").join("IMAGE.suit"), b"img").unwrap();
        std::fs::write(mmgr.join("A").join("keep.bin"), b"node-bin-A").unwrap();
        std::fs::write(mmgr.join("B").join("keep.bin"), b"node-bin-B").unwrap();
        std::fs::write(mmgr.join("start.sh"), b"#!/bin/sh\n").unwrap();
        std::os::unix::fs::symlink("A", mmgr.join("current")).unwrap();

        std::fs::create_dir_all(root.join("vhsm").join("keys")).unwrap();
        std::fs::write(root.join("vhsm").join("keys").join("device.key"), b"key").unwrap();

        for vm in ["vm1", "vm2"] {
            let vm_dir = root.join(vm);
            std::fs::create_dir_all(vm_dir.join("bank_a")).unwrap();
            std::fs::create_dir_all(vm_dir.join("bank_b")).unwrap();
            std::fs::write(vm_dir.join("bank_a").join("boot.img"), b"bank_a-img").unwrap();
            std::fs::write(vm_dir.join("bank_b").join("boot.img"), b"bank_b-img").unwrap();
            // current → bank_a for vm1, bank_b for vm2 (covers both directions)
            let target = if vm == "vm1" { "bank_a" } else { "bank_b" };
            std::os::unix::fs::symlink(target, vm_dir.join("current")).unwrap();
        }

        std::fs::create_dir_all(root.join("hsm").join("bank_a")).unwrap();
        std::fs::create_dir_all(root.join("hsm").join("bank_b")).unwrap();
        std::fs::write(root.join("hsm").join("bank_a").join("blob.bin"), b"hsm-a").unwrap();
        std::fs::write(root.join("hsm").join("bank_b").join("blob.bin"), b"hsm-b").unwrap();

        // A transfer staged into bank a of every set: its record + a part.
        for set in ["vm1", "vm2", "hsm"] {
            let set_dir = root.join(set);
            std::fs::create_dir_all(set_dir.join("staging").join("bank_a")).unwrap();
            std::fs::write(set_dir.join("staging-bank_a.cbor"), b"record").unwrap();
            std::fs::write(
                set_dir.join("staging").join("bank_a").join("x.part"),
                b"part",
            )
            .unwrap();
        }

        std::fs::create_dir_all(root.join("log")).unwrap();
        std::fs::write(root.join("log").join("node.log"), b"prior boot").unwrap();

        std::fs::create_dir_all(mmgr.join("boot-selector")).unwrap();
        std::fs::write(mmgr.join("boot-selector").join("primary"), b"{}").unwrap();
        std::fs::write(mmgr.join("boot-selector").join("secondary"), b"{}").unwrap();
        std::fs::write(mmgr.join("boot-selector").join("transaction"), b"{}").unwrap();

        let storage = root.display();
        let layout = Layout {
            root: root.to_path_buf(),
            nv_store: mmgr.join("nv-store.bin"),
            images_dir: mmgr.join("images"),
            hsm_keystore: root.join("vhsm").join("keys"),
            components: vec![
                spec(&format!("{{id: vm1, type: bank, slot: 1, storage_path: {storage}}}")),
                spec(&format!("{{id: vm2, type: bank, slot: 2, storage_path: {storage}}}")),
                spec(&format!(
                    "{{id: hsm, type: hsm, rollback: false, single_bank: true, slot: 3, storage_path: {storage}}}"
                )),
                spec(&format!(
                    "{{id: host-app, type: app, slot: 4, base_path: {}}}",
                    mmgr.display()
                )),
            ],
            log_dir: root.join("log"),
            boot_selector_dir: mmgr.join("boot-selector"),
        };
        (tmp, layout)
    }

    /// The node side of a test: the fixture's targets, a fixed reboot verdict,
    /// and the shutdowns it was asked for.
    struct TestHooks {
        layout: Layout,
        reboot: bool,
        scheduled: Arc<Mutex<Vec<ShutdownKind>>>,
    }

    #[async_trait]
    impl ResetHooks for TestHooks {
        fn resolve(&self) -> Result<WipeTargets, String> {
            self.layout.targets()
        }
        fn before_wipe(&self, _errors: &mut Vec<String>) -> bool {
            self.reboot
        }
        fn schedule_shutdown(&self, kind: ShutdownKind) {
            self.scheduled.lock().unwrap().push(kind);
        }
    }

    fn state_with(
        layout: Layout,
        authorizer: Arc<dyn Authorizer>,
        flash_in_progress: FlashInProgressProbe,
        clear_flash_sessions: ClearFlashSessions,
    ) -> (Arc<FactoryResetState>, Arc<Mutex<Vec<ShutdownKind>>>) {
        let scheduled = Arc::new(Mutex::new(Vec::new()));
        let state = FactoryResetState {
            flash_in_progress,
            clear_flash_sessions,
            authorizer,
            hooks: Arc::new(TestHooks {
                layout,
                reboot: false,
                scheduled: scheduled.clone(),
            }),
        };
        (Arc::new(state), scheduled)
    }

    fn make_state(layout: Layout) -> (Arc<FactoryResetState>, Arc<Mutex<Vec<ShutdownKind>>>) {
        state_with(
            layout,
            Arc::new(AllowAuth),
            Arc::new(|| false),
            Arc::new(|| {}),
        )
    }

    async fn body_string(resp: axum::response::Response) -> String {
        let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        String::from_utf8_lossy(&bytes).to_string()
    }

    #[tokio::test]
    async fn rejects_when_token_denied() {
        // The authorizer is the gate now (replacing UDS session + security level).
        let (_tmp, layout) = make_layout();
        let (state, scheduled) = state_with(
            layout,
            Arc::new(DenyAuth),
            Arc::new(|| false),
            Arc::new(|| {}),
        );
        let resp = handle(state, HeaderMap::new(), FR_PATH).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(
            scheduled.lock().unwrap().is_empty(),
            "denied reset must not schedule shutdown"
        );
    }

    #[tokio::test]
    async fn authorizes_against_the_request_tree_path() {
        // The `/v1` twin route passes its own path; the authz request (and the
        // denial body) must name it, and a denial stays 403 with the reason.
        let (_tmp, layout) = make_layout();
        let auth = Arc::new(RecordingDenyAuth(Mutex::new(None)));
        let (state, _) = state_with(layout, auth.clone(), Arc::new(|| false), Arc::new(|| {}));
        let resp = handle(
            state,
            HeaderMap::new(),
            "/v1/operations/factory-reset/executions",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_string(resp).await,
            "factory-reset denied: test: denied"
        );
        assert_eq!(
            auth.0.lock().unwrap().as_deref(),
            Some("/v1/operations/factory-reset/executions")
        );
    }

    #[tokio::test]
    async fn clears_orphan_flash_session_then_proceeds() {
        // A failed flash that left RAM-only flash_session populated
        // must NOT block factory_reset — the whole point of the reset
        // is to recover from such states. We verify that the clear
        // callback is invoked and the wipe still proceeds to OK.
        let (_tmp, layout) = make_layout();
        let cleared = Arc::new(AtomicBool::new(false));
        let c = cleared.clone();
        let (state, scheduled) = state_with(
            layout,
            Arc::new(AllowAuth),
            Arc::new(|| true),
            Arc::new(move || {
                c.store(true, Ordering::SeqCst);
            }),
        );
        let resp = handle(state, HeaderMap::new(), FR_PATH).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            cleared.load(Ordering::SeqCst),
            "clear_flash_sessions not called"
        );
        assert!(!scheduled.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn happy_path_wipes_targets_preserves_app_install() {
        let (tmp, layout) = make_layout();
        let root = tmp.path().to_path_buf();
        let (state, scheduled) = make_state(layout);

        let resp = handle(state, HeaderMap::new(), FR_PATH).await;
        let status = resp.status();
        let body = body_string(resp).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(*scheduled.lock().unwrap(), vec![ShutdownKind::Exit]);

        // Wiped:
        assert!(!root.join("mmgr").join("nv-store.bin").exists());
        assert!(!root.join("mmgr").join("images").join("IMAGE.suit").exists());
        assert!(!root.join("vhsm").join("keys").join("device.key").exists());
        assert!(!root.join("vm1").join("bank_a").join("boot.img").exists());
        assert!(!root.join("vm1").join("bank_b").join("boot.img").exists());
        assert!(!root.join("vm2").join("bank_a").join("boot.img").exists());
        assert!(!root.join("vm2").join("bank_b").join("boot.img").exists());
        assert!(!root.join("hsm").join("bank_a").join("blob.bin").exists());
        assert!(!root.join("hsm").join("bank_b").join("blob.bin").exists());
        assert!(!root.join("log").join("node.log").exists());
        assert!(!root
            .join("mmgr")
            .join("boot-selector")
            .join("primary")
            .exists());
        assert!(!root
            .join("mmgr")
            .join("boot-selector")
            .join("secondary")
            .exists());
        assert!(!root
            .join("mmgr")
            .join("boot-selector")
            .join("transaction")
            .exists());
        // current symlinks gone
        assert!(root.join("vm1").join("current").symlink_metadata().is_err());
        assert!(root.join("vm2").join("current").symlink_metadata().is_err());
        // staging state gone, bank dirs kept
        for set in ["vm1", "vm2", "hsm"] {
            assert!(
                !root.join(set).join("staging-bank_a.cbor").exists(),
                "{set}"
            );
            assert!(!root.join(set).join("staging").exists(), "{set}");
            assert!(root.join(set).join("bank_a").is_dir(), "{set}");
        }

        // Preserved:
        assert!(root.join("mmgr").join("A").join("keep.bin").exists());
        assert!(root.join("mmgr").join("B").join("keep.bin").exists());
        assert!(root.join("mmgr").join("start.sh").exists());
        assert!(root.join("mmgr").join("current").symlink_metadata().is_ok());
    }

    #[tokio::test]
    async fn rejects_storage_path_outside_root() {
        let (_tmp, mut layout) = make_layout();
        // Sabotage one component to point outside the wipe-root.
        for c in &mut layout.components {
            if c.id == "vm1" {
                c.storage_path = Some(PathBuf::from("/etc"));
            }
        }
        let (state, scheduled) = make_state(layout);

        let resp = handle(state, HeaderMap::new(), FR_PATH).await;
        let status = resp.status();
        let body = body_string(resp).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {body}");
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["ok"], false);
        let errors = body["errors"].as_array().unwrap();
        assert_eq!(
            errors.len(),
            3,
            "both vm1 banks and its staging state report errors: {errors:?}"
        );
        assert!(
            errors
                .iter()
                .all(|error| error.as_str().unwrap().contains("escapes root")),
            "body: {body}"
        );
        assert!(!body["wiped"].as_array().unwrap().is_empty());
        // Critical: the bogus target must NOT be wiped — /etc must be untouched.
        assert!(std::path::Path::new("/etc/passwd").exists());
        // Schedule shutdown still fires (we've wiped what we could). Best-effort
        // semantics — operator sees error in response, decides next steps.
        assert_eq!(*scheduled.lock().unwrap(), vec![ShutdownKind::Exit]);
    }

    #[test]
    fn resolves_component_types_and_storage_subdirs_into_wipe_targets() {
        let (tmp, mut layout) = make_layout();
        std::fs::remove_dir_all(tmp.path().join("vm1")).unwrap();
        std::fs::remove_dir_all(tmp.path().join("vm2")).unwrap();

        layout.components[0].storage_subdir = Some("guest-a".into());
        layout.components[1].component_type = "hpc".into();
        layout.components[3].storage_path = Some(tmp.path().to_path_buf());
        layout.components[3].storage_subdir = Some("preserved-app".into());

        let targets = layout.targets().unwrap();
        assert!(targets.vm_dirs.contains(&tmp.path().join("guest-a")));
        assert!(targets.vm_dirs.contains(&tmp.path().join("vm2")));
        assert_eq!(targets.hsm_state_dir, Some(tmp.path().join("hsm")));
        assert!(!targets.vm_dirs.contains(&tmp.path().join("preserved-app")));
    }

    #[tokio::test]
    async fn a_refused_precheck_answers_its_status_before_the_token() {
        struct Gated(Arc<AtomicBool>);
        #[async_trait]
        impl ResetHooks for Gated {
            fn precheck(&self) -> Result<(), StatusCode> {
                Err(StatusCode::NOT_FOUND)
            }
            fn resolve(&self) -> Result<WipeTargets, String> {
                self.0.store(true, Ordering::SeqCst);
                Err("unreachable".into())
            }
            fn before_wipe(&self, _errors: &mut Vec<String>) -> bool {
                false
            }
            fn schedule_shutdown(&self, _kind: ShutdownKind) {}
        }
        let auth = Arc::new(RecordingDenyAuth(Mutex::new(None)));
        let resolved = Arc::new(AtomicBool::new(false));
        let state = Arc::new(FactoryResetState {
            flash_in_progress: Arc::new(|| false),
            clear_flash_sessions: Arc::new(|| {}),
            authorizer: auth.clone(),
            hooks: Arc::new(Gated(resolved.clone())),
        });
        let resp = handle(state, HeaderMap::new(), FR_PATH).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(body_string(resp).await, "");
        assert_eq!(*auth.0.lock().unwrap(), None, "the token is not asked");
        assert!(!resolved.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn before_wipe_errors_and_reboot_reach_the_response_and_the_shutdown() {
        struct Failing(TestHooks);
        #[async_trait]
        impl ResetHooks for Failing {
            fn resolve(&self) -> Result<WipeTargets, String> {
                self.0.resolve()
            }
            fn before_wipe(&self, errors: &mut Vec<String>) -> bool {
                errors.push("device: erase failed".into());
                true
            }
            fn schedule_shutdown(&self, kind: ShutdownKind) {
                self.0.schedule_shutdown(kind)
            }
        }
        let (_tmp, layout) = make_layout();
        let scheduled = Arc::new(Mutex::new(Vec::new()));
        let state = Arc::new(FactoryResetState {
            flash_in_progress: Arc::new(|| false),
            clear_flash_sessions: Arc::new(|| {}),
            authorizer: Arc::new(AllowAuth),
            hooks: Arc::new(Failing(TestHooks {
                layout,
                reboot: false,
                scheduled: scheduled.clone(),
            })),
        });
        let resp = handle(state, HeaderMap::new(), FR_PATH).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
        assert_eq!(body["ok"], false);
        assert_eq!(body["errors"], serde_json::json!(["device: erase failed"]));
        assert!(
            !body["wiped"].as_array().unwrap().is_empty(),
            "the wipe still ran"
        );
        assert_eq!(*scheduled.lock().unwrap(), vec![ShutdownKind::Reboot]);
    }

    // -------------- provisioned-banks manifest + fallback scan --------------

    // A scratch common-rw with an mmgr/ (resident MM) + some component bank dirs.
    fn scratch_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("fr-manifest-{tag}"));
        let _ = std::fs::remove_dir_all(&root);
        // mmgr = the resident MM (must never be wiped); nv_store lives here.
        std::fs::create_dir_all(root.join("mmgr/bank_a")).unwrap();
        std::fs::write(root.join("mmgr/nv-store.bin"), b"nv").unwrap();
        root
    }

    #[test]
    fn manifest_lists_extra_component_dirs() {
        let root = scratch_root("list");
        let nv = root.join("mmgr/nv-store.bin");
        // Tier-2 provisioned vm1/vm2 (+ os) — the Tier-1 config wouldn't know these.
        std::fs::write(
            root.join("mmgr").join(PROVISIONED_BANKS_FILE),
            "# header\nos\nvm1\nvm2\n",
        )
        .unwrap();
        let dirs = manifest_and_scanned_component_dirs(&root, &nv);
        assert!(
            dirs.contains(&root.join("vm1")),
            "vm1 from manifest: {dirs:?}"
        );
        assert!(
            dirs.contains(&root.join("vm2")),
            "vm2 from manifest: {dirs:?}"
        );
        assert!(
            dirs.contains(&root.join("os")),
            "os from manifest: {dirs:?}"
        );
        // NEVER the resident MM.
        assert!(
            !dirs.contains(&root.join("mmgr")),
            "mmgr must never be a target"
        );
    }

    #[test]
    fn scan_finds_banks_when_manifest_missing() {
        let root = scratch_root("scan");
        let nv = root.join("mmgr/nv-store.bin");
        // No manifest written. Create component bank dirs the scan should find.
        std::fs::create_dir_all(root.join("vm2/bank_b")).unwrap();
        std::fs::create_dir_all(root.join("rt/bank_a")).unwrap();
        // A non-bank dir (log/) must be ignored.
        std::fs::create_dir_all(root.join("log")).unwrap();
        let dirs = manifest_and_scanned_component_dirs(&root, &nv);
        assert!(dirs.contains(&root.join("vm2")), "scan finds vm2: {dirs:?}");
        assert!(dirs.contains(&root.join("rt")), "scan finds rt: {dirs:?}");
        assert!(!dirs.contains(&root.join("log")), "non-bank dir skipped");
        assert!(!dirs.contains(&root.join("mmgr")), "mmgr never scanned in");
    }

    #[test]
    fn mmgr_never_wiped_even_if_manifest_names_it() {
        // Defence: a corrupt/malicious manifest naming mmgr or an escape must not
        // make the resident MM a wipe target.
        let root = scratch_root("evil");
        let nv = root.join("mmgr/nv-store.bin");
        std::fs::write(
            root.join("mmgr").join(PROVISIONED_BANKS_FILE),
            "mmgr\n../escape\n/abs/path\nvm1\n",
        )
        .unwrap();
        let dirs = manifest_and_scanned_component_dirs(&root, &nv);
        assert!(!dirs.contains(&root.join("mmgr")), "mmgr rejected");
        assert!(
            !dirs.iter().any(|d| d.to_string_lossy().contains("escape")),
            "traversal rejected"
        );
        assert!(
            !dirs.iter().any(|d| d.starts_with("/abs")),
            "absolute rejected"
        );
        // The legit entry still lands.
        assert!(
            dirs.contains(&root.join("vm1")),
            "vm1 still listed: {dirs:?}"
        );
    }

    #[test]
    fn write_provisioned_banks_lists_components_not_mmgr() {
        // Reuse make_layout()'s full layout (vm1/vm2 + hsm components, real mmgr dir).
        let (tmp, layout) = make_layout();
        write_provisioned_banks(&layout.nv_store, &layout.components);
        let mmgr = layout.nv_store.parent().unwrap();
        let content = std::fs::read_to_string(mmgr.join(PROVISIONED_BANKS_FILE)).unwrap();
        // make_layout's components (vm1, vm2, hsm — subdir defaults to the id) are
        // listed; the resident MM never is.
        for d in ["vm1", "vm2"] {
            assert!(
                content.lines().any(|l| l.trim() == d),
                "manifest has {d}: {content}"
            );
        }
        assert!(
            !content.lines().any(|l| l.trim() == "mmgr"),
            "mmgr never listed"
        );
        let _ = tmp;
    }
}
