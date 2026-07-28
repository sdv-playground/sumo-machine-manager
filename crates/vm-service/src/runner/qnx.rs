//! QNX qvm runner — thin wrapper around the qvm hypervisor process.
//!
//! Lifecycle:
//!   1. devb-loopback maps the rootfs file to `/dev/qvmdiskN`
//!   2. `qvm @<config>` launches the guest VM
//!   3. Track the qvm PID for is_running / stop / wait
//!
//! Health monitoring (heartbeat read, shutdown command) is owned by
//! `VmManager` via `HeartbeatDevice` + `PowerCommandDevice` over the
//! configured `DeviceTransport`. The runner has nothing to do with it.

use std::path::Path;
use std::process::{Child, Command};
use std::time::Duration;

use super::*;

/// Timeout waiting for devb-loopback to create the device node.
const LOOPBACK_TIMEOUT: Duration = Duration::from_secs(5);

pub struct QnxRunner {
    /// devb-loopback spawn parents for rootfs + every extra disk. Each held
    /// `Child` is just the fork parent — devb-loopback double-forks. The
    /// real daemons land in `loopback_pids` so cleanup can libc::kill them.
    loopback_children: Vec<Child>,
    loopback_pids: Vec<u32>,
    /// VM name remembered from start() so cleanup can re-find any daemons
    /// whose pid wasn't captured (find raced ahead of devb-loopback's
    /// daemonize) — see [`Self::slay_loopbacks_for_vm`].
    vm_name: Option<String>,
    /// qvm process (the guest VM).
    qvm_child: Option<Child>,
}

impl Default for QnxRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl QnxRunner {
    pub fn new() -> Self {
        Self {
            loopback_children: Vec::new(),
            loopback_pids: Vec::new(),
            vm_name: None,
            qvm_child: None,
        }
    }

    /// Kill a child process if it's still alive.
    fn kill_child(child: &mut Child) {
        let _ = child.kill();
        let _ = child.wait();
    }

    /// Prefix the rootfs devb-loopback registers under in `/dev`.
    fn rootfs_prefix(vm_name: &str) -> String {
        format!("qvmdisk-{vm_name}")
    }

    /// Prefix an extra-disk devb-loopback registers under in `/dev`. Single
    /// hyphen — matches the rootfs `qvmdisk-{vm}` pattern. Empirically, two
    /// hyphens in the prefix made the device node never appear (devb-loopback
    /// process ran but io-blk silently dropped the registration).
    fn extra_prefix(vm_name: &str, role: &str) -> String {
        format!("qvm{role}-{vm_name}")
    }

    fn extra_device(vm_name: &str, role: &str) -> String {
        format!("/dev/{}0", Self::extra_prefix(vm_name, role))
    }

    // Policy, ca-bundle, sumo-config, and any future partition share the
    // generic `extra_prefix` naming (`qvm{role}-{vm}`) — see the partition
    // loop in `start`. No per-type prefix fns: the role token comes from
    // the OTA-delivered vm-config.yaml, so a new partition is config, not
    // code. (Keep role tokens ≤4 chars — io-blk on QNX 7.1 silently drops
    // longer prefixes; that's why the tokens are `pols`/`cab`/`cfg`.)

    /// Walk `/proc/<pid>/cmdline` for every live process and return
    /// `(pid, argv_string)` pairs. argv tokens are NUL-separated on
    /// disk; we substitute spaces so callers can `.contains()`-match.
    ///
    /// QNX 7.1's `pidin -F "%p %a"` does NOT include argv — `%a`
    /// surfaces some other field (priority-ish). procfs is the only
    /// portable way to read argv on this platform.
    fn enumerate_pids_with_cmdline() -> Vec<(u32, String)> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return out;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            let cmdline_path = format!("/proc/{pid}/cmdline");
            let Ok(bytes) = std::fs::read(&cmdline_path) else {
                continue;
            };
            if bytes.is_empty() {
                continue;
            }
            let argv = String::from_utf8_lossy(&bytes).replace('\0', " ");
            out.push((pid, argv));
        }
        out
    }

    /// Find every live devb-loopback daemon associated with this VM.
    ///
    /// `Command::spawn`'s child pid points at the (long-dead) fork parent
    /// because devb-loopback daemonizes. The actual driver shows up with
    /// the same argv vector. Match argv on the `prefix=…-{vm_name},fd=`
    /// substring so we hit both `qvmdisk-{vm}` and `qvm-{role}-{vm}`.
    fn find_loopback_pids(vm_name: &str) -> Vec<u32> {
        let needle = format!("-{vm_name},fd=");
        Self::enumerate_pids_with_cmdline()
            .into_iter()
            .filter(|(_, argv)| argv.contains("devb-loopback") && argv.contains(&needle))
            .map(|(pid, _)| pid)
            .collect()
    }

    /// SIGTERM-then-SIGKILL every devb-loopback for this VM. Used as
    /// defense-in-depth at start() to clear leftovers from a prior boot
    /// that didn't go through cleanup() (process crash, hard reset).
    fn slay_loopbacks_for_vm(vm_name: &str) {
        for pid in Self::find_loopback_pids(vm_name) {
            tracing::info!(vm = %vm_name, pid, "killing stale devb-loopback");
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
            std::thread::sleep(Duration::from_millis(100));
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGKILL);
            }
        }
    }

    /// Spawn a devb-loopback for a backing file with a given prefix, wait
    /// for `/dev/<prefix>0` to appear, and remember the daemon pid for
    /// cleanup. Shared by the rootfs + extra-disks paths.
    fn spawn_loopback(&mut self, prefix: &str, backing: &Path) -> Result<(), RunnerError> {
        let device = format!("/dev/{prefix}0");
        tracing::info!("starting devb-loopback: {} → {device}", backing.display());
        let child = Command::new("devb-loopback")
            .arg("loopback")
            .arg(format!("prefix={prefix},fd={}", backing.display()))
            .spawn()
            .map_err(|e| RunnerError::ProcessFailed(format!("devb-loopback: {e}")))?;
        self.loopback_children.push(child);
        wait_for_device(&device, LOOPBACK_TIMEOUT)?;
        if let Some(pid) = Self::find_loopback_pid_by_prefix(prefix) {
            self.loopback_pids.push(pid);
            tracing::info!("{device} ready (devb-loopback pid: {pid})");
        } else {
            tracing::info!("{device} ready (devb-loopback pid: unresolved)");
        }
        Ok(())
    }

    fn find_loopback_pid_by_prefix(prefix: &str) -> Option<u32> {
        let needle = format!("prefix={prefix},");
        Self::enumerate_pids_with_cmdline()
            .into_iter()
            .find(|(_, argv)| argv.contains("devb-loopback") && argv.contains(&needle))
            .map(|(pid, _)| pid)
    }

    /// Find every live qvm process started against this VM's qvm config.
    ///
    /// `Command::new("qvm").arg("@<config>")` → argv shape `qvm @<config>`.
    /// Match against the config path so we only slay qvms whose config we
    /// own — other VMs' qvms stay untouched.
    fn find_qvm_pids(qvm_config: &Path) -> Vec<u32> {
        let needle = format!("@{}", qvm_config.display());
        Self::enumerate_pids_with_cmdline()
            .into_iter()
            .filter(|(_, argv)| {
                if !argv.contains(&needle) {
                    return false;
                }
                // Confirm argv[0] is `qvm` (not some other process that
                // happens to reference the config path in its argv).
                let mut tokens = argv.split_whitespace();
                let Some(cmd) = tokens.next() else {
                    return false;
                };
                cmd == "qvm" || cmd.rsplit('/').next() == Some("qvm")
            })
            .map(|(pid, _)| pid)
            .collect()
    }

    /// SIGTERM-then-SIGKILL every qvm running against this VM's config.
    ///
    /// Defense in depth at start() for orphan qvms that the tracked
    /// `qvm_child` handle can't reach — e.g. a previous host
    /// lifetime spawned qvm, then the host got slayed; start-managed.sh
    /// kicks off the next host with a global `slay qvm` but that's
    /// best-effort with no exit-wait, so the new vm-service can race a
    /// dying qvm and end up with a fresh VmManager (qvm_child=None)
    /// while an orphan qvm still holds /dev/qvm/<sys>, vdevpeer
    /// endpoints, and qvm-shmem slots. Symptom: VMs keep serving the
    /// OLD rootfs from page cache after an OTA flash — only a device
    /// reboot dislodges the orphan.
    fn slay_qvm_for_vm(qvm_config: &Path) {
        for pid in Self::find_qvm_pids(qvm_config) {
            tracing::info!(qvm_config = %qvm_config.display(), pid, "killing stale qvm");
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
            std::thread::sleep(Duration::from_millis(100));
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGKILL);
            }
        }
    }
}

/// Poll for a device node to appear, with timeout.
fn wait_for_device(path: &str, timeout: Duration) -> Result<(), RunnerError> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if Path::new(path).exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(RunnerError::ProcessFailed(format!(
        "{path} did not appear within {}s",
        timeout.as_secs()
    )))
}

/// Splice a dm-verity `dm-mod.create=… root=/dev/dm-0 ro` fragment into the
/// first `cmdline "…"` line of a qvm.conf, escaping the fragment's inner `"` as
/// `\"` (qvm's `cmdline` value is itself a double-quoted string). Returns `base`
/// unchanged if it already carries a `dm-mod.create` or has no `cmdline` line.
fn splice_verity_cmdline(base: &str, frag: &str) -> String {
    if base.contains("dm-mod.create") {
        return base.to_string();
    }
    let escaped = frag.replace('"', "\\\"");
    let mut out = String::with_capacity(base.len() + escaped.len() + 4);
    let mut done = false;
    for line in base.lines() {
        let te = line.trim_end();
        if !done && line.trim_start().starts_with("cmdline ") && te.ends_with('"') {
            // Insert the fragment just before the cmdline value's closing quote.
            out.push_str(&te[..te.len() - 1]);
            out.push(' ');
            out.push_str(&escaped);
            out.push('"');
            out.push('\n');
            done = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod verity_splice_tests {
    use super::splice_verity_cmdline;

    #[test]
    fn splices_before_closing_quote_and_escapes_inner_quotes() {
        let base =
            "system linux-guest-1\ncmdline \"console=ttyAMA0 root=/dev/vda ro\"\nvdev pl011\n";
        let frag = "dm-mod.create=\"vroot,,,ro,0 8 verity 1 /dev/vda /dev/vda 4096 4096 1 1 sha256 aa bb\" root=/dev/dm-0 ro";
        let out = splice_verity_cmdline(base, frag);
        assert!(out.contains(
            "cmdline \"console=ttyAMA0 root=/dev/vda ro dm-mod.create=\\\"vroot,,,ro,0 8 verity 1 /dev/vda /dev/vda 4096 4096 1 1 sha256 aa bb\\\" root=/dev/dm-0 ro\"\n"
        ));
        assert!(out.contains("vdev pl011"));
    }

    #[test]
    fn idempotent_when_already_present() {
        let base = "cmdline \"root=/dev/vda ro dm-mod.create=\\\"x\\\" root=/dev/dm-0 ro\"\n";
        assert_eq!(
            splice_verity_cmdline(base, "dm-mod.create=\"y\" root=/dev/dm-0 ro"),
            base
        );
    }
}

impl VmRunner for QnxRunner {
    /// Slay orphan qvm + devb-loopback for this VM. Called by
    /// VmManager BEFORE the pre-launch verify hook runs so the
    /// verifier can read `rootfs.img` directly — otherwise a
    /// leftover devb-loopback from a previous lifetime holds the
    /// file open (QNX returns EBUSY on second-opener).
    fn prepare_for_launch(&mut self, name: &str, def: &VmDefinition) {
        // Compute the same qvm_config path start() will use, so we
        // can target the orphan qvm by argv.
        let qvm_config = match def.qvm_config.as_ref() {
            Some(raw) if raw.is_relative() => def.image_dir.join(raw),
            Some(raw) => raw.clone(),
            None => return, // No config → no orphan possible to slay.
        };

        // Order: qvm first (so it stops reading from the loopback),
        // then loopback (so it stops holding rootfs.img open).
        Self::slay_qvm_for_vm(&qvm_config);
        std::thread::sleep(Duration::from_millis(100));
        Self::slay_loopbacks_for_vm(name);
        std::thread::sleep(Duration::from_millis(100));
        self.vm_name = Some(name.to_string());
    }

    fn start(&mut self, name: &str, def: &VmDefinition) -> Result<VmHandle, RunnerError> {
        let raw_path = def
            .qvm_config
            .as_ref()
            .ok_or_else(|| RunnerError::Config(format!("VM {name}: qvm_config not set")))?;

        // Relative paths resolve against image_dir, which `start_vm` has
        // already rewritten to the selector-resolved bank dir (`base/bank_{a,b}`).
        let qvm_config = if raw_path.is_relative() {
            def.image_dir.join(raw_path)
        } else {
            raw_path.clone()
        };

        if !qvm_config.exists() {
            return Err(RunnerError::Config(format!(
                "VM {name}: qvm config not found: {}",
                qvm_config.display()
            )));
        }

        // The slay dance moved to `prepare_for_launch` (called by
        // VmManager before the pre-launch verify so EBUSY doesn't
        // fire on `rootfs.img`). vm_name is set there too; we keep
        // this as belt-and-suspenders in case `start` is invoked
        // outside the VmManager path (e.g. direct tests).
        if self.vm_name.is_none() {
            self.vm_name = Some(name.to_string());
        }

        // Rootfs: per-VM prefix lets multiple VMs run concurrently with
        // distinct /dev/qvmdisk-vmX0 nodes.
        if let Some(rootfs) = def.rootfs_path() {
            if rootfs.exists() {
                let prefix = Self::rootfs_prefix(name);
                self.spawn_loopback(&prefix, &rootfs)?;
            } else {
                tracing::warn!(
                    "VM {name}: rootfs not found: {} — skipping loopback",
                    rootfs.display()
                );
            }
        }

        // Per-bank read-only partitions (policy, ca-bundle, sumo-config,
        // future app images …) — declared in the OTA-delivered
        // vm-config.yaml, NOT hardcoded here, so a new partition needs no
        // host-binary change. Each backs a devb-loopback at
        // `/dev/qvm{role}-{vm}0` (short role token — io-blk on QNX 7.1
        // silently drops prefixes >~4 chars); the bank's qvm.conf wires a
        // matching virtio-blk hostdev and the guest IFS mounts it. A
        // missing source is skipped (the guest just doesn't see it).
        for part in &def.partitions {
            let path = def.partition_path(part);
            if path.exists() {
                let prefix = Self::extra_prefix(name, &part.role);
                self.spawn_loopback(&prefix, &path)?;
                tracing::info!(
                    vm = %name, role = %part.role,
                    device = %Self::extra_device(name, &part.role),
                    path = %path.display(),
                    "partition attached"
                );
            } else {
                tracing::warn!(
                    "VM {name}: partition '{}' source not found: {} — skipping",
                    part.role,
                    path.display()
                );
            }
        }

        // Extra disks (data, swap, …) from def.disks. Uses a distinct
        // `qvm-{role}-{vm}` prefix so io-blk doesn't see name-prefix
        // collisions with the rootfs's `qvmdisk-{vm}` namespace.
        for disk in &def.disks {
            if !disk.path.exists() {
                tracing::warn!(
                    "VM {name}: extra disk {role} not found: {path} — skipping",
                    role = disk.role,
                    path = disk.path.display()
                );
                continue;
            }
            let prefix = Self::extra_prefix(name, &disk.role);
            self.spawn_loopback(&prefix, &disk.path)?;
            let device = Self::extra_device(name, &disk.role);
            tracing::info!(vm = %name, role = %disk.role, device, path = %disk.path.display(), "extra disk attached");
        }

        // Launch qvm with the bank's config file. (No per-launch
        // mutation: QNX `load`-style boots have no cmdline override
        // mechanism we can use to pass vm_id — the guest's IFS reads
        // its own vm_name from /etc/sumo/vm-host.toml, which is
        // baked per-VM at mkifs time.)
        // Run qvm FROM the bank dir (the dir holding this qvm.conf, which also
        // holds the kernel) so the conf's relative `load kernel` resolves to the
        // selector-chosen bank's kernel — bank-agnostic, no `current` symlink
        // (retired). Everything else in the conf is an absolute /dev/... node the
        // setup above created, so cwd affects only the kernel load.
        let bank_dir = qvm_config.parent().unwrap_or_else(|| Path::new("."));

        // dm-verity guests ship a `verity-cmdline` bank part — the
        // `dm-mod.create=… root=/dev/dm-0 ro` root-hash fragment — flashed +
        // IVD-signed alongside rootfs.img. qvm's guest cmdline comes ONLY from
        // qvm.conf's `cmdline "…"`; rather than bake the per-build hash into the
        // shipped qvm.conf at seed time (it drifts when the rootfs is rebuilt),
        // splice the fragment into a TEMP copy of qvm.conf here, at launch, from
        // the bank file — so the hash always matches this bank's rootfs. Absent →
        // launch the bank qvm.conf as-is. cwd is the bank dir either way, so the
        // conf's relative `load kernel` resolves to this bank's kernel.
        let launch_config = match std::fs::read_to_string(bank_dir.join("verity-cmdline")) {
            Ok(frag) if !frag.trim().is_empty() => {
                let base = std::fs::read_to_string(&qvm_config)
                    .map_err(|e| RunnerError::Config(format!("VM {name}: read qvm.conf: {e}")))?;
                let merged = splice_verity_cmdline(&base, frag.trim());
                let out = std::path::PathBuf::from(format!("/tmp/vm-svc-{name}-qvm.conf"));
                std::fs::write(&out, merged).map_err(|e| {
                    RunnerError::ProcessFailed(format!("VM {name}: write merged qvm.conf: {e}"))
                })?;
                out
            }
            _ => qvm_config.clone(),
        };

        tracing::info!(
            "starting qvm for {name}: @{} (cwd {})",
            launch_config.display(),
            bank_dir.display()
        );
        // Route qvm's stdout/stderr to a PER-VM console file — NOT inherited.
        // qvm's stdout carries the guest's serial/virtio console (kernel + any
        // service that writes to /dev/console, e.g. an `autostart.sh` layer that
        // bypasses svclog). Inheriting our fds funnels that guest console into the
        // MM's own stdout, which start-managed.sh redirects to supernova.log — so
        // guest heartbeats like "[teesa-vf] alive (tick N)" pollute the HOST log
        // and wreck its per-line timestamps. The guest's REAL logs go via svclog →
        // the in-guest log-agent (surfaced over SOVD §7.21); this console file is a
        // separate best-effort capture, per VM, for boot-time / no-agent debugging.
        // Best-effort: if the file won't open we fall back to inherited fds rather
        // than block the launch (a missing /mnt/common-rw/log must not stop a VM).
        let console_path = format!("/mnt/common-rw/log/{name}-console.log");
        let console = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&console_path);
        let mut cmd = Command::new("qvm");
        cmd.current_dir(bank_dir)
            .arg(format!("@{}", launch_config.display()));
        match console {
            Ok(f) => {
                // stderr shares the same file (dup) so both guest console streams land together.
                let f2 = f.try_clone().map_err(|e| {
                    RunnerError::ProcessFailed(format!("VM {name}: dup console fd: {e}"))
                })?;
                cmd.stdout(std::process::Stdio::from(f))
                    .stderr(std::process::Stdio::from(f2));
                tracing::info!(vm = %name, console = %console_path, "qvm console → per-VM file (kept out of the host log)");
            }
            Err(e) => {
                tracing::warn!(vm = %name, console = %console_path, error = %e,
                    "could not open per-VM console file — qvm console falls back to inherited fds (may leak into the host log)");
            }
        }
        let child = cmd
            .spawn()
            .map_err(|e| RunnerError::ProcessFailed(format!("qvm: {e}")))?;

        let pid = child.id();
        self.qvm_child = Some(child);

        tracing::info!("VM {name} started (qvm pid: {pid})");
        Ok(VmHandle {
            name: name.to_string(),
            pid: Some(pid),
        })
    }

    fn stop(&mut self, _handle: &VmHandle) -> Result<(), RunnerError> {
        if let Some(ref mut child) = self.qvm_child {
            Self::kill_child(child);
        }
        Ok(())
    }

    fn is_running(&self, handle: &VmHandle) -> bool {
        if let Some(pid) = handle.pid {
            unsafe { libc::kill(pid as i32, 0) == 0 }
        } else {
            false
        }
    }

    fn wait(&mut self, _handle: &VmHandle) -> Result<Option<i32>, RunnerError> {
        if let Some(ref mut child) = self.qvm_child {
            let status = child.wait()?;
            return Ok(status.code());
        }
        Err(RunnerError::ProcessFailed("qvm process not found".into()))
    }

    fn cleanup(&mut self) {
        // Kill qvm first so it stops accessing /dev/<prefix>N before we
        // tear down devb-loopback under it.
        if let Some(ref mut child) = self.qvm_child {
            Self::kill_child(child);
        }
        self.qvm_child = None;

        // Held Children point at the spawn-parents (daemons double-fork);
        // kill_child on them is a no-op but reaps the zombie. The real
        // daemons live in loopback_pids.
        for mut child in self.loopback_children.drain(..) {
            Self::kill_child(&mut child);
        }

        // Resolve any daemons we missed at start() (find raced with
        // daemonize) by re-scanning by VM name.
        let mut pids = std::mem::take(&mut self.loopback_pids);
        if let Some(ref vm) = self.vm_name {
            for pid in Self::find_loopback_pids(vm) {
                if !pids.contains(&pid) {
                    pids.push(pid);
                }
            }
        }
        for pid in pids {
            tracing::info!(vm = ?self.vm_name, pid, "killing devb-loopback daemon");
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
            std::thread::sleep(Duration::from_millis(100));
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGKILL);
            }
        }
        self.vm_name = None;
    }
}

impl Drop for QnxRunner {
    fn drop(&mut self) {
        self.cleanup();
    }
}
