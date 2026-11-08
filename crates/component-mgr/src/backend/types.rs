use super::*;

/// Vendor SOVD data-parameter id for the committed bank's signed IVD
/// manifest. `x-ota-` prefix per ISO 17978-3 Table 70 vendor-extension
/// namespacing — the route is plain `/data/{id}` (SOVDd stays spec-pure /
/// format-agnostic); the vendor semantics live entirely here in component-mgr.
pub const INSTALLED_MANIFEST_PARAM_ID: &str = "x-ota-installed-manifest";

/// Vendor SOVD data-parameter id for this component's **update-mode** — how it
/// updates: A/B-banked + trial + rollback, vs single-bank write-through &
/// irreversible (the HSM keystore). A STABLE per-component config property,
/// readable any time (even pre-flash), so an offboard twin can sync
/// rollback-capability the same way it syncs firmware identity. Same `x-ota-`
/// vendor namespace (SOVDd stays spec-pure; the semantics live here in component-mgr).
pub const UPDATE_MODE_PARAM_ID: &str = "x-ota-update-mode";

/// Vendor SOVD operation id for **attest-time**: push a SoftwareAuthority-signed
/// SUIT manifest so the device ratchets its safe-time floor from the manifest's
/// signed (protected-header) `signing_time`. Lets an operator advance a
/// clock-lagging device's trusted-time floor BEFORE a flash, so a freshly-minted
/// delegate cert (`not_before ≈ now`) validates against `max(wall_clock, floor)`
/// (`docs/safe-time-floor.md`). Verify-only: no payload, no bank touch; monotonic,
/// so an older-than-floor manifest is a harmless no-op. Device-global — advertised
/// on the host/device component (the floor + clock are shared singletons).
pub const ATTEST_TIME_OP_ID: &str = "x-attest-time";

/// Map a [`BankError`] raised by a bank-provider payload sink / readback onto
/// the SOVD wire, prefixed with the call site's `context`.
///
/// - `UnknownPart` — the payload names a part this bank does not have. That is
///   the wrong PACKAGE for this component, the same class the F.D3 dispatcher
///   answers with 415 (`UnsupportedMediaType`); retrying the same bytes can
///   never help.
/// - `Unverifiable` — the bytes on the medium are wrong: a bad request (400),
///   as the inline verify path has always reported it.
/// - anything else — a read/write fault on our side (500).
pub(crate) fn sink_error(context: &str, e: BankError) -> BackendError {
    match e {
        BankError::UnknownPart(_) => BackendError::UnsupportedMediaType(format!("{context}: {e}")),
        BankError::Unverifiable(_) => BackendError::InvalidRequest(format!("{context}: {e}")),
        _ => BackendError::Internal(format!("{context}: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Stored package (validated SUIT envelope)
// ---------------------------------------------------------------------------

pub(super) struct StoredPackage {
    pub(super) id: String,
    pub(super) validated: ValidatedFirmware,
    pub(super) status: PackageStatus,
}

/// A validated manifest (uploaded separately from payloads).
pub(super) struct StoredManifest {
    pub(super) raw_bytes: Vec<u8>,
}

/// A raw payload saved to disk (uploaded separately from manifest).
pub(super) struct StoredPayload {
    pub(super) path: std::path::PathBuf,
}

/// SUIT-derived facts for one uploaded manifest, cached so the
/// `GET /updates/{id}` detail body (ISO 17978-3 §7.18.3 Table 261) can be
/// enriched without re-reading / re-parsing the envelope at describe time.
///
/// Populated when the `"manifest"` bulk-data part arrives (the envelope is
/// already CBOR-decoded there for validation, so extraction is free), keyed
/// by the `file_id` the upload returned on the wire. The streaming pipeline
/// writes the *inner* payload straight to flash and drops the raw envelope
/// bytes, so a describe-time re-read isn't possible — caching at parse time
/// is the only honest source for these fields.
#[derive(Clone, Default)]
pub(super) struct ManifestDescribeMeta {
    /// Human-readable name: SUIT model/vendor text + version, or the
    /// component path + version when no text name is present.
    pub(super) update_name: Option<String>,
    /// SUIT text description (`suit-text-manifest-description`), if any.
    pub(super) notes: Option<String>,
    /// Component identifiers named by the manifest, rendered as slash-joined
    /// segment paths (e.g. `vm1`, `rt/firmware`). One entry per SUIT component.
    pub(super) component_paths: Vec<String>,
}

/// Extract the Table-261-relevant facts from an already-decoded SUIT manifest.
///
/// Pure / allocation-light; only reads the metadata the SUIT envelope
/// genuinely carries. `version_display` is the `ValidatedFirmware` version
/// string (text-version or the `seq-N` fallback) — used to qualify the name
/// when the manifest has a human model/vendor name.
pub(super) fn extract_describe_meta(
    manifest: &sumo_onboard::manifest::Manifest,
    version_display: &str,
) -> ManifestDescribeMeta {
    // Prefer a human product/model name; fall back to the supplier/vendor
    // name. Qualify either with the version so the catalog entry is
    // self-describing (e.g. "Sumo VM1 1.2.0").
    let human_name = manifest
        .text_model_name(0)
        .or_else(|| manifest.text_vendor_name(0))
        .map(str::to_string);

    let version = manifest
        .text_version(0)
        .map(str::to_string)
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| version_display.to_string());

    // Render every component id the manifest names as a slash-joined
    // segment path (component ids are arrays of bstr segments).
    let component_paths: Vec<String> = (0..manifest.component_count())
        .filter_map(|i| manifest.component_id(i))
        .map(render_component_path)
        .filter(|p| !p.is_empty())
        .collect();

    let update_name = match human_name {
        Some(name) if !version.is_empty() => Some(format!("{name} {version}")),
        Some(name) => Some(name),
        // No SUIT text name: name from the first component path + version,
        // which is still strictly better than the bare register-time id.
        None => component_paths.first().map(|p| {
            if version.is_empty() {
                p.clone()
            } else {
                format!("{p} {version}")
            }
        }),
    };

    ManifestDescribeMeta {
        update_name,
        notes: manifest.text_description().map(str::to_string),
        component_paths,
    }
}

/// Render a SUIT component id (array of byte-string segments) as a
/// slash-joined UTF-8 path. Non-UTF-8 segments are hex-encoded so the
/// result is always printable. Empty input yields an empty string.
pub(super) fn render_component_path(segments: &[Vec<u8>]) -> String {
    segments
        .iter()
        .map(|seg| match std::str::from_utf8(seg) {
            Ok(s) => s.to_string(),
            Err(_) => hex::encode(seg),
        })
        .collect::<Vec<_>>()
        .join("/")
}

// ---------------------------------------------------------------------------
// Flash session: sequential upload state machine
// ---------------------------------------------------------------------------

/// Tracks the upload state within a flash session.
///
/// After start_flash(): AwaitingManifest
/// After manifest upload: AwaitingPayload, with the parts the bank already
/// holds (kept by digest from an earlier staging) present
/// After each payload: its component present
/// After all payloads: Complete
pub(super) enum FlashSessionState {
    /// Waiting for manifest upload (first file in sequence).
    AwaitingManifest,
    /// Manifest received, waiting for the payloads still absent.
    AwaitingPayload {
        manifest_bytes: Vec<u8>,
        /// The validated manifest, parked with the session. `finalize_flash`
        /// reads its `disable_target` to route a no-payload disable manifest to
        /// the enact path instead of reconcile/activate.
        validated: ValidatedFirmware,
        /// Component indices that owe a payload (those with an `image_digest`).
        parts: Vec<usize>,
        /// Component indices whose payload the target bank holds.
        present: BTreeSet<usize>,
    },
    /// All uploads received.
    Complete,
}

/// The components of `parts` not yet `present`, in manifest order. The first
/// is the next part a sequential intake expects.
pub(super) fn absent_parts(parts: &[usize], present: &BTreeSet<usize>) -> Vec<usize> {
    parts
        .iter()
        .copied()
        .filter(|i| !present.contains(i))
        .collect()
}

/// The component of `parts` the client's `part_id` names: its payload `uri`
/// (`#kernel`), its on-medium name (`kernel`), or that name behind a `#`.
/// `None` when the id names no part of the manifest.
pub(super) fn resolve_part(
    manifest: &sumo_onboard::manifest::Manifest,
    parts: &[usize],
    part_id: &str,
) -> Option<usize> {
    let bare = part_id.strip_prefix('#').unwrap_or(part_id);
    parts.iter().copied().find(|&i| {
        manifest.uri(i) == Some(part_id)
            || crate::bank_spec::payload_target_name_for_id(manifest.component_id(i))
                .is_ok_and(|n| n == bare)
    })
}

/// Where an uploaded file_id was placed, so `verify_part` can re-confirm
/// the part's integrity post-upload.
///
/// Two flavours:
///
/// * `Manifest` — the SUIT envelope as it arrived on the wire.  Small
///   (≤100 KB), kept whole in `packages[file_id]`.  We record the
///   upload-time outer SHA-256 so verify_part can compare directly
///   against what the SOVD wire recorded during `PUT /bulk-data`.
///
/// * `OnDisk` — a detached payload.  We can't keep the raw wire bytes
///   (multi-MB; the streaming pipeline writes the decrypted +
///   decompressed *inner* content straight through the bank provider to
///   avoid doubling flash I/O).  So re-verification asks the provider to
///   re-read the staged `(bank, name)` and compare against the inner
///   SHA-256 the streaming pipeline captured at write time — which is
///   itself the manifest's declared `image_digest`, already verified
///   against ciphertext during upload.  Catches on-disk corruption
///   between upload and finalize; doesn't and can't re-verify the
///   outer-on-the-wire hash post-stream.  Stored as `(bank, name)` (not
///   a path) so the provider owns the on-medium layout.
pub(super) enum UploadedPartLocation {
    Manifest {
        upload_sha256: [u8; 32],
    },
    OnDisk {
        bank: Bank,
        name: String,
        inner_sha256: [u8; 32],
    },
}

// ---------------------------------------------------------------------------
// Flash transfer tracking
// ---------------------------------------------------------------------------

pub(super) struct FlashTransferState {
    pub(super) transfer_id: String,
    pub(super) package_id: String,
    pub(super) state: FlashState,
    /// Guest state observed before a queued VM restart. While `Verifying`, a
    /// running guest requires a changed boot id; confirmed absence accepts the
    /// first later ready boot.
    pub(super) pre_reset_health: Option<PreResetHealth>,
    pub(super) image_size: u64,
    /// `(relative_path, size, sha256)` for each payload as the streaming
    /// pipeline wrote it into the target bank dir. Lets
    /// `ivd_sign_staged_bank` build the IVD manifest without re-reading
    /// the bank from disk. Empty for the buffered (non-streaming) path
    /// and for pre-streaming-pipeline upload flows — `sign_bank` then
    /// falls back to a directory walk.
    pub(super) streamed_files: Vec<hsm::ivd::IvdFile>,
}

// ---------------------------------------------------------------------------
// Derived administrative-disable state
// ---------------------------------------------------------------------------

/// The cached answer of `ComponentBackend::admin_disabled`, guarded by an
/// epoch. A miss reads `epoch` together with `value`, derives outside the lock
/// and stores through [`store_if_epoch`](Self::store_if_epoch); a
/// [`clear`](Self::clear) in between bumps the epoch and the store is dropped.
/// Without the epoch, a status poll that read the record just before a disable
/// could cache "enabled" after the enact's clear, and keep answering it until
/// the next NV write.
#[derive(Default)]
pub(super) struct AdminStateCache {
    /// Bumped by every clear.
    pub(super) epoch: u64,
    /// `(serving bank, disabled)` as last derived; `None` = derive on the next
    /// read.
    pub(super) value: Option<(Bank, bool)>,
}

impl AdminStateCache {
    /// Invalidate: the next read re-derives, and a derivation already in flight
    /// is not stored.
    pub(super) fn clear(&mut self) {
        self.epoch += 1;
        self.value = None;
    }

    /// Store a derivation that began at epoch `observed` — only if nothing has
    /// cleared the cache since.
    pub(super) fn store_if_epoch(&mut self, observed: u64, bank: Bank, disabled: bool) {
        if self.epoch == observed {
            self.value = Some((bank, disabled));
        }
    }
}

// ---------------------------------------------------------------------------
// Component configuration
// ---------------------------------------------------------------------------

/// Where this component's logs come from — drives SOVD §7.21
/// `GET /components/{id}/logs`. `None` (the default) keeps
/// `capabilities.logs = false` and the route answers "not supported".
#[derive(Debug, Clone)]
pub enum LogSource {
    /// A guest VM: proxy the in-guest `log-agent` (guest-hal layer
    /// service) over the per-VM `guest_to_host` /30 — e.g.
    /// `http://10.0.101.2:9300`. Its `GET /logs` returns JSON records
    /// `{timestamp, priority, message, source}` (mirror-by-convention;
    /// the guest tree is a different repo).
    GuestAgent { url: String },
    /// Host-local plain files (the supernova/host component): bounded
    /// tails of every file matching the globs (only `dir/prefix*suffix`
    /// patterns — no full glob engine). Lines carry the file's mtime.
    /// These produce STANDARD (line) log entries.
    HostFiles { globs: Vec<String> },
    /// Host-local dump DIRECTORY: the §7.21 CUSTOM-log catalog. Each file
    /// in `dir` is one retrievable dump artifact (a crash dump, captured
    /// trace, …) — listed with a stable id, `size`, and `log_type`/`status`
    /// from an optional `<name>.meta.json` sidecar (else defaults). Content
    /// = the file bytes; delete = unlink the file (+ sidecar). Unlike
    /// `HostFiles` (which tails text lines), this exposes whole files as
    /// discrete downloadable entries — the message-passing pattern.
    HostDumps { dir: String },
    /// The QNX `slogger2` ring — the host system log, and the sink for everything
    /// that CAN emit to it: supernova + vhsm-ssd (via score-log-slog2) plus the OS
    /// driver/eMMC telemetry (devb_sdmmc, CAM). Read through `platform_log::read_slog2`,
    /// decoupled from the producer via the kernel-owned ring. It is ONE physical
    /// `source` (`"slog2"`); the per-buffer name is the EMITTER, surfaced in
    /// `LogEntry.fields.emitter` (not the source). Produces STANDARD (line) entries
    /// with real per-record timestamps + severities. QNX-only in effect (empty
    /// off-QNX). Logs that CANNOT reach slog2 (boot log, /var/log, shell/stderr
    /// residue) stay their own `HostFiles` sources — see the capability split in
    /// tasks/host-log-pipeline-design.md.
    Slog2,
    /// The slog2 ring PERSISTED to disk as sealed segments by the `slog2-drainer`
    /// (Tier-2 host daemon) — the durable, cursor-pageable, reboot-safe history
    /// plane the volatile ring can't offer. Read through
    /// `platform_log::read_segments` over the sealed `<stem>.<seq>.log` set in
    /// `dir` PLUS the still-growing live file `<stem>.log` in `live_dir`. The
    /// drainer keeps that live file in RAM (`/dev/shmem`) while sealing to flash
    /// (`dir`), so the two are in DIFFERENT directories — without `live_dir` the
    /// reader misses the live tail and a not-yet-sealed source reads EMPTY.
    /// `live_dir: None` means live + sealed are colocated in `dir`. The
    /// `<seq>:<offset>` cursor is reboot-safe (seq is a logical clock, independent
    /// of the non-monotonic wall clock). Surfaced as a SEPARATE source (`slog2`,
    /// the resumable timeline) from `Slog2` (the raw ring, `slog2-ring`): same bus,
    /// two planes. Tier-2 ONLY — Tier-1 never configures this.
    Slog2Segments {
        dir: String,
        stem: String,
        live_dir: Option<String>,
    },
}

/// Per-component configuration for ComponentBackend behavior.
pub struct ComponentConfig {
    /// Whether this component supports rollback (false for HSM).
    pub supports_rollback: bool,
    /// Whether this component is single-banked (true for HSM — always bank A).
    pub single_bank: bool,
    /// SOVD entity_type for component identity.
    pub entity_type: String,
    /// §7.21 log sources, queried + merged by `get_logs`. Empty = the
    /// component serves no logs (`capabilities.logs = false` → route answers
    /// "not supported"). Additive: a component may have several (e.g. host
    /// text files + a dump directory), each contributing entries to one
    /// merged, timestamp-sorted list.
    pub log_sources: Vec<LogSource>,
    /// §7.15 scripts (developer-registered TESTS): the in-guest test-agent's base
    /// URL, e.g. `http://10.0.101.2:9310`. `Some` → `list_scripts` proxies its
    /// `/tests` discovery; `None` → the component exposes no scripts. Guest-VM
    /// only today (tests aren't a host/per-component concern yet). See
    /// `tasks/sovd-tests-as-operations-design.md`.
    pub test_agent_url: Option<String>,
    /// §7.9 diagnostics: the in-guest diag-agent's base URL, e.g.
    /// `http://10.0.101.2:9320`. `Some` → the component exposes READ-ONLY system
    /// probes (mem/df/du/…) discovered + gathered by proxy; `None` → no
    /// diagnostics. Guest-VM only, same shape as `test_agent_url`. See
    /// `tasks/diag-agent-design.md`.
    pub diag_agent_url: Option<String>,
    /// §7.9 diagnostics gathered IN-PROCESS (no guest agent) — for the HOST
    /// itself (supernova) and any component that runs ON this box. `true` → the
    /// same built-in probes the guest diag-agent serves (mem/df/du:<dir>/ps/…)
    /// are gathered locally. The host has no diag-agent to proxy, so this is how
    /// its `/mnt/common-rw` disk, RAM, etc. become visible over SOVD — the gap a
    /// flash `No space left on device` exposed. Mutually complementary with
    /// `diag_agent_url` (a component is one or the other); default off.
    pub host_diagnostics: bool,
}

impl Default for ComponentConfig {
    fn default() -> Self {
        Self {
            supports_rollback: true,
            single_bank: false,
            entity_type: "vm".to_string(),
            log_sources: Vec::new(),
            test_agent_url: None,
            diag_agent_url: None,
            host_diagnostics: false,
        }
    }
}
