//! ComponentBackend — DiagnosticBackend implementation for component-mgr bank sets.
//!
//! Each instance manages one bank set (hypervisor, vm1, vm2, hsm) and provides:
//!
//! - Parameter read/write via NV DIDs
//! - Fault (DTC) management
//! - SUIT-based firmware flash with A/B banking
//!
//! Layout (one engine, split by responsibility; every submodule is an extra
//! `impl` block or a set of free helpers on the same private state):
//!
//! - `mod.rs`         — `ComponentBackend` struct, constructors/builders, accessors, NV lock helpers
//! - `types.rs`       — `ComponentConfig`, `LogSource`, staging/flash/admin-cache record types
//! - `flash.rs`       — upload staging and the flash session state machine
//! - `bank_ops.rs`    — bank identity/activation/commit/rollback, admin state, time floor
//! - `diagnostic.rs`  — the `DiagnosticBackend` trait impl (thin dispatch into the above)
//! - `did_registry.rs`— DID table and DID <-> JSON conversion
//! - `health.rs`      — guest health probe
//! - `agents.rs`      — guest log/test/diag agent HTTP clients and host diag helpers
//! - `logs.rs`        — host file / slog2 log readers, paging cursor, log-id codecs
//! - `tests/`         — scenario tests (`use super::super::*` reaches all private state)

#![allow(
    clippy::large_enum_variant,
    clippy::doc_lazy_continuation,
    clippy::match_like_matches_macro
)]
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
// `OnceLock` caches the process-wide boot_epoch (read+bumped once at first
// paged-log request); `Path`/`BTreeMap` back the reboot-safe log cursor in `logs.rs`.
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::OnceLock;

use async_trait::async_trait;
use chrono::Utc;

use nv_store::block::BlockDevice;
use nv_store::store::NvStore;
use nv_store::types::*;

use sovd_core::backend::*;
use sovd_core::error::{BackendError, BackendResult};
use sovd_core::models::*;
use sovd_core::PackageStream;

use machine_mgr::bank_provider::{
    BankError, BankProvider, FirmwareIdentity, InstalledFirmware, StagedPart, StagingRecord,
};

use crate::bank_provider::IvdBankProvider;
use crate::did;
use crate::lifecycle::GuestLifecycle;
use crate::manifest_provider::{ManifestProvider, ManifestType, ValidatedFirmware};
use crate::ota;
use machine_mgr::types::{RuntimeState, RuntimeStatus};

mod agents;
mod bank_ops;
mod diagnostic;
mod did_registry;
mod flash;
mod health;
mod logs;
#[cfg(test)]
mod tests;
mod types;

pub(crate) use did_registry::{did_value_to_json, is_identity_did, resolve_param, DID_REGISTRY};
pub use health::{GuestHealth, HealthProbe};
pub(crate) use types::sink_error;
pub use types::{
    ComponentConfig, LogSource, ATTEST_TIME_OP_ID, INSTALLED_MANIFEST_PARAM_ID,
    UPDATE_MODE_PARAM_ID,
};

use agents::*;
use did_registry::*;
use health::*;
use logs::*;
use types::*;

// ---------------------------------------------------------------------------
// ComponentBackend
// ---------------------------------------------------------------------------

pub struct ComponentBackend<D: BlockDevice + Send + 'static> {
    entity_info: EntityInfo,
    capabilities: Capabilities,
    bank_set: BankSet,
    /// Per-slot behavioral data (on-disk dir, SUIT-URI → filename
    /// layout). The constructors default it to an index-derived
    /// `slot<N>` dir; component-factory supplies the deployment's own
    /// via `with_bank_spec`.
    bank_spec: crate::bank_spec::BankSetSpec,
    config: ComponentConfig,
    nv: Arc<Mutex<NvStore<D>>>,
    /// The node-level update-transaction coordinator (the "one transaction at a
    /// time" gate), shared across every component on this node. `None` until
    /// `vm-sovd` injects it via [`with_node_coordinator`](Self::with_node_coordinator);
    /// when set, `ensure_flash_can_start` consults it. See `machine_mgr::node_update`
    /// + docs/design/node-update-state.md.
    node_coordinator: Option<Arc<machine_mgr::node_update::NodeCoordinator>>,
    manifest_provider: Arc<dyn ManifestProvider>,
    packages: Mutex<HashMap<String, StoredPackage>>,
    manifests: Mutex<HashMap<String, StoredManifest>>,
    payloads: Mutex<HashMap<String, StoredPayload>>,
    /// Records every uploaded file_id's storage location for later
    /// per-part re-verification (SOVDd `/executions{verify}`). Manifest
    /// uploads point at the in-memory `packages` entry; detached
    /// payloads point at the on-disk bank-dir file.
    uploaded_parts: Mutex<HashMap<String, UploadedPartLocation>>,
    flash_session: Mutex<Option<FlashSessionState>>,
    flash_transfer: Mutex<Option<FlashTransferState>>,
    /// Session-scoped pull source (untrusted CAS base URL + trust anchor) for
    /// installs whose manifest references payloads by
    /// content-addressed URI. Set by the pull route BEFORE `start_flash` via
    /// [`set_install_source`](Self::set_install_source); cleared when the
    /// session ends (`clear_flash_session` / successful `finalize_flash`).
    /// Never set on the push path.
    install_source: Mutex<Option<machine_mgr::InstallSource>>,
    /// The client's id for the update being staged, when the executor was
    /// told it: written into the staging record at each manifest and part, and
    /// from there sealed into the bank. `None` until something sets it
    /// ([`set_update_id`](Self::set_update_id), or the client's registration
    /// through `note_update_id`); an abort clears it.
    update_id: Mutex<Option<String>>,
    /// The bank the ECU is actually running on. Only changes on ecu_reset().
    /// NV active_bank may differ after install (it's the "next boot" bank).
    running_bank: Mutex<Bank>,
    next_id: Mutex<u64>,
    /// Optional TCP address ("host:port") for vm-service control API.
    /// When set, ecu_reset() POSTs to vm-service to restart the VM.
    /// Loopback only — same locality boundary as the prior Unix-socket
    /// path, but TCP avoids `tokio::net::UnixListener::accept()` not
    /// waking up reliably on QNX 7.1.
    vm_service_addr: Option<String>,
    /// Optional images directory — when set, firmware payloads are written
    /// to {images_dir}/{set}-{bank}.img during flash. Required for real
    /// image-based OTA (e.g. QEMU rootfs swap).
    images_dir: Option<PathBuf>,
    /// Tracks upload phase for activation state reporting.
    /// Set to Transferring during receive_package_stream so the campaign
    /// viewer can see that a firmware download is in progress.
    upload_phase: Mutex<Option<FlashState>>,
    /// Optional HSM provider — when set, HSM key material manifests
    /// (component_id `["hsm", "keys"]`) are routed to this provider
    /// instead of being written as a disk image.
    hsm_provider: Option<Arc<Mutex<dyn hsm::HsmProvider>>>,
    /// Crypto handle (e.g. the host's shared link-B `LinkBClient`, or a SimHsm).
    /// The HSM-keys provision path builds the CEK `HsmKeyUnwrap` via `from_crypto`
    /// so device-decryption unwrap routes through `HsmCryptoProvider`. Required
    /// once the HSM is provisioned — the provision path errors without it.
    /// Threaded from `FactoryDeps::hsm_crypto` via
    /// [`with_hsm_crypto`](Self::with_hsm_crypto).
    hsm_crypto: Option<Arc<dyn hsm::HsmCryptoProvider>>,
    /// Advertise the device-global `x-attest-time` operation on this
    /// component. Device-global means exactly one component carries it —
    /// the platform decides which and says so via
    /// [`with_attest_time`](Self::with_attest_time). Needs an HSM (the
    /// floor slot) too, so the op is only listed when both hold.
    attest_time: bool,
    /// This component is a vm principal: after `commit_flash` it arms
    /// in-band enrolment so the guest can run HELLO → ENROLL_ASSISTED
    /// against vhsm-ssd. Set via
    /// [`with_vm_principal`](Self::with_vm_principal); off for
    /// everything that has no guest identity to enrol.
    vm_principal: bool,
    /// Sink that steps the host wall clock forward to the safe-time floor after
    /// an install ratchets it (see [`crate::sovd::time_floor`]). Defaults to the
    /// log-only [`NoopWallClockFloor`]; the real host injects a clock-setting
    /// impl via [`with_wall_clock_floor`](Self::with_wall_clock_floor).
    wall_clock_floor: Arc<dyn crate::sovd::time_floor::WallClockFloor>,
    /// Synthetic health source — consulted by `read_data` for
    /// `guest_state` / `heartbeat_seq` when `vm_service_addr` is None.
    /// Set via `with_health_probe` (typically by the host machine manager for the
    /// RT component, wrapping `m7loader -q`). VMs leave this as None
    /// and use the vm-service HTTP path instead.
    health_probe: Option<Arc<dyn HealthProbe>>,
    /// The node's per-boot nonce (`/vehicle/v1/status/x-boot-id`), injected
    /// by the binary via [`with_node_boot_id`](Self::with_node_boot_id). Surfaced
    /// in `x-runtime.node_boot_id` on EVERY component's status so the offboard
    /// flash gate has an UNMISSABLE reboot witness: it changes on every node reboot
    /// (fresh supernova process) and is durable state, unlike the transient SOVD
    /// down→up window a fast reboot can slip through. The per-component heartbeat
    /// `boot_id` (u32) stays as the VM/RT per-lifetime witness; this is the
    /// node-wide one for no-heartbeat components (host-os). `None` in tests / where
    /// unset (field simply omitted from the status then).
    node_boot_id: Option<String>,
    /// In-memory cache of all NV-backed DID values. Populated at startup
    /// and updated atomically whenever NV is written (under the NV mutex
    /// + cache write lock). Reads bypass NV entirely — eliminates the
    /// 1-2 second per-call latency observed on QNX/eMMC during flash
    /// when the NV mutex is contended with write operations. RwLock so
    /// the campaign viewer's parallel-poll-of-many-DIDs runs concurrent.
    /// Keyed by raw 16-bit DID number.
    did_cache: std::sync::RwLock<std::collections::HashMap<u16, Vec<u8>>>,
    /// SUIT-derived Table-261 facts for uploaded manifests, keyed by the
    /// `file_id` the upload returned. Populated when the `"manifest"` part
    /// arrives; read by `describe_update_package` (via the diag adapter) to
    /// enrich `GET /updates/{id}`. Cleared with the rest of the flash
    /// session in `clear_flash_session` / `start_flash`.
    manifest_describe: Mutex<HashMap<String, ManifestDescribeMeta>>,
    /// Signature-verified IVD manifest of the RUNNING/committed bank,
    /// cached so the diagnostics reads that need it — the identity-DID
    /// overlay (`verified_bank_identity`) and the vendor
    /// `x-ota-installed-manifest` data parameter — share a single verify
    /// pass rather than re-reading + re-verifying CBOR on every SOVD call.
    ///
    /// `(bank, installed)`: the bank the cached firmware was read for, so a
    /// running-bank flip (ecu_reset) is detected and re-verified. `Arc` so
    /// readers clone cheaply without holding the lock across the JSON
    /// build. Invalidated to `None` on every NV write via
    /// `NvWriteGuard::drop` (same trigger as `did_cache`); the next reader
    /// re-populates lazily.
    verified_manifest_cache: Mutex<Option<(Bank, Arc<InstalledFirmware>)>>,
    /// The administrative-disable state [`admin_disabled`](Self::admin_disabled)
    /// derived, as `(serving bank, disabled)`, so a status poll costs a lock
    /// instead of a record read + HSM verify. LAZY: empty at construction, the
    /// first reader derives it. BANK-KEYED: a serving-bank flip (activate,
    /// rollback, ecu_reset) misses and re-derives. Cleared on every NV write, at
    /// the same point as `verified_manifest_cache`; the clear bumps an epoch so
    /// a derivation in flight across it is not stored (see [`AdminStateCache`]).
    admin_disabled_cache: Mutex<AdminStateCache>,
    /// The per-kind A/B storage + lifecycle seam — the engine's ONLY bank
    /// handle. Owns every bank touch: target selection, prepare/seed, payload
    /// sinks, IVD seal, installed-firmware read-back, activator-then-flip
    /// activation, commit/rollback, reset-kind. Built as an `IvdBankProvider`
    /// in `with_options` (and rebuilt by the `with_bank_spec` /
    /// `with_bank_activator` builders, which change its inputs); a later phase
    /// moves construction to component-factory. The concrete type is no longer
    /// retained — a non-IVD provider (e.g. RT raw-partition) drops in here
    /// without touching the engine.
    bank_provider: Arc<dyn BankProvider>,
    /// Set by [`Self::with_bank_provider`] when an explicit provider has been
    /// injected. While `true`, [`Self::rebuild_bank_provider`] is a no-op so a
    /// later `with_bank_spec` / `with_bank_activator` in the builder chain does
    /// NOT clobber the override with a fresh `IvdBankProvider`. Builder order
    /// therefore matters: call `with_bank_spec` / `with_bank_activator` (which
    /// feed an `IvdBankProvider`) FIRST, then `with_bank_provider` LAST to
    /// replace the whole provider — anything after `with_bank_provider` that
    /// would rebuild is intentionally ignored.
    bank_provider_override: bool,
    /// The part names this component's bank DECLARES, when its provider holds a
    /// fixed set (a raw-partition bank's `parts:` map). `Some` ⇒ a manifest
    /// naming anything else is refused at MANIFEST time, before a payload byte
    /// is uploaded — the provider would refuse the sink anyway, but only after
    /// the operator had pushed the whole image. `None` (file-backed banks) ⇒
    /// the provider takes any name and nothing is pre-checked. Injected by
    /// component-factory alongside the partition provider.
    declared_parts: Option<BTreeSet<String>>,
    /// The bank activator the (non-overridden) default `IvdBankProvider` is
    /// rebuilt with. Stored so a later `with_hsm_crypto` rebuild (which threads
    /// the crypto handle into the default provider) preserves the activator set
    /// by an earlier `with_bank_activator`. `None` until `with_bank_activator`.
    bank_activator: Option<Arc<dyn machine_mgr::BankActivator>>,
    /// Optional hook invoked after a successful HSM keystore provision (the
    /// `finalize_flash` HSM path) so the orchestrator reloads the backend against
    /// the freshly-written keystore. The HSM daemon's lifecycle is owned
    /// externally now (the host spawns the link-B backend), so this is the only
    /// reload path — there is no in-process daemon restart. `None` (the default)
    /// skips the reload. Threaded from `FactoryDeps::post_provision_reload` via
    /// [`with_post_provision_reload`](Self::with_post_provision_reload).
    post_provision_reload: Option<Arc<dyn Fn() + Send + Sync>>,
    /// The administrative-disable enactment seam — stops/erases this
    /// component's runtime when the operator disables it. Its PRESENCE is what
    /// makes the component disableable (structural, no name list): `None` ⇒
    /// [`is_disableable`](Self::is_disableable) is false and a disable request
    /// answers "component does not support administrative disable". Injected by
    /// component-factory via [`with_deactivator`](Self::with_deactivator): VMs
    /// get the generic vm-service-stop deactivator, RT gets the
    /// deployment-injected erase, hsm/app/host-os never get one. The persisted
    /// disable itself is the serving bank's signed sentinel record, written and
    /// read through the bank provider.
    deactivator: Option<Arc<dyn machine_mgr::Deactivator>>,
    /// SOVD §7.15 script (test) executions, keyed by exec_id. A guest test-agent
    /// run is SYNCHRONOUS — `start_script` proxies `POST /tests/{id}/run`, which
    /// blocks until the test finishes, so the [`ScriptExecution`] stored here is
    /// already terminal (`status = Done`). `get_script_execution` /
    /// `list_script_executions` read it back for the SOVD 202+poll surface.
    /// In-memory only (like the SOVDd operation-executions cache); a restart
    /// drops history — acceptable, a test run is re-runnable.
    script_executions: Mutex<HashMap<String, ScriptExecution>>,
    /// Monotonic counter feeding the exec_id (`<script_id>-<n>`). No `rand` in
    /// this cross-QNX tree, so a per-backend atomic gives a stable, unique-per-
    /// process id without an external dep.
    script_exec_seq: AtomicU64,
}

impl<D: BlockDevice + Send + 'static> ComponentBackend<D> {
    pub fn new(
        bank_set: BankSet,
        nv: Arc<Mutex<NvStore<D>>>,
        manifest_provider: Arc<dyn ManifestProvider>,
        config: ComponentConfig,
    ) -> Self {
        Self::with_options(bank_set, nv, manifest_provider, config, None, None, None)
    }

    pub fn with_vm_service(
        bank_set: BankSet,
        nv: Arc<Mutex<NvStore<D>>>,
        manifest_provider: Arc<dyn ManifestProvider>,
        config: ComponentConfig,
        vm_service_addr: Option<String>,
    ) -> Self {
        Self::with_options(
            bank_set,
            nv,
            manifest_provider,
            config,
            vm_service_addr,
            None,
            None,
        )
    }

    pub fn with_options(
        bank_set: BankSet,
        nv: Arc<Mutex<NvStore<D>>>,
        manifest_provider: Arc<dyn ManifestProvider>,
        config: ComponentConfig,
        vm_service_addr: Option<String>,
        images_dir: Option<PathBuf>,
        hsm_provider: Option<Arc<Mutex<dyn hsm::HsmProvider>>>,
    ) -> Self {
        // Neutral fallbacks for the direct-constructor path (tests): a slot
        // knows its index and nothing else, so the id is derived from it and
        // the display name defaults to the id. There is no slot→name table —
        // a component's id comes from the platform profile, never from the
        // slot it happens to occupy. The factory always supplies `spec.id` via
        // `with_id` (and a display name via `with_display_name`), which then
        // wins — so the registry key and the verdict/entity id share one
        // source of truth.
        let id = format!("slot{}", bank_set.as_index());
        let desc = format!("bank slot {}", bank_set.as_index());

        // Read the current active bank at startup — this is what we're running on.
        let running_bank = if config.single_bank {
            Bank::A // single-banked components always run on bank A
        } else {
            let nv_guard = nv.lock().unwrap();
            nv_guard
                .read_boot_state()
                .map(|s| s.banks[bank_set.as_index()].active_bank)
                .unwrap_or(Bank::A)
        };

        // Build the initial bank provider from the same nv/bank_set/images_dir/
        // hsm it holds (activator still None here; `with_bank_activator` rebuilds
        // it, as does `with_bank_spec` for the dir name). Clones the Arcs — the
        // struct literal below moves the originals into the backend's fields.
        // Neutral default dir: the factory always supplies the real one (the
        // component's `storage_subdir` or its id) via `with_bank_spec`.
        let bank_spec = crate::bank_spec::BankSetSpec {
            dir_name: format!("slot{}", bank_set.as_index()),
        };
        let bank_provider: Arc<dyn BankProvider> = Arc::new(IvdBankProvider::new(
            nv.clone(),
            bank_set,
            config.single_bank,
            images_dir.clone(),
            bank_spec.dir_name.clone(),
            hsm_provider.clone(),
            None,
            // No boot selector here: the backend's inline provider keeps the
            // NV/symlink path. component-factory builds a selector-aware
            // `IvdBankProvider` and injects it via `with_bank_provider`.
            None,
        ));

        let backend = Self {
            entity_info: EntityInfo {
                id: id.clone(),
                name: id.clone(),
                entity_type: config.entity_type.clone(),
                description: Some(desc),
                href: format!("/vehicle/v1/components/{id}"),
                status: None,
            },
            capabilities: Capabilities {
                read_data: true,
                write_data: true,
                faults: true,
                clear_faults: true,
                software_update: true,
                io_control: false,
                // Native SOVD server: privileged writes are authorized by the
                // JWT bearer token at the sovd-api layer — the UDS
                // session/security (seed/key) surface is retired.
                sessions: false,
                security: false,
                sub_entities: false,
                subscriptions: false,
                // §7.21: only components with a configured log source
                // serve logs; the rest keep the "not supported" answer.
                logs: !config.log_sources.is_empty(),
                operations: false,
                // §7.20: the `/bulk-data` routes are gated on this. We expose a
                // `logs` bulk-data category when the component has downloadable
                // log FILES — either host-local (HostFiles) or a guest VM whose
                // log-agent serves `/files` (GuestAgent). Mirror
                // list_bulk_data_categories' condition exactly.
                bulk_data: config.log_sources.iter().any(|s| {
                    matches!(
                        s,
                        LogSource::HostFiles { .. } | LogSource::GuestAgent { .. }
                    )
                }),
                // §7.9: read-only system probes — proxied from a guest's
                // diag-agent (diag_agent_url, guest VMs) OR gathered in-process
                // (host_diagnostics, the host itself). Either turns the
                // capability on.
                diagnostics: config.diag_agent_url.is_some() || config.host_diagnostics,
                // §7.12: no configuration resources on a banked component —
                // its settable state is DIDs (§7.5 data) and the update
                // lifecycle, not a `/configurations` collection. The trait
                // defaults answer "not supported"; keep the capability off so
                // the routes are never advertised.
                configurations: false,
            },
            bank_set,
            bank_spec,
            config,
            nv,
            manifest_provider,
            packages: Mutex::new(HashMap::new()),
            uploaded_parts: Mutex::new(HashMap::new()),
            manifests: Mutex::new(HashMap::new()),
            payloads: Mutex::new(HashMap::new()),
            flash_session: Mutex::new(None),
            flash_transfer: Mutex::new(None),
            install_source: Mutex::new(None),
            update_id: Mutex::new(None),
            running_bank: Mutex::new(running_bank),
            next_id: Mutex::new(1),
            vm_service_addr,
            images_dir,
            upload_phase: Mutex::new(None),
            hsm_provider,
            // Defaults to the `dyn HsmProvider` path; component-factory injects a
            // crypto-only handle via `with_hsm_crypto` when link-B is configured.
            hsm_crypto: None,
            attest_time: false,
            vm_principal: false,
            wall_clock_floor: Arc::new(crate::sovd::time_floor::NoopWallClockFloor),
            health_probe: None,
            node_boot_id: None,
            did_cache: std::sync::RwLock::new(std::collections::HashMap::new()),
            manifest_describe: Mutex::new(HashMap::new()),
            verified_manifest_cache: Mutex::new(None),
            admin_disabled_cache: Mutex::new(AdminStateCache::default()),
            bank_provider,
            bank_provider_override: false,
            declared_parts: None,
            bank_activator: None,
            node_coordinator: None,
            post_provision_reload: None,
            deactivator: None,
            script_executions: Mutex::new(HashMap::new()),
            script_exec_seq: AtomicU64::new(1),
        };
        // Populate DID cache from NV once at construction time. After this,
        // SOVD reads of NV-backed DIDs hit RAM only — see refresh_did_cache.
        {
            let nv_guard = backend.nv.lock().unwrap();
            backend.refresh_did_cache_locked(&*nv_guard);
        }
        backend
    }

    /// Override the component display name (shown in SOVD component listing).
    pub fn with_display_name(mut self, name: String) -> Self {
        self.entity_info.name = name;
        self
    }

    /// Carry the device-global `x-attest-time` operation on this component.
    /// The op ratchets the shared safe-time floor, so it is advertised ONCE
    /// per device — the platform says which component hosts it, instead of a
    /// slot identity deciding. Needs an HSM as well (the floor lives there).
    pub fn with_attest_time(mut self, on: bool) -> Self {
        self.attest_time = on;
        self
    }

    /// Mark this component a vm principal: `commit_flash` then arms in-band
    /// enrolment so the freshly promoted guest can run HELLO →
    /// ENROLL_ASSISTED against vhsm-ssd. Off for components with no guest
    /// identity of their own.
    pub fn with_vm_principal(mut self, on: bool) -> Self {
        self.vm_principal = on;
        self
    }

    /// Override the component id (and its self-`href`) with the configured
    /// component id — the single source of truth. The factory threads
    /// `spec.id` here so the SOVD registry key and the verdict / entity id
    /// agree by construction (previously the id came only from the bank-set
    /// table in `with_options`, which could diverge from the config id). An
    /// empty id is a no-op: the bank-set table's legacy id stands, preserving
    /// direct-constructor uses (tests) that don't thread one.
    pub fn with_id(mut self, id: String) -> Self {
        if !id.is_empty() {
            self.entity_info.href = format!("/vehicle/v1/components/{id}");
            self.entity_info.id = id;
        }
        self
    }

    /// Inject the node's per-boot nonce (`/vehicle/v1/status/x-boot-id`).
    /// Surfaced in `x-runtime.node_boot_id` so the offboard flash gate has an
    /// unmissable reboot witness (changes every node reboot; durable, unlike the
    /// transient down→up window a fast reboot slips through). The binary hands the
    /// SAME nonce to every component.
    pub fn with_node_boot_id(mut self, node_boot_id: String) -> Self {
        self.node_boot_id = Some(node_boot_id);
        self
    }

    /// Inject the shared node update-transaction coordinator (the `start_flash`
    /// gate). `vm-sovd` builds ONE coordinator and hands the same `Arc` to every
    /// component on the node, so the gate sees one node-wide staging state. See
    /// `machine_mgr::node_update::NodeCoordinator`.
    pub fn with_node_coordinator(
        mut self,
        coordinator: Arc<machine_mgr::node_update::NodeCoordinator>,
    ) -> Self {
        self.node_coordinator = Some(coordinator);
        self
    }

    /// Set the post-provision reload hook. When set, the HSM provision path
    /// (`finalize_flash`) calls it after provisioning so the orchestrator reloads
    /// the externally-owned HSM daemon (e.g. the link-B backend) against the new
    /// keystore. Leaving it unset (the default) skips the reload — there is no
    /// in-process daemon restart. Threaded from `FactoryDeps::post_provision_reload`.
    pub fn with_post_provision_reload(mut self, reload: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.post_provision_reload = Some(reload);
        self
    }

    /// Inject the crypto handle (e.g. the host's shared link-B `LinkBClient`, or
    /// a SimHsm). The HSM-keys provision path builds the CEK `HsmKeyUnwrap` via
    /// `from_crypto` so device-decryption unwrap routes through
    /// `HsmCryptoProvider`. Required once the HSM is provisioned — the provision
    /// path errors without it. Threaded from `FactoryDeps::hsm_crypto`.
    pub fn with_hsm_crypto(mut self, crypto: Arc<dyn hsm::HsmCryptoProvider>) -> Self {
        self.hsm_crypto = Some(crypto);
        // Thread the crypto handle into the (non-overridden) default bank
        // provider so its IVD `seal` can sign — preserving any activator set by
        // an earlier `with_bank_activator`. A `with_bank_provider` override
        // already carries its own crypto handle, so this rebuild is skipped then.
        self.rebuild_bank_provider();
        self
    }

    /// Inject the wall-clock-floor sink. The real host passes a clock-setting
    /// impl so an install that ratchets the safe-time floor also steps
    /// `CLOCK_REALTIME` forward to it; the default is the log-only no-op.
    pub fn with_wall_clock_floor(
        mut self,
        sink: Arc<dyn crate::sovd::time_floor::WallClockFloor>,
    ) -> Self {
        self.wall_clock_floor = sink;
        self
    }

    /// Override the bank-set spec (on-disk dir + URI→filename layout).
    /// Constructors default to an index-derived `slot<N>` dir;
    /// component-factory uses this to inject the deployment-config-driven
    /// value (`storage_subdir`, else the component id).
    pub fn with_bank_spec(mut self, spec: crate::bank_spec::BankSetSpec) -> Self {
        self.bank_spec = spec;
        // The provider keys its on-disk layout off `bank_spec.dir_name`; rebuild
        // it so a deployment-supplied dir name takes effect. `with_bank_spec`
        // precedes `with_bank_activator` in the builder order, so no activator is
        // stored yet (`self.bank_activator` is still `None`).
        self.rebuild_bank_provider();
        self
    }

    /// Set a bank activator for post-install bank activation.
    pub fn with_bank_activator(mut self, activator: Arc<dyn machine_mgr::BankActivator>) -> Self {
        // The provider owns the activator (used by `activate` + `reset_kind`).
        // Store it so later rebuilds (e.g. `with_hsm_crypto`) keep it, then
        // rebuild so the just-set activator is the one the provider invokes.
        // Must be called AFTER `with_bank_spec`.
        self.bank_activator = Some(activator);
        self.rebuild_bank_provider();
        self
    }

    /// Rebuild the bank provider from the backend's current bank-relevant state
    /// (`bank_activator` + `hsm_crypto` included) and re-point the `dyn` handle at
    /// the new object. Called by the `with_bank_spec` / `with_bank_activator` /
    /// `with_hsm_crypto` builders that change its inputs. `running_bank` is
    /// re-seeded from NV inside the provider — idempotent at construction.
    fn rebuild_bank_provider(&mut self) {
        // An explicit provider injected via `with_bank_provider` wins: never
        // rebuild over it. `with_bank_spec` / `with_bank_activator` /
        // `with_hsm_crypto` calls that land after the override are silently
        // no-ops on the provider (their other side effects still apply).
        if self.bank_provider_override {
            return;
        }
        let mut provider = IvdBankProvider::new(
            self.nv.clone(),
            self.bank_set,
            self.config.single_bank,
            self.images_dir.clone(),
            self.bank_spec.dir_name.clone(),
            self.hsm_provider.clone(),
            self.bank_activator.clone(),
            // No boot selector on the rebuild path: a selector-aware provider
            // is injected wholesale via `with_bank_provider` (which sets the
            // override so this rebuild is skipped). Keeps the NV/symlink path
            // for the default in-backend provider + tests.
            None,
        );
        // Thread the crypto handle so the default provider's IVD `seal` can sign.
        if let Some(crypto) = self.hsm_crypto.clone() {
            provider = provider.with_hsm_crypto(crypto);
        }
        self.bank_provider = Arc::new(provider);
    }

    /// Replace the default `IvdBankProvider` with an explicit `BankProvider`
    /// (e.g. the host machine manager's RT raw-partition provider). Sets the override flag
    /// so a subsequent `rebuild_bank_provider` (triggered by `with_bank_spec` /
    /// `with_bank_activator`) does NOT clobber it.
    ///
    /// **Builder order:** call `with_bank_spec` and `with_bank_activator` FIRST
    /// (they rebuild the default `IvdBankProvider` and set `bank_spec`), then
    /// `with_bank_provider` LAST to swap in the explicit provider. Any rebuild-
    /// triggering builder placed after this is intentionally ignored.
    pub fn with_bank_provider(mut self, provider: Arc<dyn BankProvider>) -> Self {
        self.bank_provider = provider;
        self.bank_provider_override = true;
        self
    }

    /// Declare the parts this component's bank holds — the names its provider
    /// will accept as payload sinks (a raw-partition bank's `parts:` map).
    /// Paired with a provider that refuses anything else, so the manifest-time
    /// refusal and the sink-time refusal agree. Leaving it unset keeps the
    /// take-any-name behaviour file-backed banks rely on.
    pub fn with_declared_parts(mut self, parts: impl IntoIterator<Item = String>) -> Self {
        self.declared_parts = Some(parts.into_iter().collect());
        self
    }

    /// Set a synthetic health probe used by `read_data` for `guest_state`
    /// / `heartbeat_seq` when the component has no vm-service backing
    /// (activator-backed components like RT/M7). Wraps something like
    /// `m7loader -q` with internal caching to keep the SOVD hot path
    /// cheap. Returning `None` from the probe → `guest_state = "offline"`.
    pub fn with_health_probe(mut self, probe: Arc<dyn HealthProbe>) -> Self {
        self.health_probe = Some(probe);
        self
    }

    /// Equip this component with its administrative-disable enactment
    /// (`Deactivator`) — which is what MAKES it disableable (see the field
    /// docs). Disable is now driven by a signed SUIT *disable* manifest (the
    /// serving bank's signed sentinel record is the authority — see
    /// `enact_disable_manifest` / `admin_disabled`), NOT the retired
    /// `x-sumo-admin-state` operation.
    /// Threaded from `FactoryDeps::deactivators` / built by component-factory.
    pub fn with_deactivator(mut self, deactivator: Arc<dyn machine_mgr::Deactivator>) -> Self {
        self.deactivator = Some(deactivator);
        self.capabilities.operations = true;
        self
    }

    fn next_id(&self) -> String {
        let mut id = self.next_id.lock().unwrap();
        let v = *id;
        *id += 1;
        v.to_string()
    }

    /// Re-read every NV-backed DID and atomically replace the in-memory
    /// cache. Caller must already hold the NV mutex (passed as `nv`) so
    /// the NV-read side is consistent with concurrent writers.
    ///
    /// **Build-then-swap**: the new cache is built WITHOUT holding the
    /// cache lock, so concurrent readers keep hitting the old cache
    /// during the slow per-DID NV scan. Only the final HashMap swap is
    /// done under the cache write lock — that's a single pointer move
    /// in `mem::replace`, microseconds. This avoids the 2-second
    /// reader-block we had with `clear() + insert(...)` under lock.
    ///
    /// Health DIDs (guest_state, heartbeat_seq) are deliberately NOT
    /// cached — they go through `query_vm_health` which is already a
    /// fast in-memory loopback HTTP read against vm-service.
    ///
    /// Called from:
    /// - `with_options` (one-shot at startup)
    /// - automatic `NvWriteGuard::drop` after every NV write
    /// - factory_reset (full re-population)
    fn refresh_did_cache_locked(&self, nv: &NvStore<D>) {
        let rb = *self.running_bank.lock().unwrap();

        // Invalidate the verified-manifest cache in lock-step with the DID
        // cache. This is the single funnel for both startup and every NV
        // write (`NvWriteGuard::drop`), so dropping it here covers
        // install/commit/ecu_reset. The identity overlay below re-populates
        // it via `verified_bank_identity`; the vendor
        // `x-ota-installed-manifest` reader re-populates lazily on demand.
        *self
            .verified_manifest_cache
            .lock()
            .expect("verified_manifest_cache poisoned") = None;
        // Same funnel for the derived admin-disable state — cleared only, never
        // re-derived here: deriving it takes the NV mutex this caller holds.
        self.admin_disabled_cache
            .lock()
            .expect("admin_disabled_cache poisoned")
            .clear();

        // Build the new map outside any cache lock — readers proceed
        // against the old map throughout this loop.
        let mut new_cache: std::collections::HashMap<u16, Vec<u8>> =
            std::collections::HashMap::with_capacity(DID_REGISTRY.len());
        for entry in DID_REGISTRY.iter() {
            // Skip health DIDs — sourced from vm-service, not NV.
            if entry.did == did::DID_GUEST_STATE || entry.did == did::DID_HEARTBEAT_SEQ {
                continue;
            }
            if let did::DidValue::Bytes(bytes) =
                did::read_did(nv, self.bank_set, entry.did, Some(rb))
            {
                new_cache.insert(entry.did, bytes);
            }
        }

        // Overlay the SW-identity DIDs (F187-F19E) from the running
        // bank's signature-verified IVD manifest — the single source for
        // these now that they're out of NvFwMeta. `read_did` returns
        // NotFound for them above, so this is the only insert. Verifying
        // the signature here (once per NV write / boot, not per SOVD read)
        // keeps `read_data` on the cheap in-RAM path while still proving
        // the served identity is the one the device signed. Invalidation
        // is automatic: every install/commit/ecu_reset refreshes through
        // this function via `NvWriteGuard::drop`.
        for (did, bytes) in self.identity_did_bytes(rb) {
            new_cache.insert(did, bytes);
        }

        // Atomic swap — lock held for a single move, microseconds.
        *self.did_cache.write().expect("did_cache poisoned") = new_cache;
    }

    /// Acquire the NV mutex with a write-side guard that automatically
    /// refreshes the DID cache when the guard drops.
    ///
    /// **Use this for every NV write site.** Readers can keep using
    /// `self.nv.lock()` directly — they don't need the refresh. Writers
    /// MUST go through this so the cache stays in sync; forgetting to
    /// refresh on a callsite would silently leave stale DID values
    /// served via SOVD. Pushing the refresh into `Drop` makes it
    /// impossible to forget.
    ///
    /// The refresh runs while the NV mutex is still held, so a reader
    /// scheduled after the write sees the new cache atomically with
    /// the new NV state. After the refresh, the mutex drops in the
    /// normal way.
    fn nv_write(&self) -> BackendResult<NvWriteGuard<'_, D>> {
        let inner = self
            .nv
            .lock()
            .map_err(|_| BackendError::Internal("nv lock poisoned".into()))?;
        Ok(NvWriteGuard {
            backend: self,
            inner: Some(inner),
        })
    }

    // =================================================================
    // Accessors used by component_adapter::ComponentAdapter.
    // Kept narrow on purpose — the adapter is the only outside caller.
    // =================================================================

    pub fn entity_info(&self) -> &EntityInfo {
        &self.entity_info
    }

    /// SUIT-derived Table-261 facts cached for the manifest uploaded under
    /// `file_id`, if any. Returns `(update_name, notes, component_paths)`:
    ///
    /// * `update_name` — human name + version (or component-path + version).
    /// * `notes` — SUIT text description.
    /// * `component_paths` — slash-joined SUIT component-id segment paths.
    ///
    /// `None` when no manifest was cached for that `file_id` (e.g. the part
    /// was a detached payload, or the envelope failed to parse) — the
    /// describe path then keeps the format-agnostic default. Owned clones so
    /// the caller never holds the cache lock across `.await`.
    pub fn manifest_describe_facts(
        &self,
        file_id: &str,
    ) -> Option<(Option<String>, Option<String>, Vec<String>)> {
        let cache = self.manifest_describe.lock().ok()?;
        cache.get(file_id).map(|m| {
            (
                m.update_name.clone(),
                m.notes.clone(),
                m.component_paths.clone(),
            )
        })
    }

    pub fn component_config(&self) -> &ComponentConfig {
        &self.config
    }

    /// The bank provider every bank touch routes through (the default
    /// `IvdBankProvider`, or the one set by [`Self::with_bank_provider`]).
    pub fn bank_provider(&self) -> &Arc<dyn BankProvider> {
        &self.bank_provider
    }

    pub fn bank_set(&self) -> BankSet {
        self.bank_set
    }

    /// The `committed` DID (`0xFD01`) from the bank report: `1` unless the
    /// component is in trial. PRECONDITION: never call with the NV mutex held —
    /// the report may take it.
    pub fn committed_did_bytes(&self) -> Vec<u8> {
        vec![u8::from(
            !self.bank_provider.banks().is_some_and(|b| b.in_trial),
        )]
    }

    /// "Rebooted since arming" from the NV update session (the armed boot id
    /// recorded by [`Self::set_reboot_owed`]) — the node's fallback when no
    /// boot vector is wired. Holds the NV store, not the backend.
    pub fn nv_rebooted_probe(&self) -> machine_mgr::node_update::RebootedProbe {
        let nv = self.nv.clone();
        Arc::new(move |boot_id| {
            nv.lock()
                .ok()?
                .read_update_session()
                .unwrap_or_default()
                .rebooted_since_arming(boot_id)
        })
    }

    /// The shared node update-transaction coordinator, when injected via
    /// [`Self::with_node_coordinator`].
    pub fn node_coordinator(&self) -> Option<&Arc<machine_mgr::node_update::NodeCoordinator>> {
        self.node_coordinator.as_ref()
    }

    pub fn has_vm_service(&self) -> bool {
        self.vm_service_addr.is_some()
    }

    /// A `HealthProbe` is the health source for components with no vm-service
    /// behind them (RT/M7 via `m7loader -q`). Runtime state is observable for
    /// those too, which is why `derive_capabilities` must not key
    /// `has_runtime_state` on vm-service alone.
    pub fn has_health_probe(&self) -> bool {
        self.health_probe.is_some()
    }

    pub fn has_hsm_provider(&self) -> bool {
        self.hsm_provider.is_some()
    }

    pub fn nv_lock(
        &self,
    ) -> Result<
        std::sync::MutexGuard<'_, NvStore<D>>,
        std::sync::PoisonError<std::sync::MutexGuard<'_, NvStore<D>>>,
    > {
        self.nv.lock()
    }

    pub fn nv_lock_mut(
        &self,
    ) -> Result<
        std::sync::MutexGuard<'_, NvStore<D>>,
        std::sync::PoisonError<std::sync::MutexGuard<'_, NvStore<D>>>,
    > {
        self.nv.lock()
    }

    /// Returns the HSM provisioning state if an HSM provider is wired up.
    /// `None` if no provider configured.
    pub fn hsm_provisioning_state(&self) -> Option<Result<hsm::ProvisioningState, hsm::HsmError>> {
        self.hsm_provider
            .as_ref()
            .map(|p| p.lock().unwrap().provisioning_state())
    }

    pub(crate) fn nv_bytes_to_string(data: &[u8]) -> String {
        let end = data.iter().position(|&c| c == 0).unwrap_or(data.len());
        String::from_utf8_lossy(&data[..end]).to_string()
    }

    /// Build the `?bank=` query suffix for the vm-service notify URL.
    /// `Some(Bank::A)` ⇒ `"?bank=a"`, `Some(Bank::B)` ⇒ `"?bank=b"`,
    /// `None` ⇒ `""` (vm-service then leaves its `def.bank` untouched).
    fn bank_query(bank: Option<Bank>) -> &'static str {
        match bank {
            Some(Bank::A) => "?bank=a",
            Some(Bank::B) => "?bank=b",
            None => "",
        }
    }

    /// Send a restart request to vm-service over its Unix socket.
    ///
    /// Reads back the HTTP status line so axum gets a chance to fully
    /// process the request before our side closes the socket. Earlier
    /// versions of this dropped the stream right after `write_all`,
    /// which raced under campaign load: when the orchestrator issues
    /// vm1+vm2 resets in parallel, the two `notify_vm_service` calls
    /// arrived back-to-back; axum sometimes saw EOF before parsing the
    /// second request, so vm1 never got started.
    ///
    /// vm-service's `restart_vm` returns 200 the moment it has
    /// initiated the restart (it does NOT wait for QEMU to fully boot),
    /// so this read is bounded — the orchestrator still polls
    /// activation state separately to know when the guest is healthy.
    ///
    /// `action` is the URL verb: "restart" when the VM was already running
    /// (graceful PowerCommand::Shutdown → start), or "start" when the VM
    /// was offline pre-reset (factory provision, post-crash) so callers
    /// don't pay for a phantom shutdown step and the GUI doesn't display
    /// a misleading "Shutting Down vm2" tile for a guest that never ran.
    async fn notify_vm_service(
        addr: &str,
        vm_name: &str,
        action: &str,
        bank: Option<Bank>,
    ) -> Result<(), String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|e| format!("connect to vm-service: {e}"))?;

        // Carry the just-activated bank as a `?bank=` query so vm-service
        // re-resolves the launch bank (via `set_vm_bank`) before relaunching.
        // Absent ⇒ vm-service leaves its `def.bank` untouched (back-compat).
        let query = Self::bank_query(bank);
        let request = format!(
            "POST /vms/{vm_name}/{action}{query} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Length: 0\r\n\
             Connection: close\r\n\
             \r\n"
        );

        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("write to vm-service: {e}"))?;

        // Read the status line (with a generous timeout — the handler
        // returns once restart is initiated, ~100s of ms).
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(15), stream.read(&mut buf))
            .await
            .map_err(|_| "vm-service didn't respond within 15s".to_string())?
            .map_err(|e| format!("read from vm-service: {e}"))?;

        let resp = String::from_utf8_lossy(&buf[..n]);
        let status_line = resp.lines().next().unwrap_or("(empty)");
        if status_line.contains("200") {
            Ok(())
        } else {
            Err(format!("vm-service returned: {status_line}"))
        }
    }
}

// ---------------------------------------------------------------------------
// NvWriteGuard — RAII wrapper around the NV mutex for write sites.
//
// Holds the NV mutex for as long as the guard lives. On drop, refreshes
// the DID cache before releasing the mutex — so callers don't have to
// remember to call refresh_did_cache_locked at every write site, and
// readers that wake up after the mutex drops always see a cache
// consistent with the just-written NV state.
//
// Use `ComponentBackend::nv_write()` to acquire. Read sites should keep using
// `self.nv.lock()` directly — they don't need the refresh, and going
// through the guard would do useless work.
// ---------------------------------------------------------------------------

struct NvWriteGuard<'a, D: BlockDevice + Send + 'static> {
    backend: &'a ComponentBackend<D>,
    /// `Option` so `Drop` can take it via `Option::take()` and refresh
    /// against the unwrapped guard before releasing the mutex.
    inner: Option<std::sync::MutexGuard<'a, NvStore<D>>>,
}

impl<'a, D: BlockDevice + Send + 'static> std::ops::Deref for NvWriteGuard<'a, D> {
    type Target = NvStore<D>;
    fn deref(&self) -> &NvStore<D> {
        self.inner.as_ref().expect("guard active")
    }
}

impl<'a, D: BlockDevice + Send + 'static> std::ops::DerefMut for NvWriteGuard<'a, D> {
    fn deref_mut(&mut self) -> &mut NvStore<D> {
        self.inner.as_mut().expect("guard active")
    }
}

impl<'a, D: BlockDevice + Send + 'static> Drop for NvWriteGuard<'a, D> {
    fn drop(&mut self) {
        if let Some(ref guard) = self.inner {
            // Refresh while still holding the mutex — readers waking up
            // after this point see new NV + new cache, never half-state.
            self.backend.refresh_did_cache_locked(&**guard);
        }
        // `inner` drops normally → mutex released.
    }
}

// ---------------------------------------------------------------------------
// DiagnosticBackend implementation
// ---------------------------------------------------------------------------

fn guest_state_str(state: u32) -> &'static str {
    match state {
        0 => "booting",
        1 => "running",
        2 => "degraded",
        3 => "shutting_down",
        _ => "unknown",
    }
}
