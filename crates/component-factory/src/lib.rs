use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::Deserialize;

use machine_mgr::Component;
use nv_store::block::BlockDevice;
use nv_store::store::NvStore;
use nv_store::types::BankSet;

use component_mgr::backend::{ComponentBackend, ComponentConfig};
use component_mgr::component_adapter::ComponentAdapter;
use component_mgr::manifest_provider::ManifestProvider;

/// Declarative component specification — parsed from YAML config.
#[derive(Debug, Clone, Deserialize)]
pub struct ComponentSpec {
    pub id: String,

    #[serde(rename = "type")]
    pub component_type: String,

    #[serde(default = "default_true")]
    pub rollback: bool,

    #[serde(default)]
    pub single_bank: bool,

    /// Storage path for this component's firmware images / bank directories.
    #[serde(default)]
    pub storage_path: Option<PathBuf>,

    /// Base path for app-type components (A/B bank root; bank_a/bank_b live under it).
    #[serde(default)]
    pub base_path: Option<PathBuf>,

    /// RETIRED slot-name key. Kept as a field so a stale config fails loudly
    /// rather than being silently ignored: any value makes
    /// [`resolve_bank_set`] refuse the component. Set `slot:` instead.
    #[serde(default)]
    pub bank_set: Option<String>,

    /// The NV slot index this component plugs into — the ONLY source of a
    /// component's bank set, written by the platform profile. Optional in
    /// serde so a config that omits it gets a spoken error instead of a parse
    /// failure; [`resolve_bank_set`] refuses such a spec. Must be a slot the
    /// open NV store can address (its size decides how many it has);
    /// [`build_component`] refuses the component otherwise.
    #[serde(default)]
    pub slot: Option<u8>,

    /// On-disk subdirectory under `images_dir`. Defaults to the component id.
    /// Override when a component's bank dirs don't live under its own id.
    #[serde(default)]
    pub storage_subdir: Option<String>,

    /// Bank-activator marker. When set, the caller constructs the
    /// appropriate activator and inserts it into `FactoryDeps::bank_activators`.
    /// Also suppresses vm-service notifications for this component.
    #[serde(default)]
    pub activator: Option<String>,

    /// Human-readable display name for SOVD reads. Optional override; `None`
    /// defaults to the component id. The binary typically reads this from
    /// the active bank's `vm-config.yaml` and sets it here — keeping that file
    /// I/O in the caller rather than the factory.
    #[serde(default)]
    pub display_name: Option<String>,

    /// SOVD `entity_type` override. When `None`, defaults to `component_type` (the
    /// routing key). Set this to keep the reported type distinct from the factory's
    /// routing taxonomy — e.g. id "vm1" routes as "bank" but reports as "vm".
    #[serde(default)]
    pub entity_type: Option<String>,

    /// §7.21 log reads — a guest VM's in-guest log-agent URL (e.g.
    /// `http://10.0.101.2:9300`; the guest-hal layer runs the agent).
    /// Setting it flips `capabilities.logs` on for this component.
    /// Additive with `host_log_globs` / `host_dump_dir` — all configured
    /// sources are queried and merged by `get_logs`.
    #[serde(default)]
    pub log_agent_url: Option<String>,

    /// §7.21 log reads — host-local file globs (`dir/prefix*suffix`)
    /// for components whose logs live on THIS node (e.g. the supernova
    /// component: `["/var/log/*.log"]`). STANDARD (line) logs.
    #[serde(default)]
    pub host_log_globs: Option<Vec<String>>,

    /// §7.21 CUSTOM logs — a host-local dump DIRECTORY. Each file in it is a
    /// retrievable dump artifact (crash dump, trace). Additive with the above.
    #[serde(default)]
    pub host_dump_dir: Option<String>,

    /// §7.21 log reads — the QNX `slogger2` ring (the host system log), read via
    /// `platform_log::read_slog2`. `true` for the host component on QNX: it serves
    /// supernova's own records (emitted through score-log-slog2) AND the OS
    /// driver/eMMC telemetry, decoupled from the producer via the kernel-owned
    /// ring — replacing the `host_log_globs` tail of supernova.log. Additive with
    /// the above; a no-op read off QNX. STANDARD (line) logs.
    #[serde(default)]
    pub host_slog2: bool,

    /// §7.21 log reads — the directory of SEALED slog2 disk segments written by
    /// the `slog2-drainer` (Tier-2 host daemon). `Some(dir)` adds a
    /// `LogSource::Slog2Segments` — the durable, reboot-safe, cursor-pageable
    /// slog2 timeline (SOVD source `slog2`, the resumable primary), distinct from
    /// the raw volatile ring (`host_slog2` → SOVD source `slog2-ring`).
    /// TIER-2 ONLY: set only in the full `config.yaml`; the Tier-1 provisioning
    /// config never sets it (its absence keeps Tier-1 on the ring alone). The
    /// stem is fixed `"slog2"` (matches the drainer's default).
    #[serde(default)]
    pub host_slog2_segments_dir: Option<String>,

    /// Directory of the drainer's still-growing LIVE file (`slog2.log`), when it
    /// is NOT colocated with the sealed segments. The drainer keeps its live file
    /// in RAM (`/dev/shmem`) while sealing to flash (`host_slog2_segments_dir`), so
    /// the reader needs both dirs — without this the resumable `slog2` source reads
    /// EMPTY until the first seal (the live tail lives in a dir the reader doesn't
    /// scan). Defaults to the drainer's default live dir `/dev/shmem`; only override
    /// if `SLOG2_DRAINER_LIVE_DIR` was changed. Ignored unless
    /// `host_slog2_segments_dir` is set.
    #[serde(default = "default_slog2_live_dir")]
    pub host_slog2_live_dir: String,

    /// §7.15 scripts (developer-registered TESTS): the in-guest test-agent base
    /// URL, e.g. `http://10.0.101.2:9310` (the guest-hal layer runs the agent).
    /// `Some` → `capabilities` expose a `scripts` collection proxied from its
    /// `/tests`. Guest-VM only today. See tasks/sovd-tests-as-operations-design.md.
    #[serde(default)]
    pub test_agent_url: Option<String>,
    /// §7.9 diagnostics: the in-guest diag-agent base URL, e.g.
    /// `http://10.0.101.2:9320`. `Some` → `capabilities` expose a `diagnostics`
    /// collection (read-only system probes) proxied from its `/probes`. Guest-VM
    /// only, mirror of `test_agent_url`. See tasks/diag-agent-design.md.
    #[serde(default)]
    pub diag_agent_url: Option<String>,
    /// §7.9 diagnostics gathered IN-PROCESS (no guest agent) — set `true` for
    /// the HOST itself (supernova) / on-box components, so its disk/RAM
    /// (`/mnt/common-rw`, `/proc/meminfo`) are visible over SOVD. Default false.
    #[serde(default)]
    pub host_diagnostics: bool,

    /// This component fronts the node-level time attestation operation
    /// (`x-attest-time`); exactly one component per device should set it — the
    /// platform profile decides which.
    #[serde(default)]
    pub attest_time: bool,

    /// This component is a vHSM principal: after a bank commit the host arms
    /// enrollment so the guest can enroll on its next boot. The platform fills
    /// it — supernova derives it from its `hsm.allow` list.
    #[serde(default)]
    pub vm_principal: bool,
}

impl ComponentSpec {
    /// The backend [`LogSource`]s this spec asks for. Additive — a component may
    /// have a guest agent AND/OR host line-files AND/OR a host dump directory;
    /// `get_logs` queries + merges all of them.
    fn log_sources(&self) -> Vec<component_mgr::backend::LogSource> {
        use component_mgr::backend::LogSource;
        let mut sources = Vec::new();
        if let Some(url) = &self.log_agent_url {
            sources.push(LogSource::GuestAgent { url: url.clone() });
        }
        if let Some(globs) = &self.host_log_globs {
            sources.push(LogSource::HostFiles {
                globs: globs.clone(),
            });
        }
        if let Some(dir) = &self.host_dump_dir {
            sources.push(LogSource::HostDumps { dir: dir.clone() });
        }
        if self.host_slog2 {
            sources.push(LogSource::Slog2);
        }
        if let Some(dir) = &self.host_slog2_segments_dir {
            sources.push(LogSource::Slog2Segments {
                dir: dir.clone(),
                stem: "slog2".to_string(),
                live_dir: Some(self.host_slog2_live_dir.clone()),
            });
        }
        sources
    }
}

/// Result of building a component — includes the Component trait object,
/// optionally a SOVD diagnostic backend for wire-level access, an
/// optional probe that returns whether a flash session is currently
/// in flight (used by destructive ops such as factory_reset), and an
/// optional callback to drop any in-flight flash session state
/// (used by factory_reset before wiping banks).
pub struct BuiltComponent {
    pub component: Arc<dyn Component>,
    pub diag_backend: Option<Arc<dyn sovd_core::DiagnosticBackend>>,
    pub flash_probe: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    pub flash_clear: Option<Arc<dyn Fn() + Send + Sync>>,
}

/// Shared dependencies passed to the factory for all components.
pub struct FactoryDeps<D: BlockDevice> {
    pub nv: Arc<Mutex<NvStore<D>>>,
    pub manifest_provider: Arc<dyn ManifestProvider>,
    pub vm_service_addr: Option<String>,
    pub hsm_provider: Option<Arc<Mutex<dyn hsm::HsmProvider>>>,
    /// Optional crypto-only HSM handle (e.g. the host's shared link-B
    /// `LinkBClient`). When `Some`, the built `ComponentBackend` (HSM-keys
    /// provision → `HsmKeyUnwrap`), the selector-aware `IvdBankProvider`
    /// (IVD `seal`), and the HSM component's CSR adapter prefer this
    /// `HsmCryptoProvider` over the lifecycle-bearing `hsm_provider`; `None`
    /// keeps today's `dyn HsmProvider` path. Additive — defaults preserve
    /// behaviour.
    pub hsm_crypto: Option<Arc<dyn hsm::HsmCryptoProvider>>,
    pub hsm_keystore: Option<PathBuf>,
    pub hsm_port: u16,
    /// Per-component bank activators, keyed by component id.
    /// Only components with an entry here get post-install activation.
    pub bank_activators: HashMap<String, Arc<dyn machine_mgr::BankActivator>>,
    /// Per-component RAW-PARTITION bank maps, keyed by component id. A component
    /// with an entry here is a raw-partition A/B bank: it gets a
    /// [`PartitionBankProvider`] that streams the payload STRAIGHT to the eMMC
    /// partition (no staging file, no whole-image RAM read) and computes its IVD
    /// by hashing the partition back. Mutually exclusive with `bank_activators`
    /// for the same id — the partition provider owns the write, so no
    /// separate byte-copy activator is used. The host OS bank uses this today;
    /// RT/bootloader are the future consumers. Empty ⇒ the file-staging
    /// `IvdBankProvider` path (VMs, app, or an activator-backed bank).
    pub partition_parts:
        HashMap<String, Vec<component_mgr::partition_bank_provider::PartitionPart>>,
    /// Per-component synthetic health probes, keyed by component id.
    /// Used by activator-backed components that have no vm-service backing
    /// (e.g. RT/M7 surfaces `guest_state` via `m7loader -q`). VMs leave
    /// this empty and use vm-service over loopback HTTP instead.
    pub health_probes: HashMap<String, Arc<dyn component_mgr::backend::HealthProbe>>,
    /// The node's per-boot nonce (`/vehicle/v1/status/x-boot-id`). When
    /// `Some`, every built component surfaces it in `x-runtime.node_boot_id`
    /// so the offboard flash gate has an unmissable reboot witness (see
    /// `ComponentBackend::with_node_boot_id`). `None` in tests / vm-sovd.
    pub node_boot_id: Option<String>,
    /// Per-component administrative-disable enactors, keyed by component id —
    /// for activator-backed components whose deactivation is deployment-
    /// specific (RT: the m7loader erase). VMs leave this empty: any bank-type
    /// component with a vm-service behind it gets the generic
    /// vm-service-stop deactivator built by the factory itself. A component
    /// is disableable iff it ends up with a deactivator — `hsm` and `app`
    /// types never do (see `build_component`).
    pub deactivators: HashMap<String, Arc<dyn machine_mgr::Deactivator>>,
    /// The node's shared, signed boot selector — the **write** handle
    /// (`SharedSystemBankState`), created once by the binary and shared with the
    /// registry. When `Some`, each built component gets a selector-aware
    /// `IvdBankProvider` for which the boot selector is the PRIMARY source for
    /// `active_bank()` / `target_bank()` (NV/symlink fallback) AND the
    /// destination the OTA path writes (`activate`/`commit`/`rollback`). `None`
    /// keeps the NV/symlink-only providers (the in-backend default) —
    /// behaviour-preserving, since the selector tracks `NvBootState` (dual-write).
    pub boot_selector: Option<machine_mgr::SharedSystemBankState>,
    /// The node update-transaction coordinator (the "one transaction at a time"
    /// gate). When `Some`, each built component gets it via `with_node_coordinator`
    /// so its `start_flash` consults the node-wide gate; `None` leaves it inert.
    pub node_coordinator: Option<Arc<machine_mgr::node_update::NodeCoordinator>>,
    /// Optional post-provision reload hook, passed to each built component's
    /// `ComponentBackend` via `with_post_provision_reload`. When `Some`, the HSM
    /// keystore-provision path calls it INSTEAD of the provider's `stop_service()`
    /// then `start_service()` — for a link-B backend whose daemon lifecycle is
    /// owned externally. `None` (the default) keeps today's in-process provider
    /// restart.
    pub post_provision_reload: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Sink that steps the host wall clock forward to the safe-time floor after
    /// an install ratchets it. When `Some`, each built `ComponentBackend` gets it
    /// via `with_wall_clock_floor`; `None` leaves the log-only no-op default.
    /// The real host injects a clock-setting impl; tests/CI leave it `None`.
    pub wall_clock_floor: Option<Arc<dyn component_mgr::sovd::time_floor::WallClockFloor>>,
}

/// Resolve the bank-set for a `ComponentSpec`: the explicit `slot:`, and
/// nothing else. Slot NAMES were retired in v0.1.2 — the platform profile
/// writes the number, so there is no id table and no name parser left to fall
/// back to. A spec with no `slot:`, or one still carrying the retired
/// `bank_set:` key, is an operator error and says so.
pub fn resolve_bank_set(spec: &ComponentSpec) -> Result<BankSet, String> {
    if let Some(ref name) = spec.bank_set {
        return Err(format!(
            "component '{}' sets bank_set '{name}' — slot names were retired in \
             v0.1.2, set slot: N",
            spec.id,
        ));
    }
    match spec.slot {
        Some(slot) => Ok(BankSet(slot)),
        None => Err(format!(
            "component '{}' has no slot — set slot: N (slot names were retired \
             in v0.1.2)",
            spec.id,
        )),
    }
}

/// Resolve both the bank-set slot AND its spec (on-disk dir name)
/// from a `ComponentSpec`. The slot comes from [`resolve_bank_set`];
/// the dir name is the explicit `storage_subdir` when present, else
/// the component id.
pub fn resolve_bank_set_spec(
    spec: &ComponentSpec,
) -> Result<(BankSet, component_mgr::bank_spec::BankSetSpec), String> {
    let bank_set = resolve_bank_set(spec)?;
    let bspec = component_mgr::bank_spec::BankSetSpec {
        dir_name: spec
            .storage_subdir
            .clone()
            .unwrap_or_else(|| spec.id.clone()),
    };
    Ok((bank_set, bspec))
}

/// Build a selector-aware `IvdBankProvider` mirroring the args
/// `ComponentBackend` would feed its in-backend provider, plus a **write** clone
/// of the shared boot selector from `deps` (an `Arc` clone — the provider's OTA
/// path mutates it). Returns `None` when no selector is configured (the backend
/// then keeps its own NV/symlink-only provider — behaviour-preserving).
///
/// Injected via [`component_mgr::backend::ComponentBackend::with_bank_provider`] LAST
/// in the builder chain (after `with_bank_spec` / `with_bank_activator`, which
/// otherwise rebuild the default provider), so it replaces the default wholesale
/// and the override flag suppresses any later rebuild.
fn selector_aware_provider<D: BlockDevice + Send + Sync + 'static>(
    deps: &FactoryDeps<D>,
    component_id: &str,
    bank_set: BankSet,
    single_bank: bool,
    images_dir: Option<PathBuf>,
    dir_name: String,
    activator: Option<Arc<dyn machine_mgr::BankActivator>>,
) -> Option<Arc<dyn machine_mgr::BankProvider>> {
    let selector = deps.boot_selector.clone()?;

    // RAW-PARTITION bank (host OS bank; RT/bootloader later): stream straight to
    // the eMMC partition via PartitionBankProvider. The inner IvdBankProvider is
    // built with activator = None — the partition provider owns the write, so
    // activate() is the boot-selector flip only (no byte-copy). Mutually exclusive
    // with a byte-copy activator for the same id.
    if let Some(parts) = deps.partition_parts.get(component_id) {
        let inner = component_mgr::bank_provider::IvdBankProvider::new(
            deps.nv.clone(),
            bank_set,
            single_bank,
            images_dir,
            dir_name,
            deps.hsm_provider.clone(),
            None, // partition provider owns the write; no byte-copy activator
            Some(selector),
        );
        let inner = match deps.hsm_crypto.clone() {
            Some(crypto) => inner.with_hsm_crypto(crypto),
            None => inner,
        };
        let provider = component_mgr::partition_bank_provider::PartitionBankProvider::new(
            inner,
            parts.clone(),
            deps.hsm_provider.clone(),
            deps.hsm_crypto.clone(),
        );
        return Some(Arc::new(provider));
    }

    let provider = component_mgr::bank_provider::IvdBankProvider::new(
        deps.nv.clone(),
        bank_set,
        single_bank,
        images_dir,
        dir_name,
        deps.hsm_provider.clone(),
        activator,
        Some(selector),
    );
    // When a crypto-only HSM handle is configured (the host's link-B client),
    // the IVD `seal` runs its lone `sign` over `HsmCryptoProvider` instead of the
    // lifecycle-bearing `dyn HsmProvider`. `None` keeps the `hsm_provider` path.
    let provider = match deps.hsm_crypto.clone() {
        Some(crypto) => provider.with_hsm_crypto(crypto),
        None => provider,
    };
    Some(Arc::new(provider))
}

/// Refuse a component whose NV slot the open store cannot address. The store's
/// slot count comes from its device size, so a config can legitimately name a
/// slot a smaller NV file has no room for — catch it here, where the configured
/// slot first meets the store, rather than at the first bank read further down.
fn check_slot_in_range<D: BlockDevice>(
    id: &str,
    bank_set: BankSet,
    nv: &NvStore<D>,
) -> Result<(), String> {
    if nv.slot_in_range(bank_set) {
        return Ok(());
    }
    Err(format!(
        "component '{id}' uses NV slot {} but this store has {} slots ({} bytes) \
         — recreate the store larger or fix the slot",
        bank_set.as_index(),
        nv.slot_count(),
        nv.device().size(),
    ))
}

/// Build a single component from its spec and shared dependencies.
pub fn build_component<D: BlockDevice + Send + Sync + 'static>(
    spec: &ComponentSpec,
    deps: &FactoryDeps<D>,
) -> Option<BuiltComponent> {
    let (bank_set, bank_spec) = match resolve_bank_set_spec(spec) {
        Ok(resolved) => resolved,
        Err(msg) => {
            tracing::error!("{msg}");
            return None;
        }
    };

    if let Err(msg) = check_slot_in_range(&spec.id, bank_set, &deps.nv.lock().unwrap()) {
        tracing::error!("{msg}");
        return None;
    }

    match spec.component_type.as_str() {
        "app" => {
            let base_path = spec
                .base_path
                .clone()
                .unwrap_or_else(|| PathBuf::from("/data/supernova"));
            let config = app_mgr::AppConfig {
                id: spec.id.clone(),
                base_path: base_path.clone(),
                slot: bank_set,
            };
            let comp = app_mgr::AppComponent::new(config, deps.nv.clone());
            let bank = comp.boot_check();
            tracing::info!(bank = ?bank, path = %base_path.display(), "app: boot check complete");

            let comp_config = ComponentConfig {
                entity_type: "app".into(),
                supports_rollback: spec.rollback,
                single_bank: false,
                log_sources: spec.log_sources(),
                test_agent_url: spec.test_agent_url.clone(),
                diag_agent_url: spec.diag_agent_url.clone(),
                host_diagnostics: spec.host_diagnostics,
            };
            let app_images_dir = spec.storage_path.clone().or_else(|| spec.base_path.clone());
            let mut backend = ComponentBackend::with_options(
                bank_set,
                deps.nv.clone(),
                deps.manifest_provider.clone(),
                comp_config,
                deps.vm_service_addr.clone(),
                app_images_dir.clone(),
                deps.hsm_provider.clone(),
            )
            .with_id(spec.id.clone())
            .with_bank_spec(bank_spec.clone())
            // Node-level meanings that used to ride on slot numbers, now
            // declared per component by the platform profile.
            .with_attest_time(spec.attest_time)
            .with_vm_principal(spec.vm_principal);
            // Inject a selector-aware provider LAST so the boot selector drives
            // active/target bank (NV/symlink fallback). App has no activator.
            if let Some(provider) = selector_aware_provider(
                deps,
                &spec.id,
                bank_set,
                false,
                app_images_dir,
                bank_spec.dir_name.clone(),
                None,
            ) {
                backend = backend.with_bank_provider(provider);
            }
            backend = backend
                .with_display_name(spec.display_name.clone().unwrap_or_else(|| spec.id.clone()));
            if let Some(coord) = &deps.node_coordinator {
                backend = backend.with_node_coordinator(coord.clone());
            }
            if let Some(nb) = &deps.node_boot_id {
                backend = backend.with_node_boot_id(nb.clone());
            }
            if let Some(reload) = &deps.post_provision_reload {
                backend = backend.with_post_provision_reload(reload.clone());
            }
            if let Some(sink) = &deps.wall_clock_floor {
                backend = backend.with_wall_clock_floor(sink.clone());
            }
            if let Some(crypto) = &deps.hsm_crypto {
                backend = backend.with_hsm_crypto(crypto.clone());
            }
            let backend_arc: Arc<ComponentBackend<_>> = Arc::new(backend);
            let component: Arc<dyn Component> = Arc::new(comp);

            let flash_probe: Arc<dyn Fn() -> bool + Send + Sync> = {
                let b = backend_arc.clone();
                Arc::new(move || b.flash_in_progress())
            };
            let flash_clear: Arc<dyn Fn() + Send + Sync> = {
                let b = backend_arc.clone();
                Arc::new(move || b.clear_flash_session())
            };

            // The `app` component has its OWN install/flash lifecycle
            // (`AppComponent`: app-mgr A/B symlink flip) that is NOT the VM
            // bank flow `ComponentBackend` implements — so it's the
            // install-router case: route install/flash through the `Component`
            // and delegate data/faults/modes to the engine (`backend_arc`).
            let engine: Arc<dyn sovd_core::DiagnosticBackend> = backend_arc;
            let diag = component_mgr::install_router_diag::InstallRouterDiag::new(
                component.clone(),
                engine,
            );

            Some(BuiltComponent {
                component,
                diag_backend: Some(Arc::new(diag)),
                flash_probe: Some(flash_probe),
                flash_clear: Some(flash_clear),
            })
        }
        // `bank` is the canonical name for "bank-managed Component, launch
        // is the deployment's problem" — VMs (vm-service notifies via
        // `notify_vm_service` based on `vm_service_addr`, not the type
        // string), RT side, future containers, anything generic. `hpc`
        // (host OS) and `hsm` get the same ComponentAdapter shape but
        // with extra hooks attached below (IFS activator / HSM
        // provisioning).
        "bank" | "hpc" | "hsm" => {
            let comp_config = ComponentConfig {
                entity_type: spec
                    .entity_type
                    .clone()
                    .unwrap_or_else(|| spec.component_type.clone()),
                supports_rollback: spec.rollback,
                single_bank: spec.single_bank,
                log_sources: spec.log_sources(),
                test_agent_url: spec.test_agent_url.clone(),
                diag_agent_url: spec.diag_agent_url.clone(),
                host_diagnostics: spec.host_diagnostics,
            };

            let images_dir = spec.storage_path.clone();

            // Components with a bank activator (RT, co-processor) OR a raw-partition
            // map (the host OS bank — PartitionBankProvider) are NOT VMs: they don't
            // have a vm-service backing, so they must not be given vm_service_addr.
            // Otherwise read_entity_status queries vm-service for a VM of this id
            // (which doesn't exist) → notReady, and the flash health gate fails even
            // on a healthy node. (Regression when host moved from HostBankActivator
            // in bank_activators to partition_parts — it lost its "not a VM" marker.)
            let vm_service = if deps.bank_activators.contains_key(&spec.id)
                || deps.partition_parts.contains_key(&spec.id)
            {
                None
            } else {
                deps.vm_service_addr.clone()
            };

            let mut backend = ComponentBackend::with_options(
                bank_set,
                deps.nv.clone(),
                deps.manifest_provider.clone(),
                comp_config,
                vm_service.clone(),
                images_dir.clone(),
                deps.hsm_provider.clone(),
            )
            .with_id(spec.id.clone())
            .with_bank_spec(bank_spec.clone())
            // Node-level meanings that used to ride on slot numbers, now
            // declared per component by the platform profile.
            .with_attest_time(spec.attest_time)
            .with_vm_principal(spec.vm_principal);

            let activator = deps.bank_activators.get(&spec.id).cloned();
            if let Some(ref a) = activator {
                backend = backend.with_bank_activator(a.clone());
            }
            if let Some(probe) = deps.health_probes.get(&spec.id) {
                backend = backend.with_health_probe(probe.clone());
            }

            // Structural disableability: a component is administratively
            // disableable iff it leaves the factory with a Deactivator — no
            // name list anywhere; the op handler's 400 falls out of the
            // absence. Only the generic `bank` type qualifies: an injected
            // deployment deactivator wins (activator-backed rt — its
            // vm_service is None, so it never gets the VM one), otherwise a
            // VM (has a vm-service to stop it) gets the generic
            // vm-service-stop deactivator built here. `hsm` (the security
            // anchor) and `hpc` (the host itself — the manager can't stop
            // its own node) are never equipped, and neither is `app` in the
            // arm above.
            let deactivator: Option<Arc<dyn machine_mgr::Deactivator>> =
                if spec.component_type == "bank" {
                    match deps.deactivators.get(&spec.id) {
                        Some(d) => Some(d.clone()),
                        None => vm_service.as_ref().map(|addr| {
                            Arc::new(component_mgr::vm_deactivator::VmDeactivator::new(
                                addr.clone(),
                                spec.id.clone(),
                            )) as Arc<dyn machine_mgr::Deactivator>
                        }),
                    }
                } else {
                    None
                };
            if let Some(d) = deactivator {
                backend = backend.with_deactivator(d);
            }
            // Inject a selector-aware provider LAST (after with_bank_spec /
            // with_bank_activator, which would otherwise rebuild the default):
            // the boot selector drives active/target bank, NV/symlink fallback.
            // Mirrors the same activator the backend would use.
            if let Some(provider) = selector_aware_provider(
                deps,
                &spec.id,
                bank_set,
                spec.single_bank,
                images_dir,
                bank_spec.dir_name.clone(),
                activator,
            ) {
                backend = backend.with_bank_provider(provider);
            }

            backend = backend
                .with_display_name(spec.display_name.clone().unwrap_or_else(|| spec.id.clone()));
            if let Some(coord) = &deps.node_coordinator {
                backend = backend.with_node_coordinator(coord.clone());
            }
            if let Some(nb) = &deps.node_boot_id {
                backend = backend.with_node_boot_id(nb.clone());
            }
            if let Some(reload) = &deps.post_provision_reload {
                backend = backend.with_post_provision_reload(reload.clone());
            }
            if let Some(sink) = &deps.wall_clock_floor {
                backend = backend.with_wall_clock_floor(sink.clone());
            }
            if let Some(crypto) = &deps.hsm_crypto {
                backend = backend.with_hsm_crypto(crypto.clone());
            }
            let backend_arc: Arc<ComponentBackend<_>> = Arc::new(backend);
            let mut component_inner = ComponentAdapter::new(backend_arc.clone());

            if spec.component_type == "hsm" {
                if let Some(ref keystore) = deps.hsm_keystore {
                    component_inner = component_inner.with_csr_keystore(keystore.clone());
                }
                // Prefer the crypto-only link-B handle for CSR / list-keys /
                // device-id when configured; `with_csr_crypto` wins over the
                // keystore fallback inside the adapter. `None` keeps the
                // keystore-only path (dev / no link-B).
                if let Some(ref crypto) = deps.hsm_crypto {
                    component_inner = component_inner.with_csr_crypto(crypto.clone());
                }
            }

            let component: Arc<dyn Component> = Arc::new(component_inner);

            let flash_probe: Arc<dyn Fn() -> bool + Send + Sync> = {
                let b = backend_arc.clone();
                Arc::new(move || b.flash_in_progress())
            };
            let flash_clear: Arc<dyn Fn() + Send + Sync> = {
                let b = backend_arc.clone();
                Arc::new(move || b.clear_flash_session())
            };

            // `bank`/`hpc`/`hsm` install/flash lives natively on
            // `ComponentBackend` (the `ComponentAdapter` above delegates its
            // install methods 1:1 back to this same backend), so wire the
            // engine directly as the SOVD `DiagnosticBackend`. The
            // `ComponentAdapter` still goes into the registry as the
            // `Component` view (orthogonal to SOVD).
            let diag_backend: Arc<dyn sovd_core::DiagnosticBackend> = backend_arc;

            Some(BuiltComponent {
                component,
                diag_backend: Some(diag_backend),
                flash_probe: Some(flash_probe),
                flash_clear: Some(flash_clear),
            })
        }
        other => {
            tracing::warn!("unknown component type '{other}' for id '{}'", spec.id);
            None
        }
    }
}

fn default_true() -> bool {
    true
}

/// The slog2-drainer's default live-file directory (`SLOG2_DRAINER_LIVE_DIR`
/// default). The reader looks here for the still-growing `slog2.log` when it isn't
/// colocated with the sealed segments.
pub fn default_slog2_live_dir() -> String {
    "/dev/shmem".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nv_store::block::MemBlockDevice;
    use nv_store::store::nv_device_size;

    fn spec_on_slot(id: &str, slot: u8) -> ComponentSpec {
        ComponentSpec {
            id: id.to_string(),
            component_type: "bank".to_string(),
            rollback: true,
            single_bank: false,
            storage_path: None,
            base_path: None,
            bank_set: None,
            slot: Some(slot),
            storage_subdir: None,
            activator: None,
            display_name: None,
            entity_type: None,
            log_agent_url: None,
            host_log_globs: None,
            host_dump_dir: None,
            host_slog2: false,
            host_slog2_segments_dir: None,
            host_slog2_live_dir: default_slog2_live_dir(),
            test_agent_url: None,
            diag_agent_url: None,
            host_diagnostics: false,
            attest_time: false,
            vm_principal: false,
        }
    }

    fn ten_slot_deps() -> FactoryDeps<MemBlockDevice> {
        FactoryDeps {
            nv: Arc::new(Mutex::new(NvStore::new(MemBlockDevice::new(
                nv_device_size(10) as usize,
            )))),
            manifest_provider: Arc::new(
                component_mgr::suit_provider::SuitProvider::with_factory_authority(),
            ),
            vm_service_addr: None,
            hsm_provider: None,
            hsm_crypto: None,
            hsm_keystore: None,
            hsm_port: 5100,
            bank_activators: HashMap::new(),
            partition_parts: HashMap::new(),
            health_probes: HashMap::new(),
            node_boot_id: None,
            deactivators: HashMap::new(),
            boot_selector: None,
            node_coordinator: None,
            post_provision_reload: None,
            wall_clock_floor: None,
        }
    }

    /// A configured slot the store has no room for is an operator error, not a
    /// runtime surprise: refuse the component at build time and say exactly what
    /// to do about it.
    #[test]
    fn slot_beyond_the_store_is_refused_with_an_actionable_message() {
        let deps = ten_slot_deps();
        let nv = deps.nv.lock().unwrap();

        assert_eq!(
            check_slot_in_range("co-processor", BankSet(12), &nv).unwrap_err(),
            "component 'co-processor' uses NV slot 12 but this store has 10 slots \
             (1048576 bytes) — recreate the store larger or fix the slot"
        );
        // The last slot this store owns is fine; one past it is not.
        assert!(check_slot_in_range("rt", BankSet(9), &nv).is_ok());
    }

    #[test]
    fn build_component_skips_a_component_on_an_unaddressable_slot() {
        let deps = ten_slot_deps();
        assert!(build_component(&spec_on_slot("co-processor", 12), &deps).is_none());
        // Same spec on an addressable slot still builds.
        assert!(build_component(&spec_on_slot("co-processor", 9), &deps).is_some());
    }

    /// The slot comes from the platform profile and nowhere else: a spec that
    /// omits it is refused by name, not quietly landed on whatever slot its id
    /// used to imply.
    #[test]
    fn a_spec_without_a_slot_is_refused_by_name() {
        let mut spec = spec_on_slot("vm1", 4);
        spec.slot = None;

        assert_eq!(
            resolve_bank_set(&spec).unwrap_err(),
            "component 'vm1' has no slot — set slot: N (slot names were retired in v0.1.2)"
        );
        assert!(build_component(&spec, &ten_slot_deps()).is_none());
    }

    /// A config still carrying the retired `bank_set:` name must fail loudly —
    /// the factory no longer reads it, and silently ignoring it would put the
    /// component on a slot the operator never asked for.
    #[test]
    fn a_spec_still_naming_a_bank_set_is_refused_by_name() {
        let mut spec = spec_on_slot("host", 2);
        spec.bank_set = Some("os".to_string());

        assert_eq!(
            resolve_bank_set(&spec).unwrap_err(),
            "component 'host' sets bank_set 'os' — slot names were retired in v0.1.2, set slot: N"
        );
        assert!(build_component(&spec, &ten_slot_deps()).is_none());
    }

    #[test]
    fn the_bank_dir_defaults_to_the_component_id() {
        let mut spec = spec_on_slot("co-processor", 9);
        assert_eq!(
            resolve_bank_set_spec(&spec).unwrap().1.dir_name,
            "co-processor"
        );

        spec.storage_subdir = Some("rt".to_string());
        assert_eq!(resolve_bank_set_spec(&spec).unwrap().1.dir_name, "rt");
    }

    #[test]
    fn the_display_name_defaults_to_the_component_id() {
        let deps = ten_slot_deps();
        let mut spec = spec_on_slot("vm1", 4);

        let built = build_component(&spec, &deps).unwrap();
        assert_eq!(built.diag_backend.unwrap().entity_info().name, "vm1");

        spec.display_name = Some("Infotainment".to_string());
        let built = build_component(&spec, &deps).unwrap();
        assert_eq!(
            built.diag_backend.unwrap().entity_info().name,
            "Infotainment"
        );
    }

    #[test]
    fn attest_time_and_vm_principal_default_off_and_parse_on() {
        let bare: ComponentSpec = serde_yaml::from_str("id: vm1\ntype: bank\nslot: 4\n").unwrap();
        assert!(!bare.attest_time);
        assert!(!bare.vm_principal);

        let set: ComponentSpec = serde_yaml::from_str(
            "id: vm1\ntype: bank\nslot: 4\nattest_time: true\nvm_principal: true\n",
        )
        .unwrap();
        assert!(set.attest_time);
        assert!(set.vm_principal);
    }

    /// The HSM CSR/keystore wiring follows the DECLARED component type, not the
    /// slot number it happens to sit on — `with_csr_keystore` is what flips the
    /// adapter's `hsm` capability, so the capability is the observable.
    #[test]
    fn the_hsm_csr_wiring_follows_the_component_type() {
        let mut deps = ten_slot_deps();
        deps.hsm_keystore = Some(PathBuf::from("/tmp/vhsm-keys"));

        let mut spec = spec_on_slot("keystore", 0);
        spec.component_type = "hsm".to_string();
        spec.single_bank = true;
        let built = build_component(&spec, &deps).unwrap();
        assert!(built.component.capabilities().hsm.is_some());

        // Same id, same slot, plain `bank` type: no CSR wiring.
        spec.component_type = "bank".to_string();
        let built = build_component(&spec, &deps).unwrap();
        assert!(built.component.capabilities().hsm.is_none());
    }
}
