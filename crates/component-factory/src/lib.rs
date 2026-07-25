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

    /// Override the bank-set name this component plugs into.
    /// Resolved via `BankSet::from_str`; falls back to the id-based
    /// mapping in [`bank_set_for_id`]. Use for deployment-specific
    /// component ids that don't match a well-known id/name.
    #[serde(default)]
    pub bank_set: Option<String>,

    /// Explicit NV slot index (0..=NUM_BANK_SETS-1). Wins over both
    /// `bank_set` and id-based resolution when present. Set this
    /// when a deployment uses more than one custom slot — the slot
    /// number is the source of truth, the dir name + layout below
    /// describe what to do with it.
    #[serde(default)]
    pub slot: Option<u8>,

    /// On-disk subdirectory under `images_dir`. Defaults to the
    /// well-known dir for whichever BankSet `bank_set`/`slot`/`id`
    /// resolves to (`vm1`, `host-os`, `custom`, ...). Override when
    /// two custom slots need distinct dirs (`rt`, `co-processor`, ...).
    #[serde(default)]
    pub storage_subdir: Option<String>,

    /// Bank-activator marker. When set, the caller constructs the
    /// appropriate activator and inserts it into `FactoryDeps::bank_activators`.
    /// Also suppresses vm-service notifications for this component.
    #[serde(default)]
    pub activator: Option<String>,

    /// Human-readable display name for SOVD reads. Optional override; `None`
    /// keeps the component's default name. The binary typically reads this from
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

    /// §7.15 scripts (developer-registered TESTS): the in-guest test-agent base
    /// URL, e.g. `http://10.0.101.2:9310` (the guest-hal layer runs the agent).
    /// `Some` → `capabilities` expose a `scripts` collection proxied from its
    /// `/tests`. Guest-VM only today. See tasks/sovd-tests-as-operations-design.md.
    #[serde(default)]
    pub test_agent_url: Option<String>,
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
    /// Per-component synthetic health probes, keyed by component id.
    /// Used by activator-backed components that have no vm-service backing
    /// (e.g. RT/M7 surfaces `guest_state` via `m7loader -q`). VMs leave
    /// this empty and use vm-service over loopback HTTP instead.
    pub health_probes: HashMap<String, Arc<dyn component_mgr::backend::HealthProbe>>,
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

pub fn bank_set_for_id(id: &str) -> Option<BankSet> {
    match id {
        "hsm" => Some(BankSet::Hsm),
        "bootloader" => Some(BankSet::Bootloader),
        "os" | "host-os" | "supernova" | "app" => Some(BankSet::Os),
        "rt" => Some(BankSet::Rt),
        "vm1" => Some(BankSet::Vm1),
        "vm2" => Some(BankSet::Vm2),
        _ => None,
    }
}

/// Resolve the bank-set for a `ComponentSpec`. Priority:
/// 1. Explicit `slot:` (numeric, deployment-controlled).
/// 2. Explicit `bank_set:` name (parsed via `BankSet::from_str`).
/// 3. Id-based fallback via [`bank_set_for_id`].
///
/// Returns `None` if none resolve — caller decides whether that's
/// fatal (most components require a bank-set; pure-runtime ones can
/// be `None`).
pub fn resolve_bank_set(spec: &ComponentSpec) -> Option<BankSet> {
    if let Some(slot) = spec.slot {
        return Some(BankSet(slot));
    }
    if let Some(ref s) = spec.bank_set {
        return BankSet::from_str(s);
    }
    bank_set_for_id(&spec.id)
}

/// Resolve both the bank-set slot AND its spec (on-disk dir name)
/// from a `ComponentSpec`. The slot comes from [`resolve_bank_set`];
/// the dir name is taken from the explicit `storage_subdir` when
/// present, else defaulted via `BankSetSpec::for_well_known`.
///
/// Returns `None` if the slot can't be resolved.
pub fn resolve_bank_set_spec(
    spec: &ComponentSpec,
) -> Option<(BankSet, component_mgr::bank_spec::BankSetSpec)> {
    let bank_set = resolve_bank_set(spec)?;
    let mut bspec = component_mgr::bank_spec::BankSetSpec::for_well_known(bank_set);
    if let Some(ref subdir) = spec.storage_subdir {
        bspec.dir_name = subdir.clone();
    }
    Some((bank_set, bspec))
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
    bank_set: BankSet,
    single_bank: bool,
    images_dir: Option<PathBuf>,
    dir_name: String,
    activator: Option<Arc<dyn machine_mgr::BankActivator>>,
) -> Option<Arc<dyn machine_mgr::BankProvider>> {
    let selector = deps.boot_selector.clone()?;
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

/// Build a single component from its spec and shared dependencies.
pub fn build_component<D: BlockDevice + Send + Sync + 'static>(
    spec: &ComponentSpec,
    deps: &FactoryDeps<D>,
) -> Option<BuiltComponent> {
    let Some((bank_set, bank_spec)) = resolve_bank_set_spec(spec) else {
        tracing::warn!(
            "no bank-set for component id '{}' (no `slot:`/`bank_set:` \
             override and id doesn't match a well-known set) — skipping",
            spec.id,
        );
        return None;
    };

    match spec.component_type.as_str() {
        "app" => {
            let base_path = spec
                .base_path
                .clone()
                .unwrap_or_else(|| PathBuf::from("/data/supernova"));
            let config = app_mgr::AppConfig {
                id: spec.id.clone(),
                base_path: base_path.clone(),
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
            .with_bank_spec(bank_spec.clone());
            // Inject a selector-aware provider LAST so the boot selector drives
            // active/target bank (NV/symlink fallback). App has no activator.
            if let Some(provider) = selector_aware_provider(
                deps,
                bank_set,
                false,
                app_images_dir,
                bank_spec.dir_name.clone(),
                None,
            ) {
                backend = backend.with_bank_provider(provider);
            }
            if let Some(name) = &spec.display_name {
                backend = backend.with_display_name(name.clone());
            }
            if let Some(coord) = &deps.node_coordinator {
                backend = backend.with_node_coordinator(coord.clone());
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
            };

            let images_dir = spec.storage_path.clone();

            // Components with a bank activator (RT, co-processor) are not
            // VMs — they don't need vm-service notifications or symlink flips.
            let vm_service = if deps.bank_activators.contains_key(&spec.id) {
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
            .with_bank_spec(bank_spec.clone());

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
                bank_set,
                spec.single_bank,
                images_dir,
                bank_spec.dir_name.clone(),
                activator,
            ) {
                backend = backend.with_bank_provider(provider);
            }

            if let Some(name) = &spec.display_name {
                backend = backend.with_display_name(name.clone());
            }
            if let Some(coord) = &deps.node_coordinator {
                backend = backend.with_node_coordinator(coord.clone());
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

            if bank_set == BankSet::Hsm {
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
