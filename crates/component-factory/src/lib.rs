use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::Deserialize;

use machine_mgr::Component;
use nv_store::block::BlockDevice;
use nv_store::store::NvStore;
use nv_store::types::BankSet;

use vm_mgr::backend::{ComponentBackend, ComponentConfig};
use vm_mgr::component_adapter::ComponentAdapter;
use vm_mgr::manifest_provider::ManifestProvider;
use vm_mgr::sovd::security::SecurityProvider;

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

    /// Base path for app-type components (A/B bank root with `current` symlink).
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

    /// SUIT payload-URI → filename mapping for this slot. One of:
    /// - `"vm"`: `#kernel` → `kernel`, `#qvm-config` → `qvm.conf`
    /// - `"boot-ifs"`: `#kernel` → `boot.ifs`, `#qvm-config` → `qvm.conf`
    /// - `"generic"`: pass-through (`#foo` → `foo`)
    ///
    /// Defaults to the well-known layout for the resolved BankSet.
    #[serde(default)]
    pub bank_layout: Option<String>,

    /// Bank-activator marker. When set, the caller constructs the
    /// appropriate activator and inserts it into `FactoryDeps::bank_activators`.
    /// Also suppresses vm-service notifications for this component.
    #[serde(default)]
    pub activator: Option<String>,
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
    pub security_provider: Arc<dyn SecurityProvider>,
    pub vm_service_addr: Option<String>,
    pub hsm_provider: Option<Arc<Mutex<dyn hsm::HsmProvider>>>,
    pub hsm_keystore: Option<PathBuf>,
    pub hsm_port: u16,
    /// Per-component bank activators, keyed by component id.
    /// Only components with an entry here get post-install activation.
    pub bank_activators: HashMap<String, Arc<dyn machine_mgr::BankActivator>>,
    /// Per-component synthetic health probes, keyed by component id.
    /// Used by activator-backed components that have no vm-service backing
    /// (e.g. RT/M7 surfaces `guest_state` via `m7loader -q`). VMs leave
    /// this empty and use vm-service over loopback HTTP instead.
    pub health_probes: HashMap<String, Arc<dyn vm_mgr::backend::HealthProbe>>,
    /// The node's shared, signed boot selector — the **write** handle
    /// (`SharedSystemBankState`), created once by the binary and shared with the
    /// registry. When `Some`, each built component gets a selector-aware
    /// `IvdBankProvider` for which the boot selector is the PRIMARY source for
    /// `active_bank()` / `target_bank()` (NV/symlink fallback) AND the
    /// destination the OTA path writes (`activate`/`commit`/`rollback`). `None`
    /// keeps the NV/symlink-only providers (the in-backend default) —
    /// behaviour-preserving, since the selector tracks `NvBootState` (dual-write).
    pub boot_selector: Option<machine_mgr::SharedSystemBankState>,
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

/// Resolve both the bank-set slot AND its spec (dir name + layout)
/// from a `ComponentSpec`. The slot comes from [`resolve_bank_set`];
/// the dir name and layout are taken from the explicit fields when
/// present, else defaulted via `BankSetSpec::for_well_known`.
///
/// Returns `None` if the slot can't be resolved.
pub fn resolve_bank_set_spec(
    spec: &ComponentSpec,
) -> Option<(BankSet, vm_mgr::bank_spec::BankSetSpec)> {
    let bank_set = resolve_bank_set(spec)?;
    let mut bspec = vm_mgr::bank_spec::BankSetSpec::for_well_known(bank_set);
    if let Some(ref subdir) = spec.storage_subdir {
        bspec.dir_name = subdir.clone();
    }
    if let Some(ref layout) = spec.bank_layout {
        bspec.layout = match layout.as_str() {
            "vm" => vm_mgr::bank_spec::BankLayout::Vm,
            "boot-ifs" | "bootifs" => vm_mgr::bank_spec::BankLayout::BootIfs,
            "generic" | "custom" => vm_mgr::bank_spec::BankLayout::Generic,
            other => {
                tracing::warn!(
                    component = %spec.id,
                    bank_layout = %other,
                    "unknown bank_layout — falling back to default",
                );
                bspec.layout
            }
        };
    }
    Some((bank_set, bspec))
}

/// Build a selector-aware `IvdBankProvider` mirroring the args
/// `ComponentBackend` would feed its in-backend provider, plus a **write** clone
/// of the shared boot selector from `deps` (an `Arc` clone — the provider's OTA
/// path mutates it). Returns `None` when no selector is configured (the backend
/// then keeps its own NV/symlink-only provider — behaviour-preserving).
///
/// Injected via [`vm_mgr::backend::ComponentBackend::with_bank_provider`] LAST
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
    Some(Arc::new(vm_mgr::bank_provider::IvdBankProvider::new(
        deps.nv.clone(),
        bank_set,
        single_bank,
        images_dir,
        dir_name,
        deps.hsm_provider.clone(),
        activator,
        Some(selector),
    )))
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
            };
            let app_images_dir = spec.storage_path.clone().or_else(|| spec.base_path.clone());
            let mut backend = ComponentBackend::with_options(
                bank_set,
                deps.nv.clone(),
                deps.manifest_provider.clone(),
                deps.security_provider.clone(),
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

            let fallback: Arc<dyn sovd_core::DiagnosticBackend> = backend_arc;
            let diag = vm_mgr::diag_backend::ComponentDiagBackend::new(component.clone(), fallback);

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
                entity_type: spec.component_type.clone(),
                supports_rollback: spec.rollback,
                single_bank: spec.single_bank,
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
                deps.security_provider.clone(),
                comp_config,
                vm_service,
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

            let backend_arc: Arc<ComponentBackend<_>> = Arc::new(backend);
            let mut component_inner = ComponentAdapter::new(backend_arc.clone());

            if bank_set == BankSet::Hsm {
                if let Some(ref keystore) = deps.hsm_keystore {
                    component_inner =
                        component_inner.with_csr_keystore(keystore.clone(), deps.hsm_port);
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

            let fallback: Arc<dyn sovd_core::DiagnosticBackend> = backend_arc;
            let diag = vm_mgr::diag_backend::ComponentDiagBackend::new(component.clone(), fallback);

            Some(BuiltComponent {
                component,
                diag_backend: Some(Arc::new(diag)),
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
