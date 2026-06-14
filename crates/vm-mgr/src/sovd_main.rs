use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use nv_store::block::FileBlockDevice;
use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
use nv_store::types::{BankSet, NvBootState};

use sovd_core::DiagnosticBackend;

use vm_mgr::app_install_router::AppInstallRouterComponent;
use vm_mgr::backend::{ComponentBackend, ComponentConfig};
use vm_mgr::component_adapter::ComponentAdapter;
use vm_mgr::install_router_diag::InstallRouterDiag;
use vm_mgr::sovd::security::TestSecurityProvider;
use vm_mgr::suit_provider::SuitProvider;

use machine_mgr::{Machine, MachineRegistry};
use sovd_core::EntityInfo;

use hsm::sim::SimHsm;
use hsm::{HsmProvider, KeyRole};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=debug".parse().unwrap()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: vm-sovd <nv-store-path> [options] [bind-addr]");
        eprintln!();
        eprintln!("Positional:");
        eprintln!("  nv-store-path              NV store file (created if missing)");
        eprintln!();
        eprintln!("Options:");
        eprintln!("  --images-dir <path>        Directory for A/B bank image files (enables real image OTA)");
        eprintln!("  --vm-service-socket <path> Unix socket / TCP address for vm-service lifecycle control");
        eprintln!("  --hsm-daemon <path>        Path to vhsm-test-ssd binary");
        eprintln!("  --hsm-keystore <path>      HSM keystore directory (default: /tmp/vhsm-keys)");
        eprintln!("  --hsm-port <port>          HSM TCP port (default: 5100)");
        eprintln!("  --boot-device <path>       Boot partition block device for IFS activation (e.g. /dev/hd0t177)");
        eprintln!("  --boot-mount <path>        Boot partition mount point (default: /mnt/boot)");
        eprintln!("  --sw-authority <path>      Software authority COSE_Key file (bypasses HSM, dev/test only)");
        eprintln!("  bind-addr                  Listen address (default: 0.0.0.0:4000)");
        eprintln!();
        eprintln!("Provisioning authority: built-in factory signing key (P-256 generator G).");
        eprintln!("Software authority and device key loaded from HSM after provisioning.");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  vm-sovd /tmp/nv.bin");
        eprintln!(
            "  vm-sovd /data/nv.bin --images-dir /data/images --hsm-keystore /data/vhsm-keys"
        );
        std::process::exit(1);
    }

    let nv_path = PathBuf::from(&args[1]);

    // Parse remaining args
    let mut images_dir: Option<PathBuf> = None;
    let mut vm_service_addr: Option<String> = None;
    let mut hsm_daemon_path: Option<PathBuf> = None;
    let mut hsm_keystore_path = PathBuf::from("/tmp/vhsm-keys");
    let mut hsm_port: u16 = 5100;
    let mut boot_device: Option<String> = None;
    let mut boot_mount = PathBuf::from("/mnt/boot");
    let mut sw_authority_path: Option<PathBuf> = None;
    let mut bind_addr = "0.0.0.0:4000";
    let mut i = 2;
    while i < args.len() {
        if args[i] == "--images-dir" && i + 1 < args.len() {
            images_dir = Some(PathBuf::from(&args[i + 1]));
            i += 2;
        } else if args[i] == "--vm-service-socket" && i + 1 < args.len() {
            vm_service_addr = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "--hsm-daemon" && i + 1 < args.len() {
            hsm_daemon_path = Some(PathBuf::from(&args[i + 1]));
            i += 2;
        } else if args[i] == "--hsm-keystore" && i + 1 < args.len() {
            hsm_keystore_path = PathBuf::from(&args[i + 1]);
            i += 2;
        } else if args[i] == "--hsm-port" && i + 1 < args.len() {
            hsm_port = args[i + 1].parse().unwrap_or_else(|_| {
                eprintln!("invalid --hsm-port: {}", args[i + 1]);
                std::process::exit(1);
            });
            i += 2;
        } else if args[i] == "--boot-device" && i + 1 < args.len() {
            boot_device = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "--boot-mount" && i + 1 < args.len() {
            boot_mount = PathBuf::from(&args[i + 1]);
            i += 2;
        } else if args[i] == "--sw-authority" && i + 1 < args.len() {
            sw_authority_path = Some(PathBuf::from(&args[i + 1]));
            i += 2;
        } else {
            bind_addr = &args[i];
            i += 1;
        }
    }

    let provider = SuitProvider::with_factory_authority();
    let manifest_provider = Arc::new(provider);
    let security_provider = Arc::new(TestSecurityProvider);

    // Open/create NV store
    let dev = if nv_path.exists() {
        FileBlockDevice::open(&nv_path).expect("failed to open NV store")
    } else {
        tracing::info!("creating NV store: {}", nv_path.display());
        FileBlockDevice::create(&nv_path, MIN_NV_DEVICE_SIZE).expect("failed to create NV store")
    };

    let mut nv = NvStore::new(dev);
    if nv.read_boot_state().is_none() {
        let mut state = NvBootState::default();
        nv.write_boot_state(&mut state).unwrap();
        tracing::info!("initialized boot state");
    }

    let nv = Arc::new(Mutex::new(nv));

    // Create HSM provider
    let hsm_provider: Option<Arc<Mutex<dyn hsm::HsmProvider>>> = {
        let daemon_bin = hsm_daemon_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("vhsm-test-ssd"));
        let provider = SimHsm::new(daemon_bin.clone(), hsm_keystore_path.clone(), hsm_port);

        if hsm_daemon_path.is_some() {
            tracing::info!(
                "HSM provider: daemon={}, keystore={}, port={}",
                daemon_bin.display(),
                hsm_keystore_path.display(),
                hsm_port,
            );
        } else {
            tracing::info!(
                "HSM provider: keystore={}, port={} (no daemon path, provision-only)",
                hsm_keystore_path.display(),
                hsm_port,
            );
        }

        // If HSM is already provisioned, load keys
        let provisioned = provider.is_provisioned().unwrap_or(false);
        let sw_key = if provisioned {
            provider.get_public_key(KeyRole::SoftwareAuthority).ok()
        } else {
            None
        };
        let ka = if provisioned {
            provider.get_public_key(KeyRole::KeyAuthority).ok()
        } else {
            None
        };

        // Ensure device-side EC keys exist (device-decrypt, ivd-signing, iam-signing)
        if let Err(e) = provider.ensure_device_keys() {
            tracing::warn!("failed to ensure device keys: {e}");
        }

        let hsm_arc = Arc::new(Mutex::new(provider));

        if let Some(sw_key) = sw_key {
            // CEK unwrap routed through the HSM, never extracts the
            // device decryption private key. Same Arc backs the
            // lifecycle ops below — no second view of the provider.
            let unwrap: Arc<dyn sumo_onboard::decryptor::KeyUnwrap + Send + Sync> =
                Arc::new(hsm::HsmKeyUnwrap::new(hsm_arc.clone(), "device-decrypt"));
            manifest_provider.update_keys(sw_key, Some(unwrap), ka);
            tracing::info!("loaded sw-authority from HSM keystore; CEK unwrap routed through HSM");
        } else if provisioned {
            tracing::warn!("HSM provisioned but failed to load sw-authority key");
            tracing::warn!("firmware flash will be rejected until keys are available");
        } else {
            tracing::info!(
                "HSM not yet provisioned — firmware flash disabled until HSM provisioning"
            );
        }

        Some(hsm_arc)
    };

    // --sw-authority override: directly set software authority from file,
    // bypassing HSM provisioning. For dev/test when HSM is not available.
    if let Some(ref sw_path) = sw_authority_path {
        let sw_key = std::fs::read(sw_path).unwrap_or_else(|e| {
            eprintln!("failed to read --sw-authority {}: {e}", sw_path.display());
            std::process::exit(1);
        });
        manifest_provider.update_keys(sw_key, None, None);
        tracing::info!(
            "loaded software authority from --sw-authority {}",
            sw_path.display()
        );
    }

    // Create one backend per bank set
    let components: Vec<(&str, BankSet, ComponentConfig)> = vec![
        (
            "host-os",
            BankSet::Os,
            ComponentConfig {
                entity_type: "host_os".into(),
                ..ComponentConfig::default()
            },
        ),
        ("vm1", BankSet::Vm1, ComponentConfig::default()),
        ("vm2", BankSet::Vm2, ComponentConfig::default()),
        (
            "hsm",
            BankSet::Hsm,
            ComponentConfig {
                supports_rollback: false,
                single_bank: true,
                entity_type: "hsm".into(),
            },
        ),
    ];

    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    let mut machine_builder = MachineRegistry::builder(EntityInfo {
        id: "vehicle".into(),
        name: "Vehicle".into(),
        entity_type: "vehicle".into(),
        description: None,
        href: "/vehicle/v1".into(),
        status: None,
    });
    for (id, set, config) in components {
        let mut backend = ComponentBackend::with_options(
            set,
            nv.clone(),
            manifest_provider.clone(),
            security_provider.clone(),
            config,
            vm_service_addr.clone(),
            images_dir.clone(),
            hsm_provider.clone(),
        );
        // Read display_name from the active bank's vm-config.yaml if available.
        // No `current` symlink any more — resolve the active bank from NV, and
        // if that's unreadable fall back to trying bank_a then bank_b
        // (display_name is the same in both). Best-effort: skip on any miss.
        if let Some(ref dir) = images_dir {
            let set_dir = dir.join(id);
            let active = nv.lock().ok().and_then(|nv| nv.read_boot_state()).map(|s| {
                match s.banks[set.as_index()].active_bank {
                    nv_store::types::Bank::A => "bank_a",
                    nv_store::types::Bank::B => "bank_b",
                }
            });
            // Active bank first when known; otherwise probe both (same name).
            let candidates: &[&str] = match active {
                Some("bank_b") => &["bank_b"],
                Some(_) => &["bank_a"],
                None => &["bank_a", "bank_b"],
            };
            for bank in candidates {
                let config_path = set_dir.join(bank).join("vm-config.yaml");
                if let Ok(content) = std::fs::read_to_string(&config_path) {
                    // Lightweight parse — just extract display_name
                    if let Ok(map) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
                        if let Some(name) = map.get("display_name").and_then(|v| v.as_str()) {
                            backend = backend.with_display_name(name.to_string());
                        }
                    }
                    break;
                }
            }
        }
        // Wire bank activator into the boot backend
        if set == BankSet::Os {
            if let Some(ref dev) = boot_device {
                let activator =
                    host_os_mgr::ifs::dev::DevBankActivator::new(dev.clone(), boot_mount.clone());
                backend = backend.with_bank_activator(Arc::new(activator));
            }
        }
        let backend_arc: Arc<ComponentBackend<_>> = Arc::new(backend);
        let mut component_inner = ComponentAdapter::new(backend_arc.clone());
        // Wire CSR signing for the HSM component so the route below can
        // call machine.component("hsm").get_csr() instead of building a
        // transient SimHsm at request time.
        if set == BankSet::Hsm {
            component_inner =
                component_inner.with_csr_keystore(hsm_keystore_path.clone(), hsm_port);
        }
        let vm_component: Arc<dyn machine_mgr::Component> = Arc::new(component_inner);

        // vm2 routes installs container-vs-VM through AppInstallRouterComponent;
        // every other component's install/flash lives natively on
        // ComponentBackend. The registry gets `component` either way; only the
        // SOVD diag backend differs.
        let component: Arc<dyn machine_mgr::Component> = if id == "vm2" {
            let container_images_dir = images_dir
                .clone()
                .unwrap_or_else(|| PathBuf::from("/tmp/sumo-container-images"))
                .join("vm2")
                .join("container-images");
            let container_image: Arc<dyn machine_mgr::Component> =
                Arc::new(app_mgr::ContainerImageComponent::new(
                    app_mgr::ContainerImageConfig::new("container_image", container_images_dir),
                ));
            Arc::new(AppInstallRouterComponent::new(
                "vm2",
                vm_component,
                container_image,
                manifest_provider.clone(),
            ))
        } else {
            vm_component
        };

        machine_builder = machine_builder.with_arc(component.clone());

        // vm2: wrap the install router so install/flash route through it and
        // everything else (data, faults, modes) delegates to the engine.
        // All others: the engine IS the DiagnosticBackend — wire it directly.
        let diag: Arc<dyn DiagnosticBackend> = if id == "vm2" {
            Arc::new(InstallRouterDiag::new(component, backend_arc.clone()))
        } else {
            backend_arc.clone() as Arc<dyn DiagnosticBackend>
        };
        backends.insert(id.to_string(), diag);
    }

    let machine: Arc<dyn Machine> = Arc::new(machine_builder.build());

    let state = sovd_api::AppState::new(backends);
    let router =
        sovd_api::create_router(state).merge(vm_mgr::sovd::routes::hsm_router(machine.clone()));

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("failed to bind to {bind_addr}: {e}");
            std::process::exit(1);
        });

    tracing::info!("vm-sovd listening on {bind_addr}");
    tracing::info!("  NV store: {}", nv_path.display());
    tracing::info!("  provisioning authority: built-in factory signing key");
    tracing::info!(
        "  software authority: {}",
        if manifest_provider.has_software_authority() {
            "loaded from HSM"
        } else {
            "not yet available (awaiting HSM provisioning)"
        }
    );
    if let Some(ref dir) = images_dir {
        tracing::info!("  images dir: {} (real image OTA enabled)", dir.display());
    }
    if let Some(ref addr) = vm_service_addr {
        tracing::info!("  vm-service addr: {addr}");
    }
    tracing::info!("  HSM keystore: {}", hsm_keystore_path.display());
    if let Some(ref dev) = boot_device {
        tracing::info!("  boot device: {} (IFS activation enabled)", dev);
        tracing::info!("  boot mount: {}", boot_mount.display());
    }
    tracing::info!("  components: hypervisor, vm1, vm2, hsm, boot");
    tracing::info!("  try: curl http://{bind_addr}/vehicle/v1/components");

    axum::serve(listener, router).await.unwrap();
}
