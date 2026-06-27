use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use nv_store::block::FileBlockDevice;
use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
use nv_store::types::{BankSet, NvBootState};

use sovd_core::DiagnosticBackend;

use component_factory::{build_component, ComponentSpec, FactoryDeps};
use component_mgr::sovd::security::TestSecurityProvider;
use component_mgr::suit_provider::SuitProvider;

use machine_mgr::{Machine, MachineRegistry};
use sovd_core::EntityInfo;

use hsm::link_b::LinkBClient;
use hsm::{HsmProvider, KeyRole, LinkBProvider};

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
        eprintln!("  --backend-socket <path>    Unix socket of the PRE-SPAWNED link-B HSM backend");
        eprintln!("                             (host crypto + provisioning; vm-sovd connects, never spawns)");
        eprintln!("  --hsm-keystore <path>      HSM keystore directory (default: /tmp/vhsm-keys)");
        eprintln!("  --hsm-port <port>          HSM TCP port (default: 5100)");
        eprintln!("  --boot-device <path>       Boot partition block device for IFS activation (e.g. /dev/hd0t177)");
        eprintln!("  --boot-mount <path>        Boot partition mount point (default: /mnt/boot)");
        eprintln!("  --sw-authority <path>      Software authority COSE_Key file (bypasses HSM, dev/test only)");
        eprintln!("  --gateway                  In-guest federating gateway mode (local /updates + proxy to host)");
        eprintln!("  --host-sovd-url <url>      [gateway] host SOVD base URL to proxy host-owned components to");
        eprintln!(
            "  --proxy-component <id>     [gateway] host-owned component id to proxy (repeatable)"
        );
        eprintln!("  --device-id <id>           [gateway] token audience (the device id); pins the onboard minter");
        eprintln!("  --guest-vhsm               [gateway] source HSM crypto from the guest vHSM (VhsmProvider); else the host link-B backend");
        eprintln!("  --bind <addr>              Listen address (alt to the positional; default 0.0.0.0:4000)");
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
    let mut backend_socket: Option<PathBuf> = None;
    let mut hsm_keystore_path = PathBuf::from("/tmp/vhsm-keys");
    let mut hsm_port: u16 = 5100;
    let mut boot_device: Option<String> = None;
    let mut boot_mount = PathBuf::from("/mnt/boot");
    let mut sw_authority_path: Option<PathBuf> = None;
    let mut bind_addr = "0.0.0.0:4000";
    // Gateway mode (--gateway): serve the in-guest federating SOVD surface — the
    // local onboard pull-update route (route-scoped Operational authz) plus
    // host-owned components proxied to --host-sovd-url. See component_mgr::sovd::gateway.
    let mut gateway_mode = false;
    let mut host_sovd_url: Option<String> = None;
    let mut proxy_components: Vec<String> = Vec::new();
    let mut device_id: Option<String> = None;
    // --guest-vhsm: in gateway mode, source HSM crypto from the guest vHSM
    // (VhsmProvider over the wire) instead of the host link-B backend client.
    let mut guest_vhsm = false;
    let mut i = 2;
    while i < args.len() {
        if args[i] == "--images-dir" && i + 1 < args.len() {
            images_dir = Some(PathBuf::from(&args[i + 1]));
            i += 2;
        } else if args[i] == "--vm-service-socket" && i + 1 < args.len() {
            vm_service_addr = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "--backend-socket" && i + 1 < args.len() {
            backend_socket = Some(PathBuf::from(&args[i + 1]));
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
        } else if args[i] == "--gateway" {
            gateway_mode = true;
            i += 1;
        } else if args[i] == "--host-sovd-url" && i + 1 < args.len() {
            host_sovd_url = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "--proxy-component" && i + 1 < args.len() {
            proxy_components.push(args[i + 1].clone());
            i += 2;
        } else if args[i] == "--device-id" && i + 1 < args.len() {
            device_id = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "--guest-vhsm" {
            guest_vhsm = true;
            i += 1;
        } else if args[i] == "--bind" && i + 1 < args.len() {
            bind_addr = &args[i + 1];
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

    // Connect to the PRE-SPAWNED link-B HSM backend (Decision B: this process
    // owns no backend lifecycle — an external orchestrator spawns the backend
    // (`hsm-sim-service` in dev, a vendor HSM bridge in production); vm-sovd only
    // connects). The one client is the wire to the backend: it backs the full
    // `HsmProvider` (`LinkBProvider`, for provisioning + OTA) and doubles as the
    // `HsmCryptoProvider` for any direct crypto (the gateway authorizer). No HSM
    // runs in this process; the backend self-bootstraps its device-side EC keys
    // at startup, so the host performs no device-key bootstrap of its own.
    let client: Option<Arc<LinkBClient>> = match backend_socket {
        Some(ref sock) => {
            let c = connect_backend(sock).unwrap_or_else(|e| {
                eprintln!(
                    "failed to connect link-B HSM backend at {}: {e}",
                    sock.display()
                );
                std::process::exit(1);
            });
            tracing::info!(
                "link-B HSM backend connected at {} (connect-only; lifecycle owned externally)",
                sock.display()
            );
            Some(Arc::new(c))
        }
        None => None,
    };

    // Host HSM provider — a full `HsmProvider` over the link-B client. `None` when
    // no `--backend-socket` was given (e.g. a `--gateway --guest-vhsm` guest, which
    // sources crypto from the guest vHSM instead): HSM-backed provisioning/flash is
    // then disabled until a backend is connected.
    let hsm_provider: Option<Arc<Mutex<dyn hsm::HsmProvider>>> = if let Some(ref client) = client {
        let provider = LinkBProvider::new(Arc::clone(client));

        // If the backend keystore is already provisioned, load the keys the
        // manifest path needs (sw-authority + key-authority). Both cross link-B.
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

        let hsm_arc = Arc::new(Mutex::new(provider));

        if let Some(sw_key) = sw_key {
            // CEK unwrap routed through the HSM, never extracts the
            // device decryption private key. Same Arc backs the
            // lifecycle ops below — no second view of the provider.
            let unwrap: Arc<dyn sumo_onboard::decryptor::KeyUnwrap + Send + Sync> = Arc::new(
                hsm::HsmKeyUnwrap::new(hsm_arc.clone(), hsm::KeyRole::DeviceDecryption.handle()),
            );
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
    } else {
        tracing::warn!(
            "no --backend-socket: HSM features disabled (provisioning/flash unavailable \
             until a link-B HSM backend is connected)"
        );
        None
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

    // Read display_name from the active bank's vm-config.yaml (best-effort):
    // resolve the active bank from NV, falling back to probing bank_a then bank_b
    // (display_name is the same in both). File I/O stays in the binary — the
    // factory just applies whatever name the spec carries.
    let (hostos_name, vm1_name, vm2_name) = {
        let read_display_name = |id: &str, set: BankSet| -> Option<String> {
            let dir = images_dir.as_ref()?;
            let set_dir = dir.join(id);
            let active = nv.lock().ok().and_then(|n| n.read_boot_state()).map(|s| {
                match s.banks[set.as_index()].active_bank {
                    nv_store::types::Bank::A => "bank_a",
                    nv_store::types::Bank::B => "bank_b",
                }
            });
            let candidates: &[&str] = match active {
                Some("bank_b") => &["bank_b"],
                Some(_) => &["bank_a"],
                None => &["bank_a", "bank_b"],
            };
            for bank in candidates {
                let config_path = set_dir.join(bank).join("vm-config.yaml");
                if let Ok(content) = std::fs::read_to_string(&config_path) {
                    if let Ok(map) = serde_yaml::from_str::<serde_yaml::Value>(&content) {
                        if let Some(name) = map.get("display_name").and_then(|v| v.as_str()) {
                            return Some(name.to_string());
                        }
                    }
                    break;
                }
            }
            None
        };
        (
            read_display_name("host-os", BankSet::Os),
            read_display_name("vm1", BankSet::Vm1),
            read_display_name("vm2", BankSet::Vm2),
        )
    };

    // One backend per bank set, built through the shared component-factory — the
    // same path supernova-mm uses, no hand-rolled composition. vm2 is a plain bank:
    // installing containers *inside* vm2 is the guest's own SOVD server's job, not
    // the host vm-manager's. `entity_type` is pinned to vm-sovd's historical values
    // (the factory would otherwise report the routing key).
    let specs: Vec<ComponentSpec> = vec![
        ComponentSpec {
            id: "host-os".into(),
            component_type: "hpc".into(),
            rollback: true,
            single_bank: false,
            storage_path: images_dir.clone(),
            base_path: None,
            bank_set: None,
            slot: None,
            storage_subdir: None,
            bank_layout: None,
            activator: boot_device.as_ref().map(|_| "ifs".to_string()),
            display_name: hostos_name,
            entity_type: Some("host_os".into()),
        },
        ComponentSpec {
            id: "vm1".into(),
            component_type: "bank".into(),
            rollback: true,
            single_bank: false,
            storage_path: images_dir.clone(),
            base_path: None,
            bank_set: None,
            slot: None,
            storage_subdir: None,
            bank_layout: None,
            activator: None,
            display_name: vm1_name,
            entity_type: Some("vm".into()),
        },
        ComponentSpec {
            id: "vm2".into(),
            component_type: "bank".into(),
            rollback: true,
            single_bank: false,
            storage_path: images_dir.clone(),
            base_path: None,
            bank_set: None,
            slot: None,
            storage_subdir: None,
            bank_layout: None,
            activator: None,
            display_name: vm2_name,
            entity_type: Some("vm".into()),
        },
        ComponentSpec {
            id: "hsm".into(),
            component_type: "hsm".into(),
            rollback: false,
            single_bank: true,
            storage_path: images_dir.clone(),
            base_path: None,
            bank_set: None,
            slot: None,
            storage_subdir: None,
            bank_layout: None,
            activator: None,
            display_name: None,
            entity_type: Some("hsm".into()),
        },
    ];

    // Host-os bank activator (raw IFS write), keyed by id for the factory to wire.
    // Only when a boot device is configured.
    let mut bank_activators: HashMap<String, Arc<dyn machine_mgr::BankActivator>> = HashMap::new();
    if let Some(ref dev) = boot_device {
        bank_activators.insert(
            "host-os".into(),
            Arc::new(host_os_mgr::ifs::dev::DevBankActivator::new(
                dev.clone(),
                boot_mount.clone(),
            )),
        );
    }

    let mut backends: HashMap<String, Arc<dyn DiagnosticBackend>> = HashMap::new();
    let mut machine_builder = MachineRegistry::builder(EntityInfo {
        id: "vehicle".into(),
        name: "Vehicle".into(),
        entity_type: "vehicle".into(),
        description: None,
        href: "/vehicle/v1".into(),
        status: None,
    });
    // One node update-transaction coordinator, shared into every component's
    // start_flash gate (the "one transaction at a time" / no-mixing gate). The
    // SOVD reset/verdict handlers will share this same Arc in the next steps.
    // Bank-set-index -> component-id map, so the node update-state report and the
    // gate's refusal name the components (not "bank-set N").
    let id_map: Vec<(usize, String)> = specs
        .iter()
        .filter_map(|s| {
            component_factory::resolve_bank_set(s).map(|bs| (bs.as_index(), s.id.clone()))
        })
        .collect();
    let node_coordinator = Arc::new(machine_mgr::node_update::NodeCoordinator::new(id_map));

    let deps = FactoryDeps {
        nv: nv.clone(),
        manifest_provider: manifest_provider.clone(),
        security_provider: security_provider.clone(),
        vm_service_addr: vm_service_addr.clone(),
        hsm_provider: hsm_provider.clone(),
        // No crypto-only handle in the dev vm-sovd binary — keeps the
        // `dyn HsmProvider` path for seal / unwrap / CSR.
        hsm_crypto: None,
        hsm_keystore: Some(hsm_keystore_path.clone()),
        hsm_port,
        bank_activators,
        health_probes: HashMap::new(),
        boot_selector: None,
        node_coordinator: Some(node_coordinator.clone()),
        // No reload hook needed: the external link-B backend serves crypto from
        // its keystore on disk, so a keystore-provision lands without restarting
        // it, and `LinkBProvider`'s stop/start are no-ops anyway (lifecycle owned
        // externally). A deployment that DOES need an external daemon reload on
        // provision sets this; here it stays inert.
        post_provision_reload: None,
    };
    for spec in &specs {
        if let Some(built) = build_component(spec, &deps) {
            machine_builder = machine_builder.with_arc(built.component);
            if let Some(diag) = built.diag_backend {
                backends.insert(spec.id.clone(), diag);
            }
        }
    }

    let machine: Arc<dyn Machine> = Arc::new(machine_builder.build());

    let router = if gateway_mode {
        // In-guest federating gateway: local onboard pull-update (route-scoped
        // Operational authz) + host-owned components proxied to the host SOVD.
        // HSM crypto comes from the guest vHSM (VhsmProvider) with --guest-vhsm,
        // else the host link-B backend client (the same backend the OTA provider
        // uses). Without either there is no crypto source, so we fail loudly.
        let gw_crypto: Arc<dyn hsm::HsmCryptoProvider> = if guest_vhsm {
            Arc::new(
                vhsm_provider::VhsmProvider::connect_local().unwrap_or_else(|e| {
                    eprintln!("vm-sovd --gateway --guest-vhsm: connect to guest vHSM failed: {e}");
                    std::process::exit(1);
                }),
            ) as Arc<dyn hsm::HsmCryptoProvider>
        } else if let Some(ref client) = client {
            Arc::clone(client) as Arc<dyn hsm::HsmCryptoProvider>
        } else {
            eprintln!(
                "vm-sovd --gateway without --guest-vhsm requires --backend-socket \
                 (the host link-B HSM backend)"
            );
            std::process::exit(1);
        };
        build_gateway_router(
            machine.clone(),
            backends,
            gw_crypto,
            device_id,
            host_sovd_url,
            &proxy_components,
            nv.clone(),
            node_coordinator.clone(),
        )
        .await
    } else {
        let state = sovd_api::AppState::new(backends);
        sovd_api::create_router(state)
            .merge(component_mgr::sovd::routes::hsm_router(machine.clone()))
            .merge(component_mgr::sovd::routes::update_state_router(
                nv.clone(),
                node_coordinator.clone(),
            ))
    };

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

/// Connect a [`LinkBClient`] to the PRE-SPAWNED link-B HSM backend listening on
/// the Unix socket `socket`, retrying while it finishes binding. vm-sovd never
/// spawns the backend (Decision B — process lifecycle is owned externally); it
/// only connects. Mirrors the connect-only retry budget vhsm-ssd uses
/// (~5 s = 50 × 100 ms), so a just-spawned backend isn't missed on the first
/// refused connect.
fn connect_backend(socket: &std::path::Path) -> std::io::Result<LinkBClient> {
    const ATTEMPTS: u32 = 50;
    const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(100);

    let mut last_err: Option<std::io::Error> = None;
    for attempt in 0..ATTEMPTS {
        match LinkBClient::connect(socket) {
            Ok(client) => return Ok(client),
            Err(e) => {
                last_err = Some(e);
                // Don't sleep after the final attempt — we're about to give up.
                if attempt + 1 < ATTEMPTS {
                    std::thread::sleep(RETRY_DELAY);
                }
            }
        }
    }
    let e = last_err.expect("ATTEMPTS >= 1 so at least one connect was tried");
    Err(std::io::Error::new(
        e.kind(),
        format!(
            "link-B HSM backend never accepted on {} after {ATTEMPTS} attempts: {e}",
            socket.display()
        ),
    ))
}

/// Build the in-guest federating gateway router (`--gateway` mode): the
/// authorizer from the device's HSM issuer anchors (pins `jwt-signing`
/// Operational, so the onboard minter's tokens verify), the pull-update trust
/// anchor (the sw-authority manifest key), and a `SovdProxyBackend` per
/// host-owned component (forwarding to the host SOVD). See
/// `component_mgr::sovd::gateway::gateway_router`.
///
/// `crypto` is the HSM-crypto backend: on a real guest it is `VhsmProvider`
/// (the guest vHSM, via `--guest-vhsm`); on a host/sim rig the link-B backend
/// client (`LinkBClient`). Both satisfy the same handle-addressed
/// `HsmCryptoProvider`, so this code is
/// backend-agnostic — the issuer pubkeys and the sw-authority trust anchor are
/// read via `get_public_key_der`, needing no lifecycle (`HsmProvider`) trait.
#[allow(clippy::too_many_arguments)]
async fn build_gateway_router<D>(
    machine: Arc<dyn Machine>,
    mut backends: HashMap<String, Arc<dyn DiagnosticBackend>>,
    crypto: Arc<dyn hsm::HsmCryptoProvider>,
    device_id: Option<String>,
    host_sovd_url: Option<String>,
    proxy_components: &[String],
    nv: Arc<Mutex<NvStore<D>>>,
    node_coordinator: Arc<machine_mgr::node_update::NodeCoordinator>,
) -> axum::Router
where
    D: nv_store::block::BlockDevice + Send + 'static,
{
    fn fail(msg: &str) -> ! {
        eprintln!("vm-sovd --gateway: {msg}");
        std::process::exit(1);
    }
    let device_id = device_id.unwrap_or_else(|| fail("requires --device-id <id> (the token aud)"));
    let host_url = host_sovd_url.unwrap_or_else(|| fail("requires --host-sovd-url <url>"));

    // Authorizer pinned to the device's HSM issuer anchors — so the onboard
    // minter's `jwt-signing` Operational tokens verify here. Backend-agnostic:
    // `crypto` is the guest vHSM (VhsmProvider) or the host link-B client.
    let c_pub = crypto.clone();
    let c_anchor = crypto.clone();
    let authz = component_mgr::sovd::issuer_keys::authorizer_from_anchors(
        // The authorizer pins issuer keys by their JWT issuer-id (the wire
        // `kid`/`iss` string); map that to the slot handle for the HSM lookup.
        move |id| {
            hsm::vhsm_proto::handle_for_key_id(id)
                .and_then(|h| c_pub.get_public_key_der(hsm::KeyHandle(h)).ok())
        },
        // Trust anchors are addressed by string anchor-id (not a slot handle).
        move |id| c_anchor.get_trust_anchor_der(id).ok(),
        &device_id,
    )
    .unwrap_or_else(|e| fail(&format!("authorizer: {e}")));
    let authorizer: Arc<dyn sovd_api::Authorizer> = Arc::new(authz);

    // Pull-update trust anchor = the manifest-signing (sw-authority) key, as the
    // COSE_Key the Puller validates with. `get_public_key_der` yields SPKI on
    // both the host (link-B client) and the guest (VhsmProvider); convert to the same
    // COSE_Key `HsmProvider::get_public_key(SoftwareAuthority)` produces.
    let sw_spki = crypto
        .get_public_key_der(KeyRole::SoftwareAuthority.handle())
        .unwrap_or_else(|_| fail("needs the sw-authority key (provision the HSM)"));
    let trust_anchor = hsm::cose_key_es256_from_spki_der(&sw_spki)
        .unwrap_or_else(|e| fail(&format!("sw-authority -> COSE_Key: {e}")));

    // Federate: each host-owned component becomes a proxy entry forwarding to the
    // host SOVD. Construction is async + queries the host, so it must be reachable.
    for comp in proxy_components {
        match sovd_proxy::SovdProxyBackend::new(comp, &host_url, comp).await {
            Ok(p) => {
                backends.insert(comp.clone(), Arc::new(p) as Arc<dyn DiagnosticBackend>);
            }
            Err(e) => fail(&format!("proxy '{comp}' -> {host_url}: {e}")),
        }
    }

    tracing::info!(
        "vm-sovd GATEWAY: device={device_id}, host={host_url}, proxied={proxy_components:?}"
    );
    component_mgr::sovd::gateway::gateway_router(machine, backends, authorizer, trust_anchor).merge(
        component_mgr::sovd::routes::update_state_router(nv, node_coordinator),
    )
}
