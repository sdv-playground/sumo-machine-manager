use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use nv_store::block::FileBlockDevice;
use nv_store::store::{nv_device_size, NvStore};
use nv_store::types::{BankSet, NvBootState, DEFAULT_SLOTS};

use sovd_core::DiagnosticBackend;

use component_factory::{build_component, ComponentSpec, FactoryDeps};
use component_mgr::suit_provider::SuitProvider;

use machine_mgr::{Machine, MachineRegistry};
use sovd_core::EntityInfo;

use hsm::link_b::LinkBClient;
use hsm::{HsmCryptoProvider, HsmProvider, KeyRole, LinkBProvider};

#[tokio::main]
async fn main() {
    // Fleet logging: install the env-selected recorder + tracing→score_log bridge.
    sumo_log::init_tracing("vsvd");

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
        eprintln!("  --tls                      Serve HTTPS using the HSM-held tls-identity leaf (server-only TLS)");
        eprintln!("  --no-mdns                  Disable mDNS/DNS-SD advertising of the SOVD endpoint (on by default, http and https)");
        eprintln!("  --identification <id>      SOVD server id for mDNS: TXT identification (verbatim) and, absent a TLS leaf, the hostname");
        eprintln!("  --identification-prefix <p> Like --identification, as <p>-<first 16 hex of the ECU id> (the hsm x-ecu-id); --identification wins");
        eprintln!("  --node-id <id>             Serve /v1 as node <id>: the components become /v1/components/<id>/subcomponents/...");
        eprintln!(
            "  --node-name <name>         [--node-id] the node's name (default: the node id)"
        );
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
    // --tls: serve HTTPS using the HSM-held tls-identity (host SOVD over TLS;
    // server-only — the client still authenticates with an operator token).
    let mut tls_enabled = false;
    // mDNS/DNS-SD advertising of the SOVD endpoint (ISO 17978-3 §5.11) — on by
    // default on both transports; the `accessurl` scheme tells the client which
    // one to dial. --no-mdns opts out.
    let mut mdns_enabled = true;
    // --identification: the SOVD server id — TXT `identification` (verbatim,
    // stable across enrolment) and the `<id>.local` hostname until a TLS leaf
    // supplies one. Unset: the leaf's id, else the OS hostname.
    let mut identification: Option<String> = None;
    // --identification-prefix: the identification derived from the ECU id
    // (`<prefix>-<ecu16>`), when --identification is not given.
    let mut identification_prefix: Option<String> = None;
    // --node-id / --node-name: opt-in SOVDd node topology on `/v1`.
    let mut node_id: Option<String> = None;
    let mut node_name: Option<String> = None;
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
        } else if args[i] == "--tls" {
            tls_enabled = true;
            i += 1;
        } else if args[i] == "--no-mdns" {
            mdns_enabled = false;
            i += 1;
        } else if args[i] == "--identification" && i + 1 < args.len() {
            identification = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "--identification-prefix" && i + 1 < args.len() {
            identification_prefix = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "--node-id" && i + 1 < args.len() {
            node_id = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "--node-name" && i + 1 < args.len() {
            node_name = Some(args[i + 1].clone());
            i += 2;
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

    // Open/create NV store
    let dev = if nv_path.exists() {
        FileBlockDevice::open(&nv_path).expect("failed to open NV store")
    } else {
        tracing::info!("creating NV store: {}", nv_path.display());
        FileBlockDevice::create(&nv_path, nv_device_size(DEFAULT_SLOTS))
            .expect("failed to create NV store")
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
            // CEK unwrap routed through the HSM crypto handle (the link-B client),
            // never extracting the device decryption private key.
            let crypto: Arc<dyn hsm::HsmCryptoProvider> = client.clone();
            let unwrap: Arc<dyn sumo_onboard::decryptor::KeyUnwrap + Send + Sync> = Arc::new(
                hsm::HsmKeyUnwrap::from_crypto(crypto, hsm::KeyRole::DeviceDecryption.handle()),
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

    // One backend per bank set, built through the shared component-factory — the
    // same path the host machine manager uses, no hand-rolled composition. vm2 is a plain bank:
    // installing containers *inside* vm2 is the guest's own SOVD server's job, not
    // the host vm-manager's. `entity_type` is pinned to vm-sovd's historical values
    // (the factory would otherwise report the routing key). `slot` is this dev
    // server's own platform profile: the numbers the six retired slot names used
    // to stand for.
    let mut specs: Vec<ComponentSpec> = vec![
        ComponentSpec {
            id: "host".into(),
            component_type: "hpc".into(),
            rollback: true,
            single_bank: false,
            storage_path: images_dir.clone(),
            base_path: None,
            bank_set: None,
            slot: Some(2),
            storage_subdir: None,
            parts: Vec::new(),
            activator: boot_device.as_ref().map(|_| "ifs".to_string()),
            display_name: None,
            entity_type: Some("host_os".into()),
            log_agent_url: None,
            host_log_globs: None,
            host_dump_dir: None,
            host_slog2: true,
            // dev host mode has no slog2-drainer running → no persisted segments.
            host_slog2_segments_dir: None,
            host_slog2_live_dir: component_factory::default_slog2_live_dir(),
            test_agent_url: None,
            diag_agent_url: None,
            // host-os IS the host: gather §7.9 probes in-process (disk/mem/du).
            host_diagnostics: true,
            attest_time: false,
            vm_principal: false,
        },
        ComponentSpec {
            id: "vm1".into(),
            component_type: "bank".into(),
            rollback: true,
            single_bank: false,
            storage_path: images_dir.clone(),
            base_path: None,
            bank_set: None,
            slot: Some(4),
            storage_subdir: None,
            parts: Vec::new(),
            activator: None,
            display_name: None,
            entity_type: Some("vm".into()),
            log_agent_url: None,
            host_log_globs: None,
            host_dump_dir: None,
            host_slog2: false,
            host_slog2_segments_dir: None,
            host_slog2_live_dir: component_factory::default_slog2_live_dir(),
            test_agent_url: None,
            diag_agent_url: None,
            host_diagnostics: false,
            attest_time: false,
            vm_principal: false,
        },
        ComponentSpec {
            id: "vm2".into(),
            component_type: "bank".into(),
            rollback: true,
            single_bank: false,
            storage_path: images_dir.clone(),
            base_path: None,
            bank_set: None,
            slot: Some(5),
            storage_subdir: None,
            parts: Vec::new(),
            activator: None,
            display_name: None,
            entity_type: Some("vm".into()),
            log_agent_url: None,
            host_log_globs: None,
            host_dump_dir: None,
            host_slog2: false,
            host_slog2_segments_dir: None,
            host_slog2_live_dir: component_factory::default_slog2_live_dir(),
            test_agent_url: None,
            diag_agent_url: None,
            host_diagnostics: false,
            attest_time: false,
            vm_principal: false,
        },
        ComponentSpec {
            id: "hsm".into(),
            component_type: "hsm".into(),
            rollback: false,
            single_bank: true,
            storage_path: images_dir.clone(),
            base_path: None,
            bank_set: None,
            slot: Some(0),
            storage_subdir: None,
            parts: Vec::new(),
            activator: None,
            display_name: None,
            entity_type: Some("hsm".into()),
            log_agent_url: None,
            host_log_globs: None,
            host_dump_dir: None,
            host_slog2: false,
            host_slog2_segments_dir: None,
            host_slog2_live_dir: component_factory::default_slog2_live_dir(),
            test_agent_url: None,
            diag_agent_url: None,
            host_diagnostics: false,
            attest_time: false,
            vm_principal: false,
        },
    ];

    // Read display_name from the active bank's vm-config.yaml (best-effort):
    // resolve the active bank from NV, falling back to probing bank_a then bank_b
    // (display_name is the same in both). File I/O stays in the binary — the
    // factory just applies whatever name the spec carries. Every configured
    // component is probed by id; one without a name keeps the factory default.
    {
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
        for spec in &mut specs {
            match component_factory::resolve_bank_set(spec) {
                Ok(slot) => spec.display_name = read_display_name(&spec.id, slot),
                Err(msg) => tracing::warn!("{msg} — no display name read"),
            }
        }
    }

    // Host-os bank activator (raw IFS write), keyed by id for the factory to wire.
    // Only when a boot device is configured.
    let mut bank_activators: HashMap<String, Arc<dyn machine_mgr::BankActivator>> = HashMap::new();
    if let Some(ref dev) = boot_device {
        bank_activators.insert(
            "host".into(),
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
    // start_flash gate (the "one transaction at a time" gate). The SOVD
    // reset/verdict handlers share this same Arc. Each component registers its
    // bank report with it as its adapter is built.
    let node_coordinator = Arc::new(machine_mgr::node_update::NodeCoordinator::new());

    let deps = FactoryDeps {
        nv: nv.clone(),
        manifest_provider: manifest_provider.clone(),
        vm_service_addr: vm_service_addr.clone(),
        hsm_provider: hsm_provider.clone(),
        // The link-B client as the crypto handle too — the SAME connection
        // `hsm_provider` wraps, as on the host. It signs the IVD seal and the
        // disable sentinel (without a signer a disable is refused with a 409),
        // and serves the keys-provision CEK unwrap and the HSM component's CSR.
        // `None` without `--backend-socket`, like `hsm_provider`.
        hsm_crypto: client.clone().map(|c| c as Arc<dyn hsm::HsmCryptoProvider>),
        hsm_keystore: Some(hsm_keystore_path.clone()),
        hsm_port,
        bank_activators,
        // No raw-partition banks in the dev vm-sovd binary (VMs stage to bank
        // dirs); the host OS bank's PartitionBankProvider is a host-mm concern.
        partition_parts: HashMap::new(),
        health_probes: HashMap::new(),
        // vm-sovd's VMs report their own heartbeat boot_id; the node-wide nonce
        // is a host-mm concern (surfaced there for the offboard reboot gate).
        node_boot_id: None,
        // No deployment-specific deactivators in the dev vm-sovd binary — VM
        // components still get the generic vm-service-stop deactivator from
        // the factory itself (disableable by construction); rt-style injected
        // deactivators are a host-machine-manager concern.
        deactivators: HashMap::new(),
        boot_selector: None,
        node_coordinator: Some(node_coordinator.clone()),
        // No reload hook needed: the external link-B backend serves crypto from
        // its keystore on disk, so a keystore-provision lands without restarting
        // it, and `LinkBProvider`'s stop/start are no-ops anyway (lifecycle owned
        // externally). A deployment that DOES need an external daemon reload on
        // provision sets this; here it stays inert.
        post_provision_reload: None,
        // vm-sovd doesn't own the host clock — leave the no-op default.
        wall_clock_floor: None,
    };
    for spec in &specs {
        // Non-fatal per component, but never silent: a spec that cannot be built is
        // absent from the registry, so it can be neither flashed nor diagnosed, and
        // the reason is the only thing that distinguishes "not deployed here" from
        // a profile typo. Refusing the whole gateway would be worse — one bad spec
        // would take every other component's diagnostics down with it.
        match build_component(spec, &deps) {
            Ok(built) => {
                machine_builder = machine_builder.with_arc(built.component);
                if let Some(diag) = built.diag_backend {
                    backends.insert(spec.id.clone(), diag);
                }
            }
            Err(e) => tracing::error!("component '{}' not registered: {e}", spec.id),
        }
    }

    let machine: Arc<dyn Machine> = match machine_builder.build() {
        Ok(machine) => Arc::new(machine),
        Err(e) => {
            tracing::error!("boot selector store unreadable: {e}");
            std::process::exit(1);
        }
    };

    if identification.is_none() {
        if let Some(prefix) = identification_prefix.as_deref() {
            identification = ecu_identification(machine.as_ref(), prefix).await;
        }
    }
    let node = node_topology(node_id, node_name, identification.as_deref());

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
            node_coordinator.clone(),
            node,
        )
        .await
    } else {
        let state = sovd_state(backends, node).unwrap_or_else(|e| {
            eprintln!("vm-sovd: --node-id: {e}");
            std::process::exit(1);
        });
        plain_router(machine.clone(), state, node_coordinator.clone())
    };

    // --tls: serve HTTPS with the HSM-held tls-identity (server-only TLS — the
    // client authenticates with an operator token, not a client cert). The link-B
    // backend signs the handshake; the private key never leaves the HSM.
    // Best-effort: serve HTTPS once the tls-identity leaf is provisioned; until
    // then (first-boot provisioning) serve HTTP — the very flow that installs the
    // leaf (CSR enrollment + keystore install) runs over this SOVD path, so it
    // can't require the cert it's about to deliver. A restart after provisioning
    // lights up HTTPS. Mirrors the cross-node listener's graceful degradation.
    // mDNS/DNS-SD advertiser guard — held until `serve` returns (graceful
    // shutdown on SIGTERM / ctrl-c too), dropping it sends DNS-SD goodbye
    // packets. Started on both transports: hostname from the TLS leaf (https
    // only), else --identification, else the OS hostname; TXT identification is
    // --identification when set. The rule lives in `SovdAdvertiser::new`.
    let mut _mdns_guard: Option<sovd_mdns::AdvertiserGuard> = None;
    let identities: Vec<sovd_mdns::Identity<'_>> = identification
        .as_deref()
        .map(sovd_mdns::Identity::Configured)
        .into_iter()
        .collect();
    let tls_config: Option<axum_server::tls_rustls::RustlsConfig> = if tls_enabled {
        match client.as_ref() {
            None => {
                tracing::warn!("--tls set but no --backend-socket (no HSM) — serving HTTP");
                None
            }
            Some(crypto) => match crypto.get_certificate_der(KeyRole::TlsIdentity.handle()) {
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "--tls set but the tls-identity leaf isn't provisioned yet — serving HTTP \
                         (provisioning runs over the SOVD path; restart once it lands for HTTPS)"
                    );
                    None
                }
                Ok(leaf) => {
                    // Advertise the SOVD endpoint over mDNS (ISO 17978-3 §5.11):
                    // instance/hostname come from this leaf's `<id>.local` SAN, so
                    // a discovery client dialing `<id>.local` verifies this cert.
                    if mdns_enabled {
                        let mut ids = identities.clone();
                        ids.extend([
                            sovd_mdns::Identity::Leaf(&leaf),
                            sovd_mdns::Identity::Hostname,
                        ]);
                        _mdns_guard = start_mdns(&ids, sovd_mdns::Scheme::Https, bind_addr);
                    }
                    let signer = crypto.clone();
                    let sign_fn = move |msg: &[u8]| {
                        signer
                            .sign(KeyRole::TlsIdentity.handle(), msg)
                            .map_err(|e| e.to_string())
                    };
                    let cfg = hsm_rustls::server_config_no_client_auth(leaf, sign_fn);
                    Some(axum_server::tls_rustls::RustlsConfig::from_config(
                        Arc::new(cfg),
                    ))
                }
            },
        }
    } else {
        None
    };

    // Plain-HTTP listener only when TLS is off — axum_server binds the TLS socket
    // itself, so a pre-bound TcpListener would collide on the port.
    let listener = if tls_config.is_none() {
        Some(
            tokio::net::TcpListener::bind(bind_addr)
                .await
                .unwrap_or_else(|e| {
                    eprintln!("failed to bind to {bind_addr}: {e}");
                    std::process::exit(1);
                }),
        )
    } else {
        None
    };
    if listener.is_some() && mdns_enabled {
        let mut ids = identities.clone();
        ids.push(sovd_mdns::Identity::Hostname);
        _mdns_guard = start_mdns(&ids, sovd_mdns::Scheme::Http, bind_addr);
    }

    tracing::info!(
        "vm-sovd listening on {bind_addr}{}",
        if tls_config.is_some() {
            " (HTTPS, HSM tls-identity)"
        } else {
            ""
        }
    );
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
    tracing::info!("  try: curl http://{bind_addr}/v1/components");

    match (listener, tls_config) {
        (Some(listener), None) => {
            // One signal task drives both the graceful shutdown and its 5 s cap,
            // so a long-lived client can't hold SIGTERM open and block the goodbye.
            let (stop_tx, stop_rx) = tokio::sync::watch::channel(());
            tokio::spawn(async move {
                shutdown_signal().await;
                let _ = stop_tx.send(());
            });
            let mut graceful_rx = stop_rx.clone();
            let mut cap_rx = stop_rx;
            let serve = axum::serve(listener, router).with_graceful_shutdown(async move {
                let _ = graceful_rx.changed().await;
            });
            tokio::select! {
                result = serve => result.unwrap(),
                _ = async {
                    let _ = cap_rx.changed().await;
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                } => tracing::warn!("graceful shutdown timed out after 5 s; closing"),
            }
        }
        (None, Some(tls_config)) => {
            let addr: std::net::SocketAddr = bind_addr.parse().unwrap_or_else(|e| {
                eprintln!("--tls: --bind {bind_addr} must be ip:port: {e}");
                std::process::exit(1);
            });
            let handle = axum_server::Handle::new();
            tokio::spawn({
                let handle = handle.clone();
                async move {
                    shutdown_signal().await;
                    handle.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
                }
            });
            axum_server::bind_rustls(addr, tls_config)
                .handle(handle)
                .serve(router.into_make_service())
                .await
                .unwrap();
        }
        _ => unreachable!("listener and tls_config are set together"),
    }
}

/// Resolves on ctrl-c or (on unix) SIGTERM — the trigger for graceful
/// shutdown, so `serve` returns and the mDNS guard sends its goodbye.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "cannot install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("Shutdown signal received; stopping server");
}

/// Start the mDNS / DNS-SD advertiser. Best-effort: a failure to advertise
/// must never stop serving, so it is logged and `None` returned.
fn start_mdns(
    identities: &[sovd_mdns::Identity<'_>],
    scheme: sovd_mdns::Scheme,
    bind_addr: &str,
) -> Option<sovd_mdns::AdvertiserGuard> {
    let Some(adv) = sovd_mdns::SovdAdvertiser::new(identities, scheme, bind_addr) else {
        tracing::warn!(
            "SOVD mDNS advertise skipped: no usable instance name (identification, TLS leaf or hostname)"
        );
        return None;
    };
    tracing::info!(
        instance = %adv.instance,
        identification = %adv.identification,
        accessurl = %adv.accessurl,
        "SOVD mDNS advertising"
    );
    match adv.start() {
        Ok(guard) => Some(guard),
        Err(e) => {
            tracing::warn!(error = %e, "SOVD mDNS advertise failed; serving without discovery");
            None
        }
    }
}

/// Connect a [`LinkBClient`] to the PRE-SPAWNED link-B HSM backend listening on
/// the Unix socket `socket`, retrying while it finishes binding. vm-sovd never
/// spawns the backend (Decision B — process lifecycle is owned externally); it
/// only connects. Mirrors the connect-only retry budget vhsm-ssd uses
/// (~5 s = 50 × 100 ms), so a just-spawned backend isn't missed on the first
/// refused connect.
/// The SOVD state over `backends`; with `node`, they are served on `/v1` as
/// its subcomponents too (`Err` when the node id is unusable or collides with
/// a component's).
fn sovd_state(
    backends: HashMap<String, Arc<dyn DiagnosticBackend>>,
    node: Option<sovd_api::NodeTopology>,
) -> Result<sovd_api::AppState, String> {
    let state = sovd_api::AppState::new(backends);
    // Advertise the vendor extension ops in the merged §7.5 capability
    // description (feature off until the sovd-api hook is on the pinned dep).
    #[cfg(feature = "sovd-docs-hook")]
    let state =
        state.with_capability_extensions(component_mgr::sovd::openapi::capability_extensions());
    match node {
        Some(node) => state.with_node(node),
        None => Ok(state),
    }
}

/// The `/v1` node of `--node-id` (named `--node-name`, else its id), carrying
/// the unit's `identification` on its document when one is known.
fn node_topology(
    id: Option<String>,
    name: Option<String>,
    identification: Option<&str>,
) -> Option<sovd_api::NodeTopology> {
    let id = id?;
    let name = name.unwrap_or_else(|| id.clone());
    let node = sovd_api::NodeTopology::new(id, name);
    Some(match identification {
        Some(identification) => node.with_identification(identification),
        None => node,
    })
}

/// `<prefix>-<first 16 characters of ecu_id>`; `None` when the id is shorter.
fn prefixed_identification(prefix: &str, ecu_id: &str) -> Option<String> {
    ecu_id.get(..16).map(|ecu16| format!("{prefix}-{ecu16}"))
}

/// The `--identification-prefix` identification, from the ECU id `x-ecu-id`
/// serves (the hsm component's device id). `None`, with a warning, when there
/// is none to derive it from.
async fn ecu_identification(machine: &dyn Machine, prefix: &str) -> Option<String> {
    let Some(hsm) = machine.component("hsm") else {
        tracing::warn!("--identification-prefix: no hsm component, no ECU id — ignored");
        return None;
    };
    let ecu_id = match hsm.get_device_id().await {
        Ok(Some(id)) => id,
        Ok(None) => {
            tracing::warn!("--identification-prefix: ECU id unavailable — ignored");
            return None;
        }
        Err(e) => {
            tracing::warn!(error = %e, "--identification-prefix: ECU id read failed — ignored");
            return None;
        }
    };
    let identification = prefixed_identification(prefix, &ecu_id);
    if identification.is_none() {
        tracing::warn!(%ecu_id, "--identification-prefix: ECU id shorter than 16 — ignored");
    }
    identification
}

/// The default (non-gateway) router: the standard SOVD surface plus the sumo
/// vendor routes, behind the node topology when `state` carries a node.
fn plain_router(
    machine: Arc<dyn Machine>,
    state: sovd_api::AppState,
    node_coordinator: Arc<machine_mgr::node_update::NodeCoordinator>,
) -> axum::Router {
    let router = sovd_api::create_router(state.clone())
        .merge(component_mgr::sovd::routes::hsm_router(machine.clone()))
        .merge(component_mgr::sovd::routes::update_state_router(
            node_coordinator,
            machine.clone(),
        ))
        // Keep the vendor routes in sync with component_mgr::sovd::gateway::gateway_router.
        .merge(component_mgr::sovd::routes::node_verdict_router(machine));
    sovd_api::with_node_topology(router, &state)
}

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
async fn build_gateway_router(
    machine: Arc<dyn Machine>,
    mut backends: HashMap<String, Arc<dyn DiagnosticBackend>>,
    crypto: Arc<dyn hsm::HsmCryptoProvider>,
    device_id: Option<String>,
    host_sovd_url: Option<String>,
    proxy_components: &[String],
    node_coordinator: Arc<machine_mgr::node_update::NodeCoordinator>,
    node: Option<sovd_api::NodeTopology>,
) -> axum::Router {
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
    let state = sovd_state(backends, node).unwrap_or_else(|e| fail(&format!("--node-id: {e}")));
    let router = component_mgr::sovd::gateway::gateway_router_with_state(
        machine.clone(),
        state.clone(),
        authorizer,
        trust_anchor,
    )
    .merge(component_mgr::sovd::routes::update_state_router(
        node_coordinator,
        machine,
    ));
    sovd_api::with_node_topology(router, &state)
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn test_machine() -> Arc<dyn Machine> {
        Arc::new(
            MachineRegistry::builder(EntityInfo {
                id: "vehicle".into(),
                name: "vehicle".into(),
                entity_type: "vehicle".into(),
                description: None,
                href: "/vehicle/v1".into(),
                status: None,
            })
            .build()
            .unwrap(),
        )
    }

    async fn post_commit(router: axum::Router) -> StatusCode {
        post_commit_at(router, "/vehicle/v1/operations/x-update-commit/executions").await
    }

    async fn post_commit_at(router: axum::Router, uri: &str) -> StatusCode {
        router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    #[test]
    fn identification_prefix_takes_the_first_16_of_the_ecu_id() {
        assert_eq!(
            prefixed_identification("hpc-vm1", "f88a13a329a72db1c0ffee00c0ffee00").as_deref(),
            Some("hpc-vm1-f88a13a329a72db1")
        );
        assert_eq!(
            prefixed_identification("hpc-vm1", "f88a13a329a72db1").as_deref(),
            Some("hpc-vm1-f88a13a329a72db1")
        );
        assert_eq!(prefixed_identification("hpc-vm1", "f88a13a329a72db"), None);
    }

    /// With --node-id the node form of a node-level route reaches the node
    /// verdict handler, as the root form does without it; with it the root
    /// form answers 404 naming the node form, without it the node form is a
    /// component path of an unknown component.
    #[tokio::test]
    async fn plain_router_serves_the_node_form_with_a_node() {
        let machine = test_machine();
        let coord = Arc::new(machine_mgr::node_update::NodeCoordinator::new());
        let node_form = "/v1/components/hpc/operations/x-update-commit/executions";
        let root_form = "/v1/operations/x-update-commit/executions";

        let node = Some(sovd_api::NodeTopology::new("hpc", "hpc"));
        let with = plain_router(
            machine.clone(),
            sovd_state(HashMap::new(), node).unwrap(),
            coord.clone(),
        );
        let without = plain_router(machine, sovd_state(HashMap::new(), None).unwrap(), coord);
        let root = post_commit_at(without.clone(), root_form).await;
        assert_eq!(root, StatusCode::OK);
        assert_eq!(post_commit_at(with.clone(), node_form).await, root);

        let (status, body) =
            send_text(with, Request::post(root_form).body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert!(body.contains(node_form), "{body}");
        assert_ne!(post_commit_at(without, node_form).await, StatusCode::OK);
    }

    /// `GET uri`: the status and the body text.
    async fn get_text(router: axum::Router, uri: &str) -> (StatusCode, String) {
        send_text(router, Request::get(uri).body(Body::empty()).unwrap()).await
    }

    /// Send `req`: the status and the body text.
    async fn send_text(router: axum::Router, req: Request<Body>) -> (StatusCode, String) {
        let resp = router.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    /// With --node-id, a known identification is carried on the node document
    /// as `x-identification`; without one the member is absent.
    #[tokio::test]
    async fn the_node_document_carries_the_identification() {
        let machine = test_machine();
        let coord = Arc::new(machine_mgr::node_update::NodeCoordinator::new());
        let router = |identification| {
            let node = node_topology(Some("hpc".into()), None, identification);
            plain_router(
                machine.clone(),
                sovd_state(HashMap::new(), node).unwrap(),
                coord.clone(),
            )
        };

        let (status, body) = get_text(
            router(Some("hpc-host-f88a13a329a72db1")),
            "/v1/components/hpc",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body.contains(r#""x-identification":"hpc-host-f88a13a329a72db1""#),
            "{body}"
        );

        let (status, body) = get_text(router(None), "/v1/components/hpc").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(!body.contains("x-identification"), "{body}");

        assert!(node_topology(None, None, Some("hpc-host-f88a13a329a72db1")).is_none());
    }

    /// With --node-id the node form of `x-update-state` serves the body the
    /// node-less server serves at the root form, and the root form answers 404
    /// naming the node form; the legacy alias is unchanged on both.
    #[tokio::test]
    async fn plain_router_serves_x_update_state_under_the_node() {
        let machine = test_machine();
        let coord = Arc::new(machine_mgr::node_update::NodeCoordinator::new());
        let router = |node| {
            plain_router(
                machine.clone(),
                sovd_state(HashMap::new(), node).unwrap(),
                coord.clone(),
            )
        };
        let with = router(node_topology(Some("hpc".into()), None, None));
        let without = router(None);
        let node_form = "/v1/components/hpc/data/x-update-state";

        let root = get_text(without.clone(), "/v1/data/x-update-state").await;
        assert_eq!(root.0, StatusCode::OK, "{}", root.1);
        assert_eq!(get_text(with.clone(), node_form).await, root);
        for router in [&with, &without] {
            let legacy = get_text(router.clone(), "/vehicle/v1/data/x-update-state").await;
            assert_eq!(legacy, root);
        }

        let (status, body) = get_text(with, "/v1/data/x-update-state").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert!(body.contains(node_form), "{body}");
    }

    /// A node id that is also a component's id is refused (startup fails).
    #[test]
    fn a_node_id_colliding_with_a_component_is_refused() {
        let backend: Arc<dyn DiagnosticBackend> = Arc::new(
            component_mgr::backend::ComponentBackend::new(
                BankSet(1),
                Arc::new(Mutex::new(NvStore::new(
                    nv_store::block::MemBlockDevice::new(
                        nv_store::store::MIN_NV_DEVICE_SIZE as usize,
                    ),
                ))),
                Arc::new(SuitProvider::with_factory_authority()),
                component_mgr::backend::ComponentConfig::default(),
            )
            .with_id("vm1".into()),
        );
        let backends = HashMap::from([("vm1".to_string(), backend)]);
        let node = Some(sovd_api::NodeTopology::new("vm1", "vm1"));
        assert!(sovd_state(backends, node).is_err());
    }

    /// The plain server serves the node verdict operations, as the gateway does.
    /// The control (the composition without `node_verdict_router`) 404s, so the
    /// assertion detects the route going missing.
    #[tokio::test]
    async fn plain_router_serves_node_verdict() {
        let machine = test_machine();
        let coord = Arc::new(machine_mgr::node_update::NodeCoordinator::new());

        let state = sovd_state(HashMap::new(), None).unwrap();
        let status = post_commit(plain_router(machine.clone(), state, coord.clone())).await;
        assert_ne!(status, StatusCode::NOT_FOUND);
        assert_ne!(status, StatusCode::METHOD_NOT_ALLOWED);

        let without = sovd_api::create_router(sovd_api::AppState::new(HashMap::new()))
            .merge(component_mgr::sovd::routes::hsm_router(machine.clone()))
            .merge(component_mgr::sovd::routes::update_state_router(
                coord, machine,
            ));
        assert_eq!(post_commit(without).await, StatusCode::NOT_FOUND);
    }
}
