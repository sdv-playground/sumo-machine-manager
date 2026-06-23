//! vHSM Secure Storage Daemon (v3) — host-side crypto service for guest VMs.
//!
//! Listens on TCP on a private host bridge (`vbr-vhsm`, 192.168.99.0/24).
//! Identity is established by a cert-based handshake on each accepted
//! connection (see [`vhsm_ssd::auth`]): HELLO → AUTH (or ENROLL on first
//! boot). Authorisation is statement-based; see [`vhsm_ssd::iam`].
//!
//! Usage:
//!   vhsm-ssd --keystore <path>
//!            (--policy-dir <dir> | --iam-policy <file>)
//!            --bootstrap-state <path>
//!            [--listen <ip:port>]
//!            [--cert-max-age <secs>]
//!            [--persist-dir <dir>]
//!            [--audit-log <path>]
//!            [--audit-log-max-bytes <N>]
//!            [--audit-log-max-rotated <K>]
//!            [--extension-handles <file>]
//!            [--issuer <string>]
//!
//! Policy source:
//!   --policy-dir is the AUTH-ARCH-001 §4 path — points at the policy
//!   directory shipped inside the host-os rootfs bank (typically
//!   `/etc/sumo/policy/`). Reads `policy.yaml` for the IAM policy and
//!   surfaces the rest of the partition's contents (roots/, crl.yaml,
//!   launcher-policy.yaml) via diagnostic log lines.
//!
//!   --iam-policy is the legacy single-file path. Still supported for
//!   dev rigs and SimHsm spawn lines that haven't migrated.

use std::net::{IpAddr, SocketAddr, TcpListener as StdTcpListener, TcpStream as StdTcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use hsm::sim::SimHsm;
use hsm::{HsmCryptoProvider, HsmProvider, KeyRole};

use vhsm_ssd::audit::AuditLogger;
use vhsm_ssd::auth::{self, EnrollContext, HandshakeState, IpResolver, Principal};
use vhsm_ssd::bootstrap::BootstrapState;
use vhsm_ssd::cert::EcuSigner;
use vhsm_ssd::codec;
use vhsm_ssd::crossnode;
use vhsm_ssd::handle_table::HandleTable;
use vhsm_ssd::handler::CallerId;
use vhsm_ssd::iam::IamPolicy;
use vhsm_ssd::proto::*;
use vhsm_ssd::serve::{self, Dispatch};
use vhsm_ssd::tls;
use vhsm_ssd::transport::{Connection, TcpListener};

use rustls::pki_types::CertificateDer;
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use secstore::{FileBackend, LinuxSimEncryptor, Secstore};

const DEFAULT_LISTEN: &str = "10.0.200.1:5100";
const DEFAULT_CERT_LIFETIME_SECS: u64 = 365 * 24 * 60 * 60; // 1 year
const DEFAULT_ISSUER: &str = "device-vhsm-ssd";

/// `EcuSigner` adapter that signs through the configured HSM
/// provider's `iam-signing` key. Lives at the daemon boundary so
/// the cert.rs trait stays HSM-agnostic.
///
/// Calls `sign_raw_p256` (not `sign`) because COSE_Sign1 expects
/// raw 64-byte ECDSA-P256 (r||s); the generic `HsmCryptoProvider::sign`
/// returns DER and would produce CWTs that fail validation.
struct HsmIamSigner {
    crypto: Arc<dyn HsmCryptoProvider>,
}

impl EcuSigner for HsmIamSigner {
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        match self.crypto.sign_raw_p256("iam-signing", data) {
            Ok(sig) => sig,
            Err(e) => {
                // Return an empty sig so the resulting CWT will fail
                // validation on the next AUTH attempt. The client
                // surface this as BadCertSignature; operators see this
                // tracing error in the daemon log.
                tracing::error!(error = %e, "iam-signing HSM sign failed; minted CWT will be unusable");
                Vec::new()
            }
        }
    }
}

/// In-process IP→vm_id resolver. Populated from `--ip-map` CLI args
/// (or, when SimHsm is the spawner, from `hsm.allow:` entries in the
/// supernova-mm config that already enumerate the same `(ip, vm_id)`
/// pairs). Used ONLY by ENROLL_ASSISTED — every other op derives
/// identity from the cert.
struct StaticIpResolver {
    table: std::collections::HashMap<IpAddr, String>,
}

impl StaticIpResolver {
    fn new(entries: Vec<(IpAddr, String)>) -> Self {
        Self {
            table: entries.into_iter().collect(),
        }
    }
}

impl IpResolver for StaticIpResolver {
    fn resolve(&self, ip: &IpAddr) -> Option<String> {
        self.table.get(ip).cloned()
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".parse().unwrap()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let mut keystore_path: Option<PathBuf> = None;
    let mut listen_addr: Option<SocketAddr> = None;
    let mut policy_dir: Option<PathBuf> = None;
    let mut bootstrap_state_path: Option<PathBuf> = None;
    let mut cert_max_age_secs: u64 = DEFAULT_CERT_LIFETIME_SECS;
    let mut persist_dir: Option<PathBuf> = None;
    let mut extension_handles: Option<PathBuf> = None;
    let mut audit_log_path: Option<PathBuf> = None;
    let mut audit_log_max_bytes: u64 = vhsm_ssd::audit::DEFAULT_MAX_BYTES;
    let mut audit_log_max_rotated: u32 = vhsm_ssd::audit::DEFAULT_MAX_ROTATED;
    let mut issuer: String = DEFAULT_ISSUER.to_string();
    let mut ip_map: Vec<(IpAddr, String)> = Vec::new();
    let mut cross_node_listen: Option<SocketAddr> = None;
    let mut identity_root: Option<PathBuf> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--keystore" if i + 1 < args.len() => {
                keystore_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--listen" if i + 1 < args.len() => {
                listen_addr = Some(args[i + 1].parse().unwrap_or_else(|e| {
                    eprintln!("invalid --listen '{}': {e}", args[i + 1]);
                    std::process::exit(1);
                }));
                i += 2;
            }
            "--policy-dir" if i + 1 < args.len() => {
                policy_dir = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--bootstrap-state" if i + 1 < args.len() => {
                bootstrap_state_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--cert-max-age" if i + 1 < args.len() => {
                cert_max_age_secs = args[i + 1].parse().unwrap_or_else(|e| {
                    eprintln!("invalid --cert-max-age '{}': {e}", args[i + 1]);
                    std::process::exit(1);
                });
                i += 2;
            }
            "--issuer" if i + 1 < args.len() => {
                issuer = args[i + 1].clone();
                i += 2;
            }
            "--persist-dir" if i + 1 < args.len() => {
                persist_dir = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--extension-handles" if i + 1 < args.len() => {
                extension_handles = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--audit-log" if i + 1 < args.len() => {
                audit_log_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--audit-log-max-bytes" if i + 1 < args.len() => {
                audit_log_max_bytes = args[i + 1].parse().unwrap_or_else(|e| {
                    eprintln!("invalid --audit-log-max-bytes '{}': {e}", args[i + 1]);
                    std::process::exit(1);
                });
                i += 2;
            }
            "--audit-log-max-rotated" if i + 1 < args.len() => {
                audit_log_max_rotated = args[i + 1].parse().unwrap_or_else(|e| {
                    eprintln!("invalid --audit-log-max-rotated '{}': {e}", args[i + 1]);
                    std::process::exit(1);
                });
                i += 2;
            }
            "--ip-map" if i + 1 < args.len() => {
                // Format: <ip>=<vm_id>. Repeatable. Used ONLY by
                // ENROLL_ASSISTED to resolve source IP → vm_id.
                let raw = &args[i + 1];
                let (ip_str, vm_id) = raw.split_once('=').unwrap_or_else(|| {
                    eprintln!("invalid --ip-map '{raw}': expected <ip>=<vm_id>");
                    std::process::exit(1);
                });
                let ip: IpAddr = ip_str.parse().unwrap_or_else(|e| {
                    eprintln!("invalid --ip-map IP '{ip_str}': {e}");
                    std::process::exit(1);
                });
                ip_map.push((ip, vm_id.to_string()));
                i += 2;
            }
            "--cross-node-listen" if i + 1 < args.len() => {
                cross_node_listen = Some(args[i + 1].parse().unwrap_or_else(|e| {
                    eprintln!("invalid --cross-node-listen '{}': {e}", args[i + 1]);
                    std::process::exit(1);
                }));
                i += 2;
            }
            "--identity-root" if i + 1 < args.len() => {
                identity_root = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(1);
            }
        }
    }

    let keystore_path = keystore_path.unwrap_or_else(|| {
        eprintln!("error: --keystore is required");
        std::process::exit(1);
    });
    // Policy source is the in-bank policy directory at /etc/sumo/policy
    // (AUTH-ARCH-001 §4). Required — there is no fallback. The legacy
    // single-file `--iam-policy` switch was retired once the partition
    // path was proven on the managed-cvc; operators must now ship a
    // policy.yaml (and roots/, crl.yaml) under --policy-dir.
    let policy_dir = policy_dir.unwrap_or_else(|| {
        eprintln!("error: --policy-dir is required");
        std::process::exit(1);
    });
    let bootstrap_state_path = bootstrap_state_path.unwrap_or_else(|| {
        eprintln!("error: --bootstrap-state is required");
        std::process::exit(1);
    });

    // Cross-node mTLS verifies a peer's `tls-identity` leaf against the fleet
    // identity-root CA — public trust material shipped in the policy partition's
    // roots/ as `device-identity-root.pem`, a DISTINCT anchor from the IAM/sw
    // roots (only this CA may vouch for a peer node's identity). Default to it
    // inside --policy-dir so operators wire one path, not two; an explicit
    // --identity-root still wins. If the file isn't there yet (not provisioned),
    // build_cross_node_server_config fails and the listener logs + stays
    // disabled until a policy update ships the root.
    let identity_root =
        identity_root.or_else(|| Some(policy_dir.join("roots/device-identity-root.pem")));

    let listen_addr =
        listen_addr.unwrap_or_else(|| DEFAULT_LISTEN.parse().expect("DEFAULT_LISTEN parse"));

    // Create HSM provider (reads keys from keystore)
    let hsm = SimHsm::new(
        PathBuf::from("unused"),
        keystore_path.clone(),
        listen_addr.port(),
    );

    // Daemon stays up even on an unprovisioned keystore so the listener is
    // always reachable. Key operations against an empty keystore will fail
    // naturally with KeyNotFound until provisioning lands; the host then
    // restarts us (stop+start in vm-mgr's HSM provision path) so we reload
    // with the freshly-written keystore.
    if !hsm.is_provisioned().unwrap_or(false) {
        tracing::info!(
            keystore = %keystore_path.display(),
            "keystore not yet provisioned — accepting connections, key ops will fail until provisioned"
        );
    }

    let crypto: Arc<dyn HsmCryptoProvider> = Arc::new(hsm);

    // Load IAM policy from the in-bank policy directory. Default-deny
    // if the file declares no statements — operator's intent. Refuse
    // to start on parse error / missing file.
    let iam = match vhsm_ssd::iam::load_iam_from_partition(&policy_dir) {
        Ok((iam, statements, partition_loaded_other)) => {
            tracing::info!(
                path = %policy_dir.display(),
                statements,
                roots = partition_loaded_other.roots,
                crl_present = partition_loaded_other.crl,
                launcher_policy_present = partition_loaded_other.launcher_policy,
                "IAM policy loaded from policy directory"
            );
            iam
        }
        Err(e) => {
            eprintln!(
                "error: failed to load --policy-dir {}: {e}",
                policy_dir.display()
            );
            std::process::exit(1);
        }
    };
    let iam = Arc::new(iam);

    // Load bootstrap state. Missing file is fine — creates an empty state
    // (no tokens, so all ENROLL attempts will fail with BadBootstrapToken
    // until an operator populates it).
    let bootstrap = match BootstrapState::load(&bootstrap_state_path) {
        Ok(s) => {
            tracing::info!(
                path = %bootstrap_state_path.display(),
                tokens = s.len(),
                "bootstrap state loaded"
            );
            s
        }
        Err(e) => {
            eprintln!(
                "error: failed to load --bootstrap-state {}: {e}",
                bootstrap_state_path.display()
            );
            std::process::exit(1);
        }
    };
    let bootstrap = Arc::new(Mutex::new(bootstrap));

    // Read iam-signing pubkey once at startup. AUTH verifies CWTs
    // against this; ENROLL / ENROLL_ASSISTED sign new CWTs via
    // HsmIamSigner. The HSM stores the DER-encoded SPKI; convert
    // to raw SEC1 (0x04 || x || y) which is what cert::validate
    // expects.
    let ecu_signing_pub = match crypto.get_public_key_der("iam-signing") {
        Ok(der) => match der_to_sec1_p256(&der) {
            Some(raw) => Arc::<[u8]>::from(raw.into_boxed_slice()),
            None => {
                tracing::warn!("iam-signing pubkey DER didn't decode to a P-256 point; AUTH will reject until restart");
                Arc::<[u8]>::from(Box::<[u8]>::default())
            }
        },
        Err(e) => {
            // Don't fatal — keystore might be pre-provisioning. Log
            // and continue with an empty pub; every AUTH will fail
            // until the keystore lands and we restart.
            tracing::warn!(error = %e, "iam-signing pubkey not in keystore; AUTH will reject until provisioned");
            Arc::<[u8]>::from(Box::<[u8]>::default())
        }
    };

    let signer: Arc<dyn EcuSigner> = Arc::new(HsmIamSigner {
        crypto: Arc::clone(&crypto),
    });

    // IP → vm_id resolver for the ENROLL_ASSISTED handshake. Empty
    // map = ENROLL_ASSISTED disabled; off-box ENROLL with explicit
    // tokens still works. Operators typically populate this with the
    // same `(ip, vm_id)` pairs they use for guest bridge config.
    let ip_resolver: Arc<dyn IpResolver> = Arc::new(StaticIpResolver::new(ip_map.clone()));
    if !ip_map.is_empty() {
        tracing::info!(
            entries = ip_map.len(),
            "ENROLL_ASSISTED enabled — IP-to-vm_id resolver configured"
        );
    } else {
        tracing::info!("ENROLL_ASSISTED disabled (no --ip-map entries)");
    }

    // Initialize handle table with well-known handles from keystore
    let mut table = init_handle_table(&*crypto);

    // Apply project-extension manifest (0x0080..0x00FF band), if one
    // was supplied. Sumo doesn't know what's in there; the daemon's
    // role is just to register the entries as well-known so guests can
    // address them. Missing keystore keys are skipped (same policy as
    // the core init_handle_table).
    if let Some(ref path) = extension_handles {
        match vhsm_ssd::extension_manifest::load_from_file(path) {
            Ok(entries) => {
                let n = vhsm_ssd::extension_manifest::apply(&mut table, &entries, &*crypto);
                tracing::info!(
                    path = %path.display(),
                    declared = entries.len(),
                    registered = n,
                    "applied extension-handles manifest"
                );
            }
            Err(e) => {
                eprintln!(
                    "error: failed to load --extension-handles {}: {e}",
                    path.display()
                );
                std::process::exit(1);
            }
        }
    }

    // Set up secstore for dynamic handle persistence (optional)
    let store: Option<Arc<Secstore<LinuxSimEncryptor, FileBackend>>> =
        persist_dir.as_ref().map(|dir| {
            let s = Secstore::new(LinuxSimEncryptor::default_test(), FileBackend::new(dir));
            match s.load_all() {
                Ok(metas) => {
                    for m in &metas {
                        let mut label = [0u8; LABEL_LEN];
                        let bytes = m.label.as_bytes();
                        let copy_len = bytes.len().min(LABEL_LEN - 1);
                        label[..copy_len].copy_from_slice(&bytes[..copy_len]);
                        table.allocate(
                            &m.key_id,
                            m.algorithm,
                            m.permitted_ops,
                            &m.owner_vm_id,
                            m.persistent,
                            &label,
                        );
                    }
                    tracing::info!(count = metas.len(), "loaded persisted handles");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to load persisted handles");
                }
            }
            Arc::new(s)
        });

    let handle_table = Arc::new(Mutex::new(table));

    // Open the per-op audit log if requested. Fail-loud on open
    // error: an operator who passed --audit-log expects audit; a
    // silently-disabled logger would be the worst kind of bug.
    let audit = match audit_log_path.as_ref() {
        Some(path) => match vhsm_ssd::audit::AuditLogger::open(
            path,
            audit_log_max_bytes,
            audit_log_max_rotated,
        ) {
            Ok(a) => {
                tracing::info!(
                    path = %path.display(),
                    max_bytes = audit_log_max_bytes,
                    max_rotated = audit_log_max_rotated,
                    "audit log enabled"
                );
                a
            }
            Err(e) => {
                eprintln!("error: failed to open --audit-log {}: {e}", path.display());
                std::process::exit(1);
            }
        },
        None => {
            tracing::info!("audit log disabled (no --audit-log path supplied)");
            vhsm_ssd::audit::AuditLogger::disabled()
        }
    };
    let audit = Arc::new(Mutex::new(audit));

    tracing::info!(
        keystore = %keystore_path.display(),
        handles = handle_table.lock().unwrap().len(),
        persist = persist_dir.is_some(),
        cert_max_age_secs,
        "vhsm-ssd v3 starting"
    );

    // Optional cross-node mTLS listener (a SECOND bind, distinct from the guest
    // private-bridge listener below). Off unless --cross-node-listen is set. It
    // needs the host's TlsIdentity leaf (an HSM cert object) and the identity
    // root PEM (the policy-partition trust anchor for peer client certs). If
    // either isn't provisioned yet, we log and run WITHOUT it — the guest
    // listener still comes up, and a host restart after provisioning lights this
    // up. Spawned as a detached thread so it serves alongside the guest loop.
    if let Some(xnode_addr) = cross_node_listen {
        match build_cross_node_server_config(&crypto, identity_root.as_deref()) {
            Ok(server_cfg) => {
                let server_cfg = Arc::new(server_cfg);
                let handle_table = Arc::clone(&handle_table);
                let iam = Arc::clone(&iam);
                let crypto = Arc::clone(&crypto);
                let store = store.clone();
                let audit = Arc::clone(&audit);
                let spawned = std::thread::Builder::new()
                    .name("vhsm-xnode-listener".to_string())
                    .spawn(move || {
                        run_cross_node_listener(
                            xnode_addr,
                            server_cfg,
                            handle_table,
                            iam,
                            crypto,
                            store,
                            audit,
                        );
                    });
                if let Err(e) = spawned {
                    tracing::error!(error = %e, "failed to spawn cross-node listener thread");
                }
            }
            Err(e) => {
                tracing::warn!(
                    addr = %xnode_addr,
                    reason = %e,
                    "cross-node listener configured but TLS identity not ready — disabled until provisioned"
                );
            }
        }
    } else {
        tracing::info!("cross-node mTLS listener disabled (no --cross-node-listen)");
    }

    // Bind TCP listener.
    let listener = match TcpListener::bind(listen_addr) {
        Ok(l) => {
            tracing::info!(addr = %l.local_addr(), "listening on tcp");
            l
        }
        Err(e) => {
            eprintln!("error: tcp bind to {listen_addr} failed: {e}");
            std::process::exit(1);
        }
    };

    // Accept loop — spawn a thread per accepted connection so a
    // long-lived client (e.g. Linux's /dev/vhsm kernel module which
    // keeps a persistent TCP session open) doesn't block other guests
    // from connecting. All shared state (handle_table, iam, bootstrap,
    // crypto, signer, store, audit) is already Arc-wrapped and
    // thread-safe.
    loop {
        let mut conn = match listener.accept() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed, retrying");
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
        };
        let peer_ip = conn.peer_ip();

        // Clone the per-connection state we'll move into the worker.
        let handle_table = Arc::clone(&handle_table);
        let iam = Arc::clone(&iam);
        let bootstrap = Arc::clone(&bootstrap);
        let signer = Arc::clone(&signer);
        let ecu_signing_pub = Arc::clone(&ecu_signing_pub);
        let crypto = Arc::clone(&crypto);
        let store = store.clone();
        let audit = Arc::clone(&audit);
        let issuer = issuer.clone();
        let ip_resolver = Arc::clone(&ip_resolver);

        let join = std::thread::Builder::new()
            .name(format!("vhsm-ssd-{peer_ip}"))
            .spawn(move || {
                serve_connection(
                    &mut conn,
                    peer_ip,
                    &ecu_signing_pub,
                    &iam,
                    &bootstrap,
                    &*signer,
                    &issuer,
                    cert_max_age_secs,
                    &*ip_resolver,
                    &handle_table,
                    &*crypto,
                    store.as_deref(),
                    &audit,
                );
            });
        if let Err(e) = join {
            tracing::warn!(error = %e, "failed to spawn worker thread, dropping connection");
        }
    }
}

/// Per-connection request loop. First runs the v3 handshake to bind a
/// principal, then dispatches subsequent ops through `handler::handle_request`.
/// On Failed or Enrolled (terminal) states the connection closes.
#[allow(clippy::too_many_arguments)]
fn serve_connection(
    conn: &mut Connection,
    peer_ip: IpAddr,
    ecu_signing_pub: &[u8],
    iam: &Arc<IamPolicy>,
    bootstrap: &Arc<Mutex<BootstrapState>>,
    signer: &dyn EcuSigner,
    issuer: &str,
    cert_lifetime_secs: u64,
    ip_resolver: &dyn IpResolver,
    handle_table: &Arc<Mutex<HandleTable>>,
    crypto: &dyn HsmCryptoProvider,
    store: Option<&Secstore<LinuxSimEncryptor, FileBackend>>,
    audit: &Arc<Mutex<vhsm_ssd::audit::AuditLogger>>,
) {
    tracing::info!(peer = %peer_ip, "vhsm v3 connection accepted; awaiting HELLO");

    let mut hs_state = HandshakeState::new();
    let mut principal: Option<Principal> = None;

    loop {
        let req = match codec::read_request(conn.reader()) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                tracing::debug!(peer = %peer_ip, "client closed");
                break;
            }
            Err(e) => {
                tracing::debug!(peer = %peer_ip, error = %e, "connection closed (read error)");
                break;
            }
        };

        if principal.is_none() {
            // Pre-handshake: route through auth::step.
            tracing::debug!(
                peer = %peer_ip,
                op = req.op,
                session_id = req.session_id,
                "handshake request"
            );

            let resp = {
                let mut bootstrap_guard = bootstrap.lock().unwrap();
                let mut ctx = EnrollContext {
                    bootstrap: &mut bootstrap_guard,
                    signer,
                    issuer,
                    cert_lifetime_secs,
                    peer_ip: Some(peer_ip),
                    ip_resolver: Some(ip_resolver),
                };
                auth::step(
                    &mut hs_state,
                    &req,
                    ecu_signing_pub,
                    iam,
                    Some(&mut ctx),
                    SystemTime::now(),
                )
            };

            if let Err(e) = codec::write_response(conn.writer(), &resp) {
                tracing::warn!(peer = %peer_ip, error = %e, "handshake write error");
                break;
            }

            // Inspect the state transition.
            match &hs_state {
                HandshakeState::Authenticated(p) => {
                    tracing::info!(
                        peer = %peer_ip,
                        vm = %p.vm_id,
                        thumbprint = %hex_short(&p.cert_thumbprint),
                        "principal authenticated"
                    );
                    principal = Some(p.clone());
                }
                HandshakeState::Enrolled {
                    vm_id,
                    cert_thumbprint,
                } => {
                    tracing::info!(
                        peer = %peer_ip,
                        vm = %vm_id,
                        thumbprint = %hex_short(cert_thumbprint),
                        "principal enrolled (terminal — client must reconnect)"
                    );
                    break;
                }
                HandshakeState::Failed(reason) => {
                    tracing::warn!(
                        peer = %peer_ip,
                        ?reason,
                        "handshake failed, closing"
                    );
                    break;
                }
                _ => {
                    // AwaitHello or NonceSent — handshake in progress, keep reading.
                }
            }
            continue;
        }

        // Post-handshake: normal op dispatch.
        let p = principal.as_ref().expect("principal is Some here");
        let caller = CallerId {
            peer_ip,
            vm_id: p.vm_id.clone(),
            cert_thumbprint: p.cert_thumbprint,
        };

        tracing::debug!(
            vm = %caller.vm_id,
            op = req.op,
            session_id = req.session_id,
            "request"
        );

        // Identity is bound; run the shared post-handshake dispatch (also used
        // by the cross-node TLS path) — handle_request + persist + audit + write.
        match serve::dispatch_request(
            &req,
            &caller,
            conn.writer(),
            handle_table,
            iam,
            crypto,
            store,
            audit,
        ) {
            Dispatch::Continue => {}
            Dispatch::Close => break,
        }
    }

    // Release dynamic handles owned by this connection (if any).
    if let Some(p) = principal.as_ref() {
        handle_table.lock().unwrap().remove_by_vm_id(&p.vm_id);
        tracing::info!(vm = %p.vm_id, "connection closed, dynamic handles released");
    } else {
        tracing::debug!(peer = %peer_ip, "connection closed before handshake completed");
    }
}

/// Assemble the cross-node mTLS `ServerConfig` from provisioned material: the
/// host's `TlsIdentity` leaf (an HSM cert object, fetched via `get_certificate_der`)
/// and the identity-root PEM (the policy-partition trust anchor that peer client
/// certs must chain to). Returns `Err` — the caller logs and disables the
/// listener — when `--identity-root` is missing or either piece isn't yet
/// provisioned, so a fresh device comes up serving guests with cross-node off
/// until its identity lands.
fn build_cross_node_server_config(
    crypto: &Arc<dyn HsmCryptoProvider>,
    identity_root_pem: Option<&Path>,
) -> Result<ServerConfig, String> {
    let root_path = identity_root_pem
        .ok_or("--identity-root <pem> is required when --cross-node-listen is set")?;
    let root_pem = std::fs::read(root_path)
        .map_err(|e| format!("read identity root {}: {e}", root_path.display()))?;
    let client_roots =
        tls::identity_root_store(&root_pem).map_err(|e| format!("parse identity root: {e}"))?;

    let tls_kid = KeyRole::TlsIdentity.key_id();
    let leaf_der = crypto
        .get_certificate_der(tls_kid)
        .map_err(|e| format!("TlsIdentity leaf cert not provisioned ('{tls_kid}'): {e}"))?;
    let server_chain = vec![CertificateDer::from(leaf_der)];

    tls::server_config(Arc::clone(crypto), tls_kid, server_chain, client_roots)
        .map_err(|e| format!("build server config: {e}"))
}

/// Cross-node mTLS accept loop. One thread per connection (like the guest loop)
/// so a slow handshake or a long-lived peer can't block other nodes. Runs until
/// the process exits; a bind failure logs and returns (cross-node unavailable,
/// guests unaffected).
#[allow(clippy::too_many_arguments)]
fn run_cross_node_listener(
    listen: SocketAddr,
    server_cfg: Arc<ServerConfig>,
    handle_table: Arc<Mutex<HandleTable>>,
    iam: Arc<IamPolicy>,
    crypto: Arc<dyn HsmCryptoProvider>,
    store: Option<Arc<Secstore<LinuxSimEncryptor, FileBackend>>>,
    audit: Arc<Mutex<AuditLogger>>,
) {
    let listener = match StdTcpListener::bind(listen) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(addr = %listen, error = %e, "cross-node mTLS bind failed; cross-node access unavailable");
            return;
        }
    };
    tracing::info!(addr = %listen, "cross-node mTLS listener bound");

    loop {
        let (tcp, peer) = match listener.accept() {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "cross-node accept failed, retrying");
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
        };
        let _ = tcp.set_nodelay(true);
        let peer_ip = peer.ip();

        let server_cfg = Arc::clone(&server_cfg);
        let handle_table = Arc::clone(&handle_table);
        let iam = Arc::clone(&iam);
        let crypto = Arc::clone(&crypto);
        let store = store.clone();
        let audit = Arc::clone(&audit);

        let spawned = std::thread::Builder::new()
            .name(format!("vhsm-xnode-{peer_ip}"))
            .spawn(move || {
                serve_one_cross_node(
                    tcp,
                    peer_ip,
                    server_cfg,
                    &handle_table,
                    &iam,
                    &*crypto,
                    store.as_deref(),
                    &audit,
                );
            });
        if let Err(e) = spawned {
            tracing::warn!(error = %e, "failed to spawn cross-node worker, dropping connection");
        }
    }
}

/// Complete the mTLS handshake on one accepted cross-node socket, derive the
/// principal from the verified client cert, then hand off to the shared
/// cross-node dispatch loop. Any failure before a principal is bound just drops
/// the connection (logged) — the daemon stays up.
#[allow(clippy::too_many_arguments)]
fn serve_one_cross_node(
    mut tcp: StdTcpStream,
    peer_ip: IpAddr,
    server_cfg: Arc<ServerConfig>,
    handle_table: &Arc<Mutex<HandleTable>>,
    iam: &IamPolicy,
    crypto: &dyn HsmCryptoProvider,
    store: Option<&Secstore<LinuxSimEncryptor, FileBackend>>,
    audit: &Arc<Mutex<AuditLogger>>,
) {
    let mut conn = match ServerConnection::new(server_cfg) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(peer = %peer_ip, error = %e, "cross-node rustls session init failed");
            return;
        }
    };
    // Drive the handshake to completion; the client cert is verified here
    // against the identity root before any vHSM byte is read.
    if let Err(e) = conn.complete_io(&mut tcp) {
        tracing::warn!(peer = %peer_ip, error = %e, "cross-node mTLS handshake failed");
        return;
    }
    let principal = match conn.peer_certificates().and_then(|certs| certs.first()) {
        Some(leaf) => match crossnode::principal_from_client_cert(leaf.as_ref()) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(peer = %peer_ip, error = %e, "cross-node client cert yields no principal");
                return;
            }
        },
        None => {
            // WebPkiClientVerifier requires a client cert, so reaching here means
            // a rustls contract changed — fail closed.
            tracing::warn!(peer = %peer_ip, "cross-node client presented no certificate");
            return;
        }
    };

    let mut tls = StreamOwned::new(conn, tcp);
    crossnode::serve_crossnode_connection(
        &mut tls,
        &principal,
        peer_ip,
        handle_table,
        iam,
        crypto,
        store,
        audit,
    );
}

/// Populate handle table with well-known handles from the keystore.
fn init_handle_table(crypto: &dyn HsmCryptoProvider) -> HandleTable {
    let mut table = HandleTable::new();

    // Register the guest-addressable well-known handles from the single slot
    // registry (vhsm-proto `SUMO_CORE_SLOTS`). Host-only slots (iam-signing,
    // ivd-signing, freshness-signing, tls-identity) are `guest_exposed: false`
    // and skipped — e.g. `iam-signing` (HANDLE_IAM_SIGNING = 0x0004) is the
    // daemon-internal cert-issuing key, never addressable by guest principals
    // (CWT mint goes through the HsmIamSigner adapter, calling sign_raw_p256
    // directly — host-privileged, bypassing the handle table). A slot is
    // registered only if its key actually exists in the keystore (soft-missing
    // keys are skipped).
    for slot in SUMO_CORE_SLOTS.iter().filter(|s| s.guest_exposed) {
        if crypto.get_key_info(slot.key_id).is_ok() {
            table.register_well_known(slot.handle, slot.key_id, slot.alg, slot.default_perms);
            tracing::debug!(
                handle = slot.handle,
                key_id = slot.key_id,
                "registered well-known handle"
            );
        }
    }

    table
}

/// Short lower-hex prefix of a SHA-256 (first 8 bytes / 16 hex chars).
/// Enough for log-line correlation; full thumbprint is in the audit log.
fn hex_short(tp: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for b in &tp[..8] {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Decode a DER-encoded SubjectPublicKeyInfo into a raw 65-byte SEC1
/// uncompressed P-256 point (`0x04 || x[32] || y[32]`). Returns None
/// on parse failure or non-P-256 curve.
fn der_to_sec1_p256(der: &[u8]) -> Option<Vec<u8>> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::pkcs8::DecodePublicKey;
    let pk = p256::PublicKey::from_public_key_der(der).ok()?;
    let encoded = pk.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    if bytes.len() == 65 && bytes[0] == 0x04 {
        Some(bytes.to_vec())
    } else {
        None
    }
}

fn print_usage() {
    eprintln!("Usage: vhsm-ssd --keystore <path> (--policy-dir <dir> | --iam-policy <file>) --bootstrap-state <path> [options]");
    eprintln!();
    eprintln!("Required:");
    eprintln!("  --keystore <path>           HSM keystore directory");
    eprintln!("  --policy-dir <dir>          Policy directory (AUTH-ARCH-001 §4 — Phase 3 path).");
    eprintln!("                              Contains policy.yaml + roots/ + (optional) crl.yaml.");
    eprintln!(
        "                              Typically /etc/sumo/policy/ shipped inside the host-os"
    );
    eprintln!("                              rootfs bank.");
    eprintln!("  --iam-policy <file>         YAML policy file (legacy; mutually exclusive with --policy-dir).");
    eprintln!("                              Statements + principals + handles + ops.");
    eprintln!("  --bootstrap-state <path>    YAML bootstrap token state");
    eprintln!();
    eprintln!("Connection:");
    eprintln!("  --listen <ip:port>          Bind address (default: {DEFAULT_LISTEN})");
    eprintln!("  --cert-max-age <secs>       Lifetime of CWTs minted via ENROLL (default {DEFAULT_CERT_LIFETIME_SECS})");
    eprintln!("  --issuer <string>           CWT `iss` claim value (default '{DEFAULT_ISSUER}')");
    eprintln!();
    eprintln!("Cross-node mTLS (off unless --cross-node-listen is set):");
    eprintln!("  --cross-node-listen <ip:port>  Second bind for node-to-node access; the peer is");
    eprintln!(
        "                                 authenticated by its TLS client cert (cert = principal),"
    );
    eprintln!("                                 then authorized per-node via the same IAM policy.");
    eprintln!(
        "  --identity-root <pem>          Trust anchor (identity-root CA, PEM) peer client certs"
    );
    eprintln!(
        "                                 must chain to. Default: <policy-dir>/roots/device-identity-root.pem."
    );
    eprintln!();
    eprintln!("Storage / handles:");
    eprintln!("  --persist-dir <dir>         Persist dynamic handles to this directory");
    eprintln!("  --extension-handles <file>  YAML manifest of project well-known handles (0x0080..0x00FF)");
    eprintln!();
    eprintln!("Audit:");
    eprintln!("  --audit-log <path>          Enable per-op audit log at this path (size-rotated, fsync per line)");
    eprintln!("  --audit-log-max-bytes <N>   Cap on the active audit log size (default 67108864 = 64 MiB)");
    eprintln!("  --audit-log-max-rotated <K> Number of rotated copies to keep (default 4)");
}

#[cfg(test)]
mod tests {
    use super::*;

    // Both cases fail at the identity-root PEM step, before any keystore/HSM
    // access, so the keystore path need not exist.
    fn unprovisioned_crypto() -> Arc<dyn HsmCryptoProvider> {
        Arc::new(SimHsm::new(
            PathBuf::from("unused"),
            PathBuf::from("/nonexistent-keystore"),
            0,
        ))
    }

    // The startup path turns these Errs into a warn-and-disable (a fresh device
    // serves guests with cross-node off until its identity is provisioned),
    // rather than crashing the daemon — so they must be Errs, not panics.
    #[test]
    fn cross_node_config_requires_identity_root() {
        let crypto = unprovisioned_crypto();
        let err = build_cross_node_server_config(&crypto, None).unwrap_err();
        assert!(
            err.contains("identity-root"),
            "a missing --identity-root must be reported, got: {err}"
        );
    }

    #[test]
    fn cross_node_config_errors_on_unreadable_identity_root() {
        let crypto = unprovisioned_crypto();
        let err = build_cross_node_server_config(&crypto, Some(Path::new("/nonexistent/root.pem")))
            .unwrap_err();
        assert!(
            err.contains("read identity root"),
            "an unreadable identity root must be reported, got: {err}"
        );
    }
}
