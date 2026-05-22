//! vHSM Secure Storage Daemon (v2) — host-side crypto service for guest VMs.
//!
//! Listens on TCP on a private host bridge (`vbr-vhsm`, 192.168.99.0/24).
//! Identity is derived from the source IP of the connecting socket;
//! the policy file maps each allowed source IP to a `vm_id` plus a
//! permitted-ops bitmask.
//!
//! Usage:
//!   vhsm-ssd --keystore <path> [--listen <ip:port>] [--policy <file>]
//!            [--allow-ip <ip>=<vm_id>]... [--persist-dir <dir>]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use hsm::sim::SimHsm;
use hsm::{HsmCryptoProvider, HsmProvider};

use vhsm_ssd::codec;
use vhsm_ssd::handle_table::HandleTable;
use vhsm_ssd::handler::{self, CallerId};
use vhsm_ssd::policy::Policy;
use vhsm_ssd::proto::*;
use vhsm_ssd::transport::Connection;
use vhsm_ssd::transport::TcpListener;

use secstore::{FileBackend, KeyMetadata, LinuxSimEncryptor, Secstore};

const DEFAULT_LISTEN: &str = "10.0.200.1:5100";

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
    let mut policy_path: Option<PathBuf> = None;
    let mut allow_ip_args: Vec<(std::net::IpAddr, String)> = Vec::new();
    let mut persist_dir: Option<PathBuf> = None;
    let mut extension_handles: Option<PathBuf> = None;
    let mut audit_log_path: Option<PathBuf> = None;
    let mut audit_log_max_bytes: u64 = vhsm_ssd::audit::DEFAULT_MAX_BYTES;
    let mut audit_log_max_rotated: u32 = vhsm_ssd::audit::DEFAULT_MAX_ROTATED;

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
            "--policy" if i + 1 < args.len() => {
                policy_path = Some(PathBuf::from(&args[i + 1]));
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
            "--allow-ip" if i + 1 < args.len() => {
                let raw = &args[i + 1];
                let (ip_str, vm_id) = raw.split_once('=').unwrap_or_else(|| {
                    eprintln!("invalid --allow-ip '{raw}': expected <ip>=<vm_id>");
                    std::process::exit(1);
                });
                let ip: std::net::IpAddr = ip_str.parse().unwrap_or_else(|e| {
                    eprintln!("invalid --allow-ip IP '{ip_str}': {e}");
                    std::process::exit(1);
                });
                allow_ip_args.push((ip, vm_id.to_string()));
                i += 2;
            }
            "--help" | "-h" => {
                eprintln!("Usage: vhsm-ssd --keystore <path> [--listen <ip:port>] [--policy <file>] [--allow-ip <ip>=<vm_id>]...");
                eprintln!();
                eprintln!("  --keystore <path>           HSM keystore directory (required)");
                eprintln!("  --listen <ip:port>          Bind address (default: {DEFAULT_LISTEN})");
                eprintln!("  --policy <file>             IP allow-list file (production)");
                eprintln!("  --allow-ip <ip>=<vm_id>     Grant all permissions to (ip, vm_id) (dev/test, repeatable)");
                eprintln!("  --persist-dir <dir>         Persist dynamic handles to this directory");
                eprintln!("  --extension-handles <file>  YAML manifest of project well-known handles (0x0080..0x00FF)");
                eprintln!("  --audit-log <path>          Enable per-op audit log at this path (size-rotated, fsync per line)");
                eprintln!("  --audit-log-max-bytes <N>   Cap on the active audit log size (default 67108864 = 64 MiB)");
                eprintln!("  --audit-log-max-rotated <K> Number of rotated copies to keep (default 4)");
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

    let listen_addr = listen_addr.unwrap_or_else(|| {
        DEFAULT_LISTEN.parse().expect("DEFAULT_LISTEN parse")
    });

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

    // Load policy.
    let policy = if let Some(ref path) = policy_path {
        match Policy::load_from_file(path) {
            Ok(p) => {
                tracing::info!(
                    path = %path.display(),
                    entries = p.num_entries(),
                    "policy loaded"
                );
                p
            }
            Err(e) => {
                eprintln!("error: failed to load policy: {e}");
                std::process::exit(1);
            }
        }
    } else if !allow_ip_args.is_empty() {
        tracing::info!(?allow_ip_args, "using --allow-ip policy");
        Policy::allow_all(allow_ip_args.into_iter())
    } else {
        eprintln!("error: no --policy or --allow-ip specified");
        eprintln!("       Use --policy <file> for production, or --allow-ip <ip>=<vm_id> for dev/test");
        std::process::exit(1);
    };
    let policy = Arc::new(policy);

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
                eprintln!("error: failed to load --extension-handles {}: {e}", path.display());
                std::process::exit(1);
            }
        }
    }

    // Set up secstore for dynamic handle persistence (optional)
    let store: Option<Arc<Secstore<LinuxSimEncryptor, FileBackend>>> =
        persist_dir.as_ref().map(|dir| {
            let s = Secstore::new(
                LinuxSimEncryptor::default_test(),
                FileBackend::new(dir),
            );
            // Load persisted dynamic handles
            match s.load_all() {
                Ok(metas) => {
                    for m in &metas {
                        let mut label = [0u8; LABEL_LEN];
                        let bytes = m.label.as_bytes();
                        let copy_len = bytes.len().min(LABEL_LEN - 1);
                        label[..copy_len].copy_from_slice(&bytes[..copy_len]);
                        table.allocate(
                            &m.key_id, m.algorithm, m.permitted_ops,
                            &m.owner_vm_id, m.persistent, &label,
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
        "vhsm-ssd v2 starting"
    );

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
    // from connecting. All shared state (handle_table, policy, crypto,
    // store) is already Arc-wrapped and thread-safe.
    loop {
        let mut conn = match listener.accept() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed, retrying");
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
        };

        // Resolve peer IP → vm_id via the policy. A connection from an
        // unallowed IP is rejected immediately, before any bytes are
        // accepted from the wire.
        let peer_ip = conn.peer_ip();
        let vm_id = match policy.lookup(peer_ip) {
            Some(entry) => entry.vm_id.clone(),
            None => {
                tracing::warn!(peer = %peer_ip, "rejecting connection: source IP not in policy");
                drop(conn);
                continue;
            }
        };

        // Clone the per-connection state we'll move into the worker.
        let handle_table = Arc::clone(&handle_table);
        let policy = Arc::clone(&policy);
        let crypto = Arc::clone(&crypto);
        let store = store.clone();
        let audit = Arc::clone(&audit);

        let join = std::thread::Builder::new()
            .name(format!("vhsm-ssd-{vm_id}"))
            .spawn(move || {
                let caller = CallerId {
                    peer_ip,
                    vm_id: vm_id.clone(),
                };
                serve_connection(&mut conn, &caller, &handle_table, &policy, &*crypto, store.as_deref(), &audit);
                handle_table.lock().unwrap().remove_by_vm_id(&caller.vm_id);
                tracing::info!(vm = %caller.vm_id, "connection closed, dynamic handles released");
            });
        if let Err(e) = join {
            tracing::warn!(error = %e, "failed to spawn worker thread, dropping connection");
        }
    }
}

/// Per-connection request-loop. Runs on its own thread so the accept
/// loop in main() stays responsive while a client (e.g. Linux's
/// /dev/vhsm) holds a long-lived TCP session.
fn serve_connection(
    conn: &mut Connection,
    caller: &CallerId,
    handle_table: &Arc<Mutex<HandleTable>>,
    policy: &Policy,
    crypto: &dyn HsmCryptoProvider,
    store: Option<&Secstore<LinuxSimEncryptor, FileBackend>>,
    audit: &Arc<Mutex<vhsm_ssd::audit::AuditLogger>>,
) {
    loop {
        let req = match codec::read_request(conn.reader()) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                tracing::debug!(vm = %caller.vm_id, error = %e, "connection closed");
                break;
            }
        };

        tracing::debug!(
            vm = %caller.vm_id,
            op = req.op,
            session_id = req.session_id,
            "request"
        );

        let table_len_before = handle_table.lock().unwrap().len();

        let resp = {
            let mut table = handle_table.lock().unwrap();
            handler::handle_request(&req, caller, &mut table, policy, crypto)
        };

        // Persist if a dynamic handle was added (KEY_GENERATE success)
        if let Some(s) = store {
            let table = handle_table.lock().unwrap();
            if table.len() > table_len_before {
                if let Some(entry) = table.last() {
                    if entry.persistent {
                        let label_str = std::str::from_utf8(&entry.label)
                            .unwrap_or("")
                            .trim_end_matches('\0')
                            .to_string();
                        let meta = KeyMetadata {
                            vhsm_handle: entry.handle,
                            key_id: entry.key_id.clone(),
                            algorithm: entry.algorithm,
                            permitted_ops: entry.permitted_ops,
                            owner_vm_id: entry.owner_vm_id.clone(),
                            persistent: true,
                            label: label_str,
                        };
                        if let Err(e) = s.store(&meta) {
                            tracing::warn!(handle = entry.handle, error = %e, "failed to persist handle");
                        }
                    }
                }
            }
        }

        // Emit the audit record AFTER status is final and BEFORE
        // we send the response on the wire. A failed audit write
        // logs at error level but does NOT take down the connection
        // — fail-closed policy belongs to the caller, not to the
        // audit subsystem itself. (Tracked: a future config knob
        // could turn this into "refuse the op if audit write fails"
        // for Common-Criteria-style deployments.)
        if let Err(e) = audit.lock().unwrap().record(caller, &req, &resp) {
            tracing::error!(vm = %caller.vm_id, error = %e, "audit log write failed");
        }

        if let Err(e) = codec::write_response(conn.writer(), &resp) {
            tracing::warn!(vm = %caller.vm_id, error = %e, "write error, closing connection");
            break;
        }
    }
}

/// Populate handle table with well-known handles from the keystore.
fn init_handle_table(crypto: &dyn HsmCryptoProvider) -> HandleTable {
    let mut table = HandleTable::new();

    // Map well-known handles to keystore key_ids.
    // These match KeyRole in hsm/src/types.rs.
    let well_known = [
        (HANDLE_SW_AUTHORITY, "sw-authority", ALG_ECC_P256, PERM_VERIFY),
        (HANDLE_DEVICE_DECRYPT, "device-decrypt", ALG_ECC_P256, PERM_DECRYPT | PERM_GET_PUBKEY),
        (HANDLE_ECU_SIGNING, "ecu-signing", ALG_ECC_P256, PERM_SIGN | PERM_VERIFY | PERM_GET_PUBKEY | PERM_GET_CERT),
        (HANDLE_KEY_AUTHORITY, "key-authority", ALG_ECC_P256, PERM_VERIFY),
        (HANDLE_JWT_SIGNING, "jwt-signing", ALG_ECC_P256, PERM_SIGN | PERM_VERIFY | PERM_GET_PUBKEY),
        (HANDLE_STORAGE, "storage-key", ALG_AES_256, PERM_ENCRYPT | PERM_DECRYPT),
    ];

    for (handle, key_id, alg, perms) in &well_known {
        // Only register if the key exists in the keystore
        if crypto.get_key_info(key_id).is_ok() {
            table.register_well_known(*handle, key_id, *alg, *perms);
            tracing::debug!(handle, key_id, "registered well-known handle");
        }
    }

    table
}
