//! Full-daemon end-to-end test — the WHOLE A→B path through the real binary.
//!
//! `tests/integration.rs` drives `handler::handle_request` in isolation and
//! `tests/backend_link_b.rs` drives only `backend::spawn_and_connect`. This test
//! instead spawns the actual `vhsm-ssd` binary and talks to it the way a guest
//! does, so `main.rs`'s real wiring is exercised end to end:
//!
//!   guest client (vhsm-client, guest-auth)
//!     → vhsm-ssd  (link A: v3 CWT handshake + IAM)
//!       → hsm-sim-service  (link B, spawned by the daemon)
//!         → real RustCrypto
//!
//! The guest runs the full CWT handshake — HELLO → ENROLL (the daemon mints a
//! CWT with its `iam-signing` key), then reconnects HELLO → AUTH proving
//! possession of the enrolled identity key — and then runs genuine crypto:
//! `get_random`, a well-known `get_pubkey`, and `key_generate` + `sign` +
//! `verify` on a freshly minted dynamic key. Teardown sends SIGTERM, which also
//! validates the new backend reaper: a clean exit + a no-longer-serving backend.
//!
//! ## Why the FULL handshake (not the documented dispatch-layer fallback)
//!
//! The prompt allowed falling back to driving the post-handshake path against a
//! real `LinkBClient` if a full guest handshake proved impractical. It did not:
//! the `vhsm-client` crate's `guest-auth` feature already implements the exact
//! guest side of the wire (`enroll` / `authenticate`), and the daemon mints the
//! cert itself during ENROLL (signed by the keystore's `iam-signing` key), so no
//! offline CA or cert plumbing is needed — only a bootstrap token, which the
//! ENROLL flow consumes. The full path is therefore both viable and strictly
//! more faithful, so it is used here.
//!
//! `hsm-sim-service` is a bin of the SIBLING `hsm-sim-backend` crate (not exposed via
//! `CARGO_BIN_EXE_*`), so it must be built FIRST:
//!     cargo build -p hsm-sim-backend --bin hsm-sim-service
//! If it isn't found the tests SKIP (loudly) rather than fail spuriously —
//! mirroring `backend_link_b.rs`.

use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use hsm_sim_backend::SimHsm;
use hsm::{HsmCryptoProvider, KeyRole};

use vhsm_client::auth::{authenticate, enroll, AuthConfig};
use vhsm_client::VhsmClient;

use vhsm_ssd::bootstrap::BootstrapState;
use vhsm_ssd::proto::{ALG_ECC_P256, HANDLE_JWT_SIGNING, PERM_GET_PUBKEY, PERM_SIGN, PERM_VERIFY};

/// Locate the `hsm-sim-service` binary built into `target/<profile>/` — a bin of
/// the sibling `hsm-sim-backend` crate, so `env!("CARGO_BIN_EXE_…")` can't name it. Walk our
/// own test-exe ancestors and return the first dir that holds it. (Same shape as
/// `backend_link_b.rs::locate_hsm_sim_service`.)
fn locate_hsm_sim_service() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    for ancestor in exe.ancestors() {
        let candidate = ancestor.join("hsm-sim-service");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Generate the keys the daemon needs into `dir` BEFORE it (and its spawned
/// backend) start. `hsm-sim-service` serves a file-backed `SimHsm`; well-known
/// slots resolve from `keys/<key_id>.{priv,pub}` on disk, so generating them
/// here makes them available to the freshly spawned backend instance:
///   - `iam-signing`: the daemon reads its pubkey at startup (to validate AUTH)
///     and signs minted CWTs with it (during ENROLL).
///   - `jwt-signing`: a guest-exposed EC slot the daemon registers in its handle
///     table (our well-known `get_pubkey` target).
fn provision_keystore(dir: &Path) {
    let hsm = SimHsm::new(dir.to_path_buf());
    hsm.generate_key(KeyRole::IamSigning.handle(), ALG_ECC_P256)
        .expect("generate iam-signing key");
    hsm.generate_key(KeyRole::JwtSigning.handle(), ALG_ECC_P256)
        .expect("generate jwt-signing key");
}

/// Write a minimal AUTH-ARCH-001 policy directory: `policy.yaml` granting `vm1`
/// exactly the ops the e2e runs, plus the required (here empty) `roots/` dir.
fn write_policy_dir(dir: &Path) {
    std::fs::create_dir_all(dir.join("roots")).expect("create roots/ dir");
    let policy = "\
version: 1
statements:
  - principals: [vm1]
    handles: [system]
    ops: [get-random, key-generate]
  - principals: [vm1]
    handles: [jwt-signing]
    ops: [sign, verify, get-pubkey]
";
    std::fs::write(dir.join("policy.yaml"), policy).expect("write policy.yaml");
}

/// Record `vm_id`'s bootstrap token (hashed) in a fresh bootstrap-state file at
/// `path`, so the daemon will accept an ENROLL presenting the raw token.
fn write_bootstrap(path: &Path, vm_id: &str, token: &[u8]) {
    let mut state = BootstrapState::load(path).expect("load empty bootstrap state");
    state.add(vm_id, token);
    state.save().expect("save bootstrap state");
}

/// An ephemeral loopback port: bind `:0`, read the assigned port, drop the
/// listener. A tiny TOCTOU window remains before the daemon rebinds, accepted
/// as the standard pattern for test servers.
fn free_loopback_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local_addr")
        .port()
}

/// Connect to the daemon, retrying until it has bound its listener (a successful
/// connect means it is past `spawn_and_connect` + bind, i.e. fully started) or
/// the deadline passes (then panic — the daemon failed to come up).
fn connect_retry(addr: SocketAddr, timeout: Duration) -> TcpStream {
    let deadline = Instant::now() + timeout;
    loop {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(250)) {
            Ok(s) => return s,
            Err(e) => {
                if Instant::now() >= deadline {
                    panic!("vhsm-ssd never started listening on {addr}: {e}");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Poll `cond` until it is true or `timeout` elapses; returns whether it became
/// true in time.
fn poll_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Owns the spawned `vhsm-ssd` process. Cleans it up via SIGTERM on drop so a
/// panicking test never leaks the daemon (or its backend, which the daemon's
/// reaper kills on SIGTERM).
struct DaemonHandle {
    child: Option<Child>,
}

impl DaemonHandle {
    /// SIGTERM the daemon and wait for it. With the reaper installed this
    /// returns a clean `exit(0)`; the `Child` is consumed so `drop` is a no-op.
    fn sigterm_and_wait(&mut self) -> std::process::ExitStatus {
        let mut child = self.child.take().expect("daemon already reaped");
        // SAFETY: `child.id()` is this process's direct child pid; SIGTERM is a
        // valid signal. kill() failing (already-exited) is harmless — we wait()
        // next regardless.
        unsafe {
            libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
        }
        child.wait().expect("wait for daemon to exit")
    }
}

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // SAFETY: same as sigterm_and_wait — best-effort cleanup after a
            // panic that skipped the explicit shutdown.
            unsafe {
                libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
            }
            let _ = child.wait();
        }
    }
}

/// Spawn the real `vhsm-ssd` binary (output discarded). Required args:
/// `--keystore`, `--policy-dir`, `--bootstrap-state`; plus `--listen` and an
/// explicit `--backend-cmd` so the link-B backend spawns reliably.
fn spawn_daemon(
    daemon_bin: &Path,
    backend_bin: &Path,
    keystore: &Path,
    policy_dir: &Path,
    bootstrap_path: &Path,
    addr: SocketAddr,
) -> DaemonHandle {
    let child = Command::new(daemon_bin)
        .arg("--keystore")
        .arg(keystore)
        .arg("--policy-dir")
        .arg(policy_dir)
        .arg("--bootstrap-state")
        .arg(bootstrap_path)
        .arg("--listen")
        .arg(addr.to_string())
        .arg("--backend-cmd")
        .arg(backend_bin)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn vhsm-ssd binary");
    DaemonHandle { child: Some(child) }
}

#[test]
fn full_daemon_guest_handshake_and_real_crypto() {
    let Some(backend_bin) = locate_hsm_sim_service() else {
        eprintln!(
            "SKIP: hsm-sim-service not built — run \
             `cargo build -p hsm-sim-backend --bin hsm-sim-service` first"
        );
        return;
    };
    let daemon_bin = PathBuf::from(env!("CARGO_BIN_EXE_vhsm-ssd"));

    // tempdirs declared FIRST so they drop AFTER the daemon handle (reverse drop
    // order): the daemon is reaped before its keystore dir is removed.
    let server = tempfile::tempdir().expect("server tempdir");
    let policy = tempfile::tempdir().expect("policy tempdir");
    let guest = tempfile::tempdir().expect("guest tempdir");

    let keystore = server.path().to_path_buf();
    provision_keystore(&keystore);
    write_policy_dir(policy.path());

    let token = [0x5Au8; 32];
    let bootstrap_path = keystore.join("bootstrap.yaml");
    write_bootstrap(&bootstrap_path, "vm1", &token);

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_loopback_port()));
    let mut daemon = spawn_daemon(
        &daemon_bin,
        &backend_bin,
        &keystore,
        policy.path(),
        &bootstrap_path,
        addr,
    );

    // --- ENROLL: HELLO → ENROLL. The daemon mints a CWT (signed by iam-signing);
    // the client persists cert + identity key and consumes the bootstrap token.
    let cfg = AuthConfig::in_dir(guest.path(), "vm1");
    std::fs::write(&cfg.bootstrap_token_path, token).expect("write guest bootstrap token");
    {
        let mut stream = connect_retry(addr, Duration::from_secs(20));
        enroll(&mut stream, &cfg, 1).expect("ENROLL should mint a cert through the daemon");
    }
    assert!(
        cfg.cert_path.exists(),
        "ENROLL must persist the minted cert"
    );
    assert!(
        !cfg.bootstrap_token_path.exists(),
        "ENROLL must consume (delete) the bootstrap token"
    );

    // --- AUTH on a fresh connection (ENROLL is a terminal handshake state), then
    // run crypto over the SAME connection once the principal is bound.
    let mut stream = connect_retry(addr, Duration::from_secs(20));
    let principal =
        authenticate(&mut stream, &cfg, 1).expect("AUTH with the enrolled cert should succeed");
    assert_eq!(principal.vm_id, "vm1", "AUTH must bind the cert subject");

    let mut client = VhsmClient::new(stream);

    // (1) get_random: guest → daemon (IAM: system/get-random) → backend.random().
    let rnd = client
        .get_random(32)
        .expect("get_random through the daemon");
    assert_eq!(rnd.len(), 32, "get_random must return the requested length");
    assert!(
        rnd.iter().any(|&b| b != 0),
        "32 random bytes should not be all-zero"
    );

    // (2) Well-known slot get_pubkey: exercises main.rs's init_handle_table
    // registration of jwt-signing + IAM (jwt-signing/get-pubkey) + the per-handle
    // bitmask + get_public_key_der over link-B.
    let spki = client
        .get_pubkey(HANDLE_JWT_SIGNING)
        .expect("get_pubkey on the well-known jwt-signing slot");
    assert_eq!(
        spki.first(),
        Some(&0x30),
        "SubjectPublicKeyInfo DER starts with an ASN.1 SEQUENCE tag"
    );

    // (3) The strongest "real crypto" proof, independent of well-known slots:
    // mint a fresh dynamic EC key, then sign + verify a genuine signature and
    // reject a tampered one — all flowing through the daemon to the backend's
    // RustCrypto and back.
    let (handle, gen_pub) = client
        .key_generate(
            ALG_ECC_P256,
            PERM_SIGN | PERM_VERIFY | PERM_GET_PUBKEY,
            false,
            "e2e",
        )
        .expect("key_generate a dynamic EC key through the daemon");
    assert!(
        handle >= 0x0100,
        "key_generate must return a dynamic handle (got {handle:#x})"
    );
    assert_eq!(
        gen_pub.first(),
        Some(&0x30),
        "generated EC key returns a SubjectPublicKeyInfo DER"
    );

    let msg = b"full-daemon e2e proof";
    let sig = client.sign(handle, msg).expect("sign through the daemon");
    assert!(!sig.is_empty(), "signature must be non-empty");
    assert!(
        client
            .verify(handle, msg, &sig)
            .expect("verify through the daemon"),
        "a genuine signature must verify"
    );
    assert!(
        !client
            .verify(handle, b"tampered", &sig)
            .expect("verify (tampered) through the daemon"),
        "a tampered message must NOT verify"
    );

    drop(client); // close the guest connection

    // Teardown via SIGTERM also validates the reaper: the handler's `exit(0)`
    // yields a clean exit code, whereas an un-handled SIGTERM would terminate
    // the process by signal (code() == None).
    let status = daemon.sigterm_and_wait();
    assert_eq!(
        status.code(),
        Some(0),
        "SIGTERM should trigger the reaper's clean exit(0), got {status:?}"
    );
}

/// Focused proof of the #2 reaper: on SIGTERM the daemon kills its spawned
/// link-B backend (no orphan) and exits cleanly.
#[test]
fn sigterm_reaper_kills_backend_no_orphan() {
    let Some(backend_bin) = locate_hsm_sim_service() else {
        eprintln!(
            "SKIP: hsm-sim-service not built — run \
             `cargo build -p hsm-sim-backend --bin hsm-sim-service` first"
        );
        return;
    };
    let daemon_bin = PathBuf::from(env!("CARGO_BIN_EXE_vhsm-ssd"));

    let server = tempfile::tempdir().expect("server tempdir");
    let policy = tempfile::tempdir().expect("policy tempdir");

    let keystore = server.path().to_path_buf();
    provision_keystore(&keystore);
    write_policy_dir(policy.path());
    let bootstrap_path = keystore.join("bootstrap.yaml");
    write_bootstrap(&bootstrap_path, "vm1", &[0u8; 32]);

    // The link-B backend binds this Unix socket (the daemon's default
    // <keystore>/hsm-backend.sock). We probe it to tell alive from reaped.
    let backend_socket = keystore.join("hsm-backend.sock");

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_loopback_port()));
    let mut daemon = spawn_daemon(
        &daemon_bin,
        &backend_bin,
        &keystore,
        policy.path(),
        &bootstrap_path,
        addr,
    );

    // Daemon up (so the backend is spawned + connected).
    drop(connect_retry(addr, Duration::from_secs(20)));
    // Backend alive: its link-B socket accepts a connection.
    assert!(
        UnixStream::connect(&backend_socket).is_ok(),
        "backend should be serving its link-B socket before SIGTERM"
    );

    // SIGTERM → the reaper kills + reaps the backend, then exit(0).
    let status = daemon.sigterm_and_wait();
    assert_eq!(
        status.code(),
        Some(0),
        "reaper should exit(0) on SIGTERM, got {status:?}"
    );

    // The backend must no longer accept — proving it was reaped, not orphaned.
    // (A SIGKILL leaves the socket file behind, so a still-running backend would
    // keep accepting; a reaped one yields a connect error.) The daemon reaps the
    // backend with wait() before exiting, so this should already hold; poll
    // briefly for OS listener teardown latency.
    let backend_gone = poll_until(Duration::from_secs(5), || {
        UnixStream::connect(&backend_socket).is_err()
    });
    assert!(
        backend_gone,
        "backend still accepting after daemon exit — it was orphaned, not reaped"
    );
}
