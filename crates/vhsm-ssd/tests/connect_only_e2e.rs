//! Connect-only end-to-end test — vhsm-ssd attaches to an EXTERNALLY-spawned
//! link-B backend and, on SIGTERM, exits cleanly WITHOUT reaping it.
//!
//! Where `tests/full_daemon_e2e.rs` proves the DEFAULT path (vhsm-ssd spawns +
//! reaps its backend), this proves the opt-in `--backend-connect-only` path:
//!
//!   1. The TEST pre-spawns `hsm-sim-service` on its own keystore + socket — the
//!      stand-in for an orchestrator that owns the backend's lifecycle.
//!   2. vhsm-ssd runs with `--backend-connect-only --backend-socket <that socket>`
//!      (no `--backend-cmd`): it CONNECTS to the running backend rather than
//!      spawning one. To prove every key/crypto op crosses link-B (not vhsm-ssd's
//!      own `--keystore`), the daemon is given a SEPARATE, EMPTY keystore dir.
//!   3. A guest drives the real CWT handshake (ENROLL → AUTH) + genuine crypto
//!      through the daemon, exactly as in `full_daemon_e2e.rs`.
//!   4. vhsm-ssd is SIGTERMed and must exit cleanly (code 0) via the child-less
//!      `spawn_signal_exit` path — AND the externally-spawned backend must STILL
//!      be serving its socket afterward (connect-only does NOT reap it).
//!   5. The test tears the backend down itself.
//!
//! `hsm-sim-service` is a bin of the SIBLING `hsm-sim-backend` crate (not exposed via
//! `CARGO_BIN_EXE_*`), so it must be built FIRST:
//!     cargo build -p hsm-sim-backend --bin hsm-sim-service
//! If it isn't found the test SKIPs (loudly) rather than failing spuriously —
//! mirroring `full_daemon_e2e.rs` / `backend_link_b.rs`.

use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use hsm::{HsmCryptoProvider, KeyRole};
use hsm_sim_backend::SimHsm;

use vhsm_client::auth::{authenticate, enroll, AuthConfig};
use vhsm_client::VhsmClient;

use vhsm_ssd::bootstrap::BootstrapState;
use vhsm_ssd::proto::{ALG_ECC_P256, PERM_GET_PUBKEY, PERM_SIGN, PERM_VERIFY};

/// Locate the `hsm-sim-service` binary built into `target/<profile>/` — a bin of
/// the sibling `hsm-sim-backend` crate, so `env!("CARGO_BIN_EXE_…")` can't name it. Walk our
/// own test-exe ancestors and return the first dir that holds it.
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

/// Generate the keys the backend keystore needs into `dir` BEFORE the backend
/// starts (same as `full_daemon_e2e.rs`): `iam-signing` (the daemon reads its
/// pubkey to validate AUTH and signs minted CWTs with it during ENROLL) and
/// `jwt-signing` (a guest-exposed EC slot). The daemon reaches both over link-B.
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
/// connect means it is past connect-to-backend + bind, i.e. fully started) or the
/// deadline passes (then panic — the daemon failed to come up).
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

/// Owns the EXTERNALLY pre-spawned link-B backend (the orchestrator's role).
/// Cleans it up via kill on drop so a panicking test never leaks it — this is the
/// "tear the backend down ourselves" the connect-only contract requires.
struct BackendHandle {
    child: Child,
}

impl Drop for BackendHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Pre-spawn `hsm-sim-service --keystore <ks> --listen <socket>` (the exact line
/// `link_b::spawn_and_connect` would run, but here OWNED BY THE TEST), then wait
/// for it to bind its socket. This is the externally-managed backend vhsm-ssd
/// will merely connect to.
fn prespawn_backend(backend_bin: &Path, keystore: &Path, socket: &Path) -> BackendHandle {
    let child = Command::new(backend_bin)
        .arg("--keystore")
        .arg(keystore)
        .arg("--listen")
        .arg(socket)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn pre-spawned hsm-sim-service backend");
    let handle = BackendHandle { child };

    // Wait until the backend accepts on its link-B socket before handing it to
    // the daemon — makes the test deterministic (the daemon's connect-retry would
    // also cover this, but asserting it here pinpoints a backend that never came
    // up).
    let bound = poll_until(Duration::from_secs(20), || {
        UnixStream::connect(socket).is_ok()
    });
    assert!(
        bound,
        "pre-spawned backend never bound its link-B socket {}",
        socket.display()
    );
    handle
}

/// Owns the spawned `vhsm-ssd` process. SIGTERM on drop so a panicking test never
/// leaks the daemon.
struct DaemonHandle {
    child: Option<Child>,
}

impl DaemonHandle {
    /// SIGTERM the daemon and wait for it. With the connect-only signal-exit path
    /// installed this returns a clean `exit(0)`; the `Child` is consumed so `drop`
    /// is a no-op.
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
            // SAFETY: same as sigterm_and_wait — best-effort cleanup after a panic
            // that skipped the explicit shutdown.
            unsafe {
                libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
            }
            let _ = child.wait();
        }
    }
}

/// Spawn the real `vhsm-ssd` binary in CONNECT-ONLY mode: pointed at the
/// pre-spawned backend's `socket` via `--backend-connect-only --backend-socket`,
/// with NO `--backend-cmd`. `keystore` here is deliberately a separate empty dir
/// — proving the daemon's crypto all crosses link-B to the external backend.
fn spawn_daemon_connect_only(
    daemon_bin: &Path,
    keystore: &Path,
    policy_dir: &Path,
    bootstrap_path: &Path,
    backend_socket: &Path,
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
        .arg("--backend-connect-only")
        .arg("--backend-socket")
        .arg(backend_socket)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn vhsm-ssd binary");
    DaemonHandle { child: Some(child) }
}

#[test]
fn connect_only_drives_crypto_and_does_not_reap_external_backend() {
    let Some(backend_bin) = locate_hsm_sim_service() else {
        eprintln!(
            "SKIP: hsm-sim-service not built — run \
             `cargo build -p hsm-sim-backend --bin hsm-sim-service` first"
        );
        return;
    };
    let daemon_bin = PathBuf::from(env!("CARGO_BIN_EXE_vhsm-ssd"));

    // tempdirs declared FIRST so they drop AFTER the process handles (reverse drop
    // order): both processes are reaped before their dirs are removed.
    let backend_ks = tempfile::tempdir().expect("backend keystore tempdir");
    let daemon_ks = tempfile::tempdir().expect("daemon keystore tempdir (empty)");
    let policy = tempfile::tempdir().expect("policy tempdir");
    let guest = tempfile::tempdir().expect("guest tempdir");

    // The backend serves a PROVISIONED keystore; the daemon's own keystore stays
    // EMPTY (it must reach every key over link-B).
    provision_keystore(backend_ks.path());
    write_policy_dir(policy.path());

    let token = [0x5Au8; 32];
    let bootstrap_path = daemon_ks.path().join("bootstrap.yaml");
    write_bootstrap(&bootstrap_path, "vm1", &token);

    // Pre-spawn the backend OURSELVES (the orchestrator's role) on its own socket.
    let backend_socket = backend_ks.path().join("hsm-backend.sock");
    let backend = prespawn_backend(&backend_bin, backend_ks.path(), &backend_socket);

    // Bring up vhsm-ssd in connect-only mode against that running backend.
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_loopback_port()));
    let mut daemon = spawn_daemon_connect_only(
        &daemon_bin,
        daemon_ks.path(),
        policy.path(),
        &bootstrap_path,
        &backend_socket,
        addr,
    );

    // --- ENROLL: HELLO → ENROLL. The daemon mints a CWT (signed by iam-signing,
    // read over link-B from the EXTERNAL backend's keystore); the client persists
    // cert + identity key and consumes the bootstrap token.
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

    // --- AUTH on a fresh connection (ENROLL is terminal), then run crypto over
    // the SAME connection once the principal is bound — all flowing through the
    // connect-only daemon to the EXTERNAL backend's RustCrypto and back.
    let mut stream = connect_retry(addr, Duration::from_secs(20));
    let principal =
        authenticate(&mut stream, &cfg, 1).expect("AUTH with the enrolled cert should succeed");
    assert_eq!(principal.vm_id, "vm1", "AUTH must bind the cert subject");

    let mut client = VhsmClient::new(stream);

    // (1) get_random: guest → daemon (IAM: system/get-random) → backend.random()
    // over link-B.
    let rnd = client
        .get_random(32)
        .expect("get_random through the daemon");
    assert_eq!(rnd.len(), 32, "get_random must return the requested length");
    assert!(
        rnd.iter().any(|&b| b != 0),
        "32 random bytes should not be all-zero"
    );

    // (2) Real crypto: mint a dynamic EC key, sign + verify a genuine signature,
    // reject a tampered one — proving the full A→B crypto path works in
    // connect-only mode.
    let (handle, gen_pub) = client
        .key_generate(
            ALG_ECC_P256,
            PERM_SIGN | PERM_VERIFY | PERM_GET_PUBKEY,
            false,
            "connect-only-e2e",
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

    let msg = b"connect-only e2e proof";
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

    // --- Teardown: SIGTERM vhsm-ssd. The connect-only signal-exit path yields a
    // clean exit(0) (an un-handled SIGTERM would terminate by signal, code None).
    let status = daemon.sigterm_and_wait();
    assert_eq!(
        status.code(),
        Some(0),
        "SIGTERM should trigger the connect-only clean exit(0), got {status:?}"
    );

    // --- THE no-reap proof: the EXTERNALLY-spawned backend must STILL be serving
    // its link-B socket. vhsm-ssd never owned it, so connect-only must not have
    // killed it. (In the spawn-mode reaper test the inverse holds — the backend
    // is gone.) Poll briefly to rule out any scheduling transient.
    let backend_alive = poll_until(Duration::from_secs(2), || {
        UnixStream::connect(&backend_socket).is_ok()
    });
    assert!(
        backend_alive,
        "external backend stopped accepting after vhsm-ssd exit — connect-only \
         wrongly reaped the orchestrator-owned backend"
    );

    // We own the backend: tear it down ourselves (also covered by Drop on panic).
    drop(backend);
}
