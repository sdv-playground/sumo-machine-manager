//! The full two-daemon standup against the REAL binaries.
//!
//! This exercises `hsm_supervisor::standup` itself — not a re-implementation —
//! end-to-end against a temp keystore: both children spawn, an op crosses link-B
//! in each direction, the proxy binds, and both are reaped with nothing orphaned.
//!
//! It needs `hsm-sim-service` and `vhsm-ssd` built. Both are workspace binaries,
//! so `cargo test --workspace` (what `scripts/feature-matrix.sh` runs) builds
//! them and this test executes. Under a bare `cargo test -p hsm-supervisor` they
//! are absent and the test skips with a note.
//!
//! In supernova this test located those binaries by walking to a *sibling*
//! `sumo-machine-manager` checkout's `target/` — which supernova's own
//! `cargo test` never populates, so it skipped essentially always. Probing from
//! `current_exe()` instead is profile-correct and `CARGO_TARGET_DIR`-agnostic.

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use hsm::KeyRole;
use hsm_supervisor::{standup, terminate_child, HsmSupervisorConfig};

/// Locate a workspace binary next to this test executable.
///
/// A test binary lives at `<target>/<profile>/deps/<name>-<hash>`, so its
/// grandparent is `<target>/<profile>` — where cargo puts the workspace's bins,
/// in the SAME profile as this test and wherever `CARGO_TARGET_DIR` points.
fn locate_workspace_bin(name: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let profile_dir = exe.parent()?.parent()?;
    let cand = profile_dir.join(name);
    cand.is_file().then_some(cand)
}

fn write_test_policy_dir(dir: &Path) {
    std::fs::create_dir_all(dir.join("roots")).unwrap();
    std::fs::write(dir.join("policy.yaml"), "version: 1\nstatements: []\n").unwrap();
}

fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

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

#[test]
fn standup_drives_link_b_and_shuts_down_clean() {
    use std::os::unix::net::UnixStream;

    let (Some(backend_bin), Some(daemon_bin)) = (
        locate_workspace_bin("hsm-sim-service"),
        locate_workspace_bin("vhsm-ssd"),
    ) else {
        eprintln!(
            "SKIP: hsm-sim-service / vhsm-ssd not built in this profile's target dir — \
             run `cargo test --workspace` (or `cargo build --workspace`) to include this test"
        );
        return;
    };

    let keystore = tempfile::tempdir().expect("keystore tempdir");
    let policy = tempfile::tempdir().expect("policy tempdir");
    write_test_policy_dir(policy.path());

    let port = free_port();
    let cfg = HsmSupervisorConfig {
        keystore: keystore.path().to_path_buf(),
        bind: "127.0.0.1".parse().unwrap(),
        port,
        daemon: Some(daemon_bin),
        backend_cmd: Some(backend_bin),
        backend_socket: None,
        ip_map: Vec::new(),
        audit_log: None,
        policy_dir: policy.path().to_path_buf(),
        cross_node_listen: None,
    };

    // The REAL production standup fn.
    let (provider, mut daemons) = standup(&cfg).expect("standup HSM daemons");

    // (1) A provisioning op crosses link-B: a fresh keystore is not provisioned.
    assert!(
        !provider.lock().unwrap().is_provisioned().unwrap(),
        "fresh keystore must report not-provisioned over link-B"
    );

    // (2) A keyed crypto op crosses link-B: the backend self-bootstrapped its
    //     device keys (incl. iam-signing) at startup, so a sign succeeds. The
    //     crypto half is the link-B client (`HsmCryptoProvider`).
    let sig = hsm::HsmCryptoProvider::sign(
        &*daemons.crypto_client,
        KeyRole::IamSigning.handle(),
        b"n4-standup-probe",
    )
    .expect("sign over link-B against the self-bootstrapped iam-signing key");
    assert!(!sig.is_empty(), "link-B sign must return a signature");

    // (3) The vhsm-ssd proxy came up: poll its TCP listener (proves it got past
    //     connect-to-backend + bind).
    let addr = format!("127.0.0.1:{port}");
    assert!(
        poll_until(Duration::from_secs(20), || TcpStream::connect(&addr)
            .is_ok()),
        "vhsm-ssd proxy never bound {addr}"
    );

    // Backend default socket is <keystore>/hsm-backend.sock.
    let backend_socket = keystore.path().join("hsm-backend.sock");
    assert!(
        UnixStream::connect(&backend_socket).is_ok(),
        "backend should be serving its link-B socket"
    );

    // (4) Shutdown via the SAME path the machine manager uses.
    daemons.shutdown();
    assert!(
        daemons
            .vhsm_child
            .lock()
            .unwrap()
            .try_wait()
            .unwrap()
            .is_some(),
        "vhsm-ssd must be reaped after shutdown"
    );
    assert!(
        daemons.backend_child.try_wait().unwrap().is_some(),
        "backend must be reaped after shutdown"
    );

    // No orphan: the proxy port no longer accepts, and the backend socket is gone.
    assert!(
        poll_until(Duration::from_secs(3), || TcpStream::connect(&addr)
            .is_err()),
        "vhsm-ssd port still accepting after shutdown — orphan"
    );
    assert!(
        poll_until(Duration::from_secs(3), || UnixStream::connect(
            &backend_socket
        )
        .is_err()),
        "backend socket still accepting after shutdown — orphan"
    );
}

/// `terminate_child` on its own, against a process that ignores nothing: a plain
/// sleeper. Pins the reap — the guarantee that makes the standup's failure path
/// safe — without needing the daemons built, so it runs under
/// `cargo test -p hsm-supervisor` too.
#[test]
fn terminate_child_reaps_a_live_child() {
    let mut child = std::process::Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("spawn sleep");
    assert!(
        child.try_wait().unwrap().is_none(),
        "sleeper should still be running"
    );
    terminate_child(&mut child, "sleep-probe");
    assert!(
        child.try_wait().unwrap().is_some(),
        "terminate_child must reap the child, not just signal it"
    );
}
