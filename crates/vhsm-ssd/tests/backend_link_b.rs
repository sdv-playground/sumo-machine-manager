//! Stage-3 link-B backend wiring — integration test.
//!
//! Proves vhsm-ssd's new `backend::spawn_and_connect` actually spawns the real
//! `hsm-sim-service` backend and drives genuine crypto over link-B: generate →
//! sign → verify, plus a tamper negative control. This exercises the rewired
//! A→B proxy path end to end (vhsm-ssd's crypto provider is now a `LinkBClient`
//! to an out-of-process backend), through a spawned process + Unix socket —
//! complementing backend.rs's in-crate unit test of the failure path.
//!
//! `hsm-sim-service` is a bin of the SIBLING `hsm` crate, so it is NOT exposed
//! via `CARGO_BIN_EXE_*`. We locate the already-built binary by walking this
//! test executable's ancestors to `target/<profile>/hsm-sim-service`. The bin
//! must therefore be built FIRST:
//!     cargo build -p hsm --features crypto --bin hsm-sim-service
//! (the documented VERIFY order; CI must mirror it — there is no Cargo way to
//! express a cross-crate bin build-dep for a test). If the bin isn't found, the
//! test SKIPS with a loud message rather than failing spuriously.

use std::path::PathBuf;

use hsm::vhsm_proto;
use hsm::{HsmCryptoProvider, KeyHandle};

use vhsm_ssd::backend;

/// Locate the `hsm-sim-service` binary built into `target/<profile>/`. It's a
/// bin of the sibling `hsm` crate, so `env!("CARGO_BIN_EXE_…")` can't name it;
/// walk our own test-exe ancestors and return the first dir that holds it.
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

#[test]
fn spawn_and_connect_drives_real_crypto_over_link_b() {
    let backend_cmd = match locate_hsm_sim_service() {
        Some(p) => p,
        None => {
            eprintln!(
                "SKIP: hsm-sim-service not built — run \
                 `cargo build -p hsm --features crypto --bin hsm-sim-service` first"
            );
            return;
        }
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let keystore = dir.path().to_path_buf();
    let socket = keystore.join("hsm-backend.sock");

    // Spawn the real backend and connect — the exact path main() now takes.
    let (client, mut child) =
        backend::spawn_and_connect(&backend_cmd, &keystore, &socket).expect("spawn + connect");

    let handle = KeyHandle(vhsm_proto::HANDLE_JWT_SIGNING);
    let msg = b"link-b backend proxy proof";

    // generate_key → the out-of-process SimHsm writes a real P-256 key and
    // returns its SubjectPublicKeyInfo DER over link-B. (jwt-signing is a
    // well-known slot, so a bare tempdir keystore needs no provisioning.)
    let spki = client
        .generate_key(handle, vhsm_proto::ALG_ECC_P256)
        .expect("generate_key over link-b");
    assert!(!spki.is_empty(), "EC keygen must return SPKI DER");
    assert_eq!(spki[0], 0x30, "SPKI is an ASN.1 SEQUENCE");

    // sign, then verify the genuine signature over link-B — round-trips back
    // into the backend's SimHsm.
    let sig = client.sign(handle, msg).expect("sign over link-b");
    assert!(
        client.verify(handle, msg, &sig).expect("verify over link-b"),
        "a genuine signature must verify"
    );

    // Negative control: a tampered message must NOT verify — proves the proxy
    // isn't rubber-stamping inputs.
    assert!(
        !client
            .verify(handle, b"tampered", &sig)
            .expect("verify over link-b"),
        "a tampered message must NOT verify"
    );

    // vhsm-ssd has no signal handling yet, so the test owns backend teardown.
    // Drop the client first (closes the link-B stream), then reap the backend.
    drop(client);
    let _ = child.kill();
    let _ = child.wait();
}
