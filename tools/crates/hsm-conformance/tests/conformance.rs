//! Conformance battery integration tests.
//!
//! Two ends of the spectrum:
//!   * `sim_hsm_conforms` — the real `hsm-sim-service` (RustCrypto SimHsm over
//!     link-B) is a CONFORMING backend: every non-informational check passes.
//!   * `stub_example_does_not_conform` — the C reference skeleton
//!     (`hse_service_skeleton.c`, STUBBED crypto) is framing-correct but cannot
//!     pass the real-crypto KAT: it speaks the wire yet is not a real HSM.

use std::path::PathBuf;
use std::process::Command;

use hsm_conformance::{run_conformance, spawn_and_connect, Outcome};

/// Locate the `hsm-sim-service` binary built into `target/<profile>/`. It is a
/// bin of the sibling `hsm` crate, so `env!("CARGO_BIN_EXE_…")` cannot name it;
/// walk this test exe's ancestors and return the first dir that holds it. Mirror
/// of `vhsm-ssd/tests/backend_link_b.rs`. The bin must be built FIRST:
///     cargo build -p hsm --features crypto --bin hsm-sim-service
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
fn sim_hsm_conforms() {
    let backend = match locate_hsm_sim_service() {
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
    let socket = keystore.join("backend.sock");

    // The sim REQUIRES a keystore directory (it stores keys there).
    let (client, mut child) =
        spawn_and_connect(&backend, Some(&keystore), &socket).expect("spawn + connect sim");

    let report = run_conformance(&client);
    eprintln!("{report}");

    // The sim is a conforming implementation: the verdict is CONFORMS …
    assert!(report.all_passed(), "SimHsm must conform:\n{report}");
    // … the load-bearing real-crypto KAT passes …
    assert!(
        matches!(report.outcome("C2"), Some(Outcome::Pass)),
        "C2 (real-crypto KAT) must pass for the sim:\n{report}"
    );
    // … and there are no non-informational failures at all.
    let hard_fails = report
        .checks
        .iter()
        .filter(|c| !c.informational && matches!(c.outcome, Outcome::Fail(_)))
        .count();
    assert_eq!(hard_fails, 0, "no conformance check may fail for the sim:\n{report}");

    drop(client);
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn stub_example_does_not_conform() {
    // Locate the in-repo C skeleton by walking up from this crate's manifest dir
    // to the workspace root — the first ancestor that actually holds it. Robust to
    // where this tool crate lives (crates/, tools/crates/, …); a wrong path must
    // FAIL here, not silently skip the whole stub proof.
    let rel = "crates/hsm-link-b/reference/hse_service_skeleton.c";
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest
        .ancestors()
        .find(|d| d.join(rel).is_file())
        .unwrap_or_else(|| panic!("could not find {rel} above {}", manifest.display()))
        .to_path_buf();
    let include = root.join("crates/hsm-link-b/include");
    let source = root.join(rel);

    let tmp = tempfile::tempdir().expect("tempdir");
    let stub_bin = tmp.path().join("hse_service");

    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let compile = Command::new(&cc)
        .arg("-I")
        .arg(&include)
        .arg(&source)
        .arg("-o")
        .arg(&stub_bin)
        .status();
    match compile {
        Ok(s) if s.success() => {}
        // A real compile error of the in-repo skeleton is a bug — fail, don't skip.
        Ok(s) => panic!("the in-repo C skeleton must compile, but `{cc}` failed ({s})"),
        // A genuinely-absent C compiler is the one legitimate skip.
        Err(e) => {
            eprintln!("SKIP: no C compiler `{cc}` to build the reference skeleton: {e}");
            return;
        }
    }

    // The skeleton keeps keys in its (hypothetical) slot map and takes only
    // --listen — no keystore.
    let socket = tmp.path().join("stub.sock");
    let (client, mut child) =
        spawn_and_connect(&stub_bin, None, &socket).expect("spawn + connect stub");

    let report = run_conformance(&client);
    eprintln!("{report}");

    // The stub speaks the wire — framing / dispatch checks pass:
    assert!(
        matches!(report.outcome("C1"), Some(Outcome::Pass)),
        "stub framing C1 (keygen returns bytes) should pass:\n{report}"
    );
    assert!(
        matches!(report.outcome("C7"), Some(Outcome::Pass)),
        "stub C7 (virtual anchor rejected) should pass:\n{report}"
    );
    assert!(
        matches!(report.outcome("C8"), Some(Outcome::Pass)),
        "stub C8 (unknown handle rejected) should pass:\n{report}"
    );

    // … but its STUBBED crypto cannot pass the real-crypto KAT — C2 fails because
    // the fake signature/pubkey are not real ECDSA-P256 material …
    assert!(
        matches!(report.outcome("C2"), Some(Outcome::Fail(_))),
        "stub C2 (real-crypto KAT) MUST fail — this is the 'just an example' proof:\n{report}"
    );
    // … and its verify hard-accepts everything, so the tamper-reject check fails
    // too (the spec predicted C4 would fail; in reality this stub's always-accept
    // verify passes C4 and fails C5 — see the report).
    assert!(
        matches!(report.outcome("C5"), Some(Outcome::Fail(_))),
        "stub C5 (tamper must be rejected) MUST fail — its verify always accepts:\n{report}"
    );

    // Overall verdict: DOES NOT CONFORM.
    assert!(
        !report.all_passed(),
        "the stubbed-crypto example must NOT conform:\n{report}"
    );

    drop(client);
    let _ = child.kill();
    let _ = child.wait();
}
