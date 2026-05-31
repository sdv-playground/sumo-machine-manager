//! End-to-end test: provision a SimHsm, sign a bank with the IVD
//! key, then invoke `sumo-verify` as a subprocess and check exit
//! codes. Exercises the actual CLI binary the way an external
//! secure-boot stage would.

use std::path::PathBuf;
use std::process::Command;

use hsm::ivd;
use hsm::payload;
use hsm::sim::SimHsm;

/// Per-test scratch root under `temp_dir()`. Removed on drop.
struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let pid = std::process::id();
        let root = std::env::temp_dir().join(format!("sumo-verify-e2e-{}-{}", pid, name));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        Self { root }
    }
    fn path(&self, sub: &str) -> PathBuf {
        self.root.join(sub)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Provision a SimHsm whose only mandatory slot is `ivd-signing`
/// (device-generated). Returns the keystore path the CLI will point
/// at via `--keystore`.
fn provisioned_keystore(scratch: &Scratch) -> PathBuf {
    let keystore = scratch.path("keystore");
    std::fs::create_dir_all(&keystore).unwrap();

    let hsm = SimHsm::new(PathBuf::from("/dev/null"), keystore.clone(), 0);

    let ks = payload::HsmKeystore {
        schema_version: payload::SCHEMA_VERSION,
        security_version: 1,
        identities: vec![],
        slots: vec![payload::KeySlot {
            key_id: ivd::IVD_KEY_ID.to_string(),
            key_kind: payload::KEY_TYPE_EC_P256,
            anchor_public_key: None,
            allowed_guests: None,
            allowed_ops: Some(vec![
                payload::OP_SIGN,
                payload::OP_VERIFY,
                payload::OP_GET_PUBKEY,
            ]),
        }],
    };
    hsm.write_keystore(&ks).unwrap();
    std::fs::write(keystore.join("provision_state"), b"1\n").unwrap();

    keystore
}

/// Path to the freshly-built `sumo-verify` binary. Cargo sets
/// `CARGO_BIN_EXE_<name>` for integration tests.
fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sumo-verify"))
}

#[test]
fn verifies_a_signed_bank() {
    let s = Scratch::new("happy");
    let keystore = provisioned_keystore(&s);

    let bank = s.path("vm2/bank_a");
    std::fs::create_dir_all(&bank).unwrap();
    std::fs::write(bank.join("kernel"), b"kernel bytes").unwrap();
    std::fs::write(bank.join("rootfs.img"), vec![0xAB; 4096]).unwrap();

    // Sign with the HSM the CLI will use. `gen=7` here is the
    // per-install generation counter the NV layer would assign; the
    // CLI's `--expect-install-gen` pins it on read.
    let hsm = SimHsm::new(PathBuf::from("/dev/null"), keystore.clone(), 0);
    ivd::sign_bank(&hsm, &bank, 7).unwrap();

    let out = Command::new(binary())
        .arg("--bank")
        .arg(&bank)
        .arg("--keystore")
        .arg(&keystore)
        .arg("--expect-install-gen")
        .arg("7")
        .output()
        .expect("run sumo-verify");

    assert!(
        out.status.success(),
        "expected exit 0, got {} — stderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("ok gen=7"), "got: {stdout}");
    assert!(stdout.contains("files=2"));
}

#[test]
fn rejects_tampered_file() {
    let s = Scratch::new("tampered");
    let keystore = provisioned_keystore(&s);

    let bank = s.path("vm1/bank_b");
    std::fs::create_dir_all(&bank).unwrap();
    // 12-byte original; tamper to a different 12-byte content so
    // we exercise hash mismatch (not size mismatch).
    std::fs::write(bank.join("kernel"), b"original\0\0\0\0").unwrap();
    std::fs::write(bank.join("rootfs.img"), vec![0u8; 2048]).unwrap();

    let hsm = SimHsm::new(PathBuf::from("/dev/null"), keystore.clone(), 0);
    ivd::sign_bank(&hsm, &bank, 11).unwrap();

    // Tamper post-sign.
    std::fs::write(bank.join("kernel"), b"tampered\0\0\0\0").unwrap();

    let out = Command::new(binary())
        .arg("--bank")
        .arg(&bank)
        .arg("--keystore")
        .arg(&keystore)
        .output()
        .expect("run sumo-verify");

    assert_eq!(out.status.code(), Some(1), "expected exit 1 (verify fail)");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("hash mismatch"), "got: {stderr}");
}

#[test]
fn rejects_unexpected_extra_file() {
    let s = Scratch::new("extra");
    let keystore = provisioned_keystore(&s);

    let bank = s.path("vm2/bank_a");
    std::fs::create_dir_all(&bank).unwrap();
    std::fs::write(bank.join("kernel"), b"k").unwrap();

    let hsm = SimHsm::new(PathBuf::from("/dev/null"), keystore.clone(), 0);
    ivd::sign_bank(&hsm, &bank, 1).unwrap();

    // Drop an extra file the manifest never authorised.
    std::fs::write(bank.join("evil-payload"), b"sneaky").unwrap();

    let out = Command::new(binary())
        .arg("--bank")
        .arg(&bank)
        .arg("--keystore")
        .arg(&keystore)
        .output()
        .expect("run sumo-verify");

    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("evil-payload"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn rejects_install_gen_mismatch() {
    let s = Scratch::new("gen-mismatch");
    let keystore = provisioned_keystore(&s);

    let bank = s.path("vm2/bank_a");
    std::fs::create_dir_all(&bank).unwrap();
    std::fs::write(bank.join("kernel"), b"k").unwrap();

    // Sign with gen=5; verifier pins gen=6 → must reject (the
    // between-slot swap detection case that motivated the v2
    // manifest format).
    let hsm = SimHsm::new(PathBuf::from("/dev/null"), keystore.clone(), 0);
    ivd::sign_bank(&hsm, &bank, 5).unwrap();

    let out = Command::new(binary())
        .arg("--bank")
        .arg(&bank)
        .arg("--keystore")
        .arg(&keystore)
        .arg("--expect-install-gen")
        .arg("6")
        .output()
        .expect("run sumo-verify");

    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("gen mismatch"),
        "stderr should mention gen mismatch: {stderr}"
    );
}

#[test]
fn rejects_missing_bank_dir() {
    let s = Scratch::new("missing-bank");
    let keystore = provisioned_keystore(&s);

    let out = Command::new(binary())
        .arg("--bank")
        .arg(s.path("does/not/exist"))
        .arg("--keystore")
        .arg(&keystore)
        .output()
        .expect("run sumo-verify");

    // EXIT_USAGE = 2 (setup error, not a verify-fail).
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn rejects_missing_keystore() {
    let s = Scratch::new("missing-keystore");

    let bank = s.path("vm/bank_a");
    std::fs::create_dir_all(&bank).unwrap();

    let out = Command::new(binary())
        .arg("--bank")
        .arg(&bank)
        .arg("--keystore")
        .arg(s.path("nonexistent-keystore"))
        .output()
        .expect("run sumo-verify");

    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn missing_args_prints_usage() {
    let out = Command::new(binary())
        .output()
        .expect("run sumo-verify with no args");

    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Usage:"));
    assert!(stderr.contains("--bank is required"));
}

#[test]
fn quiet_suppresses_stdout_on_success() {
    let s = Scratch::new("quiet");
    let keystore = provisioned_keystore(&s);

    let bank = s.path("vm2/bank_a");
    std::fs::create_dir_all(&bank).unwrap();
    std::fs::write(bank.join("kernel"), b"k").unwrap();

    let hsm = SimHsm::new(PathBuf::from("/dev/null"), keystore.clone(), 0);
    ivd::sign_bank(&hsm, &bank, 3).unwrap();

    let out = Command::new(binary())
        .arg("--bank")
        .arg(&bank)
        .arg("--keystore")
        .arg(&keystore)
        .arg("--quiet")
        .output()
        .expect("run sumo-verify");

    assert!(out.status.success());
    assert!(out.stdout.is_empty(), "stdout was: {:?}", out.stdout);
}
