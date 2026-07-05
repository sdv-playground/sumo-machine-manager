//! `hsm-sim-service` — serve a [`SimHsm`] as an out-of-process **link-B** crypto
//! backend.
//!
//! **NON-PRODUCTION.** A *software reference* backend for dev / test / CI — it is
//! **just another link-B implementation**, not privileged. A real deployment runs a
//! vendor C HSE service implementing the same `hsm-link-b` contract; `vhsm-ssd`
//! selects between them purely by `--backend-cmd` and can't tell them apart. Verify
//! any backend (this one included) with the `hsm-conformance` suite.
//!
//! Stage 2 of making the HSM backend a uniform out-of-process link-B service
//! (Stage 1 = `hsm::link_b`: the frame codec, `serve_crypto`, and `LinkBClient`;
//! see `crates/hsm-link-b` for the frozen wire contract). This binary is the
//! concrete *backend* side of that wire: it owns a `SimHsm` (file-backed
//! keystore + RustCrypto) and answers link-B crypto frames against it, so the
//! sim becomes the same kind of out-of-process backend a vendor HSM would be. A
//! link-B client (next stage: vhsm-ssd's) connects over the Unix socket and
//! drives crypto through `HsmCryptoProvider` without sharing a process.
//!
//! Crypto **and** provisioning are served **directly** via [`hsm::link_b::serve`]
//! (the full backend surface): the bin owns a [`SimHsm`] over `--keystore` and
//! answers link-B frames against it. `SimHsm` carries no service lifecycle of
//! its own — it is a pure keystore + crypto backend.
//!
//! Usage:
//!   hsm-sim-service --keystore <path> --listen <unix-socket-path>

use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process;
use std::sync::{Arc, Mutex};
use std::thread;

use hsm::link_b;
use hsm_sim_backend::SimHsm;

fn print_usage() {
    eprintln!("usage: hsm-sim-service --keystore <path> --listen <unix-socket-path>");
}

/// Minimal hand parse of `--keystore` / `--listen` (no clap — `hsm` doesn't
/// depend on it). Returns `(keystore_path, listen_path)` or a human-readable
/// error for the caller to print + exit non-zero on.
fn parse_args(args: &[String]) -> Result<(PathBuf, PathBuf), String> {
    let mut keystore: Option<PathBuf> = None;
    let mut listen: Option<PathBuf> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--keystore" if i + 1 < args.len() => {
                keystore = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--listen" if i + 1 < args.len() => {
                listen = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--help" | "-h" => {
                print_usage();
                process::exit(0);
            }
            other => return Err(format!("unknown or incomplete argument: {other}")),
        }
    }

    let keystore = keystore.ok_or_else(|| "error: --keystore is required".to_string())?;
    let listen = listen.ok_or_else(|| "error: --listen is required".to_string())?;
    Ok((keystore, listen))
}

/// Accept connections on `listener` forever, serving each on its own thread
/// against the shared `SimHsm` over the full link-B protocol (crypto +
/// provisioning). Factored out of `main` so a test can bind a temp socket and
/// drive the real accept loop in-process.
///
/// One thread per connection: `hsm::link_b::serve` blocks reading frames until
/// its peer drops, so a slow/long-lived client must not stall others. The
/// `Arc<Mutex<…>>` shares the single `SimHsm` (and its one keystore on disk):
/// `serve` takes the lock per op (the provisioning half needs `&mut self`), so
/// an idle client never holds it.
fn serve(listener: UnixListener, hsm: Arc<Mutex<SimHsm>>) {
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                tracing::debug!("hsm-sim-service: link-b connection accepted");
                let hsm = Arc::clone(&hsm);
                thread::spawn(move || {
                    link_b::serve(stream, &*hsm);
                    tracing::debug!("hsm-sim-service: link-b connection closed");
                });
            }
            Err(e) => tracing::warn!(error = %e, "hsm-sim-service: accept failed"),
        }
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
    let (keystore_path, listen_path) = parse_args(&args).unwrap_or_else(|e| {
        eprintln!("{e}");
        print_usage();
        process::exit(1);
    });

    // Remove any stale socket from a prior run: bind() fails with EADDRINUSE on
    // a path that still has the dead file but no listener behind it.
    if listen_path.exists() {
        if let Err(e) = std::fs::remove_file(&listen_path) {
            eprintln!(
                "failed to remove stale socket {}: {e}",
                listen_path.display()
            );
            process::exit(1);
        }
    }

    let listener = UnixListener::bind(&listen_path).unwrap_or_else(|e| {
        eprintln!("failed to bind {}: {e}", listen_path.display());
        process::exit(1);
    });

    // SimHsm is a pure keystore + crypto backend over `--keystore`; we serve
    // crypto + provisioning directly via link_b::serve.
    let hsm = SimHsm::new(keystore_path.clone());

    // Self-bootstrap the device-side key pairs before serving (idempotent): a
    // fresh keystore must have its device-generated slots before the first key
    // op, the same way the host startup paths call ensure_device_keys.
    if let Err(e) = hsm.ensure_device_keys() {
        eprintln!(
            "failed to bootstrap device keys in {}: {e}",
            keystore_path.display()
        );
        process::exit(1);
    }

    let hsm = Arc::new(Mutex::new(hsm));

    tracing::info!(
        keystore = %keystore_path.display(),
        listen = %listen_path.display(),
        "hsm-sim-service: serving SimHsm over link-B"
    );

    serve(listener, hsm);
}

// ── e2e: REAL SimHsm crypto over link-B ───────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use hsm::link_b::LinkBClient;
    use hsm::vhsm_proto;
    use hsm::{HsmCryptoProvider, KeyHandle};

    /// Bind a temp socket, run the real `serve` loop against a `SimHsm` over a
    /// fresh temp keystore, then drive a `LinkBClient` through a full
    /// generate → sign → get-pubkey → verify cycle. Proves Stage-1's wire moves
    /// genuine SimHsm crypto (Stage 1's own test used a mock backend).
    ///
    /// Keystore/SimHsm construction mirrors `crypto.rs`'s `new_hsm()` helper:
    /// `SimHsm::new(<tempdir>)`. No provisioning is
    /// needed — `jwt-signing` is a well-known slot, so `generate_key` writes
    /// `keys/jwt-signing.{priv,pub}` and the later `get_slot_info`/`sign`/
    /// `get_public_key_der` resolve those on-disk files via the disk fallback.
    #[test]
    fn sim_hsm_real_crypto_round_trips_over_link_b() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keystore = dir.path().to_path_buf();
        let sock = dir.path().join("hsm-sim.sock");

        let hsm = Arc::new(Mutex::new(SimHsm::new(keystore)));

        // Bind BEFORE spawning/connecting so the connect below can't race the
        // listener. The detached `serve` thread loops forever; the test process
        // exiting reaps it (Rust's test harness doesn't join user threads).
        let listener = UnixListener::bind(&sock).expect("bind unix socket");
        let hsm_for_server = Arc::clone(&hsm);
        thread::spawn(move || serve(listener, hsm_for_server));

        let client = LinkBClient::connect(&sock).expect("link-b connect");
        let handle = KeyHandle(vhsm_proto::HANDLE_JWT_SIGNING);
        let msg = b"msg";

        // generate_key over the wire → SimHsm makes a real P-256 key on disk and
        // returns its SubjectPublicKeyInfo DER.
        let spki = client
            .generate_key(handle, vhsm_proto::ALG_ECC_P256)
            .expect("generate_key over link-b");
        assert!(!spki.is_empty(), "EC keygen must return SPKI DER");
        assert_eq!(spki[0], 0x30, "SPKI is an ASN.1 SEQUENCE");

        // sign + get_public_key_der over the wire.
        let sig = client.sign(handle, msg).expect("sign over link-b");
        let pub_der = client
            .get_public_key_der(handle)
            .expect("get_public_key_der over link-b");
        assert_eq!(pub_der, spki, "get_public_key_der must match keygen SPKI");

        // (a) Verify over link-B — round-trips back into the SimHsm backend.
        assert!(
            client
                .verify(handle, msg, &sig)
                .expect("verify over link-b"),
            "link-b verify of a genuine signature must succeed"
        );

        // (b) Verify INDEPENDENTLY against the returned public key with p256
        // directly: proves the wire bytes are a real ECDSA-P256 signature over
        // `msg` under that exact SPKI — not merely something the backend echoes.
        // The SPKI's trailing 65 bytes are the SEC1 uncompressed point (same
        // slice crypto.rs's CSR test uses).
        use p256::ecdsa::signature::Verifier;
        let point = &pub_der[pub_der.len() - 65..];
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(point).expect("SEC1 pubkey");
        let der_sig =
            ecdsa::der::Signature::<p256::NistP256>::from_bytes(&sig).expect("DER signature");
        vk.verify(msg, &der_sig)
            .expect("p256 must verify the link-b signature against the returned pubkey");

        // Negative control: a tampered message must NOT verify (proves we aren't
        // just rubber-stamping every input).
        assert!(
            !client
                .verify(handle, b"tampered", &sig)
                .expect("verify over link-b"),
            "link-b verify of a tampered message must fail"
        );

        drop(client);
    }
}
