/// Generate HSM key material as signed + encrypted SUIT envelopes.
///
/// Trust model:
///   - Factory envelope: signed with factory signing key, encrypted to device public key.
///   - Re-provision envelope: signed with Key Authority, encrypted to device public key.
///   - Key Authority (slot 0): generated fresh, delivered in factory envelope.
///     Device uses it to verify subsequent HSM key envelopes.
///
/// Output (default mode):
///   <output-dir>/hsm-keys-v1.suit       — factory envelope (signed: factory key, encrypted: device key)
///   <output-dir>/hsm-keys-v2.suit       — re-provision envelope (signed: key authority, encrypted: device key)
///   <keys-dir>/key-authority.pub        — Key Authority public key (COSE_Key CBOR)
///   <keys-dir>/key-authority.key        — Key Authority full key (for re-provisioning)
///
/// Output (--cbor-only mode):
///   stdout                              — raw CBOR keystore (pipe to sumo-tool build --manifest)
///   <keys-dir>/key-authority.pub        — Key Authority public key
///   <keys-dir>/key-authority.key        — Key Authority full key
///
/// Run with:
///   cargo run --example build_hsm_keys -- --signing-key <path> --device-key <path> --output-dir <path>
///
/// Or pipe to sumo-tool:
///   cargo run --example build_hsm_keys -- --cbor-only --signing-key <path> --device-key <path> \
///     | sumo-tool build --manifest hsm-keys.yaml
use std::fs;
use std::path::{Path, PathBuf};

use coset::iana;
use coset::CborSerializable;
use sumo_crypto::{CryptoBackend, RustCryptoBackend};
use sumo_offboard::cose_key::CoseKey;
use sumo_offboard::encryptor;
use sumo_offboard::keygen;
use sumo_offboard::recipient::Recipient;
use sumo_offboard::ImageManifestBuilder;

use hsm::payload::*;

/// Number of "application" key slots (beyond the 8 well-known + 3 test slots).
const NUM_APP_SLOTS: usize = 89;

/// Total well-known slots (in `KeyRole::mandatory_roles()` order plus
/// `jwt-signing` which the dev/test rig needs alongside).
const NUM_WELL_KNOWN_SLOTS: usize = 8;
const NUM_TEST_SLOTS: usize = 3;

/// Load an EC-P256 keypair from disk if it exists, else generate a
/// fresh one and persist it under the same path. Used for trust-anchor
/// keys (key-authority / platform-authority / application-authority)
/// and for device-local keys (ivd-signing) so consecutive build runs
/// reuse the same key material — otherwise re-provisioning would
/// invalidate every previously-signed envelope and every previously-
/// signed bank.
///
/// On-disk format is a plain 97-byte blob: `priv[32] || pub[65]` (SEC1
/// uncompressed, leading `0x04`). Internal to this script — clients
/// receive material via the SUIT envelope or `*.cosekey` exports.
///
/// Return type matches [`generate_ec_p256_raw`] so call sites can be
/// dropped in unchanged.
fn load_or_generate_ec_keypair(path: &Path, label: &str) -> (Vec<u8>, Vec<u8>) {
    if path.exists() {
        let bytes = fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert_eq!(
            bytes.len(),
            97,
            "expected 97 bytes (32 priv + 65 pub) in {}, got {}",
            path.display(),
            bytes.len(),
        );
        eprintln!("[hsm-keys] reused {label}: {}", path.display());
        (bytes[..32].to_vec(), bytes[32..].to_vec())
    } else {
        let (priv_vec, pub_vec) = generate_ec_p256_raw();
        let mut on_disk = Vec::with_capacity(97);
        on_disk.extend_from_slice(&priv_vec);
        on_disk.extend_from_slice(&pub_vec);
        fs::write(path, &on_disk).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        eprintln!("[hsm-keys] generated {label}: {}", path.display());
        (priv_vec, pub_vec)
    }
}

/// Guest identities that can register with the HSM.
const GUESTS: &[&str] = &["bali-vm-1", "bali-vm-2", "bali-vm-3"];

fn usage() {
    eprintln!("Usage: build_hsm_keys [--signing-key <path>] [--device-pub <path>|--device-csr <path>] [--output-dir <path>] [--cbor-only]");
    eprintln!();
    eprintln!("  --signing-key <path>   Signing key (COSE_Key CBOR) — used for sw-authority slot.");
    eprintln!("                         Default: factory signing key (P-256 generator, scalar=1).");
    eprintln!("  --device-pub <path>    Device public key (COSE_Key CBOR) — encryption target.");
    eprintln!("  --device-csr <path>    Device CSR (PKCS#10 DER) — extracts public key.");
    eprintln!("                         Either --device-pub or --device-csr is required.");
    eprintln!(
        "  --output-dir <path>    Directory for .suit output files (required unless --cbor-only)"
    );
    eprintln!("  --cbor-only            Write raw CBOR keystore to stdout, skip SUIT wrapping.");
    eprintln!("                         Key Authority files are still written to --output-dir or example/keys/.");
    eprintln!("                         Pipe to: sumo-tool build --manifest hsm-keys.yaml");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut signing_key_path: Option<String> = None;
    let mut device_pub_path: Option<String> = None;
    let mut device_csr_path: Option<String> = None;
    let mut output_dir_path: Option<String> = None;
    let mut cbor_only = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--signing-key" if i + 1 < args.len() => {
                signing_key_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--device-pub" if i + 1 < args.len() => {
                device_pub_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--device-csr" if i + 1 < args.len() => {
                device_csr_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--output-dir" if i + 1 < args.len() => {
                output_dir_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--cbor-only" => {
                cbor_only = true;
                i += 1;
            }
            other => {
                usage();
                eprintln!("\nUnknown argument: {other}");
                std::process::exit(1);
            }
        }
    }

    let signing_key_path = signing_key_path;
    if device_pub_path.is_none() && device_csr_path.is_none() {
        usage();
        eprintln!("\nError: one of --device-pub or --device-csr is required");
        std::process::exit(1);
    }
    if device_pub_path.is_some() && device_csr_path.is_some() {
        usage();
        eprintln!("\nError: --device-pub and --device-csr are mutually exclusive");
        std::process::exit(1);
    }

    let output_dir = if let Some(ref p) = output_dir_path {
        PathBuf::from(p)
    } else if !cbor_only {
        usage();
        eprintln!("\nError: --output-dir is required (or use --cbor-only)");
        std::process::exit(1);
    } else {
        PathBuf::new() // not used in cbor-only mode
    };

    let keys_dir = if let Some(ref p) = output_dir_path {
        PathBuf::from(p)
    } else {
        Path::new("example").join("keys")
    };
    fs::create_dir_all(&keys_dir).unwrap();
    if !cbor_only {
        fs::create_dir_all(&output_dir).unwrap();
    }

    let crypto = RustCryptoBackend::new();

    // Factory signing key — signs the first (factory) envelope.
    let envelope_signing_key = {
        let key = coset::CoseKeyBuilder::new_ec2_priv_key(
            iana::EllipticCurve::P_256,
            FACTORY_SIGNING_PUBLIC[1..33].to_vec(),
            FACTORY_SIGNING_PUBLIC[33..65].to_vec(),
            FACTORY_SIGNING_SCALAR.to_vec(),
        )
        .algorithm(iana::Algorithm::ES256)
        .build();
        CoseKey::from_cose_key_bytes(&key.to_vec().unwrap()).unwrap()
    };

    // Software authority key — its public half goes into the HSM
    // keystore for firmware signature verification. MUST be supplied
    // explicitly; the previous "default to factory signing key"
    // fallback collapsed sw-authority into the factory bootstrap
    // anchor, defeating the trust separation. Generate one with
    // `sumo-tool keygen --output sw-authority.key`.
    let signing_key = match signing_key_path.as_ref() {
        Some(path) => {
            let bytes =
                fs::read(path).unwrap_or_else(|e| panic!("failed to read signing key {path}: {e}"));
            CoseKey::from_cose_key_bytes(&bytes).unwrap()
        }
        None => {
            usage();
            eprintln!();
            eprintln!("Error: --signing-key is required.");
            eprintln!();
            eprintln!("sw-authority MUST be a distinct key from the factory bootstrap");
            eprintln!("(the well-known scalar=1 anchor) and from key-authority. Pass:");
            eprintln!("  --signing-key <path/to/sw-authority.cosekey>");
            eprintln!("Create one with `sumo-tool keygen` if you don't have one yet.");
            std::process::exit(1);
        }
    };

    // Load device public key — from CSR or public key file.
    // Private key never leaves the device.
    let dk_pub = if let Some(ref csr_path) = device_csr_path {
        let csr_der = fs::read(csr_path)
            .unwrap_or_else(|e| panic!("failed to read device CSR {csr_path}: {e}"));
        let pub_key = extract_ec_pubkey_from_csr(&csr_der)
            .unwrap_or_else(|e| panic!("failed to extract public key from CSR: {e}"));
        eprintln!(
            "[hsm-keys] device public key extracted from CSR ({} bytes)",
            pub_key.len()
        );
        pub_key
    } else {
        let pub_path = device_pub_path.unwrap();
        let bytes = fs::read(&pub_path)
            .unwrap_or_else(|e| panic!("failed to read device public key {pub_path}: {e}"));
        let pub_bytes = extract_ec_pub_only(&bytes);
        eprintln!(
            "[hsm-keys] device public key loaded ({} bytes)",
            pub_bytes.len()
        );
        pub_bytes
    };

    // ---------------------------------------------------------------
    // 1. Load / generate trust-anchor keypairs (off-device, retained
    //    by the signing infrastructure)
    //
    // Persisted under keys_dir so consecutive builds reuse the same
    // material. Regenerating would invalidate every envelope a
    // previously-provisioned device is carrying.
    //
    // Note: only TRUST ANCHORS are loaded here. Device-side keys
    // (device-decrypt, ecu-signing, ivd-signing, jwt-signing, ...)
    // are generated INSIDE the HSM during provisioning — neither
    // pushed in via the envelope nor pulled back out. The envelope
    // enumerates those slots with empty material so SimHsm's
    // `generate_missing_local_keys` knows to create them.
    // ---------------------------------------------------------------
    let (ka_priv, ka_pub) =
        load_or_generate_ec_keypair(&keys_dir.join("key-authority.keypair"), "key-authority");
    let (_pa_priv, pa_pub) = load_or_generate_ec_keypair(
        &keys_dir.join("platform-authority.keypair"),
        "platform-authority",
    );
    let (_aa_priv, aa_pub) = load_or_generate_ec_keypair(
        &keys_dir.join("application-authority.keypair"),
        "application-authority",
    );

    // ---------------------------------------------------------------
    // 2. Build key slots — well-known first (KeyRole order), then jwt,
    //    then test slots, then bulk app slots.
    // ---------------------------------------------------------------
    let total = NUM_APP_SLOTS + NUM_WELL_KNOWN_SLOTS + NUM_TEST_SLOTS;
    println!("[hsm-keys] generating {} key slots...", total);

    let mut slots = Vec::with_capacity(total);

    // Slot 0: Key Authority — public-key-only trust anchor for
    // subsequent HSM key envelopes. Private stays with the backend.
    slots.push(KeySlot {
        key_id: "key-authority".to_string(),
        key_kind: KEY_TYPE_EC_P256,
        anchor_public_key: Some(ka_pub.clone()),
        allowed_guests: None,
        allowed_ops: Some(vec![OP_VERIFY]),
    });

    // Slot 1: Software Authority — verifies host-side firmware
    // envelopes (vm1, vm2, host-os, hsm bundle). Public-key-only.
    let (_sw_auth_priv, sw_auth_pub) = extract_ec_raw(&signing_key);
    slots.push(KeySlot {
        key_id: "sw-authority".to_string(),
        key_kind: KEY_TYPE_EC_P256,
        anchor_public_key: Some(sw_auth_pub),
        allowed_guests: None,
        allowed_ops: Some(vec![OP_VERIFY, OP_GET_PUBKEY]),
    });

    // Slot 2: Platform Authority — verifies platform-tier container
    // envelopes (SOVD gateway, observability, security helpers).
    // Public-key-only; the customer's platform-signing infra owns the
    // private half.
    slots.push(KeySlot {
        key_id: "platform-authority".to_string(),
        key_kind: KEY_TYPE_EC_P256,
        anchor_public_key: Some(pa_pub.clone()),
        allowed_guests: None,
        allowed_ops: Some(vec![OP_VERIFY, OP_GET_PUBKEY]),
    });

    // Slot 3: Application Authority — verifies vehicle-function
    // container envelopes (ADAS, infotainment, body control, third-
    // party apps). Public-key-only; signing delegated wide.
    slots.push(KeySlot {
        key_id: "application-authority".to_string(),
        key_kind: KEY_TYPE_EC_P256,
        anchor_public_key: Some(aa_pub.clone()),
        allowed_guests: None,
        allowed_ops: Some(vec![OP_VERIFY, OP_GET_PUBKEY]),
    });

    // Slot 4: Device decryption key — device generates internally
    // (ensure_device_key on first boot, before the CSR is even
    // emitted). Factory tool reads the pub from the CSR for
    // envelope-encryption recipient binding, but the envelope itself
    // just enumerates the slot — `generate_missing_local_keys` is a
    // no-op here because the .priv/.pub already exist on disk.
    slots.push(KeySlot {
        key_id: "device-decrypt".to_string(),
        key_kind: KEY_TYPE_EC_P256,
        anchor_public_key: None,
        allowed_guests: None,
        allowed_ops: None,
    });

    // Slot 5: ECU signing key — device generates internally during
    // provisioning. No private bytes pushed; the certificate-issuance
    // flow (factory tool ↔ device CSR for ecu-signing) is a
    // follow-up — for now the slot ships with no certificate and the
    // device-side key is generated by `generate_missing_local_keys`.
    slots.push(KeySlot {
        key_id: "ecu-signing".to_string(),
        key_kind: KEY_TYPE_EC_P256,
        anchor_public_key: None,
        allowed_guests: Some(vec!["bali-vm-1".into()]),
        allowed_ops: Some(vec![OP_SIGN, OP_VERIFY, OP_GET_PUBKEY]),
    });

    // Slot 6: IVD signing — device generates internally. Private
    // never crosses the HSM boundary in either direction. After
    // provisioning, `sumo-verify` fetches the public half via
    // `get_public_key("ivd-signing")` to validate bank signatures
    // for external secure boot.
    slots.push(KeySlot {
        key_id: "ivd-signing".to_string(),
        key_kind: KEY_TYPE_EC_P256,
        anchor_public_key: None,
        allowed_guests: None,
        allowed_ops: Some(vec![OP_SIGN, OP_VERIFY, OP_GET_PUBKEY]),
    });

    // Slot 7: JWT signing key for jwt-mgr — device-generated. The
    // guest's jwt-mgr fetches the public half via vHSM OP_GET_PUBKEY
    // to validate locally-issued tokens.
    slots.push(KeySlot {
        key_id: "jwt-signing".to_string(),
        key_kind: KEY_TYPE_EC_P256,
        anchor_public_key: None,
        allowed_guests: Some(vec!["bali-vm-1".into()]),
        allowed_ops: Some(vec![OP_SIGN, OP_VERIFY, OP_GET_PUBKEY]),
    });

    // ---------------------------------------------------------------
    // Test keys (matching vhsm-test / test_all.sh expectations)
    //
    // Same rule as the device-side slots above: no private bytes
    // pushed. Slot definitions are enumeration-only; SimHsm's
    // `generate_missing_local_keys` fills in the material at
    // provision time. Tests exercise these via OP_GET_PUBKEY for
    // public halves and via OP_ENCRYPT/OP_DECRYPT for AES.
    //
    // The previous `dummy_self_signed_cert` for `mykey` is dropped —
    // a CSR-based cert flow is the right path; for the slot
    // enumeration only, we can't materialise a cert without knowing
    // the locally-generated public half.
    // ---------------------------------------------------------------

    slots.push(KeySlot {
        key_id: "mykey".to_string(),
        key_kind: KEY_TYPE_EC_P256,
        anchor_public_key: None,
        allowed_guests: Some(vec!["bali-vm-1".into()]),
        allowed_ops: Some(vec![OP_SIGN, OP_VERIFY, OP_GET_PUBKEY]),
    });

    slots.push(KeySlot {
        key_id: "storage-key".to_string(),
        key_kind: KEY_TYPE_AES_256,
        anchor_public_key: None,
        allowed_guests: Some(vec!["bali-vm-1".into()]),
        allowed_ops: Some(vec![OP_ENCRYPT, OP_DECRYPT, OP_DERIVE]),
    });

    slots.push(KeySlot {
        key_id: "restricted-key".to_string(),
        key_kind: KEY_TYPE_AES_256,
        anchor_public_key: None,
        allowed_guests: Some(vec!["bali-vm-2".into()]),
        allowed_ops: Some(vec![OP_ENCRYPT, OP_DECRYPT]),
    });

    // Bulk application slots — slot enumeration only, no material.
    for i in 0..NUM_APP_SLOTS {
        let slot_num = i + 7;
        let guest = GUESTS[i % GUESTS.len()].to_string();
        if i % 3 == 0 {
            slots.push(KeySlot {
                key_id: format!("aes-{slot_num:03}"),
                key_kind: KEY_TYPE_AES_256,
                anchor_public_key: None,
                allowed_guests: Some(vec![guest]),
                allowed_ops: Some(vec![OP_ENCRYPT, OP_DECRYPT, OP_DERIVE]),
            });
        } else {
            slots.push(KeySlot {
                key_id: format!("ec-{slot_num:03}"),
                key_kind: KEY_TYPE_EC_P256,
                anchor_public_key: None,
                allowed_guests: Some(vec![guest]),
                allowed_ops: Some(vec![OP_SIGN, OP_VERIFY, OP_GET_PUBKEY]),
            });
        }
    }

    println!(
        "[hsm-keys] {} slots: {} EC-P256, {} AES-256",
        slots.len(),
        slots
            .iter()
            .filter(|s| s.key_kind == KEY_TYPE_EC_P256)
            .count(),
        slots
            .iter()
            .filter(|s| s.key_kind == KEY_TYPE_AES_256)
            .count(),
    );

    // ---------------------------------------------------------------
    // 2. Generate guest identities
    // ---------------------------------------------------------------
    let identities: Vec<IdentityDef> = GUESTS
        .iter()
        .map(|guest| {
            let (_priv_key, pub_key) = generate_ec_p256_raw();
            IdentityDef {
                identity_id: guest.to_string(),
                public_key: pub_key,
            }
        })
        .collect();

    println!("[hsm-keys] {} guest identities", identities.len());

    // ---------------------------------------------------------------
    // 3. Build keystores and serialize to CBOR
    // ---------------------------------------------------------------
    let keystore = HsmKeystore {
        schema_version: SCHEMA_VERSION,
        security_version: 1,
        identities: identities.clone(),
        slots: slots.clone(),
        certificates: Vec::new(),
    };

    let cbor = encode(&keystore).unwrap();
    eprintln!("[hsm-keys] CBOR payload: {} bytes", cbor.len());

    let digest = crypto.sha256(&cbor);

    // ---------------------------------------------------------------
    // Export Key Authority files (needed for re-provisioning)
    // ---------------------------------------------------------------
    let ka_full_cose = build_device_cose_key(&ka_priv, &ka_pub[1..33], &ka_pub[33..65]);
    let ka_pub_cose = build_public_cose_key(&ka_pub[1..33], &ka_pub[33..65]);

    let ka_pub_path = keys_dir.join("key-authority.pub");
    fs::write(&ka_pub_path, &ka_pub_cose).unwrap();
    let ka_key_path = keys_dir.join("key-authority.key");
    fs::write(&ka_key_path, &ka_full_cose).unwrap();
    eprintln!("[hsm-keys] Key Authority public: {}", ka_pub_path.display());
    eprintln!(
        "[hsm-keys] Key Authority private: {}",
        ka_key_path.display()
    );

    // Export device public key as COSE_Key (needed by sumo-tool --encrypt)
    let device_pub_cose = build_public_cose_key(&dk_pub[1..33], &dk_pub[33..65]);
    let device_pub_path = keys_dir.join("device-decrypt.cosekey");
    fs::write(&device_pub_path, &device_pub_cose).unwrap();
    eprintln!(
        "[hsm-keys] Device public key (COSE): {}",
        device_pub_path.display()
    );

    // ---------------------------------------------------------------
    // --cbor-only: write raw CBOR to stdout, skip SUIT envelope wrapping
    // ---------------------------------------------------------------
    if cbor_only {
        use std::io::Write;
        std::io::stdout().write_all(&cbor).unwrap();
        std::io::stdout().flush().unwrap();
        eprintln!(
            "[hsm-keys] wrote {} bytes CBOR to stdout ({} slots, {} identities)",
            cbor.len(),
            keystore.slots.len(),
            keystore.identities.len(),
        );
        eprintln!("[hsm-keys] pipe to: sumo-tool build --manifest <yaml>");
        return;
    }

    // ---------------------------------------------------------------
    // 4. Factory envelope (signed: factory key, encrypted: device key)
    // ---------------------------------------------------------------
    println!("\n[hsm-keys] === Factory envelope (signed: factory, encrypted: device key) ===");

    let factory_envelope = build_encrypted_envelope(
        &envelope_signing_key,
        &device_pub_cose,
        &cbor,
        &digest,
        1, // sequence_number
        1, // security_version
        "1.0.0",
        "Factory HSM key provisioning (100 slots)",
    );

    let factory_path = output_dir.join("hsm-keys-v1.suit");
    fs::write(&factory_path, &factory_envelope).unwrap();
    println!(
        "[hsm-keys] {} ({} bytes)",
        factory_path.display(),
        factory_envelope.len()
    );

    // ---------------------------------------------------------------
    // 5. Re-provision envelope (signed: key authority, encrypted: device key)
    // ---------------------------------------------------------------
    println!(
        "\n[hsm-keys] === Re-provision envelope (signed: key authority, encrypted: device key) ==="
    );

    let mut keystore_v2 = keystore.clone();
    keystore_v2.security_version = 2;
    let cbor_v2 = encode(&keystore_v2).unwrap();
    let digest_v2 = crypto.sha256(&cbor_v2);

    // Build CoseKey for Key Authority signing
    let ka_signing_key = {
        let key = coset::CoseKeyBuilder::new_ec2_priv_key(
            iana::EllipticCurve::P_256,
            ka_pub[1..33].to_vec(),
            ka_pub[33..65].to_vec(),
            ka_priv.clone(),
        )
        .algorithm(iana::Algorithm::ES256)
        .build();
        CoseKey::from_cose_key_bytes(&key.to_vec().unwrap()).unwrap()
    };

    let reprov_envelope = build_encrypted_envelope(
        &ka_signing_key,
        &device_pub_cose,
        &cbor_v2,
        &digest_v2,
        2,
        2,
        "2.0.0",
        "Re-provision HSM keys (100 slots, key authority signed)",
    );

    let reprov_path = output_dir.join("hsm-keys-v2.suit");
    fs::write(&reprov_path, &reprov_envelope).unwrap();
    println!(
        "[hsm-keys] {} ({} bytes)",
        reprov_path.display(),
        reprov_envelope.len()
    );

    // ---------------------------------------------------------------
    // 6. Summary
    // ---------------------------------------------------------------
    println!("\n=== HSM Key Provisioning Artifacts ===");
    println!();
    println!(
        "  Factory envelope:      {} ({} bytes, signed: factory, encrypted: device)",
        factory_path.display(),
        factory_envelope.len()
    );
    println!(
        "  Re-provision envelope: {} ({} bytes, signed: key-authority, encrypted: device)",
        reprov_path.display(),
        reprov_envelope.len()
    );
    println!("  Key Authority public:  {}", ka_pub_path.display());
    println!("  Key Authority private: {}", ka_key_path.display());
    println!("  Device public key:     {}", device_pub_path.display());
    println!();
    println!("  Key slots:     {}", keystore.slots.len());
    println!("  Identities:    {}", keystore.identities.len());
    println!("  CBOR payload:  {} bytes", cbor.len());
    println!();
    println!("Both envelopes: CBOR → zstd → AES-GCM (to device key) → SUIT.");
    println!("Factory signed with built-in factory key. Re-provision signed with Key Authority.");
}

/// Build a compressed + encrypted SUIT envelope.
#[allow(clippy::too_many_arguments)]
fn build_encrypted_envelope(
    signing_key: &CoseKey,
    recipient_pub_cbor: &[u8],
    cbor_payload: &[u8],
    plaintext_digest: &[u8; 32],
    seq: u64,
    security_version: u64,
    version: &str,
    description: &str,
) -> Vec<u8> {
    let recipient_pub = CoseKey::from_cose_key_bytes(recipient_pub_cbor).unwrap();

    // Compress
    let compressed = encryptor::compress_firmware(cbor_payload, 3, None).unwrap();

    // Encrypt (ECDH-ES+A128KW + AES-128-GCM) with fresh ephemeral sender key
    let ephemeral_sender = keygen::generate_device_key(keygen::ES256).unwrap();
    let recipients = [Recipient {
        public_key: recipient_pub,
        kid: b"device-decrypt".to_vec(),
    }];
    let encrypted =
        encryptor::encrypt_firmware_ecdh(&compressed, &ephemeral_sender, &recipients).unwrap();

    // Build SUIT envelope
    ImageManifestBuilder::new()
        .component_id(vec!["hsm".to_string(), "keys".to_string()])
        .sequence_number(seq)
        .security_version(security_version)
        .payload_digest(plaintext_digest, cbor_payload.len() as u64)
        .payload_uri("#hsm-keys".to_string())
        .encryption_info(&encrypted.encryption_info)
        .integrated_payload("#hsm-keys".to_string(), encrypted.ciphertext)
        .text_version(version)
        .text_vendor_name("vm-mgr")
        .text_model_name("HSM-Keys")
        .text_description(description)
        .build(signing_key)
        .unwrap()
}

/// Build a COSE_Key (EC2, P-256, private) as CBOR bytes.
fn build_device_cose_key(d: &[u8], x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut key = coset::CoseKeyBuilder::new_ec2_priv_key(
        iana::EllipticCurve::P_256,
        x.to_vec(),
        y.to_vec(),
        d.to_vec(),
    )
    .build();
    key.alg = None; // Device key — ECDH, not signing
    key.to_vec().unwrap()
}

/// Build a COSE_Key (EC2, P-256, public only) as CBOR bytes.
fn build_public_cose_key(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut key =
        coset::CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x.to_vec(), y.to_vec())
            .build();
    key.alg = None;
    key.to_vec().unwrap()
}

/// Extract public key (65 bytes uncompressed) from COSE_Key CBOR bytes.
fn extract_ec_pub_only(cose_bytes: &[u8]) -> Vec<u8> {
    let cose_key: coset::CoseKey = coset::CoseKey::from_slice(cose_bytes).unwrap();

    let mut x = Vec::new();
    let mut y = Vec::new();

    for (label, value) in &cose_key.params {
        if let (coset::Label::Int(n), ciborium::Value::Bytes(bytes)) = (label, value) {
            match *n {
                -2 => x = bytes.clone(),
                -3 => y = bytes.clone(),
                _ => {}
            }
        }
    }

    assert_eq!(x.len(), 32, "EC-P256 x coordinate must be 32 bytes");
    assert_eq!(y.len(), 32, "EC-P256 y coordinate must be 32 bytes");

    let mut pub_key = Vec::with_capacity(65);
    pub_key.push(0x04);
    pub_key.extend_from_slice(&x);
    pub_key.extend_from_slice(&y);
    pub_key
}

/// Extract raw EC-P256 key material from an existing CoseKey (signing key).
/// Returns (32-byte scalar, 65-byte uncompressed public).
fn extract_ec_raw(key: &CoseKey) -> (Vec<u8>, Vec<u8>) {
    let cose_bytes = key.to_cose_key_bytes();
    let cose_key: coset::CoseKey = coset::CoseKey::from_slice(&cose_bytes).unwrap();

    let mut d = Vec::new();
    let mut x = Vec::new();
    let mut y = Vec::new();

    for (label, value) in &cose_key.params {
        if let (coset::Label::Int(n), ciborium::Value::Bytes(bytes)) = (label, value) {
            match *n {
                -4 => d = bytes.clone(),
                -2 => x = bytes.clone(),
                -3 => y = bytes.clone(),
                _ => {}
            }
        }
    }

    let mut pub_key = Vec::with_capacity(65);
    pub_key.push(0x04);
    pub_key.extend_from_slice(&x);
    pub_key.extend_from_slice(&y);

    (d, pub_key)
}

/// Generate a raw EC-P256 key pair: (32-byte scalar, 65-byte uncompressed public).
fn generate_ec_p256_raw() -> (Vec<u8>, Vec<u8>) {
    let key = keygen::generate_device_key(keygen::ES256).unwrap();
    let cose_bytes = key.to_cose_key_bytes();
    let cose_key: coset::CoseKey = coset::CoseKey::from_slice(&cose_bytes).unwrap();

    let mut d = Vec::new();
    let mut x = Vec::new();
    let mut y = Vec::new();

    for (label, value) in &cose_key.params {
        if let (coset::Label::Int(n), ciborium::Value::Bytes(bytes)) = (label, value) {
            match *n {
                -4 => d = bytes.clone(), // EC2 d
                -2 => x = bytes.clone(), // EC2 x
                -3 => y = bytes.clone(), // EC2 y
                _ => {}
            }
        }
    }

    let mut pub_key = Vec::with_capacity(65);
    pub_key.push(0x04);
    pub_key.extend_from_slice(&x);
    pub_key.extend_from_slice(&y);

    (d, pub_key)
}

/// Extract EC-P256 uncompressed public key (65 bytes) from a PKCS#10 CSR DER.
///
/// Minimal parser: walks the ASN.1 to find SubjectPublicKeyInfo → BIT STRING
/// containing the 65-byte uncompressed point (0x04 || x || y).
fn extract_ec_pubkey_from_csr(der: &[u8]) -> Result<Vec<u8>, String> {
    // CertificationRequest ::= SEQUENCE { certificationRequestInfo, ... }
    // certificationRequestInfo ::= SEQUENCE { version, subject, subjectPKInfo, ... }
    // subjectPKInfo ::= SEQUENCE { algorithm, BIT STRING { 0x00 || pubkey } }
    //
    // We need to find the 65-byte uncompressed point (starts with 0x04).
    // Strategy: scan for the EC P-256 OID followed by a BIT STRING containing 66 bytes.

    // Look for the P-256 OID: 06 08 2A 86 48 CE 3D 03 01 07
    let p256_oid: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    let oid_pos = der
        .windows(p256_oid.len())
        .position(|w| w == p256_oid)
        .ok_or_else(|| "P-256 OID not found in CSR".to_string())?;

    // After the OID, find the next BIT STRING (tag 0x03) containing 66 bytes (0x00 + 65)
    let search_start = oid_pos + p256_oid.len();
    for i in search_start..der.len().saturating_sub(67) {
        if der[i] == 0x03 {
            // Parse length
            let (len, hdr_size) = if der[i + 1] < 0x80 {
                (der[i + 1] as usize, 2usize)
            } else if der[i + 1] == 0x81 && i + 2 < der.len() {
                (der[i + 2] as usize, 3usize)
            } else {
                continue;
            };

            if len == 66 && i + hdr_size + len <= der.len() {
                // First byte is unused-bits count (should be 0x00)
                if der[i + hdr_size] != 0x00 {
                    continue;
                }
                let point = &der[i + hdr_size + 1..i + hdr_size + len];
                if point[0] == 0x04 && point.len() == 65 {
                    return Ok(point.to_vec());
                }
            }
        }
    }

    Err("EC public key point not found in CSR".to_string())
}
