/// Simulation HSM provider (portable: Linux + QNX).
///
/// A file-based keystore + RustCrypto implementation of the HSM contract,
/// for dev/test and QNX hypervisor host deployments. Served over link-B by
/// the `hsm-sim-service` bin; it owns no service lifecycle of its own.
///
/// # Provisioning
///
/// Key material arrives as a SUIT envelope (component `["hsm", "keys"]`).
/// The payload is CBOR-encoded `HsmKeystore` (see `payload.rs`).
///
/// - **Factory** (empty HSM): envelope signed with factory signing key,
///   encrypted to device public key. Verified with built-in factory key.
/// - **Re-provision** (has keys): envelope signed with Key Authority,
///   encrypted to device public key. `security_version` must exceed current.
///   Replaces what the envelope owns and keeps everything else — the device's
///   own keys above all (see `carry_over`).
///
/// # Keystore layout (written by provision)
///
/// ```text
/// <keystore_path>/
///   manifest             — key inventory (vhsm-test-ssd line format)
///   identities           — guest-id → pubkey mapping
///   provision_state       — security_version
///   keys/
///     {key_id}.priv      — EC P-256 private key (PEM)
///     {key_id}.pub       — EC P-256 public key (PEM)
///     {key_id}.cert      — X.509 certificate (PEM, optional)
///     {key_id}.bin       — AES-256 raw key (32 bytes)
/// ```
use std::io::Write;
use std::path::{Path, PathBuf};

use hsm::payload::{self, HsmKeystore, KeySlot, KEY_TYPE_AES_256, KEY_TYPE_EC_P256};
use hsm::{
    HsmError, HsmProvider, KeyHandle, KeyRole, KeyType, ProvisioningState, SlotBacking, SlotInfo,
    SlotKind,
};

/// Software HSM — the sim/dev backend. **No hardware key protection.**
///
/// `SimHsm` is a file-keystore + RustCrypto implementation of `HsmProvider` /
/// `HsmCryptoProvider` — the HSM sim/dev deployments run (the host machine
/// manager spawns and owns it on sim devices) until real-HSM integration lands.
/// It is **just another implementation of the HSM contract**, not a privileged
/// one: hardware production runs a real HSE (a vendor C link-B service
/// implementing `hsm-link-b`). It is served over link-B by the `hsm-sim-service`
/// bin; verify any backend with the `hsm-conformance` suite.
///
/// It is purely a keystore + crypto over `keystore_path` — it owns no service
/// lifecycle. The link-B service (`hsm-sim-service`) and the host's daemon
/// supervision (the host) live outside it.
pub struct SimHsm {
    /// Keystore directory (e.g. /tmp/vhsm-keys).
    keystore_path: PathBuf,
}

impl SimHsm {
    /// Construct a SimHsm over `keystore_path`. No daemon, no port — crypto and
    /// keystore ops read/write the directory directly.
    pub fn new(keystore_path: PathBuf) -> Self {
        Self { keystore_path }
    }

    /// Factory signing public key as COSE_Key CBOR — the built-in provisioning authority.
    fn factory_provisioning_authority() -> Vec<u8> {
        use coset::CborSerializable;
        let pub_key = &payload::FACTORY_SIGNING_PUBLIC;
        let x = &pub_key[1..33];
        let y = &pub_key[33..65];
        coset::CoseKeyBuilder::new_ec2_pub_key(
            coset::iana::EllipticCurve::P_256,
            x.to_vec(),
            y.to_vec(),
        )
        .algorithm(coset::iana::Algorithm::ES256)
        .build()
        .to_vec()
        .expect("COSE_Key serialization")
    }

    /// Path to the manifest file inside the keystore.
    pub(crate) fn manifest_path(&self) -> PathBuf {
        self.keystore_path.join("manifest")
    }

    /// Path to the provision state file.
    fn state_path(&self) -> PathBuf {
        self.keystore_path.join("provision_state")
    }

    /// Path to a named monotonic-counter slot's file (a decimal `u64`) — one file
    /// PER handle (e.g. `monotonic_0000000d` for the time-floor slot). Kept
    /// separate from `provision_state` so a counter's write path is independent of
    /// keystore provisioning — a re-provision must never disturb it, and a counter
    /// ratchet must never rewrite provisioning state. On real hardware each is a
    /// slot in the HSM's secure-NV; here it's a file in the keystore dir.
    fn monotonic_path(&self, handle: u32) -> PathBuf {
        self.keystore_path.join(format!("monotonic_{handle:08x}"))
    }

    /// Read the named monotonic-counter slot `handle`'s file (decimal `u64`);
    /// 0 if absent. The per-handle read shared by the trait `read_monotonic` and
    /// `ratchet_monotonic`.
    fn read_monotonic_at(&self, handle: u32) -> Result<u64, HsmError> {
        let path = self.monotonic_path(handle);
        if !path.exists() {
            return Ok(0);
        }
        let content = std::fs::read_to_string(&path)
            .map_err(|e| HsmError::KeystoreError(format!("read {}: {e}", path.display())))?;
        content.trim().parse().map_err(|e| {
            HsmError::KeystoreError(format!("corrupt monotonic counter {}: {e}", path.display()))
        })
    }

    /// Ratchet the named monotonic-counter slot `handle` to `max(current,
    /// new_value)`; return the resulting value. Monotonic — a value at or below
    /// the stored one is a no-op (never rewinds; the anti-rollback safety core,
    /// mirroring `security_version` / `adopt_monotonic`). `&self` (file-backed),
    /// so the provisioning-time seed in `write_leaf_certs` can call it too.
    fn ratchet_monotonic(&self, handle: u32, new_value: u64) -> Result<u64, HsmError> {
        let current = self.read_monotonic_at(handle)?;
        let raised = current.max(new_value);
        if raised != current {
            write_atomic(
                &self.monotonic_path(handle),
                raised.to_string().as_bytes(),
                false,
            )
            .map_err(|e| HsmError::KeystoreError(format!("write monotonic counter: {e}")))?;
        }
        Ok(raised)
    }

    /// Keys subdirectory.
    pub(crate) fn keys_dir(&self) -> PathBuf {
        self.keystore_path.join("keys")
    }

    /// Resolve what an interrupted re-provision left behind, so a start never
    /// sees a missing or half-built keystore. A re-provision builds the new
    /// keystore in `<keystore>.tmp`, renames the live one to `<keystore>.bak`,
    /// renames `.tmp` to the live path (the commit point), then removes
    /// `.bak`. Each state a stop can leave, and its outcome:
    ///
    /// | live | `.tmp` | `.bak` | stopped | outcome |
    /// |---|---|---|---|---|
    /// | yes | yes | – | while building `.tmp`, or before the first rename | old: `.tmp` removed |
    /// | yes | – | yes | after the commit rename, before removing `.bak` | new: `.bak` removed |
    /// | no | yes | yes | between the two renames | old: `.bak` renamed back, `.tmp` removed |
    /// | no | no | yes | (never left by `provision`; `.tmp` lost) | old: `.bak` renamed back |
    /// | no | yes | no | (never left by `provision`; `.bak` lost) | `.tmp` renamed to live: it holds the carried device keys, and if its build was cut short it has no manifest (written last) and reads as unprovisioned |
    ///
    /// No leftovers (a healthy or a fresh keystore) is a no-op. Device keys are
    /// in every outcome, since `.tmp` starts as a copy of them.
    pub fn recover_interrupted_reprovision(&self) -> Result<(), HsmError> {
        let live = &self.keystore_path;
        let staging = live.with_extension("tmp");
        let backup = live.with_extension("bak");
        let discard = |dir: &Path| {
            if dir.exists() {
                tracing::warn!(dir = %dir.display(), "removing a leftover of an interrupted re-provision");
                if let Err(e) = std::fs::remove_dir_all(dir) {
                    tracing::warn!(dir = %dir.display(), error = %e, "could not remove re-provision leftover");
                }
            }
        };
        let restore = |from: &Path| {
            tracing::warn!(
                from = %from.display(),
                keystore = %live.display(),
                "keystore missing after an interrupted re-provision; restoring it"
            );
            std::fs::rename(from, live).map_err(|e| {
                HsmError::KeystoreError(format!("restore keystore from {}: {e}", from.display()))
            })
        };
        if live.exists() {
            discard(&staging);
            discard(&backup);
        } else if backup.exists() {
            restore(&backup)?;
            discard(&staging);
        } else if staging.exists() {
            restore(&staging)?;
        }
        Ok(())
    }

    /// Ensure the device-side EC-P256 key pairs exist. Called on first use.
    /// Generates `keys/{key_id}.priv` + `.pub` for every device-generated
    /// role that's missing. Runs regardless of provisioning state — these
    /// keys must exist before the first key-bundle flash so the device can
    /// (a) receive its encrypted factory envelope (device-decrypt) and
    /// (b) IVD-sign its own pre-provisioning bank dirs (ivd-signing).
    /// The provisioning envelope is allowed to leave these slots
    /// device-generated; `generate_missing_local_keys` skips existing files,
    /// and a re-provision carries every device key into the new keystore, so
    /// the factory-bootstrapped material persists across re-provision.
    ///
    /// First resolves a re-provision the process did not finish
    /// ([`Self::recover_interrupted_reprovision`]), so a key is never generated
    /// into the gap a keystore swap leaves.
    #[cfg(feature = "crypto")]
    pub fn ensure_device_keys(&self) -> Result<(), HsmError> {
        self.recover_interrupted_reprovision()?;
        std::fs::create_dir_all(self.keys_dir())
            .map_err(|e| HsmError::KeystoreError(format!("create keys dir: {e}")))?;
        restrict_dir_700(&self.keys_dir());

        // A keystore that is provisioned or already holds a device key belongs
        // to an established device: a key created in it now is not first boot.
        let material = |role: &KeyRole| {
            let ext = match role.key_type() {
                KeyType::Aes256 => "bin",
                _ => "priv",
            };
            self.keys_dir().join(format!("{}.{ext}", role.key_id()))
        };
        let established = self.manifest_path().exists()
            || KeyRole::mandatory_roles()
                .iter()
                .any(|r| r.is_device_generated() && material(r).exists());

        for role in KeyRole::mandatory_roles() {
            if !role.is_device_generated() {
                continue;
            }
            let key_id = role.key_id();

            // The lone symmetric slot (`storage-key`) generates AES-256 key
            // bytes; every other device-generated slot is an EC-P256 keypair.
            if role.key_type() == KeyType::Aes256 {
                let bin_path = self.keys_dir().join(format!("{key_id}.bin"));
                if bin_path.exists() {
                    continue;
                }
                let mut bytes = vec![0u8; 32];
                use rand::RngCore;
                rand::rngs::OsRng.fill_bytes(&mut bytes);
                write_atomic(&bin_path, &bytes, false)
                    .map_err(|e| HsmError::KeystoreError(format!("write {key_id} key: {e}")))?;
                if established {
                    log_device_key_replaced(*role);
                } else {
                    tracing::info!(key_id = %key_id, "device-side AES-256 key generated (first boot)");
                }
                continue;
            }

            let priv_path = self.keys_dir().join(format!("{key_id}.priv"));
            if priv_path.exists() {
                continue;
            }

            let sk = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
            let scalar = sk.to_bytes();
            let pk = sk.verifying_key().to_encoded_point(false);

            // Public half first: `.priv` is what marks the pair present, so a
            // crash between the two writes regenerates the pair rather than
            // leaving a private key with no public half.
            let pub_path = self.keys_dir().join(format!("{key_id}.pub"));
            write_pem_ec_public(&pub_path, pk.as_bytes())
                .map_err(|e| HsmError::KeystoreError(format!("write {key_id} pub: {e}")))?;

            write_pem_ec_private(&priv_path, &scalar)
                .map_err(|e| HsmError::KeystoreError(format!("write {key_id} priv: {e}")))?;

            if established {
                log_device_key_replaced(*role);
            } else {
                tracing::info!(key_id = %key_id, "device-side key pair generated (first boot)");
            }
        }
        Ok(())
    }

    /// Build the re-provisioned keystore for `ks` in `<keystore>.tmp`: what the
    /// live keystore holds beyond the envelope's files ([`carry_over`]), then
    /// `ks` written on top, all of it synced to disk. Returns the staging path;
    /// the live keystore is untouched.
    fn stage_reprovision(&self, ks: &HsmKeystore) -> Result<PathBuf, HsmError> {
        let staging = self.keystore_path.with_extension("tmp");
        // The live keystore exists here, so this only clears leftovers.
        self.recover_interrupted_reprovision()?;
        let staged = carry_over(&self.keystore_path, &staging, CarryLevel::Root)
            .and_then(|()| SimHsm::new(staging.clone()).write_keystore(ks))
            .and_then(|()| sync_tree(&staging));
        if let Err(e) = staged {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(e);
        }
        Ok(staging)
    }

    /// Load the current security_version from provision_state.
    fn load_security_version(&self) -> Result<u64, HsmError> {
        let path = self.state_path();
        if !path.exists() {
            return Ok(0);
        }
        let content = std::fs::read_to_string(&path)
            .map_err(|e| HsmError::KeystoreError(format!("read provision_state: {e}")))?;
        // First line is security_version
        content
            .lines()
            .next()
            .and_then(|line| line.trim().parse().ok())
            .ok_or_else(|| HsmError::KeystoreError("corrupt provision_state".into()))
    }

    fn save_state(&self, security_version: u64) -> Result<(), HsmError> {
        write_atomic(
            &self.state_path(),
            security_version.to_string().as_bytes(),
            false,
        )
        .map_err(|e| HsmError::KeystoreError(format!("write provision_state: {e}")))?;
        Ok(())
    }

    /// Write the keystore files from a parsed CBOR payload.
    ///
    /// Two-pass:
    /// 1. `write_key_files` — accept slot definitions; refuse any
    ///    pushed private keys; write trust-anchor publics and certs.
    /// 2. `generate_missing_local_keys` — every slot that still has
    ///    no private material gets a fresh one generated locally.
    ///    This is the device-side keygen the no-push-no-pull
    ///    invariant requires.
    pub fn write_keystore(&self, ks: &HsmKeystore) -> Result<(), HsmError> {
        let keys_dir = self.keys_dir();
        std::fs::create_dir_all(&keys_dir)
            .map_err(|e| HsmError::KeystoreError(format!("create keys dir: {e}")))?;
        restrict_dir_700(&keys_dir);

        for slot in &ks.slots {
            self.write_key_files(slot, &keys_dir)?;
        }

        self.generate_missing_local_keys(ks)?;

        // Install any signed leaf certs (v3) for device-generated identity
        // keys — BEFORE the manifest, so write_manifest records their
        // cert_path. The key was generated on an earlier provision; this
        // re-provision lands the CA-issued leaf for it (e.g. tls-identity).
        self.write_leaf_certs(&ks.certificates, &keys_dir)?;

        // Install any pinned trust-anchor CA roots (v4) — foreign roots the
        // device pins for delegated-token x5c validation (e.g. the delegation
        // root). Public trust material, not a device key.
        self.write_trust_anchors(&ks.trust_anchors, &keys_dir)?;

        self.write_identities(ks)?;
        self.save_state(ks.security_version)?;
        // The manifest last: its presence is what reads as provisioned, so a
        // keystore interrupted before this point is still unprovisioned and the
        // same envelope can simply be applied again.
        self.write_manifest(&ks.slots)?;

        Ok(())
    }

    /// `Ok` when every leaf in `certs` parses as an X.509 certificate whose
    /// subject public key is the key this device holds for the leaf's slot:
    /// the live `{key_id}.pub`, what `get_public_key_der` returns and what the
    /// CA signed the leaf for. `PayloadInvalid` for a leaf that does not
    /// parse, names a slot with no key here, or certifies another key — a
    /// leaf installed for another key would make every verifying TLS client
    /// fail. Reads only.
    #[cfg(feature = "crypto")]
    fn check_leaf_certs(&self, certs: &[hsm::payload::LeafCert]) -> Result<(), HsmError> {
        use p256::pkcs8::DecodePublicKey;
        use x509_cert::der::{Decode, Encode};
        for c in certs {
            let refuse = |why: String| {
                HsmError::PayloadInvalid(format!("leaf cert for '{}' {why}", c.key_id))
            };
            let leaf_spki = x509_cert::Certificate::from_der(&c.certificate)
                .and_then(|cert| cert.tbs_certificate.subject_public_key_info.to_der())
                .map_err(|e| refuse(format!("does not parse as an X.509 certificate: {e}")))?;
            let pub_path = self.keys_dir().join(format!("{}.pub", c.key_id));
            let pem = match std::fs::read_to_string(&pub_path) {
                Ok(pem) => pem,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(refuse("names a slot with no key on this device".into()))
                }
                Err(e) => {
                    return Err(HsmError::KeystoreError(format!(
                        "read {}: {e}",
                        pub_path.display()
                    )))
                }
            };
            let device = decode_pem(&pem, "PUBLIC KEY").and_then(|der| {
                p256::PublicKey::from_public_key_der(&der).map_err(|e| {
                    HsmError::KeystoreError(format!("parse {}: {e}", pub_path.display()))
                })
            })?;
            if p256::PublicKey::from_public_key_der(&leaf_spki).ok() != Some(device) {
                return Err(refuse("does not match the on-disk public key".into()));
            }
        }
        Ok(())
    }

    /// Write each delivered leaf certificate to `{key_id}.cert` (PEM). The
    /// cert is a public artifact bound to a device-generated key whose
    /// private half never left the HSM; `payload::decode` has already
    /// checked each names an EC-P256 slot in this keystore, and `provision`
    /// that each certifies the key the device holds for it
    /// ([`Self::check_leaf_certs`]).
    fn write_leaf_certs(
        &self,
        certs: &[hsm::payload::LeafCert],
        keys_dir: &Path,
    ) -> Result<(), HsmError> {
        for c in certs {
            let cert_path = keys_dir.join(format!("{}.cert", c.key_id));
            write_pem_certificate(&cert_path, &c.certificate)?;
            tracing::info!(key_id = %c.key_id, "installed leaf certificate");

            // Time-floor seed: this leaf was minted by our own CA (the payload
            // signature was verified by `provision` before we got here), so its
            // `notBefore` is a signature-anchored, rollback-proof lower bound we
            // can safely ratchet the time-floor slot to. The HSM ascribes no
            // meaning to the value; a caller interprets it (see the caller-side
            // seed/share). Seeding at provisioning makes the floor non-zero from
            // first boot. Monotonic, so this can only move it forward.
            #[cfg(feature = "crypto")]
            if let Some(nb) = leaf_not_before_secs(&c.certificate) {
                match self.ratchet_monotonic(vhsm_proto::HANDLE_TIME_FLOOR, nb) {
                    Ok(v) => tracing::info!(
                        key_id = %c.key_id, not_before = nb, monotonic = v,
                        "time-floor slot ratcheted from installed leaf notBefore"
                    ),
                    Err(e) => tracing::warn!(key_id = %c.key_id, error = %e,
                        "could not ratchet time-floor slot"),
                }
            }
        }
        Ok(())
    }

    /// Write each pinned trust-anchor CA root to `roots/{anchor_id}.cert` (PEM).
    /// A foreign CA root the device pins for delegated-token `x5c` validation —
    /// public trust material, NOT a device key, so it lives in its own `roots/`
    /// namespace, not beside the slot files. `payload::decode` has already
    /// checked each is a DER X.509 cert.
    fn write_trust_anchors(
        &self,
        anchors: &[hsm::payload::TrustAnchorCert],
        keys_dir: &Path,
    ) -> Result<(), HsmError> {
        if anchors.is_empty() {
            return Ok(());
        }
        let roots_dir = keys_dir.join("roots");
        std::fs::create_dir_all(&roots_dir)
            .map_err(|e| HsmError::KeystoreError(format!("create roots dir: {e}")))?;
        for a in anchors {
            let path = roots_dir.join(format!("{}.cert", a.anchor_id));
            write_pem_certificate(&path, &a.certificate)?;
            tracing::info!(anchor_id = %a.anchor_id, "installed trust-anchor CA root");
        }
        Ok(())
    }

    /// Write the envelope-visible material for a single slot:
    ///
    /// - Trust anchor (`slot.anchor_public_key = Some(...)`): write
    ///   `{key_id}.pub` (PEM). The HSM stores the public half for
    ///   envelope verification; the private half lives off-device.
    /// - Device-generated (`slot.anchor_public_key = None`): no file
    ///   write here. `generate_missing_local_keys` runs after the
    ///   slot loop and creates the keypair / AES key locally.
    ///
    /// Wire-format invariants are enforced by `payload::decode`
    /// (AES-256 cannot be a trust anchor; EC anchor pubkey must be
    /// 65-byte uncompressed SEC1). This function trusts those
    /// invariants.
    fn write_key_files(&self, slot: &KeySlot, keys_dir: &Path) -> Result<(), HsmError> {
        if let Some(ref pub_key) = slot.anchor_public_key {
            // Trust anchor — write the public half. EC-P256 only
            // (validated at decode).
            let pub_path = keys_dir.join(format!("{}.pub", slot.key_id));
            write_pem_ec_public(&pub_path, pub_key)?;
        }
        // Device-generated slots are deliberately a no-op here.
        // generate_missing_local_keys produces the material.
        Ok(())
    }

    /// Generate any device-side key material that wasn't present
    /// after envelope processing. Called once at the tail of
    /// [`write_keystore`] so every slot in the keystore manifest
    /// ends up with usable material — but the device, not the
    /// envelope, owns every private byte.
    ///
    /// For EC-P256 slots the keypair is fresh `(OsRng-derived
    /// scalar, SEC1-encoded public)`. For AES-256 slots a 32-byte
    /// `.bin` file is written with OS CSPRNG bytes.
    ///
    /// Requires the `crypto` feature for keygen primitives; without
    /// it (the trait-only build) we leave slots empty — callers in
    /// crypto-less builds aren't materialising actual key files
    /// either.
    #[cfg(feature = "crypto")]
    fn generate_missing_local_keys(&self, ks: &HsmKeystore) -> Result<(), HsmError> {
        let keys_dir = self.keys_dir();
        for slot in &ks.slots {
            // Trust anchors carry their public bytes; the HSM never
            // generates a private for them. Skip.
            if slot.is_anchor() {
                continue;
            }
            match slot.key_kind {
                KEY_TYPE_EC_P256 => {
                    let priv_path = keys_dir.join(format!("{}.priv", slot.key_id));
                    if priv_path.exists() {
                        // Already-provisioned slot (e.g. re-provision
                        // envelope with same slot set); leave it.
                        continue;
                    }
                    let sk = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
                    let scalar = sk.to_bytes();
                    let pk = sk.verifying_key().to_encoded_point(false);
                    // Public half first, as in `ensure_device_keys`: `.priv`
                    // marks the pair present.
                    let pub_path = keys_dir.join(format!("{}.pub", slot.key_id));
                    write_pem_ec_public(&pub_path, pk.as_bytes()).map_err(|e| {
                        HsmError::KeystoreError(format!("generate {} pub: {e}", slot.key_id,))
                    })?;
                    write_pem_ec_private(&priv_path, &scalar).map_err(|e| {
                        HsmError::KeystoreError(format!("generate {} priv: {e}", slot.key_id,))
                    })?;
                    tracing::info!(key_id = %slot.key_id, "generated EC-P256 keypair locally");
                }
                KEY_TYPE_AES_256 => {
                    let path = keys_dir.join(format!("{}.bin", slot.key_id));
                    if path.exists() {
                        continue;
                    }
                    let mut bytes = vec![0u8; 32];
                    use rand::RngCore;
                    rand::rngs::OsRng.fill_bytes(&mut bytes);
                    write_atomic(&path, &bytes, false).map_err(|e| {
                        HsmError::KeystoreError(format!("write generated {}: {e}", path.display(),))
                    })?;
                    tracing::info!(key_id = %slot.key_id, "generated AES-256 key locally");
                }
                other => {
                    tracing::warn!(
                        key_id = %slot.key_id,
                        key_kind = other,
                        "unknown key_kind; cannot generate locally",
                    );
                }
            }
        }
        Ok(())
    }

    /// No-op stub when the `crypto` feature is off. Callers in
    /// non-crypto builds (trait-surface-only consumers) don't have
    /// a working HSM anyway; the build still has to compile.
    #[cfg(not(feature = "crypto"))]
    fn generate_missing_local_keys(&self, _ks: &HsmKeystore) -> Result<(), HsmError> {
        Ok(())
    }

    /// Generate the vhsm-test-ssd manifest file.
    ///
    /// Format: `key_id type key_path cert_path [allowed_guests=...] [allowed_ops=...]`
    fn write_manifest(&self, slots: &[KeySlot]) -> Result<(), HsmError> {
        let mut f = Vec::new();

        for slot in slots {
            let type_str = match slot.key_kind {
                KEY_TYPE_EC_P256 => "EC-P256",
                KEY_TYPE_AES_256 => "AES-256",
                _ => continue,
            };

            let key_path = match slot.key_kind {
                KEY_TYPE_EC_P256 => format!("keys/{}.priv", slot.key_id),
                KEY_TYPE_AES_256 => format!("keys/{}.bin", slot.key_id),
                _ => continue,
            };

            // Cert path: check whether a {key_id}.cert file landed
            // on disk via the CSR-issuance flow (v2 envelope never
            // ships certs). `-` if none.
            let cert_disk_path = self.keys_dir().join(format!("{}.cert", slot.key_id));
            let cert_path = if cert_disk_path.exists() {
                format!("keys/{}.cert", slot.key_id)
            } else {
                "-".to_string()
            };

            write!(f, "{} {} {} {}", slot.key_id, type_str, key_path, cert_path)
                .map_err(|e| HsmError::KeystoreError(format!("write manifest: {e}")))?;

            if let Some(ref guests) = slot.allowed_guests {
                write!(f, " allowed_guests={}", guests.join(","))
                    .map_err(|e| HsmError::KeystoreError(format!("write manifest: {e}")))?;
            }

            if let Some(ops) = slot.ops_as_strings() {
                write!(f, " allowed_ops={}", ops.join(","))
                    .map_err(|e| HsmError::KeystoreError(format!("write manifest: {e}")))?;
            }

            writeln!(f).map_err(|e| HsmError::KeystoreError(format!("write manifest: {e}")))?;
        }

        write_atomic(&self.manifest_path(), &f, false)
            .map_err(|e| HsmError::KeystoreError(format!("write manifest: {e}")))
    }

    /// Write the identities file for guest registration.
    fn write_identities(&self, ks: &HsmKeystore) -> Result<(), HsmError> {
        let path = self.keystore_path.join("identities");
        let mut f = Vec::new();

        for id in &ks.identities {
            // Write identity public key as PEM file
            let pub_path = self.keys_dir().join(format!("{}.pub", id.identity_id));
            write_pem_ec_public(&pub_path, &id.public_key)?;

            writeln!(f, "{} keys/{}.pub", id.identity_id, id.identity_id)
                .map_err(|e| HsmError::KeystoreError(format!("write identities: {e}")))?;
        }

        write_atomic(&path, &f, false)
            .map_err(|e| HsmError::KeystoreError(format!("write identities: {e}")))
    }

    /// Parse the manifest file to extract key-slot information.
    pub(crate) fn parse_manifest(&self) -> Result<Vec<SlotInfo>, HsmError> {
        let manifest = std::fs::read_to_string(self.manifest_path())
            .map_err(|e| HsmError::KeystoreError(format!("read manifest: {e}")))?;

        let mut keys = Vec::new();
        for line in manifest.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }
            let key_type = match parts[1] {
                "EC-P256" => KeyType::EcP256,
                "AES-256" => KeyType::Aes256,
                other => {
                    tracing::warn!(key_type = other, "unknown key type in manifest, skipping");
                    continue;
                }
            };
            let has_certificate = parts[3] != "-";

            // Parse optional ACL fields (index 4+)
            let mut allowed_guests = None;
            let mut allowed_ops = None;
            for part in parts.iter().skip(4) {
                if let Some(guests) = part.strip_prefix("allowed_guests=") {
                    allowed_guests = Some(guests.split(',').map(|s| s.to_string()).collect());
                } else if let Some(ops) = part.strip_prefix("allowed_ops=") {
                    allowed_ops = Some(ops.split(',').map(|s| s.to_string()).collect());
                }
            }

            let key_id = parts[0].to_string();
            let handle = vhsm_proto::handle_for_key_id(&key_id)
                .map(KeyHandle)
                .unwrap_or(KeyHandle(vhsm_proto::HANDLE_INVALID));
            keys.push(SlotInfo {
                handle,
                key_id,
                kind: SlotKind::Key(key_type),
                has_certificate,
                allowed_guests,
                allowed_ops,
            });
        }
        Ok(keys)
    }

    /// List the device-generated keys present on disk — the pre-provision path
    /// where no manifest exists yet. EC keys appear as `{id}.priv`, AES as
    /// `{id}.bin`; trust anchors (`.pub`-only) don't exist until provisioning.
    /// No ACL metadata (the manifest carries that), so `allowed_*` are `None`.
    fn list_device_keys_from_disk(&self) -> Result<Vec<SlotInfo>, HsmError> {
        let keys_dir = self.keys_dir();
        let mut keys = Vec::new();
        let entries = match std::fs::read_dir(&keys_dir) {
            Ok(e) => e,
            Err(_) => return Ok(keys), // no keys dir yet → empty inventory
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let (key_id, key_type) = if let Some(id) = name.strip_suffix(".priv") {
                (id.to_string(), KeyType::EcP256)
            } else if let Some(id) = name.strip_suffix(".bin") {
                (id.to_string(), KeyType::Aes256)
            } else {
                continue;
            };
            let has_certificate = keys_dir.join(format!("{key_id}.cert")).exists();
            let handle = vhsm_proto::handle_for_key_id(&key_id)
                .map(KeyHandle)
                .unwrap_or(KeyHandle(vhsm_proto::HANDLE_INVALID));
            keys.push(SlotInfo {
                handle,
                key_id,
                kind: SlotKind::Key(key_type),
                has_certificate,
                allowed_guests: None,
                allowed_ops: None,
            });
        }
        keys.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        Ok(keys)
    }

    /// Extract the CBOR payload from a SUIT envelope.
    ///
    /// All envelopes are encrypted to the device decryption key (slot 2).
    /// Signature is verified against the provisioning authority (factory signing
    /// key on first provision, key authority from HSM on subsequent ones).
    #[cfg(feature = "suit")]
    fn extract_payload(
        &self,
        envelope_bytes: &[u8],
        is_factory: bool,
    ) -> Result<(Vec<u8>, u64), HsmError> {
        use sumo_crypto::RustCryptoBackend;
        use sumo_onboard::decryptor::StreamingDecryptor;
        use sumo_onboard::validator::Validator;

        let crypto = RustCryptoBackend::new();

        // Select trust anchor: factory signing key for first provision,
        // key authority from HSM for subsequent ones.
        let trust_anchor = if is_factory {
            Self::factory_provisioning_authority()
        } else {
            self.get_public_key(KeyRole::KeyAuthority)
                .unwrap_or_else(|_| Self::factory_provisioning_authority())
        };

        let mut validator = Validator::new(&trust_anchor, None);
        if !is_factory {
            let current_sv = self.load_security_version()?;
            validator.set_min_sequence(current_sv);
        }

        let manifest = validator
            .validate_envelope(envelope_bytes, &crypto, 0)
            .map_err(|e| HsmError::EnvelopeInvalid(format!("{e:?}")))?;

        // Verify component ID is ["hsm", "keys"]
        if let Some(cid) = manifest.component_id(0) {
            if cid.len() != 2 || cid[0].as_slice() != b"hsm" || cid[1].as_slice() != b"keys" {
                return Err(HsmError::EnvelopeInvalid(
                    "unexpected component_id (expected [\"hsm\", \"keys\"])".into(),
                ));
            }
        }

        let security_version = manifest.security_version(0).unwrap_or(0);

        // Anti-rollback check for re-provision
        if !is_factory {
            let current = self.load_security_version()?;
            if security_version <= current {
                return Err(HsmError::RollbackRejected {
                    current,
                    attempted: security_version,
                });
            }
        }

        // Decrypt with device key (slot 2) — always the same key
        let device_key = self.load_device_decrypt_key()?;

        let ciphertext = manifest.integrated_payload("#hsm-keys").ok_or_else(|| {
            HsmError::EnvelopeInvalid("missing integrated payload #hsm-keys".into())
        })?;

        // Internal SimHsm flow: extracting the bootstrap device key
        // here is fine because we own the keystore on disk and the
        // file IS the key. Outside callers (component-mgr, the host) must
        // use the operation-based unwrap_cek_*() trait methods.
        let unwrap = sumo_onboard::decryptor::InMemoryKeyUnwrap::new(&device_key, &crypto);
        let mut decryptor = StreamingDecryptor::new(&manifest, 0, &unwrap, &crypto)
            .map_err(|e| HsmError::DecryptionFailed(format!("{e:?}")))?;

        let mut plaintext = vec![0u8; ciphertext.len() + 256];
        let mut total = 0;
        let n = decryptor
            .update(ciphertext, &mut plaintext)
            .map_err(|e| HsmError::DecryptionFailed(format!("update: {e:?}")))?;
        total += n;
        let n = decryptor
            .finalize(&mut plaintext[total..])
            .map_err(|e| HsmError::DecryptionFailed(format!("finalize: {e:?}")))?;
        total += n;
        plaintext.truncate(total);

        // Decompress if zstd-compressed (detect magic bytes)
        let payload = if plaintext.len() >= 4 && plaintext[..4] == [0x28, 0xB5, 0x2F, 0xFD] {
            decompress_zstd(&plaintext)?
        } else {
            plaintext
        };

        Ok((payload, security_version))
    }

    /// Load the device decryption private key as a coset::CoseKey (ECDH).
    #[cfg(feature = "suit")]
    fn load_device_decrypt_key(&self) -> Result<coset::CoseKey, HsmError> {
        let priv_path = self.keys_dir().join("device-decrypt.priv");
        let pem = std::fs::read_to_string(&priv_path)
            .map_err(|e| HsmError::KeystoreError(format!("read device key: {e}")))?;
        let scalar = extract_ec_scalar_from_pem(&pem)?;

        let pub_path = self.keys_dir().join("device-decrypt.pub");
        let pub_pem = std::fs::read_to_string(&pub_path)
            .map_err(|e| HsmError::KeystoreError(format!("read device pubkey: {e}")))?;
        let (x, y) = extract_ec_public_from_pem(&pub_pem)?;

        let mut key = coset::CoseKeyBuilder::new_ec2_priv_key(
            coset::iana::EllipticCurve::P_256,
            x.to_vec(),
            y.to_vec(),
            scalar.to_vec(),
        )
        .build();
        key.alg = None;
        Ok(key)
    }

    /// Fallback for builds without SUIT support — just parse raw CBOR.
    #[cfg(not(feature = "suit"))]
    fn extract_payload(
        &self,
        envelope_bytes: &[u8],
        _is_factory: bool,
    ) -> Result<(Vec<u8>, u64), HsmError> {
        let ks = payload::decode(envelope_bytes).map_err(|e| HsmError::PayloadInvalid(e))?;
        let sv = ks.security_version;
        Ok((envelope_bytes.to_vec(), sv))
    }
}

impl HsmProvider for SimHsm {
    fn is_provisioned(&self) -> Result<bool, HsmError> {
        Ok(self.manifest_path().exists())
    }

    fn provision(&mut self, suit_envelope: &[u8]) -> Result<(), HsmError> {
        let is_factory = !self.is_provisioned()?;

        // Extract and validate the CBOR payload from the SUIT envelope
        let (cbor_payload, _security_version) = self.extract_payload(suit_envelope, is_factory)?;

        // Parse the key material
        let keystore = payload::decode(&cbor_payload).map_err(HsmError::PayloadInvalid)?;

        tracing::info!(
            slots = keystore.slots.len(),
            identities = keystore.identities.len(),
            security_version = keystore.security_version,
            factory = is_factory,
            "provisioning HSM keystore"
        );

        // Every delivered leaf must certify the key this device holds for its
        // slot; one that does not refuses the whole envelope, before anything
        // is written.
        #[cfg(feature = "crypto")]
        self.check_leaf_certs(&keystore.certificates)?;

        // Re-provision: build the new keystore beside the live one, starting
        // from everything the envelope does not own (the device's keys, its
        // counters, bootstrap.yaml, ...), then swap it in. See
        // `recover_interrupted_reprovision` for the swap's crash states.
        if !is_factory {
            let live = self.keystore_path.clone();
            let backup = live.with_extension("bak");
            let staging = self.stage_reprovision(&keystore)?;

            // The swap. The second rename is the commit point.
            std::fs::rename(&live, &backup)
                .map_err(|e| HsmError::KeystoreError(format!("backup old keystore: {e}")))?;
            if let Err(e) = std::fs::rename(&staging, &live) {
                let _ = std::fs::rename(&backup, &live);
                return Err(HsmError::KeystoreError(format!("swap keystore: {e}")));
            }
            if let Some(parent) = live.parent() {
                sync_dir(parent);
            }
            let _ = std::fs::remove_dir_all(&backup);
        } else {
            self.write_keystore(&keystore)?;
        }

        tracing::info!("HSM keystore provisioned");
        Ok(())
    }

    /// Arm an in-band ENROLL_ASSISTED for `vm_id` by editing the
    /// bootstrap state file shared with vhsm-ssd. The daemon picks
    /// up the new entry via its reload-on-miss path; no daemon
    /// restart needed.
    ///
    /// Implementation: read-modify-write of `<keystore>/bootstrap.yaml`
    /// with atomic tmp+rename. The YAML schema is mirrored from
    /// `vhsm-ssd::bootstrap::BootstrapState` — duplicated here to
    /// avoid the cycle (vhsm-ssd already depends on hsm).
    fn arm_enrollment(&mut self, vm_id: &str, ttl_secs: Option<u64>) -> Result<(), HsmError> {
        let path = self.keystore_path.join("bootstrap.yaml");
        let armed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Load existing state (or empty if missing).
        let mut doc: serde_yaml::Value = if path.exists() {
            let raw = std::fs::read_to_string(&path)
                .map_err(|e| HsmError::ProcessError(format!("read {}: {e}", path.display())))?;
            serde_yaml::from_str(&raw)
                .map_err(|e| HsmError::ProcessError(format!("parse {}: {e}", path.display())))?
        } else {
            serde_yaml::Value::Mapping(Default::default())
        };

        let map = doc.as_mapping_mut().ok_or_else(|| {
            HsmError::ProcessError(format!("{} root is not a mapping", path.display()))
        })?;

        // Ensure `tokens:` exists (mirrors what vhsm-ssd writes via save()).
        map.entry(serde_yaml::Value::from("tokens"))
            .or_insert_with(|| serde_yaml::Value::Mapping(Default::default()));

        // Upsert pending[vm_id] = { armed_at, ttl_secs? }.
        let pending_v = map
            .entry(serde_yaml::Value::from("pending"))
            .or_insert_with(|| serde_yaml::Value::Mapping(Default::default()));
        let pending = pending_v.as_mapping_mut().ok_or_else(|| {
            HsmError::ProcessError(format!("{} `pending` is not a mapping", path.display()))
        })?;
        let mut entry = serde_yaml::Mapping::new();
        entry.insert(
            serde_yaml::Value::from("armed_at"),
            serde_yaml::Value::from(armed_at),
        );
        if let Some(ttl) = ttl_secs {
            entry.insert(
                serde_yaml::Value::from("ttl_secs"),
                serde_yaml::Value::from(ttl),
            );
        }
        pending.insert(
            serde_yaml::Value::from(vm_id),
            serde_yaml::Value::Mapping(entry),
        );

        // Atomic write.
        let yaml = serde_yaml::to_string(&doc)
            .map_err(|e| HsmError::ProcessError(format!("serialise bootstrap.yaml: {e}")))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| HsmError::ProcessError(format!("mkdir {}: {e}", parent.display())))?;
        }
        write_atomic(&path, yaml.as_bytes(), false)
            .map_err(|e| HsmError::ProcessError(format!("write {}: {e}", path.display())))?;

        tracing::info!(
            vm_id = %vm_id,
            ttl_secs,
            path = %path.display(),
            "armed ENROLL_ASSISTED for vm_id (vhsm-ssd picks up via reload-on-miss)"
        );
        Ok(())
    }

    fn is_enrolled(&self, vm_id: &str) -> Result<bool, HsmError> {
        let path = self.keystore_path.join("bootstrap.yaml");
        if !path.exists() {
            return Ok(false);
        }
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| HsmError::ProcessError(format!("read {}: {e}", path.display())))?;
        let doc: serde_yaml::Value = serde_yaml::from_str(&raw)
            .map_err(|e| HsmError::ProcessError(format!("parse {}: {e}", path.display())))?;
        Ok(doc["enrolled"]
            .as_mapping()
            .map(|m| m.contains_key(serde_yaml::Value::from(vm_id)))
            .unwrap_or(false))
    }

    fn clear_enrolled(&mut self, vm_id: &str) -> Result<bool, HsmError> {
        let path = self.keystore_path.join("bootstrap.yaml");
        if !path.exists() {
            return Ok(false);
        }
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| HsmError::ProcessError(format!("read {}: {e}", path.display())))?;
        let mut doc: serde_yaml::Value = serde_yaml::from_str(&raw)
            .map_err(|e| HsmError::ProcessError(format!("parse {}: {e}", path.display())))?;
        let removed = doc
            .as_mapping_mut()
            .and_then(|m| m.get_mut(serde_yaml::Value::from("enrolled")))
            .and_then(|v| v.as_mapping_mut())
            .map(|m| m.remove(serde_yaml::Value::from(vm_id)).is_some())
            .unwrap_or(false);
        if removed {
            let yaml = serde_yaml::to_string(&doc)
                .map_err(|e| HsmError::ProcessError(format!("serialise: {e}")))?;
            write_atomic(&path, yaml.as_bytes(), false)
                .map_err(|e| HsmError::ProcessError(format!("write {}: {e}", path.display())))?;
            tracing::info!(vm_id, "cleared enrolled record");
        }
        Ok(removed)
    }

    fn list_slots(&self) -> Result<Vec<SlotInfo>, HsmError> {
        let mut slots = if self.is_provisioned()? {
            self.parse_manifest()?
        } else {
            // Pre-provision there is no manifest, but the device-generated keys
            // exist on disk (ensure_device_keys at first boot). List them so the
            // slot inventory is available whether or not the device is provisioned
            // — the caller reports the provisioning state separately.
            self.list_device_keys_from_disk()?
        };

        // The named monotonic-counter slot (time-floor) is a STRUCTURAL slot that
        // exists from first boot, exactly like a device-generated key. Surface it
        // in the inventory alongside the keys — mirroring the C reference's
        // always-present slot map. Inventory is STRUCTURE, not state: report the
        // slot (handle + kind), never its counter VALUE.
        let floor = KeyHandle(vhsm_proto::HANDLE_TIME_FLOOR);
        let floor_key_id = vhsm_proto::slot_for_handle(floor.get())
            .map(|s| s.key_id.to_string())
            .unwrap_or_else(|| "time-floor".to_string());
        slots.push(SlotInfo {
            handle: floor,
            key_id: floor_key_id,
            kind: SlotKind::Monotonic,
            has_certificate: false,
            allowed_guests: None,
            allowed_ops: None,
        });

        Ok(slots)
    }

    fn get_public_key(&self, role: KeyRole) -> Result<Vec<u8>, HsmError> {
        if !self.is_provisioned()? {
            return Err(HsmError::NotProvisioned);
        }
        let pub_path = self.keys_dir().join(format!("{}.pub", role.key_id()));
        if !pub_path.exists() {
            return Err(HsmError::KeystoreError(format!(
                "no public key for role {:?} at {}",
                role,
                pub_path.display()
            )));
        }
        let pem = std::fs::read_to_string(&pub_path)
            .map_err(|e| HsmError::KeystoreError(format!("read {}: {e}", pub_path.display())))?;
        let (x, y) = extract_ec_public_from_pem(&pem)?;

        // Signing / verification keys carry alg=ES256 so consumers
        // know to use ECDSA-SHA256. The decrypt key is ECDH-only and
        // has no COSE algorithm tag.
        let alg = match role {
            KeyRole::KeyAuthority
            | KeyRole::SoftwareAuthority
            | KeyRole::IamSigning
            | KeyRole::IvdSigning
            | KeyRole::JwtSigning
            | KeyRole::OperationalIssuer
            | KeyRole::FactoryResetIssuer
            | KeyRole::TlsIdentity => Some(coset::iana::Algorithm::ES256),
            KeyRole::DeviceDecryption => None,
            // AES-256 — symmetric, no public COSE key (the pub_path read
            // above already rejects a get_public_key on this slot).
            KeyRole::Storage => None,
        };
        Ok(build_public_cose_key_with_alg(&x, &y, alg))
    }

    // get_private_key removed from the trait — even SimHsm doesn't
    // expose its keystore files as bytes. Sign / unwrap_cek go through
    // operation-based methods so production HSE works the same way.

    fn provisioning_state(&self) -> Result<ProvisioningState, HsmError> {
        if self.manifest_path().exists() {
            Ok(ProvisioningState::Provisioned)
        } else {
            Ok(ProvisioningState::Unprovisioned)
        }
    }

    fn read_monotonic(&self, handle: KeyHandle) -> Result<u64, HsmError> {
        self.read_monotonic_at(handle.get())
    }

    fn raise_monotonic(&mut self, handle: KeyHandle, new_value: u64) -> Result<u64, HsmError> {
        self.ratchet_monotonic(handle.get(), new_value)
    }

    /// Every slot the sim holds is software: its keys are files, and so is its
    /// counter.
    #[cfg(feature = "crypto")]
    fn slot_backing(&self, handle: KeyHandle) -> Result<SlotBacking, HsmError> {
        use hsm::HsmCryptoProvider;
        self.get_slot_info(handle).map(|_| SlotBacking::Software)
    }
}

// --- Zstd decompression ---

/// Decompress a zstd-compressed payload.
#[cfg(feature = "suit")]
fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>, HsmError> {
    use sumo_onboard::decompressor::StreamingDecompressor;

    let mut dec = StreamingDecompressor::new()
        .map_err(|e| HsmError::PayloadInvalid(format!("zstd init: {e:?}")))?;

    let mut sink = vec![0u8; 0]; // not used by update (it accumulates internally)
    dec.update(data, &mut sink)
        .map_err(|e| HsmError::PayloadInvalid(format!("zstd update: {e:?}")))?;

    dec.finalize_to_vec()
        .map_err(|e| HsmError::PayloadInvalid(format!("zstd finalize: {e:?}")))
}

// --- PEM decoding helpers ---

/// Extract the raw 32-byte EC-P256 scalar from a SEC1 PEM private key.
pub(crate) fn extract_ec_scalar_from_pem(pem: &str) -> Result<Vec<u8>, HsmError> {
    let der = decode_pem(pem, "EC PRIVATE KEY")?;

    // SEC1 ECPrivateKey: SEQUENCE { INTEGER(1), OCTET STRING(scalar), ... }
    // Skip: 0x30 len 0x02 0x01 0x01 0x04 0x20 → scalar at offset 7
    if der.len() < 39 || der[0] != 0x30 || der[5] != 0x04 || der[6] != 0x20 {
        return Err(HsmError::KeystoreError(
            "unexpected SEC1 ECPrivateKey format".into(),
        ));
    }
    Ok(der[7..39].to_vec())
}

/// Extract (x, y) coordinates from a SubjectPublicKeyInfo PEM public key.
/// Returns (32-byte x, 32-byte y).
pub(crate) fn extract_ec_public_from_pem(pem: &str) -> Result<(Vec<u8>, Vec<u8>), HsmError> {
    let der = decode_pem(pem, "PUBLIC KEY")?;

    // SPKI: SEQUENCE { SEQUENCE { OID, OID }, BIT STRING { 0x00, 0x04, x, y } }
    // The uncompressed point (0x04 || x || y) is at the end of the DER.
    // Find it by scanning for the BIT STRING content.
    if der.len() < 91 {
        return Err(HsmError::KeystoreError(
            "SPKI too short for EC P-256".into(),
        ));
    }

    // The uncompressed point starts at offset 26 (after AlgId + BIT STRING header + 0x00 pad)
    // 0x30 0x59 | 0x30 0x13 ... (19 bytes algid) | 0x03 0x42 0x00 0x04 x(32) y(32)
    let point_start = der.len() - 65;
    if der[point_start] != 0x04 {
        return Err(HsmError::KeystoreError(
            "expected uncompressed EC point (0x04 prefix)".into(),
        ));
    }

    let x = der[point_start + 1..point_start + 33].to_vec();
    let y = der[point_start + 33..point_start + 65].to_vec();
    Ok((x, y))
}

/// Decode a PEM block with the given label, returning raw DER bytes.
pub(crate) fn decode_pem(pem: &str, expected_label: &str) -> Result<Vec<u8>, HsmError> {
    let begin = format!("-----BEGIN {expected_label}-----");
    let end = format!("-----END {expected_label}-----");

    let start = pem
        .find(&begin)
        .ok_or_else(|| HsmError::KeystoreError(format!("missing PEM header: {begin}")))?;
    let after_header = start + begin.len();

    let end_pos = pem[after_header..]
        .find(&end)
        .ok_or_else(|| HsmError::KeystoreError(format!("missing PEM footer: {end}")))?;

    let b64: String = pem[after_header..after_header + end_pos]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    base64_decode(&b64).map_err(|e| HsmError::KeystoreError(format!("base64 decode: {e}")))
}

/// Simple base64 decoder.
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    const DECODE: [u8; 128] = {
        let mut t = [0xFFu8; 128];
        let mut i = 0u8;
        while i < 26 {
            t[(b'A' + i) as usize] = i;
            t[(b'a' + i) as usize] = i + 26;
            i += 1;
        }
        let mut d = 0u8;
        while d < 10 {
            t[(b'0' + d) as usize] = d + 52;
            d += 1;
        }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t
    };

    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;

    for &b in bytes {
        if b == b'=' {
            break;
        }
        if b >= 128 || DECODE[b as usize] == 0xFF {
            return Err(format!("invalid base64 char: {}", b as char));
        }
        buf = (buf << 6) | DECODE[b as usize] as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

// --- PEM encoding helpers ---
//
// vhsm-test-ssd reads PEM files via OpenSSL. We convert raw key bytes
// from the CBOR payload into PEM format on disk.

/// Write an EC P-256 private key as PEM (SEC1 / RFC 5915).
///
/// The raw 32-byte scalar is wrapped in the ASN.1 ECPrivateKey structure
/// with the P-256 OID, then base64-encoded as PEM.
pub(crate) fn write_pem_ec_private(path: &Path, scalar: &[u8]) -> Result<(), HsmError> {
    if scalar.len() != 32 {
        return Err(HsmError::PayloadInvalid(format!(
            "EC private key must be 32 bytes, got {}",
            scalar.len()
        )));
    }

    // ASN.1 ECPrivateKey (SEC1):
    //   SEQUENCE {
    //     INTEGER 1 (version)
    //     OCTET STRING (32 bytes, private key)
    //     [0] OID 1.2.840.10045.3.1.7 (P-256)
    //   }
    let mut der = Vec::with_capacity(48 + 32);
    // SEQUENCE tag + length (will patch)
    der.push(0x30);
    der.push(0x00); // placeholder

    // version = 1
    der.extend_from_slice(&[0x02, 0x01, 0x01]);

    // privateKey OCTET STRING
    der.push(0x04);
    der.push(0x20); // 32 bytes
    der.extend_from_slice(scalar);

    // parameters [0] EXPLICIT OID
    der.extend_from_slice(&[
        0xA0, 0x0A, // context [0], length 10
        0x06, 0x08, // OID, length 8
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // P-256
    ]);

    // Patch sequence length
    let seq_len = der.len() - 2;
    der[1] = seq_len as u8;

    write_pem_file(path, "EC PRIVATE KEY", &der)
}

/// Write an EC P-256 public key as PEM (SubjectPublicKeyInfo).
pub(crate) fn write_pem_ec_public(path: &Path, uncompressed: &[u8]) -> Result<(), HsmError> {
    if uncompressed.len() != 65 || uncompressed[0] != 0x04 {
        return Err(HsmError::PayloadInvalid(format!(
            "EC public key must be 65 bytes (uncompressed), got {}",
            uncompressed.len()
        )));
    }

    // SubjectPublicKeyInfo:
    //   SEQUENCE {
    //     SEQUENCE {
    //       OID 1.2.840.10045.2.1 (ecPublicKey)
    //       OID 1.2.840.10045.3.1.7 (P-256)
    //     }
    //     BIT STRING (0x00 prefix + 65 bytes)
    //   }
    let mut der = Vec::with_capacity(91);
    der.push(0x30); // outer SEQUENCE
    der.push(0x59); // 89 bytes

    // AlgorithmIdentifier SEQUENCE
    der.extend_from_slice(&[
        0x30, 0x13, // SEQUENCE, 19 bytes
        0x06, 0x07, // OID, 7 bytes
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // ecPublicKey
        0x06, 0x08, // OID, 8 bytes
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // P-256
    ]);

    // BIT STRING
    der.push(0x03);
    der.push(0x42); // 66 bytes (1 padding byte + 65 key bytes)
    der.push(0x00); // no unused bits
    der.extend_from_slice(uncompressed);

    write_pem_file(path, "PUBLIC KEY", &der)
}

/// Write a DER-encoded X.509 certificate as PEM at `{key_id}.cert`.
/// Driven by the v3 keystore `certificates` list (`write_leaf_certs`):
/// the CA-issued leaf for a device-generated identity key, landed
/// alongside the key it certifies. `get_certificate_der` reads it back.
fn write_pem_certificate(path: &Path, der: &[u8]) -> Result<(), HsmError> {
    write_pem_file(path, "CERTIFICATE", der)
}

/// Parse a DER X.509 cert and return its `notBefore` as seconds since the epoch,
/// or `None` if it doesn't parse. Used to seed the monotonic counter from a
/// just-installed, CA-signed identity leaf (`write_leaf_certs`).
#[cfg(feature = "crypto")]
fn leaf_not_before_secs(der: &[u8]) -> Option<u64> {
    use x509_cert::der::Decode;
    let cert = x509_cert::Certificate::from_der(der).ok()?;
    Some(
        cert.tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs(),
    )
}

/// Base64-encode DER data and write as PEM with the given label.
fn write_pem_file(path: &Path, label: &str, der: &[u8]) -> Result<(), HsmError> {
    use std::fmt::Write as FmtWrite;

    let b64 = base64_encode(der);
    let mut pem = String::new();
    writeln!(pem, "-----BEGIN {label}-----").unwrap();
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    writeln!(pem, "-----END {label}-----").unwrap();

    // Private key material → owner-only (0600). Public keys / certs stay readable.
    write_atomic(path, pem.as_bytes(), label.contains("PRIVATE"))
        .map_err(|e| HsmError::KeystoreError(format!("write {}: {e}", path.display())))
}

/// Replace `path` with `data` so that a crash leaves either the old content or
/// the new, never a torn file: write a sibling `{name}.tmp`, fsync it, rename it
/// over `path`, fsync the directory. `private` restricts the file to 0600
/// (`restrict_file_600`) before it becomes visible under `path`; otherwise it
/// keeps the mode a plain create gives it.
pub(crate) fn write_atomic(path: &Path, data: &[u8], private: bool) -> std::io::Result<()> {
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    {
        let mut f = std::fs::File::create(&tmp)?;
        if private {
            restrict_file_600(&tmp);
        }
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        sync_dir(dir);
    }
    Ok(())
}

/// Report a device-generated key that `ensure_device_keys` had to create in an
/// established keystore: the device's identity or attestation for `role` is now
/// a different key, and whatever trusted the old one stops verifying.
#[cfg(feature = "crypto")]
fn log_device_key_replaced(role: KeyRole) {
    let breaks = match role {
        KeyRole::DeviceDecryption => {
            "the ECU id (the digest of this key) changed and envelopes encrypted to the old key can no longer be decrypted"
        }
        KeyRole::IvdSigning => {
            "existing bank IVD manifests and the boot selector, signed with the old key, no longer verify"
        }
        KeyRole::TlsIdentity => "the installed TLS leaf certificate no longer matches the key",
        KeyRole::Storage => "data encrypted under the old storage key can no longer be decrypted",
        _ => "anything signed with the old key no longer verifies",
    };
    tracing::error!(
        key_id = %role.key_id(),
        "device key {} was missing from a keystore that is provisioned or holds other device keys, \
         and has been created anew: the device's identity/attestation for this role changed; {breaks}",
        role.key_id(),
    );
}

/// Where [`carry_over`] is in the keystore tree; what a re-provision owns
/// differs per level.
#[derive(Clone, Copy)]
enum CarryLevel {
    Root,
    Keys,
    Other,
}

/// Create `to` and copy into it everything under the live keystore `from` that
/// a re-provision does not rewrite from its envelope, keeping every directory's
/// and file's mode. Per file kind:
///
/// | file | on re-provision |
/// |---|---|
/// | `manifest`, `identities`, `provision_state` | rewritten from the envelope |
/// | `keys/roots/{anchor_id}.cert` (pinned CA roots) | rewritten; a root the envelope no longer carries is gone |
/// | `keys/{id}.pub` without `keys/{id}.priv` (trust-anchor slot, guest identity) | rewritten; gone if the envelope no longer carries it |
/// | device keys: `keys/{id}.priv` + `.pub`, `.bin`, `.aes128.bin`, `.hmac256.bin`, `.ed25519.priv` + `.ed25519.pub` | carried, never regenerated |
/// | `keys/{id}.cert` beside a carried `keys/{id}.priv` | carried; replaced when the envelope delivers a leaf for that key |
/// | `keys/{id}.cert` without `keys/{id}.priv` | not carried (nothing writes one) |
/// | `monotonic_*`, `bootstrap.yaml`, any other file or directory | carried verbatim |
/// | sockets, FIFOs | not carried: they belong to a running process, not to the keystore |
fn carry_over(from: &Path, to: &Path, level: CarryLevel) -> Result<(), HsmError> {
    let err = |p: &Path, e: std::io::Error| {
        HsmError::KeystoreError(format!("stage keystore {}: {e}", p.display()))
    };
    std::fs::create_dir(to).map_err(|e| err(to, e))?;
    let mode = std::fs::metadata(from).map_err(|e| err(from, e))?;
    std::fs::set_permissions(to, mode.permissions()).map_err(|e| err(to, e))?;
    for entry in std::fs::read_dir(from).map_err(|e| err(from, e))? {
        let entry = entry.map_err(|e| err(from, e))?;
        let name = entry.file_name();
        if envelope_owned(from, &name.to_string_lossy(), level) {
            continue;
        }
        let (src, dst) = (entry.path(), to.join(&name));
        let meta = std::fs::metadata(&src).map_err(|e| err(&src, e))?;
        if meta.is_dir() {
            let next = match level {
                CarryLevel::Root if name == "keys" => CarryLevel::Keys,
                _ => CarryLevel::Other,
            };
            carry_over(&src, &dst, next)?;
        } else if meta.is_file() {
            std::fs::copy(&src, &dst).map_err(|e| err(&src, e))?;
        }
    }
    Ok(())
}

/// Whether `dir/name` is rewritten from the envelope on re-provision (the
/// table on [`carry_over`]).
fn envelope_owned(dir: &Path, name: &str, level: CarryLevel) -> bool {
    match level {
        CarryLevel::Root => matches!(name, "manifest" | "identities" | "provision_state"),
        CarryLevel::Keys => {
            if name == "roots" {
                return true;
            }
            match name
                .strip_suffix(".pub")
                .or_else(|| name.strip_suffix(".cert"))
            {
                Some(stem) => !dir.join(format!("{stem}.priv")).exists(),
                None => false,
            }
        }
        CarryLevel::Other => false,
    }
}

/// fsync every file and directory under `dir`, so a staged keystore is on disk
/// before it is swapped in.
fn sync_tree(dir: &Path) -> Result<(), HsmError> {
    let err = |p: &Path, e: std::io::Error| {
        HsmError::KeystoreError(format!("sync keystore {}: {e}", p.display()))
    };
    for entry in std::fs::read_dir(dir).map_err(|e| err(dir, e))? {
        let entry = entry.map_err(|e| err(dir, e))?;
        let path = entry.path();
        let kind = entry.file_type().map_err(|e| err(&path, e))?;
        if kind.is_dir() {
            sync_tree(&path)?;
        } else if kind.is_file() {
            std::fs::File::open(&path)
                .and_then(|f| f.sync_all())
                .map_err(|e| err(&path, e))?;
        }
    }
    sync_dir(dir);
    Ok(())
}

/// Best-effort fsync of a directory, so the renames in it are durable. Not every
/// filesystem accepts an fsync on a directory handle; the file data itself is
/// already synced by the caller.
fn sync_dir(dir: &Path) {
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
}

/// Best-effort: restrict a keystore directory to the owner (0700) so other local
/// users can't traverse into it to read private key material. The 0700 directory
/// is the primary protection for the file keystore; key files are also set 0600.
#[cfg(unix)]
pub(crate) fn restrict_dir_700(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)) {
        tracing::warn!(path = %path.display(), error = %e, "could not restrict keystore dir to 0700");
    }
}
#[cfg(not(unix))]
pub(crate) fn restrict_dir_700(_path: &Path) {}

/// Best-effort: restrict a freshly-written private-key file to the owner (0600).
#[cfg(unix)]
pub(crate) fn restrict_file_600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        tracing::warn!(path = %path.display(), error = %e, "could not restrict key file to 0600");
    }
}
#[cfg(not(unix))]
pub(crate) fn restrict_file_600(_path: &Path) {}

/// Build a COSE_Key (EC2, P-256, public only) as CBOR bytes.
fn build_public_cose_key_with_alg(
    x: &[u8],
    y: &[u8],
    alg: Option<coset::iana::Algorithm>,
) -> Vec<u8> {
    use coset::CborSerializable;
    let mut builder = coset::CoseKeyBuilder::new_ec2_pub_key(
        coset::iana::EllipticCurve::P_256,
        x.to_vec(),
        y.to_vec(),
    );
    if let Some(a) = alg {
        builder = builder.algorithm(a);
    }
    let mut key = builder.build();
    if alg.is_none() {
        key.alg = None;
    }
    key.to_vec().unwrap()
}

/// Simple base64 encoder (no external dep needed).
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }

        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hsm::payload::*;
    #[cfg(feature = "crypto")]
    use hsm::HsmCryptoProvider;

    /// Sample keystore — every slot enumeration-only. The schema
    /// itself no longer has a `private_key` field, so the keystore
    /// is incapable of carrying private bytes at all.
    fn sample_keystore() -> HsmKeystore {
        HsmKeystore {
            schema_version: SCHEMA_VERSION,
            security_version: 1,
            identities: vec![IdentityDef {
                identity_id: "bali-vm-1".into(),
                public_key: {
                    let mut pk = vec![0x04];
                    pk.extend_from_slice(&[0x11; 32]);
                    pk.extend_from_slice(&[0x22; 32]);
                    pk
                },
            }],
            slots: vec![
                KeySlot {
                    key_id: "jwt-signing".into(),
                    key_kind: KEY_TYPE_EC_P256,
                    anchor_public_key: None,
                    allowed_guests: Some(vec!["bali-vm-1".into()]),
                    allowed_ops: Some(vec![OP_SIGN, OP_VERIFY]),
                },
                KeySlot {
                    key_id: "storage-key".into(),
                    key_kind: KEY_TYPE_AES_256,
                    anchor_public_key: None,
                    allowed_guests: Some(vec!["bali-vm-1".into()]),
                    allowed_ops: Some(vec![OP_ENCRYPT, OP_DECRYPT]),
                },
            ],
            certificates: Vec::new(),
            trust_anchors: Vec::new(),
        }
    }

    // Both provisioning tests below exercise the
    // generate_missing_local_keys pass, which is only present when
    // the `crypto` feature is on (it needs p256 + rand). Gate them
    // accordingly so the trait-only build still runs the rest of the
    // test surface clean.

    #[test]
    #[cfg(feature = "crypto")]
    fn provisions_and_reads_back_a_trust_anchor() {
        use hsm::payload::{TrustAnchorCert, DELEGATION_ROOT_ANCHOR_ID};
        use hsm::HsmCryptoProvider;
        let tmp = std::env::temp_dir().join("hsm-test-trust-anchor");
        let _ = std::fs::remove_dir_all(&tmp);
        let hsm = SimHsm::new(tmp.clone());

        // Stand-in DER (round-trips through the PEM enclosure byte-for-byte).
        let der = vec![0x30u8, 0x82, 0x01, 0x00, 0xAB, 0xCD];
        let mut ks = sample_keystore();
        ks.trust_anchors.push(TrustAnchorCert {
            anchor_id: DELEGATION_ROOT_ANCHOR_ID.into(),
            certificate: der.clone(),
        });
        hsm.write_keystore(&ks).unwrap();

        // Landed as roots/{anchor_id}.cert and reads back byte-identical DER.
        assert!(tmp
            .join(format!("keys/roots/{DELEGATION_ROOT_ANCHOR_ID}.cert"))
            .exists());
        let got = hsm.get_trust_anchor_der(DELEGATION_ROOT_ANCHOR_ID).unwrap();
        assert_eq!(got, der);
        // An unprovisioned anchor id is a clean error (delegation stays OFF).
        assert!(hsm.get_trust_anchor_der("nope").is_err());
    }

    #[test]
    #[cfg(feature = "crypto")]
    fn provision_from_cbor_writes_keystore() {
        let tmp = std::env::temp_dir().join("hsm-test-provision");
        let _ = std::fs::remove_dir_all(&tmp);

        let hsm = SimHsm::new(tmp.clone());

        let ks = sample_keystore();
        let _cbor = payload::encode(&ks).unwrap();

        // Factory provision with raw CBOR (no SUIT feature needed for this test)
        hsm.write_keystore(&ks).unwrap();

        // Manifest still lists every slot — slot enumeration drives
        // the on-disk layout even when private bytes come from
        // generate_missing_local_keys instead of the envelope.
        let manifest = std::fs::read_to_string(tmp.join("manifest")).unwrap();
        assert!(manifest.contains("jwt-signing EC-P256 keys/jwt-signing.priv"));
        assert!(manifest.contains("allowed_guests=bali-vm-1"));
        assert!(manifest.contains("allowed_ops=SIGN,VERIFY"));
        assert!(manifest.contains("storage-key AES-256 keys/storage-key.bin"));
        assert!(manifest.contains("allowed_ops=ENCRYPT,DECRYPT"));

        let identities = std::fs::read_to_string(tmp.join("identities")).unwrap();
        assert!(identities.contains("bali-vm-1 keys/bali-vm-1.pub"));

        // The key files MUST exist — generated locally by
        // generate_missing_local_keys since the envelope had no
        // private bytes.
        assert!(tmp.join("keys/jwt-signing.priv").exists());
        assert!(tmp.join("keys/jwt-signing.pub").exists());
        assert!(tmp.join("keys/storage-key.bin").exists());
        assert!(tmp.join("keys/bali-vm-1.pub").exists());

        // Verify PEM format of locally-generated key.
        let priv_pem = std::fs::read_to_string(tmp.join("keys/jwt-signing.priv")).unwrap();
        assert!(priv_pem.starts_with("-----BEGIN EC PRIVATE KEY-----\n"));
        assert!(priv_pem.ends_with("-----END EC PRIVATE KEY-----\n"));

        let pub_pem = std::fs::read_to_string(tmp.join("keys/jwt-signing.pub")).unwrap();
        assert!(pub_pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));

        // AES key is 32 bytes of OS-CSPRNG output now (not a constant).
        let aes_key = std::fs::read(tmp.join("keys/storage-key.bin")).unwrap();
        assert_eq!(aes_key.len(), 32);
        // Sanity: not all-zero (vanishingly unlikely from CSPRNG).
        assert!(aes_key.iter().any(|&b| b != 0));

        // Provision state recorded.
        let state = std::fs::read_to_string(tmp.join("provision_state")).unwrap();
        assert!(state.starts_with("1"));

        let keys = hsm.list_slots().unwrap();
        // The two provisioned keys, plus the always-present monotonic-counter
        // (time-floor) slot that list_slots appends.
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].key_id, "jwt-signing");
        assert_eq!(keys[0].kind, SlotKind::Key(KeyType::EcP256));
        assert_eq!(keys[1].key_id, "storage-key");
        assert_eq!(keys[1].kind, SlotKind::Key(KeyType::Aes256));
        assert_eq!(keys[2].key_id, "time-floor");
        assert_eq!(keys[2].kind, SlotKind::Monotonic);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    #[cfg(feature = "crypto")]
    fn reprovision_installs_leaf_certificate() {
        let tmp = std::env::temp_dir().join("hsm-test-leaf-cert");
        let _ = std::fs::remove_dir_all(&tmp);
        let hsm = SimHsm::new(tmp.clone());

        // First provision generates the EC key for "jwt-signing"; no cert yet
        // (the leaf can only be issued from the CSR that key emits).
        hsm.write_keystore(&sample_keystore()).unwrap();
        assert!(!tmp.join("keys/jwt-signing.cert").exists());
        assert!(tmp.join("keys/jwt-signing.priv").exists());

        // Re-provision delivering the CA-issued leaf for "jwt-signing" (the v3
        // top-level certificates list). get_certificate_der decodes the
        // PEM body back to DER, so any byte blob round-trips here.
        let leaf_der = vec![0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
        let mut ks2 = sample_keystore();
        ks2.security_version = 2;
        ks2.certificates.push(payload::LeafCert {
            key_id: "jwt-signing".into(),
            certificate: leaf_der.clone(),
        });
        hsm.write_keystore(&ks2).unwrap();

        // The leaf landed on disk, the manifest records its cert_path, and
        // the runtime query returns the exact DER we shipped.
        assert!(tmp.join("keys/jwt-signing.cert").exists());
        let manifest = std::fs::read_to_string(tmp.join("manifest")).unwrap();
        assert!(manifest.contains("keys/jwt-signing.cert"));
        let got =
            hsm::HsmCryptoProvider::get_certificate_der(&hsm, hsm::KeyRole::JwtSigning.handle())
                .unwrap();
        assert_eq!(got, leaf_der);

        // The re-provision kept the original keypair the leaf certifies.
        assert!(tmp.join("keys/jwt-signing.priv").exists());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    #[cfg(feature = "crypto")]
    fn list_slots_lists_device_keys_pre_provision() {
        let tmp = std::env::temp_dir().join("hsm-test-list-preprov");
        let _ = std::fs::remove_dir_all(&tmp);
        let hsm = SimHsm::new(tmp.clone());
        // Device-generated keys exist at first boot, but the device is NOT
        // provisioned (no manifest). list_slots used to error here; now it
        // disk-lists the device keys so the inventory is available either way.
        hsm.ensure_device_keys().unwrap();
        assert!(!hsm.is_provisioned().unwrap(), "not provisioned yet");
        let keys = HsmProvider::list_slots(&hsm).unwrap();
        assert!(
            keys.iter().any(|k| k.key_id == "tls-identity"),
            "tls-identity device key listed pre-provision"
        );
        assert!(keys.iter().any(|k| k.key_id == "device-decrypt"));
        // The monotonic-counter (time-floor) slot is always present, even
        // pre-provision — it is structural, not provisioned key material.
        assert!(
            keys.iter()
                .any(|k| k.key_id == "time-floor" && k.kind == SlotKind::Monotonic),
            "time-floor counter slot listed as Monotonic"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // (The "no-push-private-keys" invariant is now enforced at the
    // schema level: KeySlot has no `private_key` field. Decode-time
    // validation lives in `payload::decode`; on-the-wire rejection
    // tests for v1 envelopes and malformed anchors are in payload.rs.)

    #[test]
    fn security_version_roundtrip() {
        let tmp = std::env::temp_dir().join("hsm-test-secver");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let hsm = SimHsm::new(tmp.clone());

        // No state file → version 0
        assert_eq!(hsm.load_security_version().unwrap(), 0);

        // Save and reload
        hsm.save_state(42).unwrap();
        assert_eq!(hsm.load_security_version().unwrap(), 42);

        let state = std::fs::read_to_string(tmp.join("provision_state")).unwrap();
        assert_eq!(state, "42");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn pem_ec_private_roundtrip() {
        let tmp = std::env::temp_dir().join("hsm-test-pem-priv");
        let scalar = vec![0x42u8; 32];
        write_pem_ec_private(&tmp, &scalar).unwrap();

        let pem = std::fs::read_to_string(&tmp).unwrap();
        let recovered = extract_ec_scalar_from_pem(&pem).unwrap();
        assert_eq!(recovered, scalar);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn pem_ec_public_roundtrip() {
        let tmp = std::env::temp_dir().join("hsm-test-pem-pub");
        let mut uncompressed = vec![0x04];
        uncompressed.extend_from_slice(&[0xAA; 32]); // x
        uncompressed.extend_from_slice(&[0xBB; 32]); // y
        write_pem_ec_public(&tmp, &uncompressed).unwrap();

        let pem = std::fs::read_to_string(&tmp).unwrap();
        let (x, y) = extract_ec_public_from_pem(&pem).unwrap();
        assert_eq!(x, vec![0xAA; 32]);
        assert_eq!(y, vec![0xBB; 32]);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    #[cfg(feature = "crypto")]
    fn ensure_device_keys_bootstraps_all_device_generated_roles() {
        let tmp = std::env::temp_dir().join("hsm-test-ensure-device-keys");
        let _ = std::fs::remove_dir_all(&tmp);

        let hsm = SimHsm::new(tmp.clone());
        hsm.ensure_device_keys().unwrap();

        // Every device-generated role must have a {priv, pub} pair on disk
        // — that's what unblocks IVD self-sign before the provisioning
        // envelope lands. Trust anchors (KeyAuthority, *Authority) stay
        // absent until provisioning supplies their public halves.
        for role in KeyRole::mandatory_roles() {
            // EC slots bootstrap as {priv,pub}; the lone AES slot (storage-key)
            // as {key_id}.bin — check the right material per key type.
            let material = match role.key_type() {
                KeyType::Aes256 => tmp.join("keys").join(format!("{}.bin", role.key_id())),
                _ => tmp.join("keys").join(format!("{}.priv", role.key_id())),
            };
            if role.is_device_generated() {
                assert!(
                    material.exists(),
                    "device-generated role {role:?} key material missing at {}",
                    material.display()
                );
            } else {
                assert!(
                    !material.exists(),
                    "anchor role {role:?} key material must NOT be bootstrapped",
                );
            }
        }

        // get_slot_info MUST resolve ivd-signing via the disk fallback path
        // — that's the chain that lets sign() work pre-provision.
        let info = <SimHsm as HsmCryptoProvider>::get_slot_info(&hsm, KeyRole::IvdSigning.handle())
            .unwrap();
        assert_eq!(info.kind, SlotKind::Key(KeyType::EcP256));

        // sign() with the bootstrap IVD key must succeed without a
        // populated manifest. This is the bootstrap escape for the very
        // first HSM-keys flash: the device must be able to attest its
        // own banks before any envelope is processed.
        let sig = <SimHsm as HsmCryptoProvider>::sign(&hsm, KeyRole::IvdSigning.handle(), b"hello")
            .unwrap();
        assert!(!sig.is_empty(), "signature must be non-empty");

        // Idempotent — calling twice must not regenerate (would invalidate
        // any IVD manifests already signed with the prior key).
        let key_path = tmp.join("keys/ivd-signing.priv");
        let original = std::fs::read(&key_path).unwrap();
        hsm.ensure_device_keys().unwrap();
        let after = std::fs::read(&key_path).unwrap();
        assert_eq!(original, after, "ensure_device_keys must be idempotent");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn base64_roundtrip() {
        for input in &[b"hello world".as_slice(), &[0u8; 32], &[0xFF; 65]] {
            let encoded = base64_encode(input);
            let decoded = base64_decode(&encoded).unwrap();
            assert_eq!(&decoded, input);
        }
    }

    #[test]
    fn base64_encode_basic() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn monotonic_slot_ratchets_per_handle_and_survives_reload() {
        let tmp = tempfile::tempdir().unwrap();
        let keystore = tmp.path().to_path_buf();
        let mut sim = SimHsm::new(keystore.clone());

        // The named time-floor slot is addressed by handle.
        let floor = KeyHandle(vhsm_proto::HANDLE_TIME_FLOOR);

        // Unset slot reads as 0.
        assert_eq!(sim.read_monotonic(floor).unwrap(), 0);

        // First raise sets it.
        assert_eq!(sim.raise_monotonic(floor, 1_000).unwrap(), 1_000);
        assert_eq!(sim.read_monotonic(floor).unwrap(), 1_000);

        // A higher value advances.
        assert_eq!(sim.raise_monotonic(floor, 2_000).unwrap(), 2_000);

        // A lower value is a no-op — never rewinds.
        assert_eq!(sim.raise_monotonic(floor, 1_500).unwrap(), 2_000);
        assert_eq!(sim.raise_monotonic(floor, 0).unwrap(), 2_000);
        assert_eq!(sim.read_monotonic(floor).unwrap(), 2_000);

        // Equal value is a no-op that returns the counter.
        assert_eq!(sim.raise_monotonic(floor, 2_000).unwrap(), 2_000);

        // A DIFFERENT handle is an independent counter (per-slot store): raising
        // it must not disturb the time-floor slot.
        let other = KeyHandle(vhsm_proto::HANDLE_IVD_SIGNING);
        assert_eq!(sim.read_monotonic(other).unwrap(), 0);
        assert_eq!(sim.raise_monotonic(other, 7).unwrap(), 7);
        assert_eq!(sim.read_monotonic(floor).unwrap(), 2_000);

        // Both survive a fresh handle over the same keystore (persisted, not in-mem).
        let reloaded = SimHsm::new(keystore.clone());
        assert_eq!(reloaded.read_monotonic(floor).unwrap(), 2_000);
        assert_eq!(reloaded.read_monotonic(other).unwrap(), 7);
    }

    #[test]
    fn arm_enrollment_writes_pending_to_bootstrap_yaml() {
        // Smoke test: arm a vm_id, parse bootstrap.yaml back, check
        // the pending entry has the right shape vhsm-ssd::BootstrapState
        // expects.
        let tmp = tempfile::tempdir().unwrap();
        let keystore = tmp.path().to_path_buf();
        let mut sim = SimHsm::new(keystore.clone());
        sim.arm_enrollment("vm9", Some(3600)).unwrap();

        let yaml = std::fs::read_to_string(keystore.join("bootstrap.yaml")).unwrap();
        let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let pending = &parsed["pending"]["vm9"];
        assert!(
            pending.is_mapping(),
            "pending entry should be a map; got: {yaml}"
        );
        assert_eq!(pending["ttl_secs"].as_u64(), Some(3600));
        assert!(pending["armed_at"].as_u64().is_some());
    }

    #[test]
    fn arm_enrollment_preserves_existing_tokens() {
        // If an off-box ENROLL flow already populated the `tokens:`
        // map, arming an ENROLL_ASSISTED entry MUST NOT clobber it.
        let tmp = tempfile::tempdir().unwrap();
        let keystore = tmp.path().to_path_buf();
        let path = keystore.join("bootstrap.yaml");
        std::fs::write(
            &path,
            "tokens:\n  vm1:\n    sha256: deadbeef\n    consumed: false\n",
        )
        .unwrap();

        let mut sim = SimHsm::new(keystore.clone());
        sim.arm_enrollment("vm9", None).unwrap();

        let yaml = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        // Both still there.
        assert_eq!(parsed["tokens"]["vm1"]["sha256"], "deadbeef");
        assert!(parsed["pending"]["vm9"].is_mapping());
    }

    #[test]
    fn arm_enrollment_replaces_existing_pending_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let keystore = tmp.path().to_path_buf();
        let mut sim = SimHsm::new(keystore.clone());
        sim.arm_enrollment("vm9", Some(1)).unwrap();
        // Re-arm with a different TTL — entry should be replaced.
        sim.arm_enrollment("vm9", Some(9999)).unwrap();

        let yaml = std::fs::read_to_string(keystore.join("bootstrap.yaml")).unwrap();
        let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed["pending"]["vm9"]["ttl_secs"].as_u64(), Some(9999));
    }

    /// Run `f` and return the events it logged on this thread (level, fields).
    /// One process-wide subscriber records into a per-thread buffer, so tests
    /// running in parallel neither see each other's events nor race on
    /// callsite interest the way a scoped subscriber per test does.
    #[cfg(feature = "crypto")]
    fn capture_logs(f: impl FnOnce()) -> Vec<(tracing::Level, String)> {
        use std::cell::RefCell;
        type Events = Vec<(tracing::Level, String)>;
        thread_local!(static CAPTURED: RefCell<Option<Events>> = const { RefCell::new(None) });
        struct Capture;
        struct Fields<'a>(&'a mut String);
        impl tracing::field::Visit for Fields<'_> {
            fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                self.0.push_str(&format!("{}={v:?} ", f.name()));
            }
        }
        impl tracing::Subscriber for Capture {
            fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }
            fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
            fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
            fn event(&self, event: &tracing::Event<'_>) {
                CAPTURED.with(|c| {
                    if let Some(events) = c.borrow_mut().as_mut() {
                        let mut fields = String::new();
                        event.record(&mut Fields(&mut fields));
                        events.push((*event.metadata().level(), fields));
                    }
                });
            }
            fn enter(&self, _: &tracing::span::Id) {}
            fn exit(&self, _: &tracing::span::Id) {}
        }
        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(|| tracing::subscriber::set_global_default(Capture).unwrap());
        CAPTURED.with(|c| *c.borrow_mut() = Some(Vec::new()));
        f();
        CAPTURED.with(|c| c.borrow_mut().take().unwrap())
    }

    /// A fresh keystore's device keys are first boot: info, no error.
    #[test]
    #[cfg(feature = "crypto")]
    fn first_boot_device_keys_log_info_only() {
        let tmp = tempfile::tempdir().unwrap();
        let hsm = SimHsm::new(tmp.path().to_path_buf());
        let logs = capture_logs(|| hsm.ensure_device_keys().unwrap());
        assert!(
            logs.iter().all(|(l, _)| *l != tracing::Level::ERROR),
            "{logs:?}"
        );
        assert!(logs
            .iter()
            .any(|(l, m)| *l == tracing::Level::INFO && m.contains("(first boot)")));
    }

    /// A device key missing from a keystore that holds other device keys (or is
    /// provisioned) is created, as before, and reported at ERROR naming the
    /// role and what stops verifying.
    #[test]
    #[cfg(feature = "crypto")]
    fn device_key_created_in_an_established_keystore_logs_error() {
        let tmp = tempfile::tempdir().unwrap();
        let hsm = SimHsm::new(tmp.path().to_path_buf());
        hsm.ensure_device_keys().unwrap();
        std::fs::remove_file(tmp.path().join("keys/ivd-signing.priv")).unwrap();
        std::fs::remove_file(tmp.path().join("keys/storage-key.bin")).unwrap();

        let logs = capture_logs(|| hsm.ensure_device_keys().unwrap());

        assert!(tmp.path().join("keys/ivd-signing.priv").exists());
        assert!(tmp.path().join("keys/storage-key.bin").exists());
        let errors: Vec<_> = logs
            .iter()
            .filter(|(l, _)| *l == tracing::Level::ERROR)
            .map(|(_, m)| m)
            .collect();
        assert_eq!(errors.len(), 2, "{logs:?}");
        assert!(errors[0].contains("ivd-signing") && errors[0].contains("boot selector"));
        assert!(errors[1].contains("storage-key") && errors[1].contains("identity/attestation"));
        assert!(!logs.iter().any(|(_, m)| m.contains("first boot")));
    }

    /// What a crash between writing a counter's temp file and renaming it
    /// leaves on disk: the counter file untouched and a (possibly torn)
    /// `{name}.tmp` beside it. The counter reads its old value, and the next
    /// ratchet replaces the leftover.
    #[test]
    fn torn_counter_write_is_never_observed() {
        let dir = tempfile::tempdir().unwrap();
        let mut hsm = SimHsm::new(dir.path().to_path_buf());
        let floor = KeyHandle(vhsm_proto::HANDLE_TIME_FLOOR);
        hsm.raise_monotonic(floor, 10).unwrap();
        let file = hsm.monotonic_path(floor.get());
        let mut tmp = file.file_name().unwrap().to_os_string();
        tmp.push(".tmp");
        let tmp = file.with_file_name(tmp);
        for torn in [&b""[..], b"2", b"20"] {
            std::fs::write(&tmp, torn).unwrap();
            assert_eq!(hsm.read_monotonic(floor).unwrap(), 10);
        }
        assert_eq!(hsm.raise_monotonic(floor, 15).unwrap(), 15);
        assert_eq!(
            SimHsm::new(dir.path().into())
                .read_monotonic(floor)
                .unwrap(),
            15
        );
        assert!(
            !tmp.exists(),
            "the ratchet's own temp file was renamed away"
        );
    }

    /// `write_atomic` keeps today's modes: a private file is 0600, any other
    /// gets the plain-create mode, and no temp file is left behind.
    #[test]
    #[cfg(unix)]
    fn write_atomic_keeps_file_modes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain");
        std::fs::write(&plain, b"x").unwrap();
        let create_mode = std::fs::metadata(&plain).unwrap().permissions().mode() & 0o777;

        let public = dir.path().join("a.pub");
        write_atomic(&public, b"pub", false).unwrap();
        let private = dir.path().join("a.priv");
        write_atomic(&private, b"priv", true).unwrap();
        write_atomic(&private, b"priv2", true).unwrap();

        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&public), create_mode);
        assert_eq!(mode(&private), 0o600);
        assert_eq!(std::fs::read(&private).unwrap(), b"priv2");
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(left.is_empty(), "temp files left: {left:?}");
    }

    /// Provisioning through the real `HsmProvider::provision`: signed +
    /// encrypted SUIT envelopes, the factory anchor for the first one and the
    /// key authority for the next. Key material is compared for equality only
    /// and never printed.
    #[cfg(all(feature = "crypto", feature = "suit"))]
    mod through_provision {
        use super::*;
        use coset::CborSerializable;
        use sumo_offboard::cose_key::CoseKey;
        use sumo_offboard::recipient::Recipient;
        use sumo_offboard::{encryptor, keygen, ImageManifestBuilder};

        /// A time-floor value far above any leaf `notBefore` a test issues, so a
        /// re-provision's legitimate ratchet is a no-op and "unchanged" is exact.
        pub(super) const FLOOR: u64 = 4_000_000_000;

        fn signer(scalar: &[u8], public: &[u8]) -> CoseKey {
            let key = coset::CoseKeyBuilder::new_ec2_priv_key(
                coset::iana::EllipticCurve::P_256,
                public[1..33].to_vec(),
                public[33..65].to_vec(),
                scalar.to_vec(),
            )
            .algorithm(coset::iana::Algorithm::ES256)
            .build();
            CoseKey::from_cose_key_bytes(&key.to_vec().unwrap()).unwrap()
        }

        /// The off-device key authority: (scalar, uncompressed public).
        pub(super) fn key_authority() -> (Vec<u8>, Vec<u8>) {
            let sk = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
            let public = sk
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec();
            (sk.to_bytes().to_vec(), public)
        }

        /// The keystore a factory tool sends: the key-authority anchor, every
        /// device-generated role enumerated (no material), one guest identity
        /// and one pinned trust anchor.
        pub(super) fn keystore(security_version: u64, ka_public: &[u8]) -> HsmKeystore {
            let mut slots = vec![KeySlot {
                key_id: KeyRole::KeyAuthority.key_id().into(),
                key_kind: KEY_TYPE_EC_P256,
                anchor_public_key: Some(ka_public.to_vec()),
                allowed_guests: None,
                allowed_ops: Some(vec![OP_VERIFY]),
            }];
            for role in KeyRole::mandatory_roles() {
                if !role.is_device_generated() {
                    continue;
                }
                slots.push(KeySlot {
                    key_id: role.key_id().into(),
                    key_kind: match role.key_type() {
                        KeyType::Aes256 => KEY_TYPE_AES_256,
                        _ => KEY_TYPE_EC_P256,
                    },
                    anchor_public_key: None,
                    allowed_guests: None,
                    allowed_ops: None,
                });
            }
            let mut guest = vec![0x04];
            guest.extend_from_slice(&[0x11; 32]);
            guest.extend_from_slice(&[0x22; 32]);
            HsmKeystore {
                schema_version: SCHEMA_VERSION,
                security_version,
                identities: vec![IdentityDef {
                    identity_id: "vm-a".into(),
                    public_key: guest,
                }],
                slots,
                certificates: Vec::new(),
                trust_anchors: vec![TrustAnchorCert {
                    anchor_id: DELEGATION_ROOT_ANCHOR_ID.into(),
                    certificate: vec![0x30, 0x82, 0x01, 0x00, 0xAB, 0xCD],
                }],
            }
        }

        /// Seal `ks` the way the factory tooling does: CBOR → zstd → ECDH-ES to
        /// the device's own `device-decrypt` public key → SUIT, signed by
        /// `(scalar, public)`.
        pub(super) fn envelope(
            hsm: &SimHsm,
            ks: &HsmKeystore,
            scalar: &[u8],
            public: &[u8],
        ) -> Vec<u8> {
            use sha2::Digest;
            let pem = std::fs::read_to_string(hsm.keys_dir().join("device-decrypt.pub")).unwrap();
            let (x, y) = extract_ec_public_from_pem(&pem).unwrap();
            let mut device =
                coset::CoseKeyBuilder::new_ec2_pub_key(coset::iana::EllipticCurve::P_256, x, y)
                    .build();
            device.alg = None;
            let recipient = CoseKey::from_cose_key_bytes(&device.to_vec().unwrap()).unwrap();

            let cbor = payload::encode(ks).unwrap();
            let digest: [u8; 32] = sha2::Sha256::digest(&cbor).into();
            let compressed = encryptor::compress_firmware(&cbor, 3, None).unwrap();
            let ephemeral = keygen::generate_device_key(keygen::ES256).unwrap();
            let encrypted = encryptor::encrypt_firmware_ecdh(
                &compressed,
                &ephemeral,
                &[Recipient {
                    public_key: recipient,
                    kid: b"device-decrypt".to_vec(),
                }],
            )
            .unwrap();
            ImageManifestBuilder::new()
                .signing_time(1_700_000_000)
                .component_id(vec!["hsm".to_string(), "keys".to_string()])
                .sequence_number(ks.security_version)
                .security_version(ks.security_version)
                .payload_digest(&digest, cbor.len() as u64)
                .payload_uri("#hsm-keys".to_string())
                .encryption_info(&encrypted.encryption_info)
                .integrated_payload("#hsm-keys".to_string(), encrypted.ciphertext)
                .build(&signer(scalar, public))
                .unwrap()
        }

        /// A CA-issued leaf for the device's current `role` key (what the CA
        /// returns for that key's CSR).
        pub(super) fn leaf_for(hsm: &SimHsm, role: KeyRole) -> Vec<u8> {
            leaf_over(&hsm.get_public_key_der(role.handle()).unwrap())
        }

        /// A CA-issued leaf certifying the key `spki_der`.
        pub(super) fn leaf_over(spki_der: &[u8]) -> Vec<u8> {
            use std::str::FromStr;
            use x509_cert::builder::{Builder, CertificateBuilder, Profile};
            use x509_cert::der::{Decode, Encode};
            let spki = x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(spki_der).unwrap();
            let ca = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
            let builder = CertificateBuilder::new(
                Profile::Root,
                x509_cert::serial_number::SerialNumber::from(7u32),
                x509_cert::time::Validity::from_now(std::time::Duration::from_secs(3600)).unwrap(),
                x509_cert::name::Name::from_str("CN=leaf").unwrap(),
                spki,
                &ca,
            )
            .unwrap();
            builder
                .build::<p256::ecdsa::DerSignature>()
                .unwrap()
                .to_der()
                .unwrap()
        }

        /// The SPKI DER a leaf certifies.
        pub(super) fn leaf_spki(der: &[u8]) -> Vec<u8> {
            use x509_cert::der::{Decode, Encode};
            x509_cert::Certificate::from_der(der)
                .unwrap()
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .unwrap()
        }

        /// Every device-generated role's material: the public half for EC roles,
        /// the key bytes for the AES storage key.
        pub(super) fn device_material(keystore: &Path) -> Vec<(KeyRole, Vec<u8>)> {
            KeyRole::mandatory_roles()
                .iter()
                .filter(|r| r.is_device_generated())
                .map(|r| {
                    let file = match r.key_type() {
                        KeyType::Aes256 => format!("{}.bin", r.key_id()),
                        _ => format!("{}.pub", r.key_id()),
                    };
                    (*r, std::fs::read(keystore.join("keys").join(file)).unwrap())
                })
                .collect()
        }

        /// A started, factory-provisioned keystore with a raised time floor, a
        /// second counter, an armed enrolment, and the key authority that
        /// signs its re-provisions.
        pub(super) fn provisioned() -> (tempfile::TempDir, SimHsm, (Vec<u8>, Vec<u8>)) {
            let dir = tempfile::tempdir().unwrap();
            let mut hsm = SimHsm::new(dir.path().join("keystore"));
            hsm.ensure_device_keys().unwrap();
            let ka = key_authority();
            let factory = envelope(
                &hsm,
                &keystore(1, &ka.1),
                &FACTORY_SIGNING_SCALAR,
                &FACTORY_SIGNING_PUBLIC,
            );
            hsm.provision(&factory).unwrap();
            hsm.raise_monotonic(KeyHandle(vhsm_proto::HANDLE_TIME_FLOOR), FLOOR)
                .unwrap();
            hsm.raise_monotonic(KeyHandle(vhsm_proto::HANDLE_IVD_SIGNING), 7)
                .unwrap();
            hsm.arm_enrollment("vm9", Some(600)).unwrap();
            (dir, hsm, ka)
        }

        /// A re-provision (higher security version, signed by the key
        /// authority, carrying the CA-issued `tls-identity` leaf) keeps every
        /// key the device generated, its counters and its enrolment state.
        #[test]
        fn reprovision_keeps_device_keys_counters_and_bootstrap() {
            let (dir, mut hsm, ka) = provisioned();
            let live = dir.path().join("keystore");
            let floor = KeyHandle(vhsm_proto::HANDLE_TIME_FLOOR);
            let other = KeyHandle(vhsm_proto::HANDLE_IVD_SIGNING);

            let keys_before = device_material(&live);
            let ecu_id_before = hsm
                .get_public_key_der(KeyRole::DeviceDecryption.handle())
                .unwrap();
            let bootstrap_before = std::fs::read(live.join("bootstrap.yaml")).unwrap();
            let leaf = leaf_for(&hsm, KeyRole::TlsIdentity);

            let mut ks2 = keystore(2, &ka.1);
            ks2.certificates.push(LeafCert {
                key_id: KeyRole::TlsIdentity.key_id().into(),
                certificate: leaf.clone(),
            });
            let update = envelope(&hsm, &ks2, &ka.0, &ka.1);
            hsm.provision(&update).unwrap();

            // Every check is collected so one run names every broken property.
            let mut broken = Vec::new();
            let mut check = |ok: bool, what: String| {
                if !ok {
                    broken.push(what);
                }
            };
            let keys_after = device_material(&live);
            for ((role, before), (_, after)) in keys_before.iter().zip(keys_after.iter()) {
                check(
                    before == after,
                    format!("device-generated {role:?} key replaced"),
                );
            }
            let ecu_id_after = hsm
                .get_public_key_der(KeyRole::DeviceDecryption.handle())
                .unwrap();
            check(ecu_id_before == ecu_id_after, "ECU id changed".into());
            check(
                hsm.read_monotonic(floor).ok() == Some(FLOOR),
                format!("time floor now {:?}", hsm.read_monotonic(floor)),
            );
            check(
                hsm.read_monotonic(other).ok() == Some(7),
                format!("second counter now {:?}", hsm.read_monotonic(other)),
            );
            check(
                std::fs::read(live.join("bootstrap.yaml")).ok() == Some(bootstrap_before),
                "bootstrap.yaml lost or changed".into(),
            );
            let installed = hsm
                .get_certificate_der(KeyRole::TlsIdentity.handle())
                .unwrap();
            check(installed == leaf, "delivered leaf not installed".into());
            check(
                leaf_spki(&installed)
                    == hsm
                        .get_public_key_der(KeyRole::TlsIdentity.handle())
                        .unwrap(),
                "installed tls-identity leaf certifies a key the device no longer has".into(),
            );
            check(
                hsm.load_security_version().ok() == Some(2),
                "security version not advanced".into(),
            );
            assert!(broken.is_empty(), "re-provision broke: {broken:#?}");
        }

        /// What the envelope owns is replaced: a pinned root or a guest
        /// identity the new envelope no longer carries is gone. A leaf for a
        /// kept key stays until an envelope delivers a new one.
        #[test]
        fn reprovision_replaces_what_the_envelope_owns() {
            let (dir, mut hsm, ka) = provisioned();
            let live = dir.path().join("keystore");
            assert!(hsm.get_trust_anchor_der(DELEGATION_ROOT_ANCHOR_ID).is_ok());
            assert!(live.join("keys/vm-a.pub").exists());

            let leaf = leaf_for(&hsm, KeyRole::TlsIdentity);
            let mut ks2 = keystore(2, &ka.1);
            ks2.trust_anchors.clear();
            ks2.identities.clear();
            ks2.certificates.push(LeafCert {
                key_id: KeyRole::TlsIdentity.key_id().into(),
                certificate: leaf.clone(),
            });
            hsm.provision(&envelope(&hsm, &ks2, &ka.0, &ka.1)).unwrap();

            assert!(hsm.get_trust_anchor_der(DELEGATION_ROOT_ANCHOR_ID).is_err());
            assert!(!live.join("keys/roots").exists());
            assert!(!live.join("keys/vm-a.pub").exists());
            assert_eq!(
                std::fs::read_to_string(live.join("identities")).unwrap(),
                ""
            );
            // The key authority the envelope still carries is still the anchor.
            assert!(hsm.get_public_key(KeyRole::KeyAuthority).is_ok());

            // A third envelope without the leaf keeps the installed one: it
            // certifies a key the device still holds.
            let ks3 = keystore(3, &ka.1);
            hsm.provision(&envelope(&hsm, &ks3, &ka.0, &ka.1)).unwrap();
            let installed = hsm
                .get_certificate_der(KeyRole::TlsIdentity.handle())
                .unwrap();
            assert!(installed == leaf);
            let manifest = std::fs::read_to_string(live.join("manifest")).unwrap();
            assert!(manifest.contains("keys/tls-identity.cert"));
            // ... and the third envelope's root is back.
            assert!(hsm.get_trust_anchor_der(DELEGATION_ROOT_ANCHOR_ID).is_ok());
            assert_eq!(hsm.load_security_version().unwrap(), 3);
        }

        /// Every file and directory keeps its mode through a re-provision: the
        /// keys directory 0700, private keys 0600, the rest as created.
        #[test]
        #[cfg(unix)]
        fn reprovision_keeps_file_modes() {
            use std::collections::BTreeMap;
            use std::os::unix::fs::PermissionsExt;
            fn modes(root: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, u32>) {
                for e in std::fs::read_dir(dir).unwrap() {
                    let p = e.unwrap().path();
                    let m = std::fs::metadata(&p).unwrap();
                    out.insert(
                        p.strip_prefix(root).unwrap().into(),
                        m.permissions().mode() & 0o7777,
                    );
                    if m.is_dir() {
                        modes(root, &p, out);
                    }
                }
            }
            let (dir, mut hsm, ka) = provisioned();
            let live = dir.path().join("keystore");
            let root_mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
            let root_before = root_mode(&live);
            let mut before = BTreeMap::new();
            modes(&live, &live, &mut before);

            hsm.provision(&envelope(&hsm, &keystore(2, &ka.1), &ka.0, &ka.1))
                .unwrap();

            let mut after = BTreeMap::new();
            modes(&live, &live, &mut after);
            assert_eq!(root_mode(&live), root_before);
            assert_eq!(before, after, "file list or modes changed");
            assert_eq!(after[Path::new("keys")], 0o700);
            for (path, mode) in &after {
                if path.extension().is_some_and(|e| e == "priv") {
                    assert_eq!(*mode, 0o600, "{}", path.display());
                }
            }
        }

        /// Stop a re-provision after each step of the keystore switch, start
        /// again (`ensure_device_keys`, which recovers first), and check the
        /// result is the complete old or the complete new keystore with the
        /// device keys intact — the table on `recover_interrupted_reprovision`.
        #[test]
        fn every_interrupted_switch_recovers_to_a_complete_keystore() {
            enum Stop {
                BuildingStaging,
                BeforeFirstRename,
                BetweenRenames,
                AfterCommit,
                BackupOnly,
                StagingOnly,
                PartialStagingOnly,
            }
            let cases = [
                (Stop::BuildingStaging, Some(1)),
                (Stop::BeforeFirstRename, Some(1)),
                (Stop::BetweenRenames, Some(1)),
                (Stop::AfterCommit, Some(2)),
                (Stop::BackupOnly, Some(1)),
                (Stop::StagingOnly, Some(2)),
                // Cut short before its manifest: unprovisioned, same device.
                (Stop::PartialStagingOnly, None),
            ];
            for (stop, expect) in cases {
                let (dir, hsm, ka) = provisioned();
                let live = dir.path().join("keystore");
                let (tmp, bak) = (live.with_extension("tmp"), live.with_extension("bak"));
                let keys = device_material(&live);
                let mut ks2 = keystore(2, &ka.1);
                ks2.trust_anchors.clear();

                let staged = hsm.stage_reprovision(&ks2).unwrap();
                assert_eq!(staged, tmp);
                let rename = |a: &Path, b: &Path| std::fs::rename(a, b).unwrap();
                let remove = |d: &Path| std::fs::remove_dir_all(d).unwrap();
                match stop {
                    Stop::BuildingStaging => {
                        std::fs::remove_file(tmp.join("manifest")).unwrap();
                        std::fs::remove_file(tmp.join("keys/ivd-signing.priv")).unwrap();
                    }
                    Stop::BeforeFirstRename => {}
                    Stop::BetweenRenames => rename(&live, &bak),
                    Stop::AfterCommit => {
                        rename(&live, &bak);
                        rename(&tmp, &live);
                    }
                    Stop::BackupOnly => {
                        rename(&live, &bak);
                        remove(&tmp);
                    }
                    Stop::StagingOnly => {
                        rename(&live, &bak);
                        remove(&bak);
                    }
                    Stop::PartialStagingOnly => {
                        std::fs::remove_file(tmp.join("manifest")).unwrap();
                        rename(&live, &bak);
                        remove(&bak);
                    }
                }

                let restarted = SimHsm::new(live.clone());
                restarted.ensure_device_keys().unwrap();

                assert!(!tmp.exists() && !bak.exists(), "leftovers remain");
                assert!(
                    device_material(&live) == keys,
                    "device keys changed across an interrupted switch"
                );
                match expect {
                    Some(sv) => {
                        assert!(restarted.is_provisioned().unwrap());
                        assert_eq!(restarted.load_security_version().unwrap(), sv);
                        // A complete keystore, old or new: its root is there
                        // exactly when its envelope carried one.
                        assert_eq!(
                            restarted
                                .get_trust_anchor_der(DELEGATION_ROOT_ANCHOR_ID)
                                .is_ok(),
                            sv == 1
                        );
                    }
                    None => assert!(!restarted.is_provisioned().unwrap()),
                }
                assert_eq!(
                    restarted
                        .read_monotonic(KeyHandle(vhsm_proto::HANDLE_TIME_FLOOR))
                        .unwrap(),
                    FLOOR
                );
            }
        }

        /// A re-provision that fails while building its keystore leaves the
        /// live one as it was and no staging directory behind.
        #[test]
        #[cfg(unix)]
        fn failed_reprovision_changes_nothing() {
            use std::os::unix::fs::PermissionsExt;
            let (dir, mut hsm, ka) = provisioned();
            let live = dir.path().join("keystore");
            let keys = device_material(&live);
            // An unreadable file the re-provision has to carry makes staging fail.
            let blocked = live.join("bootstrap.yaml");
            std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000)).unwrap();
            if std::fs::read(&blocked).is_ok() {
                return; // running as root: permissions do not block the copy
            }
            let update = envelope(&hsm, &keystore(2, &ka.1), &ka.0, &ka.1);
            assert!(hsm.provision(&update).is_err());
            assert!(!live.with_extension("tmp").exists());
            assert!(device_material(&live) == keys);
            assert_eq!(hsm.load_security_version().unwrap(), 1);
            std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        /// Every file under `dir` (recursively), by relative path, with its
        /// bytes.
        fn tree(dir: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
            fn walk(
                root: &Path,
                dir: &Path,
                out: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>,
            ) {
                for e in std::fs::read_dir(dir).unwrap() {
                    let p = e.unwrap().path();
                    if p.is_dir() {
                        walk(root, &p, out);
                    } else {
                        let bytes = std::fs::read(&p).unwrap();
                        out.insert(p.strip_prefix(root).unwrap().into(), bytes);
                    }
                }
            }
            let mut out = std::collections::BTreeMap::new();
            walk(dir, dir, &mut out);
            out
        }

        /// A started keystore that was never provisioned: the device keys
        /// only.
        fn unprovisioned() -> (tempfile::TempDir, SimHsm) {
            let dir = tempfile::tempdir().unwrap();
            let hsm = SimHsm::new(dir.path().join("keystore"));
            hsm.ensure_device_keys().unwrap();
            (dir, hsm)
        }

        /// A leaf certifying a key this device does not hold.
        fn foreign_leaf() -> Vec<u8> {
            use p256::pkcs8::EncodePublicKey;
            let other = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
            leaf_over(
                other
                    .verifying_key()
                    .to_public_key_der()
                    .unwrap()
                    .as_bytes(),
            )
        }

        /// The leaves no envelope may install, each named: for `tls-identity`
        /// a leaf for another key, garbage, and one good leaf beside a bad
        /// one; a valid leaf for a slot with no key on the device; a leaf for
        /// the key-authority anchor slot that certifies another key.
        fn bad_leaves(hsm: &SimHsm) -> Vec<(&'static str, Vec<LeafCert>)> {
            let tls = KeyRole::TlsIdentity.key_id();
            let leaf = |key_id: &str, certificate: Vec<u8>| LeafCert {
                key_id: key_id.into(),
                certificate,
            };
            let good = leaf_for(hsm, KeyRole::TlsIdentity);
            vec![
                ("another key", vec![leaf(tls, foreign_leaf())]),
                (
                    "garbage",
                    vec![leaf(tls, vec![0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD])],
                ),
                (
                    "one good, one bad",
                    vec![
                        leaf(tls, good.clone()),
                        leaf(KeyRole::JwtSigning.key_id(), foreign_leaf()),
                    ],
                ),
                ("a slot without a key", vec![leaf("extra-identity", good)]),
                (
                    "the anchor slot",
                    vec![leaf(KeyRole::KeyAuthority.key_id(), foreign_leaf())],
                ),
            ]
        }

        /// `ks` with `leaves`, and with an EC slot `extra-identity` the
        /// device has no key for yet.
        fn with_leaves(mut ks: HsmKeystore, leaves: Vec<LeafCert>) -> HsmKeystore {
            ks.slots.push(KeySlot {
                key_id: "extra-identity".into(),
                key_kind: KEY_TYPE_EC_P256,
                anchor_public_key: None,
                allowed_guests: None,
                allowed_ops: None,
            });
            ks.certificates = leaves;
            ks
        }

        /// A first provision carrying a leaf for the device's own key
        /// installs it, as a re-provision does.
        #[test]
        fn first_provision_installs_a_leaf_for_the_device_key() {
            let (_dir, mut hsm) = unprovisioned();
            let leaf = leaf_for(&hsm, KeyRole::TlsIdentity);
            let ka = key_authority();
            let mut ks = keystore(1, &ka.1);
            ks.certificates.push(LeafCert {
                key_id: KeyRole::TlsIdentity.key_id().into(),
                certificate: leaf.clone(),
            });
            hsm.provision(&envelope(
                &hsm,
                &ks,
                &FACTORY_SIGNING_SCALAR,
                &FACTORY_SIGNING_PUBLIC,
            ))
            .unwrap();
            assert!(hsm.is_provisioned().unwrap());
            assert!(
                hsm.get_certificate_der(KeyRole::TlsIdentity.handle())
                    .unwrap()
                    == leaf
            );
        }

        /// A first provision whose leaf does not certify the device's key is
        /// refused whole: the keystore stays unprovisioned, byte for byte.
        #[test]
        fn first_provision_with_a_bad_leaf_is_refused_and_writes_nothing() {
            let ka = key_authority();
            let (_dir, probe) = unprovisioned();
            for (case, _) in bad_leaves(&probe) {
                let (dir, mut hsm) = unprovisioned();
                let leaves = bad_leaves(&hsm)
                    .into_iter()
                    .find(|(c, _)| *c == case)
                    .unwrap()
                    .1;
                let ks = with_leaves(keystore(1, &ka.1), leaves);
                let update = envelope(&hsm, &ks, &FACTORY_SIGNING_SCALAR, &FACTORY_SIGNING_PUBLIC);
                let before = tree(dir.path());

                let err = hsm.provision(&update).expect_err(case);
                assert!(matches!(err, HsmError::PayloadInvalid(_)), "{case}: {err}");
                assert!(tree(dir.path()) == before, "{case}: the keystore changed");
                assert!(!hsm.is_provisioned().unwrap(), "{case}");
            }
        }

        /// A re-provision whose leaf does not certify the device's key is
        /// refused whole, before any staging: the keystore stays as it was,
        /// byte for byte, and the same envelope without the leaf applies.
        #[test]
        fn reprovision_with_a_bad_leaf_is_refused_and_writes_nothing() {
            let (_probe_dir, probe, _) = provisioned();
            for (case, _) in bad_leaves(&probe) {
                let (dir, mut hsm, ka) = provisioned();
                let leaves = bad_leaves(&hsm)
                    .into_iter()
                    .find(|(c, _)| *c == case)
                    .unwrap()
                    .1;
                let update = envelope(&hsm, &with_leaves(keystore(2, &ka.1), leaves), &ka.0, &ka.1);
                let before = tree(dir.path());

                let err = hsm.provision(&update).expect_err(case);
                assert!(matches!(err, HsmError::PayloadInvalid(_)), "{case}: {err}");
                assert!(tree(dir.path()) == before, "{case}: the keystore changed");
                assert_eq!(hsm.load_security_version().unwrap(), 1, "{case}");

                let retry = envelope(&hsm, &keystore(2, &ka.1), &ka.0, &ka.1);
                hsm.provision(&retry).expect(case);
                assert_eq!(hsm.load_security_version().unwrap(), 2, "{case}");
            }
        }
    }
}
