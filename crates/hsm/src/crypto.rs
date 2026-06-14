/// HsmCryptoProvider implementation for SimHsm.
///
/// Performs crypto operations in software using RustCrypto crates.
/// Keys are read from the file-based keystore (PEM for EC-P256,
/// raw binary for AES-256). On production hardware, this would be
/// replaced by a QnxHsm implementation that routes to HSM firmware.
///
/// Key material never leaves this module — callers (vhsm-ssd) only
/// see operation results (signatures, ciphertexts, etc.).
use crate::sim::{decode_pem, extract_ec_scalar_from_pem, SimHsm};
use crate::{HsmCryptoProvider, HsmError, HsmProvider, KeyInfo, KeyType};

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use ecdsa::signature::Signer;
use ecdsa::signature::Verifier;
use hkdf::Hkdf;
use hmac::Hmac;
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand::RngCore;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

impl HsmCryptoProvider for SimHsm {
    fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        let key_info = self.get_key_info(key_id)?;
        match key_info.key_type {
            KeyType::EcP256 => {
                let scalar = load_ec_private_scalar(self, key_id)?;
                let signing_key = SigningKey::from_bytes((&scalar[..]).into())
                    .map_err(|e| HsmError::CryptoError(format!("invalid signing key: {e}")))?;
                let signature: ecdsa::der::Signature<p256::NistP256> = signing_key.sign(data);
                Ok(signature.to_bytes().to_vec())
            }
            KeyType::Ed25519 => {
                let sk = load_ed25519_signing_key(self, key_id)?;
                Ok(sk.sign(data).to_bytes().to_vec())
            }
            other => Err(HsmError::CryptoError(format!(
                "sign requires asymmetric signing key (EC-P256 or Ed25519), got {other}"
            ))),
        }
    }

    fn sign_raw_p256(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        let key_info = self.get_key_info(key_id)?;
        if key_info.key_type != KeyType::EcP256 {
            return Err(HsmError::CryptoError(format!(
                "sign_raw_p256 requires EC-P256 key, got {}",
                key_info.key_type
            )));
        }

        let scalar = load_ec_private_scalar(self, key_id)?;
        let signing_key = SigningKey::from_bytes((&scalar[..]).into())
            .map_err(|e| HsmError::CryptoError(format!("invalid signing key: {e}")))?;

        // Non-DER `Signature` returns raw 64-byte `r || s`.
        let signature: ecdsa::Signature<p256::NistP256> = signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    fn verify(&self, key_id: &str, data: &[u8], signature: &[u8]) -> Result<bool, HsmError> {
        let key_info = self.get_key_info(key_id)?;
        match key_info.key_type {
            KeyType::EcP256 => {
                let verifying_key = load_ec_verifying_key(self, key_id)?;
                let sig = ecdsa::der::Signature::<p256::NistP256>::from_bytes(signature)
                    .map_err(|e| HsmError::CryptoError(format!("invalid signature: {e}")))?;
                match verifying_key.verify(data, &sig) {
                    Ok(()) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            KeyType::Ed25519 => {
                let vk = load_ed25519_verifying_key(self, key_id)?;
                let sig_arr: &[u8; 64] = signature.try_into().map_err(|_| {
                    HsmError::CryptoError(format!(
                        "Ed25519 signature must be 64 bytes, got {}",
                        signature.len()
                    ))
                })?;
                let sig = ed25519_dalek::Signature::from_bytes(sig_arr);
                Ok(vk.verify(data, &sig).is_ok())
            }
            other => Err(HsmError::CryptoError(format!(
                "verify requires asymmetric signing key (EC-P256 or Ed25519), got {other}"
            ))),
        }
    }

    fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, HsmError> {
        let key_info = self.get_key_info(key_id)?;
        let (raw_key, expected_len) = match key_info.key_type {
            KeyType::Aes256 => (load_aes_key_bytes(self, key_id, 32)?, 32),
            KeyType::Aes128 => (load_aes_key_bytes(self, key_id, 16)?, 16),
            other => {
                return Err(HsmError::CryptoError(format!(
                    "encrypt requires AES-128 or AES-256 key, got {other}"
                )));
            }
        };
        debug_assert_eq!(raw_key.len(), expected_len);

        let mut iv_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut iv_bytes);
        let nonce = Nonce::from_slice(&iv_bytes);

        let ciphertext = if expected_len == 32 {
            Aes256Gcm::new_from_slice(&raw_key)
                .map_err(|e| HsmError::CryptoError(format!("invalid AES-256 key: {e}")))?
                .encrypt(nonce, plaintext)
                .map_err(|e| HsmError::CryptoError(format!("AES-256-GCM encrypt: {e}")))?
        } else {
            Aes128Gcm::new_from_slice(&raw_key)
                .map_err(|e| HsmError::CryptoError(format!("invalid AES-128 key: {e}")))?
                .encrypt(nonce, plaintext)
                .map_err(|e| HsmError::CryptoError(format!("AES-128-GCM encrypt: {e}")))?
        };

        // Return iv(12) || ciphertext || tag (tag is appended by aes-gcm)
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&iv_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn decrypt(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        let key_info = self.get_key_info(key_id)?;
        let (raw_key, expected_len) = match key_info.key_type {
            KeyType::Aes256 => (load_aes_key_bytes(self, key_id, 32)?, 32),
            KeyType::Aes128 => (load_aes_key_bytes(self, key_id, 16)?, 16),
            other => {
                return Err(HsmError::CryptoError(format!(
                    "decrypt requires AES-128 or AES-256 key, got {other}"
                )));
            }
        };
        debug_assert_eq!(raw_key.len(), expected_len);

        if data.len() < 12 + 16 {
            return Err(HsmError::CryptoError(
                "ciphertext too short (need at least iv + tag)".into(),
            ));
        }

        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext_and_tag = &data[12..];

        if expected_len == 32 {
            Aes256Gcm::new_from_slice(&raw_key)
                .map_err(|e| HsmError::CryptoError(format!("invalid AES-256 key: {e}")))?
                .decrypt(nonce, ciphertext_and_tag)
                .map_err(|e| HsmError::CryptoError(format!("AES-256-GCM decrypt: {e}")))
        } else {
            Aes128Gcm::new_from_slice(&raw_key)
                .map_err(|e| HsmError::CryptoError(format!("invalid AES-128 key: {e}")))?
                .decrypt(nonce, ciphertext_and_tag)
                .map_err(|e| HsmError::CryptoError(format!("AES-128-GCM decrypt: {e}")))
        }
    }

    fn mac_generate(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        use cmac::{Cmac, Mac};

        let key_info = self.get_key_info(key_id)?;
        match key_info.key_type {
            KeyType::Aes256 => {
                let raw_key = load_aes_key_bytes(self, key_id, 32)?;
                let mut mac =
                    <Cmac<aes::Aes256> as Mac>::new_from_slice(&raw_key).map_err(|e| {
                        HsmError::CryptoError(format!("invalid AES-256 key for CMAC: {e}"))
                    })?;
                mac.update(data);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            KeyType::Aes128 => {
                let raw_key = load_aes_key_bytes(self, key_id, 16)?;
                let mut mac =
                    <Cmac<aes::Aes128> as Mac>::new_from_slice(&raw_key).map_err(|e| {
                        HsmError::CryptoError(format!("invalid AES-128 key for CMAC: {e}"))
                    })?;
                mac.update(data);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            KeyType::HmacSha256 => {
                let raw_key = load_hmac_key(self, key_id)?;
                let mut mac = <HmacSha256 as Mac>::new_from_slice(&raw_key)
                    .map_err(|e| HsmError::CryptoError(format!("invalid HMAC key: {e}")))?;
                mac.update(data);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            other => Err(HsmError::CryptoError(format!(
                "mac_generate requires AES-{{128,256}} (CMAC) or HMAC-SHA256 key, got {other}"
            ))),
        }
    }

    fn mac_verify(&self, key_id: &str, data: &[u8], tag: &[u8]) -> Result<bool, HsmError> {
        use cmac::{Cmac, Mac};

        let key_info = self.get_key_info(key_id)?;
        match key_info.key_type {
            KeyType::Aes256 => {
                let raw_key = load_aes_key_bytes(self, key_id, 32)?;
                let mut mac =
                    <Cmac<aes::Aes256> as Mac>::new_from_slice(&raw_key).map_err(|e| {
                        HsmError::CryptoError(format!("invalid AES-256 key for CMAC: {e}"))
                    })?;
                mac.update(data);
                Ok(mac.verify_slice(tag).is_ok())
            }
            KeyType::Aes128 => {
                let raw_key = load_aes_key_bytes(self, key_id, 16)?;
                let mut mac =
                    <Cmac<aes::Aes128> as Mac>::new_from_slice(&raw_key).map_err(|e| {
                        HsmError::CryptoError(format!("invalid AES-128 key for CMAC: {e}"))
                    })?;
                mac.update(data);
                Ok(mac.verify_slice(tag).is_ok())
            }
            KeyType::HmacSha256 => {
                let raw_key = load_hmac_key(self, key_id)?;
                let mut mac = <HmacSha256 as Mac>::new_from_slice(&raw_key)
                    .map_err(|e| HsmError::CryptoError(format!("invalid HMAC key: {e}")))?;
                mac.update(data);
                Ok(mac.verify_slice(tag).is_ok())
            }
            other => Err(HsmError::CryptoError(format!(
                "mac_verify requires AES-{{128,256}} (CMAC) or HMAC-SHA256 key, got {other}"
            ))),
        }
    }

    fn derive(&self, key_id: &str, context: &[u8], len: usize) -> Result<Vec<u8>, HsmError> {
        let key_info = self.get_key_info(key_id)?;
        let raw_key = match key_info.key_type {
            KeyType::Aes256 => load_aes_key_bytes(self, key_id, 32)?,
            KeyType::Aes128 => load_aes_key_bytes(self, key_id, 16)?,
            KeyType::HmacSha256 => load_hmac_key(self, key_id)?,
            other => {
                return Err(HsmError::CryptoError(format!(
                    "derive requires symmetric key (AES-128, AES-256, or HMAC-SHA256), got {other}"
                )));
            }
        };

        let hk = Hkdf::<Sha256>::new(None, &raw_key);
        let mut okm = vec![0u8; len];
        hk.expand(context, &mut okm)
            .map_err(|e| HsmError::CryptoError(format!("HKDF expand: {e}")))?;
        Ok(okm)
    }

    fn random(&self, len: usize) -> Result<Vec<u8>, HsmError> {
        if len > 1024 {
            return Err(HsmError::CryptoError(format!(
                "random request too large: {len} (max 1024)"
            )));
        }
        let mut buf = vec![0u8; len];
        OsRng.fill_bytes(&mut buf);
        Ok(buf)
    }

    fn get_certificate_der(&self, key_id: &str) -> Result<Vec<u8>, HsmError> {
        let key_info = self.get_key_info(key_id)?;
        if !key_info.has_certificate {
            return Err(HsmError::KeyNotFound(format!(
                "no certificate for key '{key_id}'"
            )));
        }

        let cert_path = self.keys_dir().join(format!("{key_id}.cert"));
        let pem = std::fs::read_to_string(&cert_path)
            .map_err(|e| HsmError::KeystoreError(format!("read {}: {e}", cert_path.display())))?;
        decode_pem(&pem, "CERTIFICATE")
    }

    fn get_public_key_der(&self, key_id: &str) -> Result<Vec<u8>, HsmError> {
        let key_info = self.get_key_info(key_id)?;
        match key_info.key_type {
            KeyType::EcP256 => {
                let pub_path = self.keys_dir().join(format!("{key_id}.pub"));
                let pem = std::fs::read_to_string(&pub_path).map_err(|e| {
                    HsmError::KeystoreError(format!("read {}: {e}", pub_path.display()))
                })?;
                decode_pem(&pem, "PUBLIC KEY")
            }
            KeyType::Ed25519 => {
                let pub_path = self.keys_dir().join(format!("{key_id}.ed25519.pub"));
                let pem = std::fs::read_to_string(&pub_path).map_err(|e| {
                    HsmError::KeystoreError(format!("read {}: {e}", pub_path.display()))
                })?;
                decode_pem(&pem, "PUBLIC KEY")
            }
            other => Err(HsmError::CryptoError(format!(
                "get_public_key_der requires asymmetric key (EC-P256 or Ed25519), got {other}"
            ))),
        }
    }

    fn get_key_info(&self, key_id: &str) -> Result<KeyInfo, HsmError> {
        // Manifest lookup (provisioned well-known keys)
        if self.is_provisioned().unwrap_or(false) {
            let keys = self.parse_manifest()?;
            if let Some(info) = keys.into_iter().find(|k| k.key_id == key_id) {
                return Ok(info);
            }
        }

        // Disk fallback (dynamically-generated keys). Infer type from the
        // file extension produced by `generate_key`:
        //   `{key_id}.bin`           → AES-256 (32-byte raw)
        //   `{key_id}.aes128.bin`    → AES-128 (16-byte raw)
        //   `{key_id}.hmac256.bin`   → HMAC-SHA256 (32-byte raw)
        //   `{key_id}.priv`          → EC-P256 (PEM)
        //   `{key_id}.ed25519.priv`  → Ed25519 (PEM)
        let kd = self.keys_dir();
        let probes: [(&str, KeyType); 5] = [
            ("ed25519.priv", KeyType::Ed25519),
            ("priv", KeyType::EcP256),
            ("aes128.bin", KeyType::Aes128),
            ("hmac256.bin", KeyType::HmacSha256),
            ("bin", KeyType::Aes256),
        ];
        for (ext, kt) in probes {
            if kd.join(format!("{key_id}.{ext}")).exists() {
                return Ok(KeyInfo {
                    key_id: key_id.to_string(),
                    key_type: kt,
                    has_certificate: false,
                    allowed_guests: None,
                    allowed_ops: None,
                });
            }
        }

        if !self.is_provisioned().unwrap_or(false) {
            return Err(HsmError::NotProvisioned);
        }
        Err(HsmError::KeyNotFound(key_id.to_string()))
    }

    fn generate_key(&self, key_id: &str, alg: u32) -> Result<Vec<u8>, HsmError> {
        // Algorithm constants mirror vHSM wire protocol — see
        // `vhsm-ssd::proto::ALG_*`. Keep in sync.
        const ALG_AES_128: u32 = 0x0001;
        const ALG_AES_256: u32 = 0x0002;
        const ALG_HMAC_SHA256: u32 = 0x0010;
        const ALG_ED25519: u32 = 0x0020;
        const ALG_ECC_P256: u32 = 0x0021;

        std::fs::create_dir_all(self.keys_dir())
            .map_err(|e| HsmError::KeystoreError(format!("create keys dir: {e}")))?;
        crate::sim::restrict_dir_700(&self.keys_dir());

        let write_raw = |ext: &str, len: usize| -> Result<(), HsmError> {
            let mut key = vec![0u8; len];
            OsRng.fill_bytes(&mut key);
            let path = self.keys_dir().join(format!("{key_id}.{ext}"));
            std::fs::write(&path, &key)
                .map_err(|e| HsmError::KeystoreError(format!("write {}: {e}", path.display())))?;
            crate::sim::restrict_file_600(&path);
            Ok(())
        };

        match alg {
            ALG_AES_128 => {
                write_raw("aes128.bin", 16)?;
                Ok(Vec::new())
            }
            ALG_AES_256 => {
                write_raw("bin", 32)?;
                Ok(Vec::new())
            }
            ALG_HMAC_SHA256 => {
                // 32-byte HMAC key — matches SHA-256 block boundary.
                write_raw("hmac256.bin", 32)?;
                Ok(Vec::new())
            }
            ALG_ECC_P256 => {
                let sk = p256::ecdsa::SigningKey::random(&mut OsRng);
                let scalar = sk.to_bytes();
                let vk = sk.verifying_key();
                let pub_point = vk.to_encoded_point(false);

                let priv_path = self.keys_dir().join(format!("{key_id}.priv"));
                crate::sim::write_pem_ec_private(&priv_path, &scalar)?;
                let pub_path = self.keys_dir().join(format!("{key_id}.pub"));
                crate::sim::write_pem_ec_public(&pub_path, pub_point.as_bytes())?;

                // Return SubjectPublicKeyInfo DER — matches `get_public_key_der`.
                let pem = std::fs::read_to_string(&pub_path).map_err(|e| {
                    HsmError::KeystoreError(format!("read back {}: {e}", pub_path.display()))
                })?;
                decode_pem(&pem, "PUBLIC KEY")
            }
            ALG_ED25519 => {
                use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
                use rand::rngs::OsRng as DalekOsRng;

                let sk = ed25519_dalek::SigningKey::generate(&mut DalekOsRng);
                let vk = sk.verifying_key();

                let priv_pem = sk
                    .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
                    .map_err(|e| HsmError::CryptoError(format!("Ed25519 PKCS8 PEM: {e}")))?;
                let priv_path = self.keys_dir().join(format!("{key_id}.ed25519.priv"));
                std::fs::write(&priv_path, priv_pem.as_bytes()).map_err(|e| {
                    HsmError::KeystoreError(format!("write {}: {e}", priv_path.display()))
                })?;
                crate::sim::restrict_file_600(&priv_path);

                let pub_pem = vk
                    .to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
                    .map_err(|e| HsmError::CryptoError(format!("Ed25519 SPKI PEM: {e}")))?;
                let pub_path = self.keys_dir().join(format!("{key_id}.ed25519.pub"));
                std::fs::write(&pub_path, pub_pem.as_bytes()).map_err(|e| {
                    HsmError::KeystoreError(format!("write {}: {e}", pub_path.display()))
                })?;

                // Return SPKI DER — same convention as EC.
                decode_pem(&pub_pem, "PUBLIC KEY")
            }
            other => Err(HsmError::NotSupported(format!(
                "generate_key algorithm 0x{other:04x}"
            ))),
        }
    }

    fn generate_csr(&self, key_id: &str, subject_cn: &str) -> Result<Vec<u8>, HsmError> {
        let priv_path = self.keys_dir().join(format!("{key_id}.priv"));
        if !priv_path.exists() {
            return Err(HsmError::KeyNotFound(format!(
                "no private key for CSR: {key_id}"
            )));
        }

        let pem = std::fs::read_to_string(&priv_path)
            .map_err(|e| HsmError::KeystoreError(format!("read {}: {e}", priv_path.display())))?;
        let scalar = extract_ec_scalar_from_pem(&pem)?;
        let signing_key = SigningKey::from_bytes((&scalar[..]).into())
            .map_err(|e| HsmError::CryptoError(format!("invalid signing key: {e}")))?;

        // Build the PKCS#10 CSR with x509-cert — the same library the Tower CA
        // parses with — so the CertificationRequestInfo round-trips exactly (the
        // CA verifies proof-of-possession over a re-serialization of it). On real
        // hardware the signature would be delegated to the HSM; here the SimHsm
        // signs with the in-process key.
        use std::str::FromStr;
        use x509_cert::builder::{Builder, RequestBuilder};
        use x509_cert::der::Encode;
        use x509_cert::name::Name;

        let subject = Name::from_str(&format!("CN={subject_cn}"))
            .map_err(|e| HsmError::CryptoError(format!("invalid subject CN: {e}")))?;
        let builder = RequestBuilder::new(subject, &signing_key)
            .map_err(|e| HsmError::CryptoError(format!("CSR builder init: {e}")))?;
        let csr = builder
            .build::<p256::ecdsa::DerSignature>()
            .map_err(|e| HsmError::CryptoError(format!("CSR build/sign: {e}")))?;
        csr.to_der()
            .map_err(|e| HsmError::CryptoError(format!("CSR encode: {e}")))
    }

    /// CEK unwrap via in-host crypto, using the symmetric key stored
    /// at `key_id.bin` (raw bytes for AES-KW).
    fn unwrap_cek_a128kw(&self, key_id: &str, wrapped_cek: &[u8]) -> Result<Vec<u8>, HsmError> {
        let kek_path = self.keys_dir().join(format!("{key_id}.bin"));
        if !kek_path.exists() {
            return Err(HsmError::KeyNotFound(format!(
                "no symmetric KEK for A128KW unwrap: {key_id} (no {})",
                kek_path.display()
            )));
        }
        let kek = std::fs::read(&kek_path)
            .map_err(|e| HsmError::KeystoreError(format!("read {}: {e}", kek_path.display())))?;
        // RustCryptoBackend has aes_kw_unwrap; reuse rather than reimplement.
        let backend = sumo_crypto::RustCryptoBackend;
        sumo_crypto::CryptoBackend::aes_kw_unwrap(&backend, &kek, wrapped_cek)
            .map_err(|e| HsmError::CryptoError(format!("A128KW unwrap: {e:?}")))
    }

    /// CEK unwrap via in-host crypto, using the EC private scalar
    /// stored at `key_id.priv` (PEM). On real HSE this op stays inside
    /// the secure element; here it's RustCrypto + a file read.
    fn unwrap_cek_ecdh_es(
        &self,
        key_id: &str,
        ephem_pub: &[u8],
        wrapped_cek: &[u8],
        recipient_protected: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        let priv_path = self.keys_dir().join(format!("{key_id}.priv"));
        if !priv_path.exists() {
            return Err(HsmError::KeyNotFound(format!(
                "no EC private key for ECDH-ES unwrap: {key_id} (no {})",
                priv_path.display()
            )));
        }
        let pem = std::fs::read_to_string(&priv_path)
            .map_err(|e| HsmError::KeystoreError(format!("read {}: {e}", priv_path.display())))?;
        let scalar = extract_ec_scalar_from_pem(&pem)?;
        let backend = sumo_crypto::RustCryptoBackend;
        sumo_crypto::ecdh_es::ecdh_es_a128kw_unwrap(
            &backend,
            &scalar,
            ephem_pub,
            wrapped_cek,
            recipient_protected,
        )
        .map_err(|e| HsmError::CryptoError(format!("ECDH-ES+A128KW unwrap: {e:?}")))
    }
}

// --- Internal key loading helpers ---

fn load_ec_private_scalar(hsm: &SimHsm, key_id: &str) -> Result<Vec<u8>, HsmError> {
    let priv_path = hsm.keys_dir().join(format!("{key_id}.priv"));
    let pem = std::fs::read_to_string(&priv_path)
        .map_err(|e| HsmError::KeystoreError(format!("read {}: {e}", priv_path.display())))?;
    extract_ec_scalar_from_pem(&pem)
}

fn load_ec_verifying_key(hsm: &SimHsm, key_id: &str) -> Result<VerifyingKey, HsmError> {
    let pub_path = hsm.keys_dir().join(format!("{key_id}.pub"));
    let pem = std::fs::read_to_string(&pub_path)
        .map_err(|e| HsmError::KeystoreError(format!("read {}: {e}", pub_path.display())))?;
    let der = decode_pem(&pem, "PUBLIC KEY")?;
    VerifyingKey::from_sec1_bytes(&der[der.len() - 65..])
        .map_err(|e| HsmError::CryptoError(format!("invalid verifying key: {e}")))
}

/// Load a raw symmetric key of the expected size.
///
/// `expected_bytes` selects the on-disk extension:
///   * 16 → `{key_id}.aes128.bin`
///   * 32 → `{key_id}.bin`            (AES-256 — legacy/default symmetric)
///
/// Use `load_hmac_key` for HMAC-SHA256 (also 32 bytes but a different
/// extension to disambiguate from AES-256 at the `get_key_info` layer).
fn load_aes_key_bytes(
    hsm: &SimHsm,
    key_id: &str,
    expected_bytes: usize,
) -> Result<Vec<u8>, HsmError> {
    let ext = match expected_bytes {
        16 => "aes128.bin",
        32 => "bin",
        _ => {
            return Err(HsmError::CryptoError(format!(
                "unsupported AES key size: {expected_bytes}"
            )));
        }
    };
    let path = hsm.keys_dir().join(format!("{key_id}.{ext}"));
    let key = std::fs::read(&path)
        .map_err(|e| HsmError::KeystoreError(format!("read {}: {e}", path.display())))?;
    if key.len() != expected_bytes {
        return Err(HsmError::CryptoError(format!(
            "AES-{} key must be {expected_bytes} bytes, got {}",
            expected_bytes * 8,
            key.len()
        )));
    }
    Ok(key)
}

fn load_hmac_key(hsm: &SimHsm, key_id: &str) -> Result<Vec<u8>, HsmError> {
    let path = hsm.keys_dir().join(format!("{key_id}.hmac256.bin"));
    let key = std::fs::read(&path)
        .map_err(|e| HsmError::KeystoreError(format!("read {}: {e}", path.display())))?;
    if key.is_empty() {
        return Err(HsmError::CryptoError("HMAC key is empty".into()));
    }
    Ok(key)
}

fn load_ed25519_signing_key(
    hsm: &SimHsm,
    key_id: &str,
) -> Result<ed25519_dalek::SigningKey, HsmError> {
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    let priv_path = hsm.keys_dir().join(format!("{key_id}.ed25519.priv"));
    let pem = std::fs::read_to_string(&priv_path)
        .map_err(|e| HsmError::KeystoreError(format!("read {}: {e}", priv_path.display())))?;
    ed25519_dalek::SigningKey::from_pkcs8_pem(&pem)
        .map_err(|e| HsmError::CryptoError(format!("invalid Ed25519 private key: {e}")))
}

fn load_ed25519_verifying_key(
    hsm: &SimHsm,
    key_id: &str,
) -> Result<ed25519_dalek::VerifyingKey, HsmError> {
    use ed25519_dalek::pkcs8::DecodePublicKey;
    let pub_path = hsm.keys_dir().join(format!("{key_id}.ed25519.pub"));
    let pem = std::fs::read_to_string(&pub_path)
        .map_err(|e| HsmError::KeystoreError(format!("read {}: {e}", pub_path.display())))?;
    ed25519_dalek::VerifyingKey::from_public_key_pem(&pem)
        .map_err(|e| HsmError::CryptoError(format!("invalid Ed25519 public key: {e}")))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim::SimHsm;
    use crate::HsmCryptoProvider;
    use std::path::PathBuf;
    use tempfile::TempDir;

    const ALG_AES_128: u32 = 0x0001;
    const ALG_AES_256: u32 = 0x0002;
    const ALG_HMAC_SHA256: u32 = 0x0010;
    const ALG_ED25519: u32 = 0x0020;
    const ALG_ECC_P256: u32 = 0x0021;

    fn new_hsm() -> (SimHsm, TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let keystore = PathBuf::from(tmp.path());
        let hsm = SimHsm::new(PathBuf::from("unused"), keystore, 0);
        (hsm, tmp)
    }

    #[test]
    fn generate_key_aes256_produces_usable_key() {
        let (hsm, _tmp) = new_hsm();

        let pk = hsm.generate_key("k-aes", ALG_AES_256).unwrap();
        assert!(pk.is_empty(), "AES is symmetric, no public key");

        // get_key_info must find it via disk fallback (no manifest entry)
        let info = hsm.get_key_info("k-aes").unwrap();
        assert_eq!(info.key_type, KeyType::Aes256);

        // encrypt+decrypt round-trip
        let pt = b"hello generate_key";
        let ct = hsm.encrypt("k-aes", pt).unwrap();
        let rt = hsm.decrypt("k-aes", &ct).unwrap();
        assert_eq!(rt, pt);

        // mac-generate must now work (was failing with CRYPTO_ERROR before the fix)
        let mac = hsm.mac_generate("k-aes", pt).unwrap();
        assert_eq!(mac.len(), 16, "AES-CMAC tag is 16 bytes");
        assert!(hsm.mac_verify("k-aes", pt, &mac).unwrap());
    }

    #[test]
    fn generate_key_ecc_p256_returns_spki_and_signs() {
        let (hsm, _tmp) = new_hsm();

        let spki = hsm.generate_key("k-ec", ALG_ECC_P256).unwrap();
        assert!(!spki.is_empty(), "EC must return public key DER");
        // SubjectPublicKeyInfo starts with SEQUENCE (0x30)
        assert_eq!(spki[0], 0x30, "SPKI should be ASN.1 SEQUENCE");

        let info = hsm.get_key_info("k-ec").unwrap();
        assert_eq!(info.key_type, KeyType::EcP256);

        // get_public_key_der returns the same SPKI bytes
        let spki_via_getter = hsm.get_public_key_der("k-ec").unwrap();
        assert_eq!(spki, spki_via_getter);

        // sign+verify round-trip. SimHsm impls both HsmProvider and
        // HsmCryptoProvider, both with `sign`/`verify`; UFCS picks
        // the crypto trait explicitly.
        let digest = [0xAA_u8; 32];
        let sig = HsmCryptoProvider::sign(&hsm, "k-ec", &digest).unwrap();
        assert!(HsmCryptoProvider::verify(&hsm, "k-ec", &digest, &sig).unwrap());
    }

    #[test]
    fn generate_key_rejects_unsupported_alg() {
        let (hsm, _tmp) = new_hsm();
        // 0x0099 isn't on the wire; should be rejected with NotSupported.
        let err = hsm.generate_key("k-bogus", 0x0099).unwrap_err();
        assert!(matches!(err, HsmError::NotSupported(_)), "got {err:?}");
    }

    #[test]
    fn generate_csr_produces_a_ca_consumable_pkcs10() {
        let (hsm, _tmp) = new_hsm();
        let kid = crate::KeyRole::TlsIdentity.key_id();
        hsm.generate_key(kid, ALG_ECC_P256).unwrap();
        let csr_der = hsm.generate_csr(kid, "node-7").unwrap();

        // Parse as PKCS#10 and verify proof-of-possession exactly as the Tower
        // CA's parse_and_verify_csr does: reserialize the request info, verify
        // the self-signature. Round-trips by construction (both sides x509-cert).
        use x509_cert::der::{Decode, Encode};
        use x509_cert::request::CertReq;
        let csr = CertReq::from_der(&csr_der).expect("CSR must parse as PKCS#10");
        let info_der = csr.info.to_der().unwrap();
        let csr_point = csr.info.public_key.subject_public_key.as_bytes().unwrap();

        // Verify proof-of-possession the same way the Tower CA does: the
        // self-signature over the (reserialized) request info verifies against
        // the CSR's own key.
        use p256::ecdsa::signature::Verifier;
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(csr_point).unwrap();
        let sig =
            ecdsa::der::Signature::<p256::NistP256>::try_from(csr.signature.as_bytes().unwrap())
                .unwrap();
        vk.verify(&info_der, &sig)
            .expect("CSR self-signature (POP) must verify");

        // The CSR carries this slot's key + the CN we asked for.
        let slot_spki = hsm.get_public_key_der(kid).unwrap();
        assert_eq!(
            csr_point,
            &slot_spki[slot_spki.len() - 65..],
            "CSR public key must be the slot's key"
        );
        assert!(format!("{}", csr.info.subject).contains("node-7"));
    }

    #[test]
    fn generate_key_ed25519_signs_and_verifies() {
        let (hsm, _tmp) = new_hsm();

        let spki = hsm.generate_key("k-ed", ALG_ED25519).unwrap();
        assert!(!spki.is_empty(), "Ed25519 must return public key DER");
        assert_eq!(spki[0], 0x30, "SPKI should be ASN.1 SEQUENCE");

        let info = hsm.get_key_info("k-ed").unwrap();
        assert_eq!(info.key_type, KeyType::Ed25519);

        // get_public_key_der returns the same SPKI bytes
        let spki_via_getter = hsm.get_public_key_der("k-ed").unwrap();
        assert_eq!(spki, spki_via_getter);

        // Ed25519 produces a fixed-size 64-byte signature.
        let msg = b"hello ed25519 from SimHsm";
        let sig = HsmCryptoProvider::sign(&hsm, "k-ed", msg).unwrap();
        assert_eq!(sig.len(), 64, "Ed25519 signatures are 64 bytes");
        assert!(HsmCryptoProvider::verify(&hsm, "k-ed", msg, &sig).unwrap());

        // Tampered message must not verify
        let bad = b"hello ed25519 from SimHsm!";
        assert!(!HsmCryptoProvider::verify(&hsm, "k-ed", bad, &sig).unwrap());
    }

    #[test]
    fn generate_key_aes128_encrypts_decrypts_and_macs() {
        let (hsm, _tmp) = new_hsm();
        let pk = hsm.generate_key("k-aes128", ALG_AES_128).unwrap();
        assert!(pk.is_empty(), "symmetric — no public material");

        let info = hsm.get_key_info("k-aes128").unwrap();
        assert_eq!(info.key_type, KeyType::Aes128);

        let pt = b"AES-128 round trip";
        let ct = hsm.encrypt("k-aes128", pt).unwrap();
        let rt = hsm.decrypt("k-aes128", &ct).unwrap();
        assert_eq!(rt, pt);

        // CMAC-AES128 tag is 16 bytes (one AES block)
        let mac = hsm.mac_generate("k-aes128", pt).unwrap();
        assert_eq!(mac.len(), 16);
        assert!(hsm.mac_verify("k-aes128", pt, &mac).unwrap());
    }

    #[test]
    fn generate_key_hmac_sha256_macs_and_verifies() {
        let (hsm, _tmp) = new_hsm();
        let pk = hsm.generate_key("k-hmac", ALG_HMAC_SHA256).unwrap();
        assert!(pk.is_empty(), "symmetric — no public material");

        let info = hsm.get_key_info("k-hmac").unwrap();
        assert_eq!(info.key_type, KeyType::HmacSha256);

        let data = b"hmac-sha256 round trip";
        let tag = hsm.mac_generate("k-hmac", data).unwrap();
        assert_eq!(tag.len(), 32, "HMAC-SHA256 tag is 32 bytes");
        assert!(hsm.mac_verify("k-hmac", data, &tag).unwrap());

        // Tampered data must not verify
        assert!(!hsm.mac_verify("k-hmac", b"different", &tag).unwrap());
    }

    #[test]
    fn encrypt_rejects_non_aes_keys() {
        let (hsm, _tmp) = new_hsm();
        hsm.generate_key("k-ed", ALG_ED25519).unwrap();
        let err = hsm.encrypt("k-ed", b"data").unwrap_err();
        assert!(matches!(err, HsmError::CryptoError(_)), "got {err:?}");
    }

    #[test]
    fn sign_rejects_symmetric_keys() {
        let (hsm, _tmp) = new_hsm();
        hsm.generate_key("k-aes", ALG_AES_256).unwrap();
        let err = HsmCryptoProvider::sign(&hsm, "k-aes", b"data").unwrap_err();
        assert!(matches!(err, HsmError::CryptoError(_)), "got {err:?}");
    }

    #[test]
    fn mac_rejects_asymmetric_keys() {
        let (hsm, _tmp) = new_hsm();
        hsm.generate_key("k-ec", ALG_ECC_P256).unwrap();
        let err = hsm.mac_generate("k-ec", b"data").unwrap_err();
        assert!(matches!(err, HsmError::CryptoError(_)), "got {err:?}");
    }

    #[test]
    fn generate_key_creates_files_in_keystore() {
        let (hsm, _tmp) = new_hsm();
        hsm.generate_key("sym256", ALG_AES_256).unwrap();
        hsm.generate_key("sym128", ALG_AES_128).unwrap();
        hsm.generate_key("hmac", ALG_HMAC_SHA256).unwrap();
        hsm.generate_key("asym-ec", ALG_ECC_P256).unwrap();
        hsm.generate_key("asym-ed", ALG_ED25519).unwrap();

        assert!(hsm.keys_dir().join("sym256.bin").exists());
        assert!(hsm.keys_dir().join("sym128.aes128.bin").exists());
        assert!(hsm.keys_dir().join("hmac.hmac256.bin").exists());
        assert!(hsm.keys_dir().join("asym-ec.priv").exists());
        assert!(hsm.keys_dir().join("asym-ec.pub").exists());
        assert!(hsm.keys_dir().join("asym-ed.ed25519.priv").exists());
        assert!(hsm.keys_dir().join("asym-ed.ed25519.pub").exists());

        // File-size invariants we rely on at load time
        assert_eq!(
            std::fs::read(hsm.keys_dir().join("sym256.bin"))
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            std::fs::read(hsm.keys_dir().join("sym128.aes128.bin"))
                .unwrap()
                .len(),
            16
        );
        assert_eq!(
            std::fs::read(hsm.keys_dir().join("hmac.hmac256.bin"))
                .unwrap()
                .len(),
            32
        );
    }

    #[test]
    fn aes256_gcm_decrypt_rejects_tampered_ciphertext() {
        let (hsm, _tmp) = new_hsm();
        hsm.generate_key("k-aes", ALG_AES_256).unwrap();
        let pt = b"some plaintext that needs an auth tag";
        let mut ct = hsm.encrypt("k-aes", pt).unwrap();

        // Flip a byte in the ciphertext (not the 12-byte nonce prefix).
        // AES-GCM's auth tag MUST reject this.
        ct[15] ^= 0x01;
        let err = hsm.decrypt("k-aes", &ct).unwrap_err();
        assert!(matches!(err, HsmError::CryptoError(_)), "got {err:?}");
    }

    #[test]
    fn aes128_gcm_decrypt_rejects_tampered_ciphertext() {
        let (hsm, _tmp) = new_hsm();
        hsm.generate_key("k-aes128", ALG_AES_128).unwrap();
        let pt = b"aes-128 plaintext for tamper test";
        let mut ct = hsm.encrypt("k-aes128", pt).unwrap();
        ct[15] ^= 0x01;
        let err = hsm.decrypt("k-aes128", &ct).unwrap_err();
        assert!(matches!(err, HsmError::CryptoError(_)), "got {err:?}");
    }

    #[test]
    fn hmac_sha256_verify_rejects_bad_tag() {
        let (hsm, _tmp) = new_hsm();
        hsm.generate_key("k-hmac", ALG_HMAC_SHA256).unwrap();
        let data = b"data with mac";
        let mut tag = hsm.mac_generate("k-hmac", data).unwrap();
        tag[0] ^= 0x01; // flip one bit
        assert!(!hsm.mac_verify("k-hmac", data, &tag).unwrap());
    }

    #[test]
    fn aes256_cmac_verify_rejects_bad_tag() {
        let (hsm, _tmp) = new_hsm();
        hsm.generate_key("k-aes", ALG_AES_256).unwrap();
        let data = b"cmac round trip data";
        let mut tag = hsm.mac_generate("k-aes", data).unwrap();
        tag[0] ^= 0x01;
        assert!(!hsm.mac_verify("k-aes", data, &tag).unwrap());
    }

    #[test]
    fn aes128_cmac_roundtrip_and_rejects_bad_tag() {
        let (hsm, _tmp) = new_hsm();
        hsm.generate_key("k-aes128", ALG_AES_128).unwrap();
        let data = b"cmac aes-128 data";
        let tag = hsm.mac_generate("k-aes128", data).unwrap();
        assert_eq!(tag.len(), 16, "CMAC-AES128 tag is 16 bytes");
        assert!(hsm.mac_verify("k-aes128", data, &tag).unwrap());
        let mut bad = tag.clone();
        bad[0] ^= 0x01;
        assert!(!hsm.mac_verify("k-aes128", data, &bad).unwrap());
    }

    #[test]
    fn hkdf_derive_is_deterministic_per_key_and_context() {
        let (hsm, _tmp) = new_hsm();
        hsm.generate_key("k-aes", ALG_AES_256).unwrap();
        let a = hsm.derive("k-aes", b"info-a", 32).unwrap();
        let b = hsm.derive("k-aes", b"info-a", 32).unwrap();
        let c = hsm.derive("k-aes", b"info-b", 32).unwrap();
        assert_eq!(a.len(), 32);
        assert_eq!(a, b, "same key+context must produce same output");
        assert_ne!(a, c, "different context must produce different output");
    }

    #[test]
    fn hkdf_derive_works_for_all_symmetric_key_types() {
        let (hsm, _tmp) = new_hsm();
        hsm.generate_key("k-aes256", ALG_AES_256).unwrap();
        hsm.generate_key("k-aes128", ALG_AES_128).unwrap();
        hsm.generate_key("k-hmac", ALG_HMAC_SHA256).unwrap();
        for key in ["k-aes256", "k-aes128", "k-hmac"] {
            let okm = hsm.derive(key, b"info", 48).unwrap();
            assert_eq!(okm.len(), 48, "derive({key}) wrong length");
        }
    }

    #[test]
    fn hkdf_derive_rejects_asymmetric_keys() {
        let (hsm, _tmp) = new_hsm();
        hsm.generate_key("k-ec", ALG_ECC_P256).unwrap();
        hsm.generate_key("k-ed", ALG_ED25519).unwrap();
        for key in ["k-ec", "k-ed"] {
            let err = hsm.derive(key, b"info", 32).unwrap_err();
            assert!(
                matches!(err, HsmError::CryptoError(_)),
                "{key}: got {err:?}"
            );
        }
    }

    #[test]
    fn ed25519_verify_rejects_tampered_signature() {
        let (hsm, _tmp) = new_hsm();
        hsm.generate_key("k-ed", ALG_ED25519).unwrap();
        let msg = b"ed25519 negative-verify message";
        let mut sig = HsmCryptoProvider::sign(&hsm, "k-ed", msg).unwrap();
        sig[0] ^= 0x01;
        assert!(!HsmCryptoProvider::verify(&hsm, "k-ed", msg, &sig).unwrap());
    }

    #[test]
    fn ed25519_verify_rejects_wrong_length_signature() {
        let (hsm, _tmp) = new_hsm();
        hsm.generate_key("k-ed", ALG_ED25519).unwrap();
        // Ed25519 signatures must be exactly 64 bytes.
        let too_short = vec![0u8; 63];
        let err = HsmCryptoProvider::verify(&hsm, "k-ed", b"x", &too_short).unwrap_err();
        assert!(matches!(err, HsmError::CryptoError(_)), "got {err:?}");
    }

    #[test]
    fn ed25519_get_public_key_der_returns_spki() {
        let (hsm, _tmp) = new_hsm();
        let spki_from_keygen = hsm.generate_key("k-ed", ALG_ED25519).unwrap();
        let spki_via_getter = hsm.get_public_key_der("k-ed").unwrap();
        assert_eq!(
            spki_from_keygen, spki_via_getter,
            "keygen + getter must agree"
        );
        assert_eq!(spki_via_getter[0], 0x30, "SPKI must be ASN.1 SEQUENCE");
        // Ed25519 SPKI is 44 bytes — 12-byte AlgorithmIdentifier + 32-byte pub.
        assert!(
            spki_via_getter.len() >= 40 && spki_via_getter.len() <= 50,
            "Ed25519 SPKI length should be ~44, got {}",
            spki_via_getter.len()
        );
    }

    #[test]
    fn get_key_info_falls_back_to_disk_when_not_provisioned() {
        let (hsm, _tmp) = new_hsm();
        // HSM is not provisioned — but generate_key still creates disk files.
        assert!(!hsm.is_provisioned().unwrap());
        hsm.generate_key("dyn", ALG_AES_256).unwrap();

        let info = hsm.get_key_info("dyn").unwrap();
        assert_eq!(info.key_id, "dyn");
        assert_eq!(info.key_type, KeyType::Aes256);
    }

    #[test]
    fn get_key_info_key_not_found_still_errors() {
        let (hsm, _tmp) = new_hsm();
        let err = hsm.get_key_info("never-generated").unwrap_err();
        // Not provisioned and key not on disk
        assert!(
            matches!(err, HsmError::NotProvisioned | HsmError::KeyNotFound(_)),
            "got {err:?}"
        );
    }
}
