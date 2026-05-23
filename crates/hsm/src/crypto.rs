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
use aes_gcm::{Aes256Gcm, Nonce};
use ecdsa::signature::Signer;
use ecdsa::signature::Verifier;
use hkdf::Hkdf;
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand::RngCore;
use sha2::Sha256;

impl HsmCryptoProvider for SimHsm {
    fn sign(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        let key_info = self.get_key_info(key_id)?;
        if key_info.key_type != KeyType::EcP256 {
            return Err(HsmError::CryptoError(format!(
                "sign requires EC-P256 key, got {}",
                key_info.key_type
            )));
        }

        let scalar = load_ec_private_scalar(self, key_id)?;
        let signing_key = SigningKey::from_bytes((&scalar[..]).into())
            .map_err(|e| HsmError::CryptoError(format!("invalid signing key: {e}")))?;

        let signature: ecdsa::der::Signature<p256::NistP256> = signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
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
        if key_info.key_type != KeyType::EcP256 {
            return Err(HsmError::CryptoError(format!(
                "verify requires EC-P256 key, got {}",
                key_info.key_type
            )));
        }

        let verifying_key = load_ec_verifying_key(self, key_id)?;
        let sig = ecdsa::der::Signature::<p256::NistP256>::from_bytes(signature)
            .map_err(|e| HsmError::CryptoError(format!("invalid signature: {e}")))?;

        match verifying_key.verify(data, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn encrypt(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, HsmError> {
        let key_info = self.get_key_info(key_id)?;
        if key_info.key_type != KeyType::Aes256 {
            return Err(HsmError::CryptoError(format!(
                "encrypt requires AES-256 key, got {}",
                key_info.key_type
            )));
        }

        let raw_key = load_aes_key(self, key_id)?;
        let cipher = Aes256Gcm::new_from_slice(&raw_key)
            .map_err(|e| HsmError::CryptoError(format!("invalid AES key: {e}")))?;

        let mut iv_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut iv_bytes);
        let nonce = Nonce::from_slice(&iv_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| HsmError::CryptoError(format!("AES-GCM encrypt: {e}")))?;

        // Return iv(12) || ciphertext || tag (tag is appended by aes-gcm)
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&iv_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn decrypt(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        let key_info = self.get_key_info(key_id)?;
        if key_info.key_type != KeyType::Aes256 {
            return Err(HsmError::CryptoError(format!(
                "decrypt requires AES-256 key, got {}",
                key_info.key_type
            )));
        }

        if data.len() < 12 + 16 {
            return Err(HsmError::CryptoError(
                "ciphertext too short (need at least iv + tag)".into(),
            ));
        }

        let raw_key = load_aes_key(self, key_id)?;
        let cipher = Aes256Gcm::new_from_slice(&raw_key)
            .map_err(|e| HsmError::CryptoError(format!("invalid AES key: {e}")))?;

        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext_and_tag = &data[12..];

        cipher
            .decrypt(nonce, ciphertext_and_tag)
            .map_err(|e| HsmError::CryptoError(format!("AES-GCM decrypt: {e}")))
    }

    fn mac_generate(&self, key_id: &str, data: &[u8]) -> Result<Vec<u8>, HsmError> {
        use cmac::{Cmac, Mac};

        let key_info = self.get_key_info(key_id)?;
        if key_info.key_type != KeyType::Aes256 {
            return Err(HsmError::CryptoError(format!(
                "mac_generate requires AES-256 key, got {}", key_info.key_type
            )));
        }

        let raw_key = load_aes_key(self, key_id)?;
        let mut mac = <Cmac<aes::Aes256> as Mac>::new_from_slice(&raw_key)
            .map_err(|e| HsmError::CryptoError(format!("invalid AES key for CMAC: {e}")))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    fn mac_verify(&self, key_id: &str, data: &[u8], tag: &[u8]) -> Result<bool, HsmError> {
        use cmac::{Cmac, Mac};

        let key_info = self.get_key_info(key_id)?;
        if key_info.key_type != KeyType::Aes256 {
            return Err(HsmError::CryptoError(format!(
                "mac_verify requires AES-256 key, got {}", key_info.key_type
            )));
        }

        let raw_key = load_aes_key(self, key_id)?;
        let mut mac = <Cmac<aes::Aes256> as Mac>::new_from_slice(&raw_key)
            .map_err(|e| HsmError::CryptoError(format!("invalid AES key for CMAC: {e}")))?;
        mac.update(data);
        Ok(mac.verify_slice(tag).is_ok())
    }

    fn derive(&self, key_id: &str, context: &[u8], len: usize) -> Result<Vec<u8>, HsmError> {
        let key_info = self.get_key_info(key_id)?;
        if key_info.key_type != KeyType::Aes256 {
            return Err(HsmError::CryptoError(format!(
                "derive requires AES-256 key, got {}",
                key_info.key_type
            )));
        }

        let raw_key = load_aes_key(self, key_id)?;
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
        if key_info.key_type != KeyType::EcP256 {
            return Err(HsmError::CryptoError(format!(
                "get_public_key_der requires EC-P256 key, got {}",
                key_info.key_type
            )));
        }

        let pub_path = self.keys_dir().join(format!("{key_id}.pub"));
        let pem = std::fs::read_to_string(&pub_path)
            .map_err(|e| HsmError::KeystoreError(format!("read {}: {e}", pub_path.display())))?;
        decode_pem(&pem, "PUBLIC KEY")
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
        //   `{key_id}.bin`  → AES-256
        //   `{key_id}.priv` → EC-P256
        let aes_path = self.keys_dir().join(format!("{key_id}.bin"));
        if aes_path.exists() {
            return Ok(KeyInfo {
                key_id: key_id.to_string(),
                key_type: KeyType::Aes256,
                has_certificate: false,
                allowed_guests: None,
                allowed_ops: None,
            });
        }
        let ec_priv_path = self.keys_dir().join(format!("{key_id}.priv"));
        if ec_priv_path.exists() {
            return Ok(KeyInfo {
                key_id: key_id.to_string(),
                key_type: KeyType::EcP256,
                has_certificate: false,
                allowed_guests: None,
                allowed_ops: None,
            });
        }

        if !self.is_provisioned().unwrap_or(false) {
            return Err(HsmError::NotProvisioned);
        }
        Err(HsmError::KeyNotFound(key_id.to_string()))
    }

    fn generate_key(&self, key_id: &str, alg: u32) -> Result<Vec<u8>, HsmError> {
        // Algorithm constants mirror vHSM wire protocol (vhsm_proto.h /
        // vhsm-ssd/src/proto.rs). Keep in sync.
        const ALG_AES_256: u32 = 0x0002;
        const ALG_ECC_P256: u32 = 0x0021;

        std::fs::create_dir_all(self.keys_dir())
            .map_err(|e| HsmError::KeystoreError(format!("create keys dir: {e}")))?;

        match alg {
            ALG_AES_256 => {
                // `load_aes_key` requires a 32-byte key; AES-128 isn't
                // supported end-to-end in this backend, reject it explicitly.
                let mut key = vec![0u8; 32];
                OsRng.fill_bytes(&mut key);
                let path = self.keys_dir().join(format!("{key_id}.bin"));
                std::fs::write(&path, &key).map_err(|e| {
                    HsmError::KeystoreError(format!("write {}: {e}", path.display()))
                })?;
                // Symmetric — no public material to return.
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
        let verifying_key = signing_key.verifying_key();
        let pub_point = verifying_key.to_encoded_point(false);

        build_pkcs10_csr(subject_cn, pub_point.as_bytes(), &signing_key)
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

fn load_ec_verifying_key(
    hsm: &SimHsm,
    key_id: &str,
) -> Result<VerifyingKey, HsmError> {
    let pub_path = hsm.keys_dir().join(format!("{key_id}.pub"));
    let pem = std::fs::read_to_string(&pub_path)
        .map_err(|e| HsmError::KeystoreError(format!("read {}: {e}", pub_path.display())))?;
    let der = decode_pem(&pem, "PUBLIC KEY")?;
    VerifyingKey::from_sec1_bytes(&der[der.len() - 65..])
        .map_err(|e| HsmError::CryptoError(format!("invalid verifying key: {e}")))
}

/// Build a PKCS#10 CertificationRequest (CSR) DER for EC-P256.
///
/// Structure:
///   SEQUENCE {
///     CertificationRequestInfo ::= SEQUENCE {
///       version INTEGER 0
///       subject Name (SEQUENCE { SET { SEQUENCE { OID cn, UTF8String } } })
///       subjectPKInfo SubjectPublicKeyInfo
///       attributes [0] (empty)
///     }
///     signatureAlgorithm AlgorithmIdentifier (ecdsa-with-SHA256)
///     signature BIT STRING
///   }
fn build_pkcs10_csr(
    cn: &str,
    public_key_uncompressed: &[u8], // 65 bytes (0x04 || x || y)
    signing_key: &SigningKey,
) -> Result<Vec<u8>, HsmError> {
    // --- Build CertificationRequestInfo ---
    let mut cri = Vec::with_capacity(256);

    // version INTEGER 0
    cri.extend_from_slice(&[0x02, 0x01, 0x00]);

    // subject: Name = SEQUENCE { SET { SEQUENCE { OID 2.5.4.3 (cn), UTF8String } } }
    let cn_bytes = cn.as_bytes();
    let cn_oid: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03]; // OID 2.5.4.3
    let cn_val_tag: &[u8] = &[0x0C]; // UTF8String tag
    // inner SEQUENCE: OID + UTF8String
    let inner_seq_len = cn_oid.len() + 1 + der_len_size(cn_bytes.len()) + cn_bytes.len();
    // SET wrapping inner SEQUENCE
    let set_len = 1 + der_len_size(inner_seq_len) + inner_seq_len;
    // outer SEQUENCE wrapping SET
    let name_len = 1 + der_len_size(set_len) + set_len;

    cri.push(0x30); // SEQUENCE (Name)
    push_der_len(&mut cri, name_len);
    cri.push(0x31); // SET
    push_der_len(&mut cri, inner_seq_len + 1 + der_len_size(inner_seq_len));
    cri.push(0x30); // SEQUENCE (AttributeTypeAndValue)
    push_der_len(&mut cri, inner_seq_len);
    cri.extend_from_slice(cn_oid);
    cri.push(cn_val_tag[0]);
    push_der_len(&mut cri, cn_bytes.len());
    cri.extend_from_slice(cn_bytes);

    // subjectPKInfo: SubjectPublicKeyInfo for EC-P256
    // SEQUENCE { SEQUENCE { OID ecPublicKey, OID P-256 }, BIT STRING { 0x00 || uncompressed } }
    let ec_pk_oid: &[u8] = &[
        0x30, 0x13, // SEQUENCE (AlgorithmIdentifier)
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // OID ecPublicKey
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // OID P-256
    ];
    let bit_string_len = 1 + public_key_uncompressed.len(); // 0x00 padding + key
    let spki_inner_len = ec_pk_oid.len() + 1 + der_len_size(bit_string_len) + bit_string_len;

    cri.push(0x30); // SEQUENCE (SubjectPublicKeyInfo)
    push_der_len(&mut cri, spki_inner_len);
    cri.extend_from_slice(ec_pk_oid);
    cri.push(0x03); // BIT STRING
    push_der_len(&mut cri, bit_string_len);
    cri.push(0x00); // no unused bits
    cri.extend_from_slice(public_key_uncompressed);

    // attributes [0] IMPLICIT (empty)
    cri.extend_from_slice(&[0xA0, 0x00]);

    // Wrap CRI in SEQUENCE
    let mut cri_seq = Vec::with_capacity(cri.len() + 4);
    cri_seq.push(0x30);
    push_der_len(&mut cri_seq, cri.len());
    cri_seq.extend_from_slice(&cri);

    // --- Sign CRI ---
    let signature: ecdsa::der::Signature<p256::NistP256> = signing_key.sign(&cri_seq);
    let sig_bytes = signature.to_bytes();

    // --- Build outer CertificationRequest ---
    // signatureAlgorithm: ecdsa-with-SHA256
    let sig_alg: &[u8] = &[
        0x30, 0x0A, // SEQUENCE (AlgorithmIdentifier)
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, // OID ecdsa-with-SHA256
    ];

    let bit_sig_len = 1 + sig_bytes.len(); // 0x00 + DER signature
    let outer_len =
        cri_seq.len() + sig_alg.len() + 1 + der_len_size(bit_sig_len) + bit_sig_len;

    let mut csr = Vec::with_capacity(outer_len + 4);
    csr.push(0x30); // SEQUENCE (CertificationRequest)
    push_der_len(&mut csr, outer_len);
    csr.extend_from_slice(&cri_seq);
    csr.extend_from_slice(sig_alg);
    csr.push(0x03); // BIT STRING
    push_der_len(&mut csr, bit_sig_len);
    csr.push(0x00); // no unused bits
    csr.extend_from_slice(&sig_bytes);

    Ok(csr)
}

/// Size of a DER length encoding.
fn der_len_size(len: usize) -> usize {
    if len < 0x80 {
        1
    } else if len < 0x100 {
        2
    } else {
        3
    }
}

/// Push a DER length encoding.
fn push_der_len(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

fn load_aes_key(hsm: &SimHsm, key_id: &str) -> Result<Vec<u8>, HsmError> {
    let path = hsm.keys_dir().join(format!("{key_id}.bin"));
    let key = std::fs::read(&path)
        .map_err(|e| HsmError::KeystoreError(format!("read {}: {e}", path.display())))?;
    if key.len() != 32 {
        return Err(HsmError::CryptoError(format!(
            "AES key must be 32 bytes, got {}",
            key.len()
        )));
    }
    Ok(key)
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

    const ALG_AES_256: u32 = 0x0002;
    const ALG_ECC_P256: u32 = 0x0021;
    const ALG_ED25519: u32 = 0x0020;

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
        let err = hsm.generate_key("k-ed", ALG_ED25519).unwrap_err();
        assert!(matches!(err, HsmError::NotSupported(_)), "got {err:?}");
    }

    #[test]
    fn generate_key_creates_files_in_keystore() {
        let (hsm, _tmp) = new_hsm();
        hsm.generate_key("sym", ALG_AES_256).unwrap();
        hsm.generate_key("asym", ALG_ECC_P256).unwrap();

        assert!(hsm.keys_dir().join("sym.bin").exists());
        assert!(hsm.keys_dir().join("asym.priv").exists());
        assert!(hsm.keys_dir().join("asym.pub").exists());

        // .bin is exactly 32 bytes
        let aes_bytes = std::fs::read(hsm.keys_dir().join("sym.bin")).unwrap();
        assert_eq!(aes_bytes.len(), 32);
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
