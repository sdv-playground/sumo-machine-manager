//! Cert + identity-key + bootstrap-token persistence for the guest handshake.
//!
//! The daemon owns three small files on its local writable storage:
//!
//! | File | Format | Perms |
//! |---|---|---|
//! | cert | raw CWT bytes (COSE_Sign1 ~200B) | 0644 |
//! | identity key | raw 32-byte P-256 scalar (`d`) | 0600 |
//! | bootstrap token | raw 32 random bytes (single-use, deleted after ENROLL) | 0600 |
//!
//! Layouts are minimal-by-design: no headers, no length prefixes. The files
//! exist or they don't; their lengths are checked at load time. Any divergence
//! (truncation, corruption) is a hard error. Saves are atomic via tmp+rename.

use std::fs::{self, File};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use p256::ecdsa::SigningKey;

/// Bytes in a raw P-256 private scalar.
pub const IDENTITY_KEY_LEN: usize = 32;

/// Bytes in the bootstrap token. Matches `sumo-offboard::bootstrap` and
/// `vhsm-ssd::bootstrap` so the off-box and on-box sides agree.
pub const BOOTSTRAP_TOKEN_LEN: usize = 32;

/// File-paths and the principal name needed by the handshake layer.
///
/// `vm_id` is consulted only during ENROLL. During AUTH the principal name
/// comes from the cert's `sub` claim, not from this struct.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub cert_path: PathBuf,
    pub identity_key_path: PathBuf,
    pub bootstrap_token_path: PathBuf,
    pub vm_id: String,
}

impl AuthConfig {
    /// Common deployment layout: all three files live in `<dir>`.
    pub fn in_dir(dir: impl AsRef<Path>, vm_id: impl Into<String>) -> Self {
        let dir = dir.as_ref();
        Self {
            cert_path: dir.join("vhsm-cert.cwt"),
            identity_key_path: dir.join("vhsm-identity.key"),
            bootstrap_token_path: dir.join("vhsm-bootstrap.token"),
            vm_id: vm_id.into(),
        }
    }
}

/// Load a persisted CWT cert from disk. `None` if the file doesn't exist
/// (signal that ENROLL is required).
pub fn load_cert(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(b) if b.is_empty() => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("cert file {} is empty", path.display()),
        )),
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Save a CWT cert atomically (tmp+rename). 0644 perms — the cert is not
/// sensitive; the identity key is.
pub fn save_cert(path: &Path, cwt: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("cwt.tmp");
    {
        let mut f = File::create(&tmp)?;
        f.write_all(cwt)?;
        f.sync_data()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Load the persisted identity key (raw 32-byte P-256 scalar) and reconstruct a
/// `SigningKey`. `None` if the file doesn't exist (paired with `load_cert ==
/// None` is the ENROLL signal).
pub fn load_identity_key(path: &Path) -> io::Result<Option<SigningKey>> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if bytes.len() != IDENTITY_KEY_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "identity key length {} != expected {}",
                bytes.len(),
                IDENTITY_KEY_LEN
            ),
        ));
    }
    SigningKey::from_bytes(bytes.as_slice().into())
        .map(Some)
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("identity key not on the P-256 curve: {e}"),
            )
        })
}

/// Save the identity key atomically with 0600 perms on unix.
pub fn save_identity_key(path: &Path, sk: &SigningKey) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("key.tmp");
    {
        let mut f = File::create(&tmp)?;
        let raw = sk.to_bytes();
        f.write_all(&raw)?;
        f.sync_data()?;
    }
    set_owner_only_perms(&tmp)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Load the single-use bootstrap token. `None` if it doesn't exist.
pub fn load_bootstrap_token(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(b) if b.len() != BOOTSTRAP_TOKEN_LEN => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "bootstrap token length {} != expected {}",
                b.len(),
                BOOTSTRAP_TOKEN_LEN
            ),
        )),
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Delete the bootstrap-token file after a successful ENROLL so the next boot
/// can't replay it. "Not found" is converted to `Ok(())` (goal-state met).
pub fn delete_bootstrap_token(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Generate a fresh P-256 identity key pair. Returns `(SigningKey, x, y)` where
/// `x`/`y` are the SEC1 coordinates of the verifying key.
pub fn generate_identity_keypair() -> (SigningKey, [u8; 32], [u8; 32]) {
    let sk = SigningKey::random(&mut rand::thread_rng());
    let vk = sk.verifying_key();
    let p = vk.to_encoded_point(false);
    let bytes = p.as_bytes();
    debug_assert_eq!(bytes.len(), 65);
    debug_assert_eq!(bytes[0], 0x04);
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&bytes[1..33]);
    y.copy_from_slice(&bytes[33..65]);
    (sk, x, y)
}

#[cfg(unix)]
fn set_owner_only_perms(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_owner_only_perms(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn missing_cert_returns_none() {
        let t = tempdir().unwrap();
        let path = t.path().join("nope.cwt");
        assert!(load_cert(&path).unwrap().is_none());
    }

    #[test]
    fn empty_cert_file_is_invalid() {
        let t = tempdir().unwrap();
        let path = t.path().join("empty.cwt");
        fs::write(&path, b"").unwrap();
        let err = load_cert(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn save_then_load_cert_round_trips() {
        let t = tempdir().unwrap();
        let path = t.path().join("cert.cwt");
        let bytes = vec![0xAB; 200];
        save_cert(&path, &bytes).unwrap();
        let read = load_cert(&path).unwrap().unwrap();
        assert_eq!(read, bytes);
    }

    #[test]
    fn save_cert_is_atomic_no_tmp_leftover() {
        let t = tempdir().unwrap();
        let path = t.path().join("cert.cwt");
        save_cert(&path, &[0u8; 64]).unwrap();
        let tmp = path.with_extension("cwt.tmp");
        assert!(!tmp.exists(), "tmp file should not be left after rename");
    }

    #[test]
    fn save_then_load_identity_key_round_trips() {
        let t = tempdir().unwrap();
        let path = t.path().join("id.key");
        let (sk, _, _) = generate_identity_keypair();
        save_identity_key(&path, &sk).unwrap();
        let loaded = load_identity_key(&path).unwrap().unwrap();
        assert_eq!(sk.to_bytes(), loaded.to_bytes());
    }

    #[test]
    #[cfg(unix)]
    fn identity_key_file_is_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let t = tempdir().unwrap();
        let path = t.path().join("id.key");
        let (sk, _, _) = generate_identity_keypair();
        save_identity_key(&path, &sk).unwrap();
        let meta = fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {:o}", mode);
    }

    #[test]
    fn identity_key_wrong_length_rejected() {
        let t = tempdir().unwrap();
        let path = t.path().join("bad.key");
        fs::write(&path, b"too short").unwrap();
        let err = load_identity_key(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn bootstrap_token_wrong_length_rejected() {
        let t = tempdir().unwrap();
        let path = t.path().join("bad.token");
        fs::write(&path, &[0u8; 16][..]).unwrap();
        let err = load_bootstrap_token(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn delete_bootstrap_token_idempotent() {
        let t = tempdir().unwrap();
        let path = t.path().join("token");
        delete_bootstrap_token(&path).unwrap();
        fs::write(&path, &[0u8; BOOTSTRAP_TOKEN_LEN][..]).unwrap();
        assert!(path.exists());
        delete_bootstrap_token(&path).unwrap();
        assert!(!path.exists());
        delete_bootstrap_token(&path).unwrap();
    }

    #[test]
    fn generated_key_pubkey_matches_signer_pub() {
        let (sk, x, y) = generate_identity_keypair();
        let vk = sk.verifying_key();
        let p = vk.to_encoded_point(false);
        let bytes = p.as_bytes();
        assert_eq!(&bytes[1..33], &x);
        assert_eq!(&bytes[33..65], &y);
    }

    #[test]
    fn in_dir_constructs_standard_paths() {
        let cfg = AuthConfig::in_dir("/persist/vhsm", "vm9");
        assert_eq!(cfg.cert_path, PathBuf::from("/persist/vhsm/vhsm-cert.cwt"));
        assert_eq!(
            cfg.identity_key_path,
            PathBuf::from("/persist/vhsm/vhsm-identity.key")
        );
        assert_eq!(
            cfg.bootstrap_token_path,
            PathBuf::from("/persist/vhsm/vhsm-bootstrap.token")
        );
        assert_eq!(cfg.vm_id, "vm9");
    }
}
