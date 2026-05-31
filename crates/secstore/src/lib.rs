//! Encrypted key metadata persistence with pluggable backends.
//!
//! Two trait axes:
//! - [`SecstoreEncryptor`]: who encrypts (HSE on production, static key for dev)
//! - [`SecstoreBackend`]: where blobs live (filesystem, NOR flash, etc.)
//!
//! The generic [`FileBackend`] + any encryptor works on any POSIX system.
//! Board-specific crates (e.g. `hse-s32g3`) provide hardware encryptors.
//!
//! # What's Stored
//!
//! Key *metadata* only — not key material. The actual keys live in the HSE
//! (or file-based keystore in dev). Metadata maps opaque vhsm handles to
//! their backing key identity, algorithm, permissions, and ownership.
//!
//! # Concurrency
//!
//! The store is single-writer (vhsm-ssd daemon). Writes are atomic
//! (write-to-temp + rename) to survive power loss.

mod file_backend;
mod linux_encryptor;

pub use file_backend::FileBackend;
pub use linux_encryptor::LinuxSimEncryptor;

/// Encrypts/decrypts metadata blobs before storage.
///
/// Production: implemented by the board HSE crate (AES-GCM with HSE-held key).
/// Development: [`LinuxSimEncryptor`] uses a static key.
pub trait SecstoreEncryptor: Send + Sync {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecstoreError>;
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecstoreError>;
}

/// Persistent blob storage backend.
///
/// Default: [`FileBackend`] (std::fs, works on any POSIX).
/// Board-specific: NOR flash with wear leveling, secure RRAM, etc.
pub trait SecstoreBackend: Send + Sync {
    /// Read a blob by key. Returns None if not found.
    fn read(&self, key: &str) -> Result<Option<Vec<u8>>, SecstoreError>;

    /// Write a blob atomically (must survive power loss).
    fn write(&self, key: &str, data: &[u8]) -> Result<(), SecstoreError>;

    /// Delete a blob.
    fn delete(&self, key: &str) -> Result<(), SecstoreError>;

    /// List all stored keys.
    fn list(&self) -> Result<Vec<String>, SecstoreError>;
}

/// Key metadata record — serialized to/from the store.
#[derive(Debug, Clone)]
pub struct KeyMetadata {
    pub vhsm_handle: u32,
    pub key_id: String,
    pub algorithm: u32,
    pub permitted_ops: u32,
    /// VM identity that owns this dynamic handle. Empty string means
    /// the handle is shared (well-known) and accessible to any caller.
    pub owner_vm_id: String,
    pub persistent: bool,
    pub label: String,
}

/// Combined encrypted store: encryptor + backend.
pub struct Secstore<E: SecstoreEncryptor, B: SecstoreBackend> {
    encryptor: E,
    backend: B,
}

impl<E: SecstoreEncryptor, B: SecstoreBackend> Secstore<E, B> {
    pub fn new(encryptor: E, backend: B) -> Self {
        Self { encryptor, backend }
    }

    /// Store key metadata (encrypt then write).
    pub fn store(&self, meta: &KeyMetadata) -> Result<(), SecstoreError> {
        let plaintext = serialize_metadata(meta);
        let ciphertext = self.encryptor.encrypt(&plaintext)?;
        let key = format!("handle_{:08x}", meta.vhsm_handle);
        self.backend.write(&key, &ciphertext)
    }

    /// Load all stored key metadata (read then decrypt).
    pub fn load_all(&self) -> Result<Vec<KeyMetadata>, SecstoreError> {
        let keys = self.backend.list()?;
        let mut result = Vec::new();
        for key in keys {
            if let Some(ciphertext) = self.backend.read(&key)? {
                let plaintext = self.encryptor.decrypt(&ciphertext)?;
                if let Some(meta) = deserialize_metadata(&plaintext) {
                    result.push(meta);
                }
            }
        }
        Ok(result)
    }

    /// Delete key metadata.
    pub fn delete(&self, vhsm_handle: u32) -> Result<(), SecstoreError> {
        let key = format!("handle_{:08x}", vhsm_handle);
        self.backend.delete(&key)
    }
}

#[derive(Debug)]
pub enum SecstoreError {
    Io(std::io::Error),
    Crypto(String),
    Format(String),
}

impl std::fmt::Display for SecstoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecstoreError::Io(e) => write!(f, "secstore I/O: {e}"),
            SecstoreError::Crypto(e) => write!(f, "secstore crypto: {e}"),
            SecstoreError::Format(e) => write!(f, "secstore format: {e}"),
        }
    }
}

impl std::error::Error for SecstoreError {}

impl From<std::io::Error> for SecstoreError {
    fn from(e: std::io::Error) -> Self {
        SecstoreError::Io(e)
    }
}

// Simple binary serialization (no serde dependency).
//
// Layout: vhsm_handle(4) + algorithm(4) + permitted_ops(4) + persistent(1)
// then three length-prefixed (u16) UTF-8 strings: key_id, owner_vm_id, label.
// owner_vm_id of length 0 means "shared / well-known".
fn serialize_metadata(meta: &KeyMetadata) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&meta.vhsm_handle.to_le_bytes());
    buf.extend_from_slice(&meta.algorithm.to_le_bytes());
    buf.extend_from_slice(&meta.permitted_ops.to_le_bytes());
    buf.push(meta.persistent as u8);
    for s in [&meta.key_id, &meta.owner_vm_id, &meta.label] {
        let bytes = s.as_bytes();
        buf.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(bytes);
    }
    buf
}

fn deserialize_metadata(data: &[u8]) -> Option<KeyMetadata> {
    if data.len() < 13 {
        return None;
    }
    let vhsm_handle = u32::from_le_bytes(data[0..4].try_into().ok()?);
    let algorithm = u32::from_le_bytes(data[4..8].try_into().ok()?);
    let permitted_ops = u32::from_le_bytes(data[8..12].try_into().ok()?);
    let persistent = data[12] != 0;

    let mut pos = 13;
    let mut take_str = || -> Option<String> {
        let len = u16::from_le_bytes(data.get(pos..pos + 2)?.try_into().ok()?) as usize;
        pos += 2;
        let s = std::str::from_utf8(data.get(pos..pos + len)?)
            .ok()?
            .to_string();
        pos += len;
        Some(s)
    };
    let key_id = take_str()?;
    let owner_vm_id = take_str()?;
    let label = take_str()?;

    Some(KeyMetadata {
        vhsm_handle,
        key_id,
        algorithm,
        permitted_ops,
        owner_vm_id,
        persistent,
        label,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_roundtrip() {
        let meta = KeyMetadata {
            vhsm_handle: 0x0042,
            key_id: "iam-signing".into(),
            algorithm: 0x0021,
            permitted_ops: 0x0330,
            owner_vm_id: "vm1".into(),
            persistent: true,
            label: "ECU signing key".into(),
        };
        let bytes = serialize_metadata(&meta);
        let back = deserialize_metadata(&bytes).unwrap();
        assert_eq!(back.vhsm_handle, 0x0042);
        assert_eq!(back.key_id, "iam-signing");
        assert_eq!(back.algorithm, 0x0021);
        assert_eq!(back.permitted_ops, 0x0330);
        assert_eq!(back.owner_vm_id, "vm1");
        assert!(back.persistent);
        assert_eq!(back.label, "ECU signing key");
    }

    #[test]
    fn store_and_load_roundtrip() {
        let dir = std::env::temp_dir().join("secstore-test");
        let _ = std::fs::remove_dir_all(&dir);

        let store = Secstore::new(LinuxSimEncryptor::new([0xAB; 16]), FileBackend::new(&dir));

        let meta = KeyMetadata {
            vhsm_handle: 0x0100,
            key_id: "test-key".into(),
            algorithm: 0x0002,
            permitted_ops: 0x03,
            owner_vm_id: String::new(),
            persistent: true,
            label: "test".into(),
        };

        store.store(&meta).unwrap();
        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].vhsm_handle, 0x0100);
        assert_eq!(loaded[0].key_id, "test-key");

        store.delete(0x0100).unwrap();
        let loaded = store.load_all().unwrap();
        assert!(loaded.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------------------------------------------------------------------
    // Additional coverage
    // ---------------------------------------------------------------------

    fn tmp_store() -> (Secstore<LinuxSimEncryptor, FileBackend>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = Secstore::new(
            LinuxSimEncryptor::new([0x42; 16]),
            FileBackend::new(dir.path()),
        );
        (s, dir)
    }

    fn make_meta(handle: u32, key_id: &str) -> KeyMetadata {
        KeyMetadata {
            vhsm_handle: handle,
            key_id: key_id.into(),
            algorithm: 0x0002,
            permitted_ops: 0x03,
            owner_vm_id: "vm1".into(),
            persistent: true,
            label: String::new(),
        }
    }

    #[test]
    fn multiple_handles_roundtrip_independently() {
        let (store, _tmp) = tmp_store();
        store.store(&make_meta(0x100, "k1")).unwrap();
        store.store(&make_meta(0x101, "k2")).unwrap();
        store.store(&make_meta(0x102, "k3")).unwrap();

        let mut loaded = store.load_all().unwrap();
        loaded.sort_by_key(|m| m.vhsm_handle);
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[0].key_id, "k1");
        assert_eq!(loaded[1].key_id, "k2");
        assert_eq!(loaded[2].key_id, "k3");
    }

    #[test]
    fn delete_specific_handle_leaves_others() {
        let (store, _tmp) = tmp_store();
        store.store(&make_meta(0x100, "k1")).unwrap();
        store.store(&make_meta(0x101, "k2")).unwrap();

        store.delete(0x100).unwrap();
        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].key_id, "k2");
    }

    #[test]
    fn delete_nonexistent_handle_is_ok() {
        // FileBackend::delete treats missing files as success (idempotent).
        let (store, _tmp) = tmp_store();
        store.delete(0xDEAD_BEEF).unwrap();
    }

    #[test]
    fn store_overwrites_existing_handle() {
        let (store, _tmp) = tmp_store();
        store.store(&make_meta(0x100, "original")).unwrap();
        let mut updated = make_meta(0x100, "overwritten");
        updated.permitted_ops = 0xFF;
        store.store(&updated).unwrap();

        let loaded = store.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].key_id, "overwritten");
        assert_eq!(loaded[0].permitted_ops, 0xFF);
    }

    #[test]
    fn empty_store_loads_empty_vec() {
        let (store, _tmp) = tmp_store();
        let loaded = store.load_all().unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn deserialize_rejects_truncated_buffer() {
        let short = vec![0u8; 5]; // needs at least 13 bytes of fixed fields
        assert!(deserialize_metadata(&short).is_none());
    }

    #[test]
    fn deserialize_rejects_string_length_past_end() {
        // vhsm_handle(4) + algorithm(4) + permitted_ops(4) + persistent(1) +
        // key_id_len(2)=big + (key_id missing) → must fail
        let mut buf = vec![0u8; 4 + 4 + 4 + 1];
        buf.extend_from_slice(&(9999_u16).to_le_bytes()); // absurd key_id len
        assert!(deserialize_metadata(&buf).is_none());
    }

    #[test]
    fn different_encryptor_key_cannot_decrypt() {
        let dir = tempfile::tempdir().unwrap();

        let store_a = Secstore::new(
            LinuxSimEncryptor::new([0xAA; 16]),
            FileBackend::new(dir.path()),
        );
        store_a.store(&make_meta(0x100, "k")).unwrap();

        let store_b = Secstore::new(
            LinuxSimEncryptor::new([0xBB; 16]),
            FileBackend::new(dir.path()),
        );
        // Different key → decryption produces garbage → metadata parse fails
        // → entry is silently skipped (per load_all's if-let). Verifies isolation.
        let loaded = store_b.load_all().unwrap();
        assert!(loaded.is_empty(), "wrong key must not decrypt valid data");
    }

    #[test]
    fn linux_sim_encryptor_roundtrip() {
        let enc = LinuxSimEncryptor::new([0x33; 16]);
        let pt = b"hello secstore";
        let ct = enc.encrypt(pt).unwrap();
        assert_ne!(ct, pt);
        let rt = enc.decrypt(&ct).unwrap();
        assert_eq!(rt, pt);
    }

    #[test]
    fn secstore_error_display_and_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let e: SecstoreError = io_err.into();
        assert!(matches!(e, SecstoreError::Io(_)));
        // Smoke: Display doesn't panic
        let _ = e.to_string();
    }

    #[test]
    fn secstore_error_is_std_error() {
        fn take<E: std::error::Error>(_: E) {}
        take(SecstoreError::Crypto("bad".into()));
        take(SecstoreError::Format("bad".into()));
    }
}
