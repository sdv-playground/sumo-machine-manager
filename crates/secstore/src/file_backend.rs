//! Filesystem-based blob storage backend.
//!
//! Stores each blob as a file in a directory. Writes are atomic
//! (write to temp file + rename) to survive power loss.

use std::path::{Path, PathBuf};

use super::{SecstoreBackend, SecstoreError};

/// File-based backend — one file per blob in a directory.
pub struct FileBackend {
    dir: PathBuf,
}

impl FileBackend {
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }
}

impl SecstoreBackend for FileBackend {
    fn read(&self, key: &str) -> Result<Option<Vec<u8>>, SecstoreError> {
        let path = self.dir.join(key);
        match std::fs::read(&path) {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(SecstoreError::Io(e)),
        }
    }

    fn write(&self, key: &str, data: &[u8]) -> Result<(), SecstoreError> {
        std::fs::create_dir_all(&self.dir)?;
        let path = self.dir.join(key);
        let tmp = self.dir.join(format!(".{key}.tmp"));
        std::fs::write(&tmp, data)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), SecstoreError> {
        let path = self.dir.join(key);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(SecstoreError::Io(e)),
        }
    }

    fn list(&self) -> Result<Vec<String>, SecstoreError> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(SecstoreError::Io(e)),
        };
        let mut keys = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with('.') {
                keys.push(name);
            }
        }
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> (FileBackend, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (FileBackend::new(dir.path()), dir)
    }

    #[test]
    fn write_and_read_roundtrip() {
        let (b, _t) = tmp();
        b.write("k", b"hello").unwrap();
        assert_eq!(b.read("k").unwrap(), Some(b"hello".to_vec()));
    }

    #[test]
    fn read_missing_returns_none() {
        let (b, _t) = tmp();
        assert_eq!(b.read("missing").unwrap(), None);
    }

    #[test]
    fn delete_existing_key_removes_it() {
        let (b, _t) = tmp();
        b.write("k", b"x").unwrap();
        b.delete("k").unwrap();
        assert_eq!(b.read("k").unwrap(), None);
    }

    #[test]
    fn delete_missing_key_is_ok() {
        let (b, _t) = tmp();
        b.delete("never-existed").unwrap();
    }

    #[test]
    fn list_on_empty_dir_is_empty() {
        let (b, _t) = tmp();
        assert!(b.list().unwrap().is_empty());
    }

    #[test]
    fn list_returns_all_non_dotfile_keys() {
        let (b, _t) = tmp();
        b.write("a", b"1").unwrap();
        b.write("b", b"2").unwrap();
        b.write("c", b"3").unwrap();
        let mut keys = b.list().unwrap();
        keys.sort();
        assert_eq!(keys, vec!["a", "b", "c"]);
    }

    #[test]
    fn list_skips_tmp_dotfiles() {
        // Stray .foo.tmp files from interrupted writes must not appear in list()
        let (b, t) = tmp();
        b.write("real", b"x").unwrap();
        std::fs::write(t.path().join(".stale.tmp"), b"leftover").unwrap();
        let keys = b.list().unwrap();
        assert_eq!(keys, vec!["real"]);
    }

    #[test]
    fn list_on_missing_dir_is_empty_not_error() {
        // `new(dir)` doesn't create the directory — list should handle that
        let dir = tempfile::tempdir().unwrap();
        let bogus = dir.path().join("does-not-exist-yet");
        let b = FileBackend::new(&bogus);
        assert!(b.list().unwrap().is_empty());
    }

    #[test]
    fn write_creates_parent_dir_if_absent() {
        // FileBackend::new doesn't create the dir — write() should.
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a/b/c");
        let b = FileBackend::new(&nested);
        b.write("k", b"v").unwrap();
        assert_eq!(b.read("k").unwrap(), Some(b"v".to_vec()));
    }

    #[test]
    fn overwrite_replaces_value() {
        let (b, _t) = tmp();
        b.write("k", b"v1").unwrap();
        b.write("k", b"v2-longer").unwrap();
        assert_eq!(b.read("k").unwrap(), Some(b"v2-longer".to_vec()));
    }

    #[test]
    fn write_tmp_file_does_not_persist() {
        // After a successful write, no `.{key}.tmp` file should linger
        let (b, t) = tmp();
        b.write("key", b"x").unwrap();
        let stragglers: Vec<_> = std::fs::read_dir(t.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with('.'))
            .collect();
        assert!(stragglers.is_empty(), "tmp file leaked: {stragglers:?}");
    }
}
