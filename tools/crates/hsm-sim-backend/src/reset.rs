//! HSM-only factory reset of a [`SimHsm`](crate::SimHsm) keystore directory.
//!
//! [`reset_keystore`] returns the keystore to the unprovisioned floor the way a
//! workshop gives an HSM a new security configuration, without touching the rest
//! of the device:
//!
//! - **removed**: the provisioning state (`manifest`, `identities`,
//!   `provision_state`, `bootstrap.yaml`), every provisioned key, root and
//!   certificate (`keys/roots/`, `keys/*.cert`, the authority / issuer public
//!   keys), and the device-generated **identity** keys: `device-decrypt` (whose
//!   digest is the ECU id), `tls-identity`, `iam-signing`, `jwt-signing`; plus
//!   the `.tmp` / `.bak` siblings a re-provision leaves.
//! - **kept**: `ivd-signing` (it signs the boot selector and every bank's IVD
//!   manifest, which stay valid), `storage-key` (what guests encrypted with it
//!   stays readable) and the monotonic counters (`monotonic_*`, the time floor
//!   never rewinds); also anything the keystore does not own (the link-B socket).
//!
//! The backend regenerates the missing device keys at its next start
//! ([`SimHsm::ensure_device_keys`](crate::SimHsm::ensure_device_keys)), so the
//! caller stops the HSM daemons (or restarts the node) after the reset: the
//! device comes back with a new ECU id and no provisioning, ready to enroll.
//!
//! Pure filesystem work, no crypto: it builds without the `crypto` feature.

use std::io;
use std::path::{Path, PathBuf};

use hsm::KeyRole;

/// Device-generated keys the reset keeps: their files stay in `keys/`.
pub const KEPT_KEYS: [KeyRole; 2] = [KeyRole::IvdSigning, KeyRole::Storage];

/// Top-level keystore files that hold provisioning state.
const PROVISIONING_FILES: [&str; 4] = [
    "manifest",
    "identities",
    "provision_state",
    "bootstrap.yaml",
];

/// Reset the keystore at `keystore` to the unprovisioned floor (see the module
/// docs). Returns every path it removed, in the order removed. A missing
/// keystore, or one already reset, removes nothing and is not an error.
pub fn reset_keystore(keystore: &Path) -> io::Result<Vec<PathBuf>> {
    let mut removed = Vec::new();
    for name in PROVISIONING_FILES {
        remove(&keystore.join(name), &mut removed)?;
    }
    let keys = keystore.join("keys");
    if keys.is_dir() {
        for entry in std::fs::read_dir(&keys)? {
            let path = entry?.path();
            if !is_kept_key_file(&path) {
                remove(&path, &mut removed)?;
            }
        }
    }
    for sibling in ["tmp", "bak"] {
        remove(&keystore.with_extension(sibling), &mut removed)?;
    }
    Ok(removed)
}

/// Whether `path` (an entry of `keys/`) is the private, public or raw half of a
/// [`KEPT_KEYS`] slot. Certificates are never kept: a kept key's certificate was
/// issued by the provisioning the reset undoes.
fn is_kept_key_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    KEPT_KEYS.iter().any(|role| {
        let id = role.key_id();
        ["priv", "pub", "bin"]
            .iter()
            .any(|ext| name == format!("{id}.{ext}"))
    })
}

/// Remove `path` (a file or a directory tree) if it exists, recording it.
fn remove(path: &Path, removed: &mut Vec<PathBuf>) -> io::Result<()> {
    let result = match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => std::fs::remove_file(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    result?;
    removed.push(path.to_path_buf());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A provisioned keystore as the sim backend lays it out.
    fn provisioned(dir: &Path) {
        let keys = dir.join("keys");
        std::fs::create_dir_all(keys.join("roots")).unwrap();
        for name in PROVISIONING_FILES {
            std::fs::write(dir.join(name), name).unwrap();
        }
        std::fs::write(dir.join("monotonic_0000000d"), "1795004081").unwrap();
        std::fs::write(dir.join("hsm-backend.sock"), "").unwrap();
        for id in [
            "device-decrypt",
            "tls-identity",
            "iam-signing",
            "jwt-signing",
            "ivd-signing",
        ] {
            std::fs::write(keys.join(format!("{id}.priv")), id).unwrap();
            std::fs::write(keys.join(format!("{id}.pub")), id).unwrap();
        }
        std::fs::write(keys.join("tls-identity.cert"), "leaf").unwrap();
        std::fs::write(keys.join("ivd-signing.cert"), "cert").unwrap();
        std::fs::write(keys.join("storage-key.bin"), [7u8; 32]).unwrap();
        for id in [
            "sw-authority",
            "key-authority",
            "operational-issuer",
            "factory-reset-issuer",
        ] {
            std::fs::write(keys.join(format!("{id}.pub")), id).unwrap();
        }
        std::fs::write(keys.join("roots/delegation-root.cert"), "root").unwrap();
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut out: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        out.sort();
        out
    }

    #[test]
    fn keeps_ivd_signing_storage_key_and_the_time_floor_only() {
        let tmp = tempfile::tempdir().unwrap();
        let keystore = tmp.path().join("keys-store");
        provisioned(&keystore);

        let removed = reset_keystore(&keystore).unwrap();

        assert_eq!(
            names(&keystore),
            ["hsm-backend.sock", "keys", "monotonic_0000000d"]
        );
        assert_eq!(
            names(&keystore.join("keys")),
            ["ivd-signing.priv", "ivd-signing.pub", "storage-key.bin"]
        );
        assert_eq!(
            std::fs::read(keystore.join("keys/storage-key.bin")).unwrap(),
            [7u8; 32],
            "kept keys are untouched"
        );
        assert!(removed.contains(&keystore.join("manifest")));
        assert!(removed.contains(&keystore.join("keys/device-decrypt.priv")));
        assert!(removed.contains(&keystore.join("keys/roots")));
    }

    #[test]
    fn removes_the_reprovision_siblings() {
        let tmp = tempfile::tempdir().unwrap();
        let keystore = tmp.path().join("keys-store");
        provisioned(&keystore);
        std::fs::create_dir_all(keystore.with_extension("tmp")).unwrap();
        std::fs::create_dir_all(keystore.with_extension("bak").join("keys")).unwrap();

        reset_keystore(&keystore).unwrap();

        assert!(!keystore.with_extension("tmp").exists());
        assert!(!keystore.with_extension("bak").exists());
    }

    #[test]
    fn a_missing_or_reset_keystore_removes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let keystore = tmp.path().join("absent");
        assert!(reset_keystore(&keystore).unwrap().is_empty());

        provisioned(&keystore);
        reset_keystore(&keystore).unwrap();
        assert!(reset_keystore(&keystore).unwrap().is_empty());
    }

    /// The backend regenerates exactly the removed identity keys at its next
    /// start, and leaves the kept ones as they were.
    #[cfg(feature = "crypto")]
    #[test]
    fn the_next_start_regenerates_the_identity_keys_only() {
        let tmp = tempfile::tempdir().unwrap();
        let keystore = tmp.path().join("keys-store");
        let sim = crate::SimHsm::new(keystore.clone());
        sim.ensure_device_keys().unwrap();
        let keys = keystore.join("keys");
        let before = |id: &str| std::fs::read(keys.join(id)).unwrap();
        let ivd = before("ivd-signing.priv");
        let storage = before("storage-key.bin");
        let decrypt = before("device-decrypt.pub");

        reset_keystore(&keystore).unwrap();
        sim.ensure_device_keys().unwrap();

        assert_eq!(before("ivd-signing.priv"), ivd);
        assert_eq!(before("storage-key.bin"), storage);
        assert_ne!(before("device-decrypt.pub"), decrypt, "a new ECU id");
        for id in ["tls-identity", "iam-signing", "jwt-signing"] {
            assert!(keys.join(format!("{id}.priv")).exists(), "{id} regenerated");
        }
    }
}
