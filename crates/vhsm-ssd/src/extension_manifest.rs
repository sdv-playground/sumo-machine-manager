//! Generic extension-handle manifest, applied after `init_handle_table`.
//!
//! Sumo's `vhsm-ssd` daemon owns the well-known range `0x0001..0x0080`
//! and seeds it from a hardcoded table at startup (see
//! `main.rs::init_handle_table`). The range `0x0080..0x0100` is reserved
//! for downstream/project-specific well-known handles (see
//! `proto::HANDLE_PROJECT_BASE`). This module reads such project entries
//! from a TOML file at startup so sumo stays project-agnostic.
//!
//! ## File format
//!
//! ```yaml
//! # vHSM extension-handle manifest. Each item under `extensions`
//! # registers one project-owned well-known handle in the
//! # 0x0080..0x00FF band.
//! extensions:
//!   - handle: 0x0080
//!     key_id: mqtt-client-cert
//!     algorithm: ecc-p256
//!     permitted_ops:
//!       - sign
//!       - verify
//!       - get-pubkey
//!       - get-cert
//! ```
//!
//! `handle` accepts decimal or `0x`-prefixed hex (serde_yaml parses both
//! as integers). `algorithm` and `permitted_ops` are case-insensitive
//! kebab/snake/upper variants of the constants in [`crate::proto`].
//! Unknown values are refused at load time with a clear error.
//!
//! ## Behavior
//!
//! [`load_from_file`] parses + validates structure (range, distinct
//! handles, known names). [`apply`] walks the loaded entries and calls
//! `HandleTable::register_well_known` for each whose `key_id` exists in
//! the keystore — matching the policy of `init_handle_table` (missing
//! keys are skipped silently; the slot is "reserved by number" until
//! provisioning lands).

use std::path::Path;

use hsm::HsmCryptoProvider;
use serde::Deserialize;

use crate::handle_table::HandleTable;
use crate::proto::{
    handle_is_project, ALG_AES_128, ALG_AES_256, ALG_ECC_P256, ALG_ED25519, ALG_HMAC_SHA256,
    PERM_DECRYPT, PERM_DELETE, PERM_DERIVE, PERM_ENCRYPT, PERM_GET_CERT, PERM_GET_PUBKEY,
    PERM_KEY_GENERATE, PERM_MAC_GEN, PERM_MAC_VFY, PERM_SIGN, PERM_VERIFY,
};

/// One parsed extension entry. Mirrors the tuple shape used by sumo's
/// `init_handle_table`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    pub handle: u32,
    pub key_id: String,
    pub algorithm: u32,
    pub permitted_ops: u32,
}

#[derive(Debug)]
pub enum LoadError {
    Io(std::io::Error),
    Parse(serde_yaml::Error),
    HandleOutOfRange { handle: u32 },
    DuplicateHandle { handle: u32 },
    UnknownAlgorithm(String),
    UnknownPermission(String),
    EmptyKeyId,
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Io(e) => write!(f, "i/o error reading extension manifest: {e}"),
            LoadError::Parse(e) => write!(f, "extension manifest parse error: {e}"),
            LoadError::HandleOutOfRange { handle } => write!(
                f,
                "handle 0x{handle:04x} not in project range (0x0080..0x0100)"
            ),
            LoadError::DuplicateHandle { handle } => {
                write!(f, "duplicate extension handle 0x{handle:04x}")
            }
            LoadError::UnknownAlgorithm(s) => write!(f, "unknown algorithm: {s:?}"),
            LoadError::UnknownPermission(s) => write!(f, "unknown permission: {s:?}"),
            LoadError::EmptyKeyId => write!(f, "extension entry has empty key_id"),
        }
    }
}

impl std::error::Error for LoadError {}

impl From<std::io::Error> for LoadError {
    fn from(e: std::io::Error) -> Self {
        LoadError::Io(e)
    }
}
impl From<serde_yaml::Error> for LoadError {
    fn from(e: serde_yaml::Error) -> Self {
        LoadError::Parse(e)
    }
}

#[derive(Debug, Deserialize)]
struct ManifestFile {
    #[serde(default)]
    extensions: Vec<ExtensionRow>,
}

#[derive(Debug, Deserialize)]
struct ExtensionRow {
    handle: u32,
    key_id: String,
    algorithm: String,
    permitted_ops: Vec<String>,
}

/// Read + validate an extension manifest from disk. Returns the parsed
/// entries ready for [`apply`]. Returns an empty Vec if the file
/// contains no `[[extension]]` rows.
pub fn load_from_file(path: &Path) -> Result<Vec<Extension>, LoadError> {
    let text = std::fs::read_to_string(path)?;
    parse(&text)
}

/// Parse an in-memory manifest string. Public for testability + for
/// callers that already have the bytes (e.g. embedded in a launcher).
pub fn parse(text: &str) -> Result<Vec<Extension>, LoadError> {
    let raw: ManifestFile = serde_yaml::from_str(text)?;
    let mut out = Vec::with_capacity(raw.extensions.len());
    for row in raw.extensions {
        if !handle_is_project(row.handle) {
            return Err(LoadError::HandleOutOfRange { handle: row.handle });
        }
        if row.key_id.is_empty() {
            return Err(LoadError::EmptyKeyId);
        }
        let algorithm = parse_algorithm(&row.algorithm)?;
        let mut perms: u32 = 0;
        for p in &row.permitted_ops {
            perms |= parse_permission(p)?;
        }
        out.push(Extension {
            handle: row.handle,
            key_id: row.key_id,
            algorithm,
            permitted_ops: perms,
        });
    }
    // Reject duplicate handle declarations in the manifest itself.
    // (register_well_known would also catch duplicates against the
    // table, but doing it here gives the operator a precise file-level
    // error before any side effect.)
    for i in 0..out.len() {
        for j in (i + 1)..out.len() {
            if out[i].handle == out[j].handle {
                return Err(LoadError::DuplicateHandle {
                    handle: out[i].handle,
                });
            }
        }
    }
    Ok(out)
}

/// Register each manifest entry whose `key_id` exists in the keystore.
/// Matches the policy of `init_handle_table`: missing keys are skipped
/// (logged at debug); already-registered handles are warned.
///
/// Returns the count of handles actually registered. Call AFTER
/// `init_handle_table` and BEFORE the daemon starts serving.
pub fn apply(
    table: &mut HandleTable,
    entries: &[Extension],
    crypto: &dyn HsmCryptoProvider,
) -> usize {
    let mut registered = 0;
    for e in entries {
        if crypto.get_key_info(hsm::KeyHandle(e.handle)).is_err() {
            tracing::debug!(
                handle = e.handle,
                key_id = %e.key_id,
                "extension key not in keystore; skipping"
            );
            continue;
        }
        if table.register_well_known(e.handle, &e.key_id, e.algorithm, e.permitted_ops) {
            tracing::info!(
                handle = e.handle,
                key_id = %e.key_id,
                "registered extension handle"
            );
            registered += 1;
        } else {
            tracing::warn!(
                handle = e.handle,
                key_id = %e.key_id,
                "extension register_well_known refused (duplicate or out-of-range)"
            );
        }
    }
    registered
}

/// Map a textual algorithm name to the `ALG_*` constant. Accepts the
/// kebab/snake/upper variants of the names in `proto.rs` — `"ecc-p256"`,
/// `"ECC_P256"`, `"ecc_p256"` all map to `ALG_ECC_P256`.
fn parse_algorithm(s: &str) -> Result<u32, LoadError> {
    match s.to_ascii_lowercase().replace('_', "-").as_str() {
        "aes-128" => Ok(ALG_AES_128),
        "aes-256" => Ok(ALG_AES_256),
        "hmac-sha256" => Ok(ALG_HMAC_SHA256),
        "ed25519" => Ok(ALG_ED25519),
        "ecc-p256" => Ok(ALG_ECC_P256),
        _ => Err(LoadError::UnknownAlgorithm(s.to_string())),
    }
}

/// Map a textual permission to the `PERM_*` bit. Same case rules as
/// algorithm; `"get-pubkey"` / `"GET_PUBKEY"` both work.
fn parse_permission(s: &str) -> Result<u32, LoadError> {
    match s.to_ascii_lowercase().replace('_', "-").as_str() {
        "encrypt" => Ok(PERM_ENCRYPT),
        "decrypt" => Ok(PERM_DECRYPT),
        "mac-gen" | "mac-generate" => Ok(PERM_MAC_GEN),
        "mac-vfy" | "mac-verify" => Ok(PERM_MAC_VFY),
        "sign" => Ok(PERM_SIGN),
        "verify" => Ok(PERM_VERIFY),
        "derive" => Ok(PERM_DERIVE),
        "delete" => Ok(PERM_DELETE),
        "get-pubkey" => Ok(PERM_GET_PUBKEY),
        "get-cert" => Ok(PERM_GET_CERT),
        "key-generate" => Ok(PERM_KEY_GENERATE),
        _ => Err(LoadError::UnknownPermission(s.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_mqtt_entry() -> &'static str {
        r#"
extensions:
  - handle: 0x0080
    key_id: mqtt-client-cert
    algorithm: ecc-p256
    permitted_ops:
      - sign
      - verify
      - get-pubkey
      - get-cert
"#
    }

    #[test]
    fn parses_a_minimal_manifest() {
        let entries = parse(one_mqtt_entry()).unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.handle, 0x0080);
        assert_eq!(e.key_id, "mqtt-client-cert");
        assert_eq!(e.algorithm, ALG_ECC_P256);
        assert_eq!(
            e.permitted_ops,
            PERM_SIGN | PERM_VERIFY | PERM_GET_PUBKEY | PERM_GET_CERT
        );
    }

    #[test]
    fn empty_manifest_is_ok() {
        // An empty document or one with no `extensions:` key both parse.
        let entries = parse("extensions: []").unwrap();
        assert!(entries.is_empty());
        let entries = parse("{}").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn rejects_handle_outside_project_range() {
        let yaml = r#"
extensions:
  - handle: 0x0007
    key_id: foo
    algorithm: ecc-p256
    permitted_ops: [sign]
"#;
        let err = parse(yaml).unwrap_err();
        assert!(matches!(
            err,
            LoadError::HandleOutOfRange { handle: 0x0007 }
        ));
    }

    #[test]
    fn rejects_handle_in_dynamic_range() {
        let yaml = r#"
extensions:
  - handle: 0x0100
    key_id: foo
    algorithm: ecc-p256
    permitted_ops: [sign]
"#;
        let err = parse(yaml).unwrap_err();
        assert!(matches!(
            err,
            LoadError::HandleOutOfRange { handle: 0x0100 }
        ));
    }

    #[test]
    fn rejects_duplicate_handles_in_file() {
        let yaml = r#"
extensions:
  - handle: 0x0080
    key_id: a
    algorithm: ecc-p256
    permitted_ops: [sign]
  - handle: 0x0080
    key_id: b
    algorithm: ecc-p256
    permitted_ops: [verify]
"#;
        let err = parse(yaml).unwrap_err();
        assert!(matches!(err, LoadError::DuplicateHandle { handle: 0x0080 }));
    }

    #[test]
    fn rejects_unknown_algorithm() {
        let yaml = r#"
extensions:
  - handle: 0x0080
    key_id: foo
    algorithm: rsa-4096
    permitted_ops: [sign]
"#;
        match parse(yaml).unwrap_err() {
            LoadError::UnknownAlgorithm(s) => assert_eq!(s, "rsa-4096"),
            other => panic!("expected UnknownAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_permission() {
        let yaml = r#"
extensions:
  - handle: 0x0080
    key_id: foo
    algorithm: ecc-p256
    permitted_ops: [fly]
"#;
        match parse(yaml).unwrap_err() {
            LoadError::UnknownPermission(s) => assert_eq!(s, "fly"),
            other => panic!("expected UnknownPermission, got {other:?}"),
        }
    }

    #[test]
    fn accepts_upper_and_snake_case_names() {
        let yaml = r#"
extensions:
  - handle: 0x0081
    key_id: foo
    algorithm: ECC_P256
    permitted_ops: [SIGN, GET_PUBKEY]
"#;
        let entries = parse(yaml).unwrap();
        assert_eq!(entries[0].algorithm, ALG_ECC_P256);
        assert_eq!(entries[0].permitted_ops, PERM_SIGN | PERM_GET_PUBKEY);
    }

    #[test]
    fn accepts_decimal_handle() {
        // 128 == 0x0080
        let yaml = r#"
extensions:
  - handle: 128
    key_id: foo
    algorithm: ecc-p256
    permitted_ops: [sign]
"#;
        let entries = parse(yaml).unwrap();
        assert_eq!(entries[0].handle, 0x0080);
    }
}
