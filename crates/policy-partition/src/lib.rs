//! Loader for the policy directory.
//!
//! See AUTH-ARCH-001 §4. As of Phase 3 the policy directory rides
//! inside an existing bank-set rootfs rather than being its own
//! SUIT-delivered bank: host-side policy lives in the host-os bank,
//! per-VM policy lives in the respective VM bank. Either way the
//! existing OTA pipeline (component-mgr / host-os-mgr) delivers it with
//! the same trial-boot + auto-rollback + `security_version`
//! anti-rollback semantics we already trust for firmware.
//!
//! That means this crate has a much smaller job than the spec-level
//! design implied: it loads + validates a directory. Anti-rollback,
//! atomic activation, and reload signalling are inherited from
//! whatever bank-set holds the directory — no logic here.
//!
//! ## On-disk layout
//!
//! ```text
//! /etc/sumo/policy/
//!   policy.yaml              ← authorisation policy (policy-eval)
//!   launcher-policy.yaml     ← jwt-mgr launcher policy (guest-only consumer;
//!                              the host validates structure but doesn't
//!                              parse fields)
//!   roots/                   ← PEM trust anchors
//!     sumo-sign.pem
//!     device-jwt.pem
//!     tester-idp.pem
//!     ...
//!   crl.yaml                 ← revocation list (cert thumbprints + JWT jti)
//! ```
//!
//! Required files: `policy.yaml`, `roots/` (may be empty for
//! dev rigs but must exist). Optional: `launcher-policy.yaml`,
//! `crl.yaml`. Missing optional files surface as `None` in the
//! loaded struct; consumers decide whether to fail.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

// =============================================================================
// Loaded partition
// =============================================================================

/// One loaded policy directory.
#[derive(Debug, Clone)]
pub struct PolicyPartition {
    /// Root of the policy directory on disk. Useful for resolving
    /// relative paths to roots/ and for diagnostic messages.
    pub root: PathBuf,

    /// Parsed authorisation policy (see policy-eval).
    pub authorisation: policy_eval::Policy,

    /// Trust roots, keyed by PEM filename (e.g. `"sumo-sign.pem"`).
    /// Values are the raw PEM bytes — callers parse with their own
    /// X.509 / CWT machinery.
    pub roots: HashMap<String, Vec<u8>>,

    /// Certificate Revocation List, if present in the partition.
    pub crl: Option<Crl>,

    /// Raw bytes of `launcher-policy.yaml` if present. Validated
    /// to be well-formed YAML at load time; not parsed further
    /// (the launcher-policy crate lives in guest-vm-sdk and is
    /// owned by the guest jwt-mgr consumer).
    pub launcher_policy: Option<Vec<u8>>,
}

impl PolicyPartition {
    /// Default mount point on both host and guests.
    pub const DEFAULT_MOUNT: &'static str = "/etc/sumo/policy";

    /// Load + validate a partition from a directory. Strict:
    /// missing required files, malformed YAML, or unreadable
    /// `roots/` all surface as errors. Optional files (CRL,
    /// launcher-policy) being absent is fine.
    pub fn load_from_dir(
        path: impl AsRef<Path>,
        normalize_op: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, PartitionError> {
        let root = path.as_ref().to_path_buf();
        if !root.is_dir() {
            return Err(PartitionError::NotADirectory(root));
        }

        let authorisation = load_authorisation(&root, &normalize_op)?;
        let roots = load_roots(&root.join("roots"))?;
        let crl = load_optional_crl(&root)?;
        let launcher_policy = load_optional_launcher(&root)?;

        Ok(Self {
            root,
            authorisation,
            roots,
            crl,
            launcher_policy,
        })
    }

    /// Look up a trust root by PEM filename. Returns the raw PEM
    /// bytes if present.
    pub fn root(&self, name: &str) -> Option<&[u8]> {
        self.roots.get(name).map(|v| v.as_slice())
    }
}

// =============================================================================
// CRL
// =============================================================================

/// Certificate Revocation List entries.
///
/// Two flavours of revocation are tracked:
/// - `cert_thumbprints`: SHA-256 thumbprints of CWT certs (vHSM cert
///   handshake principals). Hex-encoded for ergonomics.
/// - `jwt_jti`: `jti` claims from individual JWTs that should not be
///   honoured even before their `exp`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct Crl {
    #[serde(default)]
    pub cert_thumbprints: Vec<String>,
    #[serde(default)]
    pub jwt_jti: Vec<String>,
}

impl Crl {
    pub fn is_cert_revoked(&self, thumbprint_hex: &str) -> bool {
        self.cert_thumbprints.iter().any(|t| t == thumbprint_hex)
    }

    pub fn is_jwt_revoked(&self, jti: &str) -> bool {
        self.jwt_jti.iter().any(|j| j == jti)
    }
}

// =============================================================================
// Errors
// =============================================================================

#[derive(Debug)]
pub enum PartitionError {
    /// The path passed to `load_from_dir` isn't a directory.
    NotADirectory(PathBuf),
    /// A required file is missing.
    MissingRequiredFile(PathBuf),
    /// I/O error reading a file.
    Io { path: PathBuf, error: String },
    /// `policy.yaml` failed to parse via policy-eval.
    AuthorisationPolicyParse(policy_eval::LoadError),
    /// `crl.yaml` is malformed.
    CrlParse(String),
    /// `launcher-policy.yaml` exists but isn't valid YAML. (Structural
    /// validation against the launcher-policy schema happens in the
    /// guest consumer; this catches "operator typed garbage" early.)
    LauncherPolicyParse(String),
    /// `roots/` directory is missing.
    MissingRootsDir(PathBuf),
}

impl std::fmt::Display for PartitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PartitionError::NotADirectory(p) => {
                write!(
                    f,
                    "policy partition path is not a directory: {}",
                    p.display()
                )
            }
            PartitionError::MissingRequiredFile(p) => {
                write!(f, "policy partition missing required file: {}", p.display())
            }
            PartitionError::Io { path, error } => {
                write!(f, "i/o error on {}: {error}", path.display())
            }
            PartitionError::AuthorisationPolicyParse(e) => {
                write!(f, "policy.yaml parse error: {e}")
            }
            PartitionError::CrlParse(e) => write!(f, "crl.yaml parse error: {e}"),
            PartitionError::LauncherPolicyParse(e) => {
                write!(f, "launcher-policy.yaml not valid YAML: {e}")
            }
            PartitionError::MissingRootsDir(p) => {
                write!(f, "roots/ directory missing under {}", p.display())
            }
        }
    }
}

impl std::error::Error for PartitionError {}

impl From<policy_eval::LoadError> for PartitionError {
    fn from(e: policy_eval::LoadError) -> Self {
        PartitionError::AuthorisationPolicyParse(e)
    }
}

// =============================================================================
// Loaders (internal)
// =============================================================================

fn load_authorisation(
    root: &Path,
    normalize_op: &impl Fn(&str) -> Option<String>,
) -> Result<policy_eval::Policy, PartitionError> {
    let path = root.join("policy.yaml");
    if !path.exists() {
        return Err(PartitionError::MissingRequiredFile(path));
    }
    let text = std::fs::read_to_string(&path).map_err(|e| PartitionError::Io {
        path: path.clone(),
        error: e.to_string(),
    })?;
    Ok(policy_eval::Policy::parse(&text, normalize_op)?)
}

fn load_roots(roots_dir: &Path) -> Result<HashMap<String, Vec<u8>>, PartitionError> {
    if !roots_dir.is_dir() {
        return Err(PartitionError::MissingRootsDir(roots_dir.to_path_buf()));
    }
    let mut out = HashMap::new();
    let read_dir = std::fs::read_dir(roots_dir).map_err(|e| PartitionError::Io {
        path: roots_dir.to_path_buf(),
        error: e.to_string(),
    })?;
    for entry in read_dir {
        let entry = entry.map_err(|e| PartitionError::Io {
            path: roots_dir.to_path_buf(),
            error: e.to_string(),
        })?;
        let path = entry.path();
        if !path.is_file() {
            continue; // skip subdirs / symlinks-to-dirs
        }
        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue, // non-UTF8 filenames ignored — operators shouldn't ship them
        };
        // Only PEM files. Other extensions are operator-private
        // notes (e.g. README.md) — silently ignored.
        if !name.ends_with(".pem") {
            continue;
        }
        let bytes = std::fs::read(&path).map_err(|e| PartitionError::Io {
            path: path.clone(),
            error: e.to_string(),
        })?;
        out.insert(name, bytes);
    }
    Ok(out)
}

fn load_optional_crl(root: &Path) -> Result<Option<Crl>, PartitionError> {
    let path = root.join("crl.yaml");
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path).map_err(|e| PartitionError::Io {
        path: path.clone(),
        error: e.to_string(),
    })?;
    let crl: Crl =
        serde_yaml::from_str(&text).map_err(|e| PartitionError::CrlParse(e.to_string()))?;
    Ok(Some(crl))
}

fn load_optional_launcher(root: &Path) -> Result<Option<Vec<u8>>, PartitionError> {
    let path = root.join("launcher-policy.yaml");
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path).map_err(|e| PartitionError::Io {
        path: path.clone(),
        error: e.to_string(),
    })?;
    // Verify it's valid YAML — don't parse the schema (that's the
    // launcher-policy crate's job on the guest). This is a smell
    // test that catches obvious operator mistakes early.
    let _: serde_yaml::Value = serde_yaml::from_slice(&bytes)
        .map_err(|e| PartitionError::LauncherPolicyParse(e.to_string()))?;
    Ok(Some(bytes))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn normalize_test(s: &str) -> Option<String> {
        Some(s.to_ascii_lowercase().replace('_', "-"))
    }

    /// Build a well-formed partition in `dir`. Caller picks which
    /// optional files to add. Returns dir for convenience.
    fn build_partition(dir: &Path, include_crl: bool, include_launcher: bool) -> &Path {
        fs::write(
            dir.join("policy.yaml"),
            r#"
version: 1
statements:
  - principals: [vm1]
    handles: [jwt-signing]
    ops: [sign]
"#,
        )
        .unwrap();

        fs::create_dir(dir.join("roots")).unwrap();
        fs::write(
            dir.join("roots/sumo-sign.pem"),
            b"-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        fs::write(
            dir.join("roots/device-jwt.pem"),
            b"-----BEGIN CERTIFICATE-----\nALSOFAKE\n-----END CERTIFICATE-----\n",
        )
        .unwrap();

        if include_crl {
            fs::write(
                dir.join("crl.yaml"),
                r#"
cert_thumbprints:
  - "deadbeef"
jwt_jti:
  - "01J5XYZ"
"#,
            )
            .unwrap();
        }

        if include_launcher {
            fs::write(
                dir.join("launcher-policy.yaml"),
                r#"
version: 1
rules:
  - match: {}
    assign:
      namespace: "dev/{container_name}"
"#,
            )
            .unwrap();
        }

        dir
    }

    #[test]
    fn loads_minimal_partition_without_optional_files() {
        let tmp = tempfile::tempdir().unwrap();
        build_partition(tmp.path(), false, false);

        let p = PolicyPartition::load_from_dir(tmp.path(), normalize_test).expect("loads");
        assert_eq!(p.authorisation.num_statements(), 1);
        assert_eq!(p.roots.len(), 2);
        assert!(p.crl.is_none());
        assert!(p.launcher_policy.is_none());
    }

    #[test]
    fn loads_full_partition_with_crl_and_launcher() {
        let tmp = tempfile::tempdir().unwrap();
        build_partition(tmp.path(), true, true);

        let p = PolicyPartition::load_from_dir(tmp.path(), normalize_test).expect("loads");
        assert!(p.crl.is_some());
        assert!(p.launcher_policy.is_some());

        let crl = p.crl.as_ref().unwrap();
        assert!(crl.is_cert_revoked("deadbeef"));
        assert!(!crl.is_cert_revoked("not-revoked"));
        assert!(crl.is_jwt_revoked("01J5XYZ"));
    }

    #[test]
    fn missing_policy_yaml_is_required_file_error() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("roots")).unwrap();
        let err = PolicyPartition::load_from_dir(tmp.path(), normalize_test).unwrap_err();
        match err {
            PartitionError::MissingRequiredFile(p) => {
                assert!(p.ends_with("policy.yaml"));
            }
            other => panic!("expected MissingRequiredFile, got {other:?}"),
        }
    }

    #[test]
    fn missing_roots_dir_is_explicit_error() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("policy.yaml"),
            "version: 1\nstatements: []\n",
        )
        .unwrap();
        let err = PolicyPartition::load_from_dir(tmp.path(), normalize_test).unwrap_err();
        assert!(matches!(err, PartitionError::MissingRootsDir(_)));
    }

    #[test]
    fn malformed_policy_yaml_surfaces_policy_eval_error() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("policy.yaml"),
            "this is not valid yaml: : :",
        )
        .unwrap();
        fs::create_dir(tmp.path().join("roots")).unwrap();
        let err = PolicyPartition::load_from_dir(tmp.path(), normalize_test).unwrap_err();
        assert!(matches!(err, PartitionError::AuthorisationPolicyParse(_)));
    }

    #[test]
    fn malformed_crl_yaml_errors_at_load() {
        let tmp = tempfile::tempdir().unwrap();
        build_partition(tmp.path(), false, false);
        fs::write(tmp.path().join("crl.yaml"), "[ not valid").unwrap();
        let err = PolicyPartition::load_from_dir(tmp.path(), normalize_test).unwrap_err();
        assert!(matches!(err, PartitionError::CrlParse(_)));
    }

    #[test]
    fn malformed_launcher_yaml_errors_at_load() {
        let tmp = tempfile::tempdir().unwrap();
        build_partition(tmp.path(), false, false);
        fs::write(tmp.path().join("launcher-policy.yaml"), "[ not yaml").unwrap();
        let err = PolicyPartition::load_from_dir(tmp.path(), normalize_test).unwrap_err();
        assert!(matches!(err, PartitionError::LauncherPolicyParse(_)));
    }

    #[test]
    fn non_pem_files_in_roots_are_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        build_partition(tmp.path(), false, false);
        // Operators sometimes leave README.md, .gitkeep, etc. in
        // roots/ — those shouldn't show up as trust anchors.
        fs::write(tmp.path().join("roots/README.md"), b"these are roots").unwrap();
        fs::write(tmp.path().join("roots/.gitkeep"), b"").unwrap();
        let p = PolicyPartition::load_from_dir(tmp.path(), normalize_test).expect("loads");
        // Only the two .pem files should be visible.
        assert_eq!(p.roots.len(), 2);
        assert!(p.root("sumo-sign.pem").is_some());
        assert!(p.root("device-jwt.pem").is_some());
        assert!(p.root("README.md").is_none());
    }

    #[test]
    fn not_a_directory_errors_clearly() {
        let tmp = tempfile::tempdir().unwrap();
        let bogus = tmp.path().join("not-a-dir");
        fs::write(&bogus, b"this is a file, not a directory").unwrap();
        let err = PolicyPartition::load_from_dir(&bogus, normalize_test).unwrap_err();
        assert!(matches!(err, PartitionError::NotADirectory(_)));
    }

    #[test]
    fn root_lookup_returns_raw_pem_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        build_partition(tmp.path(), false, false);
        let p = PolicyPartition::load_from_dir(tmp.path(), normalize_test).expect("loads");
        let pem = p.root("sumo-sign.pem").expect("present");
        assert!(pem.starts_with(b"-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn default_mount_path_constant_matches_spec() {
        // AUTH-ARCH-001 §4 anchors `/etc/sumo/policy/` as the canonical
        // mount path. If this constant drifts, audit lines + operator
        // scripts go out of sync.
        assert_eq!(PolicyPartition::DEFAULT_MOUNT, "/etc/sumo/policy");
    }

    #[test]
    fn empty_crl_round_trips() {
        let crl = Crl::default();
        assert!(!crl.is_cert_revoked("anything"));
        assert!(!crl.is_jwt_revoked("anything"));

        let crl: Crl = serde_yaml::from_str("{}").unwrap();
        assert_eq!(crl, Crl::default());
    }
}
