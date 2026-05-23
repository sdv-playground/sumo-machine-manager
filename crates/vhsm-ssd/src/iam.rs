//! IAM policy expressions for the v3 protocol.
//!
//! Replaces the v2 source-IP allow-list (which conflated identity
//! and authorisation) with a per-key-class policy DSL evaluated at
//! every op. Identity is sourced from the AUTH-resolved cert
//! subject in `auth.rs`; authorisation is `(principal, handle,
//! op) → Allow | Deny`.
//!
//! ## Schema
//!
//! ```yaml
//! version: 1
//! statements:
//!   - principals: [vm1, vm2]
//!     handles: [sw-authority, key-authority]
//!     ops: [verify, get-pubkey]
//!
//!   - principals: [vm1]
//!     handles: [iam-signing, jwt-signing]
//!     ops: [sign, verify, get-pubkey, get-cert]
//!
//!   - principals: ["*"]
//!     handles: [device-decrypt]
//!     ops: [decrypt]               # any authenticated guest may decrypt
//!
//!   # Project-extension handles work the same way:
//!   - principals: [vm2]
//!     handles: [mqtt-client-cert]
//!     ops: [sign, verify, get-pubkey, get-cert]
//! ```
//!
//! ## Semantics
//!
//! - **Default deny.** Empty `statements` list rejects everything.
//! - **First match wins.** Statements are evaluated in declared
//!   order; the first `(principals × handles × ops)` triple that
//!   covers the caller's request returns Allow. No precedence,
//!   no explicit-deny-overrides-allow.
//! - **Wildcards.** `principals: ["*"]` and `handles: ["*"]` both
//!   supported. No glob patterns — v1 keeps it simple.
//! - **Op-name strings** are kebab-case lower (`sign`, `mac-gen`,
//!   `get-pubkey`, etc.). Same vocabulary as
//!   `extension_manifest.rs::parse_permission` for consistency
//!   across the daemon. Accepts upper/underscore variants for
//!   convenience; `SIGN`, `Sign`, `sign`, and `mac-generate` all
//!   normalise the same way.
//! - **Handle name strings** are the `key_id` field from
//!   `HandleEntry` (the same string passed to
//!   `register_well_known`). Standard well-known names:
//!   `sw-authority`, `key-authority`, `device-decrypt`, `iam-signing`,
//!   `jwt-signing`, `storage`. Project-extension key_ids
//!   (e.g. `mqtt-client-cert`) are allowed verbatim.
//!
//! ## Evaluation result
//!
//! `evaluate()` returns the matched statement index (or `None` for
//! deny). The audit log carries that index in the `iam_statement`
//! field so an operator can grep deny lines and trace them back to
//! a specific (or absent) policy statement.

use std::collections::HashSet;
use std::path::Path;

use serde::Deserialize;

use crate::proto::Op;

/// Top-level on-disk shape.
#[derive(Debug, Clone, Deserialize)]
struct PolicyFile {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    statements: Vec<RawStatement>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawStatement {
    #[serde(default)]
    principals: Vec<String>,
    #[serde(default)]
    handles: Vec<String>,
    #[serde(default)]
    ops: Vec<String>,
}

/// Compiled, in-memory policy.
#[derive(Debug, Clone)]
pub struct IamPolicy {
    statements: Vec<Statement>,
}

/// One compiled statement. Sets give O(1) lookup at evaluate time.
#[derive(Debug, Clone)]
struct Statement {
    principals: PrincipalMatch,
    handles: HandleMatch,
    ops: OpMatch,
}

#[derive(Debug, Clone)]
enum PrincipalMatch {
    Any,
    Exact(HashSet<String>),
}

#[derive(Debug, Clone)]
enum HandleMatch {
    Any,
    Exact(HashSet<String>),
}

#[derive(Debug, Clone)]
enum OpMatch {
    Any,
    Exact(HashSet<Op>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum LoadError {
    Io(String),
    Parse(String),
    UnknownVersion(u32),
    EmptyPrincipals(usize),
    EmptyHandles(usize),
    EmptyOps(usize),
    UnknownOp { stmt_idx: usize, op: String },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Io(e) => write!(f, "i/o error reading IAM policy: {e}"),
            LoadError::Parse(e) => write!(f, "parse error in IAM policy: {e}"),
            LoadError::UnknownVersion(v) => {
                write!(f, "unsupported IAM policy version {v} (expected 1)")
            }
            LoadError::EmptyPrincipals(i) => {
                write!(f, "statement {i}: principals list is empty")
            }
            LoadError::EmptyHandles(i) => write!(f, "statement {i}: handles list is empty"),
            LoadError::EmptyOps(i) => write!(f, "statement {i}: ops list is empty"),
            LoadError::UnknownOp { stmt_idx, op } => {
                write!(f, "statement {stmt_idx}: unknown op name {op:?}")
            }
        }
    }
}

impl std::error::Error for LoadError {}

/// Per-call result from [`IamPolicy::evaluate`].
#[derive(Debug, PartialEq, Eq)]
pub enum IamDecision {
    /// First matching statement (0-based index into the policy file
    /// — humans read 1-based; conversion happens at the audit log
    /// boundary).
    Allow { matched_statement: usize },
    /// No statement matched — default-deny.
    Deny,
}

impl IamPolicy {
    /// Empty policy — denies everything. Useful as a startup
    /// fallback for tests; production daemons should refuse to
    /// start if the policy file is missing.
    pub fn empty() -> Self {
        Self { statements: vec![] }
    }

    pub fn load_from_file(path: &Path) -> Result<Self, LoadError> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| LoadError::Io(format!("{}: {e}", path.display())))?;
        Self::parse(&raw)
    }

    pub fn parse(text: &str) -> Result<Self, LoadError> {
        let file: PolicyFile =
            serde_yaml::from_str(text).map_err(|e| LoadError::Parse(e.to_string()))?;
        if file.version != 1 {
            return Err(LoadError::UnknownVersion(file.version));
        }
        let mut statements = Vec::with_capacity(file.statements.len());
        for (i, raw) in file.statements.iter().enumerate() {
            if raw.principals.is_empty() {
                return Err(LoadError::EmptyPrincipals(i));
            }
            if raw.handles.is_empty() {
                return Err(LoadError::EmptyHandles(i));
            }
            if raw.ops.is_empty() {
                return Err(LoadError::EmptyOps(i));
            }
            statements.push(Statement {
                principals: compile_principal_match(&raw.principals),
                handles: compile_handle_match(&raw.handles),
                ops: compile_op_match(&raw.ops, i)?,
            });
        }
        Ok(IamPolicy { statements })
    }

    /// First-match-wins evaluation. Returns the matched statement
    /// index on Allow, or Deny if nothing matched.
    pub fn evaluate(&self, principal: &str, handle_key_id: &str, op: Op) -> IamDecision {
        for (i, stmt) in self.statements.iter().enumerate() {
            if !stmt.principals.matches(principal) {
                continue;
            }
            if !stmt.handles.matches(handle_key_id) {
                continue;
            }
            if !stmt.ops.matches(op) {
                continue;
            }
            return IamDecision::Allow {
                matched_statement: i,
            };
        }
        IamDecision::Deny
    }

    pub fn num_statements(&self) -> usize {
        self.statements.len()
    }
}

// ---- compile helpers --------------------------------------------

fn compile_principal_match(list: &[String]) -> PrincipalMatch {
    if list.iter().any(|s| s == "*") {
        PrincipalMatch::Any
    } else {
        PrincipalMatch::Exact(list.iter().cloned().collect())
    }
}

fn compile_handle_match(list: &[String]) -> HandleMatch {
    if list.iter().any(|s| s == "*") {
        HandleMatch::Any
    } else {
        HandleMatch::Exact(list.iter().cloned().collect())
    }
}

fn compile_op_match(list: &[String], stmt_idx: usize) -> Result<OpMatch, LoadError> {
    if list.iter().any(|s| s == "*") {
        return Ok(OpMatch::Any);
    }
    let mut set = HashSet::new();
    for s in list {
        match parse_op_name(s) {
            Some(op) => {
                set.insert(op);
            }
            None => {
                return Err(LoadError::UnknownOp {
                    stmt_idx,
                    op: s.clone(),
                })
            }
        }
    }
    Ok(OpMatch::Exact(set))
}

impl PrincipalMatch {
    fn matches(&self, p: &str) -> bool {
        match self {
            PrincipalMatch::Any => true,
            PrincipalMatch::Exact(set) => set.contains(p),
        }
    }
}

impl HandleMatch {
    fn matches(&self, h: &str) -> bool {
        match self {
            HandleMatch::Any => true,
            HandleMatch::Exact(set) => set.contains(h),
        }
    }
}

impl OpMatch {
    fn matches(&self, op: Op) -> bool {
        match self {
            OpMatch::Any => true,
            OpMatch::Exact(set) => set.contains(&op),
        }
    }
}

/// Map a textual op name to the [`Op`] enum. Accepts kebab/snake/
/// upper variants. Same vocabulary as the extension-manifest
/// permission parser so operators have one mental model across all
/// policy files in the daemon.
fn parse_op_name(s: &str) -> Option<Op> {
    let norm = s.to_ascii_lowercase().replace('_', "-");
    match norm.as_str() {
        "get-random" => Some(Op::GetRandom),
        "key-generate" => Some(Op::KeyGenerate),
        "encrypt" => Some(Op::Encrypt),
        "decrypt" => Some(Op::Decrypt),
        "mac-gen" | "mac-generate" => Some(Op::MacGenerate),
        "mac-vfy" | "mac-verify" => Some(Op::MacVerify),
        "sign" => Some(Op::Sign),
        "verify" => Some(Op::Verify),
        "get-handle-info" => Some(Op::GetHandleInfo),
        "get-pubkey" => Some(Op::GetPubkey),
        "get-cert" => Some(Op::GetCert),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> &'static str {
        r#"
version: 1
statements:
  - principals: [vm1, vm2]
    handles: [sw-authority, key-authority]
    ops: [verify, get-pubkey]
  - principals: [vm1]
    handles: [iam-signing, jwt-signing]
    ops: [sign, verify, get-pubkey, get-cert]
  - principals: ["*"]
    handles: [device-decrypt]
    ops: [decrypt]
  - principals: [vm2]
    handles: [mqtt-client-cert]
    ops: [sign, verify, get-pubkey, get-cert]
"#
    }

    #[test]
    fn parses_sample_policy() {
        let p = IamPolicy::parse(sample()).unwrap();
        assert_eq!(p.num_statements(), 4);
    }

    #[test]
    fn empty_policy_denies_everything() {
        let p = IamPolicy::empty();
        assert_eq!(p.evaluate("vm1", "sw-authority", Op::Verify), IamDecision::Deny);
    }

    #[test]
    fn first_match_wins() {
        let p = IamPolicy::parse(sample()).unwrap();
        // vm1 + sw-authority + verify → matches statement 0 (vm1
        // + sw-authority + verify), NOT statement 2 (any + decrypt).
        let d = p.evaluate("vm1", "sw-authority", Op::Verify);
        assert_eq!(d, IamDecision::Allow { matched_statement: 0 });
    }

    #[test]
    fn wildcard_principal_matches_unknown_vm() {
        let p = IamPolicy::parse(sample()).unwrap();
        // vmX + device-decrypt + decrypt → matches statement 2 (any
        // principal).
        let d = p.evaluate("vmX", "device-decrypt", Op::Decrypt);
        assert_eq!(d, IamDecision::Allow { matched_statement: 2 });
    }

    #[test]
    fn default_deny_for_unmatched_combinations() {
        let p = IamPolicy::parse(sample()).unwrap();
        // vm2 + iam-signing + sign → no statement covers this.
        // Statement 1 is vm1-only for iam-signing.
        let d = p.evaluate("vm2", "iam-signing", Op::Sign);
        assert_eq!(d, IamDecision::Deny);
    }

    #[test]
    fn default_deny_for_wrong_op() {
        let p = IamPolicy::parse(sample()).unwrap();
        // vm1 + sw-authority + sign → statement 0 covers verify
        // and get-pubkey, NOT sign.
        let d = p.evaluate("vm1", "sw-authority", Op::Sign);
        assert_eq!(d, IamDecision::Deny);
    }

    #[test]
    fn project_extension_handle_in_policy() {
        let p = IamPolicy::parse(sample()).unwrap();
        let d = p.evaluate("vm2", "mqtt-client-cert", Op::Sign);
        assert_eq!(d, IamDecision::Allow { matched_statement: 3 });
        let d = p.evaluate("vm1", "mqtt-client-cert", Op::Sign);
        assert_eq!(d, IamDecision::Deny); // only vm2 may use it
    }

    #[test]
    fn rejects_unknown_op_name_in_policy() {
        let bad = r#"
version: 1
statements:
  - principals: [vm1]
    handles: [storage]
    ops: [encrypt, fly]
"#;
        let err = IamPolicy::parse(bad).unwrap_err();
        assert_eq!(
            err,
            LoadError::UnknownOp {
                stmt_idx: 0,
                op: "fly".to_string(),
            }
        );
    }

    #[test]
    fn rejects_unknown_version() {
        let bad = "version: 99\nstatements: []\n";
        assert_eq!(IamPolicy::parse(bad).unwrap_err(), LoadError::UnknownVersion(99));
    }

    #[test]
    fn rejects_empty_principals() {
        let bad = "version: 1\nstatements:\n  - handles: [storage]\n    ops: [encrypt]\n";
        assert_eq!(
            IamPolicy::parse(bad).unwrap_err(),
            LoadError::EmptyPrincipals(0)
        );
    }

    #[test]
    fn rejects_empty_handles() {
        let bad = "version: 1\nstatements:\n  - principals: [vm1]\n    ops: [encrypt]\n";
        assert_eq!(IamPolicy::parse(bad).unwrap_err(), LoadError::EmptyHandles(0));
    }

    #[test]
    fn rejects_empty_ops() {
        let bad = "version: 1\nstatements:\n  - principals: [vm1]\n    handles: [storage]\n";
        assert_eq!(IamPolicy::parse(bad).unwrap_err(), LoadError::EmptyOps(0));
    }

    #[test]
    fn accepts_upper_and_snake_op_names() {
        let p = IamPolicy::parse(
            r#"
version: 1
statements:
  - principals: [vm1]
    handles: [jwt-signing]
    ops: [SIGN, MAC_GEN, GET_PUBKEY]
"#,
        )
        .unwrap();
        assert_eq!(
            p.evaluate("vm1", "jwt-signing", Op::Sign),
            IamDecision::Allow { matched_statement: 0 }
        );
        assert_eq!(
            p.evaluate("vm1", "jwt-signing", Op::MacGenerate),
            IamDecision::Allow { matched_statement: 0 }
        );
        assert_eq!(
            p.evaluate("vm1", "jwt-signing", Op::GetPubkey),
            IamDecision::Allow { matched_statement: 0 }
        );
    }

    #[test]
    fn handles_wildcard_works() {
        let p = IamPolicy::parse(
            r#"
version: 1
statements:
  - principals: [super-vm]
    handles: ["*"]
    ops: [verify]
"#,
        )
        .unwrap();
        assert_eq!(
            p.evaluate("super-vm", "any-key-id-at-all", Op::Verify),
            IamDecision::Allow { matched_statement: 0 }
        );
    }

    #[test]
    fn ops_wildcard_works() {
        let p = IamPolicy::parse(
            r#"
version: 1
statements:
  - principals: [admin]
    handles: [storage]
    ops: ["*"]
"#,
        )
        .unwrap();
        for op in [Op::Encrypt, Op::Decrypt, Op::Sign, Op::Verify] {
            assert_eq!(
                p.evaluate("admin", "storage", op),
                IamDecision::Allow { matched_statement: 0 }
            );
        }
    }

    #[test]
    fn parse_op_name_accepts_canonical_variants() {
        assert_eq!(parse_op_name("get-pubkey"), Some(Op::GetPubkey));
        assert_eq!(parse_op_name("GET_PUBKEY"), Some(Op::GetPubkey));
        assert_eq!(parse_op_name("MAC_GENERATE"), Some(Op::MacGenerate));
        assert_eq!(parse_op_name("mac-gen"), Some(Op::MacGenerate));
        assert_eq!(parse_op_name("unknown"), None);
    }
}
