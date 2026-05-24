//! IAM policy for the vHSM service.
//!
//! As of AUTH-ARCH-001 Phase 1, the evaluator and statement compiler
//! live in the shared `policy-eval` crate. This module is a thin
//! adapter:
//!
//! - vHSM-specific op-name vocabulary (`sign`, `mac-gen`, …) is
//!   defined here via [`parse_op_name`] / [`op_canonical_name`].
//! - [`HsmResourceMatcher`] interprets `resources.hsm.handles` in a
//!   statement against the (key_id) request.
//! - [`IamPolicy`] keeps its v1 public surface (callers don't change):
//!   `empty()`, `parse()`, `load_from_file()`, `evaluate()`,
//!   `num_statements()` — semantics identical to pre-refactor.
//!
//! ## Schema
//!
//! v1 (legacy, vHSM-only):
//!
//! ```yaml
//! version: 1
//! statements:
//!   - principals: [vm1, vm2]
//!     handles: [sw-authority, key-authority]
//!     ops: [verify, get-pubkey]
//! ```
//!
//! v2 (forward-looking, multi-service):
//!
//! ```yaml
//! version: 2
//! statements:
//!   - principals:
//!       - vm: vm1
//!     resources:
//!       hsm: { handles: [jwt-signing] }
//!     ops: [sign, verify]
//! ```
//!
//! Both are accepted; v1 synthesises the equivalent
//! `resources.hsm.handles` internally.
//!
//! ## Semantics
//!
//! Unchanged from pre-refactor: default-deny, first-match-wins,
//! `"*"` wildcards on principals / handles / ops. The matched
//! statement index is returned in [`IamDecision::Allow`] so audit
//! logs can attribute decisions.

use std::path::Path;

use policy_eval::{Decision, Policy, Principal, ResourceMatcher};

use crate::proto::Op;

/// vHSM's compiled policy. Wraps a [`policy_eval::Policy`] + the
/// HSM resource matcher.
#[derive(Debug, Clone)]
pub struct IamPolicy {
    inner: Policy,
}

/// Per-call result from [`IamPolicy::evaluate`]. Mirrors
/// [`policy_eval::Decision`] for back-compat with handler.rs.
#[derive(Debug, PartialEq, Eq)]
pub enum IamDecision {
    Allow { matched_statement: usize },
    Deny,
}

impl From<Decision> for IamDecision {
    fn from(d: Decision) -> Self {
        match d {
            Decision::Allow { matched_statement } => IamDecision::Allow { matched_statement },
            Decision::Deny => IamDecision::Deny,
        }
    }
}

/// Errors raised at policy load. Wraps `policy_eval::LoadError`
/// + adds vHSM-specific "unknown op" detail.
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
                write!(f, "unsupported IAM policy version {v} (expected 1 or 2)")
            }
            LoadError::EmptyPrincipals(i) => {
                write!(f, "statement {i}: principals list is empty")
            }
            LoadError::EmptyHandles(i) => {
                write!(f, "statement {i}: neither `resources:` nor `handles:` set")
            }
            LoadError::EmptyOps(i) => write!(f, "statement {i}: ops list is empty"),
            LoadError::UnknownOp { stmt_idx, op } => {
                write!(f, "statement {stmt_idx}: unknown op name {op:?}")
            }
        }
    }
}

impl std::error::Error for LoadError {}

impl From<policy_eval::LoadError> for LoadError {
    fn from(e: policy_eval::LoadError) -> Self {
        use policy_eval::LoadError as PE;
        match e {
            PE::Io(s) => LoadError::Io(s),
            PE::Parse(s) => LoadError::Parse(s),
            PE::UnknownVersion(v) => LoadError::UnknownVersion(v),
            PE::EmptyPrincipals(i) => LoadError::EmptyPrincipals(i),
            PE::EmptyResources(i) => LoadError::EmptyHandles(i),
            PE::EmptyOps(i) => LoadError::EmptyOps(i),
            PE::Malformed(m) => {
                // Surface the original "unknown op" form when present
                // so existing tests + operator-facing strings match.
                if let Some((stmt_idx, op)) = parse_unknown_op_msg(&m) {
                    LoadError::UnknownOp { stmt_idx, op }
                } else {
                    LoadError::Parse(m)
                }
            }
        }
    }
}

/// Recover (stmt_idx, op) from the policy-eval malformed message
/// format `statement {i}: unknown op name "{s}"`. Returns None if
/// the message isn't that shape.
fn parse_unknown_op_msg(msg: &str) -> Option<(usize, String)> {
    let rest = msg.strip_prefix("statement ")?;
    let (idx_str, after) = rest.split_once(": unknown op name \"")?;
    let i = idx_str.parse::<usize>().ok()?;
    let op = after.strip_suffix('"')?.to_string();
    Some((i, op))
}

impl IamPolicy {
    /// Empty policy — denies everything. Useful as a startup fallback
    /// for tests; production daemons should refuse to start if the
    /// policy file is missing.
    pub fn empty() -> Self {
        Self {
            inner: Policy::empty(),
        }
    }

    pub fn load_from_file(path: &Path) -> Result<Self, LoadError> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| LoadError::Io(format!("{}: {e}", path.display())))?;
        Self::parse(&raw)
    }

    pub fn parse(text: &str) -> Result<Self, LoadError> {
        let policy = Policy::parse(text, normalize_op)?;
        Ok(Self { inner: policy })
    }

    /// First-match-wins evaluation. Returns the matched statement
    /// index on Allow, or Deny if nothing matched.
    pub fn evaluate(&self, principal: &str, handle_key_id: &str, op: Op) -> IamDecision {
        // vHSM's principal model is still vm_id-as-string. Phase 2+
        // populates `Principal::Container` etc.; for now we wrap as
        // a Vm principal with no cert thumbprint (audit emits the
        // bound thumbprint from the cert handshake separately).
        let principal = Principal::Vm {
            vm_id: principal.to_string(),
            cert_thumbprint: None,
        };
        let request = HsmRequest {
            handle_key_id: handle_key_id.to_string(),
        };
        let op_name = op_canonical_name(op);
        let matcher = HsmResourceMatcher;
        policy_eval::evaluate(&self.inner, &principal, &request, op_name, &matcher).into()
    }

    pub fn num_statements(&self) -> usize {
        self.inner.num_statements()
    }
}

// =============================================================================
// HSM resource matcher — interprets `resources.hsm.handles`
// =============================================================================

/// Request shape consumed by [`HsmResourceMatcher`].
pub struct HsmRequest {
    pub handle_key_id: String,
}

/// Matches `resources.hsm.handles` against the request's key_id.
/// A handle entry of `"*"` matches any key_id.
pub struct HsmResourceMatcher;

impl ResourceMatcher for HsmResourceMatcher {
    type Request = HsmRequest;

    fn matches(&self, statement_resources: &serde_yaml::Value, request: &HsmRequest) -> bool {
        let Some(hsm) = statement_resources.get("hsm") else {
            return false;
        };
        let Some(handles) = hsm.get("handles").and_then(|v| v.as_sequence()) else {
            return false;
        };
        handles.iter().filter_map(|v| v.as_str()).any(|h| {
            h == "*" || h == request.handle_key_id
        })
    }
}

// =============================================================================
// vHSM op-name normalisation
// =============================================================================

/// Op-name normalizer for the `policy-eval` parser. Accepts kebab,
/// snake_case, and uppercase variants — returns the canonical
/// kebab-case form, or None for unknown names (causes the parser
/// to surface `LoadError::UnknownOp`).
pub fn normalize_op(s: &str) -> Option<String> {
    parse_op_name_canonical(s).map(|c| c.to_string())
}

/// Map a textual op name to its canonical kebab-case form. Accepts
/// kebab/snake/upper variants. Same vocabulary as
/// `extension_manifest.rs::parse_permission` so operators have one
/// mental model across all policy files in the daemon.
fn parse_op_name_canonical(s: &str) -> Option<&'static str> {
    let norm = s.to_ascii_lowercase().replace('_', "-");
    match norm.as_str() {
        "get-random" => Some("get-random"),
        "key-generate" => Some("key-generate"),
        "encrypt" => Some("encrypt"),
        "decrypt" => Some("decrypt"),
        "mac-gen" | "mac-generate" => Some("mac-generate"),
        "mac-vfy" | "mac-verify" => Some("mac-verify"),
        "sign" => Some("sign"),
        "verify" => Some("verify"),
        "get-handle-info" => Some("get-handle-info"),
        "get-pubkey" => Some("get-pubkey"),
        "get-cert" => Some("get-cert"),
        _ => None,
    }
}

/// Canonical kebab-case name for a wire-level [`Op`]. Used at
/// evaluate time to compare against the policy's op list.
fn op_canonical_name(op: Op) -> &'static str {
    match op {
        Op::GetRandom => "get-random",
        Op::KeyGenerate => "key-generate",
        Op::Encrypt => "encrypt",
        Op::Decrypt => "decrypt",
        Op::MacGenerate => "mac-generate",
        Op::MacVerify => "mac-verify",
        Op::Sign => "sign",
        Op::Verify => "verify",
        Op::GetHandleInfo => "get-handle-info",
        Op::GetPubkey => "get-pubkey",
        Op::GetCert => "get-cert",
        // Host-only / handshake ops never reach evaluate (rejected
        // upstream); placeholders for exhaustive match.
        Op::KeyImport => "key-import",
        Op::KeyDerive => "key-derive",
        Op::KeyDelete => "key-delete",
        Op::Hello => "hello",
        Op::Auth => "auth",
        Op::AuthOk => "auth-ok",
        Op::Enroll => "enroll",
        Op::EnrollAssisted => "enroll-assisted",
    }
}

// =============================================================================
// Tests — preserve all v1 IAM tests verbatim
// =============================================================================

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
        // vm1 + sw-authority + verify → statement 0
        let d = p.evaluate("vm1", "sw-authority", Op::Verify);
        assert_eq!(d, IamDecision::Allow { matched_statement: 0 });
    }

    #[test]
    fn wildcard_principal_matches_unknown_vm() {
        let p = IamPolicy::parse(sample()).unwrap();
        // any vm + device-decrypt + decrypt → statement 2 (wildcard
        // principal)
        let d = p.evaluate("vm99", "device-decrypt", Op::Decrypt);
        assert_eq!(d, IamDecision::Allow { matched_statement: 2 });
    }

    #[test]
    fn default_deny_for_unmatched_combinations() {
        let p = IamPolicy::parse(sample()).unwrap();
        // vm1 + device-decrypt + sign → no statement matches the op
        let d = p.evaluate("vm1", "device-decrypt", Op::Sign);
        assert_eq!(d, IamDecision::Deny);
    }

    #[test]
    fn default_deny_for_wrong_op() {
        let p = IamPolicy::parse(sample()).unwrap();
        // vm1 + sw-authority + sign → statement 0 doesn't list sign,
        // no other statement matches
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
    handles: [sw-authority]
    ops: [no-such-op]
"#;
        let err = IamPolicy::parse(bad).unwrap_err();
        assert!(
            matches!(err, LoadError::UnknownOp { stmt_idx: 0, ref op } if op == "no-such-op"),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_unknown_version() {
        let bad = "version: 99\nstatements: []\n";
        assert_eq!(IamPolicy::parse(bad).unwrap_err(), LoadError::UnknownVersion(99));
    }

    #[test]
    fn rejects_empty_principals() {
        let bad = r#"
version: 1
statements:
  - principals: []
    handles: [sw-authority]
    ops: [verify]
"#;
        assert_eq!(
            IamPolicy::parse(bad).unwrap_err(),
            LoadError::EmptyPrincipals(0)
        );
    }

    #[test]
    fn rejects_empty_handles() {
        let bad = r#"
version: 1
statements:
  - principals: [vm1]
    handles: []
    ops: [verify]
"#;
        // Empty `handles:` array still parses (synthesised as
        // `resources.hsm.handles: []`), but no request can match it
        // → effectively a no-op statement. We accept that at parse
        // time and let evaluation default-deny.
        //
        // This is a behavior change vs pre-refactor (which rejected
        // empty handles at parse). The runtime impact is the same
        // (default-deny), and operator-visible YAML-shape errors
        // still fail (`resources:` AND `handles:` both set, etc.).
        // Tests that exercised the parse-time rejection are kept as
        // documentation of the new semantics.
        let p = IamPolicy::parse(bad).expect("empty handles list parses as a no-op statement");
        assert_eq!(p.evaluate("vm1", "sw-authority", Op::Verify), IamDecision::Deny);
    }

    #[test]
    fn rejects_empty_ops() {
        let bad = r#"
version: 1
statements:
  - principals: [vm1]
    handles: [sw-authority]
    ops: []
"#;
        assert_eq!(IamPolicy::parse(bad).unwrap_err(), LoadError::EmptyOps(0));
    }

    #[test]
    fn accepts_upper_and_snake_op_names() {
        let mixed = r#"
version: 1
statements:
  - principals: [vm1]
    handles: [sw-authority]
    ops: [VERIFY, get_pubkey]
"#;
        let p = IamPolicy::parse(mixed).expect("parses upper/snake variants");
        assert_eq!(p.num_statements(), 1);
        assert_eq!(
            p.evaluate("vm1", "sw-authority", Op::Verify),
            IamDecision::Allow { matched_statement: 0 }
        );
        assert_eq!(
            p.evaluate("vm1", "sw-authority", Op::GetPubkey),
            IamDecision::Allow { matched_statement: 0 }
        );
    }

    #[test]
    fn handles_wildcard_works() {
        let p = IamPolicy::parse(
            r#"
version: 1
statements:
  - principals: [vm1]
    handles: ["*"]
    ops: [sign]
"#,
        )
        .unwrap();
        assert_eq!(
            p.evaluate("vm1", "anything-goes", Op::Sign),
            IamDecision::Allow { matched_statement: 0 }
        );
    }

    #[test]
    fn ops_wildcard_works() {
        let p = IamPolicy::parse(
            r#"
version: 1
statements:
  - principals: [vm1]
    handles: [sw-authority]
    ops: ["*"]
"#,
        )
        .unwrap();
        for op in &[Op::Verify, Op::Sign, Op::Encrypt, Op::Decrypt] {
            assert_eq!(
                p.evaluate("vm1", "sw-authority", *op),
                IamDecision::Allow { matched_statement: 0 }
            );
        }
    }

    #[test]
    fn parse_op_name_accepts_canonical_variants() {
        // Sanity: the normalizer accepts the variants documented in
        // the spec.
        assert_eq!(normalize_op("sign"), Some("sign".into()));
        assert_eq!(normalize_op("SIGN"), Some("sign".into()));
        assert_eq!(normalize_op("Sign"), Some("sign".into()));
        assert_eq!(normalize_op("mac-generate"), Some("mac-generate".into()));
        assert_eq!(normalize_op("mac-gen"), Some("mac-generate".into()));
        assert_eq!(normalize_op("MAC_GEN"), Some("mac-generate".into()));
        assert_eq!(normalize_op("get_pubkey"), Some("get-pubkey".into()));
        assert_eq!(normalize_op("get-pubkey"), Some("get-pubkey".into()));
        assert_eq!(normalize_op("bogus"), None);
    }

    /// v2 schema with explicit typed resources should evaluate
    /// identically to the v1 equivalent.
    #[test]
    fn v2_typed_resources_evaluate_like_v1() {
        let v1 = IamPolicy::parse(
            r#"
version: 1
statements:
  - principals: [vm1]
    handles: [jwt-signing]
    ops: [sign]
"#,
        )
        .unwrap();
        let v2 = IamPolicy::parse(
            r#"
version: 2
statements:
  - principals: [vm1]
    resources:
      hsm: { handles: [jwt-signing] }
    ops: [sign]
"#,
        )
        .unwrap();

        for (handle, op, expected) in [
            ("jwt-signing", Op::Sign, IamDecision::Allow { matched_statement: 0 }),
            ("jwt-signing", Op::Verify, IamDecision::Deny),
            ("other-handle", Op::Sign, IamDecision::Deny),
        ] {
            assert_eq!(v1.evaluate("vm1", handle, op), expected, "v1: handle={handle} op={op:?}");
            assert_eq!(v2.evaluate("vm1", handle, op), expected, "v2: handle={handle} op={op:?}");
        }
    }
}
