//! Shared policy schema + evaluator.
//!
//! See `guest-vm-spec/specs/auth/architecture.md` (AUTH-ARCH-001) §5
//! for the design. This crate provides the matcher-agnostic core:
//!
//! - [`Principal`] — the typed identity of a caller (VM, container,
//!   tester, device, anonymous).
//! - [`Statement`] — one row of a policy file: principal selectors +
//!   typed resource block + op list + optional conditions.
//! - [`Decision`] — Allow with the matched statement index, or Deny.
//! - [`ResourceMatcher`] — trait each service implements to interpret
//!   its own resource subtree (e.g. vHSM matches `resources.hsm`,
//!   signal services match `resources.signals`).
//! - [`evaluate`] — first-match-wins evaluator. Returns Decision.
//!
//! The crate is intentionally minimal. Services own their resource
//! shapes; this crate owns identity, statement iteration, op matching,
//! and the default-deny semantic.
//!
//! ## Policy file shape (illustrative)
//!
//! ```yaml
//! version: 2
//! statements:
//!   - principals:
//!       - vm: vm1
//!       - vm: vm1
//!         container: telemetry-uploader
//!   resources:
//!     hsm: { handles: [jwt-signing] }
//!   ops: [sign, verify]
//! ```
//!
//! This crate parses the matcher-agnostic layer (principals, ops,
//! resources-as-opaque-yaml). The `resources` subtree is handed to a
//! service-specific [`ResourceMatcher`] at evaluate time.

use std::collections::HashSet;

use serde::Deserialize;

// =============================================================================
// Principal
// =============================================================================

/// Caller identity, populated by the service's authentication layer
/// before invoking [`evaluate`]. Each variant carries the fields a
/// principal-selector statement can match on.
///
/// Phase 1: only `Vm` is populated by current services. Adding
/// `Container` / `Tester` here unlocks AUTH-ARCH-001 Phase 2+ without
/// changing the evaluator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// A guest VM authenticated via the vHSM cert handshake.
    Vm {
        vm_id: String,
        cert_thumbprint: Option<[u8; 32]>,
    },
    /// A container running inside a VM, authenticated via JWT.
    Container {
        vm_id: String,
        container: String,
        image_digest: Option<String>,
    },
    /// An external tester authenticated via JWT from an IdP.
    Tester {
        idp: String,
        sub: String,
        role: Option<String>,
        scope: Vec<String>,
    },
    /// The device itself acting as a principal (host-internal services).
    Device { serial: String },
    /// No authenticated identity. Used for unauthenticated probes
    /// (e.g. metrics scrape) — policy can match `Anonymous` explicitly
    /// to allow such access.
    Anonymous,
}

impl Principal {
    /// Human-readable identifier for audit lines. Stable per principal
    /// type — operators can grep on it.
    pub fn display_id(&self) -> String {
        match self {
            Principal::Vm { vm_id, .. } => format!("vm:{vm_id}"),
            Principal::Container { vm_id, container, .. } => {
                format!("vm:{vm_id}/container:{container}")
            }
            Principal::Tester { idp, sub, .. } => format!("tester:{idp}/{sub}"),
            Principal::Device { serial } => format!("device:{serial}"),
            Principal::Anonymous => "anonymous".to_string(),
        }
    }
}

// =============================================================================
// PrincipalSelector — one entry in a statement's `principals:` list
// =============================================================================

/// On-disk shape of a principal selector.
///
/// Three accepted forms (all valid YAML):
///
/// ```yaml
/// # 1. Bare string — back-compat with vHSM v1 IAM:
/// principals: [vm1, vm2, "*"]
///
/// # 2. Typed object — forward-looking schema:
/// principals:
///   - vm: vm1
///   - vm: vm1
///     container: telemetry-uploader
///   - tester:
///       idp: "*"
///       role: workshop-tech
/// ```
///
/// Bare strings parse as `Vm { vm_id: <string> }`. The literal `"*"`
/// in either form matches any principal.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum RawPrincipalSelector {
    /// Bare string — v1 back-compat. `"*"` matches any.
    Bare(String),
    /// Typed object — v2 schema.
    Typed(TypedPrincipalSelector),
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TypedPrincipalSelector {
    #[serde(default)]
    pub vm: Option<String>,
    #[serde(default)]
    pub container: Option<String>,
    #[serde(default)]
    pub image_digest: Option<String>,
    #[serde(default)]
    pub tester: Option<TesterSelector>,
    #[serde(default)]
    pub device: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TesterSelector {
    #[serde(default)]
    pub idp: Option<String>,
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
}

/// Compiled principal selector. The compile step happens at policy
/// load — see [`PrincipalSelector::compile`].
#[derive(Debug, Clone)]
pub enum PrincipalSelector {
    /// Matches any principal regardless of type.
    Any,
    /// Matches `Principal::Vm` with the given vm_id.
    Vm { vm_id: String },
    /// Matches `Principal::Container` with the given vm_id and optional
    /// container name + image_digest. `None` fields are wildcards
    /// within the Container variant.
    Container {
        vm_id: String,
        container: Option<String>,
        image_digest: Option<String>,
    },
    /// Matches `Principal::Tester`. `None` fields are wildcards.
    Tester {
        idp: Option<String>,
        sub: Option<String>,
        role: Option<String>,
    },
    /// Matches `Principal::Device` with the given serial.
    Device { serial: String },
    /// Matches the literal `Principal::Anonymous`.
    Anonymous,
}

impl PrincipalSelector {
    fn compile(raw: &RawPrincipalSelector) -> Result<PrincipalSelector, LoadError> {
        match raw {
            RawPrincipalSelector::Bare(s) if s == "*" => Ok(PrincipalSelector::Any),
            RawPrincipalSelector::Bare(s) if s == "anonymous" => Ok(PrincipalSelector::Anonymous),
            // Bare strings = bare vm_ids (v1 IAM back-compat).
            RawPrincipalSelector::Bare(s) => Ok(PrincipalSelector::Vm { vm_id: s.clone() }),
            RawPrincipalSelector::Typed(t) => {
                // Exactly one of vm / tester / device should be set.
                let set_count = [t.vm.is_some(), t.tester.is_some(), t.device.is_some()]
                    .iter()
                    .filter(|x| **x)
                    .count();
                if set_count != 1 {
                    return Err(LoadError::Malformed(format!(
                        "principal selector must set exactly one of vm/tester/device (got {set_count})"
                    )));
                }
                if let Some(vm) = &t.vm {
                    if t.container.is_some() || t.image_digest.is_some() {
                        Ok(PrincipalSelector::Container {
                            vm_id: vm.clone(),
                            container: t.container.clone(),
                            image_digest: t.image_digest.clone(),
                        })
                    } else {
                        Ok(PrincipalSelector::Vm { vm_id: vm.clone() })
                    }
                } else if let Some(tester) = &t.tester {
                    Ok(PrincipalSelector::Tester {
                        idp: tester.idp.clone().filter(|s| s != "*"),
                        sub: tester.sub.clone().filter(|s| s != "*"),
                        role: tester.role.clone().filter(|s| s != "*"),
                    })
                } else if let Some(d) = &t.device {
                    Ok(PrincipalSelector::Device { serial: d.clone() })
                } else {
                    unreachable!("set_count == 1 was enforced above")
                }
            }
        }
    }

    pub fn matches(&self, principal: &Principal) -> bool {
        match (self, principal) {
            (PrincipalSelector::Any, _) => true,
            (PrincipalSelector::Vm { vm_id: w }, Principal::Vm { vm_id: g, .. }) => {
                w == g || w == "*"
            }
            (
                PrincipalSelector::Container {
                    vm_id: w_vm,
                    container: w_c,
                    image_digest: w_img,
                },
                Principal::Container {
                    vm_id: g_vm,
                    container: g_c,
                    image_digest: g_img,
                },
            ) => {
                (w_vm == g_vm || w_vm == "*")
                    && w_c.as_ref().map_or(true, |w| w == g_c)
                    && w_img
                        .as_ref()
                        .map_or(true, |w| g_img.as_ref().map_or(false, |g| w == g))
            }
            (
                PrincipalSelector::Tester {
                    idp: w_idp,
                    sub: w_sub,
                    role: w_role,
                },
                Principal::Tester {
                    idp: g_idp,
                    sub: g_sub,
                    role: g_role,
                    ..
                },
            ) => {
                w_idp.as_ref().map_or(true, |w| w == g_idp)
                    && w_sub.as_ref().map_or(true, |w| w == g_sub)
                    && w_role
                        .as_ref()
                        .map_or(true, |w| g_role.as_ref().map_or(false, |g| w == g))
            }
            (PrincipalSelector::Device { serial: w }, Principal::Device { serial: g }) => {
                w == g || w == "*"
            }
            (PrincipalSelector::Anonymous, Principal::Anonymous) => true,
            // Cross-type — never matches. A `Vm` selector doesn't match
            // a `Container` principal; explicit Container selectors are
            // required for fine-grained gating.
            _ => false,
        }
    }
}

// =============================================================================
// Statement + Policy
// =============================================================================

/// One row of a policy file.
///
/// `resources` is opaque YAML — the service's [`ResourceMatcher`]
/// interprets it. Keeping it opaque here is what lets new resource
/// types ship without changes to this crate.
#[derive(Debug, Clone)]
pub struct Statement {
    pub principals: Vec<PrincipalSelector>,
    pub resources: serde_yaml::Value,
    pub ops: OpSelector,
    /// Optional conditions (rate limit, time window, etc.). Conditions
    /// are evaluated by the calling service — this crate just carries
    /// them through. Phase 1 leaves them as opaque YAML; later phases
    /// add a structured condition type.
    pub conditions: Option<serde_yaml::Value>,
}

/// On-disk form of a statement.
#[derive(Debug, Clone, Deserialize)]
struct RawStatement {
    #[serde(default)]
    principals: Vec<RawPrincipalSelector>,
    #[serde(default)]
    resources: Option<serde_yaml::Value>,
    /// v1 back-compat: bare `handles: [...]` at statement level
    /// means `resources: { hsm: { handles: [...] } }`.
    #[serde(default)]
    handles: Option<Vec<String>>,
    #[serde(default)]
    ops: Vec<String>,
    #[serde(default)]
    conditions: Option<serde_yaml::Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct PolicyFile {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    statements: Vec<RawStatement>,
}

/// Compiled set of statements.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub statements: Vec<Statement>,
}

/// Compiled op selector. `Any` for `["*"]`; `Exact(set)` otherwise.
/// Op-name normalisation (kebab/snake/upper) is the caller's
/// responsibility — services pass canonical names at evaluate time.
#[derive(Debug, Clone)]
pub enum OpSelector {
    Any,
    Exact(HashSet<String>),
}

impl OpSelector {
    pub fn matches(&self, op: &str) -> bool {
        match self {
            OpSelector::Any => true,
            OpSelector::Exact(set) => set.contains(op),
        }
    }
}

// =============================================================================
// Errors
// =============================================================================

#[derive(Debug, PartialEq, Eq)]
pub enum LoadError {
    Io(String),
    Parse(String),
    UnknownVersion(u32),
    EmptyPrincipals(usize),
    EmptyResources(usize),
    EmptyOps(usize),
    Malformed(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Io(e) => write!(f, "i/o error reading policy: {e}"),
            LoadError::Parse(e) => write!(f, "parse error in policy: {e}"),
            LoadError::UnknownVersion(v) => write!(f, "unsupported policy version {v}"),
            LoadError::EmptyPrincipals(i) => write!(f, "statement {i}: principals list is empty"),
            LoadError::EmptyResources(i) => {
                write!(f, "statement {i}: neither `resources:` nor `handles:` set")
            }
            LoadError::EmptyOps(i) => write!(f, "statement {i}: ops list is empty"),
            LoadError::Malformed(m) => write!(f, "malformed policy: {m}"),
        }
    }
}

impl std::error::Error for LoadError {}

// =============================================================================
// Decision
// =============================================================================

/// Result of evaluating one request against a policy.
///
/// On Allow, `matched_statement` is the 0-based index of the first
/// statement that matched. Operators reading audit lines typically
/// see this as a 1-based number — conversion happens at the audit
/// boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow { matched_statement: usize },
    Deny,
}

// =============================================================================
// ResourceMatcher
// =============================================================================

/// Service-specific resource matcher.
///
/// Each service that gates ops via policy implements this trait. The
/// matcher is given the statement's `resources:` subtree (opaque YAML)
/// and a typed request, and decides whether they're compatible.
///
/// Example (vHSM):
///
/// ```ignore
/// struct HsmRequest { handle_key_id: String }
///
/// struct HsmMatcher;
/// impl ResourceMatcher for HsmMatcher {
///     type Request = HsmRequest;
///     fn matches(&self, statement: &serde_yaml::Value, req: &Self::Request) -> bool {
///         let Some(hsm) = statement.get("hsm") else { return false; };
///         let Some(handles) = hsm.get("handles").and_then(|v| v.as_sequence()) else {
///             return false;
///         };
///         handles.iter().filter_map(|v| v.as_str()).any(|h| {
///             h == "*" || h == req.handle_key_id
///         })
///     }
/// }
/// ```
pub trait ResourceMatcher {
    type Request;

    /// Does this statement's resource subtree match the request?
    fn matches(&self, statement_resources: &serde_yaml::Value, request: &Self::Request) -> bool;
}

// =============================================================================
// evaluate
// =============================================================================

/// First-match-wins, default-deny evaluation.
///
/// Returns [`Decision::Allow`] with the index of the first matching
/// statement, or [`Decision::Deny`] if no statement covered the
/// request. Empty policy denies everything.
pub fn evaluate<M: ResourceMatcher>(
    policy: &Policy,
    principal: &Principal,
    request: &M::Request,
    op: &str,
    matcher: &M,
) -> Decision {
    for (i, stmt) in policy.statements.iter().enumerate() {
        if !stmt.principals.iter().any(|p| p.matches(principal)) {
            continue;
        }
        if !matcher.matches(&stmt.resources, request) {
            continue;
        }
        if !stmt.ops.matches(op) {
            continue;
        }
        return Decision::Allow {
            matched_statement: i,
        };
    }
    Decision::Deny
}

// =============================================================================
// Policy loading
// =============================================================================

impl Policy {
    /// Empty policy — denies everything. Useful as a startup fallback
    /// for tests; production daemons should refuse to start with an
    /// empty policy.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Parse a policy from YAML text. The op-name normalizer is
    /// applied per-statement to allow kebab/snake/upper variants.
    pub fn parse(
        text: &str,
        normalize_op: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, LoadError> {
        let file: PolicyFile =
            serde_yaml::from_str(text).map_err(|e| LoadError::Parse(e.to_string()))?;
        // Phase 1 accepts version 1 (vHSM legacy) and 2 (typed
        // resources). Version 0 was never released; later versions
        // are rejected at this layer.
        if !matches!(file.version, 1 | 2) {
            return Err(LoadError::UnknownVersion(file.version));
        }

        let mut statements = Vec::with_capacity(file.statements.len());
        for (i, raw) in file.statements.iter().enumerate() {
            if raw.principals.is_empty() {
                return Err(LoadError::EmptyPrincipals(i));
            }
            if raw.ops.is_empty() {
                return Err(LoadError::EmptyOps(i));
            }

            // Compile principals.
            let principals: Result<Vec<_>, _> = raw
                .principals
                .iter()
                .map(PrincipalSelector::compile)
                .collect();
            let principals = principals?;

            // Resources: prefer `resources:`; fall back to legacy
            // `handles: [...]` at statement level → synthesise the
            // equivalent `resources: { hsm: { handles: [...] } }`.
            let resources = match (&raw.resources, &raw.handles) {
                (Some(r), None) => r.clone(),
                (None, Some(h)) => {
                    let mut hsm_inner = serde_yaml::Mapping::new();
                    hsm_inner.insert(
                        serde_yaml::Value::String("handles".to_string()),
                        serde_yaml::Value::Sequence(
                            h.iter()
                                .map(|s| serde_yaml::Value::String(s.clone()))
                                .collect(),
                        ),
                    );
                    let mut outer = serde_yaml::Mapping::new();
                    outer.insert(
                        serde_yaml::Value::String("hsm".to_string()),
                        serde_yaml::Value::Mapping(hsm_inner),
                    );
                    serde_yaml::Value::Mapping(outer)
                }
                (Some(_), Some(_)) => {
                    return Err(LoadError::Malformed(format!(
                        "statement {i}: set either `resources:` or legacy `handles:`, not both"
                    )));
                }
                (None, None) => return Err(LoadError::EmptyResources(i)),
            };

            // Compile ops.
            let ops = if raw.ops.iter().any(|s| s == "*") {
                OpSelector::Any
            } else {
                let mut set = HashSet::with_capacity(raw.ops.len());
                for s in &raw.ops {
                    let canonical = normalize_op(s).ok_or_else(|| {
                        LoadError::Malformed(format!(
                            "statement {i}: unknown op name {s:?}"
                        ))
                    })?;
                    set.insert(canonical);
                }
                OpSelector::Exact(set)
            };

            statements.push(Statement {
                principals,
                resources,
                ops,
                conditions: raw.conditions.clone(),
            });
        }

        Ok(Policy { statements })
    }

    pub fn num_statements(&self) -> usize {
        self.statements.len()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Identity op normalizer used by the unit tests — accepts any
    /// kebab-case string verbatim. Real services pass their own
    /// (e.g. vHSM's `parse_op_name`).
    fn normalize_identity(s: &str) -> Option<String> {
        Some(s.to_ascii_lowercase().replace('_', "-"))
    }

    /// Minimal matcher used by these tests — matches when the
    /// statement's `resources.test.value` equals the request string.
    struct TestMatcher;
    impl ResourceMatcher for TestMatcher {
        type Request = String;
        fn matches(&self, stmt: &serde_yaml::Value, req: &String) -> bool {
            stmt.get("test")
                .and_then(|t| t.get("value"))
                .and_then(|v| v.as_str())
                .map_or(false, |s| s == "*" || s == req)
        }
    }

    fn vm(id: &str) -> Principal {
        Principal::Vm {
            vm_id: id.to_string(),
            cert_thumbprint: None,
        }
    }

    #[test]
    fn empty_policy_denies_everything() {
        let p = Policy::empty();
        let d = evaluate(&p, &vm("vm1"), &"x".to_string(), "sign", &TestMatcher);
        assert_eq!(d, Decision::Deny);
    }

    #[test]
    fn bare_string_principal_back_compat() {
        let p = Policy::parse(
            r#"
version: 1
statements:
  - principals: [vm1]
    resources:
      test: { value: foo }
    ops: [sign]
"#,
            normalize_identity,
        )
        .expect("parses");
        let d = evaluate(&p, &vm("vm1"), &"foo".to_string(), "sign", &TestMatcher);
        assert_eq!(d, Decision::Allow { matched_statement: 0 });

        // vm2 doesn't match.
        let d = evaluate(&p, &vm("vm2"), &"foo".to_string(), "sign", &TestMatcher);
        assert_eq!(d, Decision::Deny);
    }

    #[test]
    fn wildcard_principal_matches_unknown_vm() {
        let p = Policy::parse(
            r#"
version: 2
statements:
  - principals: ["*"]
    resources:
      test: { value: "*" }
    ops: [sign]
"#,
            normalize_identity,
        )
        .expect("parses");
        let d = evaluate(&p, &vm("vm99"), &"foo".to_string(), "sign", &TestMatcher);
        assert_eq!(d, Decision::Allow { matched_statement: 0 });
    }

    #[test]
    fn typed_principal_vm_only_matches_vm() {
        let p = Policy::parse(
            r#"
version: 2
statements:
  - principals:
      - vm: vm1
    resources:
      test: { value: foo }
    ops: [sign]
"#,
            normalize_identity,
        )
        .expect("parses");
        let d = evaluate(&p, &vm("vm1"), &"foo".to_string(), "sign", &TestMatcher);
        assert_eq!(d, Decision::Allow { matched_statement: 0 });

        // A Container principal on vm1 does NOT match a `vm:` selector
        // (selector requires exact variant).
        let container = Principal::Container {
            vm_id: "vm1".to_string(),
            container: "telemetry".to_string(),
            image_digest: None,
        };
        let d = evaluate(&p, &container, &"foo".to_string(), "sign", &TestMatcher);
        assert_eq!(d, Decision::Deny);
    }

    #[test]
    fn typed_principal_container_matches_container() {
        let p = Policy::parse(
            r#"
version: 2
statements:
  - principals:
      - vm: vm1
        container: telemetry
    resources:
      test: { value: foo }
    ops: [sign]
"#,
            normalize_identity,
        )
        .expect("parses");
        let container = Principal::Container {
            vm_id: "vm1".to_string(),
            container: "telemetry".to_string(),
            image_digest: None,
        };
        let d = evaluate(&p, &container, &"foo".to_string(), "sign", &TestMatcher);
        assert_eq!(d, Decision::Allow { matched_statement: 0 });

        // Different container — denied.
        let other = Principal::Container {
            vm_id: "vm1".to_string(),
            container: "other".to_string(),
            image_digest: None,
        };
        let d = evaluate(&p, &other, &"foo".to_string(), "sign", &TestMatcher);
        assert_eq!(d, Decision::Deny);
    }

    #[test]
    fn typed_principal_tester_matches_role() {
        let p = Policy::parse(
            r#"
version: 2
statements:
  - principals:
      - tester:
          idp: "*"
          role: workshop-tech
    resources:
      test: { value: "*" }
    ops: [read]
"#,
            normalize_identity,
        )
        .expect("parses");
        let tester = Principal::Tester {
            idp: "cloud-prod".to_string(),
            sub: "tech@example.com".to_string(),
            role: Some("workshop-tech".to_string()),
            scope: vec![],
        };
        let d = evaluate(&p, &tester, &"x".to_string(), "read", &TestMatcher);
        assert_eq!(d, Decision::Allow { matched_statement: 0 });

        // Wrong role — denied.
        let tester2 = Principal::Tester {
            idp: "cloud-prod".to_string(),
            sub: "tech@example.com".to_string(),
            role: Some("intern".to_string()),
            scope: vec![],
        };
        let d = evaluate(&p, &tester2, &"x".to_string(), "read", &TestMatcher);
        assert_eq!(d, Decision::Deny);
    }

    #[test]
    fn first_match_wins_indexes() {
        let p = Policy::parse(
            r#"
version: 2
statements:
  - principals: [vm1]
    resources:
      test: { value: foo }
    ops: [sign]
  - principals: ["*"]
    resources:
      test: { value: "*" }
    ops: ["*"]
"#,
            normalize_identity,
        )
        .expect("parses");

        // vm1 hits statement 0.
        let d = evaluate(&p, &vm("vm1"), &"foo".to_string(), "sign", &TestMatcher);
        assert_eq!(d, Decision::Allow { matched_statement: 0 });

        // vm2 falls through to statement 1.
        let d = evaluate(&p, &vm("vm2"), &"bar".to_string(), "verify", &TestMatcher);
        assert_eq!(d, Decision::Allow { matched_statement: 1 });
    }

    #[test]
    fn op_wildcard_matches_any_known_op() {
        let p = Policy::parse(
            r#"
version: 2
statements:
  - principals: [vm1]
    resources:
      test: { value: "*" }
    ops: ["*"]
"#,
            normalize_identity,
        )
        .expect("parses");
        for op in &["sign", "verify", "encrypt", "literally-anything"] {
            let d = evaluate(&p, &vm("vm1"), &"x".to_string(), op, &TestMatcher);
            assert_eq!(
                d,
                Decision::Allow { matched_statement: 0 },
                "op {op}"
            );
        }
    }

    #[test]
    fn rejects_empty_principals() {
        let err = Policy::parse(
            r#"
version: 2
statements:
  - principals: []
    resources:
      test: { value: foo }
    ops: [sign]
"#,
            normalize_identity,
        )
        .unwrap_err();
        assert_eq!(err, LoadError::EmptyPrincipals(0));
    }

    #[test]
    fn rejects_empty_ops() {
        let err = Policy::parse(
            r#"
version: 2
statements:
  - principals: [vm1]
    resources:
      test: { value: foo }
    ops: []
"#,
            normalize_identity,
        )
        .unwrap_err();
        assert_eq!(err, LoadError::EmptyOps(0));
    }

    #[test]
    fn legacy_handles_at_statement_level_synthesizes_hsm_resources() {
        // The vHSM v1 schema put `handles: [...]` at the statement
        // top level. We synthesise the equivalent `resources.hsm.handles`
        // so the matcher chain sees a uniform shape.
        let p = Policy::parse(
            r#"
version: 1
statements:
  - principals: [vm1]
    handles: [jwt-signing]
    ops: [sign]
"#,
            normalize_identity,
        )
        .expect("parses");
        assert_eq!(p.statements.len(), 1);

        // Check the synthesised resources shape.
        let res = &p.statements[0].resources;
        let handles = res
            .get("hsm")
            .and_then(|h| h.get("handles"))
            .and_then(|v| v.as_sequence())
            .expect("synthesised hsm.handles");
        assert_eq!(handles.len(), 1);
        assert_eq!(handles[0].as_str(), Some("jwt-signing"));
    }

    #[test]
    fn rejects_both_resources_and_legacy_handles() {
        let err = Policy::parse(
            r#"
version: 2
statements:
  - principals: [vm1]
    resources:
      hsm: { handles: [jwt-signing] }
    handles: [also-jwt-signing]
    ops: [sign]
"#,
            normalize_identity,
        )
        .unwrap_err();
        assert!(matches!(err, LoadError::Malformed(_)), "got {err:?}");
    }

    #[test]
    fn rejects_unknown_version() {
        let err = Policy::parse(
            r#"
version: 99
statements:
  - principals: [vm1]
    handles: [x]
    ops: [sign]
"#,
            normalize_identity,
        )
        .unwrap_err();
        assert_eq!(err, LoadError::UnknownVersion(99));
    }

    #[test]
    fn principal_display_id_stable_per_type() {
        let p = vm("vm1");
        assert_eq!(p.display_id(), "vm:vm1");

        let p = Principal::Container {
            vm_id: "vm1".into(),
            container: "telemetry".into(),
            image_digest: None,
        };
        assert_eq!(p.display_id(), "vm:vm1/container:telemetry");

        let p = Principal::Tester {
            idp: "prod".into(),
            sub: "alice@example.com".into(),
            role: None,
            scope: vec![],
        };
        assert_eq!(p.display_id(), "tester:prod/alice@example.com");

        let p = Principal::Anonymous;
        assert_eq!(p.display_id(), "anonymous");
    }
}
