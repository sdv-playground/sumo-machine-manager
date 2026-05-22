//! Per-request audit logger.
//!
//! Writes one structured single-line JSON record per dispatched op to
//! a size-rotated file. Records are durable: `sync_each_line = true`
//! at the [`log_rotate`] layer means every line is `fdatasync`'d
//! before `write()` returns.
//!
//! ## Record schema
//!
//! ```jsonc
//! {
//!   "ts": "2026-05-22T14:32:01.123456Z",   // RFC 3339 with µs
//!   "vm_id": "vm2",                        // cert subject (v3 principal)
//!   "cert_thumbprint": "5c41…8b",          // SHA-256 of CWT (lower-hex)
//!   "peer_ip": "10.0.200.2",               // diagnostic only in v3
//!   "op_code": "0x00000040",
//!   "op_name": "SIGN",
//!   "session_id": 4711,
//!   "status_code": 0,
//!   "status_name": "OK",
//!   "handle": "0x00000080",                // optional (only on ops carrying a handle)
//!   "iam_decision": "allow",               // "allow" | "deny" | "bypass"
//!   "iam_statement": 1,                    // optional; matched statement index
//!   "payload_len_in": 64,
//!   "payload_len_out": 71
//! }
//! ```
//!
//! Fields are stable; new fields will be added (additive) but
//! existing ones won't be renamed or removed. Parsers SHOULD ignore
//! unknown fields.
//!
//! ## Failure semantics
//!
//! - Daemon refuses to start if `--audit-log <path>` is supplied and
//!   the path can't be opened (fail loud, never silently disabled).
//! - If an individual `record()` call fails at the I/O layer (disk
//!   full, file unlinked under us), the failure is logged via
//!   `tracing::error!` but the request is NOT failed — that policy
//!   choice belongs to the caller. Callers that want fail-closed
//!   audit (Common Criteria-style) should check `record()`'s return
//!   and reject the op on error.
//!
//! ## Defaults
//!
//! - `max_bytes`: 64 MiB
//! - `max_rotated`: 4 (so 5 files total, 320 MiB worst-case footprint)
//! - `sync_each_line`: always true for audit. Not configurable.

use std::io::{self, Write};
use std::net::IpAddr;
use std::path::Path;

use log_rotate::{RotatingFileConfig, RotatingFileWriter};
use serde::Serialize;

use crate::handler::{AuthzOutcome, CallerId};
use crate::proto::{Op, Request, Response, StatusCode};

/// Default `max_bytes` for the rotating audit file (64 MiB).
pub const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Default `max_rotated` (4 rotated copies + 1 active = 5 total).
pub const DEFAULT_MAX_ROTATED: u32 = 4;

/// Audit logger. `None` instance behaves as a no-op so callers don't
/// need to branch on enabled-or-not at every dispatch.
pub struct AuditLogger {
    inner: Option<RotatingFileWriter>,
}

impl AuditLogger {
    /// Disabled (no-op) audit logger. Use when `--audit-log` was not
    /// passed.
    pub fn disabled() -> Self {
        Self { inner: None }
    }

    /// Open the rotating file at `path` with the given size cap and
    /// rotated-copies count. Always uses `sync_each_line: true`.
    pub fn open(
        path: impl AsRef<Path>,
        max_bytes: u64,
        max_rotated: u32,
    ) -> io::Result<Self> {
        let cfg = RotatingFileConfig::new(path.as_ref().to_path_buf(), max_bytes)
            .with_max_rotated(max_rotated)
            .with_sync_each_line(true);
        Ok(Self {
            inner: Some(RotatingFileWriter::open(cfg)?),
        })
    }

    /// Open with the default size cap and rotated-copies count.
    pub fn open_default(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::open(path, DEFAULT_MAX_BYTES, DEFAULT_MAX_ROTATED)
    }

    /// Record one dispatched op. Best-effort: a failure to write logs
    /// via `tracing::error!` and returns the error; the caller may
    /// ignore or fail the op as policy dictates. Disabled instances
    /// always return Ok(()) without touching disk.
    pub fn record(
        &mut self,
        caller: &CallerId,
        req: &Request,
        resp: &Response,
        authz: AuthzOutcome,
    ) -> io::Result<()> {
        let Some(w) = self.inner.as_mut() else {
            return Ok(());
        };
        let rec = AuditRecord::build(caller, req, resp, authz);
        let mut line = serde_json::to_vec(&rec)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("serialize audit record: {e}")))?;
        line.push(b'\n');
        match w.write_all(&line) {
            Ok(()) => Ok(()),
            Err(e) => {
                tracing::error!(error = %e, "audit log write failed");
                Err(e)
            }
        }
    }
}

/// In-memory shape of one audit record. Field order is the
/// emit order (serde_json preserves declaration order).
#[derive(Serialize)]
struct AuditRecord<'a> {
    /// RFC 3339 timestamp with microsecond precision, always UTC.
    ts: String,
    /// Cert subject — the v3 principal name. Bound at AUTH time.
    vm_id: &'a str,
    /// SHA-256 of the CWT cert that authenticated this connection,
    /// rendered as lower-hex. Lets an operator pin which cert
    /// authorised which op.
    cert_thumbprint: String,
    /// Source IP that opened the connection. Diagnostic only in v3
    /// (identity comes from the cert, not the IP).
    peer_ip: String,
    /// Operation code, as `0xHHHHHHHH`.
    op_code: String,
    /// Human-readable operation name (e.g. `"SIGN"`, `"GET_RANDOM"`,
    /// or `"<unknown:0x...>"` for malformed requests).
    op_name: String,
    /// Client-chosen session_id, echoed in the response.
    session_id: u32,
    /// Numeric status from the response.
    status_code: u32,
    /// Human-readable status name (e.g. `"OK"`, `"PERMISSION_DENY"`).
    status_name: &'static str,
    /// Resolved handle if the op carries one in its payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    handle: Option<String>,
    /// IAM gate outcome: `"allow"`, `"deny"`, or `"bypass"` (latter
    /// for dynamic handles + host-only-op rejections that didn't go
    /// through IAM eval).
    iam_decision: &'static str,
    /// Zero-based statement index that matched. Only present on
    /// `iam_decision == "allow"` against a well-known handle;
    /// absent on deny, bypass, and dynamic-handle allows.
    #[serde(skip_serializing_if = "Option::is_none")]
    iam_statement: Option<usize>,
    /// Payload length on the wire (request side).
    payload_len_in: usize,
    /// Payload length on the wire (response side).
    payload_len_out: usize,
}

impl<'a> AuditRecord<'a> {
    fn build(caller: &'a CallerId, req: &Request, resp: &Response, authz: AuthzOutcome) -> Self {
        let op = Op::from_u32(req.op);
        let op_name = op
            .map(|o| op_name_for(o))
            .unwrap_or("<unknown>")
            .to_string();
        let (iam_decision, iam_statement) = render_authz(authz);

        Self {
            ts: now_rfc3339(),
            vm_id: &caller.vm_id,
            cert_thumbprint: hex_lower(&caller.cert_thumbprint),
            peer_ip: caller.peer_ip.to_string(),
            op_code: format!("0x{:08x}", req.op),
            op_name,
            session_id: req.session_id,
            status_code: resp.status,
            status_name: status_name(resp.status),
            handle: extract_handle(req).map(|h| format!("0x{:08x}", h)),
            iam_decision,
            iam_statement,
            payload_len_in: req.payload.len(),
            payload_len_out: resp.payload.len(),
        }
    }
}

fn render_authz(o: AuthzOutcome) -> (&'static str, Option<usize>) {
    match o {
        AuthzOutcome::Allow { matched_statement } => ("allow", Some(matched_statement)),
        AuthzOutcome::Deny => ("deny", None),
        AuthzOutcome::Bypass => ("bypass", None),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn op_name_for(op: Op) -> &'static str {
    match op {
        Op::GetRandom => "GET_RANDOM",
        Op::KeyGenerate => "KEY_GENERATE",
        Op::KeyImport => "KEY_IMPORT",
        Op::KeyDerive => "KEY_DERIVE",
        Op::KeyDelete => "KEY_DELETE",
        Op::Encrypt => "ENCRYPT",
        Op::Decrypt => "DECRYPT",
        Op::MacGenerate => "MAC_GENERATE",
        Op::MacVerify => "MAC_VERIFY",
        Op::Sign => "SIGN",
        Op::Verify => "VERIFY",
        Op::GetHandleInfo => "GET_HANDLE_INFO",
        Op::GetPubkey => "GET_PUBKEY",
        Op::GetCert => "GET_CERT",
        Op::Hello => "HELLO",
        Op::Auth => "AUTH",
        Op::AuthOk => "AUTH_OK",
        Op::Enroll => "ENROLL",
        Op::EnrollAssisted => "ENROLL_ASSISTED",
    }
}

fn status_name(code: u32) -> &'static str {
    match code {
        x if x == StatusCode::Ok as u32 => "OK",
        x if x == StatusCode::InvalidHandle as u32 => "INVALID_HANDLE",
        x if x == StatusCode::PermissionDeny as u32 => "PERMISSION_DENY",
        x if x == StatusCode::PolicyReject as u32 => "POLICY_REJECT",
        x if x == StatusCode::HseError as u32 => "HSE_ERROR",
        x if x == StatusCode::InvalidParam as u32 => "INVALID_PARAM",
        x if x == StatusCode::NoResource as u32 => "NO_RESOURCE",
        x if x == StatusCode::StorageError as u32 => "STORAGE_ERROR",
        x if x == StatusCode::CryptoError as u32 => "CRYPTO_ERROR",
        x if x == StatusCode::Internal as u32 => "INTERNAL",
        _ => "<unknown>",
    }
}

/// Extract the handle that the request operates on, if any. Ops that
/// don't carry a handle return `None`. The handle is the first
/// 4 bytes of the payload for every op except GET_RANDOM,
/// KEY_GENERATE, and the host-only ops (KEY_IMPORT, KEY_DERIVE,
/// KEY_DELETE — those would be rejected before reaching audit
/// anyway, but if they did appear we'd still record their handles).
fn extract_handle(req: &Request) -> Option<u32> {
    let op = Op::from_u32(req.op)?;
    let carries_handle = matches!(
        op,
        Op::Encrypt
            | Op::Decrypt
            | Op::MacGenerate
            | Op::MacVerify
            | Op::Sign
            | Op::Verify
            | Op::GetHandleInfo
            | Op::GetPubkey
            | Op::GetCert
            | Op::KeyDerive
            | Op::KeyDelete
    );
    if !carries_handle || req.payload.len() < 4 {
        return None;
    }
    let bytes = req.payload.get(0..4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// RFC 3339 UTC timestamp with microsecond precision. Format is
/// stable across calls so log lines sort lexicographically.
fn now_rfc3339() -> String {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

// Allow consumers to coerce CallerId without exposing peer_ip's
// concrete IpAddr type beyond the module boundary.
#[allow(dead_code)]
fn _coerce_unused(_: IpAddr) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::fs;
    use std::net::Ipv4Addr;
    use tempfile::tempdir;

    fn caller(vm: &str, ip: [u8; 4]) -> CallerId {
        CallerId {
            peer_ip: IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
            vm_id: vm.to_string(),
            cert_thumbprint: [0u8; 32],
        }
    }

    fn read_lines(p: &std::path::Path) -> Vec<String> {
        let mut s = String::new();
        fs::File::open(p).unwrap().read_to_string(&mut s).unwrap();
        s.lines().map(|l| l.to_string()).collect()
    }

    #[test]
    fn disabled_logger_records_nothing() {
        let mut a = AuditLogger::disabled();
        let req = Request {
            op: Op::GetRandom as u32,
            session_id: 1,
            payload: vec![],
        };
        let resp = Response::ok(req.op, 1, vec![]);
        a.record(
            &caller("vmX", [127, 0, 0, 1]),
            &req,
            &resp,
            AuthzOutcome::Allow { matched_statement: 0 },
        )
        .unwrap();
        // No file to assert against — just confirm we don't panic.
    }

    #[test]
    fn writes_one_line_per_op() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.log");
        let mut a = AuditLogger::open(&path, 1024 * 1024, 2).unwrap();

        // SIGN with handle 0x00000080 in payload[0..4]
        let handle_bytes = 0x80u32.to_le_bytes();
        let req = Request {
            op: Op::Sign as u32,
            session_id: 4711,
            payload: handle_bytes.to_vec(),
        };
        let resp = Response::ok(req.op, 4711, vec![0x30, 0x44]); // dummy sig prefix
        a.record(
            &caller("vm2", [10, 0, 200, 2]),
            &req,
            &resp,
            AuthzOutcome::Allow { matched_statement: 3 },
        )
        .unwrap();
        drop(a);

        let lines = read_lines(&path);
        assert_eq!(lines.len(), 1);
        let v: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(v["vm_id"], "vm2");
        // cert_thumbprint: 32 zero bytes → 64 zeros in hex (test fixture)
        assert_eq!(v["cert_thumbprint"], "0".repeat(64));
        assert_eq!(v["peer_ip"], "10.0.200.2");
        assert_eq!(v["op_code"], "0x00000040");
        assert_eq!(v["op_name"], "SIGN");
        assert_eq!(v["session_id"], 4711);
        assert_eq!(v["status_code"], 0);
        assert_eq!(v["status_name"], "OK");
        assert_eq!(v["handle"], "0x00000080");
        assert_eq!(v["iam_decision"], "allow");
        assert_eq!(v["iam_statement"], 3);
        assert_eq!(v["payload_len_in"], 4);
        assert_eq!(v["payload_len_out"], 2);
    }

    #[test]
    fn omits_handle_field_for_get_random() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.log");
        let mut a = AuditLogger::open(&path, 1024 * 1024, 2).unwrap();

        let req = Request {
            op: Op::GetRandom as u32,
            session_id: 1,
            payload: 32u32.to_le_bytes().to_vec(), // length param, NOT a handle
        };
        let resp = Response::ok(req.op, 1, vec![0; 32]);
        a.record(
            &caller("vm1", [10, 0, 201, 2]),
            &req,
            &resp,
            AuthzOutcome::Allow { matched_statement: 0 },
        )
        .unwrap();
        drop(a);

        let lines = read_lines(&path);
        let v: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert!(v.get("handle").is_none(), "GET_RANDOM has no handle");
        assert_eq!(v["op_name"], "GET_RANDOM");
        assert_eq!(v["payload_len_in"], 4);
        assert_eq!(v["payload_len_out"], 32);
    }

    #[test]
    fn records_error_responses() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.log");
        let mut a = AuditLogger::open(&path, 1024 * 1024, 2).unwrap();

        let req = Request {
            op: Op::Sign as u32,
            session_id: 1,
            payload: 0xDEADBEEFu32.to_le_bytes().to_vec(),
        };
        let resp = Response::err(req.op, 1, StatusCode::InvalidHandle);
        a.record(
            &caller("vm1", [10, 0, 201, 2]),
            &req,
            &resp,
            AuthzOutcome::Allow { matched_statement: 0 },
        )
        .unwrap();
        drop(a);

        let lines = read_lines(&path);
        let v: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(v["status_code"], 1);
        assert_eq!(v["status_name"], "INVALID_HANDLE");
        assert_eq!(v["handle"], "0xdeadbeef");
        assert_eq!(v["payload_len_out"], 0);
    }

    #[test]
    fn rotation_happens_under_load() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.log");
        // Tiny cap: a single JSON record is ~250 bytes, so a few
        // records will force rotation.
        let mut a = AuditLogger::open(&path, 512, 2).unwrap();

        let req = Request {
            op: Op::Sign as u32,
            session_id: 1,
            payload: 0x80u32.to_le_bytes().to_vec(),
        };
        let resp = Response::ok(req.op, 1, vec![0; 64]);

        for _ in 0..20 {
            a.record(
                &caller("vm1", [10, 0, 201, 2]),
                &req,
                &resp,
                AuthzOutcome::Allow { matched_statement: 0 },
            )
            .unwrap();
        }
        drop(a);

        // Rotation occurred; some rotated copies exist.
        let rotated_1 = {
            let mut s = path.as_os_str().to_os_string();
            s.push(".1");
            std::path::PathBuf::from(s)
        };
        assert!(
            rotated_1.exists(),
            "expected {} after rotation",
            rotated_1.display()
        );
    }

    #[test]
    fn op_name_covers_every_variant() {
        // Belt-and-suspenders: every Op variant resolves to a name.
        for op in [
            Op::GetRandom, Op::KeyGenerate, Op::KeyImport, Op::KeyDerive,
            Op::KeyDelete, Op::Encrypt, Op::Decrypt, Op::MacGenerate,
            Op::MacVerify, Op::Sign, Op::Verify, Op::GetHandleInfo,
            Op::GetPubkey, Op::GetCert,
            Op::Hello, Op::Auth, Op::AuthOk, Op::Enroll,
        ] {
            assert!(!op_name_for(op).is_empty());
        }
    }

    #[test]
    fn iam_deny_omits_statement_field() {
        // Deny records don't carry a matched-statement index, so the
        // field must be absent (not serialised as null).
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.log");
        let mut a = AuditLogger::open(&path, 1024 * 1024, 2).unwrap();

        let req = Request {
            op: Op::Sign as u32,
            session_id: 7,
            payload: 0x80u32.to_le_bytes().to_vec(),
        };
        let resp = Response::err(req.op, 7, StatusCode::PolicyReject);
        a.record(
            &caller("strang3r", [10, 0, 0, 99]),
            &req,
            &resp,
            AuthzOutcome::Deny,
        )
        .unwrap();
        drop(a);

        let v: serde_json::Value = serde_json::from_str(&read_lines(&path)[0]).unwrap();
        assert_eq!(v["iam_decision"], "deny");
        assert!(
            v.get("iam_statement").is_none(),
            "deny record must not include iam_statement; got: {v}"
        );
        assert_eq!(v["status_name"], "POLICY_REJECT");
    }

    #[test]
    fn iam_bypass_records_as_bypass() {
        // Dynamic-handle ops bypass IAM; the audit log marks them so
        // an operator can tell them apart from explicit allows.
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.log");
        let mut a = AuditLogger::open(&path, 1024 * 1024, 2).unwrap();

        // Dynamic handle 0x0100
        let req = Request {
            op: Op::Encrypt as u32,
            session_id: 1,
            payload: 0x100u32.to_le_bytes().to_vec(),
        };
        let resp = Response::ok(req.op, 1, vec![]);
        a.record(
            &caller("vm1", [10, 0, 201, 2]),
            &req,
            &resp,
            AuthzOutcome::Bypass,
        )
        .unwrap();
        drop(a);

        let v: serde_json::Value = serde_json::from_str(&read_lines(&path)[0]).unwrap();
        assert_eq!(v["iam_decision"], "bypass");
        assert!(v.get("iam_statement").is_none());
    }

    #[test]
    fn cert_thumbprint_renders_lower_hex() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("audit.log");
        let mut a = AuditLogger::open(&path, 1024 * 1024, 2).unwrap();

        // Construct a caller with a non-zero thumbprint so the hex
        // rendering is exercised.
        let mut c = caller("vm1", [10, 0, 201, 2]);
        c.cert_thumbprint = [0xABu8; 32];
        let req = Request { op: Op::GetRandom as u32, session_id: 1, payload: 32u32.to_le_bytes().to_vec() };
        let resp = Response::ok(req.op, 1, vec![]);
        a.record(&c, &req, &resp, AuthzOutcome::Allow { matched_statement: 2 }).unwrap();
        drop(a);

        let v: serde_json::Value = serde_json::from_str(&read_lines(&path)[0]).unwrap();
        assert_eq!(v["cert_thumbprint"], "ab".repeat(32));
    }
}
