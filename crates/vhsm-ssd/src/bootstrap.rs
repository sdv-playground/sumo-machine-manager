//! Bootstrap-token state for in-box ENROLL.
//!
//! At provision time, off-box tooling generates a per-guest bootstrap
//! token (32 random bytes) and writes it to **two** places:
//!
//!  - **Bank side** (raw bytes): inside the guest's firmware bank as
//!    `<bank>/vhsm-bootstrap.token`. Read by the guest on first
//!    boot, sent to vhsm-ssd in the ENROLL request payload, then
//!    deleted.
//!  - **Daemon side** (this module): SHA-256 of the token plus a
//!    `consumed: bool` flag, persisted to
//!    `<keystore>/bootstrap.yaml`. Loaded at daemon startup, updated
//!    on every successful ENROLL, fsync'd to disk so a daemon
//!    restart can't re-accept an already-consumed token.
//!
//! The daemon never stores the raw token — only its hash. Tokens
//! the daemon hasn't issued can't be presented; tokens the daemon
//! has marked consumed can't be replayed.
//!
//! ## On-disk format
//!
//! ```yaml
//! tokens:
//!   vm1:
//!     sha256: "a3f1...0c"               # hex
//!     consumed: false
//!   vm2:
//!     sha256: "b9e2...4d"
//!     consumed: true
//!     consumed_at: 1740441600           # Unix seconds (optional)
//!     bound_cert_thumbprint: "5c41...8b"  # hex; tells operator
//!                                         # which cert this token
//!                                         # got bound to.
//! ```
//!
//! Failure semantics: load failure (missing file, malformed YAML)
//! returns an error to the caller, which fail-loud-aborts at daemon
//! startup. Save failure during operation logs to `tracing::error!`
//! and propagates the error — caller decides whether to reject the
//! ENROLL (current policy: yes, fail closed so we never silently
//! lose the consumed-marker).
//!
//! ## Replay protection
//!
//! Once a token is marked `consumed: true`, any subsequent ENROLL
//! presenting it MUST be rejected with `TokenAlreadyConsumed`. This
//! is enforced by [`BootstrapState::consume`].

use std::collections::BTreeMap;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// In-memory state of all known bootstrap tokens + pending
/// enrolments. Tokens are the off-box ENROLL flow (operator-shipped
/// secret in firmware bank). Pending enrolments are the on-device
/// ENROLL_ASSISTED flow: the HSM arms a vm_id; the guest then
/// connects from its pinned source IP, the daemon resolves identity
/// from the IP, and consumes the pending flag with no secret on
/// the wire.
#[derive(Debug)]
pub struct BootstrapState {
    /// Path the state is persisted at; `save()` writes here.
    path: PathBuf,
    /// Token records keyed by vm_id (off-box ENROLL).
    entries: BTreeMap<String, TokenEntry>,
    /// Pending enrolment flags keyed by vm_id (in-band ENROLL_ASSISTED).
    pending: BTreeMap<String, PendingEnrollment>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenEntry {
    /// Lower-hex SHA-256 of the raw token. 64 chars.
    pub sha256: String,
    pub consumed: bool,
    /// Unix seconds when consumed. None until consumption.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed_at: Option<u64>,
    /// Lower-hex thumbprint of the cert this token was bound to.
    /// None until consumption.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_cert_thumbprint: Option<String>,
}

/// In-band enrolment record. No secret bytes — just a "vm_id may
/// enroll once" flag, set by the host (e.g. vm-mgr at OTA install
/// time via the HSM) and consumed by the next successful
/// ENROLL_ASSISTED from that vm_id's pinned source IP.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingEnrollment {
    /// Unix seconds when the host armed this entry.
    pub armed_at: u64,
    /// Optional TTL; the daemon refuses ENROLL_ASSISTED after
    /// `armed_at + ttl_secs`. None = no expiry (operator manages
    /// lifecycle).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StateFile {
    #[serde(default)]
    tokens: BTreeMap<String, TokenEntry>,
    #[serde(default)]
    pending: BTreeMap<String, PendingEnrollment>,
}

/// Outcome of a [`BootstrapState::consume`] call.
#[derive(Debug, PartialEq, Eq)]
pub enum ConsumeOutcome {
    /// Token matched + not previously consumed; now marked consumed.
    Accepted,
    /// vm_id not in the state file.
    UnknownVmId,
    /// Token bytes don't hash to the stored sha256.
    TokenMismatch,
    /// Token already marked consumed.
    AlreadyConsumed,
}

/// Outcome of a [`BootstrapState::consume_pending`] call (in-band
/// ENROLL_ASSISTED flow). Mirrors `ConsumeOutcome` but for the
/// no-secret path.
#[derive(Debug, PartialEq, Eq)]
pub enum PendingConsumeOutcome {
    /// Pending flag found + not expired; now removed (single-use).
    Accepted,
    /// vm_id has no pending enrolment (never armed, or already
    /// consumed).
    NotPending,
    /// Pending flag found but past its TTL.
    Expired,
}

impl BootstrapState {
    /// Load from `path`, creating an empty file if it doesn't exist.
    /// A malformed file is an error — operator should resolve before
    /// the daemon proceeds.
    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            // No prior state — that's fine on a fresh deployment.
            // Caller will populate via add() / arm_pending() before
            // any ENROLL or ENROLL_ASSISTED can succeed.
            return Ok(Self {
                path,
                entries: BTreeMap::new(),
                pending: BTreeMap::new(),
            });
        }
        let raw = std::fs::read_to_string(&path)?;
        let parsed: StateFile = serde_yaml::from_str(&raw).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bootstrap.yaml parse: {e}"),
            )
        })?;
        Ok(Self {
            path,
            entries: parsed.tokens,
            pending: parsed.pending,
        })
    }

    /// Re-read from disk. Used by the daemon when a `consume*` lookup
    /// misses — handles the case where another process (e.g. vm-mgr
    /// via `arm_enrollment`) wrote a fresh entry between the daemon's
    /// startup load and this lookup.
    pub fn reload(&mut self) -> io::Result<()> {
        if !self.path.exists() {
            self.entries.clear();
            self.pending.clear();
            return Ok(());
        }
        let raw = std::fs::read_to_string(&self.path)?;
        let parsed: StateFile = serde_yaml::from_str(&raw).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bootstrap.yaml parse: {e}"),
            )
        })?;
        self.entries = parsed.tokens;
        self.pending = parsed.pending;
        Ok(())
    }

    /// Persist current state to `self.path`. Atomic via tmp+rename.
    pub fn save(&self) -> io::Result<()> {
        let doc = StateFile {
            tokens: self.entries.clone(),
            pending: self.pending.clone(),
        };
        let yaml = serde_yaml::to_string(&doc).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("bootstrap.yaml serialise: {e}"))
        })?;
        let parent = self.path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "bootstrap path has no parent")
        })?;
        std::fs::create_dir_all(parent)?;
        let tmp_path = self.path.with_extension("yaml.tmp");
        {
            let mut f = std::fs::File::create(&tmp_path)?;
            f.write_all(yaml.as_bytes())?;
            f.sync_data()?;
        }
        std::fs::rename(&tmp_path, &self.path)?;
        Ok(())
    }

    /// Register a fresh, un-consumed token record for `vm_id`.
    /// Caller has already generated the raw token and shipped it
    /// into the bank — this just records its hash on the daemon
    /// side. Existing entries for the same `vm_id` are REPLACED
    /// (a re-flash issues a fresh token).
    pub fn add(&mut self, vm_id: impl Into<String>, raw_token: &[u8]) {
        let entry = TokenEntry {
            sha256: hex_lower(&sha256(raw_token)),
            consumed: false,
            consumed_at: None,
            bound_cert_thumbprint: None,
        };
        self.entries.insert(vm_id.into(), entry);
    }

    /// Attempt to consume a token. Returns the outcome; caller
    /// must `save()` if outcome is `Accepted`.
    pub fn consume(
        &mut self,
        vm_id: &str,
        raw_token: &[u8],
        cert_thumbprint: &[u8; 32],
    ) -> ConsumeOutcome {
        let entry = match self.entries.get_mut(vm_id) {
            Some(e) => e,
            None => return ConsumeOutcome::UnknownVmId,
        };
        if entry.consumed {
            return ConsumeOutcome::AlreadyConsumed;
        }
        let provided_hash = hex_lower(&sha256(raw_token));
        // Constant-time-ish compare — the hashes are public-derived
        // and the same length, so subtle isn't strictly necessary,
        // but use a CT helper to be safe.
        if !ct_eq(provided_hash.as_bytes(), entry.sha256.as_bytes()) {
            return ConsumeOutcome::TokenMismatch;
        }
        entry.consumed = true;
        entry.consumed_at = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );
        entry.bound_cert_thumbprint = Some(hex_lower(cert_thumbprint));
        ConsumeOutcome::Accepted
    }

    pub fn get(&self, vm_id: &str) -> Option<&TokenEntry> {
        self.entries.get(vm_id)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Arm an in-band enrolment for `vm_id`. Called by the host
    /// (e.g. vm-mgr at OTA install time, via `HsmProvider::arm_enrollment`).
    /// Existing armed-but-not-consumed entries for the same `vm_id`
    /// are REPLACED — a re-install resets the clock.
    ///
    /// `ttl_secs = None` means no expiry; caller-controlled lifecycle.
    pub fn arm_pending(&mut self, vm_id: impl Into<String>, ttl_secs: Option<u64>) {
        let armed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.pending.insert(
            vm_id.into(),
            PendingEnrollment { armed_at, ttl_secs },
        );
    }

    /// Attempt to consume a pending enrolment. Returns the outcome;
    /// caller must `save()` if outcome is `Accepted`. The entry is
    /// removed from the in-memory table on Accepted (single-use).
    ///
    /// `now_unix` is passed in so the daemon can pin a deterministic
    /// clock during tests and avoid TOCTOU between this check and any
    /// surrounding I/O.
    pub fn consume_pending(&mut self, vm_id: &str, now_unix: u64) -> PendingConsumeOutcome {
        let entry = match self.pending.get(vm_id) {
            Some(e) => e,
            None => return PendingConsumeOutcome::NotPending,
        };
        if let Some(ttl) = entry.ttl_secs {
            if now_unix.saturating_sub(entry.armed_at) >= ttl {
                return PendingConsumeOutcome::Expired;
            }
        }
        self.pending.remove(vm_id);
        PendingConsumeOutcome::Accepted
    }

    pub fn get_pending(&self, vm_id: &str) -> Option<&PendingEnrollment> {
        self.pending.get(vm_id)
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Constant-time equality for two same-length byte slices.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fresh_state() -> (tempfile::TempDir, BootstrapState) {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("bootstrap.yaml");
        let state = BootstrapState::load(&path).unwrap();
        (tmp, state)
    }

    #[test]
    fn load_missing_file_returns_empty() {
        let (_tmp, state) = fresh_state();
        assert!(state.is_empty());
        assert_eq!(state.len(), 0);
    }

    #[test]
    fn add_then_consume_succeeds_once() {
        let (_tmp, mut state) = fresh_state();
        let token = [0xABu8; 32];
        let cert_tp = [0xCDu8; 32];
        state.add("vm1", &token);

        let out = state.consume("vm1", &token, &cert_tp);
        assert_eq!(out, ConsumeOutcome::Accepted);

        // Second attempt — same token, same vm — is rejected.
        let out2 = state.consume("vm1", &token, &cert_tp);
        assert_eq!(out2, ConsumeOutcome::AlreadyConsumed);
    }

    #[test]
    fn consume_unknown_vm_id_rejected() {
        let (_tmp, mut state) = fresh_state();
        let out = state.consume("vmX", &[0u8; 32], &[0u8; 32]);
        assert_eq!(out, ConsumeOutcome::UnknownVmId);
    }

    #[test]
    fn consume_wrong_token_rejected() {
        let (_tmp, mut state) = fresh_state();
        state.add("vm1", &[0xAAu8; 32]);
        let out = state.consume("vm1", &[0xBBu8; 32], &[0u8; 32]);
        assert_eq!(out, ConsumeOutcome::TokenMismatch);

        // The original token still works.
        let out2 = state.consume("vm1", &[0xAAu8; 32], &[0u8; 32]);
        assert_eq!(out2, ConsumeOutcome::Accepted);
    }

    #[test]
    fn save_then_load_round_trips_state() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("bootstrap.yaml");
        {
            let mut state = BootstrapState::load(&path).unwrap();
            state.add("vm1", &[0x11u8; 32]);
            state.add("vm2", &[0x22u8; 32]);
            let _ = state.consume("vm1", &[0x11u8; 32], &[0xCDu8; 32]);
            state.save().unwrap();
        }
        // Reload.
        let state = BootstrapState::load(&path).unwrap();
        assert_eq!(state.len(), 2);
        let e1 = state.get("vm1").unwrap();
        assert!(e1.consumed);
        assert!(e1.consumed_at.is_some());
        assert_eq!(
            e1.bound_cert_thumbprint.as_deref(),
            Some(&hex_lower(&[0xCDu8; 32])[..]),
        );
        let e2 = state.get("vm2").unwrap();
        assert!(!e2.consumed);
        assert!(e2.consumed_at.is_none());
    }

    #[test]
    fn consumed_marker_survives_daemon_restart() {
        // Simulate the canonical bug we want to defend against:
        // a daemon crash AFTER consume() but BEFORE the cert was
        // distributed should NOT let the next daemon re-accept the
        // same token.
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("bootstrap.yaml");
        let token = [0xABu8; 32];

        {
            let mut state = BootstrapState::load(&path).unwrap();
            state.add("vm1", &token);
            assert_eq!(
                state.consume("vm1", &token, &[0xCDu8; 32]),
                ConsumeOutcome::Accepted
            );
            state.save().unwrap();
        }

        // Daemon restart.
        let mut state = BootstrapState::load(&path).unwrap();
        assert_eq!(
            state.consume("vm1", &token, &[0xCDu8; 32]),
            ConsumeOutcome::AlreadyConsumed
        );
    }

    #[test]
    fn re_add_replaces_existing_entry() {
        // Re-flash issues a new token; the daemon-side bookkeeping
        // (driven by the HSM-bundle manifest) calls add() again. The
        // new token must REPLACE the old, not be rejected.
        let (_tmp, mut state) = fresh_state();
        state.add("vm1", &[0x11u8; 32]);
        let _ = state.consume("vm1", &[0x11u8; 32], &[0u8; 32]); // consumed
        state.add("vm1", &[0x22u8; 32]); // re-flash: new token
        let out = state.consume("vm1", &[0x22u8; 32], &[0u8; 32]);
        assert_eq!(out, ConsumeOutcome::Accepted);
    }

    #[test]
    fn rejects_malformed_yaml() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("bootstrap.yaml");
        std::fs::write(&path, "not: valid: yaml: at all").unwrap();
        let err = BootstrapState::load(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn atomic_save_leaves_no_tmp_file() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("bootstrap.yaml");
        let mut state = BootstrapState::load(&path).unwrap();
        state.add("vm1", &[0x42u8; 32]);
        state.save().unwrap();
        assert!(path.exists());
        // The tmp file is renamed away.
        let tmp_path = path.with_extension("yaml.tmp");
        assert!(!tmp_path.exists(), "stale tmp file at {}", tmp_path.display());
    }
}
