//! Domain types specific to machine-mgr.
//!
//! Wire types we share with SOVD (`ActivationState`, `FlashStatus`, ...) are
//! re-exported from `sovd-core` at the crate root. The types here describe
//! richer machine-side concepts that the orchestrator may want even if the
//! current SOVD wire format doesn't surface them yet.

use serde::{Deserialize, Serialize};

// `ResetKind` is part of the SOVD wire (ActivationState carries it), so the
// canonical definition lives in sovd-core. We re-export here so existing
// `machine_mgr::ResetKind` import paths keep working and BankActivator's
// trait method can reference it without an extra dep edge for callers.
pub use sovd_core::ResetKind;

/// Capability descriptor for a `Component`.
///
/// Optional groups: `None` means the component does not support that
/// family of operations. The defaulted `Component` methods return
/// `MachineError::NotSupported` for anything that's `None` here.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capabilities {
    /// True if the component exposes any factory or runtime DIDs.
    pub did_store: bool,

    /// Software-update capability and its shape (single bank, A/B, etc.).
    pub flash: Option<FlashCaps>,

    /// Lifecycle capability (restart, runtime state).
    pub lifecycle: Option<LifecycleCaps>,

    /// HSM-specific operations (CSR retrieval, key envelope install).
    pub hsm: Option<HsmCaps>,

    /// True if the component reports DTCs.
    pub dtcs: bool,

    /// True if the component supports clearing DTCs.
    pub clear_dtcs: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlashCaps {
    /// Two banks with rollback (A/B) vs. single bank (no rollback).
    pub dual_bank: bool,
    /// Whether `rollback_install` is meaningful after commit.
    pub supports_rollback: bool,
    /// Whether the component runs the new image on trial before commit.
    pub supports_trial_boot: bool,
    /// True if `abort_install` works *after* `finalize_install` has run.
    /// HSM-style components are `false` (finalize writes irreversibly);
    /// A/B-style components are typically `true` (finalize just flips a
    /// pointer that can be flipped back before reboot).
    pub abortable_after_finalize: bool,
    /// What kind of reset is needed to activate a newly-staged image.
    /// The orchestrator coalesces resets across components — multiple
    /// `RequiresEcuReset` components in one campaign collapse into a single
    /// `PUT {ecu-path}/status/restart` instead of N per-component restarts.
    /// `#[serde(default)]` keeps older JSON payloads (pre-Phase-1) deserialising
    /// — they get `Local` which matches their actual behaviour today.
    /// See `tasks/reset-kind-and-status-restart.md` for the full design.
    #[serde(default)]
    pub reset_kind: ResetKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleCaps {
    /// `restart()` will actually restart the component.
    pub restartable: bool,
    /// `runtime_state()` returns meaningful info.
    pub has_runtime_state: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmCaps {
    pub supports_csr: bool,
    pub supports_key_install: bool,
}

/// Whether a DID belongs to factory-provisioned data or runtime-mutable data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DidKind {
    Factory,
    Runtime,
}

/// Opaque identifier for an in-progress flash session.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlashId(pub String);

impl FlashId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for FlashId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Result of `prepare_flash` — the handle the orchestrator uses for the
/// remainder of the OTA pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlashSession {
    pub id: FlashId,
    /// Target bank (`"a"` / `"b"`) for dual-bank components, otherwise `None`.
    pub target_bank: Option<String>,
    /// Maximum chunk size for `write_chunk`, mirrored from `FlashCaps` for
    /// convenience so the caller doesn't have to look it up again.
    pub max_chunk_size: usize,
}

/// Session-scoped pull source for an install whose manifest references
/// payloads by content-addressed URI, plus the campaign identity for the
/// node update-transaction gate. Set via `Component::set_install_source`
/// BEFORE `start_install`; cleared when the session ends.
#[derive(Clone)]
pub struct InstallSource {
    /// Base URL of the (untrusted) content-addressed store. Every fetched
    /// blob is verified against the content-address the signed manifest
    /// committed to, so the URL itself carries no trust.
    pub cas_base_url: String,
    /// CBOR COSE_Key trust anchor (sw-authority) for validating any manifest
    /// fetched through this source.
    pub trust_anchor: Vec<u8>,
    /// Campaign identity (sha256 of the signed L1 envelope bytes) used as the
    /// node update-transaction session id, so sibling components of one
    /// campaign JOIN a single node transaction. `None` keeps the interim
    /// zero id.
    pub session_id: Option<[u8; 32]>,
}

impl std::fmt::Debug for InstallSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstallSource")
            .field("cas_base_url", &self.cas_base_url)
            .field("trust_anchor_bytes", &self.trust_anchor.len())
            .field("session_id", &self.session_id.map(hex::encode))
            .finish()
    }
}

/// Snapshot of a component's runtime state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeState {
    pub status: RuntimeStatus,
    /// Free-form, human-readable detail (firmware version, health summary,
    /// uptime, last boot reason, etc.). The orchestrator should treat the
    /// shape as informational.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeStatus {
    Running,
    Stopped,
    Booting,
    Faulted,
    Unknown,
}

/// Outcome of `Component::set_admin_state` — the persisted per-component
/// administrative state after the call, for the SOVD §7.14 operation
/// execution render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminStateOutcome {
    /// The persisted state after the call: `true` = administratively disabled.
    pub disabled: bool,
    /// True when the enacted deactivation only completes at the next node
    /// reset (RT erase) — the caller issues the existing `status/restart`;
    /// the op itself never reboots (see `crate::deactivator`).
    pub reboot_required: bool,
    /// The enactment step's failure, if any. The persisted flag is written
    /// FIRST, so a failed enact leaves the state changed regardless — the
    /// caller reports the error honestly instead of rolling the flag back
    /// (the start/flash gates converge the runtime at the next boot).
    pub enact_error: Option<String>,
}

/// Filter for `Component::list_dids`.
#[derive(Debug, Clone, Default)]
pub struct DidFilter {
    /// If set, only DIDs of this kind are returned.
    pub kind: Option<DidKind>,
    /// If set, only DIDs whose name matches this prefix are returned.
    pub name_prefix: Option<String>,
}

/// DTC filter delegated through to the component. Mirrors sovd-core's
/// `FaultFilter` shape but lives in machine-mgr so impls don't have to depend
/// on sovd-core directly if they choose not to.
#[derive(Debug, Clone, Default)]
pub struct DtcFilter {
    pub active_only: bool,
    pub category: Option<String>,
}

/// Streaming source of envelope bytes for `Component::upload_envelope`.
///
/// One-shot callers wrap their `Vec<u8>` with `futures::stream::once` and
/// pin-box it. Same shape as sovd-core's `PackageStream` so translation in
/// the diagserver layer is trivial.
pub type EnvelopeStream = std::pin::Pin<
    Box<
        dyn futures::Stream<Item = Result<bytes::Bytes, Box<dyn std::error::Error + Send + Sync>>>
            + Send,
    >,
>;

/// PEM- or DER-encoded device CSR returned by `Component::get_csr`.
#[derive(Debug, Clone)]
pub struct Csr(pub bytes::Bytes);

impl Csr {
    pub fn from_bytes(b: impl Into<bytes::Bytes>) -> Self {
        Self(b.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// What a slot in the `data/keys` inventory holds: a cryptographic key (with its
/// type label) or the non-key monotonic counter.
///
/// Mirrors the HSM contract's `SlotKind` at the SOVD layer. machine-mgr carries
/// no HSM dependency, so a key slot's type is the already-resolved label string
/// (`EC-P256`, `AES-256`, …) rather than the HSM `KeyType` enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotKind {
    /// A cryptographic key slot; the string is the key-type label.
    Key(String),
    /// A rollback-proof monotonic-counter slot (e.g. the time-floor) — holds no
    /// key material, just an upward-only counter.
    Monotonic,
}

impl SlotKind {
    /// The honest wire label for this kind: the key-type label for a key slot,
    /// or `"monotonic"` for the counter.
    pub fn label(&self) -> &str {
        match self {
            SlotKind::Key(t) => t,
            SlotKind::Monotonic => "monotonic",
        }
    }
}

/// A slot surfaced by an HSM component's `data/keys` SOVD resource — the public,
/// SOVD-facing view of one keystore slot (never any key material). Returned by
/// [`Component::list_keys`](crate::Component::list_keys); the inventory reports
/// EVERY slot, key slots AND the monotonic counter (see [`SlotKind`]).
#[derive(Debug, Clone)]
pub struct KeyDescriptor {
    /// The slot id (e.g. `tls-identity`, `device-decrypt`, `time-floor`) — the
    /// slot's identifier (there is no separate numeric slot index).
    pub key_id: String,
    /// Whether this slot is a key (with its type label, `EC-P256`/`AES-256`/…)
    /// or the non-key monotonic counter. See [`SlotKind`].
    pub kind: SlotKind,
    /// Whether the slot already holds a leaf certificate.
    pub has_certificate: bool,
    /// Permitted operations (e.g. `["sign","verify"]`); `None` = unrestricted.
    pub allowed_ops: Option<Vec<String>>,
    /// The slot's public key (DER SubjectPublicKeyInfo) for asymmetric keys —
    /// safe to return (e.g. the device-decryption pubkey a Tower encrypts to);
    /// `None` for symmetric keys and the counter. Never any private material.
    pub public_key: Option<Vec<u8>>,
}

/// The HSM key inventory returned by [`Component::list_keys`](crate::Component::list_keys)
/// — the device's own provisioning state plus the key slots. Always available
/// (the device-generated keys exist from first boot), so callers read
/// `provisioned` directly instead of inferring it from an endpoint's status.
#[derive(Debug, Clone)]
pub struct KeyInventory {
    /// Whether the HSM has been provisioned (its keystore installed). The device
    /// reports its own truth — no heuristic.
    pub provisioned: bool,
    /// The key slots (public metadata only; see [`KeyDescriptor`]).
    pub keys: Vec<KeyDescriptor>,
}
