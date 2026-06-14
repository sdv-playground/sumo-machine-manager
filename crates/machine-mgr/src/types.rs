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

/// A key slot surfaced by an HSM component's `data/keys` SOVD resource — the
/// public, SOVD-facing view of one keystore slot (never any key material).
/// Returned by [`Component::list_keys`](crate::Component::list_keys).
#[derive(Debug, Clone)]
pub struct KeyDescriptor {
    /// The slot id (e.g. `tls-identity`, `device-decrypt`) — the slot's
    /// identifier (there is no separate numeric slot index).
    pub key_id: String,
    /// Key type label (`EC-P256`, `AES-256`, …); the algorithm is implied.
    pub key_type: String,
    /// Whether the slot already holds a leaf certificate.
    pub has_certificate: bool,
    /// Permitted operations (e.g. `["sign","verify"]`); `None` = unrestricted.
    pub allowed_ops: Option<Vec<String>>,
    /// The slot's public key (DER SubjectPublicKeyInfo) for asymmetric keys —
    /// safe to return (e.g. the device-decryption pubkey a Tower encrypts to);
    /// `None` for symmetric keys. Never any private material.
    pub public_key: Option<Vec<u8>>,
}
