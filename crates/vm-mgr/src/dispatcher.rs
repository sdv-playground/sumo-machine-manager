//! F.D3 dispatcher — manifest target identification.
//!
//! The dispatcher answers a narrow but recurring question: given the
//! bytes of a SUIT envelope, **which Component should handle it?**
//! Today that mapping is implicit (each Component is wired to a single
//! `BankSet` at construction; the SOVD wire's `component_id` already
//! selects the right `Component` before bytes flow).  This module makes
//! the mapping explicit so:
//!
//! 1. SOVD-side or off-board callers can pre-flight a manifest against
//!    a target component before opening a stream — failing fast with
//!    HTTP 415 (Unsupported Media Type) instead of burning bandwidth
//!    on an upload the backend would reject mid-stream.
//! 2. Future fleet-pull / campaign code (F.D5+) can resolve "this
//!    manifest belongs to bank_set X" without re-implementing the
//!    SUIT envelope parse.
//!
//! This is the SUIT-aware peek path.  The SOVDd `POST /updates` wire
//! also accepts an explicit `target: <component_id>` string field that
//! the SOVD layer validates without parsing SUIT — that path is faster
//! and is what F.D2 wired.  This module's peek is for callers that
//! have envelope bytes in hand but no out-of-band target hint.
//!
//! ## Mapping
//!
//! Envelope's first component_id segment (UTF-8 decoded) is matched
//! against:
//!
//! - The well-known `BankSet::from_str` aliases (`host-os`, `vm1`,
//!   `vm2`, `hsm`, `app`, `custom`).
//! - Deployment-registered aliases on `SuitProvider::component_aliases`
//!   — not yet exposed here; callers that need alias-aware resolution
//!   should use `SuitProvider::extract_metadata` instead.
//!
//! ## Future direction
//!
//! `peek_target_bank_set` is intentionally a free function (not on a
//! trait) because today there's exactly one envelope format.  When the
//! dispatcher gains shape-discrimination (e.g. plain firmware vs SUIT)
//! it'll grow a trait whose default impl is this function.

use machine_mgr::MachineError;
use nv_store::types::BankSet;

use crate::manifest_provider::ManifestError;

/// Decode the SUIT envelope just enough to recover its target
/// [`BankSet`].  Does not verify the signature — callers that need
/// signature validation should use [`crate::suit_provider::SuitProvider`].
///
/// Returns `ManifestError::ParseError` on malformed CBOR and
/// `ManifestError::ComponentUnknown` when the manifest carries a
/// `component_id` segment that doesn't resolve to a known BankSet.
pub fn peek_target_bank_set(envelope_bytes: &[u8]) -> Result<BankSet, ManifestError> {
    let envelope = sumo_codec::decode::decode_envelope(envelope_bytes)
        .map_err(|e| ManifestError::ParseError(format!("decode envelope: {e:?}")))?;
    let manifest = sumo_onboard::manifest::Manifest { envelope };

    let segments = manifest
        .component_id(0)
        .ok_or_else(|| ManifestError::ComponentUnknown("missing component_id".into()))?;

    segments
        .iter()
        .find_map(|seg| {
            let s = std::str::from_utf8(seg).ok()?;
            BankSet::from_str(s)
        })
        .ok_or_else(|| {
            let comp_str = segments
                .iter()
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect::<Vec<_>>()
                .join("/");
            ManifestError::ComponentUnknown(comp_str)
        })
}

/// Pre-flight check: peek the envelope's target BankSet and compare
/// against `expected`.  Returns `MachineError::WrongTarget` on mismatch
/// so the SOVD adapter surfaces it as HTTP 415 to the client.
///
/// Callers with an already-decoded `BankSet` (e.g. after
/// [`crate::suit_provider::SuitProvider::extract_metadata`]) should
/// compare directly rather than re-parse.
pub fn check_target(envelope_bytes: &[u8], expected: BankSet) -> Result<(), MachineError> {
    let actual = peek_target_bank_set(envelope_bytes)
        .map_err(|e| MachineError::ManifestInvalid(format!("peek failed: {e}")))?;
    if actual != expected {
        return Err(MachineError::WrongTarget(format!(
            "manifest target {:?} != expected {:?}",
            actual, expected
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peek_rejects_garbage() {
        let err = peek_target_bank_set(b"not a SUIT envelope").unwrap_err();
        match err {
            ManifestError::ParseError(_) => {}
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn check_target_propagates_parse_error_as_manifest_invalid() {
        let err = check_target(b"garbage", BankSet::Vm1).unwrap_err();
        match err {
            MachineError::ManifestInvalid(msg) => {
                assert!(msg.contains("peek failed"), "msg={msg}");
            }
            other => panic!("expected ManifestInvalid, got {other:?}"),
        }
    }
}
