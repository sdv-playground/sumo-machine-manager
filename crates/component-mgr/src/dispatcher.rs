//! F.D3 dispatcher — manifest target identification.
//!
//! The dispatcher answers a narrow but recurring question: given the
//! bytes of a SUIT envelope, **which Component should handle it?**
//! A SUIT manifest addresses a component by NAME — the id the platform
//! profile declares — so the answer is simply the name it carries.  This
//! module makes the mapping explicit so:
//!
//! 1. SOVD-side or off-board callers can pre-flight a manifest against
//!    a target component before opening a stream — failing fast with
//!    HTTP 415 (Unsupported Media Type) instead of burning bandwidth
//!    on an upload the backend would reject mid-stream.
//! 2. Fleet-pull / campaign code can resolve "this manifest belongs to
//!    component X" without re-implementing the SUIT envelope parse.
//!
//! This is the SUIT-aware peek path.  The SOVDd `POST /updates` wire
//! also accepts an explicit `target: <component_id>` string field that
//! the SOVD layer validates without parsing SUIT — that path is faster
//! and is what F.D2 wired.  This module's peek is for callers that
//! have envelope bytes in hand but no out-of-band target hint.
//!
//! ## Mapping
//!
//! The component id's first segment, UTF-8 decoded, IS the component
//! name, and it is compared **verbatim** against the component's own id.
//! There is no alias map and no name→slot table: which slot a component
//! occupies lives in the platform profile, not in a manifest.
//!
//! ## Future direction
//!
//! `peek_target_component` is intentionally a free function (not on a
//! trait) because today there's exactly one envelope format.  When the
//! dispatcher gains shape-discrimination (e.g. plain firmware vs SUIT)
//! it'll grow a trait whose default impl is this function.

use machine_mgr::MachineError;
use sumo_onboard::manifest::Manifest;

use crate::manifest_provider::ManifestError;

/// The component NAME a manifest targets: segment 0 of its SUIT
/// component id, UTF-8 decoded, verbatim.
///
/// A multi-component envelope (host-os carries `#ifs` + `#rootfs`, a VM
/// carries kernel + rootfs + config) names the same component in every
/// entry — only the trailing `part` segment differs.  Entries that
/// disagree address two components at once, which no single component
/// can install, so that is an error naming both.
///
/// Returns `ManifestError::ComponentUnknown` when the manifest carries
/// no component id, when segment 0 isn't UTF-8, or on disagreement.
pub fn target_component(manifest: &Manifest) -> Result<String, ManifestError> {
    let mut target: Option<String> = None;
    for i in 0..manifest.component_count() {
        let seg = manifest
            .component_id(i)
            .and_then(|segs| segs.first())
            .ok_or_else(|| ManifestError::ComponentUnknown("missing component_id".into()))?;
        let name = std::str::from_utf8(seg).map_err(|_| {
            ManifestError::ComponentUnknown(format!("component {i}: id segment is not UTF-8"))
        })?;
        match target {
            None => target = Some(name.to_string()),
            Some(ref first) if first == name => {}
            Some(first) => {
                return Err(ManifestError::ComponentUnknown(format!(
                    "manifest names two components: '{first}' and '{name}'"
                )))
            }
        }
    }
    target.ok_or_else(|| ManifestError::ComponentUnknown("missing component_id".into()))
}

/// Decode the SUIT envelope just enough to recover the component name it
/// targets.  Does not verify the signature — callers that need signature
/// validation should use [`crate::suit_provider::SuitProvider`].
///
/// Returns `ManifestError::ParseError` on malformed CBOR, and whatever
/// [`target_component`] reports for an unusable component id.
pub fn peek_target_component(envelope_bytes: &[u8]) -> Result<String, ManifestError> {
    let envelope = sumo_codec::decode::decode_envelope(envelope_bytes)
        .map_err(|e| ManifestError::ParseError(format!("decode envelope: {e:?}")))?;
    target_component(&Manifest { envelope })
}

/// Pre-flight check: peek the envelope's target component name and
/// compare it against `expected_component_id`.  Returns
/// `MachineError::WrongTarget` on mismatch so the SOVD adapter surfaces
/// it as HTTP 415 to the client.
///
/// Callers with an already-validated manifest in hand (e.g. after
/// [`crate::manifest_provider::ManifestProvider::validate`]) should
/// compare `ValidatedFirmware::component_name` rather than re-parse.
pub fn check_target(
    envelope_bytes: &[u8],
    expected_component_id: &str,
) -> Result<(), MachineError> {
    let actual = peek_target_component(envelope_bytes)
        .map_err(|e| MachineError::ManifestInvalid(format!("peek failed: {e}")))?;
    if actual != expected_component_id {
        return Err(MachineError::WrongTarget(format!(
            "manifest target '{actual}' != expected '{expected_component_id}'"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumo_offboard::image_builder::{ComponentSpec, MultiComponentBuilder};
    use sumo_offboard::{keygen, ImageManifestBuilder};

    /// Single-component envelope addressed to `component`.
    fn envelope_for(component: &str) -> Vec<u8> {
        let key = keygen::generate_signing_key(keygen::ES256).unwrap();
        ImageManifestBuilder::new()
            .signing_time(1_700_000_000)
            .component_id(vec![component.into(), "rootfs.img".into()])
            .sequence_number(1)
            .payload_digest(&[0u8; 32], 0)
            .payload_uri("#firmware".into())
            .build(&key)
            .unwrap()
    }

    /// Multi-component envelope whose entries name `first` and `second`.
    fn envelope_for_two(first: &str, second: &str) -> Vec<u8> {
        let key = keygen::generate_signing_key(keygen::ES256).unwrap();
        let spec = |component: &str, part: &str| ComponentSpec {
            id: vec![component.to_string(), part.to_string()],
            digest: vec![0u8; 32],
            size: 0,
            uri: format!("#{part}"),
            encryption_info: None,
        };
        MultiComponentBuilder::new()
            .signing_time(1_700_000_000)
            .sequence_number(1)
            .add_component(spec(first, "kernel"))
            .add_component(spec(second, "rootfs.img"))
            .build(&key)
            .unwrap()
    }

    #[test]
    fn peek_rejects_garbage() {
        let err = peek_target_component(b"not a SUIT envelope").unwrap_err();
        match err {
            ManifestError::ParseError(_) => {}
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn check_target_propagates_parse_error_as_manifest_invalid() {
        let err = check_target(b"garbage", "vm1").unwrap_err();
        match err {
            MachineError::ManifestInvalid(msg) => {
                assert!(msg.contains("peek failed"), "msg={msg}");
            }
            other => panic!("expected ManifestInvalid, got {other:?}"),
        }
    }

    /// The name is read verbatim off segment 0 — no table, no slot.
    /// A name no slot vocabulary ever knew resolves just as well.
    #[test]
    fn peek_returns_the_component_name_verbatim() {
        assert_eq!(peek_target_component(&envelope_for("vm1")).unwrap(), "vm1");
        assert_eq!(
            peek_target_component(&envelope_for("co-processor")).unwrap(),
            "co-processor"
        );
    }

    /// Matching name passes; a different name is the 415 (`WrongTarget`) path.
    #[test]
    fn check_target_compares_names() {
        let env = envelope_for("co-processor");
        check_target(&env, "co-processor").expect("same name → accepted");

        let err = check_target(&env, "vm1").unwrap_err();
        match err {
            MachineError::WrongTarget(msg) => {
                assert!(
                    msg.contains("co-processor") && msg.contains("vm1"),
                    "msg={msg}"
                );
            }
            other => panic!("expected WrongTarget, got {other:?}"),
        }
    }

    /// A multi-component envelope naming the same component in every entry is
    /// the normal shape (kernel + rootfs); one that names two is rejected —
    /// no single component can install it.
    #[test]
    fn multi_component_entries_must_agree() {
        assert_eq!(
            peek_target_component(&envelope_for_two("vm1", "vm1")).unwrap(),
            "vm1"
        );

        let err = peek_target_component(&envelope_for_two("vm1", "vm2")).unwrap_err();
        match err {
            ManifestError::ComponentUnknown(msg) => {
                assert!(msg.contains("vm1") && msg.contains("vm2"), "msg={msg}");
            }
            other => panic!("expected ComponentUnknown, got {other:?}"),
        }
    }
}
