//! Per-bank-set behavioral data, decoupled from the `BankSet` identity.
//!
//! `BankSet` (a numeric slot index) names a slot; `BankSetSpec` carries
//! the behavior that used to be hard-coded in `match bank_set { … }`
//! helpers — today just the on-disk directory name. The name comes from
//! the platform, which is the only thing that knows what a slot holds:
//! the component's `storage_subdir` when deployment config sets one,
//! else its component id. Each component supplies its own `BankSetSpec`
//! at construction time; the bank-set machinery in component-mgr stays
//! generic and derives no directory from a slot.
//!
//! On-disk bank filenames are the SUIT component-id's last segment
//! **verbatim**: the manifest author picks the real filename
//! (`rootfs.img`, `vm-config.yaml`, `qvm.conf`, `kernel`, …) and it lands
//! under the bank dir unchanged. There is no URI→filename remap layer —
//! naming keys off the stable component-id part, never the (possibly
//! content-addressed) payload uri.

use machine_mgr::bank_provider::DISABLED_RECORD_PATH;
use sovd_core::error::{BackendError, BackendResult};

/// Per-bank-set spec attached to each ComponentBackend at construction.
#[derive(Debug, Clone)]
pub struct BankSetSpec {
    /// On-disk subdirectory under `images_dir`, supplied by the platform:
    /// the component's `storage_subdir` when deployment config sets one,
    /// else its component id. `images_dir/<dir_name>/<bank>` is where the
    /// banked payloads live, so every component needs its own.
    pub dir_name: String,
}

/// The on-disk bank filename for a SUIT component: its component-id's last
/// **part** segment, taken verbatim.
///
/// The payload uri is the content-address fetch reference (`sha256:<outer>`) and
/// must never dictate the on-disk name — otherwise a content-addressed payload
/// lands verbatim as `sha256:…` and the bank won't boot. The component-id's last
/// segment is the stable part identity (`[component, part]` → `part`) and IS the
/// on-disk filename as authored (`rootfs.img`, `vm-config.yaml`, `qvm.conf`,
/// `kernel`, …) — no remap. `firmware` is the fallback when a component carries
/// no id.
///
/// One name is refused: [`DISABLED_RECORD_PATH`], the entry the device's
/// administrative-disable record is made of (`InvalidRequest`, naming it). Every
/// payload's bank name is decided here, so this is the one place to refuse it.
pub fn payload_target_name_for_id(component_id: Option<&[Vec<u8>]>) -> BackendResult<String> {
    let name = component_id
        .and_then(|segs| segs.last())
        .map(|seg| String::from_utf8_lossy(seg).into_owned())
        .unwrap_or_else(|| "firmware".to_string());
    if name == DISABLED_RECORD_PATH {
        return Err(BackendError::InvalidRequest(format!(
            "manifest part name '{DISABLED_RECORD_PATH}' is reserved for the device's administrative-disable record"
        )));
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_name_from_component_id_not_uri() {
        // Regression guard: a content-address payload uri must NOT leak into the
        // on-disk name (that produced un-bootable `sha256:…` bank files). Naming
        // keys off the component-id `[component, part]` part segment, taken
        // VERBATIM — the manifest author already chose the real filename, so
        // there is no URI→filename remap.
        let kernel = [b"vm1".to_vec(), b"kernel".to_vec()];
        let rootfs = [b"vm1".to_vec(), b"rootfs.img".to_vec()];
        let config = [b"vm1".to_vec(), b"vm-config.yaml".to_vec()];
        let qvm = [b"vm1".to_vec(), b"qvm.conf".to_vec()];
        // A deployment-specific segment lands verbatim, same as any other.
        let rt = [b"rt".to_vec(), b"rt-firmware.s19".to_vec()];
        assert_eq!(
            payload_target_name_for_id(Some(kernel.as_slice())).unwrap(),
            "kernel"
        );
        assert_eq!(
            payload_target_name_for_id(Some(rootfs.as_slice())).unwrap(),
            "rootfs.img"
        );
        assert_eq!(
            payload_target_name_for_id(Some(config.as_slice())).unwrap(),
            "vm-config.yaml"
        );
        assert_eq!(
            payload_target_name_for_id(Some(qvm.as_slice())).unwrap(),
            "qvm.conf"
        );
        assert_eq!(
            payload_target_name_for_id(Some(rt.as_slice())).unwrap(),
            "rt-firmware.s19"
        );
        // No id → the `firmware` fallback, never a raw content address.
        assert_eq!(payload_target_name_for_id(None).unwrap(), "firmware");
    }

    /// The disable record's entry name is the device's own: a payload named
    /// like it is refused, and the refusal names the reserved path.
    #[test]
    fn a_payload_named_like_the_sentinel_is_refused() {
        let id = [b"vm1".to_vec(), DISABLED_RECORD_PATH.as_bytes().to_vec()];
        match payload_target_name_for_id(Some(id.as_slice())) {
            Err(BackendError::InvalidRequest(msg)) => {
                assert!(msg.contains(DISABLED_RECORD_PATH), "got: {msg}")
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }
}
