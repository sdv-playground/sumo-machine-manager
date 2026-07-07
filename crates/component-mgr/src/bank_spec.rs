//! Per-bank-set behavioral data, decoupled from the `BankSet` identity.
//!
//! `BankSet` (a numeric slot index) names a slot; `BankSetSpec` carries
//! the behavior that used to be hard-coded in `match bank_set { … }`
//! helpers — today just the on-disk directory name. Each component
//! supplies its own `BankSetSpec` at construction time; the bank-set
//! machinery in component-mgr stays generic.
//!
//! On-disk bank filenames are the SUIT component-id's last segment
//! **verbatim**: the manifest author picks the real filename
//! (`rootfs.img`, `vm-config.yaml`, `qvm.conf`, `kernel`, …) and it lands
//! under the bank dir unchanged. There is no URI→filename remap layer —
//! naming keys off the stable component-id part, never the (possibly
//! content-addressed) payload uri.

use nv_store::types::BankSet;

/// Per-bank-set spec attached to each ComponentBackend at construction.
#[derive(Debug, Clone)]
pub struct BankSetSpec {
    /// On-disk subdirectory under `images_dir`. E.g. "vm1", "host-os",
    /// "custom", or a deployment-defined name for an extra slot.
    pub dir_name: String,
}

impl BankSetSpec {
    /// Build the default spec for one of the well-known BankSet slots —
    /// the on-disk directory name that slot lives under. Every existing
    /// ComponentBackend constructor goes through here; component-factory
    /// overrides `dir_name` from deployment config (`storage_subdir`)
    /// when a slot needs a distinct directory.
    pub fn for_well_known(bs: BankSet) -> Self {
        let dir_name = match bs {
            BankSet::Hsm => "hsm",
            BankSet::Bootloader => "bootloader",
            BankSet::Os => "os",
            BankSet::Rt => "rt",
            BankSet::Vm1 => "vm1",
            BankSet::Vm2 => "vm2",
            _ => "custom",
        }
        .to_string();

        Self { dir_name }
    }
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
pub fn payload_target_name_for_id(component_id: Option<&[Vec<u8>]>) -> String {
    component_id
        .and_then(|segs| segs.last())
        .map(|seg| String::from_utf8_lossy(seg).into_owned())
        .unwrap_or_else(|| "firmware".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_well_known_vm_slots() {
        assert_eq!(BankSetSpec::for_well_known(BankSet::Vm1).dir_name, "vm1");
        assert_eq!(BankSetSpec::for_well_known(BankSet::Vm2).dir_name, "vm2");
    }

    #[test]
    fn for_well_known_os_hsm_dir_names() {
        assert_eq!(BankSetSpec::for_well_known(BankSet::Os).dir_name, "os");
        assert_eq!(BankSetSpec::for_well_known(BankSet::Hsm).dir_name, "hsm");
    }

    #[test]
    fn for_well_known_rt_dir_name() {
        assert_eq!(BankSetSpec::for_well_known(BankSet::Rt).dir_name, "rt");
    }

    #[test]
    fn unknown_slot_falls_back_to_custom() {
        // Slots beyond the well-known ones get the "custom" dir. Phase 3
        // replaces this with a component-config lookup.
        assert_eq!(BankSetSpec::for_well_known(BankSet(99)).dir_name, "custom");
    }

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
            payload_target_name_for_id(Some(kernel.as_slice())),
            "kernel"
        );
        assert_eq!(
            payload_target_name_for_id(Some(rootfs.as_slice())),
            "rootfs.img"
        );
        assert_eq!(
            payload_target_name_for_id(Some(config.as_slice())),
            "vm-config.yaml"
        );
        assert_eq!(payload_target_name_for_id(Some(qvm.as_slice())), "qvm.conf");
        assert_eq!(
            payload_target_name_for_id(Some(rt.as_slice())),
            "rt-firmware.s19"
        );
        // No id → the `firmware` fallback, never a raw content address.
        assert_eq!(payload_target_name_for_id(None), "firmware");
    }
}
