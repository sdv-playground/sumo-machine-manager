//! Per-bank-set behavioral data, decoupled from the `BankSet` identity.
//!
//! `BankSet` (a numeric slot index) names a slot; `BankSetSpec` carries
//! the behaviors that used to be hard-coded in `match bank_set { … }`
//! helpers — the on-disk directory name and the SUIT-payload-URI →
//! filename layout. Each component supplies its own `BankSetSpec` at
//! construction time; the bank-set machinery in component-mgr stays generic.
//!
//! Phase 2 of the deep refactor adds this module. Phase 3 makes the
//! spec construction config-driven (via component-factory's
//! `ComponentSpec`) so deployments add components without touching
//! this code at all.

use nv_store::types::BankSet;

/// How SUIT payload URIs map to on-disk filenames inside a bank dir.
///
/// `payload_target_name(layout, uri)` is the lookup helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BankLayout {
    /// VM-style: `#kernel` → `kernel`, `#qvm-config` → `qvm.conf`.
    /// Used by qvm guest VMs (vm1, vm2 today).
    Vm,
    /// Bootable IFS: `#kernel` → `boot.ifs`, `#qvm-config` → `qvm.conf`.
    /// Used by the host OS image, the HSM keystore, and the supernova
    /// self-update slot. (The `qvm.conf` part is meaningless for HSM
    /// but harmless — that slot never delivers a `#qvm-config` URI.)
    BootIfs,
    /// Pass-through: no special URI mappings. Any `#foo` URI lands as
    /// `foo` (the `#` is stripped). Used by Custom-style slots whose
    /// manifests deliver deployment-specific files (e.g. the RT side's
    /// `rt-firmware.bin`).
    Generic,
}

/// Per-bank-set spec attached to each ComponentBackend at construction.
#[derive(Debug, Clone)]
pub struct BankSetSpec {
    /// On-disk subdirectory under `images_dir`. E.g. "vm1", "host-os",
    /// "custom", or a deployment-defined name for an extra slot.
    pub dir_name: String,

    /// SUIT-URI → filename mapping.
    pub layout: BankLayout,
}

impl BankSetSpec {
    /// Build the default spec for one of the six well-known BankSet
    /// slots. **Bridge for Phase 2** — until Phase 3 wires the spec
    /// through component-factory, every existing ComponentBackend
    /// constructor goes through here.
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

        let layout = match bs {
            BankSet::Vm1 | BankSet::Vm2 => BankLayout::Vm,
            BankSet::Os | BankSet::Hsm => BankLayout::BootIfs,
            // Bootloader + Rt are pass-through (like the old Custom slot).
            _ => BankLayout::Generic,
        };

        Self { dir_name, layout }
    }
}

/// Map a SUIT payload URI to the on-disk filename inside the target
/// bank dir, given the bank's layout. Replaces the
/// `bank_set`-keyed `payload_target_name(BankSet, &str)`.
pub fn payload_target_name(layout: BankLayout, uri: &str) -> String {
    let (kernel_name, qvm_config_name) = match layout {
        BankLayout::Vm => ("kernel", "qvm.conf"),
        BankLayout::BootIfs => ("boot.ifs", "qvm.conf"),
        BankLayout::Generic => ("", ""),
    };
    // Generic banks (e.g. the M7/RT slot) are verbatim — NO VM-style URI
    // remapping. Without this gate, `#firmware`/`#config` would be force-renamed
    // to rootfs.img / vm-config.yaml even for rt, so `rt-firmware.s19` lands as
    // rootfs.img and the m7loader can't find it. Only VM/BootIfs layouts remap.
    let vm_style = !matches!(layout, BankLayout::Generic);
    match uri {
        "#kernel" if !kernel_name.is_empty() => kernel_name.to_string(),
        "#firmware" if vm_style => "rootfs.img".to_string(),
        "#config" if vm_style => "vm-config.yaml".to_string(),
        "#qvm-config" if !qvm_config_name.is_empty() => qvm_config_name.to_string(),
        other => other.trim_start_matches('#').to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_well_known_vm_slots() {
        let s = BankSetSpec::for_well_known(BankSet::Vm1);
        assert_eq!(s.dir_name, "vm1");
        assert_eq!(s.layout, BankLayout::Vm);

        let s = BankSetSpec::for_well_known(BankSet::Vm2);
        assert_eq!(s.dir_name, "vm2");
        assert_eq!(s.layout, BankLayout::Vm);
    }

    #[test]
    fn for_well_known_boot_ifs_slots() {
        for bs in [BankSet::Os, BankSet::Hsm] {
            let s = BankSetSpec::for_well_known(bs);
            assert_eq!(s.layout, BankLayout::BootIfs);
        }
    }

    #[test]
    fn for_well_known_rt_is_generic() {
        let s = BankSetSpec::for_well_known(BankSet::Rt);
        assert_eq!(s.dir_name, "rt");
        assert_eq!(s.layout, BankLayout::Generic);
    }

    #[test]
    fn unknown_slot_falls_back_to_generic_custom() {
        // Slots beyond the well-known 6 get the same default as Custom.
        // Phase 3 replaces this with a component-config lookup.
        let s = BankSetSpec::for_well_known(BankSet(99));
        assert_eq!(s.dir_name, "custom");
        assert_eq!(s.layout, BankLayout::Generic);
    }

    #[test]
    fn payload_uri_mapping_vm() {
        assert_eq!(payload_target_name(BankLayout::Vm, "#kernel"), "kernel");
        assert_eq!(
            payload_target_name(BankLayout::Vm, "#firmware"),
            "rootfs.img"
        );
        assert_eq!(
            payload_target_name(BankLayout::Vm, "#config"),
            "vm-config.yaml"
        );
        assert_eq!(
            payload_target_name(BankLayout::Vm, "#qvm-config"),
            "qvm.conf"
        );
        // Anything else strips the leading '#'.
        assert_eq!(payload_target_name(BankLayout::Vm, "#extra"), "extra");
    }

    #[test]
    fn payload_uri_mapping_boot_ifs() {
        assert_eq!(
            payload_target_name(BankLayout::BootIfs, "#kernel"),
            "boot.ifs"
        );
        assert_eq!(
            payload_target_name(BankLayout::BootIfs, "#qvm-config"),
            "qvm.conf"
        );
    }

    #[test]
    fn payload_uri_mapping_generic_passes_through() {
        // No special URI mappings — `#kernel` becomes `kernel` via the
        // trim_start_matches fallback, NOT the layout-specific table.
        assert_eq!(
            payload_target_name(BankLayout::Generic, "#kernel"),
            "kernel"
        );
        assert_eq!(
            payload_target_name(BankLayout::Generic, "#rt-firmware"),
            "rt-firmware",
        );
        // #firmware / #config are VM/BootIfs-isms — Generic must NOT remap them
        // (the regression that wrote rt's firmware as rootfs.img). Verbatim.
        assert_eq!(
            payload_target_name(BankLayout::Generic, "#firmware"),
            "firmware"
        );
        assert_eq!(
            payload_target_name(BankLayout::Generic, "#config"),
            "config"
        );
        // The real rt payload URI lands verbatim — what the m7loader expects.
        assert_eq!(
            payload_target_name(BankLayout::Generic, "#rt-firmware.s19"),
            "rt-firmware.s19"
        );
    }
}
