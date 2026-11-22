//! Built-in bank activators: the [`BankActivator`]s that behave the same on
//! every node, selected by a component's `activator:` marker through
//! [`builtin_activator`]. Device activators (a co-processor loader, a raw
//! partition bank, ...) are not here; the node binary registers those itself for
//! the markers [`builtin_activator`] does not know.

use std::path::Path;
use std::sync::Arc;

use machine_mgr::{BankActivator, BankActivatorError, ResetKind};

/// The [`BankActivator`] for an `activator:` marker sumo implements itself, or
/// `None` for a marker the node binary has to wire. Known markers:
/// `hsm-keystore` ([`HsmKeystoreActivator`]).
pub fn builtin_activator(marker: &str) -> Option<Arc<dyn BankActivator>> {
    match marker {
        "hsm-keystore" => Some(Arc::new(HsmKeystoreActivator)),
        _ => None,
    }
}

/// `hsm-keystore` activator — the [`BankActivator`] for the `hsm` component.
///
/// A keystore update is live the moment it is installed (the HSM provision
/// path writes it and reloads the vhsm-ssd proxy), so `activate` has nothing
/// left to do. What it does declare is that activation needs an ECU reset: a
/// new `tls-identity` leaf switches the SOVD server from HTTP to HTTPS, and
/// that transport choice is made once at startup. The server never restarts
/// itself — the tester issues the node restart (`ResetKind::RequiresEcuReset`).
pub struct HsmKeystoreActivator;

impl BankActivator for HsmKeystoreActivator {
    fn activate(&self, _bank_dir: &Path) -> Result<(), BankActivatorError> {
        // The keystore is live once installed.
        Ok(())
    }

    fn reset_kind(&self) -> ResetKind {
        ResetKind::RequiresEcuReset
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build_component, default_slog2_live_dir, ComponentSpec, FactoryDeps};
    use nv_store::block::MemBlockDevice;
    use nv_store::store::{nv_device_size, NvStore};
    use nv_store::types::NvBootState;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// The `hsm` component as a node profile declares it (`single_bank: true`,
    /// slot 0), built through the factory with the `hsm-keystore` activator
    /// wired the way a node binary wires it.
    fn built_hsm() -> crate::BuiltComponent {
        let spec = ComponentSpec {
            id: "hsm".to_string(),
            component_type: "hsm".to_string(),
            rollback: false,
            single_bank: true,
            storage_path: None,
            base_path: None,
            bank_set: None,
            slot: Some(0),
            storage_subdir: None,
            parts: Vec::new(),
            activator: Some("hsm-keystore".into()),
            display_name: None,
            entity_type: None,
            log_agent_url: None,
            host_log_globs: None,
            host_dump_dir: None,
            host_slog2: false,
            host_slog2_segments_dir: None,
            host_slog2_live_dir: default_slog2_live_dir(),
            test_agent_url: None,
            diag_agent_url: None,
            host_diagnostics: false,
            attest_time: false,
            vm_principal: false,
        };

        let mut nv = NvStore::new(MemBlockDevice::new(nv_device_size(10) as usize));
        nv.write_boot_state(&mut NvBootState::default()).unwrap();
        let mut bank_activators: HashMap<String, Arc<dyn BankActivator>> = HashMap::new();
        bank_activators.insert(spec.id.clone(), Arc::new(HsmKeystoreActivator));
        let deps = FactoryDeps {
            nv: Arc::new(Mutex::new(nv)),
            manifest_provider: Arc::new(
                component_mgr::suit_provider::SuitProvider::with_factory_authority(),
            ),
            vm_service_addr: None,
            hsm_provider: None,
            hsm_crypto: None,
            hsm_keystore: None,
            hsm_port: 5100,
            bank_activators,
            partition_parts: HashMap::new(),
            health_probes: HashMap::new(),
            node_boot_id: None,
            deactivators: HashMap::new(),
            boot_selector: None,
            node_coordinator: None,
            post_provision_reload: None,
            wall_clock_floor: None,
        };
        build_component(&spec, &deps).expect("hsm component builds")
    }

    #[test]
    fn hsm_keystore_activation_requires_ecu_reset() {
        let built = built_hsm();
        let flash = built
            .component
            .capabilities()
            .flash
            .clone()
            .expect("hsm is flashable");
        assert_eq!(flash.reset_kind, ResetKind::RequiresEcuReset);
    }

    /// `restart_supported` is `single_bank || vm_service || reset_kind !=
    /// RequiresEcuReset` in component-mgr v0.1.24, so the single-bank hsm still
    /// advertises a component restart — true ONLY because of the `single_bank`
    /// term. The planned sumo-mm v0.1.25 predicate change drops that term and
    /// flips this (and rt) to false; update the assertion with that pin.
    #[test]
    fn hsm_restart_supported_true_only_via_single_bank_in_component_mgr_v0_1_24() {
        let built = built_hsm();
        let diag = built.diag_backend.expect("hsm has a SOVD backend");
        assert!(diag.supports_restart());
    }

    #[test]
    fn builtin_activator_knows_hsm_keystore_and_nothing_else() {
        let hsm = builtin_activator("hsm-keystore").expect("hsm-keystore is built in");
        assert_eq!(hsm.reset_kind(), ResetKind::RequiresEcuReset);
        // Device markers stay the node binary's to wire.
        for marker in ["host-bank", "some-device-loader", "HSM-KEYSTORE", ""] {
            assert!(builtin_activator(marker).is_none(), "{marker}");
        }
    }
}
