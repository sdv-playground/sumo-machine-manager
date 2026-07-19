//! Unit tests for the `machine-mgr` crate.
//!
//! These tests lock down the trait surface new maintainers will work
//! against: `Component` method defaults (everything `NotSupported` except
//! the two required methods), `MachineRegistry` builder semantics
//! (duplicate-id rejection, lookup, iteration), and wire-format
//! round-trips for the capability descriptors.

use crate::bank_activator::BankActivator;
use crate::component::{Component, DidEntry};
use crate::error::{MachineError, MachineResult};
use crate::machine::{DuplicateComponentId, Machine, MachineRegistry};
use crate::types::{
    Capabilities, Csr, DidFilter, DidKind, DtcFilter, FlashCaps, FlashId, FlashSession, HsmCaps,
    LifecycleCaps, ResetKind, RuntimeState, RuntimeStatus,
};
use crate::EntityInfo;

use std::sync::Arc;

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

/// Minimal `Component` that overrides nothing — exercises the trait defaults.
struct BareComponent {
    id: String,
    caps: Capabilities,
}

#[async_trait::async_trait]
impl Component for BareComponent {
    fn id(&self) -> &str {
        &self.id
    }
    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }
}

fn entity(name: &str) -> EntityInfo {
    EntityInfo {
        id: name.to_string(),
        name: name.to_string(),
        entity_type: "vehicle".to_string(),
        description: None,
        href: format!("/vehicle/v1/{name}"),
        status: None,
    }
}

fn bare(id: &str) -> BareComponent {
    BareComponent {
        id: id.to_string(),
        caps: Capabilities::default(),
    }
}

// ---------------------------------------------------------------------------
// Component trait defaults
// ---------------------------------------------------------------------------

#[tokio::test]
async fn component_defaults_return_not_supported() {
    let c = bare("vm1");
    let id = FlashId::new("x");

    // DID store
    assert!(matches!(
        c.list_dids(&DidFilter::default()).await,
        Err(MachineError::NotSupported(_))
    ));
    assert!(matches!(
        c.read_did(0x1234, DidKind::Runtime).await,
        Err(MachineError::NotSupported(_))
    ));
    assert!(matches!(
        c.write_did(0x1234, DidKind::Runtime, b"x").await,
        Err(MachineError::NotSupported(_))
    ));

    // Install pipeline
    assert!(matches!(
        c.start_install().await,
        Err(MachineError::NotSupported(_))
    ));
    let empty_stream: crate::types::EnvelopeStream = Box::pin(futures::stream::empty());
    assert!(matches!(
        c.upload_envelope(&id, empty_stream).await,
        Err(MachineError::NotSupported(_))
    ));
    assert!(matches!(
        c.finalize_install(&id).await,
        Err(MachineError::NotSupported(_))
    ));
    assert!(matches!(
        c.commit_install(&id).await,
        Err(MachineError::NotSupported(_))
    ));
    assert!(matches!(
        c.rollback_install(&id).await,
        Err(MachineError::NotSupported(_))
    ));
    assert!(matches!(
        c.abort_install(&id).await,
        Err(MachineError::NotSupported(_))
    ));

    // Admin state — the default IS "cannot be disabled" (no deactivator);
    // the SOVD op maps it to 400.
    assert!(matches!(
        c.set_admin_state(true).await,
        Err(MachineError::NotSupported(_))
    ));
    assert!(matches!(
        c.set_admin_state(false).await,
        Err(MachineError::NotSupported(_))
    ));

    // Activation — returns Ok(None), not NotSupported (component has no concept)
    assert!(matches!(c.activation_state().await, Ok(None)));

    // Lifecycle
    assert!(matches!(
        c.restart().await,
        Err(MachineError::NotSupported(_))
    ));
    assert!(matches!(
        c.runtime_state().await,
        Err(MachineError::NotSupported(_))
    ));

    // HSM
    assert!(matches!(
        c.get_csr("device-decrypt").await,
        Err(MachineError::NotSupported(_))
    ));
    assert!(matches!(
        c.install_keys(b"envelope").await,
        Err(MachineError::NotSupported(_))
    ));

    // DTCs
    assert!(matches!(
        c.read_dtcs(&DtcFilter::default()).await,
        Err(MachineError::NotSupported(_))
    ));
    assert!(matches!(
        c.clear_dtcs(None).await,
        Err(MachineError::NotSupported(_))
    ));
}

#[tokio::test]
async fn component_overrides_take_precedence() {
    // If a component overrides a default, that method should work.
    struct RestartComp {
        id: String,
        caps: Capabilities,
    }
    #[async_trait::async_trait]
    impl Component for RestartComp {
        fn id(&self) -> &str {
            &self.id
        }
        fn capabilities(&self) -> &Capabilities {
            &self.caps
        }
        async fn restart(&self) -> MachineResult<()> {
            Ok(())
        }
    }

    let c = RestartComp {
        id: "vm1".into(),
        caps: Capabilities::default(),
    };
    assert!(c.restart().await.is_ok());
    // But unchanged defaults still surface:
    assert!(matches!(
        c.get_csr("device-decrypt").await,
        Err(MachineError::NotSupported(_))
    ));
}

// ---------------------------------------------------------------------------
// MachineRegistry builder
// ---------------------------------------------------------------------------

#[test]
fn registry_build_preserves_component_order() {
    let m = MachineRegistry::builder(entity("veh"))
        .with(bare("host"))
        .with(bare("vm1"))
        .with(bare("vm2"))
        .build();

    let ids: Vec<&str> = m.components().iter().map(|c| c.id()).collect();
    assert_eq!(ids, ["host", "vm1", "vm2"]);
}

#[test]
fn registry_component_lookup_by_id() {
    let m = MachineRegistry::builder(entity("veh"))
        .with(bare("host"))
        .with(bare("vm1"))
        .build();

    assert_eq!(m.component("host").unwrap().id(), "host");
    assert_eq!(m.component("vm1").unwrap().id(), "vm1");
    assert!(m.component("nope").is_none());
}

#[test]
fn registry_entity_accessor_returns_whats_provided() {
    let e = entity("my-vehicle");
    let m = MachineRegistry::builder(e.clone()).build();
    assert_eq!(m.entity().id, e.id);
    assert_eq!(m.entity().name, e.name);
}

#[test]
fn registry_try_build_detects_duplicate_ids() {
    let result = MachineRegistry::builder(entity("veh"))
        .with(bare("host"))
        .with(bare("vm1"))
        .with(bare("host")) // duplicate
        .try_build();
    let err = result.err().expect("duplicate should fail");
    assert_eq!(err.0, "host");
}

#[test]
fn registry_try_build_succeeds_with_unique_ids() {
    let m = MachineRegistry::builder(entity("veh"))
        .with(bare("host"))
        .with(bare("vm1"))
        .with(bare("vm2"))
        .with(bare("hsm"))
        .try_build()
        .expect("unique ids");
    assert_eq!(m.components().len(), 4);
}

#[test]
fn registry_with_arc_accepts_prebuilt_arcs() {
    let comp: Arc<dyn Component> = Arc::new(bare("vm1"));
    let m = MachineRegistry::builder(entity("veh"))
        .with_arc(comp)
        .build();
    assert_eq!(m.components().len(), 1);
    assert_eq!(m.component("vm1").unwrap().id(), "vm1");
}

#[test]
fn seed_selector_writes_on_first_seed_and_is_idempotent() {
    use crate::system_bank_state::{InMemorySelectorStore, SelectorStore, TestSigner};
    use nv_store::types::{Bank, BankSet};

    // A real two-slot store we can inspect after seeding.
    let store = InMemorySelectorStore::new();
    let mut m = MachineRegistry::builder(entity("veh"))
        .with_selector_store(Box::new(store.clone()), Box::new(TestSigner))
        .build();

    // Selector starts empty (no PRIMARY blob, generation 0). Read through a
    // short-lived lock on the now-shared (Arc<RwLock>) manager.
    assert!(store.read_primary().is_none());
    assert!(store.read_secondary().is_none());
    assert_eq!(m.system_bank().read().unwrap().generation(), 0);

    // First seed of an empty selector: both entries differ from the (absent)
    // PRIMARY view, so both are staged and a single seal promotes them.
    let entries = vec![(BankSet::Vm1, Bank::B), (BankSet::Vm2, Bank::A)];
    m.seed_selector(entries.clone());

    // The selector now mirrors the seed and the store's PRIMARY slot was
    // written with both entries at generation 1. Active-bank reads also go via
    // the read-only `boot_selector()` view to exercise that handle.
    let sel = m.boot_selector();
    assert_eq!(sel.active_bank(BankSet::Vm1), Some(Bank::B));
    assert_eq!(sel.active_bank(BankSet::Vm2), Some(Bank::A));
    assert_eq!(
        m.system_bank().read().unwrap().generation(),
        1,
        "one seal => generation 1"
    );
    let primary = store.read_primary().expect("PRIMARY written by the seed");
    assert_eq!(primary.generation, 1);
    assert_eq!(primary.selectors.get(&BankSet::Vm1), Some(&Bank::B));
    assert_eq!(primary.selectors.get(&BankSet::Vm2), Some(&Bank::A));

    // The seed commits too, so SECONDARY is written equal to PRIMARY — the
    // not-in-trial baseline (PRIMARY == SECONDARY).
    let secondary = store
        .read_secondary()
        .expect("SECONDARY written by the seed's commit");
    assert_eq!(secondary.generation, 1);
    assert_eq!(secondary.selectors, primary.selectors);
    assert!(!sel.is_trial(), "seed leaves the node not-in-trial");

    // Second identical seed: every entry already matches PRIMARY, so nothing
    // is staged and seal is NOT called — the generation must not inflate.
    m.seed_selector(entries);
    assert_eq!(
        m.system_bank().read().unwrap().generation(),
        1,
        "idempotent re-seed must not bump the generation"
    );
    assert_eq!(
        store.read_primary().map(|b| b.generation),
        Some(1),
        "no second PRIMARY write on an idempotent re-seed"
    );
}

#[test]
fn registry_build_accepts_zero_components() {
    let m = MachineRegistry::builder(entity("empty")).build();
    assert!(m.components().is_empty());
    assert!(m.component("anything").is_none());
}

#[test]
fn coordinator_owns_staging_across_gate_calls() {
    use crate::node_update::{Admit, Durable, NodeCoordinator, NodePhase};
    let c = NodeCoordinator::new(vec![(4, "vm1".to_string()), (5, "vm2".to_string())]);
    let id_a: [u8; 32] = [1; 32];
    let idle = Durable::default();

    // First component opens the transaction; a sibling with the SAME id joins it
    // — the coordinator persists the Staging session between calls.
    assert_eq!(
        c.gate_new_session(id_a, "vm1", &idle, &[]).unwrap(),
        Admit::OpenedNew
    );
    assert_eq!(
        c.gate_new_session(id_a, "vm2", &idle, &[]).unwrap(),
        Admit::Joined
    );
    let st = c.node_update_state(&idle, &[]);
    assert_eq!(st.phase, NodePhase::Staging);
    assert_eq!(st.components, vec!["vm1".to_string(), "vm2".to_string()]);

    // A DIFFERENT id is refused (would mix updates); the open session is untouched.
    assert!(c.gate_new_session([9; 32], "vm3", &idle, &[]).is_err());
    assert_eq!(c.node_update_state(&idle, &[]).components.len(), 2);

    // Promoting staging (reboot issued) clears it → back to Idle.
    assert!(c.take_staging().is_some());
    assert_eq!(c.node_update_state(&idle, &[]).phase, NodePhase::Idle);
}

#[test]
fn coordinator_names_and_removes_from_staging() {
    use crate::node_update::{Durable, NodeCoordinator, NodePhase};
    let c = NodeCoordinator::new(vec![(4, "vm1".to_string()), (5, "vm2".to_string())]);
    // label: known index → name; unknown → fallback.
    assert_eq!(c.label(4), "vm1");
    assert_eq!(c.label(9), "bank-set 9");

    // remove_from_staging drops a component as its flash resolves, and clears the
    // session when the last leaves → back to Idle (no stale Staging).
    let id: [u8; 32] = [1; 32];
    let idle = Durable::default();
    c.gate_new_session(id, "vm1", &idle, &[]).unwrap();
    c.gate_new_session(id, "vm2", &idle, &[]).unwrap();
    c.remove_from_staging("vm1");
    assert_eq!(
        c.node_update_state(&idle, &[]).components,
        vec!["vm2".to_string()]
    );
    c.remove_from_staging("vm2");
    assert_eq!(c.node_update_state(&idle, &[]).phase, NodePhase::Idle);
}

// ---------------------------------------------------------------------------
// Types — basic sanity + round-trips
// ---------------------------------------------------------------------------

#[test]
fn flash_id_display_and_as_str_match() {
    let id = FlashId::new("transfer-42");
    assert_eq!(id.as_str(), "transfer-42");
    assert_eq!(format!("{id}"), "transfer-42");
    assert_eq!(id.0, "transfer-42");
}

#[test]
fn flash_id_equality_and_hash() {
    use std::collections::HashMap;
    let a = FlashId::new("x");
    let b = FlashId::new("x");
    assert_eq!(a, b);

    let mut m = HashMap::new();
    m.insert(a, "session-x");
    assert_eq!(m.get(&b), Some(&"session-x"));
}

#[test]
fn capabilities_default_is_all_off() {
    let c = Capabilities::default();
    assert!(!c.did_store);
    assert!(c.flash.is_none());
    assert!(c.lifecycle.is_none());
    assert!(c.hsm.is_none());
    assert!(!c.dtcs);
    assert!(!c.clear_dtcs);
}

#[test]
fn capabilities_json_roundtrip() {
    let c = Capabilities {
        did_store: true,
        flash: Some(FlashCaps {
            dual_bank: true,
            supports_rollback: true,
            supports_trial_boot: true,
            abortable_after_finalize: false,
            reset_kind: ResetKind::Local,
        }),
        lifecycle: Some(LifecycleCaps {
            restartable: true,
            has_runtime_state: false,
        }),
        hsm: Some(HsmCaps {
            supports_csr: true,
            supports_key_install: false,
        }),
        dtcs: true,
        clear_dtcs: true,
    };
    let json = serde_json::to_string(&c).unwrap();
    let back: Capabilities = serde_json::from_str(&json).unwrap();
    assert_eq!(back.did_store, c.did_store);
    assert_eq!(back.flash.as_ref().map(|f| f.dual_bank), Some(true));
    assert_eq!(back.hsm.as_ref().map(|h| h.supports_csr), Some(true));
}

// ---------------------------------------------------------------------------
// ResetKind — capability declared by BankActivator implementations,
// surfaced via FlashCaps so the orchestrator can coalesce per-component
// restarts into one ECU-level reboot when required.
// See tasks/reset-kind-and-status-restart.md (Phase 1).
// ---------------------------------------------------------------------------

#[test]
fn reset_kind_defaults_to_local() {
    // Both the enum's Default and the BankActivator trait default land on Local.
    assert_eq!(ResetKind::default(), ResetKind::Local);

    struct DefaultActivator;
    impl crate::bank_activator::BankActivator for DefaultActivator {
        fn activate(
            &self,
            _: &std::path::Path,
        ) -> Result<(), crate::bank_activator::BankActivatorError> {
            Ok(())
        }
        // No reset_kind override — should fall back to Local.
    }
    let a = DefaultActivator;
    assert_eq!(a.reset_kind(), ResetKind::Local);
}

#[test]
fn reset_kind_override_is_honoured() {
    struct EcuResetActivator;
    impl crate::bank_activator::BankActivator for EcuResetActivator {
        fn activate(
            &self,
            _: &std::path::Path,
        ) -> Result<(), crate::bank_activator::BankActivatorError> {
            Ok(())
        }
        fn reset_kind(&self) -> ResetKind {
            ResetKind::RequiresEcuReset
        }
    }
    let a = EcuResetActivator;
    assert_eq!(a.reset_kind(), ResetKind::RequiresEcuReset);
}

#[test]
fn reset_kind_serializes_snake_case() {
    // Wire-visible names — orchestrator parses these. Lock them down.
    assert_eq!(serde_json::to_string(&ResetKind::None).unwrap(), "\"none\"");
    assert_eq!(
        serde_json::to_string(&ResetKind::Local).unwrap(),
        "\"local\""
    );
    assert_eq!(
        serde_json::to_string(&ResetKind::RequiresEcuReset).unwrap(),
        "\"requires_ecu_reset\""
    );
}

#[test]
fn flash_caps_reset_kind_round_trips() {
    // Verify reset_kind survives JSON round-trip on FlashCaps.
    let caps = FlashCaps {
        dual_bank: true,
        supports_rollback: true,
        supports_trial_boot: true,
        abortable_after_finalize: false,
        reset_kind: ResetKind::RequiresEcuReset,
    };
    let json = serde_json::to_string(&caps).unwrap();
    let back: FlashCaps = serde_json::from_str(&json).unwrap();
    assert_eq!(back.reset_kind, ResetKind::RequiresEcuReset);
}

#[test]
fn flash_caps_reset_kind_defaults_for_old_payloads() {
    // Pre-Phase-1 JSON (no reset_kind field) must still deserialise — the
    // #[serde(default)] attribute keeps callers using older wire formats
    // working, defaulting to Local which matches their actual behaviour
    // before the field existed.
    let legacy_json = r#"{
        "dual_bank": true,
        "supports_rollback": true,
        "supports_trial_boot": true,
        "abortable_after_finalize": false
    }"#;
    let caps: FlashCaps = serde_json::from_str(legacy_json).unwrap();
    assert_eq!(caps.reset_kind, ResetKind::Local);
}

#[test]
fn capabilities_serialization_omits_none_optionals() {
    // When flash/lifecycle/hsm are None, the JSON should not include null
    // fields — the wire stays compact.
    let c = Capabilities::default();
    let json = serde_json::to_string(&c).unwrap();
    // Defaults serialize the Option fields as null (serde default), so just
    // verify the shape parses back cleanly.
    let back: Capabilities = serde_json::from_str(&json).unwrap();
    assert!(back.flash.is_none());
    assert!(back.lifecycle.is_none());
    assert!(back.hsm.is_none());
}

#[test]
fn runtime_state_serialization() {
    let rs = RuntimeState {
        status: RuntimeStatus::Running,
        detail: serde_json::json!({"uptime": 42, "fw": "1.0"}),
    };
    let json = serde_json::to_string(&rs).unwrap();
    // snake_case per #[serde(rename_all = "snake_case")] on RuntimeStatus
    assert!(json.contains("\"running\""));
    assert!(json.contains("\"uptime\":42"));
    let back: RuntimeState = serde_json::from_str(&json).unwrap();
    assert_eq!(back.status, RuntimeStatus::Running);
}

#[test]
fn runtime_status_all_snake_case() {
    // Ensure every variant round-trips without surprise casing.
    for s in [
        RuntimeStatus::Running,
        RuntimeStatus::Stopped,
        RuntimeStatus::Booting,
        RuntimeStatus::Faulted,
        RuntimeStatus::Unknown,
    ] {
        let j = serde_json::to_string(&s).unwrap();
        let back: RuntimeStatus = serde_json::from_str(&j).unwrap();
        assert_eq!(back, s);
    }
}

#[test]
fn flash_session_serialization() {
    let s = FlashSession {
        id: FlashId::new("abc"),
        target_bank: Some("b".into()),
        max_chunk_size: 4096,
    };
    let j = serde_json::to_string(&s).unwrap();
    let back: FlashSession = serde_json::from_str(&j).unwrap();
    assert_eq!(back.id, s.id);
    assert_eq!(back.target_bank, s.target_bank);
    assert_eq!(back.max_chunk_size, s.max_chunk_size);
}

#[test]
fn did_entry_construction() {
    let e = DidEntry {
        key: 0xF18C,
        kind: DidKind::Factory,
        id: "serial_number".into(),
        name: "Serial Number".into(),
        writable: false,
    };
    assert_eq!(e.key, 0xF18C);
    assert_eq!(e.id, "serial_number");
    assert!(!e.writable);
}

#[test]
fn csr_wraps_bytes() {
    let c = Csr::from_bytes(vec![0x30, 0x82, 0x01]);
    assert_eq!(c.as_bytes(), &[0x30, 0x82, 0x01]);
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[test]
fn machine_error_display_covers_all_variants() {
    // Each variant should format without panicking and include a
    // human-recognizable keyword.
    let cases = [
        (MachineError::NotSupported("op"), "not supported"),
        (MachineError::NotFound("comp".into()), "not found"),
        (MachineError::InvalidArgument("arg".into()), "invalid"),
        (MachineError::PolicyRejected("pol".into()), "policy"),
        (MachineError::ManifestInvalid("m".into()), "manifest"),
        (
            MachineError::UnknownFlashSession("s".into()),
            "flash session",
        ),
        (MachineError::Storage("disk".into()), "storage"),
        (MachineError::Internal("boom".into()), "internal"),
    ];
    for (err, needle) in cases {
        let s = err.to_string().to_lowercase();
        assert!(
            s.contains(needle),
            "Display of {err:?} should mention '{needle}', got '{s}'"
        );
    }
}

#[test]
fn machine_error_is_std_error() {
    // Sanity: `?` composition requires `std::error::Error` impl.
    fn take_err<E: std::error::Error>(_: E) {}
    take_err(MachineError::Internal("x".into()));
}

// ---------------------------------------------------------------------------
// Duplicate id error
// ---------------------------------------------------------------------------

#[test]
fn duplicate_component_id_error_display() {
    let e = DuplicateComponentId("host".into());
    assert!(e.to_string().contains("host"));
}
