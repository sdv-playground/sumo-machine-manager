use std::collections::HashMap;
use std::sync::Arc;

use nv_store::types::{Bank, BankSet};

use crate::component::Component;
use crate::system_bank_state::{
    SelectorStore, Signer, StubSelectorStore, StubSigner, SystemBankManager,
};
use crate::EntityInfo;

/// The top-level machine: an `EntityInfo` (vehicle-level identity) plus a
/// registry of `Component` objects.
///
/// `diagserver` holds an `Arc<dyn Machine>` and routes SOVD requests by
/// `/components/{id}` to `machine.component(id)`.
pub trait Machine: Send + Sync {
    /// Vehicle-level identity (VIN, serial, name).
    fn entity(&self) -> &EntityInfo;

    /// All registered components, in declaration order.
    fn components(&self) -> &[Arc<dyn Component>];

    /// Look up a component by id.
    fn component(&self, id: &str) -> Option<&Arc<dyn Component>>;
}

/// Default `Machine` implementation backed by an in-memory registry.
///
/// Composition pattern (in `vm-sovd`'s `main`):
///
/// ```ignore
/// let machine = MachineRegistry::builder(entity_info)
///     .with(HostComponent::real(...))
///     .with(VmComponent::real("vm1", ...))
///     .with(VmComponent::real("vm2", ...))
///     .with(HsmComponent::real(...))
///     .build();
/// ```
pub struct MachineRegistry {
    entity: EntityInfo,
    components: Vec<Arc<dyn Component>>,
    by_id: HashMap<String, usize>,
    /// The node's single signed, generation-counted boot selector. The store +
    /// signer are chosen at construction (see
    /// [`with_selector_store`](MachineRegistryBuilder::with_selector_store)):
    /// the default is the loud production stubs
    /// ([`StubSelectorStore`] / [`StubSigner`]); supernova-mm swaps in a
    /// file-backed store on the host/sim.
    ///
    /// TODO: wire component activate()->stage() and campaign commit->seal()/
    /// commit(); additive shadow until the bootloader sector contract lands.
    /// Today this is NOT load-bearing — the existing per-component commit/
    /// rollback (`BankProvider` + `NvBootState`) stays the authority; this
    /// reconstructs alongside so the state machine is exercised + correct when
    /// the selector partition layout exists.
    system_bank: SystemBankManager,
}

impl MachineRegistry {
    pub fn builder(entity: EntityInfo) -> MachineRegistryBuilder {
        MachineRegistryBuilder {
            entity,
            components: Vec::new(),
            selector_store: None,
            signer: None,
        }
    }

    /// Accessor for the node-level system bank selector (see field docs).
    /// Additive shadow — read-only handle for now; mutation seams
    /// (stage/seal/commit/rollback) are wired in a later change once the
    /// bootloader sector contract is real.
    pub fn system_bank(&self) -> &SystemBankManager {
        &self.system_bank
    }

    /// Seed the boot selector from the node's per-bank-set boot state so the
    /// selector's PRIMARY slot mirrors reality on startup.
    ///
    /// For each `(set, bank)` entry, this stages the selection **only when it
    /// differs** from the selector's current PRIMARY view; after the loop, it
    /// seals **once** iff anything was staged.
    ///
    /// **Idempotent on purpose**: when the selector already matches the
    /// supplied entries (the steady-state case on every boot), nothing is
    /// staged and `seal` is *not* called — so the global generation does not
    /// inflate on every startup. It only advances when the boot state actually
    /// changed (e.g. after an OTA bank flip) and the selector needs to catch
    /// up.
    ///
    /// Additive: this is a read-only mirror of `NvBootState` into the selector
    /// — it does not make the selector the boot authority. Nothing consults the
    /// selector for a boot/bank decision.
    pub fn seed_selector(&mut self, entries: impl IntoIterator<Item = (BankSet, Bank)>) {
        let mut staged_any = false;
        for (set, bank) in entries {
            if self.system_bank.active_bank(set) != Some(bank) {
                self.system_bank.stage(set, bank);
                staged_any = true;
            }
        }
        if staged_any {
            // seal writes PRIMARY; commit copies it to SECONDARY so both slots
            // exist and are equal — the not-in-trial baseline (PRIMARY ==
            // SECONDARY). A real trial (the two diverging) only arises later
            // from an OTA stage/seal, not from this mirror seed.
            self.system_bank.seal();
            self.system_bank.commit();
        }
    }
}

impl Machine for MachineRegistry {
    fn entity(&self) -> &EntityInfo {
        &self.entity
    }

    fn components(&self) -> &[Arc<dyn Component>] {
        &self.components
    }

    fn component(&self, id: &str) -> Option<&Arc<dyn Component>> {
        let idx = *self.by_id.get(id)?;
        self.components.get(idx)
    }
}

pub struct MachineRegistryBuilder {
    entity: EntityInfo,
    components: Vec<Arc<dyn Component>>,
    /// Optional override for the boot-selector persistence + signing seams.
    /// `None` falls back to the loud production stubs at build time.
    selector_store: Option<Box<dyn SelectorStore>>,
    signer: Option<Box<dyn Signer>>,
}

impl MachineRegistryBuilder {
    /// Register a component. Order is preserved; later registrations with the
    /// same id silently shadow earlier ones in `component(id)` lookups (build
    /// will panic if you really want a check — see `try_build`).
    pub fn with<C: Component + 'static>(mut self, component: C) -> Self {
        self.components.push(Arc::new(component));
        self
    }

    /// Like `with` but takes an already-allocated `Arc`.
    pub fn with_arc(mut self, component: Arc<dyn Component>) -> Self {
        self.components.push(component);
        self
    }

    /// Override the boot-selector persistence + signing seams. The host/sim
    /// build passes a file-backed [`FileSelectorStore`](crate::system_bank_state::FileSelectorStore)
    /// (still with [`StubSigner`] until HSM signing is wired) so the selector
    /// vector survives restarts; when omitted, `build` falls back to the loud
    /// stubs. Additive — the boot authority is still `NvBootState`.
    pub fn with_selector_store(
        mut self,
        store: Box<dyn SelectorStore>,
        signer: Box<dyn Signer>,
    ) -> Self {
        self.selector_store = Some(store);
        self.signer = Some(signer);
        self
    }

    pub fn build(self) -> MachineRegistry {
        let mut by_id = HashMap::with_capacity(self.components.len());
        for (idx, c) in self.components.iter().enumerate() {
            by_id.insert(c.id().to_string(), idx);
        }
        let system_bank = SystemBankManager::load(
            self.selector_store
                .unwrap_or_else(|| Box::new(StubSelectorStore)),
            self.signer.unwrap_or_else(|| Box::new(StubSigner)),
        );
        MachineRegistry {
            entity: self.entity,
            components: self.components,
            by_id,
            system_bank,
        }
    }

    /// Like `build` but returns an error if any two components share an id.
    pub fn try_build(self) -> Result<MachineRegistry, DuplicateComponentId> {
        let mut by_id = HashMap::with_capacity(self.components.len());
        for (idx, c) in self.components.iter().enumerate() {
            let id = c.id().to_string();
            if by_id.contains_key(&id) {
                return Err(DuplicateComponentId(id));
            }
            by_id.insert(id, idx);
        }
        let system_bank = SystemBankManager::load(
            self.selector_store
                .unwrap_or_else(|| Box::new(StubSelectorStore)),
            self.signer.unwrap_or_else(|| Box::new(StubSigner)),
        );
        Ok(MachineRegistry {
            entity: self.entity,
            components: self.components,
            by_id,
            system_bank,
        })
    }
}

#[derive(Debug)]
pub struct DuplicateComponentId(pub String);

impl std::fmt::Display for DuplicateComponentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "duplicate component id: {}", self.0)
    }
}

impl std::error::Error for DuplicateComponentId {}
