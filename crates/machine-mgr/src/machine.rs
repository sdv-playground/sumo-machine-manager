use std::collections::HashMap;
use std::sync::Arc;

use crate::component::Component;
use crate::system_bank_state::{StubSelectorStore, StubSigner, SystemBankManager};
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
    /// The node's single signed, generation-counted boot selector — built on
    /// the production stubs ([`StubSelectorStore`] / [`StubSigner`]) and
    /// `load()`ed at construction.
    ///
    /// TODO: wire component activate()->stage() and campaign commit->seal()/
    /// commit(); additive shadow until the bootloader sector contract lands.
    /// Today this is NOT load-bearing — the existing per-component commit/
    /// rollback (`BankProvider` + `NvBootState`) stays the authority; this
    /// reconstructs alongside so the state machine is exercised + correct when
    /// the selector partition layout exists.
    system_bank: SystemBankManager<StubSelectorStore, StubSigner>,
}

impl MachineRegistry {
    pub fn builder(entity: EntityInfo) -> MachineRegistryBuilder {
        MachineRegistryBuilder {
            entity,
            components: Vec::new(),
        }
    }

    /// Accessor for the node-level system bank selector (see field docs).
    /// Additive shadow — read-only handle for now; mutation seams
    /// (stage/seal/commit/rollback) are wired in a later change once the
    /// bootloader sector contract is real.
    pub fn system_bank(&self) -> &SystemBankManager<StubSelectorStore, StubSigner> {
        &self.system_bank
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

    pub fn build(self) -> MachineRegistry {
        let mut by_id = HashMap::with_capacity(self.components.len());
        for (idx, c) in self.components.iter().enumerate() {
            by_id.insert(c.id().to_string(), idx);
        }
        MachineRegistry {
            entity: self.entity,
            components: self.components,
            by_id,
            system_bank: SystemBankManager::load(StubSelectorStore, StubSigner),
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
        Ok(MachineRegistry {
            entity: self.entity,
            components: self.components,
            by_id,
            system_bank: SystemBankManager::load(StubSelectorStore, StubSigner),
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
