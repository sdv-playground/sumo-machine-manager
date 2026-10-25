use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

use nv_store::types::BankBootState;

use crate::component::Component;
use crate::node_update::NodeCoordinator;
use crate::system_bank_state::{
    BootObservation, BootSelector, Reason, SelectorError, SelectorStore, SharedSystemBankState,
    StubSelectorStore, SystemBankManager,
};
use crate::{EntityInfo, FlashId};

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

    /// The node's boot vector, if this machine holds one.
    fn system_bank(&self) -> Option<&SharedSystemBankState> {
        None
    }
}

/// What [`MachineRegistry::observe_node_boot`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeBootOutcome {
    /// The trial boot count after this boot; `None` when no trial is armed
    /// (or the count could not be read or written).
    pub trial_boots: Option<u8>,
    /// The coordinator's trial boot limit (`None` = disabled).
    pub limit: Option<u8>,
    /// Whether the node rolled itself back through the boot vector.
    pub bailed_out: bool,
    /// Per-component rollback failures after the bail-out: (component id,
    /// error).
    pub errors: Vec<(String, String)>,
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
///     .build()?;
/// ```
pub struct MachineRegistry {
    entity: EntityInfo,
    components: Vec<Arc<dyn Component>>,
    by_id: HashMap<String, usize>,
    /// The node's single signed, generation-counted boot selector. The store
    /// is chosen at construction (see
    /// [`with_selector_store`](MachineRegistryBuilder::with_selector_store)):
    /// the default is the loud production stub
    /// ([`StubSelectorStore`]); the host machine manager swaps in a
    /// file-backed store on the host/sim.
    ///
    /// TODO: wire component activate()->stage() and campaign commit->seal()/
    /// commit(); additive shadow until the bootloader sector contract lands.
    /// Today this is NOT load-bearing — the existing per-component commit/
    /// rollback (`BankProvider` + `NvBootState`) stays the authority; this
    /// reconstructs alongside so the state machine is exercised + correct when
    /// the selector partition layout exists.
    ///
    /// Held as a [`SharedSystemBankState`] (`Arc<RwLock<…>>`) so later pieces
    /// can hand cheap clones to many readers — a read-only [`BootSelector`]
    /// view ([`boot_selector`](Self::boot_selector)) to consumers and the raw
    /// write handle ([`shared_selector`](Self::shared_selector)) to the
    /// seed/OTA path — without each holding its own copy of the manager.
    system_bank: SharedSystemBankState,
}

impl MachineRegistry {
    pub fn builder(entity: EntityInfo) -> MachineRegistryBuilder {
        MachineRegistryBuilder {
            entity,
            components: Vec::new(),
            selector_store: None,
            shared_selector: None,
        }
    }

    /// The shared boot-selector handle (see field docs). Clone of the `Arc`;
    /// callers take a short-lived `.read()`/`.write()` lock. Prefer
    /// [`boot_selector`](Self::boot_selector) for read-only access and
    /// [`shared_selector`](Self::shared_selector) for the write/seed path —
    /// this raw accessor exists for tests and call sites that need the manager
    /// directly.
    pub fn system_bank(&self) -> &SharedSystemBankState {
        &self.system_bank
    }

    /// A cheap, cloneable **read-only** view of the boot selector for future
    /// readers (vm-service, the providers). Additive — holding it does not
    /// flip any reader onto the selector for a boot/bank decision.
    pub fn boot_selector(&self) -> BootSelector {
        BootSelector::new(Arc::clone(&self.system_bank))
    }

    /// The shared **write** handle to the boot selector, for the OTA/seed path
    /// that mutates it (`stage`/`seal`/`commit`/`rollback`). Clone of the
    /// `Arc`; the caller takes a `.write()` lock.
    pub fn shared_selector(&self) -> SharedSystemBankState {
        Arc::clone(&self.system_bank)
    }

    /// Seed the boot selector from the node's per-bank-set boot state so the
    /// selector mirrors reality on startup. Each entry is `(component id, its
    /// slot's NV boot state)`; the selector is staged by component id. PRIMARY boots each set's NV
    /// `active_bank`, and SECONDARY (the rollback floor) holds each set's
    /// COMMITTED bank — `active_bank` itself for a committed set,
    /// `active_bank.other()` for a set NV holds in trial (`committed ==
    /// false`), so a trial survives the reseed as a trial over its floor.
    ///
    /// The seed runs **only when some entry's `active_bank` differs** from the
    /// selector's current PRIMARY view. On an empty vector it stages every set's floor, seals
    /// and commits (PRIMARY == SECONDARY == floor), and — iff any set is in
    /// trial — stages those sets' active banks and seals again, which arms the
    /// trial exactly as an OTA does: PRIMARY ahead of the committed floor.
    ///
    /// Every entry is staged with **no images**: NV records banks, not what was
    /// sealed into them, so a reseed has no sealed facts to carry. The next
    /// install of a component fills its images in.
    ///
    /// **Idempotent on purpose**: when the selector already matches the
    /// supplied entries (the steady-state case on every boot), nothing is
    /// staged and `seal` is *not* called — so the global generation does not
    /// inflate on every startup. It only advances when the selector is empty
    /// or lacks an entry.
    ///
    /// A **non-empty** vector is never restaged as a whole: only the ids with
    /// no entry ([`SystemBankManager::missing_entries`]) are added, at their NV
    /// floor with no images, over the booted selection — the existing entries
    /// and their sealed images are untouched — then committed, and the NV
    /// trials among them re-sealed. Nothing missing writes nothing. While a
    /// trial stands nothing is written either (a commit would settle the
    /// trial without a verdict): the missing ids are seeded after the verdict.
    ///
    /// A vector with no committed copy is not a trial the node can resolve by
    /// rollback: the seed anchors it by committing what stands, adding any
    /// missing ids first — the ordinary sequence over the missing ids
    /// (possibly none), with no trial guard and even when every id matches NV,
    /// so a missing id NV holds in trial is re-armed over the new floor.
    ///
    /// The selector, not `NvBootState`, is the boot / VM-launch authority; this
    /// only gives it a starting selection. The host machine managers call it at
    /// startup when the selector is empty — a fresh node, a factory reset, or a
    /// copy that failed the store's check (read as absent by
    /// [`SystemBankManager::load`]; a record that could not be read fails the
    /// load and is never seeded) — or when some id has no entry (a vector
    /// holding the boot stage's rows but no manager rows).
    ///
    /// A failed selector write is returned as `Err`; the in-memory selector
    /// then holds whatever the last successful write left.
    pub fn seed_selector<'a>(
        &mut self,
        entries: impl IntoIterator<Item = (&'a str, &'a BankBootState)>,
    ) -> Result<(), SelectorError> {
        // One write lock for the whole seed: the compare and the stage/seal/
        // commit sequence must see a consistent view of the selector.
        let mut sb = self.system_bank.write().expect("selector poisoned");
        let mut entries: Vec<(&str, &BankBootState)> = entries.into_iter().collect();
        // No committed copy: not a trial the node can resolve by rollback.
        // The seed anchors it — the missing ids (possibly none) through the
        // ordinary sequence — whatever NV says and whatever stands.
        let unanchored = !sb.is_empty() && sb.committed_generation() == 0;
        if !unanchored
            && entries
                .iter()
                .all(|(id, nv)| sb.active_bank(id) == Some(nv.active_bank))
        {
            return Ok(());
        }
        if !sb.is_empty() {
            let missing = sb.missing_entries(entries.iter().map(|(id, _)| *id));
            if !unanchored {
                if missing.is_empty() {
                    return Ok(());
                }
                if sb.is_trial() {
                    tracing::warn!(
                        missing = ?missing,
                        "boot-vector: {} components have no entry while a trial stands; seeded after the verdict",
                        missing.len()
                    );
                    return Ok(());
                }
            }
            entries.retain(|(id, _)| missing.iter().any(|m| m == id));
        }
        for (id, nv) in &entries {
            let floor = if nv.committed {
                nv.active_bank
            } else {
                nv.active_bank.other()
            };
            sb.stage(id, floor, BTreeMap::new());
        }
        // A no-op when nothing is staged (an anchor with no id missing).
        sb.seal(None)?;
        sb.commit()?;
        for (id, nv) in entries.iter().filter(|(_, nv)| !nv.committed) {
            sb.stage(id, nv.active_bank, BTreeMap::new());
        }
        // A no-op when nothing is in trial: `seal` needs something staged.
        sb.seal(None)?;
        Ok(())
    }

    /// Count this node boot against the armed trial and, once the count
    /// reaches `coord`'s trial boot limit, roll the whole node back.
    ///
    /// This is the node's **one bounded autonomous act**: after the
    /// host-configured number of distinct node boots while armed without a
    /// verdict, the node takes the same rollback path a rollback verdict takes
    /// — the boot vector first (the authority, its header recording
    /// `trial_boot_limit` as the reason), then each component that was in trial
    /// rolls back its own NV. The node never commits by itself. Counting is
    /// per distinct boot id, so a process restart within one boot counts
    /// nothing; a failed count or a failed boot-vector rollback logs and is
    /// retried on the next boot.
    ///
    /// The host calls this once after the store is loaded and before serving,
    /// and sets the limit below its boot stage's own bound so the node, not
    /// the boot stage, settles the trial. No boot id or no limit: counts (or
    /// not) and never rolls back.
    pub async fn observe_node_boot(&self, coord: &NodeCoordinator) -> NodeBootOutcome {
        let limit = coord.trial_boot_limit();
        let mut out = NodeBootOutcome {
            trial_boots: None,
            limit,
            bailed_out: false,
            errors: Vec::new(),
        };
        let Some(boot_id) = coord.node_boot_id() else {
            return out;
        };
        let observed = self
            .system_bank
            .write()
            .expect("selector poisoned")
            .observe_node_boot(boot_id);
        let trial_boots = match observed {
            Ok(BootObservation::NotArmed) => return out,
            Ok(
                BootObservation::AlreadyCounted { trial_boots }
                | BootObservation::Counted { trial_boots },
            ) => trial_boots,
            Err(e) => {
                tracing::warn!(error = %e, "trial boot not counted — retried next boot");
                return out;
            }
        };
        out.trial_boots = Some(trial_boots);
        if limit.is_none_or(|l| trial_boots < l) {
            return out;
        }

        // The in-trial set is taken BEFORE the boot-vector rollback: afterwards
        // the vector no longer names anyone in trial.
        let in_trial: Vec<Arc<dyn Component>> = self
            .components
            .iter()
            .filter(|c| c.banks().is_some_and(|b| b.in_trial))
            .cloned()
            .collect();
        {
            let mut sb = self.system_bank.write().expect("selector poisoned");
            if !sb.is_trial() {
                return out;
            }
            if let Err(e) = sb.rollback(Reason::TrialBootLimit) {
                tracing::warn!(error = %e, "trial boot limit reached but boot-vector rollback failed — retried next boot");
                return out;
            }
        }
        out.bailed_out = true;
        tracing::warn!(
            trial_boots,
            limit = ?limit,
            components = ?in_trial.iter().map(|c| c.id()).collect::<Vec<_>>(),
            "trial boot limit reached without a verdict — node rolled back"
        );
        // The advisory FlashId, as the node rollback verdict passes it.
        let id = FlashId::new("");
        for comp in in_trial {
            if let Err(e) = comp.rollback_install(&id).await {
                out.errors.push((comp.id().to_string(), e.to_string()));
            }
        }
        out
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

    fn system_bank(&self) -> Option<&SharedSystemBankState> {
        Some(&self.system_bank)
    }
}

pub struct MachineRegistryBuilder {
    entity: EntityInfo,
    components: Vec<Arc<dyn Component>>,
    /// Optional override for the boot-selector store. `None` falls back to
    /// the loud production stub at build time.
    selector_store: Option<Box<dyn SelectorStore>>,
    /// Optional pre-built shared selector. When set (via
    /// [`with_shared_selector`](Self::with_shared_selector)) the registry
    /// adopts this exact `Arc<RwLock<…>>` rather than loading its own from a
    /// store — so the binary can build the selector ONCE, inject a read view
    /// into the providers via the factory, AND hand the same write handle to
    /// the registry. Wins over `selector_store` when present.
    shared_selector: Option<SharedSystemBankState>,
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

    /// Override the boot-selector store. The host/sim build passes a
    /// file-backed [`FileSelectorStore`](crate::system_bank_state::FileSelectorStore)
    /// (which carries its own signer) so the selector vector survives
    /// restarts; when omitted, `build` falls back to the loud stub. Additive —
    /// the boot authority is still `NvBootState`.
    pub fn with_selector_store(mut self, store: Box<dyn SelectorStore>) -> Self {
        self.selector_store = Some(store);
        self
    }

    /// Adopt an **already-built** shared boot selector instead of loading one
    /// from a store at build time.
    ///
    /// The binary builds the `SharedSystemBankState` ONCE (so the factory can
    /// inject a read-only [`BootSelector`] view of it into every
    /// `IvdBankProvider` before the registry exists), then hands that same
    /// `Arc<RwLock<…>>` here. The registry's seed/OTA write paths
    /// ([`seed_selector`](MachineRegistry::seed_selector),
    /// [`shared_selector`](MachineRegistry::shared_selector)) then operate on
    /// the very selector the providers read — a single source of truth.
    ///
    /// Wins over [`with_selector_store`](Self::with_selector_store): when this
    /// is set, the store is ignored (the caller already loaded the
    /// manager from its store). Tests / the default path keep using
    /// `with_selector_store` (or neither, falling back to the loud stubs).
    pub fn with_shared_selector(mut self, selector: SharedSystemBankState) -> Self {
        self.shared_selector = Some(selector);
        self
    }

    /// Resolve the registry's `system_bank`: prefer a pre-built shared selector
    /// (adopted as-is), else `load` one from the configured store, else the
    /// loud production stub. A store that could not be read is `Err`.
    fn resolve_system_bank(
        shared_selector: Option<SharedSystemBankState>,
        selector_store: Option<Box<dyn SelectorStore>>,
    ) -> Result<SharedSystemBankState, SelectorError> {
        match shared_selector {
            Some(selector) => Ok(selector),
            None => Ok(Arc::new(RwLock::new(SystemBankManager::load(
                selector_store.unwrap_or_else(|| Box::new(StubSelectorStore)),
            )?))),
        }
    }

    /// Build the registry, loading the boot selector from the configured store
    /// unless a shared one was adopted; `Err` when the store could not be read.
    pub fn build(self) -> Result<MachineRegistry, SelectorError> {
        let mut by_id = HashMap::with_capacity(self.components.len());
        for (idx, c) in self.components.iter().enumerate() {
            by_id.insert(c.id().to_string(), idx);
        }
        let system_bank = Self::resolve_system_bank(self.shared_selector, self.selector_store)?;
        Ok(MachineRegistry {
            entity: self.entity,
            components: self.components,
            by_id,
            system_bank,
        })
    }

    /// Like `build` but also returns an error if any two components share an
    /// id.
    pub fn try_build(self) -> Result<MachineRegistry, BuildError> {
        let mut by_id = HashMap::with_capacity(self.components.len());
        for (idx, c) in self.components.iter().enumerate() {
            let id = c.id().to_string();
            if by_id.contains_key(&id) {
                return Err(BuildError::DuplicateComponentId(DuplicateComponentId(id)));
            }
            by_id.insert(id, idx);
        }
        let system_bank = Self::resolve_system_bank(self.shared_selector, self.selector_store)
            .map_err(BuildError::Selector)?;
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

/// Why [`MachineRegistryBuilder::try_build`] failed.
#[derive(Debug)]
pub enum BuildError {
    DuplicateComponentId(DuplicateComponentId),
    /// The boot selector's store could not be read.
    Selector(SelectorError),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::DuplicateComponentId(e) => e.fmt(f),
            BuildError::Selector(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for BuildError {}
