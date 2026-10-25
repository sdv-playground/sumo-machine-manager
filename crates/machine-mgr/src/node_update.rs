//! Node-level update-transaction state — the coordinator logic the
//! [`MachineRegistry`](crate::machine::MachineRegistry) owns. **One update
//! transaction at a time per ECU:** while any component is pending a node
//! reset, or a component is in trial and the node has rebooted since arming
//! (the trial awaits its verdict), a new flash session is refused; otherwise a
//! sibling component joins the open `Staging` transaction — so one campaign
//! step stages every component, takes one reboot, then one verdict.
//!
//! Phases: `Idle` → `Staging` (in-memory) → `RebootPending` (a component's
//! install needs a node reset that has not happened yet) → `Trial` (rebooted
//! into the staged banks, or a Local-reset component in trial) → verdict →
//! `Idle`.
//!
//! Every phase is derived from facts, not stored intent: each component
//! registers a [`BanksProbe`] (its [`ComponentBanks`] report: `in_trial`,
//! `pending_reset`), and the node answers "rebooted since arming" through a
//! [`RebootedProbe`] (the boot vector's transaction header, or a host
//! fallback). The coordinator reads them on demand. The derivation itself
//! ([`derive`], [`admit`]) is pure. [`NodeCoordinator`] holds the probes and the
//! in-memory [`Staging`].

use std::sync::{Arc, RwLock};

use crate::system_bank_state::SharedSystemBankState;
use crate::ComponentBanks;

/// A component's bank report, read on demand (`None` = the component does not
/// report bank contents).
pub type BanksProbe = Arc<dyn Fn() -> Option<ComponentBanks> + Send + Sync>;

/// Whether the node has rebooted since the open trial was armed, given the
/// node's current boot id (`None` = unknown).
pub type RebootedProbe = Arc<dyn Fn(Option<&str>) -> Option<bool> + Send + Sync>;

/// The node's update-transaction phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodePhase {
    /// No transaction in flight; new sessions allowed.
    Idle,
    /// A component has an open flash session (a transaction is being assembled).
    Staging,
    /// A component's install needs a node reset that has not happened yet (its
    /// installed manifest records the node boot id still running). A plain
    /// observation: nothing on the device vetoes a verdict on it; the
    /// orchestrator decides to reset.
    RebootPending,
    /// Rebooted into the staged banks (or a Local-reset component in trial);
    /// components await a verdict.
    Trial,
}

impl NodePhase {
    pub fn as_str(self) -> &'static str {
        match self {
            NodePhase::Idle => "Idle",
            NodePhase::Staging => "Staging",
            NodePhase::RebootPending => "RebootPending",
            NodePhase::Trial => "Trial",
        }
    }
}

/// A snapshot of the node update-transaction state — what the gate decides on and
/// the `x-ota-update-state` SOVD resource reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeUpdateState {
    pub phase: NodePhase,
    pub components: Vec<String>,
    /// Components pending a node reset: their install needs a node reset that
    /// has not happened yet (`ComponentBanks::pending_reset`).
    pub reboot_owed: Vec<String>,
    /// Whether the node has rebooted since arming (`None` = unknown).
    pub rebooted_since_arming: Option<bool>,
}

impl NodeUpdateState {
    pub fn idle() -> Self {
        Self {
            phase: NodePhase::Idle,
            components: Vec::new(),
            reboot_owed: Vec::new(),
            rebooted_since_arming: None,
        }
    }
}

/// The in-memory `Staging` session — ephemeral. A crash before activation
/// abandons it (nothing is activated, so it's safe).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Staging {
    pub components: Vec<String>,
}

/// The node-level facts: the components' bank reports and the node's reboot
/// observation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Durable {
    /// Components pending a node reset (`ComponentBanks::pending_reset`).
    pub reboot_owed: Vec<String>,
    /// Whether the node has rebooted since the open trial was armed (the
    /// [`RebootedProbe`]); `None` = unknown.
    pub rebooted_since_arming: Option<bool>,
}

/// A new flash session was admitted.
#[derive(Debug, PartialEq, Eq)]
pub enum Admit {
    /// Opened a fresh transaction (`Idle` → `Staging`).
    OpenedNew,
    /// Joined the open transaction (a sibling component).
    Joined,
}

/// A new flash session was refused — maps to SOVD `Busy` / HTTP 409.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// These components are pending a node reset.
    RebootPending(Vec<String>),
    /// These components are in a trial the node rebooted into; it awaits a
    /// verdict.
    Trial(Vec<String>),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::RebootPending(c) => write!(
                f,
                "an unresolved update owes a node reboot for {c:?} — reboot the node if not yet done, then commit or roll back before starting a new flash"
            ),
            Refused::Trial(c) => write!(
                f,
                "node owes a verdict for in-trial {c:?} — commit or roll back before starting a new flash"
            ),
        }
    }
}

/// Derive the node phase + snapshot from the durable facts, the in-trial
/// components and the in-memory `staging`. Precedence: RebootPending (a
/// component pending a node reset) > Trial (a component in trial) > Staging >
/// Idle — a transaction advances through those, and the most-advanced one wins.
/// `rebooted_since_arming` is reported only while a component is in trial or
/// pending a reset; otherwise `None`.
pub fn derive(
    durable: &Durable,
    in_trial: &[String],
    staging: Option<&Staging>,
) -> NodeUpdateState {
    if !durable.reboot_owed.is_empty() {
        return NodeUpdateState {
            phase: NodePhase::RebootPending,
            components: durable.reboot_owed.clone(),
            reboot_owed: durable.reboot_owed.clone(),
            rebooted_since_arming: durable.rebooted_since_arming,
        };
    }
    if !in_trial.is_empty() {
        return NodeUpdateState {
            phase: NodePhase::Trial,
            components: in_trial.to_vec(),
            reboot_owed: vec![],
            rebooted_since_arming: durable.rebooted_since_arming,
        };
    }
    // Nothing in trial or pending: the reboot answer describes no open trial
    // (a leftover header), so it is unknown.
    if let Some(s) = staging {
        return NodeUpdateState {
            phase: NodePhase::Staging,
            components: s.components.clone(),
            reboot_owed: vec![],
            rebooted_since_arming: None,
        };
    }
    NodeUpdateState::idle()
}

/// Decide whether to admit a new flash session for `comp`, mutating the
/// in-memory `staging` on success. Refuses while any component is pending a
/// node reset (`RebootPending`), then while a component is in trial and the
/// node has rebooted since arming (`Trial`: the trial awaits its verdict);
/// otherwise opens a fresh session or joins the open one. Before that reboot
/// (`Some(false)` or unknown) an in-trial component is an armed sibling of the
/// same step, so the newcomer joins.
pub fn admit(
    comp: &str,
    durable: &Durable,
    in_trial: &[String],
    staging: &mut Option<Staging>,
) -> Result<Admit, Refused> {
    if !durable.reboot_owed.is_empty() {
        return Err(Refused::RebootPending(durable.reboot_owed.clone()));
    }
    if !in_trial.is_empty() && durable.rebooted_since_arming == Some(true) {
        return Err(Refused::Trial(in_trial.to_vec()));
    }
    match staging {
        None => {
            *staging = Some(Staging {
                components: vec![comp.to_string()],
            });
            Ok(Admit::OpenedNew)
        }
        Some(s) => {
            if !s.components.iter().any(|x| x == comp) {
                s.components.push(comp.to_string());
            }
            Ok(Admit::Joined)
        }
    }
}

/// One component's facts for the node derivation.
type Report = (String, ComponentBanks);

/// The ids of the reports matching `keep`, in registration order.
fn labels(reports: &[Report], keep: impl Fn(&ComponentBanks) -> bool) -> Vec<String> {
    reports
        .iter()
        .filter(|(_, b)| keep(b))
        .map(|(id, _)| id.clone())
        .collect()
}

/// The node's update-transaction coordinator — the single home for the
/// node-level ("uber-component") update state. Owns the in-memory [`Staging`],
/// the components' [`BanksProbe`]s, the node's [`RebootedProbe`] and the gate; built once and shared (`Arc`)
/// into each component (for the `start_flash` gate) and the SOVD layer
/// (reboot / verdict / the `x-ota-update-state` report).
#[derive(Default)]
pub struct NodeCoordinator {
    staging: RwLock<Option<Staging>>,
    /// Component id -> its bank report, in registration order.
    probes: RwLock<Vec<(String, BanksProbe)>>,
    /// Whether the node has rebooted since arming. `None` = no source (the
    /// answer is unknown).
    rebooted: RwLock<Option<RebootedProbe>>,
    /// The node's current boot id (the components record it into the installs
    /// they seal, which is how `pending_reset` is observed). `None` = unknown.
    node_boot_id: Option<String>,
    /// Node boots while armed without a verdict after which the node rolls
    /// itself back (see `MachineRegistry::observe_node_boot`). `None` =
    /// disabled. Set by the host; there is no default.
    trial_boot_limit: Option<u8>,
}

impl NodeCoordinator {
    /// Build a coordinator with no probes registered.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the node's current boot id.
    pub fn with_node_boot_id(mut self, id: impl Into<String>) -> Self {
        self.node_boot_id = Some(id.into());
        self
    }

    /// The node's current boot id, if known.
    pub fn node_boot_id(&self) -> Option<&str> {
        self.node_boot_id.as_deref()
    }

    /// Set the trial boot limit (`None` = disabled). The host sets it below
    /// its boot stage's own bound.
    pub fn with_trial_boot_limit(mut self, limit: Option<u8>) -> Self {
        self.trial_boot_limit = limit;
        self
    }

    /// The trial boot limit, if one is set.
    pub fn trial_boot_limit(&self) -> Option<u8> {
        self.trial_boot_limit
    }

    /// Answer "rebooted since arming" from the boot vector's transaction
    /// header (the boot id recorded at seal, whatever the reset kind).
    pub fn with_system_bank(self, system_bank: SharedSystemBankState) -> Self {
        self.with_rebooted_probe(Arc::new(move |boot_id| {
            system_bank
                .read()
                .expect("selector poisoned")
                .rebooted_since_arming(boot_id)
        }))
    }

    /// Answer "rebooted since arming" with `probe`, replacing any earlier one.
    pub fn with_rebooted_probe(mut self, probe: RebootedProbe) -> Self {
        *self.rebooted.get_mut().expect("rebooted lock poisoned") = Some(probe);
        self
    }

    /// Install `probe` only when no source is set yet — the fallback a
    /// component registers when the host wired no boot vector.
    pub fn register_rebooted_fallback(&self, probe: RebootedProbe) {
        self.rebooted
            .write()
            .expect("rebooted lock poisoned")
            .get_or_insert(probe);
    }

    /// Register `component_id`'s bank report, replacing any earlier probe for
    /// the same id.
    pub fn register_banks_probe(&self, component_id: &str, probe: BanksProbe) {
        let mut probes = self.probes.write().expect("probes lock poisoned");
        match probes.iter_mut().find(|(id, _)| id == component_id) {
            Some(entry) => entry.1 = probe,
            None => probes.push((component_id.to_string(), probe)),
        }
    }

    /// Read every registered probe that reports.
    fn reports(&self) -> Vec<Report> {
        self.probes
            .read()
            .expect("probes lock poisoned")
            .iter()
            .filter_map(|(id, probe)| probe().map(|b| (id.clone(), b)))
            .collect()
    }

    /// Components pending a node reset.
    pub fn pending_reset_labels(&self) -> Vec<String> {
        labels(&self.reports(), |b| b.pending_reset)
    }

    /// Components in trial (armed or booted into).
    pub fn in_trial_labels(&self) -> Vec<String> {
        labels(&self.reports(), |b| b.in_trial)
    }

    /// Whether the node has rebooted since the open trial was armed (`None` =
    /// unknown or no source).
    pub fn rebooted_since_arming(&self) -> Option<bool> {
        let probe = self
            .rebooted
            .read()
            .expect("rebooted lock poisoned")
            .clone();
        probe.and_then(|p| p(self.node_boot_id()))
    }

    /// The node-level facts.
    pub fn durable(&self) -> Durable {
        self.durable_of(&self.reports())
    }

    fn durable_of(&self, reports: &[Report]) -> Durable {
        Durable {
            reboot_owed: labels(reports, |b| b.pending_reset),
            rebooted_since_arming: self.rebooted_since_arming(),
        }
    }

    /// Remove `comp` from the open staging session (its flash resolved); clears
    /// the session when the last component leaves — so the report returns to
    /// `Idle` instead of showing a stale `Staging`.
    pub fn remove_from_staging(&self, comp: &str) {
        let mut staging = self.staging.write().expect("staging lock poisoned");
        if let Some(s) = staging.as_mut() {
            s.components.retain(|c| c != comp);
            if s.components.is_empty() {
                *staging = None;
            }
        }
    }

    /// Admit (or refuse -> SOVD 409) a new flash session for `comp`, from the
    /// registered probes (see [`admit`]). Mutates the in-memory staging on admit.
    pub fn gate_new_session(&self, comp: &str) -> Result<Admit, Refused> {
        let reports = self.reports();
        let durable = self.durable_of(&reports);
        let in_trial = labels(&reports, |b| b.in_trial);
        let mut staging = self.staging.write().expect("staging lock poisoned");
        admit(comp, &durable, &in_trial, &mut staging)
    }

    /// The node's current update-transaction state (for the `x-ota-update-state`
    /// resource), combining the probes' facts with the in-memory staging.
    pub fn node_update_state(&self) -> NodeUpdateState {
        let reports = self.reports();
        let durable = self.durable_of(&reports);
        let in_trial = labels(&reports, |b| b.in_trial);
        let staging = self.staging.read().expect("staging lock poisoned");
        derive(&durable, &in_trial, staging.as_ref())
    }

    /// Take and clear the in-memory staging — called when the node reboot is
    /// issued, so the transaction leaves `Staging`; the components' bank reports
    /// carry it from there. Returns what was staged.
    pub fn take_staging(&self) -> Option<Staging> {
        self.staging.write().expect("staging lock poisoned").take()
    }

    /// Drop the in-memory staging (an abandoned `Staging` window).
    pub fn clear_staging(&self) {
        *self.staging.write().expect("staging lock poisoned") = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BankContents;
    use nv_store::types::Bank;

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn banks(in_trial: bool, pending_reset: bool) -> ComponentBanks {
        ComponentBanks {
            active: BankContents {
                bank: Bank::A,
                images: Default::default(),
                install_boot_id: None,
            },
            inactive: None,
            in_trial,
            pending_reset,
        }
    }

    fn probe(in_trial: bool, pending_reset: bool) -> BanksProbe {
        Arc::new(move || Some(banks(in_trial, pending_reset)))
    }

    #[test]
    fn idle_opens_a_new_session() {
        let mut staging = None;
        let r = admit("vm1", &Durable::default(), &[], &mut staging);
        assert_eq!(r.unwrap(), Admit::OpenedNew);
        assert_eq!(staging.unwrap().components, ids(&["vm1"]));
    }

    #[test]
    fn a_sibling_joins_the_transaction() {
        let mut staging = Some(Staging {
            components: ids(&["vm1"]),
        });
        let r = admit("vm2", &Durable::default(), &[], &mut staging);
        assert_eq!(r.unwrap(), Admit::Joined);
        assert_eq!(staging.unwrap().components, ids(&["vm1", "vm2"]));
    }

    fn rebooted(answer: Option<bool>) -> RebootedProbe {
        Arc::new(move |_| answer)
    }

    #[test]
    fn reboot_pending_refuses_any_new_session() {
        // rt is pending a node reset; vm1 must be refused so it does not join
        // rt's owed reboot.
        let durable = Durable {
            reboot_owed: ids(&["rt"]),
            rebooted_since_arming: Some(false),
        };
        let mut staging = None;
        let r = admit("vm1", &durable, &ids(&["rt"]), &mut staging);
        assert_eq!(r.unwrap_err(), Refused::RebootPending(ids(&["rt"])));
        assert!(staging.is_none());
        // Still refused once the reboot has been observed — rt is no longer
        // pending, but its trial now awaits the verdict.
        let durable = Durable {
            reboot_owed: vec![],
            rebooted_since_arming: Some(true),
        };
        let r = admit("vm1", &durable, &ids(&["rt"]), &mut staging);
        assert_eq!(r.unwrap_err(), Refused::Trial(ids(&["rt"])));
        assert!(staging.is_none());
    }

    #[test]
    fn trial_refuses_a_new_session_only_after_the_reboot() {
        let mut staging = None;
        for answer in [Some(false), None] {
            let durable = Durable {
                rebooted_since_arming: answer,
                ..Default::default()
            };
            assert!(
                admit("vm1", &durable, &ids(&["vm2"]), &mut staging).is_ok(),
                "{answer:?}: an armed sibling of the same step joins"
            );
        }
        let durable = Durable {
            rebooted_since_arming: Some(true),
            ..Default::default()
        };
        let r = admit("vm3", &durable, &ids(&["vm2"]), &mut staging);
        assert_eq!(r.unwrap_err(), Refused::Trial(ids(&["vm2"])));
    }

    #[test]
    fn derive_walks_idle_staging_trial_rebootpending() {
        // Idle
        assert_eq!(
            derive(&Durable::default(), &[], None).phase,
            NodePhase::Idle
        );
        // Staging
        let st = Staging {
            components: ids(&["vm1"]),
        };
        let s = derive(&Durable::default(), &[], Some(&st));
        assert_eq!(s.phase, NodePhase::Staging);
        assert_eq!(s.reboot_owed, Vec::<String>::new());
        assert_eq!(s.rebooted_since_arming, None);
        // Trial from in-trial (nothing pending), reboot reported as observed
        let durable = Durable {
            rebooted_since_arming: Some(true),
            ..Default::default()
        };
        let s = derive(&durable, &ids(&["vm1"]), Some(&st));
        assert_eq!(s.phase, NodePhase::Trial);
        assert_eq!(s.components, ids(&["vm1"]));
        assert_eq!(s.reboot_owed, Vec::<String>::new());
        assert_eq!(s.rebooted_since_arming, Some(true));
        // Pending a reset -> RebootPending dominates, whatever the node reports
        for answer in [Some(false), None] {
            let durable = Durable {
                reboot_owed: ids(&["rt"]),
                rebooted_since_arming: answer,
            };
            let s = derive(&durable, &ids(&["rt", "vm1"]), Some(&st));
            assert_eq!(s.phase, NodePhase::RebootPending);
            assert_eq!(s.components, ids(&["rt"]));
            assert_eq!(s.reboot_owed, ids(&["rt"]));
            assert_eq!(s.rebooted_since_arming, answer);
        }
    }

    #[test]
    fn idle_node_with_a_stale_probe_answer_reports_none() {
        let c = NodeCoordinator::new().with_rebooted_probe(rebooted(Some(true)));
        c.register_banks_probe("vm1", probe(false, false));
        let st = c.node_update_state();
        assert_eq!(st.phase, NodePhase::Idle);
        assert_eq!(st.rebooted_since_arming, None);
        c.gate_new_session("vm1").unwrap();
        let st = c.node_update_state();
        assert_eq!(st.phase, NodePhase::Staging);
        assert_eq!(st.rebooted_since_arming, None);
    }

    #[test]
    fn gate_refuses_while_a_probe_reports_pending_reset() {
        let c = NodeCoordinator::new();
        c.register_banks_probe("rt", probe(true, true));
        assert_eq!(
            c.gate_new_session("vm1").unwrap_err(),
            Refused::RebootPending(ids(&["rt"]))
        );
        assert_eq!(c.node_update_state().phase, NodePhase::RebootPending);
    }

    #[test]
    fn gate_joins_an_in_trial_sibling_until_the_node_reboots() {
        for answer in [Some(false), None] {
            let c = NodeCoordinator::new().with_rebooted_probe(rebooted(answer));
            c.register_banks_probe("vm2", probe(true, false));
            assert_eq!(
                c.gate_new_session("vm1").unwrap(),
                Admit::OpenedNew,
                "{answer:?}"
            );
            assert_eq!(c.node_update_state().phase, NodePhase::Trial);
        }
    }

    #[test]
    fn gate_refuses_an_in_trial_node_once_it_rebooted() {
        let c = NodeCoordinator::new().with_rebooted_probe(rebooted(Some(true)));
        c.register_banks_probe("vm2", probe(true, false));
        assert_eq!(
            c.gate_new_session("vm1").unwrap_err(),
            Refused::Trial(ids(&["vm2"]))
        );
        assert_eq!(c.node_update_state().phase, NodePhase::Trial);
    }

    #[test]
    fn gate_admits_when_no_probe_reports_trial_or_pending_reset() {
        let c = NodeCoordinator::new().with_rebooted_probe(rebooted(Some(true)));
        c.register_banks_probe("vm1", probe(false, false));
        c.register_banks_probe("vm2", Arc::new(|| None));
        assert_eq!(c.gate_new_session("vm1").unwrap(), Admit::OpenedNew);
        assert_eq!(c.gate_new_session("vm2").unwrap(), Admit::Joined);
        let st = c.node_update_state();
        assert_eq!(st.phase, NodePhase::Staging);
        assert_eq!(st.components, ids(&["vm1", "vm2"]));
    }

    #[test]
    fn register_banks_probe_replaces_the_same_id() {
        let c = NodeCoordinator::new();
        c.register_banks_probe("vm1", probe(true, true));
        c.register_banks_probe("vm1", probe(false, false));
        assert!(c.pending_reset_labels().is_empty());
        assert!(c.in_trial_labels().is_empty());
    }

    #[test]
    fn labels_follow_the_bank_reports() {
        let c = NodeCoordinator::new();
        c.register_banks_probe("rt", probe(true, true));
        c.register_banks_probe("vm1", probe(true, false));
        c.register_banks_probe("vm2", probe(false, false));
        assert_eq!(c.pending_reset_labels(), ids(&["rt"]));
        assert_eq!(c.in_trial_labels(), ids(&["rt", "vm1"]));
        assert_eq!(c.durable().reboot_owed, ids(&["rt"]));
    }

    #[test]
    fn rebooted_since_arming_comes_from_the_rebooted_probe() {
        // No source: unknown, whatever the components report.
        let c = NodeCoordinator::new();
        c.register_banks_probe("vm1", probe(true, true));
        assert_eq!(c.rebooted_since_arming(), None);
        // The probe is asked with the node's boot id.
        let c = NodeCoordinator::new()
            .with_node_boot_id("boot-b")
            .with_rebooted_probe(Arc::new(|id| Some(id == Some("boot-b"))));
        assert_eq!(c.rebooted_since_arming(), Some(true));
        // A fallback does not replace the host's source…
        c.register_rebooted_fallback(rebooted(Some(false)));
        assert_eq!(c.rebooted_since_arming(), Some(true));
        // …but fills in when there is none.
        let c = NodeCoordinator::new();
        c.register_rebooted_fallback(rebooted(Some(false)));
        assert_eq!(c.rebooted_since_arming(), Some(false));
    }

    #[test]
    fn with_system_bank_reads_the_transaction_header() {
        use crate::system_bank_state::{InMemorySelectorStore, SystemBankManager};
        let mut m = SystemBankManager::load(Box::new(InMemorySelectorStore::new()));
        m.stage("vm1", Bank::A, Default::default());
        m.seal(None).unwrap();
        m.commit().unwrap();
        m.stage("vm1", Bank::B, Default::default());
        m.seal(Some("boot-a")).unwrap();
        let sb: SharedSystemBankState = Arc::new(RwLock::new(m));
        let at = |id: &str| {
            NodeCoordinator::new()
                .with_node_boot_id(id)
                .with_system_bank(sb.clone())
                .rebooted_since_arming()
        };
        assert_eq!(at("boot-a"), Some(false));
        assert_eq!(at("boot-b"), Some(true));
    }

    #[test]
    fn node_boot_id_defaults_to_none_and_is_settable() {
        assert_eq!(NodeCoordinator::new().node_boot_id(), None);
        assert_eq!(
            NodeCoordinator::new()
                .with_node_boot_id("abc")
                .node_boot_id(),
            Some("abc")
        );
    }

    #[test]
    fn trial_boot_limit_defaults_to_none_and_is_settable() {
        assert_eq!(NodeCoordinator::new().trial_boot_limit(), None);
        assert_eq!(
            NodeCoordinator::new()
                .with_trial_boot_limit(Some(3))
                .trial_boot_limit(),
            Some(3)
        );
    }
}
