//! Node-level update-transaction state — the coordinator logic the
//! [`MachineRegistry`](crate::machine::MachineRegistry) owns. **One update
//! transaction at a time per ECU:** while a node reboot is owed or a trial is
//! unresolved, a new flash session is refused; a sibling component joins the
//! *same* `Staging` transaction only if its session id matches — so two updates
//! never get coalesced into one reboot.
//!
//! The logic here is pure. The registry feeds it the durable facts (the NV
//! reboot-owed record, per-component `committed`) and holds the in-memory
//! [`Staging`]. See `docs/design/node-update-state.md`.

/// A 32-byte update-transaction session id (provenance). Interim: the
/// vehicle-release content identity; later the SUIT L1 campaign-manifest id.
pub type SessionId = [u8; 32];

const NO_SESSION: SessionId = [0u8; 32];

/// The node's update-transaction phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodePhase {
    /// No transaction in flight; new sessions allowed.
    Idle,
    /// A component has an open flash session (a transaction is being assembled).
    Staging,
    /// A node activation reboot is owed (issued-but-unconfirmed) — the durable phase.
    RebootPending,
    /// Rebooted into the staged banks; components in-trial awaiting a verdict.
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
/// the `x-sumo-update-state` SOVD resource reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeUpdateState {
    pub phase: NodePhase,
    pub session_id: Option<SessionId>,
    pub components: Vec<String>,
}

impl NodeUpdateState {
    pub fn idle() -> Self {
        Self {
            phase: NodePhase::Idle,
            session_id: None,
            components: Vec::new(),
        }
    }
}

/// The in-memory `Staging` session — ephemeral. A crash before a reboot is owed
/// abandons it (nothing is activated, so it's safe). Promoted to the durable NV
/// reboot-owed record when the node reboot is issued.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Staging {
    pub session_id: SessionId,
    pub components: Vec<String>,
}

/// The durable half of the node session, as the registry reads it back from NV
/// (translated from the bank-set bitmask into component ids).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Durable {
    /// The open transaction's session id (`NO_SESSION` ⇒ none).
    pub session_id: SessionId,
    /// Components that still owe the coalesced node reboot (RebootPending). Empty
    /// once the reboot is confirmed — the transaction is then `Trial`, which is
    /// derived from per-component `committed`, the session id retained.
    pub reboot_owed: Vec<String>,
}

impl Durable {
    fn has_session(&self) -> bool {
        self.session_id != NO_SESSION
    }
}

/// A new flash session was admitted.
#[derive(Debug, PartialEq, Eq)]
pub enum Admit {
    /// Opened a fresh transaction (`Idle` → `Staging`).
    OpenedNew,
    /// Joined the open transaction (a sibling component, matching id).
    Joined,
}

/// A new flash session was refused — maps to SOVD `Busy` / HTTP 409.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// The node owes an activation reboot for these components.
    RebootPending(Vec<String>),
    /// The node owes a verdict (commit / rollback) for these in-trial components.
    Trial(Vec<String>),
    /// A *different* transaction is already staging — admitting would mix updates.
    Mixing { open_session_id: SessionId },
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::RebootPending(c) => write!(
                f,
                "node owes an activation reboot for {c:?} — reboot or roll back before starting a new flash"
            ),
            Refused::Trial(c) => write!(
                f,
                "node owes a verdict for in-trial {c:?} — commit or roll back before starting a new flash"
            ),
            Refused::Mixing { .. } => write!(
                f,
                "a different update is already staging on this node — finish or abort it first \
                 (a new one would mix two updates into one reboot)"
            ),
        }
    }
}

/// Derive the node phase + snapshot from the durable facts and the in-memory
/// `staging`. Precedence: RebootPending > Trial > Staging > Idle — a transaction
/// advances through those, and the most-advanced one wins.
pub fn derive(durable: &Durable, in_trial: &[String], staging: Option<&Staging>) -> NodeUpdateState {
    if !durable.reboot_owed.is_empty() {
        return NodeUpdateState {
            phase: NodePhase::RebootPending,
            session_id: Some(durable.session_id),
            components: durable.reboot_owed.clone(),
        };
    }
    if !in_trial.is_empty() {
        return NodeUpdateState {
            phase: NodePhase::Trial,
            session_id: durable.has_session().then_some(durable.session_id),
            components: in_trial.to_vec(),
        };
    }
    if let Some(s) = staging {
        return NodeUpdateState {
            phase: NodePhase::Staging,
            session_id: Some(s.session_id),
            components: s.components.clone(),
        };
    }
    NodeUpdateState::idle()
}

/// Decide whether to admit a new flash session for `comp` under `incoming_id`,
/// mutating the in-memory `staging` on success. The durable facts gate first
/// (RebootPending / Trial → refuse); then `Staging` admits a join only if the id
/// matches (else `Mixing`); `Idle` opens a fresh session.
pub fn admit(
    incoming_id: SessionId,
    comp: &str,
    durable: &Durable,
    in_trial: &[String],
    staging: &mut Option<Staging>,
) -> Result<Admit, Refused> {
    if !durable.reboot_owed.is_empty() {
        return Err(Refused::RebootPending(durable.reboot_owed.clone()));
    }
    if !in_trial.is_empty() {
        return Err(Refused::Trial(in_trial.to_vec()));
    }
    match staging {
        None => {
            *staging = Some(Staging {
                session_id: incoming_id,
                components: vec![comp.to_string()],
            });
            Ok(Admit::OpenedNew)
        }
        Some(s) if s.session_id == incoming_id => {
            if !s.components.iter().any(|x| x == comp) {
                s.components.push(comp.to_string());
            }
            Ok(Admit::Joined)
        }
        Some(s) => Err(Refused::Mixing {
            open_session_id: s.session_id,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: SessionId = [0xAA; 32];
    const B: SessionId = [0xBB; 32];

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn idle_opens_a_new_session() {
        let mut staging = None;
        let r = admit(A, "vm1", &Durable::default(), &[], &mut staging);
        assert_eq!(r.unwrap(), Admit::OpenedNew);
        let s = staging.unwrap();
        assert_eq!(s.session_id, A);
        assert_eq!(s.components, ids(&["vm1"]));
    }

    #[test]
    fn same_id_joins_the_transaction() {
        let mut staging = Some(Staging {
            session_id: A,
            components: ids(&["vm1"]),
        });
        let r = admit(A, "vm2", &Durable::default(), &[], &mut staging);
        assert_eq!(r.unwrap(), Admit::Joined);
        assert_eq!(staging.unwrap().components, ids(&["vm1", "vm2"]));
    }

    #[test]
    fn different_id_is_refused_as_mixing() {
        let mut staging = Some(Staging {
            session_id: A,
            components: ids(&["vm1"]),
        });
        let r = admit(B, "vm2", &Durable::default(), &[], &mut staging);
        assert_eq!(r.unwrap_err(), Refused::Mixing { open_session_id: A });
        // The open session is untouched — vm2 did not sneak in.
        assert_eq!(staging.unwrap().components, ids(&["vm1"]));
    }

    #[test]
    fn reboot_pending_refuses_any_new_session() {
        // The reported bug: rt owes a node reboot; vm1/vm2 must be refused — even
        // with a fresh id — so they don't join rt's owed reboot.
        let durable = Durable {
            session_id: A,
            reboot_owed: ids(&["rt"]),
        };
        let mut staging = None;
        let r = admit(B, "vm1", &durable, &[], &mut staging);
        assert_eq!(r.unwrap_err(), Refused::RebootPending(ids(&["rt"])));
        assert!(staging.is_none());
    }

    #[test]
    fn trial_refuses_any_new_session() {
        let mut staging = None;
        let r = admit(A, "vm1", &Durable::default(), &ids(&["vm2"]), &mut staging);
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
            session_id: A,
            components: ids(&["vm1"]),
        };
        let s = derive(&Durable::default(), &[], Some(&st));
        assert_eq!(s.phase, NodePhase::Staging);
        assert_eq!(s.session_id, Some(A));
        // Trial (session id retained from the durable record, reboot_owed cleared)
        let durable = Durable {
            session_id: A,
            reboot_owed: vec![],
        };
        let s = derive(&durable, &ids(&["vm1"]), Some(&st));
        assert_eq!(s.phase, NodePhase::Trial);
        assert_eq!(s.session_id, Some(A));
        assert_eq!(s.components, ids(&["vm1"]));
        // RebootPending dominates everything below it
        let durable = Durable {
            session_id: A,
            reboot_owed: ids(&["rt"]),
        };
        let s = derive(&durable, &ids(&["vm1"]), Some(&st));
        assert_eq!(s.phase, NodePhase::RebootPending);
        assert_eq!(s.components, ids(&["rt"]));
    }
}
