//! The device's **time-floor**: the plumbing over the HSM's named
//! rollback-proof monotonic-counter slot (`vhsm_proto::HANDLE_TIME_FLOOR`), plus
//! the monotonic-adoption safety core.
//!
//! The slot is a generic upward-only `u64` counter; [`TimeFloor`] ascribes the
//! "UNIX **seconds**, a lower bound on real time" meaning to it
//! (`docs/design/safe-time-floor.md`) — the HSM only guarantees the value never
//! rewinds. The op stays generic (`read_monotonic` / `raise_monotonic`); the
//! SLOT carries the meaning, exactly as a named key slot carries the meaning of
//! a generic `sign`.
//!
//! Cross-ECU freshness no longer rides a signed assertion here (that machinery
//! was removed); a later change carries it over mTLS as configuration. What
//! stays portable is [`adopt_monotonic`], the ratchet-to-max rule a consumer
//! reuses when it adopts a value from a remote source.

use hsm::{HsmError, HsmProvider, KeyHandle};

/// Adopt an incoming monotonic value: take the max, never go backwards.
///
/// The safety rule applied to any monotonic quantity (an epoch, a floor): a
/// compromised or spoofed source can only **stall** the value (fail to raise
/// it), never **rewind** it — so it can never resurrect an expired grant or
/// replay an old value into validity. Same monotonic discipline as the
/// anti-rollback floor in §4/§6.5.
pub fn adopt_monotonic(local: u64, incoming: u64) -> u64 {
    local.max(incoming)
}

/// Handle-addressed plumbing over the named monotonic-counter slot that holds
/// the device's time-floor. Stateless: each call borrows an [`HsmProvider`], so
/// the same seam serves the shared read path and the (future) advance path
/// without owning the provider.
///
/// `read()` is wired today (the host seeds its live floor cell from it at boot).
/// `advance()` is the clean seam a later change feeds from a verified time
/// source — an identity leaf's `not_before`, a signed SUIT timestamp, or an mTLS
/// master's floor. Nothing ratchets it at runtime yet beyond the
/// provisioning-time seed the backend applies when it installs a CA-signed leaf.
pub struct TimeFloor;

impl TimeFloor {
    /// The named rollback-proof monotonic-counter slot the floor lives in.
    pub const HANDLE: KeyHandle = KeyHandle(hsm::vhsm_proto::HANDLE_TIME_FLOOR);

    /// Read the current floor — UNIX seconds, a monotonic lower bound on real
    /// time; 0 if never raised.
    pub fn read(hsm: &dyn HsmProvider) -> Result<u64, HsmError> {
        hsm.read_monotonic(Self::HANDLE)
    }

    /// Ratchet the floor up to `max(current, verified_secs)` and return the
    /// resulting value. `verified_secs` MUST come from a trustworthy source: the
    /// value can only move forward, never rewind (the safety core).
    pub fn advance(hsm: &mut dyn HsmProvider, verified_secs: u64) -> Result<u64, HsmError> {
        hsm.raise_monotonic(Self::HANDLE, verified_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hsm::{KeyInfo, KeyRole, ProvisioningState};

    #[test]
    fn adopt_monotonic_never_rewinds() {
        assert_eq!(adopt_monotonic(5, 9), 9); // raise forward
        assert_eq!(adopt_monotonic(9, 5), 9); // a lower incoming cannot rewind
        assert_eq!(adopt_monotonic(7, 7), 7); // equal stays
    }

    /// Minimal in-memory `HsmProvider` exercising only the monotonic-counter
    /// slot — enough to prove `TimeFloor` plumbs to the right handle and ratchets.
    #[derive(Default)]
    struct MockHsm {
        counter: u64,
    }

    impl HsmProvider for MockHsm {
        fn is_provisioned(&self) -> Result<bool, HsmError> {
            Ok(true)
        }
        fn provision(&mut self, _envelope: &[u8]) -> Result<(), HsmError> {
            Ok(())
        }
        fn list_keys(&self) -> Result<Vec<KeyInfo>, HsmError> {
            Ok(Vec::new())
        }
        fn get_public_key(&self, _role: KeyRole) -> Result<Vec<u8>, HsmError> {
            Ok(Vec::new())
        }
        fn provisioning_state(&self) -> Result<ProvisioningState, HsmError> {
            Ok(ProvisioningState::Provisioned)
        }
        fn read_monotonic(&self, handle: KeyHandle) -> Result<u64, HsmError> {
            // TimeFloor must address the time-floor slot, nothing else.
            assert_eq!(handle, TimeFloor::HANDLE);
            Ok(self.counter)
        }
        fn raise_monotonic(&mut self, handle: KeyHandle, v: u64) -> Result<u64, HsmError> {
            assert_eq!(handle, TimeFloor::HANDLE);
            self.counter = self.counter.max(v);
            Ok(self.counter)
        }
    }

    #[test]
    fn time_floor_reads_and_advances_the_named_slot() {
        let mut hsm = MockHsm::default();
        assert_eq!(TimeFloor::read(&hsm).unwrap(), 0);
        assert_eq!(TimeFloor::advance(&mut hsm, 1_000).unwrap(), 1_000);
        assert_eq!(TimeFloor::read(&hsm).unwrap(), 1_000);
        // Max-ratchet: a lower value never rewinds.
        assert_eq!(TimeFloor::advance(&mut hsm, 500).unwrap(), 1_000);
        assert_eq!(TimeFloor::read(&hsm).unwrap(), 1_000);
    }
}
