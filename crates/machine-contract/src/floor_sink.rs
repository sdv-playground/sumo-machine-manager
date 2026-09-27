//! `FloorSink` — the seam a deployment implements to make a safe-time-floor
//! advance *durable*.
//!
//! Out-of-tree implemented, so it lives here: the real impl needs two host
//! resources the HSM-agnostic authorizer does not hold — the HSM monotonic slot
//! (so the floor survives a power cycle) and the system clock. A platform
//! machine manager holds both; naming this trait must not cost it the OTA
//! engine's dependency closure.
//!
//! Pairs with [`crate::wall_clock_floor::WallClockFloor`]: that one is the
//! clock half, this one is the persist-and-then-clock half.

/// Durably persist a safe-time-floor advance discovered during authorization.
///
/// When the delegated path accepts a workshop delegate whose (trusted) `not_before`
/// is ahead of the device's clock, the authorizer bumps its in-memory floor cell for
/// the current run — but the *durable* effects (ratchet the HSM monotonic slot so it
/// survives reboot, and step `CLOCK_REALTIME` forward so the JWT `exp`/`nbf` checks,
/// which read the raw wall clock, also see the advanced time) require host resources
/// the HSM-agnostic authorizer does not hold. The deployment injects a sink that does
/// them (a host manager wires it to `TimeFloor::advance` + `SystemWallClockFloor`); the
/// default is a no-op. Best-effort and monotonic — `secs` at/below the current floor
/// is a no-op. See `docs/safe-time-floor.md`.
pub trait FloorSink: Send + Sync {
    fn advance_floor(&self, secs: u64);
}

/// No-op sink: the in-memory bump still applies, but nothing is persisted or
/// clock-disciplined. The default where the deployment wires nothing (tests, or a
/// platform that owns its own clock).
pub struct NoopFloorSink;
impl FloorSink for NoopFloorSink {
    fn advance_floor(&self, _secs: u64) {}
}
