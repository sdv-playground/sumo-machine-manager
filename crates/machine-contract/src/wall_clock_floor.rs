//! `WallClockFloor` — the seam a deployment implements to step the host's
//! `CLOCK_REALTIME` forward to a proven time floor.
//!
//! Here rather than in `component-mgr` for the reason every other trait in this
//! crate is here: it is **implemented out of tree**. The real impl sets the
//! system clock over `libc::clock_settime`, which is a host-OS privilege a
//! platform machine manager holds and the OTA engine does not. Leaving the trait
//! inside component-mgr meant the ~15-line impl had to link the whole SUIT /
//! streaming / SOVD / tokio closure to name the trait it satisfies.
//!
//! The floor's *authority* stays in component-mgr (`sovd::time_floor::TimeFloor`,
//! over the HSM's monotonic slot) — that one needs `hsm` and is called, not
//! implemented. Only the clock-stepping seam moved.

/// What [`WallClockFloor::discipline_to`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisciplineOutcome {
    /// The wall clock was below the floor and was stepped forward to it.
    Stepped { from_secs: u64, to_secs: u64 },
    /// The wall clock was already at or ahead of the floor — left untouched.
    AlreadyAhead,
    /// A step was wanted but not performed (no privilege, or a log-only sink).
    /// Best-effort: the caller logs and continues; the authoritative floor still
    /// lives in the HSM.
    NotStepped,
}

/// A sink that disciplines the host wall clock forward to a proven time floor.
///
/// After the safe-time floor is ratcheted (from a verified SUIT `iat`, an
/// identity leaf's `not_before`, etc.), the device steps its own
/// `CLOCK_REALTIME` up to the floor when the clock is behind it — so every
/// reader of the system clock gets `max(now, floor)` for free, with no separate
/// floor cache to keep in sync. Forward-only; a clock already ahead is left
/// alone (so it never fights NTP/gPTP). Injected: the real host wires a
/// clock-setting impl (`host_clock::SystemWallClockFloor`, over libc); tests and
/// clock-owned-elsewhere deployments use [`NoopWallClockFloor`].
///
/// `discipline_to` never errors — a failed set reports
/// [`DisciplineOutcome::NotStepped`], so a clock hiccup can never fail an
/// otherwise-valid OTA install.
pub trait WallClockFloor: Send + Sync {
    fn discipline_to(&self, floor_secs: u64) -> DisciplineOutcome;
}

/// Log-only sink: never touches the OS clock. The default in `ComponentBackend`
/// and the right choice where something else owns the clock or the platform
/// cannot set time (dev/CI). Carries no clock dependency of its own.
pub struct NoopWallClockFloor;

impl WallClockFloor for NoopWallClockFloor {
    fn discipline_to(&self, _floor_secs: u64) -> DisciplineOutcome {
        DisciplineOutcome::NotStepped
    }
}
