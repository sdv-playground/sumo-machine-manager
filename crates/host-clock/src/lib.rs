//! host-clock — discipline the host's `CLOCK_REALTIME` forward to a proven
//! safe-time floor.
//!
//! ```text
//!   OTA / authz raises the floor (HSM monotonic slot)
//!         │
//!         ▼
//!   WallClockFloor::discipline_to(floor) ──► step_needed(now, floor)
//!         │                                   │        │
//!         │                              None │        │ Some(to)
//!         ▼                                   ▼        ▼
//!   FloorSink::advance_floor(secs) ──►  AlreadyAhead   clock_settime
//!   (same step, reached from the                        │      │
//!    delegated-authz path)                         Stepped   NotStepped
//! ```
//!
//! # Why this is a library and not part of a machine manager
//!
//! Two ~20-line impls of two `machine-contract` seams, over POSIX `clock_gettime`
//! / `clock_settime`. Nothing in them is board-specific, node-family-specific or
//! OEM-specific — QNX and Linux expose the identical libc surface — so every node
//! that owns its own clock wants this exact code. It was sitting in one
//! deployment's `main.rs`, where the next node family could only copy it.
//!
//! # Forward-only, and why that is the whole safety argument
//!
//! The floor is a *lower bound* on real time. Stepping the clock up to it can
//! only move time toward truth; stepping it down could resurrect an expired
//! grant or replay an old token into validity. So `step_needed` is the rule,
//! it takes no syscall, and it is tested exhaustively — the dangerous direction
//! is unrepresentable rather than merely unused.
//!
//! Forward-only also means it never fights a real time source: a clock already
//! synced by NTP or gPTP is by definition ≥ the floor, so the step is a no-op.
//!
//! # Best-effort, and why a failure is not an error
//!
//! `discipline_to` cannot fail the caller. A denied `clock_settime` (an
//! unprivileged dev box, a platform that will not let userland set time) reports
//! [`DisciplineOutcome::NotStepped`] and logs. That is safe because the clock is
//! never the authority — the floor's durable home is the HSM's monotonic slot.
//! The clock step is an optimisation: it lets every *other* reader on the box
//! (notably the JWT `exp`/`nbf` checks, which read the raw wall clock) see the
//! advanced time without each one learning about the floor.
//!
//! # What a node still owns
//!
//! Wiring. A node injects [`SystemWallClockFloor`] where it wants the clock
//! stepped and [`ClockDiscipliningFloorSink`] where an authorizer discovers a
//! floor advance; a node whose clock belongs to something else injects
//! `machine_contract::NoopWallClockFloor` instead and links none of this.

use machine_contract::floor_sink::FloorSink;
use machine_contract::wall_clock_floor::{DisciplineOutcome, WallClockFloor};

/// Steps the host `CLOCK_REALTIME` forward to the safe-time floor when the clock
/// is behind it (`docs/design/safe-time-floor.md`). A host machine manager IS the
/// system software on these nodes — no NTP daemon competes — and QNX provides
/// `clock_settime(CLOCK_REALTIME)` over the same POSIX libc as `clock_gettime`.
/// Forward-only, so it never fights a real time source (a synced clock is already
/// ≥ floor → no-op); best-effort, so a denied set (e.g. an unprivileged Linux dev
/// box) logs and continues — the authoritative floor still lives in the HSM.
pub struct SystemWallClockFloor;

/// The forward-only rule, with no syscall in it: `Some(to)` means step the clock
/// to `to`, `None` means leave it alone.
///
/// Extracted so the rule is testable without privilege and without a test ever
/// setting the machine's clock — which is also the reason it can be tested
/// exhaustively at the boundary (`now == floor`), the case a
/// clock-touching test would be least likely to cover.
fn step_needed(now: u64, floor_secs: u64) -> Option<u64> {
    (now < floor_secs).then_some(floor_secs)
}

impl SystemWallClockFloor {
    fn now_realtime_secs() -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is a valid initialised timespec; clock_gettime writes it.
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
        ts.tv_sec.max(0) as u64
    }
}

impl WallClockFloor for SystemWallClockFloor {
    fn discipline_to(&self, floor_secs: u64) -> DisciplineOutcome {
        let now = Self::now_realtime_secs();
        let Some(to_secs) = step_needed(now, floor_secs) else {
            return DisciplineOutcome::AlreadyAhead;
        };
        // Set whole seconds (nsec 0): the floor is a coarse lower bound, and
        // rounding to the second keeps us at or below true time.
        let ts = libc::timespec {
            tv_sec: to_secs as libc::time_t,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is a valid initialised timespec for the call; the kernel
        // reads it and does not retain the pointer.
        let rc = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) };
        if rc == 0 {
            tracing::info!(
                from_secs = now,
                to_secs,
                "wall clock disciplined forward to the safe-time floor"
            );
            DisciplineOutcome::Stepped {
                from_secs: now,
                to_secs,
            }
        } else {
            let err = std::io::Error::last_os_error();
            tracing::warn!(now, floor_secs, error = %err,
                "clock_settime failed — leaving wall clock as-is (floor stays authoritative in the HSM)");
            DisciplineOutcome::NotStepped
        }
    }
}

/// Bridges an authorizer's [`FloorSink`] to the host's real clock. When the
/// delegated path advances the safe-time floor from a verified workshop
/// delegate's `not_before`, this steps `CLOCK_REALTIME` forward to it — so the JWT
/// `exp`/`nbf` checks (which read the raw wall clock) and every other clock reader
/// on the box also see the advanced time, not just the in-memory floor cell.
/// Forward-only + best-effort (see [`SystemWallClockFloor`]). The HSM-slot
/// durability across reboot is handled separately by the OTA ratchet path.
pub struct ClockDiscipliningFloorSink;

impl FloorSink for ClockDiscipliningFloorSink {
    fn advance_floor(&self, secs: u64) {
        SystemWallClockFloor.discipline_to(secs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The forward-only rule, including the boundary. A floor at or below `now`
    /// must NEVER produce a step: stepping the clock backwards could resurrect an
    /// expired grant, which is the one thing this must not be able to do.
    #[test]
    fn a_floor_at_or_below_now_never_steps() {
        assert_eq!(step_needed(1_000, 999), None, "floor behind now");
        assert_eq!(step_needed(1_000, 1_000), None, "floor exactly at now");
        assert_eq!(step_needed(1_000, 0), None, "no floor (never raised)");
        assert_eq!(step_needed(0, 0), None, "no clock, no floor");
    }

    /// A floor ahead of `now` steps to the floor exactly — not past it. The floor
    /// is a lower bound, so overshooting would claim time we cannot prove.
    #[test]
    fn a_floor_ahead_of_now_steps_to_the_floor_exactly() {
        assert_eq!(step_needed(1_000, 1_001), Some(1_001));
        assert_eq!(step_needed(0, 1_700_000_000), Some(1_700_000_000));
        assert_eq!(step_needed(u64::MAX - 1, u64::MAX), Some(u64::MAX));
    }

    /// The real impl with a floor far in the past: `AlreadyAhead`, and no
    /// `clock_settime` is reached at all. Deliberately the ONLY test that touches
    /// the real clock path — a test that exercised the stepping branch would set
    /// this machine's clock when run as root, which CI containers often are.
    #[test]
    fn the_real_impl_leaves_a_clock_already_ahead_alone() {
        let before = SystemWallClockFloor::now_realtime_secs();
        assert_eq!(
            SystemWallClockFloor.discipline_to(1),
            DisciplineOutcome::AlreadyAhead
        );
        // Not a tautology restated: proves the early return really did skip the
        // syscall rather than setting the clock to 1970 and reporting otherwise.
        assert!(SystemWallClockFloor::now_realtime_secs() >= before);
    }

    /// The sink is the same step reached from the authz path, so it inherits the
    /// same safety: a floor in the past does nothing.
    #[test]
    fn the_floor_sink_is_also_forward_only() {
        let before = SystemWallClockFloor::now_realtime_secs();
        ClockDiscipliningFloorSink.advance_floor(1);
        assert!(SystemWallClockFloor::now_realtime_secs() >= before);
    }
}
