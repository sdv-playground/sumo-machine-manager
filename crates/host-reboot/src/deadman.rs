//! The once-guarded reset and the watchdog that fires it when teardown wedges.

use std::sync::Arc;
use std::time::Duration;

use crate::reset::{reboot_host, PreReboot};

/// Hard deadline from "reboot requested" to the reset. A clean teardown of both
/// guests measures ≤6s on the S32G3 (and ~0 with no guests running), so 15s is
/// generous headroom that still resets the node while the requester is watching.
/// Deliberately a constant, not config: a node that can't reset is worse than a
/// node that resets a few seconds early, and no deployment wants a different
/// answer.
pub const REBOOT_DEADLINE: Duration = Duration::from_secs(15);

/// The reset mechanism, behind a closure so [`OnceReset`] is unit-testable off
/// the rig (production wires [`reboot_host`]).
pub type ResetFn = Arc<dyn Fn() + Send + Sync>;

/// One node reset, fired exactly once — by the normal reboot path or by its
/// deadman, whichever gets there first.
///
/// A double reset is harmless in itself (after the first one lands, procnto
/// resets the board and nothing else runs), but the two CAN genuinely race:
/// `sysmgr_reboot` takes a moment to land, and the deadman's deadline can expire
/// inside exactly that window. The once-flag keeps that from spawning two
/// privileged reset threads, and keeps the "deadman FIRED" log line honest — it
/// appears only when the deadman really did beat a wedged teardown.
pub struct OnceReset {
    fired: std::sync::atomic::AtomicBool,
    reset: ResetFn,
}

impl OnceReset {
    pub fn new(reset: ResetFn) -> Arc<Self> {
        Arc::new(Self {
            fired: std::sync::atomic::AtomicBool::new(false),
            reset,
        })
    }

    /// Fire the reset unless someone already did. Returns `true` if THIS call
    /// fired it.
    pub fn fire(&self) -> bool {
        if self.fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return false;
        }
        (self.reset)();
        true
    }
}

/// Watchdog thread: fires `reset` once `deadline` elapses, whatever the teardown
/// is doing.
///
/// A plain `std::thread` on purpose — it must be immune to everything the
/// teardown can wedge on: a VM-manager mutex, a blocked async worker, an
/// uninterruptible `wait()` on a guest that won't die. That is exactly how the
/// field hang looked (2026-08-30, S32G3, both guests up): the pre-reset teardown
/// never returned, so the reset was never even scheduled and the board had to be
/// power-cut. An unclean cut is safe here by design — banks are hash-verified at
/// launch (fail-closed) and guest rootfs is dm-verity.
///
/// Split out of [`arm_reboot_deadman`] so tests can drive it with a short
/// deadline and an observable reset.
pub fn spawn_reboot_deadman(reset: Arc<OnceReset>, deadline: Duration, phase: &'static str) {
    // Detached, and it always sleeps the FULL deadline: on the clean path the
    // teardown has already fired by the time it wakes, so `fire()` is a no-op and
    // the thread just dies with the board. Nothing here can slow the clean path.
    let spawned = std::thread::Builder::new()
        .name("reboot-deadman".into())
        .spawn(move || {
            std::thread::sleep(deadline);
            if reset.fire() {
                tracing::error!(
                    phase,
                    deadline_secs = deadline.as_secs(),
                    "reboot deadman FIRED — teardown overran its deadline; resetting anyway"
                );
            }
        });
    if let Err(e) = spawned {
        tracing::error!(phase, error = %e, "could not spawn the reboot deadman — a wedged teardown will NOT reset");
    }
}

/// Arm the reboot deadman and hand back the once-guarded reset that the normal
/// path must fire through. Call BEFORE any teardown work: from that point the
/// node resets within [`REBOOT_DEADLINE`] no matter what wedges.
///
/// `pre_reboot` is the deployment's bounded last-chance hook (see [`PreReboot`]);
/// it runs on whichever path actually fires, deadman included, which is the point
/// — the wedged path is exactly the one where losing the RAM log window hurts.
pub fn arm_reboot_deadman(phase: &'static str, pre_reboot: PreReboot) -> Arc<OnceReset> {
    let reset = OnceReset::new(Arc::new(move || {
        if let Err(e) = reboot_host(pre_reboot.clone()) {
            tracing::error!(phase, "kernel-direct reboot failed: {e}");
        }
    }));
    tracing::warn!(
        phase,
        deadline_secs = REBOOT_DEADLINE.as_secs(),
        "reboot deadman armed — the node resets by this deadline even if teardown wedges"
    );
    spawn_reboot_deadman(reset.clone(), REBOOT_DEADLINE, phase);
    reset
}

#[cfg(test)]
mod tests {
    use super::{spawn_reboot_deadman, OnceReset};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// A reset that counts instead of resetting the board.
    fn counting_reset() -> (Arc<OnceReset>, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        (
            OnceReset::new(Arc::new(move || {
                h.fetch_add(1, Ordering::SeqCst);
            })),
            hits,
        )
    }

    #[test]
    fn deadman_fires_when_teardown_blocks_past_the_deadline() {
        let (reset, hits) = counting_reset();
        spawn_reboot_deadman(reset, Duration::from_millis(100), "test");
        // The "teardown" never fires — the wedge case.
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(hits.load(Ordering::SeqCst), 1, "deadman reset the node");
    }

    #[test]
    fn fast_teardown_resets_once_and_the_deadman_stays_quiet() {
        let (reset, hits) = counting_reset();
        spawn_reboot_deadman(reset.clone(), Duration::from_millis(200), "test");
        assert!(reset.fire(), "the teardown path fired the reset");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        // Past the deadline: the deadman woke, found it already fired, did nothing.
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(hits.load(Ordering::SeqCst), 1, "no second reset");
    }

    #[test]
    fn racing_paths_reset_exactly_once() {
        let (reset, hits) = counting_reset();
        // Deadman deadline ~now, plus a pack of "teardown finished" callers: all
        // of them race, exactly one wins.
        spawn_reboot_deadman(reset.clone(), Duration::from_millis(50), "test");
        let winners: usize = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let reset = reset.clone();
                    s.spawn(move || {
                        std::thread::sleep(Duration::from_millis(50));
                        usize::from(reset.fire())
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).sum()
        });
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(hits.load(Ordering::SeqCst), 1, "exactly one reset");
        assert!(winners <= 1, "at most one caller claimed the fire");
    }
}
