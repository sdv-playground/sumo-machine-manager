//! System clock backed by CLOCK_MONOTONIC and CLOCK_REALTIME.

use super::Clock;

/// Real-time system clock.
///
/// Reads `clock_gettime(CLOCK_MONOTONIC)` for monotonic time and
/// computes wall offset from `CLOCK_REALTIME - CLOCK_MONOTONIC`.
pub struct SystemClock;

impl SystemClock {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now_mono_ns(&self) -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }

    fn wall_offset_ns(&self) -> i64 {
        let mut mono = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let mut real = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe {
            libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut mono);
            libc::clock_gettime(libc::CLOCK_REALTIME, &mut real);
        }
        let mono_ns = mono.tv_sec * 1_000_000_000 + mono.tv_nsec;
        let real_ns = real.tv_sec * 1_000_000_000 + real.tv_nsec;
        real_ns - mono_ns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_mono_is_nondecreasing() {
        let c = SystemClock::new();
        let t1 = c.now_mono_ns();
        let t2 = c.now_mono_ns();
        assert!(t2 >= t1, "mono clock went backwards: {t1} > {t2}");
    }

    #[test]
    fn system_clock_wall_now_is_plausible() {
        // Wall clock should be well past 2020-01-01 (1577836800 s).
        let c = SystemClock::new();
        let wall = c.now_wall_ns();
        assert!(
            wall > 1_577_836_800_000_000_000,
            "wall clock too low: {wall}"
        );
    }

    #[test]
    fn system_clock_default_constructs() {
        let _ = SystemClock;
        let _ = SystemClock;
    }
}
