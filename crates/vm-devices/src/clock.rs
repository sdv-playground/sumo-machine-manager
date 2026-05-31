//! Clock abstractions for device simulators.

pub mod gptp;
pub mod simulation;
pub mod system;

/// Clock source for device simulators.
///
/// All devices read time from a Clock, enabling simulation environments
/// to control time progression independently of wall-clock time.
pub trait Clock: Send + Sync {
    /// Current monotonic time in nanoseconds.
    fn now_mono_ns(&self) -> u64;

    /// Offset from monotonic to wall clock (UTC) in nanoseconds (signed).
    /// `wall_time_ns = now_mono_ns() as i64 + wall_offset_ns()`
    fn wall_offset_ns(&self) -> i64;

    /// Current wall time in nanoseconds since Unix epoch.
    fn now_wall_ns(&self) -> u64 {
        (self.now_mono_ns() as i64 + self.wall_offset_ns()) as u64
    }
}
