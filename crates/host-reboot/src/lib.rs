//! host-reboot — reset the node this process runs on, and guarantee it happens.
//!
//! ```text
//!   reboot requested
//!         │
//!         ▼
//!   arm_reboot_deadman(phase, pre_reboot) ──► OnceReset  ──┐ whichever
//!         │                                                │ gets there
//!         └─► deadman thread: sleep(REBOOT_DEADLINE) ───────┤ first wins
//!                                                          ▼
//!                                              reboot_host(pre_reboot)
//!                                                          │ dedicated thread
//!                                                          ▼
//!                       ThreadCtl(_NTO_TCTL_IO) ─► procmgr_ability(REBOOT)
//!                                 ─► pre_reboot hook ─► sync() ─► sysmgr_reboot()
//!                                                          │
//!                                                  (returned? ⇒ spawn
//!                                                   `shutdown -f -b`)
//! ```
//!
//! # Why this is a library and not part of a machine manager
//!
//! Every node family resets the same way, for reasons that have nothing to do
//! with the board: QNX I/O privity is per-thread, `sysmgr_reboot` faults without
//! it, `shutdown`'s process sweep deadlocks on a dead loopback pager, and a
//! teardown that wedges must still reset the node. That knowledge was living in
//! one deployment's `main.rs` — where a second node family could only get it by
//! copying it, and would copy the parts and not the reasons.
//!
//! **QNX-specific is not board-specific.** Nothing here names a partition, a
//! mount point, a network or an OEM; the two `cfg(target_os = "nto")` arms are a
//! *kernel* distinction, and the non-QNX arm exists only so shared call sites
//! compile on a dev host.
//!
//! # The dep-light promise
//!
//! `libc` and `tracing`, nothing else — guarded as an allowlist in
//! `scripts/feature-matrix.sh`. A node that needs to reset itself must not have
//! to link a SOVD server, an async runtime or an OTA engine to do it.
//!
//! # What a node still owns
//!
//! - **What to do before the reset.** Injected as [`PreReboot`]: the reset is
//!   kernel-direct, so anything that must be told "we are going down" has to be
//!   told by the hook. supernova seals its sibling log drainer's RAM file to
//!   flash there. That is a *deployment topology* fact (a named sibling process
//!   started by a particular start script), so it is passed in, not compiled in.
//! - **Board-specific diagnostics.** A trace of mounts, device nodes and pager
//!   processes is written in the deployment's own paths and stays there.
//! - **When to reboot at all**, and stopping its guests first.
//!
//! # Firing exactly once
//!
//! Two paths can reach the reset — the teardown that finished and the deadman
//! whose deadline expired — and they can genuinely race inside the window where
//! `sysmgr_reboot` has been called but has not yet landed. [`OnceReset`] makes
//! that window safe and keeps the "deadman FIRED" log line meaningful: it appears
//! only when the deadman really did beat a wedged teardown.

mod deadman;
mod reset;

pub use deadman::{arm_reboot_deadman, spawn_reboot_deadman, OnceReset, ResetFn, REBOOT_DEADLINE};
#[cfg(target_os = "nto")]
pub use reset::reboot_now;
pub use reset::{reboot_host, PreReboot};
