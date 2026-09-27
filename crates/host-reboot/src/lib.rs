//! host-reboot — reset the node this process runs on, and guarantee it happens.
//!
//! ```text
//!   reboot requested
//!         │
//!         ▼
//!   arm_reboot_deadman(phase, reboot) ──► OnceReset  ──┐ whichever
//!         │                                            │ gets there
//!         └─► deadman thread: sleep(REBOOT_DEADLINE) ───┤ first wins
//!                                                      ▼
//!                                       reboot_host(Arc<dyn HostReboot>)
//!                                                      │ dedicated thread,
//!                                                      │ panic-contained
//!                                                      ▼
//!                                           HostReboot::reboot()
//!                          ┌───────────────────────┴───────────────────────┐
//!             QnxSysmgrReboot (cfg nto)                        ExitRespawnReboot
//!   ThreadCtl(_NTO_TCTL_IO) ─► procmgr_ability(REBOOT)          hook
//!             ─► hook ─► sync() ─► sysmgr_reboot()               ─► process::exit(code)
//!                        │                                          │
//!                (returned? ⇒ spawn `shutdown -f -b`)        (supervisor respawns)
//! ```
//!
//! # Why this is a library and not part of a machine manager
//!
//! Every node family needs the same guarantees, for reasons that have nothing to
//! do with the board: the reset must run on a thread of its own, a mechanism that
//! fails or panics must never take the process down, and a teardown that wedges
//! must still reset the node. That knowledge was living in one deployment's
//! `main.rs` — where a second node family could only get it by copying it, and
//! would copy the parts and not the reasons.
//!
//! **The mechanism is not the guarantee.** *How* a node resets — `sysmgr_reboot`
//! on QNX, a process exit under a respawn supervisor on an emulated node — is a
//! platform fact, so it is a seam: [`HostReboot`], defined in `machine-contract`
//! and passed to every entry point here. The deadman never learns which one it
//! holds, and a board with a third mechanism implements the trait instead of
//! forking the watchdog. The two this crate ships are the two the stack has.
//!
//! **QNX-specific is not board-specific.** Nothing here names a partition, a
//! mount point, a network or an OEM; the one `cfg(target_os = "nto")` arm is a
//! *kernel* distinction and covers exactly one implementation — not the deadman,
//! not the reset thread, not the hook.
//!
//! # The dep-light promise
//!
//! `machine-contract`, `libc` and `tracing`, nothing else — guarded as an
//! allowlist in `scripts/feature-matrix.sh`. A node that needs to reset itself
//! must not have to link a SOVD server, an async runtime or an OTA engine to do
//! it, and `machine-contract` is held to the same promise by its own guard.
//!
//! # What a node still owns
//!
//! - **Which mechanism it is.** `QnxSysmgrReboot` (cfg `nto`, so unlinked here)
//!   for a kernel-direct board reset, [`ExitRespawnReboot`] for a node whose
//!   reset is a process restart under an external supervisor, its own
//!   [`HostReboot`] impl for an OS neither fits. The board binary picks one and
//!   hands it in.
//! - **What to do before the reset.** Carried by that implementation as
//!   [`PreReboot`]: the reset tells nobody it is coming, so anything that must
//!   hear "we are going down" has to be told by the hook — a deployment with a
//!   sibling log drainer seals its RAM file to flash there. That is a *deployment
//!   topology* fact (a named sibling process started by a particular start
//!   script), so it is passed in, not compiled in.
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
// Re-exported so a board binary names one crate, not two, to wire a reset.
pub use machine_contract::HostReboot;
#[cfg(target_os = "nto")]
pub use reset::QnxSysmgrReboot;
pub use reset::{reboot_host, ExitRespawnReboot, PreReboot};
