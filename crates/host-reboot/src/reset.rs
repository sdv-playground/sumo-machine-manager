//! The reset itself: the deployment's bounded last-chance hook, the dedicated
//! thread every mechanism runs on, and the two mechanisms this crate ships.

use std::sync::Arc;
use std::time::Duration;

use machine_contract::HostReboot;

/// Work the deployment needs done on the reset thread — after the privileges are
/// acquired, before the board resets.
///
/// This exists because the reset is kernel-direct: `sysmgr_reboot` sends no
/// signals and runs no process sweep, so anything that has to be told "we are
/// about to go down" has to be told here, by us. What that *is* differs per
/// deployment — one host manager seals its sibling log drainer's RAM live file
/// to flash, a node with no drainer has nothing to do — and encoding one
/// deployment's process topology into this crate would make every node that
/// merely wants a reset primitive inherit it. So it is injected.
///
/// **The hook must be bounded.** It runs on the path to the reset, so a hook
/// that blocks is a node that does not reboot — which is the failure this whole
/// module exists to prevent. Bound it internally; nothing here will interrupt it.
///
/// Carried by the [`HostReboot`] implementation, not by the deadman: what has to
/// be persisted before the node stops being a node is a fact about the node, and
/// the deadman's job is timing, not content.
#[derive(Clone, Default)]
pub struct PreReboot(Option<Arc<dyn Fn() + Send + Sync>>);

impl PreReboot {
    /// Run `f` on the reset thread just before the board resets. Must be bounded.
    pub fn new(f: impl Fn() + Send + Sync + 'static) -> Self {
        Self(Some(Arc::new(f)))
    }

    /// Nothing to do before the reset — the same as [`PreReboot::default`], named
    /// so a call site can say so out loud.
    pub fn none() -> Self {
        Self(None)
    }

    fn run(&self) {
        if let Some(hook) = self.0.as_ref() {
            hook();
        }
    }
}

impl std::fmt::Debug for PreReboot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PreReboot")
            .field(&if self.0.is_some() { "set" } else { "none" })
            .finish()
    }
}

/// Run the deployment's hook, and leave evidence if it overran.
///
/// Shared by both mechanisms below, because the reason is the same for both: the
/// hook is the last thing that runs before the node stops being a node, and a
/// hook that blocks is a node that does not reset. Nothing here can interrupt it
/// — the warning is the only evidence anyone gets, so it is emitted on the way
/// past rather than saved for a caller that may never exist.
fn run_hook(pre_reboot: &PreReboot) {
    let started = std::time::Instant::now();
    pre_reboot.run();
    let elapsed = started.elapsed();
    if elapsed > Duration::from_secs(5) {
        tracing::warn!(
            elapsed_ms = elapsed.as_millis(),
            "pre-reboot hook overran its budget — it must be bounded"
        );
    }
}

/// Fire `reboot` on a dedicated thread that cannot take the process down.
///
/// P1 (field, 2026-08-16): the QNX reset's privileged path intermittently faulted
/// — taking the PROCESS down instead of the BOARD (202 sent, then a pid jump with
/// BootTime unchanged and no error log) — whenever the calling thread lacked I/O
/// privity. QNX I/O privity is PER-THREAD, and callers run this from a detached
/// async task that lands on an ARBITRARY worker thread. So the reset always runs
/// on a DEDICATED `std::thread`, and the mechanism acquires whatever per-thread
/// privileges it needs there. The thread is the crate's guarantee, not the
/// mechanism's: a board that brings its own [`HostReboot`] inherits it.
///
/// Fire-and-forget: returns `Ok(())` once the reset thread is SPAWNED (callers are
/// already fire-and-forget after their 202), so the only `Err` here is a thread
/// that could not be created. A mechanism that fails, or panics, is a log line on
/// that thread and nothing more — the process stays alive either way, which is
/// what lets the deadman keep its own deadline meaningful.
pub fn reboot_host(reboot: Arc<dyn HostReboot>) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("reboot".into())
        // catch_unwind: a panic on the reset thread must never unwind into the FFI or
        // abort the process — swallow it and leave a log line.
        .spawn(move || {
            // `AssertUnwindSafe` because the implementation is held behind an
            // `Arc` and typically owns an `Arc<dyn Fn()>` hook, which is not
            // `RefUnwindSafe`. Sound here: if it unwinds, this thread logs and
            // dies, and nothing on it observes the implementation again. The
            // other holder of the same `Arc` can only call it through `&self`,
            // so there is no half-updated state for it to see that the
            // implementation did not create for itself.
            let run = std::panic::AssertUnwindSafe(move || reboot.reboot());
            match std::panic::catch_unwind(run) {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::error!(error = %e, "the node reset could not even be requested — process left alive")
                }
                Err(_) => {
                    tracing::error!("reboot thread panicked before reset — process left alive")
                }
            }
        })?;
    Ok(())
}

/// QNX: reset the board with a KERNEL-DIRECT `sysmgr_reboot()` — no `shutdown`
/// process sweep.
///
/// ROOT CAUSE of the intermittent reboot hang (captured in a shutdown trace,
/// 2026-08-01): the machine manager, its log drainer and its start script all run
/// FROM the `devb-loopback` filesystem mounted over the OS bank (the bank is a
/// loopback of an eMMC partition). QNX `shutdown` SIGTERMs then SIGKILLs every
/// process — but a process demand-paged from a filesystem whose pager
/// (devb-loopback → devb-sdmmc) dies FIRST during teardown blocks uninterruptibly
/// on the dead pager, so the SIGKILL never completes and `shutdown` waits forever
/// (the trace froze mid-`pidin` at post-reboot t=2s). It's a teardown ORDERING
/// race → intermittent.
///
/// Fix: bypass userland teardown entirely. `sync` to flush filesystem buffers,
/// then the QNX Neutrino `sysmgr_reboot()` syscall (`<sys/sysmgr.h>`) — procnto
/// resets the board directly, with no process sweep to deadlock on the loopback
/// pager. Callers stop their guests first (where they have any) so guest images
/// flush.
///
/// Acquires the per-thread privileges the syscall needs — `ThreadCtl(_NTO_TCTL_IO)`
/// and `procmgr_ability(PROCMGR_AID_REBOOT)`; root MAY reboot via ABLE_ALLOW_ROOT,
/// but we acquire it deliberately — on whichever thread [`reboot_host`] gave it,
/// logs a last-line witness, and on failure falls back to `shutdown -f -b`,
/// NEVER taking the process down itself.
#[cfg(target_os = "nto")]
pub struct QnxSysmgrReboot {
    pre_reboot: PreReboot,
}

#[cfg(target_os = "nto")]
impl QnxSysmgrReboot {
    /// `pre_reboot` is the deployment's bounded last-chance hook — see
    /// [`PreReboot`]. It runs after the privileges are acquired and before the
    /// `sync`, so whatever it writes is flushed.
    pub fn new(pre_reboot: PreReboot) -> Self {
        Self { pre_reboot }
    }
}

#[cfg(target_os = "nto")]
impl HostReboot for QnxSysmgrReboot {
    fn reboot(&self) -> std::io::Result<()> {
        // I/O privity is PER-THREAD; acquire it on THIS thread or the reset can fault.
        if unsafe {
            libc::ThreadCtl(
                libc::_NTO_TCTL_IO as std::os::raw::c_int,
                std::ptr::null_mut(),
            )
        } != 0
        {
            tracing::warn!(
                errno = %std::io::Error::last_os_error(),
                "ThreadCtl(_NTO_TCTL_IO) failed — sysmgr_reboot may fault"
            );
        }
        // Deliberately enable PROCMGR_AID_REBOOT for this process (root MAY via
        // ABLE_ALLOW_ROOT — acquire it explicitly rather than relying on the default).
        // procmgr_ability returns EOK(0) or an errno; log both the rc and errno on failure.
        let rc =
            unsafe { procmgr_ability(0, PROCMGR_AOP_ALLOW | PROCMGR_AID_REBOOT, PROCMGR_AID_EOL) };
        if rc != 0 {
            tracing::warn!(
                rc,
                errno = %std::io::Error::last_os_error(),
                "procmgr_ability(ALLOW REBOOT) failed — reboot may be denied"
            );
        }
        // The deployment's last chance to persist anything that lives in RAM: the reset
        // below is kernel-direct (no process sweep, no signals), so nothing else will
        // get told. Bounded by the hook itself — see `PreReboot`. The `sync` immediately
        // after flushes whatever it just wrote.
        run_hook(&self.pre_reboot);
        // Flush filesystem buffers — sysmgr_reboot does not run `shutdown`'s sync path.
        unsafe { libc::sync() };
        // Last-line witness, emitted synchronously to slog2 BEFORE the call so a fault is
        // diagnosable from the log tail (the QNX slog2 recorder writes the ring inline).
        tracing::warn!("invoking sysmgr_reboot tid={}", unsafe { libc::gettid() });
        // Kernel-direct reset. Never returns on success — so there is no `Ok` path
        // out of this function.
        unsafe { sysmgr_reboot() };
        // Returned ⇒ the reset did not fire. Belt-and-braces: spawn `shutdown -f -b`
        // (spawn, NEVER .status() — the QNX reboot-spawn rule). NEVER take the process
        // down ourselves.
        tracing::error!(
            errno = %std::io::Error::last_os_error(),
            "sysmgr_reboot returned (reset did not fire) — falling back to `shutdown -f -b`"
        );
        match std::process::Command::new("shutdown")
            .arg("-f")
            .arg("-b")
            .spawn()
        {
            Ok(child) => tracing::warn!(pid = child.id(), "spawned `shutdown -f -b` fallback"),
            Err(e) => {
                tracing::error!(error = %e, "`shutdown -f -b` fallback spawn failed — host will NOT reboot")
            }
        }
        Err(std::io::Error::other(
            "sysmgr_reboot returned; shutdown fallback spawned",
        ))
    }
}

// QNX Neutrino privileged calls not declared by the `libc` crate; the symbols live in
// the system libc we already link.
//   sysmgr_reboot()   <sys/sysmgr.h>:38   — messages procnto to reset the board.
//   procmgr_ability() <sys/procmgr.h>:254 — variadic: (pid, AOP|AID, …, AID_EOL);
//                     grants/denies process abilities.
#[cfg(target_os = "nto")]
extern "C" {
    fn sysmgr_reboot() -> std::os::raw::c_int;
    fn procmgr_ability(pid: libc::pid_t, ability: std::os::raw::c_uint, ...)
        -> std::os::raw::c_int;
}

// <sys/procmgr.h> ability op + ids (values verified against the QNX SDP 7.1 header).
#[cfg(target_os = "nto")]
const PROCMGR_AOP_ALLOW: std::os::raw::c_uint = 0x0002_0000; // procmgr.h:163
#[cfg(target_os = "nto")]
const PROCMGR_AID_REBOOT: std::os::raw::c_uint = 6; // procmgr.h:91
#[cfg(target_os = "nto")]
const PROCMGR_AID_EOL: std::os::raw::c_uint = 0xffff; // PROCMGR_AID_MASK, procmgr.h:158

/// Nodes whose "reset" is a process restart: run the hook, then exit and let an
/// external supervisor bring the node back.
///
/// For a node started by a `while true` wrapper — a container entrypoint, a start
/// script, any respawner that treats an exit as "start me again". There is no
/// kernel-direct reset to reach for and no board to cycle; re-entering the
/// process from its first line IS the node's reset, so the mechanism is
/// `std::process::exit`.
///
/// `exit_code` is what the supervisor sees. The deployment's graceful-shutdown
/// signalling — telling guests, peers or a parent that this node is going away —
/// belongs in the [`PreReboot`] hook, exactly as it does on QNX: this crate
/// knows the mechanism, never the topology.
pub struct ExitRespawnReboot {
    pre_reboot: PreReboot,
    exit_code: i32,
}

impl ExitRespawnReboot {
    /// `pre_reboot` is the deployment's bounded last-chance hook (see
    /// [`PreReboot`]); `exit_code` is the status handed to the supervisor.
    pub fn new(pre_reboot: PreReboot, exit_code: i32) -> Self {
        Self {
            pre_reboot,
            exit_code,
        }
    }
}

impl HostReboot for ExitRespawnReboot {
    fn reboot(&self) -> std::io::Result<()> {
        run_hook(&self.pre_reboot);
        // Last-line witness before the process is gone, for the same reason the
        // QNX arm emits one: whatever comes after this is a different process.
        tracing::warn!(
            exit_code = self.exit_code,
            "exiting for the respawn supervisor to bring the node back"
        );
        // Diverges — there is no `Ok` path out of this function either.
        std::process::exit(self.exit_code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// `PreReboot` is the injected seam, so it must survive the trip into the
    /// reset thread: `Clone` (both call sites hold one), `Send + Sync + 'static`.
    /// A compile-time assertion, because the failure mode is a build break at the
    /// consumer, not a test failure here.
    #[test]
    fn pre_reboot_is_shareable() {
        fn assert_shareable<T: Clone + Send + Sync + 'static>() {}
        assert_shareable::<PreReboot>();
    }

    /// The default is "nothing to do" — a node with no RAM state to seal wires
    /// nothing and must not be forced to invent a no-op closure.
    #[test]
    fn default_and_none_carry_no_hook() {
        assert!(PreReboot::default().0.is_none());
        assert!(PreReboot::none().0.is_none());
        assert!(PreReboot::new(|| {}).0.is_some());
    }

    /// A cloned `PreReboot` must invoke the SAME hook, not a copy — the
    /// implementation owns one and a deployment that builds two implementations
    /// from one hook must not get two hooks.
    #[test]
    fn a_clone_shares_the_one_hook() {
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let a = PreReboot::new(move || {
            h.fetch_add(1, Ordering::SeqCst);
        });
        let b = a.clone();
        a.run();
        b.run();
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    /// `run_hook` is what makes an unbounded hook visible; an empty one must cost
    /// nothing and warn about nothing.
    #[test]
    fn a_missing_hook_is_a_no_op() {
        run_hook(&PreReboot::none());
    }

    /// `ExitRespawnReboot::reboot` ends in `std::process::exit`, which cannot be
    /// observed from inside the process that calls it — so observe it from
    /// outside. The parent re-execs this test binary with a marker in the
    /// environment; the child takes the branch below, runs the real mechanism,
    /// and the parent asserts on what it left behind: exit code 7 (the mechanism
    /// reached the exit with the configured status) and `HOOK-RAN` on stderr (the
    /// hook ran BEFORE it). Ordering and code in one observation, which is the
    /// only way to get either.
    #[test]
    fn exit_respawn_runs_the_hook_then_exits_with_the_code() {
        const MARKER: &str = "HOST_REBOOT_TEST_CHILD";
        const TEST_PATH: &str = "reset::tests::exit_respawn_runs_the_hook_then_exits_with_the_code";

        if std::env::var_os(MARKER).is_some() {
            let _ = ExitRespawnReboot::new(PreReboot::new(|| eprintln!("HOOK-RAN")), 7).reboot();
            unreachable!("ExitRespawnReboot::reboot returned instead of exiting");
        }

        let exe = std::env::current_exe().expect("this test binary's own path");
        let out = std::process::Command::new(exe)
            // `--nocapture` so the child's hook writes to the real stderr rather
            // than libtest's per-test capture buffer, which the exit discards.
            .args(["--exact", TEST_PATH, "--nocapture"])
            .env(MARKER, "1")
            .output()
            .expect("re-exec this test binary as the child");

        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(7),
            "the child exited with the configured code; stderr: {stderr}"
        );
        assert!(
            stderr.contains("HOOK-RAN"),
            "the hook ran before the exit; stderr: {stderr}"
        );
    }
}
