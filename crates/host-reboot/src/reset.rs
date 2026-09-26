//! The reset itself: acquire the per-thread privileges QNX wants, run the
//! deployment's pre-reboot hook, flush, then message procnto directly.

use std::sync::Arc;
#[cfg(target_os = "nto")]
use std::time::Duration;

/// Work the deployment needs done on the reset thread — after the privileges are
/// acquired, before the board resets.
///
/// This exists because the reset is kernel-direct: `sysmgr_reboot` sends no
/// signals and runs no process sweep, so anything that has to be told "we are
/// about to go down" has to be told here, by us. What that *is* differs per
/// deployment — supernova seals its sibling slog2-drainer's RAM live file to
/// flash, a node with no drainer has nothing to do — and encoding one
/// deployment's process topology into this crate would make every node that
/// merely wants a reset primitive inherit it. So it is injected.
///
/// **The hook must be bounded.** It runs on the path to the reset, so a hook
/// that blocks is a node that does not reboot — which is the failure this whole
/// module exists to prevent. Bound it internally; nothing here will interrupt it.
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

    #[cfg(target_os = "nto")]
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

/// Reboot the host with a KERNEL-DIRECT reset — no `shutdown` process sweep.
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
/// P1 (field, 2026-08-16): `sysmgr_reboot`'s privileged path intermittently faulted
/// — taking the PROCESS down instead of the BOARD (202 sent, then a pid jump with
/// BootTime unchanged and no error log) — whenever the calling thread lacked I/O
/// privity. QNX I/O privity is PER-THREAD (`ThreadCtl(_NTO_TCTL_IO)`), and callers
/// run this from a detached async task that lands on an ARBITRARY worker thread. So
/// the reset runs on a DEDICATED `std::thread` that first acquires the privileges
/// explicitly (`ThreadCtl(_NTO_TCTL_IO)` + `procmgr_ability(PROCMGR_AID_REBOOT)`;
/// root MAY reboot via ABLE_ALLOW_ROOT, but we acquire it deliberately), logs a
/// last-line witness, and on failure falls back to `shutdown -f -b` — never taking
/// the process down itself. Fire-and-forget: returns `Ok(())` once the reset thread
/// is spawned (callers are already fire-and-forget after their 202).
#[cfg(target_os = "nto")]
pub fn reboot_host(pre_reboot: PreReboot) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("reboot".into())
        // catch_unwind: a panic on the reset thread must never unwind into the FFI or
        // abort the process — swallow it and leave a log line.
        .spawn(move || {
            // `AssertUnwindSafe` because `PreReboot` holds an `Arc<dyn Fn()>`,
            // which is not `RefUnwindSafe`. Sound here: if the hook unwinds, this
            // thread logs and dies, and nothing on it observes the hook again. The
            // other holder of the same `Arc` can only call it through `Fn`
            // (immutable captures), so there is no half-updated state for it to
            // see that the hook did not create for itself.
            let run = std::panic::AssertUnwindSafe(move || reboot_now(&pre_reboot));
            if std::panic::catch_unwind(run).is_err() {
                tracing::error!("reboot thread panicked before reset — process left alive");
            }
        })?;
    Ok(())
}

/// The privileged kernel-direct reset, run on its own thread (see [`reboot_host`]).
/// Acquires the per-thread privileges `sysmgr_reboot` needs, then resets. Returns only
/// if the reset FAILED to fire (then falls back to `shutdown`); on success the board
/// resets and control never returns. NEVER exits the process itself.
#[cfg(target_os = "nto")]
pub fn reboot_now(pre_reboot: &PreReboot) {
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
    let rc = unsafe { procmgr_ability(0, PROCMGR_AOP_ALLOW | PROCMGR_AID_REBOOT, PROCMGR_AID_EOL) };
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
    let hook_started = std::time::Instant::now();
    pre_reboot.run();
    let hook_ms = hook_started.elapsed();
    if hook_ms > Duration::from_secs(5) {
        tracing::warn!(
            elapsed_ms = hook_ms.as_millis(),
            "pre-reboot hook overran its budget — it must be bounded"
        );
    }
    // Flush filesystem buffers — sysmgr_reboot does not run `shutdown`'s sync path.
    unsafe { libc::sync() };
    // Last-line witness, emitted synchronously to slog2 BEFORE the call so a fault is
    // diagnosable from the log tail (the QNX slog2 recorder writes the ring inline).
    tracing::warn!("invoking sysmgr_reboot tid={}", unsafe { libc::gettid() });
    // Kernel-direct reset. Never returns on success.
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

/// Non-QNX (dev / emulated-container / host tests): there is no kernel-direct reset
/// syscall, and this path is unreachable in practice on the deployments that have
/// one — the emulated container has no activator component, so the graceful
/// re-exec branch handles the node "reset". Exists only so the shared reboot
/// callsites compile off QNX.
#[cfg(not(target_os = "nto"))]
pub fn reboot_host(_pre_reboot: PreReboot) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "kernel-direct reboot is QNX-only (no activator component on this platform)",
    ))
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

    /// `run()` is `cfg(nto)`-only (it is only ever called from the QNX reset
    /// path), so exercise the closure through the `Arc` directly: a cloned
    /// `PreReboot` must invoke the SAME hook, not a copy — both call sites clone
    /// it and either may be the one that fires.
    #[test]
    fn a_clone_shares_the_one_hook() {
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let a = PreReboot::new(move || {
            h.fetch_add(1, Ordering::SeqCst);
        });
        let b = a.clone();
        (a.0.as_ref().unwrap())();
        (b.0.as_ref().unwrap())();
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }
}
