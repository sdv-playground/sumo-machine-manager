//! Spawn a *local test* link-B backend and connect a [`LinkBClient`] to it.
//!
//! This is a **test/dev convenience**, not the harness's production path: the
//! `hsm-conformance` bin connects to an already-running backend (how that backend
//! is launched is the operator's concern). This helper exists so the conformance
//! tests can bring up the two reference backends they check — `hsm-sim-service`
//! and the compiled C skeleton — over a throwaway socket.
//!
//! It is a near-verbatim copy of `vhsm-ssd`'s `backend::spawn_and_connect`
//! (`crates/vhsm-ssd/src/backend.rs`), with one difference: the keystore argument
//! is **optional**. The software sim (`hsm-sim-service`) requires `--keystore`;
//! the C reference skeleton keeps its keys in its (hypothetical) slot map and
//! takes only `--listen`. Both must spawn, so `--keystore` is omitted when `None`.
//!
//! DRY follow-up: this duplicates vhsm-ssd's helper. The right home for a single
//! shared `spawn_and_connect` is `hsm::link_b` (next to `LinkBClient` itself), so
//! both vhsm-ssd and this harness call one implementation. That consolidation is
//! intentionally left out of scope here (it touches vhsm-ssd); this crate carries
//! its own copy for now.

use std::io;
use std::path::Path;
use std::process::{Child, Command};
use std::time::Duration;

use hsm::link_b::LinkBClient;

/// Retry budget for the post-spawn connect: ~5 s (50 × 100 ms) covers a cold
/// backend start without hanging forever on a wedged one.
const CONNECT_ATTEMPTS: u32 = 50;
const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(100);

/// Spawn link-B backend `backend_cmd` on the Unix socket `socket` and connect a
/// [`LinkBClient`] to it. Runs `backend_cmd --keystore <ks> --listen <socket>`
/// when `keystore` is `Some`, or `backend_cmd --listen <socket>` when `None`.
///
/// Removes any stale `socket` first (a crashed prior backend leaves the path
/// behind, which would `EADDRINUSE` the backend's own `bind()`). Retries the
/// connect while the child binds; if the child exits early (bad args / crash) it
/// is detected at once via `try_wait`. On timeout the child is killed + reaped so
/// a broken backend surfaces here rather than as mystery errors later.
///
/// Returns `(client, child)`. The caller MUST keep `child` alive for the
/// session: dropping the handle does not kill the process, but losing it forfeits
/// the ability to reap/kill it.
pub fn spawn_and_connect(
    backend_cmd: &Path,
    keystore: Option<&Path>,
    socket: &Path,
) -> io::Result<(LinkBClient, Child)> {
    // Clear a stale socket from a previous run so the backend's bind() and our
    // connect() both see a fresh path.
    if socket.exists() {
        std::fs::remove_file(socket).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("remove stale backend socket {}: {e}", socket.display()),
            )
        })?;
    }

    let mut cmd = Command::new(backend_cmd);
    if let Some(ks) = keystore {
        cmd.arg("--keystore").arg(ks);
    }
    cmd.arg("--listen").arg(socket);

    let mut child = cmd.spawn().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("spawn link-B backend {}: {e}", backend_cmd.display()),
        )
    })?;

    let mut last_err: Option<io::Error> = None;
    for attempt in 0..CONNECT_ATTEMPTS {
        // Fast-fail if the backend already exited (bad args, crash, keystore
        // perms) instead of waiting out the whole retry budget. `try_wait` reaps
        // it, so no kill is needed on this branch.
        if let Ok(Some(status)) = child.try_wait() {
            return Err(io::Error::other(format!(
                "link-B backend {} exited before binding {} ({status})",
                backend_cmd.display(),
                socket.display(),
            )));
        }

        match LinkBClient::connect(socket) {
            Ok(client) => return Ok((client, child)),
            Err(e) => {
                last_err = Some(e);
                // Don't sleep after the final attempt — we're about to give up.
                if attempt + 1 < CONNECT_ATTEMPTS {
                    std::thread::sleep(CONNECT_RETRY_DELAY);
                }
            }
        }
    }

    // Budget exhausted: the backend is alive but never accepted. Don't orphan it.
    let _ = child.kill();
    let _ = child.wait();
    let e = last_err.expect("CONNECT_ATTEMPTS >= 1 so at least one connect was tried");
    Err(io::Error::new(
        e.kind(),
        format!(
            "link-B backend {} never accepted on {} after {CONNECT_ATTEMPTS} attempts: {e}",
            backend_cmd.display(),
            socket.display(),
        ),
    ))
}
