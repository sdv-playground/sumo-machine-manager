//! Out-of-process link-B HSM backend: spawn + connect.
//!
//! Stage 3 of the link-B HSM refactor. `vhsm-ssd` no longer owns an in-process
//! `SimHsm`; instead it spawns a backend *service* — `hsm-sim-service` in dev, a
//! vendor HSM bridge in production — that serves crypto over a **link-B** Unix
//! socket, and reaches it through a [`LinkBClient`]. That makes `vhsm-ssd` a pure
//! A→B proxy: it terminates the guest vHSM wire + IAM on side A and forwards
//! every crypto op over link-B on side B.
//!
//! See `crates/hsm/src/link_b.rs` (the wire glue + `LinkBClient`) and
//! `crates/hsm/src/bin/hsm-sim-service.rs` (the dev backend) for the other end.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

use hsm::link_b::LinkBClient;

/// Retry budget for the post-spawn link-B connect. The backend binds its socket
/// early in startup, but process spawn + bind isn't instant; ~5 s (50 × 100 ms)
/// covers a cold start without hanging the daemon forever on a slow backend.
const CONNECT_ATTEMPTS: u32 = 50;
const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(100);

/// Default backend command: the `hsm-sim-service` binary sitting beside our own
/// executable. In a normal install vhsm-ssd and its dev backend ship in the same
/// directory; `--backend-cmd` overrides to point at a vendor bridge elsewhere.
pub fn default_backend_cmd() -> io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "current_exe has no parent directory",
        )
    })?;
    Ok(dir.join("hsm-sim-service"))
}

/// Spawn the link-B backend `backend_cmd` (serving `keystore` on the Unix socket
/// `socket`) and connect a [`LinkBClient`] to it.
///
/// Removes any stale `socket` file first — a crashed prior backend leaves the
/// path behind, which would EADDRINUSE the backend's own `bind()` (and a connect
/// to a dead path can't succeed anyway). Spawns
/// `backend_cmd --keystore <keystore> --listen <socket>`, then retries the
/// connect for the [`CONNECT_ATTEMPTS`] budget while the child binds. If the
/// child exits early (bad args / crash) it is detected at once via `try_wait`;
/// if it stays up but never binds, the budget runs out. Either failure kills +
/// reaps the child and returns an error, so a broken backend surfaces at startup
/// rather than as mystery `KeyNotFound` errors later.
///
/// Returns `(client, child)`. The caller MUST keep `child` alive for the
/// daemon's lifetime: dropping the handle does not kill the process, but losing
/// it forfeits the ability to reap/kill it.
pub fn spawn_and_connect(
    backend_cmd: &Path,
    keystore: &Path,
    socket: &Path,
) -> io::Result<(LinkBClient, Child)> {
    // Clear a stale socket from a previous run so the backend's bind() and our
    // connect() both see a fresh path (mirrors hsm-sim-service's own cleanup).
    if socket.exists() {
        std::fs::remove_file(socket).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("remove stale backend socket {}: {e}", socket.display()),
            )
        })?;
    }

    let mut child = Command::new(backend_cmd)
        .arg("--keystore")
        .arg(keystore)
        .arg("--listen")
        .arg(socket)
        .spawn()
        .map_err(|e| {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A backend command that exits immediately without ever binding the socket
    /// must be detected and surfaced as an error — fast (via `try_wait`), not
    /// after the full retry budget. `/bin/true` ignores our `--keystore` /
    /// `--listen` args and exits 0 at once, so it stands in for a crashed/broken
    /// backend. Proves the failure/cleanup branch with no dependency on a real
    /// backend bin.
    #[test]
    fn errors_when_backend_exits_before_binding() {
        let true_bin = Path::new("/bin/true");
        if !true_bin.exists() {
            eprintln!("SKIP: /bin/true not present on this host");
            return;
        }
        let dir = std::env::temp_dir().join(format!(
            "vhsm-backend-timeout-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir tempdir");
        let socket = dir.join("never-bound.sock");

        // `LinkBClient` isn't `Debug`, so match rather than `expect_err`.
        let err = match spawn_and_connect(true_bin, &dir, &socket) {
            Ok(_) => panic!("a backend that never binds must error out"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("exited before binding"),
            "expected an early-exit error, got: {err}"
        );
        assert!(
            !socket.exists(),
            "the backend never bound, so the socket must not exist"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
