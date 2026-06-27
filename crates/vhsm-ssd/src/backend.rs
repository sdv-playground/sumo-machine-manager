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
use std::process::Child;

use hsm::link_b::{self, LinkBClient};

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
/// Thin wrapper over the single shared [`hsm::link_b::spawn_and_connect`],
/// pinning `keystore` to `Some(..)` — vhsm-ssd's dev backend (`hsm-sim-service`)
/// always needs a keystore. See that function for the stale-socket cleanup,
/// retry-while-binding, and early-exit detection.
///
/// Returns `(client, child)`. The caller MUST keep `child` alive for the
/// daemon's lifetime: dropping the handle does not kill the process, but losing
/// it forfeits the ability to reap/kill it.
pub fn spawn_and_connect(
    backend_cmd: &Path,
    keystore: &Path,
    socket: &Path,
) -> io::Result<(LinkBClient, Child)> {
    link_b::spawn_and_connect(backend_cmd, Some(keystore), socket)
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
