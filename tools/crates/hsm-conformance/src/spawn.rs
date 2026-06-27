//! Spawn a *local test* link-B backend and connect a [`LinkBClient`] to it.
//!
//! This is a **test/dev convenience**, not the harness's production path: the
//! `hsm-conformance` bin connects to an already-running backend (how that backend
//! is launched is the operator's concern). This helper exists so the conformance
//! tests can bring up the two reference backends they check — `hsm-sim-service`
//! and the compiled C skeleton — over a throwaway socket.
//!
//! It is a thin wrapper over the single shared [`hsm::link_b::spawn_and_connect`]
//! — the consolidation the earlier DRY follow-up called for: both this harness
//! and `vhsm-ssd` now delegate to that one implementation. The only thing this
//! layer pins is the crate's preferred call shape — an **optional** keystore (the
//! software sim needs `--keystore`; the C reference skeleton keeps its keys in
//! its slot map and takes only `--listen`).

use std::io;
use std::path::Path;
use std::process::Child;

use hsm::link_b::{self, LinkBClient};

/// Spawn link-B backend `backend_cmd` on the Unix socket `socket` and connect a
/// [`LinkBClient`] to it. Runs `backend_cmd --keystore <ks> --listen <socket>`
/// when `keystore` is `Some`, or `backend_cmd --listen <socket>` when `None`.
///
/// Delegates to [`hsm::link_b::spawn_and_connect`]; see it for the stale-socket
/// cleanup, retry-while-binding, and early-exit detection. Returns
/// `(client, child)` — the caller MUST keep `child` alive for the session.
pub fn spawn_and_connect(
    backend_cmd: &Path,
    keystore: Option<&Path>,
    socket: &Path,
) -> io::Result<(LinkBClient, Child)> {
    link_b::spawn_and_connect(backend_cmd, keystore, socket)
}
