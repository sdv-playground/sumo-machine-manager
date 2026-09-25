//! `hsm-supervisor` — spawn, supervise and reap a node's two HSM daemons.
//!
//! The HSM is an out-of-process link-B service (see
//! `docs/hsm-backend-architecture.md`), so every node's machine manager brings up
//! the same two children and owns their lifecycle:
//!
//! ```text
//!   machine manager
//!     ├── hsm-sim-service (or a vendor bridge)   ← link-B backend, serves the keystore
//!     │     ▲                    ▲
//!     │     │ LinkBClient        │ --backend-connect-only --backend-socket
//!     │     │ (this process)     │
//!     └── vhsm-ssd ──────────────┘               ← the proxy guests reach over /dev/vhsm
//! ```
//!
//! [`standup`] spawns the backend, connects (the connect is what proves it
//! bound), pre-creates the bootstrap state, then spawns the proxy in
//! connect-only mode against the same socket — reaping the backend rather than
//! orphaning it if the proxy cannot start. It returns the node's
//! `HsmProvider` (a `LinkBProvider` over the shared client) plus the owned
//! [`HsmDaemons`].
//!
//! # Why this is a library and not part of a machine manager
//!
//! Nothing here is board-specific. It is config→argv, plus liveness,
//! stale-endpoint reclaim and respawn. It lived in one board's `main.rs` until
//! there was a second board; a CVC, a CM5 and a DDU manager differ in their
//! guests, their boot vectors and their HSM *hardware*, but not in how the two
//! daemons are parented. Extracted 2026-09-25 from
//! `supernova-machine-manager/src/main.rs`.
//!
//! The crate is deliberately **dep-light** — `hsm`, `tracing`, `libc`, and
//! nothing else, enforced as an allowlist by `scripts/feature-matrix.sh`. A node
//! that needs to parent an HSM daemon must not have to link a SOVD server to do
//! it.
//!
//! # What a node still owns
//!
//! The deployment config. [`HsmSupervisorConfig`] is a plain struct with no
//! serde, because the useful *defaults* are board facts, not HSM facts: one
//! board's `bind` default is its private vdevpeer address, its `policy_dir`
//! default a bank-relative path under its own mount layout. The node keeps its
//! YAML surface and maps it in.
//!
//! # Lifecycle, and why there is no `Drop`
//!
//! [`HsmDaemons`] is held for the process lifetime and torn down with
//! [`HsmDaemons::shutdown`]. There is deliberately no `Drop` impl:
//! `std::process::exit` — which is how a machine manager ends, including on the
//! reboot path — does not run destructors, so a `Drop` would be a promise broken
//! exactly when it mattered, leaving both daemons orphaned with the port and
//! socket still bound. The stale-orphan reclaim in [`standup`] exists because
//! that case is real; explicit shutdown is what keeps it rare.

mod config;
mod daemons;

pub use config::{
    resolve_backend_cmd, resolve_backend_socket, resolve_daemon_bin, sibling_bin,
    HsmSupervisorConfig,
};
pub use daemons::{
    kill_stale_backend_if_socket_live, kill_stale_daemon_if_port_busy, respawn_vhsm, standup,
    terminate_child, vhsm_spawn_spec, HsmDaemons, VhsmSpawnSpec,
};
