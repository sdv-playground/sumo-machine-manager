//! node-shell — the SOVD node application shell.
//!
//! Every node binary (a host machine manager, a guest's SOVD server) wraps its
//! components in the same server: the config keys that say how it is reached
//! and who it is, the identification mDNS advertises, the `/v1` node its
//! backends are served under. That shell used to be hand-assembled in each
//! binary's `main.rs`; it lives here, and the binary keeps only its device
//! facts and wires it.
//!
//! - [`ShellConfig`] — the shell's top-level config keys (`bind`, `sovd_tls`,
//!   `sovd_mdns`, `identification`, `identification_prefix`, `node`), embedded in
//!   the binary's config with `#[serde(flatten)]`.
//! - [`read_ecu_id`], [`configured_identification`], [`node_topology`],
//!   [`sovd_state`] — the identification and the node, then the SOVD state over
//!   the binary's backends.
//!
//! Nothing here knows a device: no paths, no reset primitive, no board.

mod config;
mod identity;

pub use config::{NodeConfig, ShellConfig};
pub use identity::{
    configured_identification, node_topology, prefixed_identification, read_ecu_id, sovd_state,
};
