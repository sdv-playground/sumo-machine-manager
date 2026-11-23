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
//! - [`sovd_router`] — SOVDd's router, the binary's vendor routes and the
//!   node-level routes (`status/x-boot-id`, the node status, `status/restart`
//!   with [`restart_route`] and the shape of its 202 in [`restart_response`],
//!   the legacy restart-status stub, the factory-reset route), in the node
//!   topology; [`capability_extensions`] documents the `/v1`-only ones.
//! - [`SovdListener`] — HTTPS from the HSM-held tls-identity leaf (else HTTP),
//!   the mDNS advertisement on either transport, and serving until the
//!   binary's shutdown [`Notify`](tokio::sync::Notify) fires, then a drain
//!   capped at 5 s and the DNS-SD goodbye; [`shutdown_on_signals`] fires it on
//!   SIGTERM / SIGINT. A reset that ends the process without that notify sends
//!   the goodbye itself, through [`SovdListener::advertisement`].
//! - `reset` (feature `factory-reset`, on by default) — the factory-reset
//!   engine: the authorized, ordered wipe, its response and the handler for
//!   the router's factory-reset slot; the node's device comes in through
//!   `reset::ResetHooks`.
//!
//! Nothing here knows a device: no paths, no reset primitive, no board. What a
//! binary supplies is its device: the backends, the vendor routes it merges,
//! the boot id, the HSM, the authorizer and action of its restart, its
//! factory-reset hooks (what to wipe, its before-wipe work, how its guests stop
//! and how it shuts down), and the shutdown it cleans up after.
//!
//! ```no_run
//! # use std::{collections::HashMap, sync::Arc};
//! # use sovd_core::DiagnosticBackend;
//! # async fn wire(
//! #     cfg: node_shell::ShellConfig, // `#[serde(flatten)]` in the binary's config
//! #     machine: Arc<dyn machine_mgr::Machine>,
//! #     backends: HashMap<String, Arc<dyn DiagnosticBackend>>,
//! #     vendor: axum::Router, // the vendor routes the binary merges in
//! #     boot_id: String,
//! #     crypto: Arc<dyn hsm::HsmCryptoProvider>,
//! #     restart_authz: Arc<dyn sovd_api::Authorizer>,
//! # ) {
//! let ecu_id = node_shell::read_ecu_id(&cfg, machine.as_ref()).await;
//! let identification = node_shell::configured_identification(&cfg, ecu_id.as_deref());
//! let node = node_shell::node_topology(&cfg, identification.as_deref());
//! let state = node_shell::sovd_state(backends, node).expect("SOVD node refused");
//! // The binary's own capability rows (here none) plus the shell's `/v1`-only ones.
//! let state = state.with_capability_extensions(node_shell::capability_extensions(
//!     sovd_api::CapabilityExtensions::default(),
//! ));
//!
//! let shutdown = Arc::new(tokio::sync::Notify::new());
//! node_shell::shutdown_on_signals(shutdown.clone());
//! // The device's reset: schedule the teardown and the reboot, return the message.
//! let reset: Arc<dyn Fn() -> &'static str + Send + Sync> =
//!     Arc::new(|| "ECU restart initiated");
//! let no_factory_reset: Option<fn(&str) -> axum::routing::MethodRouter> = None;
//! let router = node_shell::sovd_router(&state, vendor, &boot_id, no_factory_reset, |tree| {
//!     node_shell::restart_route(tree, restart_authz.clone(), reset.clone())
//! });
//!
//! let listener = node_shell::SovdListener::bind(&cfg, &crypto, identification.as_deref())
//!     .await
//!     .unwrap_or_else(|e| panic!("{e}"));
//! tracing::info!("listening on {} (tls: {})", cfg.bind, listener.is_tls());
//! // A reset path that never returns from serve calls `withdraw()` before it fires.
//! let _advertisement = listener.advertisement();
//! listener.serve(router, shutdown).await.unwrap();
//! // ... the binary's cleanup; the DNS-SD goodbye has already been sent.
//! # }
//! ```

mod config;
mod identity;
#[cfg(feature = "factory-reset")]
pub mod reset;
mod router;
mod serve;

pub use config::{NodeConfig, ShellConfig};
pub use identity::{
    configured_identification, node_topology, prefixed_identification, read_ecu_id, sovd_state,
};
pub use router::{
    auth_error_message, capability_extensions, restart_response, restart_route, sovd_router,
};
pub use serve::{shutdown_on_signals, Advertisement, SovdListener};
