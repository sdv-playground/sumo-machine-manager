//! Backend selection for QNX (`target_os = "nto"`).
//!
//! On QNX the live DNS-SD backend is the hand-rolled, pure-Rust [`responder`]
//! (`simple-dns` + `socket2`) — `mdns-sd`'s deps (`mio` / `if-addrs` /
//! `socket-pktinfo`) have no `nto` support. This file only *selects* it: it
//! re-exports the responder's `start` and guard under the names `lib.rs`
//! expects, so the public [`SovdAdvertiser`](crate::SovdAdvertiser) /
//! [`AdvertiserGuard`](crate::AdvertiserGuard) API is byte-identical on every
//! target.
//!
//! [`responder`]: crate::responder

pub use crate::responder::{start, ResponderGuard as AdvertiserGuard};
