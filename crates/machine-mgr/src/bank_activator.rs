//! Moved to `machine-contract` in v0.1.3 — the trait is synchronous and needs
//! neither sovd-core nor an async runtime, so an out-of-tree implementer should
//! not have to take this crate's dependency closure to satisfy it. This module
//! re-exports it so `machine_mgr::bank_activator::…` paths keep resolving.

pub use machine_contract::bank_activator::*;
