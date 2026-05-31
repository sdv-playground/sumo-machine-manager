//! Non-volatile store for boot state, factory identity, per-bank FW metadata,
//! and per-bank runtime DIDs.
//!
//! Platform-independent: drives a pluggable [`block::BlockDevice`] (in-memory
//! for tests, file-backed for Linux dev, raw partition for production). No
//! `std::fs` outside `FileBlockDevice`.
//!
//! Layout (see `specs/nv-store-format.md`): each region occupies a fixed
//! sector window with two rotating copies guarded by CRC-32 and a monotonic
//! `write_seq`. Readers pick the copy with the highest valid seq; writers
//! flip between slots so a half-written copy never destroys the live one.
//!
//! Region summary:
//! - Boot state — active bank + committed flag + trial boot count per bank set
//! - Factory   — serial, VIN, ECU HW IDs (one-time, shared across banks)
//! - App       — app-level persistence
//! - FW meta   — SW identity, hash, sequence, min_security_ver (per bank set × bank)
//! - Runtime   — writable DIDs and DTCs (per bank set × bank; copy-on-update)

pub mod block;
pub mod store;
pub mod types;

#[cfg(test)]
mod tests;
