//! Host-side transport implementations + re-export of the contract.
//!
//! The trait surface (`DeviceChannel`, `StreamChannel`, `DeviceTransport`,
//! `SharedMemory`, `Doorbell`, `TransportError`, `seqcount_write`) lives in
//! the [`vm_wire`] contract crate so host and guest never duplicate it.
//! This module re-exports those names so existing host callers
//! (`use vm_devices::transport::DeviceChannel;`) continue to work.
//!
//! Two layers, same as before:
//!
//! - **Low-level** `SharedMemory` + `Doorbell`: byte-level shmem ops + notify.
//!   Used by shmem-backed transport impls. Tied to "this is a memory region"
//!   semantics.
//!
//! - **High-level** `DeviceChannel` + `DeviceTransport`: substrate-agnostic
//!   "structured-state-with-notification" primitive. Devices consume this so
//!   the same device code runs over shmem (`IvshmemTransport`,
//!   `QvmShmemTransport`) and network (`HttpTransport`) without changes.
//!
//! See `tasks/device-transport-design.md` for the full design.

#[cfg(feature = "http-transport")]
pub mod http;
#[cfg(target_os = "linux")]
pub mod ivshmem;
pub mod mem;
pub mod shmem;
pub mod tcp_stream;

// Re-export the contract so `use vm_devices::transport::DeviceChannel`
// keeps working for host-side callers.
pub use vm_wire::{
    seqcount_write, DeviceChannel, DeviceTransport, Doorbell, SharedMemory, StreamChannel,
    TransportError,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mem::MemSharedMemory;

    // Trait-display tests live in vm-wire (no SharedMemory impl needed).
    // Here we keep the seqcount_write tests because they need a real
    // SharedMemory impl that lives in this crate.

    #[test]
    fn seqcount_write_leaves_even_seq() {
        let shm = MemSharedMemory::new(16);
        seqcount_write(&shm, 0, || {
            shm.write_u32(4, 42);
        });
        assert_eq!(shm.read_u32(0), 2);
        assert_eq!(shm.read_u32(4), 42);
    }

    #[test]
    fn seqcount_write_increments_by_two_per_call() {
        let shm = MemSharedMemory::new(16);
        for expected in [2u32, 4, 6, 8] {
            seqcount_write(&shm, 0, || {});
            assert_eq!(shm.read_u32(0), expected);
        }
    }

    #[test]
    fn seqcount_write_odd_during_write_closure() {
        let shm = MemSharedMemory::new(16);
        seqcount_write(&shm, 0, || {
            let mid = shm.read_u32(0);
            assert_eq!(mid & 1, 1, "seq must be odd mid-write, got {mid}");
        });
    }
}
