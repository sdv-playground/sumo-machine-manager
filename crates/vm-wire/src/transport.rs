//! Transport contract — traits + error type.
//!
//! Two layers:
//!
//! - **Low-level** [`SharedMemory`] + [`Doorbell`]: byte-level shmem ops + notify.
//!   Used by shmem-backed transport impls. Tied to "this is a memory region"
//!   semantics.
//!
//! - **High-level** [`DeviceChannel`] + [`DeviceTransport`]: substrate-agnostic
//!   "structured-state-with-notification" primitive. Devices consume this so
//!   the same device code runs over shmem (`IvshmemTransport`,
//!   `QvmShmemTransport`) and network (`HttpTransport`) without changes.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

/// Error type for transport operations.
#[derive(Debug)]
pub enum TransportError {
    Io(std::io::Error),
    OutOfBounds {
        offset: usize,
        len: usize,
        size: usize,
    },
    /// The transport doesn't support the requested channel shape — typically
    /// returned by `DeviceTransport::open_stream` on register-only transports
    /// (HTTP, plain ivshmem) and by `open_channel` on stream-only transports.
    Unsupported(&'static str),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Io(e) => write!(f, "transport I/O: {e}"),
            TransportError::OutOfBounds { offset, len, size } => {
                write!(f, "out of bounds: offset={offset} len={len} size={size}")
            }
            TransportError::Unsupported(s) => write!(f, "unsupported: {s}"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<std::io::Error> for TransportError {
    fn from(e: std::io::Error) -> Self {
        TransportError::Io(e)
    }
}

/// One direction of a device's state-with-notification.
///
/// Each channel carries a single byte snapshot from one peer to the other,
/// plus an optional notification primitive. Devices serialize their wire
/// format (typically a `#[repr(C)]` struct via `bytemuck`) into bytes and
/// hand them to `write`; readers `read` and deserialize.
pub trait DeviceChannel: Send + Sync {
    /// Read the current snapshot. Implementations are responsible for
    /// internal coherency (seqlock retry on shmem, atomic swap in-mem,
    /// HTTP GET on network). Returned `Vec<u8>` may be empty on a fresh
    /// channel that has not been written.
    fn read(&self) -> Result<Vec<u8>, TransportError>;

    /// Write a new snapshot, replacing whatever was there. For shmem-backed
    /// channels this uses a seqlock so a concurrent reader sees a consistent
    /// view. For HTTP it's a single PUT.
    fn write(&self, data: &[u8]) -> Result<(), TransportError>;

    /// Wake the peer that data changed. May be a no-op for transports that
    /// rely on polling (HTTP without long-poll).
    fn notify(&self) -> Result<(), TransportError>;

    /// Block until peer notifies us, or `timeout` elapses. `None` means
    /// wait forever. Returns `Ok(true)` on signal, `Ok(false)` on timeout.
    fn wait(&self, timeout: Option<Duration>) -> Result<bool, TransportError>;
}

/// One direction of a device's frame stream.
///
/// `StreamChannel` is the FIFO sibling of [`DeviceChannel`]: where a channel
/// holds a single snapshot that any reader can re-fetch, a stream carries an
/// ordered, lossless sequence of distinct frames where each frame is read
/// once and then gone. CAN frames, audio buffers, and log records fit here;
/// heartbeat / power-command / time-sync fit `DeviceChannel`.
///
/// Wire framing is the transport's concern (e.g. TCP impls use a 4-byte
/// little-endian length prefix per frame). Devices serialize their per-frame
/// wire format into bytes and hand them to `send_frame`; readers `recv_frame`
/// and deserialize.
pub trait StreamChannel: Send + Sync {
    /// Send one frame to the peer. Frames are delivered in order; the
    /// transport must not reorder or drop them silently. Backpressure is
    /// transport-defined (TCP: blocks; bounded queues: returns error).
    fn send_frame(&self, data: &[u8]) -> Result<(), TransportError>;

    /// Receive the next frame, blocking up to `timeout` (or forever if
    /// `None`). Returns:
    /// - `Ok(Some(frame))` on a frame
    /// - `Ok(None)` on clean EOF (peer closed) or timeout
    /// - `Err(...)` on transport failure
    fn recv_frame(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, TransportError>;

    /// Non-blocking variant of `recv_frame`. Returns `Ok(None)` when no
    /// frame is currently queued.
    fn try_recv_frame(&self) -> Result<Option<Vec<u8>>, TransportError>;
}

/// Factory that constructs `DeviceChannel` and/or `StreamChannel` for a
/// given transport substrate.
///
/// The runner picks one impl per VM at start time, based on `(host, guest_os)`,
/// then hands `Arc<dyn DeviceTransport>` to each device. Devices request
/// channels by `(vm, device, channel)` triple; the transport decides storage:
/// shmem region, HTTP endpoint, TCP socket, etc.
///
/// `open_channel` and `open_stream` are idempotent — calling either twice
/// with the same triple returns the same underlying channel.
///
/// Each transport implementation declares which shapes it supports by
/// providing real impls; the defaults below return `Unsupported` so a
/// register-only transport (HTTP) doesn't need to know about streams and
/// vice versa.
pub trait DeviceTransport: Send + Sync {
    /// Open or attach to a register-shaped channel. `size_hint` is advisory
    /// — shmem-backed transports use it to size the underlying region;
    /// HTTP ignores it. Default returns `Unsupported`.
    fn open_channel(
        &self,
        _vm: &str,
        _device: &str,
        _channel: &str,
        _size_hint: usize,
    ) -> Result<Arc<dyn DeviceChannel>, TransportError> {
        Err(TransportError::Unsupported(
            "this transport does not provide register-shaped channels",
        ))
    }

    /// Open or attach to a stream-shaped channel. Default returns
    /// `Unsupported` — implement this on transports whose substrate
    /// naturally carries a frame FIFO (TCP, shmem rings).
    fn open_stream(
        &self,
        _vm: &str,
        _device: &str,
        _channel: &str,
    ) -> Result<Arc<dyn StreamChannel>, TransportError> {
        Err(TransportError::Unsupported(
            "this transport does not provide stream-shaped channels",
        ))
    }

    /// Release any cached per-VM state (regions, channels). Called by
    /// VmManager around `start_vm` / `finalize_stop` for transports
    /// whose substrate is bound to the VM process lifetime — qvm vdev
    /// shmem regions live and die with the qvm process, so the host
    /// must drop its handle before the next qvm spawn or it ends up
    /// reading stale memory from the dead process.
    ///
    /// Default is a no-op for transports whose state is independent of
    /// VM lifecycle (HTTP, in-memory, ivshmem files).
    fn release_vm(&self, _vm: &str) {}
}

/// A region of shared memory accessible by both host and guest.
///
/// Implementations handle platform-specific mapping:
/// - Linux/QEMU: mmap of `/dev/shm/ivshmem-*`
/// - QNX: `shm_open` + `mmap`, or qvm vdev shmem via libhyp
/// - Tests: heap-allocated buffer
///
/// All reads/writes use volatile semantics to prevent compiler reordering.
#[allow(clippy::len_without_is_empty)]
pub trait SharedMemory: Send + Sync {
    /// Size of the shared region in bytes.
    fn len(&self) -> usize;

    /// Read a little-endian u32 at the given byte offset (volatile).
    fn read_u32(&self, offset: usize) -> u32;

    /// Write a little-endian u32 at the given byte offset (volatile).
    fn write_u32(&self, offset: usize, value: u32);

    /// Read a little-endian u64 at the given byte offset (volatile).
    fn read_u64(&self, offset: usize) -> u64;

    /// Write a little-endian u64 at the given byte offset (volatile).
    fn write_u64(&self, offset: usize, value: u64);

    /// Read a little-endian i64 at the given byte offset (volatile).
    fn read_i64(&self, offset: usize) -> i64 {
        self.read_u64(offset) as i64
    }

    /// Write a little-endian i64 at the given byte offset (volatile).
    fn write_i64(&self, offset: usize, value: i64) {
        self.write_u64(offset, value as u64);
    }

    /// Read a little-endian u16 at the given byte offset (volatile).
    fn read_u16(&self, offset: usize) -> u16;

    /// Write a little-endian u16 at the given byte offset (volatile).
    fn write_u16(&self, offset: usize, value: u16);

    /// Read a byte slice from the given offset (non-atomic, for bulk data).
    fn read_bytes(&self, offset: usize, buf: &mut [u8]);

    /// Write a byte slice to the given offset (non-atomic, for bulk data).
    fn write_bytes(&self, offset: usize, data: &[u8]);

    /// Memory fence (compiler + hardware barrier).
    fn fence(&self, ordering: Ordering);
}

/// Doorbell mechanism for notifying the peer (guest or host).
pub trait Doorbell: Send + Sync {
    /// Ring the doorbell (notify the peer that data is ready).
    fn notify(&self) -> Result<(), TransportError>;

    /// Wait for a doorbell from the peer. Blocks until notification.
    fn wait(&self) -> Result<(), TransportError>;

    /// Non-blocking check if a doorbell is pending.
    fn try_wait(&self) -> Result<bool, TransportError>;
}

/// Seqcount write helper for lock-free multi-word updates.
///
/// Increments the sequence counter to odd (writing), executes the closure,
/// then increments to even (done). Readers retry if they see an odd seq
/// or if seq changed between start and end of their read.
pub fn seqcount_write(shm: &dyn SharedMemory, seq_offset: usize, write_fn: impl FnOnce()) {
    let seq = shm.read_u32(seq_offset);
    shm.write_u32(seq_offset, seq.wrapping_add(1)); // odd = writing
    shm.fence(Ordering::Release);

    write_fn();

    shm.fence(Ordering::Release);
    shm.write_u32(seq_offset, seq.wrapping_add(2)); // even = done
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_error_display_io_variant() {
        let e = TransportError::Io(std::io::Error::other("boom"));
        assert!(format!("{e}").contains("boom"));
    }

    #[test]
    fn transport_error_display_out_of_bounds() {
        let e = TransportError::OutOfBounds {
            offset: 10,
            len: 4,
            size: 8,
        };
        let s = format!("{e}");
        assert!(s.contains("offset=10"));
        assert!(s.contains("len=4"));
        assert!(s.contains("size=8"));
    }

    #[test]
    fn transport_error_is_std_error() {
        fn as_error(_e: &dyn std::error::Error) {}
        let e = TransportError::OutOfBounds {
            offset: 0,
            len: 0,
            size: 0,
        };
        as_error(&e);
    }

    // seqcount_write tests need a SharedMemory impl, which lives in the
    // crates that provide the impls (vm-devices, qnx-devices, etc.). Those
    // crates carry the integration tests for this helper.
}
