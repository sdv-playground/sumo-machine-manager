//! Generic `DeviceChannel` impl backed by a `SharedMemory` region + `Doorbell`.
//!
//! `ShmemChannel` is the common engine behind `IvshmemTransport` (Linux+QEMU)
//! and the future `QvmShmemTransport` (QNX qvm). It also works in tests on
//! top of `MemSharedMemory` + `MemDoorbell` to exercise the seqlock-and-fence
//! paths without any OS shmem mapping.
//!
//! ## Coherency model
//!
//! Channel writes are a raw `memcpy` of the device's byte buffer at offset 0
//! of the region, followed by a `Release` fence. Reads do an `Acquire` fence
//! and `memcpy` back. The channel does **not** add its own seqlock header —
//! coherency is the device's responsibility (e.g. `HeartbeatDevice` embeds a
//! `seq` field in its 32-byte wire format, mirroring the legacy on-device
//! layout at `regs::health::HB_OFF_SEQ`).
//!
//! Why no channel-level seqlock? Adding one would either:
//! - shift the device bytes off offset 0 and break QNX guest drivers that
//!   already read the legacy region directly, or
//! - duplicate seqcount logic the device wire format already carries.
//!
//! The `notify`/`wait` doorbell pair is the primary synchronization point;
//! readers normally consume on doorbell, and a torn read (rare in practice
//! given u32-aligned writes) is detected by `Heartbeat::from_bytes` returning
//! `None` on inconsistent fields, which `wait_for_state` retries.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{DeviceChannel, Doorbell, SharedMemory, TransportError};

/// `DeviceChannel` backed by a real shared-memory region.
///
/// `region` and `doorbell` are `Arc<dyn ...>` so the same struct works
/// across all combinations of mmap-backed (`IvshmemSharedMemory`,
/// `PosixSharedMemory`) and in-process (`MemSharedMemory`) primitives.
///
/// `size` is the payload size in bytes. `write` requires exactly this many
/// (excess or short slices are rejected); `read` always returns this many.
/// The caller picks `size` via `DeviceTransport::open_channel`'s `size_hint`.
pub struct ShmemChannel {
    region: Arc<dyn SharedMemory>,
    doorbell: Arc<dyn Doorbell>,
    size: usize,
}

impl ShmemChannel {
    pub fn new(
        region: Arc<dyn SharedMemory>,
        doorbell: Arc<dyn Doorbell>,
        size: usize,
    ) -> Result<Self, TransportError> {
        if size > region.len() {
            return Err(TransportError::OutOfBounds {
                offset: 0,
                len: size,
                size: region.len(),
            });
        }
        Ok(Self {
            region,
            doorbell,
            size,
        })
    }

    pub fn payload_size(&self) -> usize {
        self.size
    }
}

impl DeviceChannel for ShmemChannel {
    fn read(&self) -> Result<Vec<u8>, TransportError> {
        // Acquire ordering pairs with the writer's Release in `write`.
        // On a doorbell-driven read, this guarantees the writer's bytes are
        // visible to us.
        self.region.fence(Ordering::Acquire);
        let mut buf = vec![0u8; self.size];
        self.region.read_bytes(0, &mut buf);
        Ok(buf)
    }

    fn write(&self, data: &[u8]) -> Result<(), TransportError> {
        if data.len() != self.size {
            return Err(TransportError::OutOfBounds {
                offset: 0,
                len: data.len(),
                size: self.size,
            });
        }
        self.region.write_bytes(0, data);
        // Release ordering pairs with the reader's Acquire in `read`. The
        // upcoming `notify()` (or any future read) will observe a complete
        // payload, never a torn write.
        self.region.fence(Ordering::Release);
        Ok(())
    }

    fn notify(&self) -> Result<(), TransportError> {
        self.doorbell.notify()
    }

    fn wait(&self, timeout: Option<Duration>) -> Result<bool, TransportError> {
        match timeout {
            None => {
                // Block until peer signals.
                self.doorbell.wait()?;
                Ok(true)
            }
            Some(dur) => {
                // Doorbell trait has no native timeout; poll try_wait at 10ms
                // intervals against a deadline. Production users with an
                // eventfd-backed doorbell should override this with a poll(2)
                // path — see EventfdDoorbell. For NullDoorbell + legitimate
                // polling, this is the floor we can offer.
                let deadline = Instant::now() + dur;
                loop {
                    if self.doorbell.try_wait()? {
                        return Ok(true);
                    }
                    let now = Instant::now();
                    if now >= deadline {
                        return Ok(false);
                    }
                    let slice = (deadline - now).min(Duration::from_millis(10));
                    std::thread::sleep(slice);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mem::{MemDoorbell, MemSharedMemory};

    fn make_channel(payload_size: usize) -> ShmemChannel {
        let region: Arc<dyn SharedMemory> = Arc::new(MemSharedMemory::new(4096));
        let doorbell: Arc<dyn Doorbell> = Arc::new(MemDoorbell);
        ShmemChannel::new(region, doorbell, payload_size).expect("channel")
    }

    #[test]
    fn new_rejects_size_larger_than_region() {
        let region: Arc<dyn SharedMemory> = Arc::new(MemSharedMemory::new(64));
        let doorbell: Arc<dyn Doorbell> = Arc::new(MemDoorbell);
        let result = ShmemChannel::new(region, doorbell, 128);
        assert!(matches!(result, Err(TransportError::OutOfBounds { .. })));
    }

    #[test]
    fn fresh_channel_read_returns_zeros() {
        // SharedMemory is zero-initialized; channel returns those zeros.
        let ch = make_channel(32);
        let bytes = ch.read().unwrap();
        assert_eq!(bytes, vec![0u8; 32]);
    }

    #[test]
    fn write_then_read_roundtrip() {
        let ch = make_channel(8);
        ch.write(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        assert_eq!(ch.read().unwrap(), vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn write_rejects_wrong_length() {
        let ch = make_channel(8);
        // Too short.
        assert!(matches!(
            ch.write(&[1, 2, 3]),
            Err(TransportError::OutOfBounds { .. })
        ));
        // Too long.
        assert!(matches!(
            ch.write(&[0; 16]),
            Err(TransportError::OutOfBounds { .. })
        ));
    }

    #[test]
    fn write_replaces_previous_payload_in_full() {
        let ch = make_channel(4);
        ch.write(&[0xAA; 4]).unwrap();
        ch.write(&[0xBB, 0xCC, 0xDD, 0xEE]).unwrap();
        assert_eq!(ch.read().unwrap(), vec![0xBB, 0xCC, 0xDD, 0xEE]);
    }

    #[test]
    fn wait_with_timeout_returns_false_when_no_notify() {
        let ch = make_channel(8);
        // MemDoorbell::try_wait always returns false.
        let woken = ch.wait(Some(Duration::from_millis(15))).unwrap();
        assert!(!woken);
    }

    #[test]
    fn shmem_channel_drives_heartbeat_device() {
        // End-to-end: HeartbeatDevice on top of ShmemChannel on top of
        // MemSharedMemory. Validates that the higher-level device contract
        // works through the real shmem-channel codepath, not just MemChannel.
        use crate::heartbeat::{GuestState, Heartbeat, HeartbeatDevice, HEARTBEAT_WIRE_SIZE};

        let region: Arc<dyn SharedMemory> = Arc::new(MemSharedMemory::new(4096));
        let doorbell: Arc<dyn Doorbell> = Arc::new(MemDoorbell);
        let channel: Arc<dyn DeviceChannel> =
            Arc::new(ShmemChannel::new(region, doorbell, HEARTBEAT_WIRE_SIZE).unwrap());

        let host = HeartbeatDevice::new(channel.clone());
        let guest = HeartbeatDevice::new(channel);

        let hb = Heartbeat {
            seq: 7,
            state: GuestState::Running,
            mono_ns: 1_234_567_890,
            flags: crate::heartbeat::HB_FLAG_SERVICES_READY,
            boot_id: 0xCAFE_BABE,
        };
        guest.write(&hb).unwrap();

        let got = host.read().expect("host should see guest's write");
        assert_eq!(got, hb);
    }

    #[test]
    fn shmem_channel_drives_power_command_device() {
        use crate::power::{PowerCommand, PowerCommandDevice, POWER_WIRE_SIZE};

        let region: Arc<dyn SharedMemory> = Arc::new(MemSharedMemory::new(4096));
        let doorbell: Arc<dyn Doorbell> = Arc::new(MemDoorbell);
        let channel: Arc<dyn DeviceChannel> =
            Arc::new(ShmemChannel::new(region, doorbell, POWER_WIRE_SIZE).unwrap());

        let host = PowerCommandDevice::new(channel.clone());
        let guest = PowerCommandDevice::new(channel);

        let seq = host.send(PowerCommand::Reboot).unwrap();
        let frame = guest.read().expect("guest should see host's send");
        assert_eq!(frame.seq, seq);
        assert_eq!(frame.cmd, PowerCommand::Reboot);
    }
}
