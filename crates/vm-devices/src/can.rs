//! CAN bridge: transfers frames between ivshmem SPSC rings and a host CAN backend.
//!
//! The shared memory is split in half:
//! - RX ring (host→guest): first half, host writes frames
//! - TX ring (guest→host): second half, guest writes frames
//!
//! Each ring has a 32-byte header + frame slots (72 bytes each, CAN FD format).
//! SPSC lock-free protocol: writer advances head, reader advances tail.

#[cfg(target_os = "linux")]
pub mod socketcan;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::regs::can as r;
use crate::transport::SharedMemory;

/// CAN frame as it appears in the SPSC ring buffer.
#[derive(Clone)]
#[repr(C)]
pub struct CanFrame {
    pub id: u32,
    pub len: u8,
    pub flags: u8,
    pub _pad: [u8; 2],
    pub data: [u8; 64],
}

impl Default for CanFrame {
    fn default() -> Self {
        Self {
            id: 0,
            len: 0,
            flags: 0,
            _pad: [0; 2],
            data: [0; 64],
        }
    }
}

/// Host-side CAN backend trait.
pub trait CanBackend: Send {
    /// Send a CAN frame to the host CAN network.
    fn send(&mut self, frame: &CanFrame) -> Result<(), CanError>;

    /// Receive a CAN frame from the host CAN network (non-blocking).
    /// Returns Ok(true) if a frame was received, Ok(false) if none available.
    fn try_recv(&mut self, frame: &mut CanFrame) -> Result<bool, CanError>;
}

#[derive(Debug)]
pub enum CanError {
    Io(std::io::Error),
    RingFull,
}

impl std::fmt::Display for CanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CanError::Io(e) => write!(f, "CAN I/O: {e}"),
            CanError::RingFull => write!(f, "CAN ring full"),
        }
    }
}

/// CAN bridge between ivshmem shared memory rings and a host CAN backend.
pub struct CanBridge<S: SharedMemory, B: CanBackend> {
    shm: S,
    doorbell: Box<dyn crate::transport::Doorbell>,
    backend: B,
    ring_size: u32,
    rx_base: usize, // host→guest ring offset in shm
    tx_base: usize, // guest→host ring offset in shm
}

impl<S: SharedMemory, B: CanBackend> CanBridge<S, B> {
    pub fn new(shm: S, doorbell: Box<dyn crate::transport::Doorbell>, backend: B) -> Self {
        let half = shm.len() / 2;
        Self {
            shm,
            doorbell,
            backend,
            ring_size: 4096,
            rx_base: 0,
            tx_base: half,
        }
    }

    /// Initialize both ring headers.
    pub fn init(&self) {
        for base in [self.rx_base, self.tx_base] {
            self.shm.write_u32(base + r::RING_OFF_MAGIC, r::MAGIC);
            self.shm.write_u32(base + r::RING_OFF_VERSION, r::VERSION);
            self.shm.write_u32(base + r::RING_OFF_HEAD, 0);
            self.shm.write_u32(base + r::RING_OFF_TAIL, 0);
            self.shm.write_u32(base + r::RING_OFF_SIZE, self.ring_size);
            self.shm
                .write_u32(base + r::RING_OFF_FLAGS, r::RING_FLAG_FD);
        }
        self.shm.fence(Ordering::SeqCst);
    }

    /// Run the bridge loop. Blocks until `cancel` is set.
    ///
    /// Each iteration:
    /// 1. Read frames from TX ring (guest→host) and send to backend
    /// 2. Read frames from backend and write to RX ring (host→guest)
    pub fn run(&mut self, cancel: &AtomicBool) {
        self.init();

        while !cancel.load(Ordering::Relaxed) {
            // Drain TX ring (guest→host)
            while let Some(frame) = self.tx_read() {
                if let Err(e) = self.backend.send(&frame) {
                    tracing::warn!("CAN TX send failed: {e}");
                }
            }

            // Forward from backend to RX ring (host→guest)
            let mut frame = CanFrame::default();
            let mut wrote_rx = false;
            while let Ok(true) = self.backend.try_recv(&mut frame) {
                if let Err(e) = self.rx_write(&frame) {
                    tracing::warn!("CAN RX ring write failed: {e}");
                    break;
                }
                wrote_rx = true;
            }
            // Ring doorbell to wake guest NAPI after batch
            if wrote_rx {
                let _ = self.doorbell.notify();
            }

            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Write a frame to the RX ring (host→guest).
    fn rx_write(&self, frame: &CanFrame) -> Result<(), CanError> {
        let base = self.rx_base;
        let head = self.shm.read_u32(base + r::RING_OFF_HEAD);
        let tail = self.shm.read_u32(base + r::RING_OFF_TAIL);
        let next = (head + 1) % self.ring_size;

        if next == tail {
            return Err(CanError::RingFull);
        }

        let slot = base + r::RING_HEADER_SIZE + (head as usize) * r::FRAME_SIZE;
        self.write_frame(slot, frame);

        self.shm.fence(Ordering::Release);
        self.shm.write_u32(base + r::RING_OFF_HEAD, next);
        Ok(())
    }

    /// Read a frame from the TX ring (guest→host).
    fn tx_read(&self) -> Option<CanFrame> {
        let base = self.tx_base;
        let head = self.shm.read_u32(base + r::RING_OFF_HEAD);
        self.shm.fence(Ordering::Acquire);
        let tail = self.shm.read_u32(base + r::RING_OFF_TAIL);

        if head == tail {
            return None;
        }

        let slot = base + r::RING_HEADER_SIZE + (tail as usize) * r::FRAME_SIZE;
        let frame = self.read_frame(slot);

        self.shm.fence(Ordering::Release);
        self.shm
            .write_u32(base + r::RING_OFF_TAIL, (tail + 1) % self.ring_size);
        Some(frame)
    }

    fn write_frame(&self, offset: usize, frame: &CanFrame) {
        // Zero the slot first
        let zeros = [0u8; r::FRAME_SIZE];
        self.shm.write_bytes(offset, &zeros);

        self.shm.write_u32(offset + r::FRAME_OFF_ID, frame.id);
        let mut meta = [0u8; 4];
        meta[0] = frame.len;
        meta[1] = frame.flags;
        self.shm.write_bytes(offset + r::FRAME_OFF_LEN, &meta);
        self.shm.write_bytes(
            offset + r::FRAME_OFF_DATA,
            &frame.data[..frame.len.min(64) as usize],
        );
    }

    fn read_frame(&self, offset: usize) -> CanFrame {
        let id = self.shm.read_u32(offset + r::FRAME_OFF_ID);
        let mut meta = [0u8; 4];
        self.shm.read_bytes(offset + r::FRAME_OFF_LEN, &mut meta);
        let len = meta[0];
        let flags = meta[1];
        let mut frame = CanFrame {
            id,
            len,
            flags,
            ..CanFrame::default()
        };
        let dlen = len.min(64) as usize;
        self.shm
            .read_bytes(offset + r::FRAME_OFF_DATA, &mut frame.data[..dlen]);
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mem::MemSharedMemory;

    struct NullBackend {
        outbox: Vec<CanFrame>,
        inbox: Vec<CanFrame>,
    }

    impl NullBackend {
        fn new() -> Self {
            Self {
                outbox: Vec::new(),
                inbox: Vec::new(),
            }
        }
    }

    impl CanBackend for NullBackend {
        fn send(&mut self, frame: &CanFrame) -> Result<(), CanError> {
            self.outbox.push(frame.clone());
            Ok(())
        }
        fn try_recv(&mut self, frame: &mut CanFrame) -> Result<bool, CanError> {
            if let Some(f) = self.inbox.pop() {
                *frame = f;
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }

    fn make_frame(id: u32, data: &[u8]) -> CanFrame {
        let mut frame = CanFrame {
            id,
            len: data.len() as u8,
            ..CanFrame::default()
        };
        frame.data[..data.len()].copy_from_slice(data);
        frame
    }

    #[test]
    fn init_writes_ring_headers() {
        let shm = MemSharedMemory::new(1024 * 1024);
        let bridge = CanBridge::new(
            shm,
            Box::new(crate::transport::mem::MemDoorbell),
            NullBackend::new(),
        );
        bridge.init();

        // RX ring header
        assert_eq!(bridge.shm.read_u32(r::RING_OFF_MAGIC), r::MAGIC);
        assert_eq!(bridge.shm.read_u32(r::RING_OFF_SIZE), 4096);

        // TX ring header
        let tx = 1024 * 1024 / 2;
        assert_eq!(bridge.shm.read_u32(tx + r::RING_OFF_MAGIC), r::MAGIC);
    }

    #[test]
    fn rx_write_and_read_roundtrip() {
        let shm = MemSharedMemory::new(1024 * 1024);
        let bridge = CanBridge::new(
            shm,
            Box::new(crate::transport::mem::MemDoorbell),
            NullBackend::new(),
        );
        bridge.init();

        let frame = make_frame(0x123, &[0xDE, 0xAD, 0xBE, 0xEF]);
        bridge.rx_write(&frame).unwrap();

        // Verify head advanced
        assert_eq!(bridge.shm.read_u32(r::RING_OFF_HEAD), 1);

        // Read back from the slot
        let slot = r::RING_HEADER_SIZE;
        let read_back = bridge.read_frame(slot);
        assert_eq!(read_back.id, 0x123);
        assert_eq!(read_back.len, 4);
        assert_eq!(&read_back.data[..4], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn tx_read_returns_none_when_empty() {
        let shm = MemSharedMemory::new(1024 * 1024);
        let bridge = CanBridge::new(
            shm,
            Box::new(crate::transport::mem::MemDoorbell),
            NullBackend::new(),
        );
        bridge.init();

        assert!(bridge.tx_read().is_none());
    }

    #[test]
    fn tx_read_returns_guest_written_frame() {
        let shm = MemSharedMemory::new(1024 * 1024);
        let bridge = CanBridge::new(
            shm,
            Box::new(crate::transport::mem::MemDoorbell),
            NullBackend::new(),
        );
        bridge.init();

        // Simulate guest writing to TX ring
        let tx_base = 1024 * 1024 / 2;
        let slot = tx_base + r::RING_HEADER_SIZE;
        bridge.shm.write_u32(slot + r::FRAME_OFF_ID, 0x456);
        let mut meta = [0u8; 4];
        meta[0] = 3; // len
        bridge.shm.write_bytes(slot + r::FRAME_OFF_LEN, &meta);
        bridge
            .shm
            .write_bytes(slot + r::FRAME_OFF_DATA, &[0xCA, 0xFE, 0x01]);

        // Advance TX head (guest writes this)
        bridge.shm.write_u32(tx_base + r::RING_OFF_HEAD, 1);

        let frame = bridge.tx_read().unwrap();
        assert_eq!(frame.id, 0x456);
        assert_eq!(frame.len, 3);
        assert_eq!(&frame.data[..3], &[0xCA, 0xFE, 0x01]);

        // Tail should have advanced
        assert_eq!(bridge.shm.read_u32(tx_base + r::RING_OFF_TAIL), 1);
    }

    #[test]
    fn rx_ring_full_returns_error() {
        let shm = MemSharedMemory::new(1024 * 1024);
        let bridge = CanBridge::new(
            shm,
            Box::new(crate::transport::mem::MemDoorbell),
            NullBackend::new(),
        );
        bridge.init();

        // Simulate tail at 0, fill ring to capacity-1
        for i in 0..4095u32 {
            bridge.shm.write_u32(r::RING_OFF_HEAD, i);
            let frame = make_frame(i, &[0x01]);
            bridge.rx_write(&frame).unwrap();
        }

        // Next write should fail (ring full)
        let frame = make_frame(0xFFF, &[0x02]);
        assert!(bridge.rx_write(&frame).is_err());
    }
}
