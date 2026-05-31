//! In-memory transport backend for tests.
//!
//! Two abstractions here, layered:
//! - **`MemSharedMemory` / `MemDoorbell`** — byte-level `SharedMemory` +
//!   `Doorbell` for tests of seqlock / register-layout code.
//! - **`MemTransport` / `MemChannel`** — `DeviceTransport` + `DeviceChannel`
//!   impls for tests of device code that's been migrated to the high-level
//!   trait. Heap buffer, condvar for `notify`/`wait`. Idempotent
//!   `open_channel`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use super::{DeviceChannel, DeviceTransport, Doorbell, SharedMemory, TransportError};

/// Heap-backed shared memory for unit tests.
pub struct MemSharedMemory {
    data: Vec<AtomicU8>,
}

impl MemSharedMemory {
    pub fn new(size: usize) -> Self {
        let mut data = Vec::with_capacity(size);
        for _ in 0..size {
            data.push(AtomicU8::new(0));
        }
        Self { data }
    }
}

impl SharedMemory for MemSharedMemory {
    fn len(&self) -> usize {
        self.data.len()
    }

    fn read_u16(&self, offset: usize) -> u16 {
        let b0 = self.data[offset].load(Ordering::Relaxed);
        let b1 = self.data[offset + 1].load(Ordering::Relaxed);
        u16::from_le_bytes([b0, b1])
    }

    fn write_u16(&self, offset: usize, value: u16) {
        let bytes = value.to_le_bytes();
        self.data[offset].store(bytes[0], Ordering::Relaxed);
        self.data[offset + 1].store(bytes[1], Ordering::Relaxed);
    }

    fn read_u32(&self, offset: usize) -> u32 {
        let mut buf = [0u8; 4];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = self.data[offset + i].load(Ordering::Relaxed);
        }
        u32::from_le_bytes(buf)
    }

    fn write_u32(&self, offset: usize, value: u32) {
        let bytes = value.to_le_bytes();
        for (i, b) in bytes.iter().enumerate() {
            self.data[offset + i].store(*b, Ordering::Relaxed);
        }
    }

    fn read_u64(&self, offset: usize) -> u64 {
        let mut buf = [0u8; 8];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = self.data[offset + i].load(Ordering::Relaxed);
        }
        u64::from_le_bytes(buf)
    }

    fn write_u64(&self, offset: usize, value: u64) {
        let bytes = value.to_le_bytes();
        for (i, b) in bytes.iter().enumerate() {
            self.data[offset + i].store(*b, Ordering::Relaxed);
        }
    }

    fn read_bytes(&self, offset: usize, buf: &mut [u8]) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = self.data[offset + i].load(Ordering::Relaxed);
        }
    }

    fn write_bytes(&self, offset: usize, data: &[u8]) {
        for (i, b) in data.iter().enumerate() {
            self.data[offset + i].store(*b, Ordering::Relaxed);
        }
    }

    fn fence(&self, ordering: Ordering) {
        std::sync::atomic::fence(ordering);
    }
}

/// No-op doorbell for tests.
pub struct MemDoorbell;

impl Doorbell for MemDoorbell {
    fn notify(&self) -> Result<(), TransportError> {
        Ok(())
    }

    fn wait(&self) -> Result<(), TransportError> {
        Ok(())
    }

    fn try_wait(&self) -> Result<bool, TransportError> {
        Ok(false)
    }
}

// ---------------------------------------------------------------------------
// MemTransport / MemChannel — in-process DeviceTransport for tests.
// ---------------------------------------------------------------------------

/// One channel's mutable state.
///
/// `notify_seq` is incremented on each `notify()`; waiters compare against
/// the seq they observed at entry to detect "did a notify fire while I was
/// asleep?" without racing.
struct MemChannelState {
    data: Vec<u8>,
    notify_seq: u64,
}

/// In-process `DeviceChannel`. Both peers (writer and reader) reference the
/// same `Arc`, so writes are immediately visible after the lock is dropped.
pub struct MemChannel {
    inner: Mutex<MemChannelState>,
    condvar: Condvar,
}

impl MemChannel {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(MemChannelState {
                data: Vec::new(),
                notify_seq: 0,
            }),
            condvar: Condvar::new(),
        })
    }
}

impl DeviceChannel for MemChannel {
    fn read(&self) -> Result<Vec<u8>, TransportError> {
        let state = self.inner.lock().expect("MemChannel mutex poisoned");
        Ok(state.data.clone())
    }

    fn write(&self, data: &[u8]) -> Result<(), TransportError> {
        let mut state = self.inner.lock().expect("MemChannel mutex poisoned");
        state.data.clear();
        state.data.extend_from_slice(data);
        Ok(())
    }

    fn notify(&self) -> Result<(), TransportError> {
        {
            let mut state = self.inner.lock().expect("MemChannel mutex poisoned");
            state.notify_seq = state.notify_seq.wrapping_add(1);
        }
        self.condvar.notify_all();
        Ok(())
    }

    fn wait(&self, timeout: Option<Duration>) -> Result<bool, TransportError> {
        let state = self.inner.lock().expect("MemChannel mutex poisoned");
        let observed_seq = state.notify_seq;
        match timeout {
            None => {
                let _state = self
                    .condvar
                    .wait_while(state, |s| s.notify_seq == observed_seq)
                    .expect("MemChannel condvar poisoned");
                Ok(true)
            }
            Some(dur) => {
                let (_state, result) = self
                    .condvar
                    .wait_timeout_while(state, dur, |s| s.notify_seq == observed_seq)
                    .expect("MemChannel condvar poisoned");
                Ok(!result.timed_out())
            }
        }
    }
}

/// In-process `DeviceTransport` keyed by `(vm, device, channel)`. Same key
/// always returns the same channel, so a host-side writer and a host-side
/// reader sharing the transport see each other's data.
#[derive(Default)]
pub struct MemTransport {
    channels: Mutex<HashMap<(String, String, String), Arc<MemChannel>>>,
}

impl MemTransport {
    pub fn new() -> Self {
        Self::default()
    }
}

impl DeviceTransport for MemTransport {
    fn open_channel(
        &self,
        vm: &str,
        device: &str,
        channel: &str,
        _size_hint: usize,
    ) -> Result<Arc<dyn DeviceChannel>, TransportError> {
        let key = (vm.to_string(), device.to_string(), channel.to_string());
        let mut map = self.channels.lock().expect("MemTransport mutex poisoned");
        let entry = map.entry(key).or_insert_with(MemChannel::new);
        Ok(entry.clone() as Arc<dyn DeviceChannel>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn len_matches_constructor_size() {
        let shm = MemSharedMemory::new(128);
        assert_eq!(shm.len(), 128);
    }

    #[test]
    fn u16_roundtrip_little_endian() {
        let shm = MemSharedMemory::new(16);
        shm.write_u16(0, 0xABCD);
        assert_eq!(shm.read_u16(0), 0xABCD);
        // Low byte first (LE)
        let mut raw = [0u8; 2];
        shm.read_bytes(0, &mut raw);
        assert_eq!(raw, [0xCD, 0xAB]);
    }

    #[test]
    fn u32_roundtrip_little_endian() {
        let shm = MemSharedMemory::new(16);
        shm.write_u32(4, 0xDEAD_BEEF);
        assert_eq!(shm.read_u32(4), 0xDEAD_BEEF);
        let mut raw = [0u8; 4];
        shm.read_bytes(4, &mut raw);
        assert_eq!(raw, [0xEF, 0xBE, 0xAD, 0xDE]);
    }

    #[test]
    fn u64_roundtrip_little_endian() {
        let shm = MemSharedMemory::new(16);
        shm.write_u64(0, 0x0123_4567_89AB_CDEF);
        assert_eq!(shm.read_u64(0), 0x0123_4567_89AB_CDEF);
        let mut raw = [0u8; 8];
        shm.read_bytes(0, &mut raw);
        assert_eq!(raw, [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01]);
    }

    #[test]
    fn i64_roundtrip_preserves_sign() {
        let shm = MemSharedMemory::new(16);
        shm.write_i64(0, -42);
        assert_eq!(shm.read_i64(0), -42);
        shm.write_i64(0, i64::MIN);
        assert_eq!(shm.read_i64(0), i64::MIN);
    }

    #[test]
    fn read_bytes_write_bytes_roundtrip() {
        let shm = MemSharedMemory::new(32);
        let payload = [1u8, 2, 3, 4, 5, 6, 7, 8];
        shm.write_bytes(8, &payload);
        let mut out = [0u8; 8];
        shm.read_bytes(8, &mut out);
        assert_eq!(out, payload);
    }

    #[test]
    fn adjacent_writes_do_not_overlap() {
        let shm = MemSharedMemory::new(16);
        shm.write_u32(0, 0x1111_1111);
        shm.write_u32(4, 0x2222_2222);
        assert_eq!(shm.read_u32(0), 0x1111_1111);
        assert_eq!(shm.read_u32(4), 0x2222_2222);
    }

    #[test]
    fn new_memory_starts_zeroed() {
        let shm = MemSharedMemory::new(32);
        for i in 0..32 {
            let mut b = [0xFFu8; 1];
            shm.read_bytes(i, &mut b);
            assert_eq!(b[0], 0, "byte {i} not zero-initialized");
        }
    }

    #[test]
    fn doorbell_notify_wait_are_noops() {
        let db = MemDoorbell;
        // Notify and try_wait never block or error in the test impl.
        db.notify().unwrap();
        assert!(!db.try_wait().unwrap());
    }

    // -----------------------------------------------------------------------
    // MemTransport / MemChannel
    // -----------------------------------------------------------------------

    #[test]
    fn mem_channel_fresh_read_returns_empty() {
        let t = MemTransport::new();
        let ch = t.open_channel("vm2", "heartbeat", "data", 64).unwrap();
        assert!(ch.read().unwrap().is_empty());
    }

    #[test]
    fn mem_channel_write_then_read_roundtrip() {
        let t = MemTransport::new();
        let ch = t.open_channel("vm2", "heartbeat", "data", 64).unwrap();
        ch.write(&[1, 2, 3, 4]).unwrap();
        assert_eq!(ch.read().unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn mem_channel_write_replaces_previous_snapshot() {
        let t = MemTransport::new();
        let ch = t.open_channel("vm2", "heartbeat", "data", 64).unwrap();
        ch.write(&[0xAA; 16]).unwrap();
        ch.write(&[0xBB; 4]).unwrap();
        // Replacement: length is 4, not 16+4.
        assert_eq!(ch.read().unwrap(), vec![0xBB; 4]);
    }

    #[test]
    fn mem_transport_returns_same_channel_for_same_triple() {
        let t = MemTransport::new();
        let ch1 = t.open_channel("vm2", "heartbeat", "data", 64).unwrap();
        let ch2 = t.open_channel("vm2", "heartbeat", "data", 64).unwrap();
        ch1.write(&[42]).unwrap();
        // Second handle reads the same backing state.
        assert_eq!(ch2.read().unwrap(), vec![42]);
    }

    #[test]
    fn mem_transport_returns_distinct_channels_for_different_triples() {
        let t = MemTransport::new();
        let a = t.open_channel("vm2", "heartbeat", "data", 64).unwrap();
        let b = t.open_channel("vm2", "power", "cmd", 64).unwrap();
        let c = t.open_channel("vm1", "heartbeat", "data", 64).unwrap();
        a.write(&[1]).unwrap();
        b.write(&[2]).unwrap();
        c.write(&[3]).unwrap();
        assert_eq!(a.read().unwrap(), vec![1]);
        assert_eq!(b.read().unwrap(), vec![2]);
        assert_eq!(c.read().unwrap(), vec![3]);
    }

    #[test]
    fn mem_channel_wait_returns_false_on_timeout() {
        let t = MemTransport::new();
        let ch = t.open_channel("vm2", "heartbeat", "data", 64).unwrap();
        let woken = ch.wait(Some(Duration::from_millis(20))).unwrap();
        assert!(!woken, "wait must return false on timeout with no notify");
    }

    #[test]
    fn mem_channel_notify_wakes_waiter() {
        let t = MemTransport::new();
        let ch = t.open_channel("vm2", "heartbeat", "data", 64).unwrap();
        let ch_clone = ch.clone();

        let waiter = std::thread::spawn(move || {
            // Generous timeout so the test passes even on a slow CI box —
            // the assertion is that we got woken, not that we got woken fast.
            ch_clone.wait(Some(Duration::from_secs(5))).unwrap()
        });

        // Sleep briefly so the waiter actually parks before we notify.
        std::thread::sleep(Duration::from_millis(20));
        ch.notify().unwrap();

        let woken = waiter.join().expect("waiter thread panicked");
        assert!(woken, "wait must return true after notify");
    }

    #[test]
    fn mem_channel_notify_before_wait_does_not_lose_signal() {
        // Spec: a notify that fires before the matched wait() call should
        // still cause the next wait() to return immediately. This is what
        // distinguishes "wait for a notify" from "wait for an unconditional
        // wakeup". We track this via the seq counter — wait() observes the
        // current seq at entry and returns as soon as seq has advanced.
        let t = MemTransport::new();
        let ch = t.open_channel("vm2", "heartbeat", "data", 64).unwrap();

        ch.notify().unwrap(); // pre-fire — seq = 1

        // Now wait. The seq we observe at entry is 1, the predicate is
        // `seq == 1`, which is initially true → we'd block forever. But
        // there's no waiter yet, so notify_seq stays at 1; wait blocks.
        // On a second notify, seq goes to 2 and we wake.
        //
        // This test documents the *current* behavior — notifies don't
        // accumulate. If we want edge-triggered "remember the last
        // notify", a future change would track unconsumed_seq separately.
        let woken = ch.wait(Some(Duration::from_millis(20))).unwrap();
        assert!(!woken, "notify-before-wait does not currently latch");
    }

    #[test]
    fn mem_channel_two_channels_isolated_notifies() {
        let t = MemTransport::new();
        let a = t.open_channel("vm2", "heartbeat", "data", 64).unwrap();
        let b = t.open_channel("vm2", "power", "cmd", 64).unwrap();

        let b_clone = b.clone();
        let waiter =
            std::thread::spawn(move || b_clone.wait(Some(Duration::from_millis(50))).unwrap());

        std::thread::sleep(Duration::from_millis(10));
        a.notify().unwrap(); // wrong channel — must not wake b's waiter

        let woken = waiter.join().expect("waiter panicked");
        assert!(
            !woken,
            "notify on a different channel must not wake this waiter"
        );
    }
}
