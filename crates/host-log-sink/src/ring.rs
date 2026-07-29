//! A bounded, in-process ring of [`LogRecord`]s — both a [`LogSink`] (push) and a
//! [`HostLogReader`] (snapshot). This is what makes the portable build servable
//! over SOVD §7.21 without a file: the newest `capacity` records are retained in
//! RAM; older ones fall off the back. RAM-only, so it does NOT survive a process
//! crash — acceptable for the portable/sim path (the QNX rig uses the
//! kernel-owned slog2 buffer, which does survive; see the design doc).

use std::collections::VecDeque;
use std::sync::Mutex;

use host_log_contract::{HostLogReader, LogRecord, LogSink};

/// Bounded FIFO of records, newest pushed at the back, oldest evicted at the
/// front once `capacity` is exceeded.
pub struct Ring {
    inner: Mutex<VecDeque<LogRecord>>,
    capacity: usize,
}

impl Ring {
    /// A ring retaining the last `capacity` records. `capacity == 0` retains
    /// nothing (every push is immediately dropped) — a valid "discard" sink.
    pub fn new(capacity: usize) -> Self {
        Ring {
            // Pre-size to capacity (capped) so steady-state pushes don't realloc.
            inner: Mutex::new(VecDeque::with_capacity(capacity.min(4096))),
            capacity,
        }
    }

    /// Append a record, evicting the oldest if at capacity.
    pub fn push(&self, record: LogRecord) {
        if self.capacity == 0 {
            return;
        }
        let mut q = self.inner.lock().expect("Ring mutex poisoned");
        if q.len() == self.capacity {
            q.pop_front();
        }
        q.push_back(record);
    }

    /// Current number of retained records (test/introspection helper).
    pub fn len(&self) -> usize {
        self.inner.lock().expect("Ring mutex poisoned").len()
    }

    /// Whether the ring currently holds no records.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl LogSink for Ring {
    fn emit(&self, record: LogRecord) {
        self.push(record);
    }
}

impl HostLogReader for Ring {
    fn snapshot(&self, max: usize) -> Vec<LogRecord> {
        if max == 0 {
            return Vec::new();
        }
        let q = self.inner.lock().expect("Ring mutex poisoned");
        // OLDEST-first, up to `max` of the MOST RECENT: skip the front overflow
        // when the ring holds more than max.
        let skip = q.len().saturating_sub(max);
        q.iter().skip(skip).cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use host_log_contract::Level;

    fn rec(n: i64, msg: &str) -> LogRecord {
        let mut r = LogRecord::new(Level::Info, "test", msg);
        r.unix_nanos = n;
        r
    }

    #[test]
    fn retains_newest_and_evicts_oldest() {
        let ring = Ring::new(3);
        for i in 1..=5 {
            ring.push(rec(i, &format!("m{i}")));
        }
        assert_eq!(ring.len(), 3);
        // Snapshot is oldest-first over what's retained: m3, m4, m5.
        let snap = ring.snapshot(10);
        let msgs: Vec<_> = snap.iter().map(|r| r.message.as_str()).collect();
        assert_eq!(msgs, ["m3", "m4", "m5"]);
    }

    #[test]
    fn snapshot_max_takes_most_recent_oldest_first() {
        let ring = Ring::new(10);
        for i in 1..=5 {
            ring.push(rec(i, &format!("m{i}")));
        }
        // Last 2, oldest-first: m4, m5.
        let snap = ring.snapshot(2);
        let msgs: Vec<_> = snap.iter().map(|r| r.message.as_str()).collect();
        assert_eq!(msgs, ["m4", "m5"]);
    }

    #[test]
    fn zero_capacity_discards() {
        let ring = Ring::new(0);
        ring.push(rec(1, "x"));
        assert!(ring.is_empty());
        assert!(ring.snapshot(10).is_empty());
    }

    #[test]
    fn snapshot_zero_max_is_empty() {
        let ring = Ring::new(4);
        ring.push(rec(1, "x"));
        assert!(ring.snapshot(0).is_empty());
    }

    #[test]
    fn as_a_logsink_pushes() {
        let ring = Ring::new(2);
        LogSink::emit(&ring, rec(1, "a"));
        assert_eq!(ring.len(), 1);
    }
}
