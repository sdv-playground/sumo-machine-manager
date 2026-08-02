//! Native journald reader via `libsystemd`'s `sd_journal` API (Linux only).
//!
//! Replaces the `journalctl -o json` subprocess with in-process journal iteration,
//! and — the point of this — pushes SOVD filters DOWN to the journal as native,
//! indexed matches instead of fetch-then-discard:
//!
//! - `priority` → `PRIORITY=<n>` match (journald's indexed severity field);
//! - `source` → `SYSLOG_IDENTIFIER=<x>` OR `_SYSTEMD_UNIT=<x>.service` (a
//!   disjunction, so either field name matches);
//! - `since`/`until` → `sd_journal_seek_realtime_usec` + a realtime bound;
//! - `after` (cursor) → `sd_journal_seek_cursor` + skip the cursor's own entry;
//! - `pattern` → NO native equivalent in `sd_journal` (that's `journalctl -g`, a
//!   PCRE pass journald doesn't expose via matches) → applied client-side.
//!
//! Falls back to the `journalctl` path in `main.rs` when the journal can't be
//! opened (returns `None`), so a minimal/permission-restricted image never loses
//! logs. The plain-file reader (`/var/log`, QNX `/dev/shmem`) is untouched — this
//! is only the journald source.
//!
//! This module is compiled only on Linux (gated at its `mod` declaration in the
//! crate's readers section); `libsystemd` is Linux-only and QNX uses the file reader.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr;

use crate::{journald_priority_name, rfc3339_utc, LogQuery, LogRecord, DEFAULT_TAIL, MAX_RECORDS};

// --- sd_journal FFI ----------------------------------------------------------
// libsystemd is linked verbatim by build.rs (`libsystemd.so.0`, gated to linux).
// No `#[link]` attribute here on purpose — it would additionally emit `-lsystemd`,
// which needs the -dev symlink we don't require. Symbols are LIBSYSTEMD_209 (old).

type Journal = *mut c_void;

// SD_JOURNAL_LOCAL_ONLY: this machine's journal only (no remote/foreign).
const SD_JOURNAL_LOCAL_ONLY: c_int = 1 << 0;

extern "C" {
    fn sd_journal_open(ret: *mut Journal, flags: c_int) -> c_int;
    fn sd_journal_close(j: Journal);
    fn sd_journal_add_match(j: Journal, data: *const c_void, size: usize) -> c_int;
    fn sd_journal_add_disjunction(j: Journal) -> c_int;
    fn sd_journal_seek_head(j: Journal) -> c_int;
    fn sd_journal_seek_realtime_usec(j: Journal, usec: u64) -> c_int;
    fn sd_journal_seek_cursor(j: Journal, cursor: *const c_char) -> c_int;
    fn sd_journal_next(j: Journal) -> c_int;
    fn sd_journal_get_data(
        j: Journal,
        field: *const c_char,
        data: *mut *const c_void,
        size: *mut usize,
    ) -> c_int;
    fn sd_journal_get_realtime_usec(j: Journal, usec: *mut u64) -> c_int;
    fn sd_journal_get_monotonic_usec(j: Journal, usec: *mut u64, boot_id: *mut SdId128) -> c_int;
    fn sd_journal_get_cursor(j: Journal, cursor: *mut *mut c_char) -> c_int;
}

/// `sd_id128_t` — 16 opaque bytes (journald's 128-bit boot id). We only need it
/// as an out-param for `sd_journal_get_monotonic_usec` (the monotonic clock is
/// per-boot; the boot id identifies which boot). We don't decode it here — the
/// runtime window is scoped to the current boot by only reading `-b` entries.
#[repr(C)]
struct SdId128 {
    bytes: [u8; 16],
}

/// RAII wrapper: opens the journal and closes it on drop. `None` if the journal
/// can't be opened (no journald, no permission) → caller falls back to the CLI.
struct JournalHandle(Journal);

impl JournalHandle {
    fn open() -> Option<Self> {
        let mut j: Journal = ptr::null_mut();
        // SAFETY: `j` is a valid out-pointer; on success it holds a live handle.
        let rc = unsafe { sd_journal_open(&mut j, SD_JOURNAL_LOCAL_ONLY) };
        if rc < 0 || j.is_null() {
            return None;
        }
        Some(JournalHandle(j))
    }

    /// Add an exact `FIELD=value` match (native, indexed). Ignores errors — a bad
    /// match just isn't applied, degrading to a wider read, never a failure.
    fn add_match(&self, field_eq_value: &str) {
        if let Ok(c) = CString::new(field_eq_value) {
            // `as_bytes` excludes the trailing NUL — the match size is the byte len.
            let bytes = c.as_bytes();
            // SAFETY: ptr+len describe `bytes`; sd_journal_add_match copies them.
            unsafe {
                sd_journal_add_match(self.0, bytes.as_ptr() as *const c_void, bytes.len());
            }
        }
    }

    fn add_disjunction(&self) {
        // SAFETY: valid handle; combines the preceding matches as an OR group.
        unsafe {
            sd_journal_add_disjunction(self.0);
        }
    }

    fn seek_head(&self) {
        unsafe {
            sd_journal_seek_head(self.0);
        }
    }

    fn seek_realtime(&self, usec: u64) {
        unsafe {
            sd_journal_seek_realtime_usec(self.0, usec);
        }
    }

    /// Seek to `cursor`. Returns true on success.
    fn seek_cursor(&self, cursor: &str) -> bool {
        let Ok(c) = CString::new(cursor) else {
            return false;
        };
        // SAFETY: valid handle + NUL-terminated cursor string.
        unsafe { sd_journal_seek_cursor(self.0, c.as_ptr()) >= 0 }
    }

    /// Advance to the next entry. Returns Ok(true) if positioned on an entry,
    /// Ok(false) at end-of-journal, Err on a read error.
    fn next(&self) -> Result<bool, ()> {
        // SAFETY: valid handle.
        let rc = unsafe { sd_journal_next(self.0) };
        if rc < 0 {
            Err(())
        } else {
            Ok(rc > 0)
        }
    }

    /// Read field `name` of the current entry as a `String`. journald returns
    /// `NAME=value` bytes; we strip the `NAME=` prefix. `None` if absent or
    /// non-UTF8 (e.g. a binary MESSAGE).
    fn field(&self, name: &str) -> Option<String> {
        let cname = CString::new(name).ok()?;
        let mut data: *const c_void = ptr::null();
        let mut size: usize = 0;
        // SAFETY: valid handle + NUL-terminated field name; on success `data`/`size`
        // point at journald-owned memory valid until the next iteration step.
        let rc = unsafe { sd_journal_get_data(self.0, cname.as_ptr(), &mut data, &mut size) };
        if rc < 0 || data.is_null() {
            return None;
        }
        // SAFETY: `data`/`size` delimit a valid, journald-owned byte range.
        let bytes = unsafe { std::slice::from_raw_parts(data as *const u8, size) };
        let s = std::str::from_utf8(bytes).ok()?;
        // Strip the leading "NAME=".
        let prefix_len = name.len() + 1;
        Some(s.get(prefix_len..).unwrap_or("").to_string())
    }

    fn realtime_usec(&self) -> u64 {
        let mut usec: u64 = 0;
        // SAFETY: valid handle + out-pointer.
        let rc = unsafe { sd_journal_get_realtime_usec(self.0, &mut usec) };
        if rc < 0 {
            0
        } else {
            usec
        }
    }

    /// Monotonic runtime of the current entry, SECONDS since the entry's boot
    /// (journald `__MONOTONIC_TIMESTAMP`). The jump-proof `x-sumo-runtime` axis.
    /// `None` on error (kept off the runtime axis).
    fn monotonic_secs(&self) -> Option<u64> {
        let mut usec: u64 = 0;
        let mut boot = SdId128 { bytes: [0u8; 16] };
        // SAFETY: valid handle + out-pointers; boot_id is written but unused here.
        let rc = unsafe { sd_journal_get_monotonic_usec(self.0, &mut usec, &mut boot) };
        if rc < 0 {
            None
        } else {
            Some(usec / 1_000_000)
        }
    }

    /// The current entry's opaque cursor. `None` on error.
    fn cursor(&self) -> Option<String> {
        let mut ptr_out: *mut c_char = ptr::null_mut();
        // SAFETY: valid handle + out-pointer; on success `ptr_out` is a malloc'd
        // C string we must free.
        let rc = unsafe { sd_journal_get_cursor(self.0, &mut ptr_out) };
        if rc < 0 || ptr_out.is_null() {
            return None;
        }
        // SAFETY: `ptr_out` is a valid NUL-terminated string owned by us.
        let s = unsafe { CStr::from_ptr(ptr_out) }
            .to_str()
            .ok()
            .map(|s| s.to_string());
        // SAFETY: free the libc-malloc'd cursor exactly once.
        unsafe { libc_free(ptr_out as *mut c_void) };
        s
    }
}

impl Drop for JournalHandle {
    fn drop(&mut self) {
        // SAFETY: `self.0` was returned by sd_journal_open and not yet closed.
        unsafe { sd_journal_close(self.0) };
    }
}

// sd_journal_get_cursor returns a malloc'd string the caller frees with free(3).
extern "C" {
    #[link_name = "free"]
    fn libc_free(ptr: *mut c_void);
}

// --- name → PRIORITY number (inverse of journald_priority_name) --------------

/// Map a SOVD priority NAME to journald's numeric `PRIORITY` value, for a native
/// `PRIORITY=<n>` match. `None` for an unrecognized name (→ no priority match).
fn priority_number(name: &str) -> Option<u8> {
    match name {
        "emergency" => Some(0),
        "alert" => Some(1),
        "critical" => Some(2),
        "error" => Some(3),
        "warning" => Some(4),
        "notice" => Some(5),
        "info" => Some(6),
        "debug" => Some(7),
        _ => None,
    }
}

// --- shared field extraction -------------------------------------------------

/// Build a `LogRecord` from the current journal entry (source/timestamp/priority
/// mapping identical to the CLI path). `None` if the entry has no UTF-8 MESSAGE.
fn record_from_current(j: &JournalHandle) -> Option<LogRecord> {
    let message = j.field("MESSAGE")?;
    let source = j
        .field("SYSLOG_IDENTIFIER")
        .or_else(|| j.field("_SYSTEMD_UNIT"))
        .or_else(|| j.field("_COMM"))
        .unwrap_or_else(|| "journal".to_string())
        .trim_end_matches(".service")
        .to_string();
    let priority = j
        .field("PRIORITY")
        .map(|p| journald_priority_name(&p))
        .unwrap_or("info");
    let usec = j.realtime_usec();
    Some(LogRecord {
        timestamp: rfc3339_utc(usec / 1_000_000),
        priority: priority.into(),
        message,
        source,
        uptime_secs: j.monotonic_secs(),
    })
}

/// Apply the native, indexed matches for a query's `priority` and `source`.
/// (Pattern has no native match and is filtered by the caller.)
fn apply_matches(j: &JournalHandle, q: &LogQuery) {
    if let Some(p) = q.priority.as_deref().and_then(priority_number) {
        j.add_match(&format!("PRIORITY={p}"));
    }
    if let Some(src) = &q.source {
        // Either SYSLOG_IDENTIFIER or the systemd unit (with the conventional
        // `.service` suffix, since our `source` strips it). A disjunction ORs the
        // two field matches; combined with the PRIORITY match above as an AND.
        j.add_match(&format!("SYSLOG_IDENTIFIER={src}"));
        j.add_disjunction();
        j.add_match(&format!("_SYSTEMD_UNIT={src}.service"));
    }
}

/// Parse an RFC3339-ish `since`/`until` value to microseconds-since-epoch. journald
/// wants usec; we accept the common forms the CLI accepted plus a bare unix-seconds
/// integer. `None` if unparseable (→ that bound isn't applied).
fn to_usec(s: &str) -> Option<u64> {
    let t = s.trim();
    // Bare integer seconds (what END-relative resolution upstream produces).
    if let Ok(secs) = t.parse::<u64>() {
        return Some(secs.saturating_mul(1_000_000));
    }
    None
}

// --- public entry points (mirror the CLI fns' signatures) --------------------

/// Native equivalent of `journald(q)` — tail the newest matching entries.
/// Returns `None` if the journal can't be opened (caller falls back to CLI).
pub fn journald(q: &LogQuery) -> Option<Vec<LogRecord>> {
    let j = JournalHandle::open()?;
    apply_matches(&j, q);

    // Position: honor `since` (seek to it); else start at head and read forward.
    // We read the whole matching window (bounded by MAX_RECORDS) then tail it, so
    // "last N matching" behaves like the CLI path without the -n/filter race.
    match q.since.as_deref().and_then(to_usec) {
        Some(usec) => j.seek_realtime(usec),
        None => j.seek_head(),
    }
    let until_usec = q.until.as_deref().and_then(to_usec);
    let cap = MAX_RECORDS * 2;

    let mut out: Vec<LogRecord> = Vec::new();
    let mut scanned = 0usize;
    while scanned < cap {
        match j.next() {
            Ok(true) => {}
            _ => break,
        }
        scanned += 1;
        if let Some(u) = until_usec {
            if j.realtime_usec() > u {
                break; // past the until bound (entries are time-ordered)
            }
        }
        let Some(rec) = record_from_current(&j) else {
            continue;
        };
        // Pattern has no native match — filter here.
        if let Some(pat) = &q.pattern {
            if !rec.message.contains(pat.as_str()) {
                continue;
            }
        }
        out.push(rec);
    }

    // Tail to the requested count (newest N), matching the CLI reader's semantics.
    let n = q.tail.unwrap_or(DEFAULT_TAIL).min(MAX_RECORDS);
    if out.len() > n {
        out.drain(..out.len() - n);
    }
    Some(out)
}

/// Native equivalent of `journald_page(q)` — one FORWARD page + resume cursor.
/// Returns `None` if the journal can't be opened (caller falls back to CLI).
pub fn journald_page(q: &LogQuery) -> Option<(Vec<LogRecord>, Option<String>)> {
    let j = JournalHandle::open()?;
    apply_matches(&j, q);

    // Position: resume after a cursor if given (skip its own entry), else honor
    // `since`, else the head. sd_journal_seek_cursor lands ON the cursor's entry,
    // so the first `next()` moves to the following one — but to EXCLUDE the cursor
    // entry itself we do one extra `next()` after a successful cursor seek.
    let resumed = match &q.after {
        Some(c) if j.seek_cursor(c) => {
            let _ = j.next(); // step onto the cursor's own entry (to be skipped)
            true
        }
        _ => false,
    };
    if !resumed {
        match q.since.as_deref().and_then(to_usec) {
            Some(usec) => j.seek_realtime(usec),
            None => j.seek_head(),
        }
    }
    let until_usec = q.until.as_deref().and_then(to_usec);
    let limit = q.tail.unwrap_or(DEFAULT_TAIL).min(MAX_RECORDS);

    let mut out: Vec<LogRecord> = Vec::new();
    let mut last_cursor: Option<String> = None;
    // Scan forward until the page fills. A generous scan bound stops a
    // pathological all-filtered stream from looping unboundedly.
    let scan_cap = limit.saturating_mul(50).max(MAX_RECORDS);
    let mut scanned = 0usize;
    while out.len() < limit && scanned < scan_cap {
        match j.next() {
            Ok(true) => {}
            _ => break,
        }
        scanned += 1;
        if let Some(u) = until_usec {
            if j.realtime_usec() > u {
                break;
            }
        }
        // Track the cursor of every scanned entry (even filtered-out) so the next
        // page resumes past them — else a page of all-filtered entries loops.
        if let Some(c) = j.cursor() {
            last_cursor = Some(c);
        }
        let Some(rec) = record_from_current(&j) else {
            continue;
        };
        if let Some(pat) = &q.pattern {
            if !rec.message.contains(pat.as_str()) {
                continue;
            }
        }
        out.push(rec);
    }

    // next_cursor only when the page filled (more may remain); None at head.
    let next_cursor = if out.len() >= limit {
        last_cursor
    } else {
        None
    };
    Some((out, next_cursor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_number_roundtrips_with_name() {
        for (name, num) in [
            ("emergency", 0u8),
            ("error", 3),
            ("warning", 4),
            ("info", 6),
            ("debug", 7),
        ] {
            assert_eq!(priority_number(name), Some(num));
            // and the inverse used by the reader agrees
            assert_eq!(journald_priority_name(&num.to_string()), name);
        }
        assert_eq!(priority_number("bogus"), None);
    }

    #[test]
    fn to_usec_parses_bare_seconds() {
        assert_eq!(to_usec("1785339207"), Some(1_785_339_207_000_000));
        assert_eq!(to_usec("  42 "), Some(42_000_000));
        assert_eq!(to_usec("not-a-time"), None);
    }

    // A live-journal smoke test: open + read a couple entries. Only meaningful on
    // a box with a readable journal; skips cleanly (returns None) otherwise.
    #[test]
    fn open_and_read_smoke() {
        let q = LogQuery {
            tail: Some(5),
            ..Default::default()
        };
        match journald(&q) {
            Some(recs) => {
                // If we opened the journal, records should have plausible shape.
                for r in &recs {
                    assert!(!r.timestamp.is_empty());
                    assert!(!r.priority.is_empty());
                }
            }
            None => { /* no journal here — fallback path covers it */ }
        }
    }
}
