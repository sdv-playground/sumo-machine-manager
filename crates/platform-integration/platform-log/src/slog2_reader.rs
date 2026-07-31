//! Native QNX slog2 reader via `libslog2parse` (QNX only).
//!
//! Reads the `slogger2` ring — the QNX system log — with `slog2_parse_all`, which
//! walks every buffer and invokes a callback per packet. This is the READ half of
//! the host log pipeline: supernova emits into slog2 (via score-log-slog2), and
//! this reads the SAME ring back for SOVD §7.21 — producer and reader decoupled
//! through the OS ring, which is kernel-owned (survives a supernova crash) and
//! also carries the host's driver/eMMC telemetry (devb_sdmmc, CAM), so those
//! surface over SOVD for free.
//!
//! Filters (source/pattern/priority/since/until/tail) are applied in the callback
//! — `slog2_parse_all` has no match API like journald's, so filtering is
//! per-packet here (still cheap; it's one in-process walk). Buffer-set NAME →
//! `source`; a `context`-named buffer (see score-log-slog2) is thus queryable by
//! `source`.
//!
//! Compiled only on QNX (`mod` gated in lib.rs); `libslog2parse` linked by build.rs.
//! ABI note: `slog2_packet_info_t` is size-versioned and the header marks the API
//! "SUBJECT TO CHANGE" — `PacketInfo` mirrors the QNX 7.1 layout (verified 232
//! bytes == C `sizeof`), and `.size` is set before the call for the version gate.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};

use crate::{LogQuery, LogRecord, DEFAULT_TAIL, MAX_RECORDS};

const SLOG2_PARSE_MAX_NAME_SIZE: usize = 64;

/// `slog2_packet_info_t` (QNX 7.1, sys `slog2_parse.h`). `#[repr(C)]`; field order
/// and the `[c_char; N]` name arrays mirror the header exactly (size 232 bytes,
/// checked against C `sizeof`). `data_type` values: ASCII_STRING=0, BINARY=1,
/// UNSYNC=2, ONLINE=3.
#[repr(C)]
struct PacketInfo {
    size: u32,
    sequence_number: u16,
    data_size: u16,
    timestamp: u64,
    data_type: u32,
    thread_id: u16,
    code: u16,
    severity: u8,
    file_name: [c_char; 2 * SLOG2_PARSE_MAX_NAME_SIZE],
    buffer_name: [c_char; SLOG2_PARSE_MAX_NAME_SIZE],
    owner_pid: u32,
    flags: u32,
    register_flags: u32,
}

type PacketCallback = extern "C" fn(*mut PacketInfo, *mut c_void, *mut c_void) -> c_int;

extern "C" {
    fn slog2_parse_all(
        flags: u32,
        directory_path: *mut c_char,
        match_list: *mut c_char,
        packet_info: *mut PacketInfo,
        callback: PacketCallback,
        param: *mut c_void,
    ) -> c_int;
}

/// slog2 severity (0=SHUTDOWN … 7=DEBUG2) → SOVD priority name. Mirrors the
/// score-log-slog2 write mapping so a round-trip is stable.
fn severity_name(sev: u8) -> &'static str {
    match sev {
        0 => "emergency", // SHUTDOWN
        1 => "critical",  // CRITICAL
        2 => "error",     // ERROR
        3 => "warning",   // WARNING
        4 => "notice",    // NOTICE
        5 => "info",      // INFO
        6 | 7 => "debug", // DEBUG1 / DEBUG2
        _ => "info",
    }
}

/// Accumulator passed as `param` through the C callback.
struct Acc<'q> {
    q: &'q LogQuery,
    out: Vec<LogRecord>,
    /// Stop pushing once we've gathered a safe upper bound (post-filter tail trims
    /// to the requested count); bounds memory on a huge ring.
    cap: usize,
}

/// The per-packet callback. Maps an ASCII packet to a `LogRecord`, applies the
/// query filters, and pushes it. Returns 0 to continue, non-zero to stop early.
extern "C" fn on_packet(info: *mut PacketInfo, payload: *mut c_void, param: *mut c_void) -> c_int {
    // SAFETY: slog2_parse_all passes our `Acc` as `param`, and a valid `info` +
    // (for ASCII packets) NUL-terminated `payload` for the duration of the call.
    unsafe {
        let acc = &mut *(param as *mut Acc);
        if acc.out.len() >= acc.cap {
            return 1; // enough gathered — stop the walk
        }
        let pi = &*info;
        // Only ASCII string packets carry a text message; skip binary/unsync.
        if pi.data_type != 0 || payload.is_null() {
            return 0;
        }
        let message = CStr::from_ptr(payload as *const c_char)
            .to_string_lossy()
            .into_owned();
        // The EMITTER (buffer-SET name: snova / vhsm / devb_ram / …) is the
        // packet's `file_name` — slog2 names each buffer set's on-disk file after
        // the set, so `file_name` holds the registrant name. The per-packet
        // `buffer_name` is only the INNER buffer ("default" / "slog"), NOT the
        // emitter — don't use it. (buffer_set_name lives in slog2_log_info_t, not
        // the packet.) component-mgr maps this LogRecord.source → fields.emitter.
        // The slog2 buffer-set name IS the emitter (snova / devb_sdmmc_mx8x / …).
        let emitter = cstr_field(&pi.file_name);
        let priority = severity_name(pi.severity);
        // timestamp is nanoseconds since the epoch (QNX CLOCK_REALTIME).
        let secs = pi.timestamp / 1_000_000_000;

        // Emitter include/exclude FIRST — before the cap check above would have
        // fired — so a muted high-volume emitter (the devb_* eMMC/CAM firehose)
        // never consumes the gather budget and can't crowd real records out of
        // the tail. This is the whole point of server-side emitter filtering.
        if !acc.q.emitter_allows(&emitter) {
            return 0;
        }

        // Filters (parse_all has no native match): source/pattern/priority here.
        // NOTE: `source` on the slog2 record carries the EMITTER (see below); the
        // component-mgr layer sets the physical `source="slog2"` and checks that.
        if let Some(src) = &acc.q.source {
            if &emitter != src {
                return 0;
            }
        }
        if let Some(pat) = &acc.q.pattern {
            if !message.contains(pat.as_str()) {
                return 0;
            }
        }
        if let Some(want) = &acc.q.priority {
            if priority != want.as_str() {
                return 0;
            }
        }
        acc.out.push(LogRecord {
            timestamp: crate::rfc3339_utc(secs),
            priority: priority.into(),
            message,
            // The reader carries the emitter in `source`; component-mgr maps it to
            // `fields.emitter` and sets the physical `source="slog2"`.
            source: emitter,
        });
    }
    0
}

/// Read a fixed-size C `char[N]` name field as an owned `String` (NUL-terminated).
fn cstr_field(buf: &[c_char]) -> String {
    // SAFETY: the field is a NUL-terminated C string within the array.
    unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

/// Read the current slog2 ring into records (oldest-first, filtered, tail-capped).
/// Returns `None` if the parse call fails outright (caller can fall back).
pub fn read(q: &LogQuery) -> Option<Vec<LogRecord>> {
    let mut info: PacketInfo = unsafe { std::mem::zeroed() };
    info.size = std::mem::size_of::<PacketInfo>() as u32;

    let mut acc = Acc {
        q,
        out: Vec::new(),
        // Gather up to 2× the cap so the post-walk tail can pick the newest N even
        // when filters are loose; bounded so a huge ring can't OOM.
        cap: MAX_RECORDS * 2,
    };

    // flags=0 (static snapshot of current buffers), dir=NULL (all buffers),
    // match_list=NULL (no buffer-set name filter — we filter in the callback).
    // SAFETY: valid `info` (size set), our callback + `Acc` as param; slog2_parse_all
    // owns the walk and the payload/info lifetime within each callback invocation.
    let rc = unsafe {
        slog2_parse_all(
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut info,
            on_packet,
            &mut acc as *mut Acc as *mut c_void,
        )
    };
    if rc < 0 {
        return None;
    }

    // since/until: parse_all is time-ordered; filter by the record timestamp after
    // the fact (bare-seconds bound, same convention as the journald reader).
    let mut out = acc.out;
    if let Some(since) = q.since.as_deref().and_then(parse_secs) {
        out.retain(|r| {
            rfc3339_secs(&r.timestamp)
                .map(|s| s >= since)
                .unwrap_or(true)
        });
    }
    if let Some(until) = q.until.as_deref().and_then(parse_secs) {
        out.retain(|r| {
            rfc3339_secs(&r.timestamp)
                .map(|s| s <= until)
                .unwrap_or(true)
        });
    }

    // Tail to the requested count (newest N).
    let n = q.tail.unwrap_or(DEFAULT_TAIL).min(MAX_RECORDS);
    if out.len() > n {
        out.drain(..out.len() - n);
    }
    Some(out)
}

/// Parse a bare unix-seconds string (the `END-<N>s`-resolved form SOVD sends).
fn parse_secs(s: &str) -> Option<u64> {
    s.trim().parse::<u64>().ok()
}

/// Best-effort inverse of `rfc3339_utc` for the since/until compare — only needs
/// the epoch seconds back. Parses `YYYY-MM-DDThh:mm:ssZ`. `None` if malformed.
fn rfc3339_secs(ts: &str) -> Option<u64> {
    // Cheap fixed-position parse (no chrono), inverse of crate::rfc3339_utc.
    let b = ts.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[19] != b'Z' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| ts.get(r).and_then(|s| s.parse::<i64>().ok());
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, s) = (num(11..13)?, num(14..16)?, num(17..19)?);
    // days_from_civil (Howard Hinnant).
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some((days * 86_400 + h * 3600 + mi * 60 + s) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_info_abi_size() {
        // Verified against C `sizeof(slog2_packet_info_t)` on QNX 7.1 = 232 bytes.
        assert_eq!(std::mem::size_of::<PacketInfo>(), 232);
    }

    #[test]
    fn severity_maps_to_sovd_names() {
        assert_eq!(severity_name(1), "critical");
        assert_eq!(severity_name(2), "error");
        assert_eq!(severity_name(5), "info");
        assert_eq!(severity_name(7), "debug");
    }

    #[test]
    fn rfc3339_secs_inverts_rfc3339_utc() {
        for secs in [0u64, 1_784_562_613, 951_827_696] {
            let ts = crate::rfc3339_utc(secs);
            assert_eq!(rfc3339_secs(&ts), Some(secs), "round-trip {ts}");
        }
        assert_eq!(rfc3339_secs("not-a-timestamp"), None);
    }
}
