//! Guest log agent — library half (everything testable off-target).
//!
//! The HOST's component-mgr answers SOVD §7.21 `GET /components/{vm}/logs`
//! by proxying this agent over the per-VM `guest_to_host` /30. One
//! endpoint, read-only:
//!
//! ```text
//!   GET /logs?tail=&source=&pattern=&priority=&since=&until=
//!     -> 200 application/json  [ LogRecord, ... ]  (oldest first)
//!   GET /files
//!     -> 200 application/json  [ FileEntry, ... ]  (the SOVD §7.20
//!        bulk-data catalog: the downloadable plain-file log sources)
//!   GET /files/{id}
//!     -> 200 application/octet-stream  the raw file bytes (bounded)
//!     -> 404 if {id} doesn't decode, or names a file NOT in the live
//!        allow-list (the set /files would return right now)
//!   GET /healthz -> 200 "ok"
//! ```
//!
//! `/files` + `/files/{id}` are the guest half of SOVD §7.20 bulk-data:
//! the host's component-mgr lists them under the component's `logs`
//! bulk-data category and proxies whole-file downloads. `id` is the
//! base64url (url-safe, no pad) of the file's ABSOLUTE path — stateless,
//! decodable straight back, no server-side id→file map. On Linux the
//! journald source has no discrete files, so `/files` lists only the
//! plain `/var/log` files there (journald whole-export is out of scope).
//!
//! Sources are OS-conventional:
//! - **QNX**: `/dev/shmem/*.log` (layer services — the declarative-hook
//!   logging convention) + `/var/log/*` (OS logs). `source` = file stem;
//!   file lines carry the file's mtime as their timestamp (best effort —
//!   the files are plain text).
//! - **Linux**: journald via `journalctl -o json` (real per-entry
//!   timestamps + priorities; layer services are systemd units, so
//!   journald IS the convention there).
//!
//! Bounds everywhere: last [`FILE_READ_CAP`] bytes per file, at most
//! [`MAX_RECORDS`] records per response, default tail [`DEFAULT_TAIL`].
//! A log read must never be able to OOM the guest or flood the wire.

use serde::Serialize;

/// Read at most this many bytes from the tail of one log file.
pub const FILE_READ_CAP: u64 = 64 * 1024;
/// Hard cap on records in one response (after filtering).
pub const MAX_RECORDS: usize = 2000;
/// `tail` when the query doesn't say.
pub const DEFAULT_TAIL: usize = 200;
/// Hard cap on a single `/files/{id}` download. The point of bulk-data is
/// "the whole file" (not a 64 KiB tail like `/logs`), but a runaway file
/// must not OOM the guest or flood the host→guest /30: a file at or under
/// the cap is served whole, a larger one is served TRUNCATED to this many
/// bytes. Matches the host's `MAX_BULK_BYTES`.
pub const FILE_DOWNLOAD_CAP: u64 = 32 * 1024 * 1024;

/// One log line on the wire. Field names are the CONTRACT — the host's
/// component-mgr parses exactly these (mirror-by-convention; see
/// Cargo.toml). Priorities use the SOVD §7.21 names
/// (emergency..debug), lowercase.
#[derive(Debug, Clone, Serialize)]
pub struct LogRecord {
    /// RFC 3339 UTC. For plain-file sources this is the file's mtime
    /// (all lines of one file share it) — honest best-effort.
    pub timestamp: String,
    /// emergency|alert|critical|error|warning|notice|info|debug
    pub priority: String,
    pub message: String,
    /// Service/file identity: file stem (QNX) or syslog identifier /
    /// unit (journald).
    pub source: String,
}

/// One downloadable log FILE in the `/files` bulk-data catalog. Field names
/// are the CONTRACT — the host's component-mgr parses exactly these into its
/// hand-mirrored `GuestFileRecord` (mirror-by-convention, like [`LogRecord`];
/// the host never git-deps this tree). `id` = base64url of the file's
/// ABSOLUTE path (see [`file_id`]); `modified` = mtime in epoch seconds (the
/// key the host filters `created-before`/`created-after` against).
#[derive(Debug, Clone, Serialize)]
pub struct FileEntry {
    /// Opaque, stateless id: base64url(no-pad) of the absolute path bytes.
    /// Decodes straight back to the path on download — no server-side map.
    pub id: String,
    /// The file's basename (e.g. `vhealth.log`) — human label only.
    pub name: String,
    /// File size in bytes (best effort; 0 if metadata is unavailable).
    pub size: u64,
    /// Source label = file stem (matches `/logs`' `source` for the same file).
    pub source: String,
    /// Last-modified time, epoch seconds (best effort; 0 if unavailable).
    pub modified: u64,
}

/// Parsed query filters (all optional).
#[derive(Debug, Default, Clone)]
pub struct LogQuery {
    pub tail: Option<usize>,
    pub source: Option<String>,
    /// Keep only these EMITTERs (sub-sources): comma-separated, prefix-matched.
    /// For slog2 the emitter is the per-buffer name (`snova`/`devb_sdmmc_mx8x`/…);
    /// on file/journald sources it coincides with `source`. Empty ⇒ all.
    pub emitter: Option<String>,
    /// DROP these emitters (comma-separated, prefix-matched), applied after the
    /// include. Mutes a high-volume sub-source (e.g. `devb_`) before the record
    /// is gathered — so it can't crowd real records out of a tail.
    pub emitter_exclude: Option<String>,
    pub pattern: Option<String>,
    pub priority: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    /// Opaque forward-paging cursor (journald `__CURSOR`). Only the `/logs/page`
    /// endpoint reads it; `/logs` (the tail view) ignores it.
    pub after: Option<String>,
}

/// One page of the `/logs/page` (cursor) view: the records plus the cursors.
/// Records are oldest-first (forward order).
///
/// Cursors (QNX svclog segment model — `<seq>:<offset>`, see
/// tasks/qnx-log-segments-design.md):
/// - `next_cursor` — resume point; feed back as `after`. `None` at the head
///   (paging loop terminates). On the journald path it's the `__CURSOR`.
/// - `oldest_cursor` — earliest still-available position (gap detection: a
///   client whose `after` is older got culled data).
/// - `tip_cursor` — "now" (`<max_seq>:<live_len>`); poll `after = tip` to
///   follow only new entries. Present even when `next_cursor` is None.
///
/// Each cursor is `#[serde(skip)]`-when-None, so the journald path (which sets
/// only next_cursor) and the host mirror stay compatible.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PagedLogs {
    pub items: Vec<LogRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tip_cursor: Option<String>,
}

impl LogQuery {
    /// Parse the raw query-string part of the request target
    /// (`tail=50&source=vhealth`). Unknown keys are ignored; values are
    /// percent-decoded.
    pub fn parse(qs: &str) -> Self {
        let mut q = LogQuery::default();
        for kv in qs.split('&') {
            let (k, v) = match kv.split_once('=') {
                Some((k, v)) => (k, percent_decode(v)),
                None => continue,
            };
            match k {
                "tail" | "limit" => q.tail = v.parse().ok(),
                "source" => q.source = Some(v),
                "x-sumo-emitter" => q.emitter = Some(v),
                "x-sumo-emitter-exclude" => q.emitter_exclude = Some(v),
                "pattern" => q.pattern = Some(v),
                "priority" => q.priority = Some(v),
                "since" => q.since = Some(v),
                "until" => q.until = Some(v),
                "after" => q.after = Some(v),
                _ => {}
            }
        }
        q
    }

    /// Whether an entry with the given `emitter` passes the emitter include /
    /// exclude filters. Both are comma-separated PREFIX lists (so `devb` matches
    /// `devb_sdmmc_mx8x`); include is applied first (empty ⇒ all), then exclude
    /// removes. Mirrors `sovd_core::LogFilter::emitter_allows` so the host and the
    /// guest agent filter identically. On sources with no sub-source (files,
    /// journald) the emitter is the `source`.
    pub fn emitter_allows(&self, emitter: &str) -> bool {
        let matches_any = |list: &str| {
            list.split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .any(|p| emitter.starts_with(p))
        };
        if let Some(inc) = self.emitter.as_deref() {
            if !inc.trim().is_empty() && !matches_any(inc) {
                return false;
            }
        }
        if let Some(exc) = self.emitter_exclude.as_deref() {
            if matches_any(exc) {
                return false;
            }
        }
        true
    }

    /// Apply the in-process filters (source/emitter/pattern) and the tail cap to
    /// an oldest-first record list. Priority/since/until are applied by
    /// the source readers where they can be (journald); plain files
    /// carry `info` and their mtime, so those filters degrade gracefully.
    pub fn apply(&self, mut records: Vec<LogRecord>) -> Vec<LogRecord> {
        if let Some(src) = &self.source {
            records.retain(|r| &r.source == src);
        }
        // Emitter filter: for file/journald sources the emitter is the source.
        if self.emitter.is_some() || self.emitter_exclude.is_some() {
            records.retain(|r| self.emitter_allows(&r.source));
        }
        if let Some(pat) = &self.pattern {
            records.retain(|r| r.message.contains(pat.as_str()));
        }
        if let Some(pri) = &self.priority {
            records.retain(|r| &r.priority == pri);
        }
        let tail = self.tail.unwrap_or(DEFAULT_TAIL).min(MAX_RECORDS);
        if records.len() > tail {
            records.drain(..records.len() - tail);
        }
        records
    }
}

/// Minimal percent-decoding (enough for patterns/timestamps in query
/// strings; invalid escapes pass through verbatim).
pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = b.get(i + 1..i + 3).and_then(|h| {
                    std::str::from_utf8(h)
                        .ok()
                        .and_then(|h| u8::from_str_radix(h, 16).ok())
                });
                match hex {
                    Some(v) => {
                        out.push(v);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Epoch seconds -> RFC 3339 UTC (`2026-07-18T15:50:13Z`). Hand-rolled
/// (days-from-civil inverse) so the guest tree stays chrono-free.
pub fn rfc3339_utc(epoch_secs: u64) -> String {
    let days = epoch_secs / 86_400;
    let secs = epoch_secs % 86_400;
    // Howard Hinnant's civil_from_days, shifted to the 0000-03-01 era.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Split a leading ISO-8601 UTC stamp off a svclog line.
///
/// svclog prepends `YYYY-MM-DDThh:mm:ssZ ` (a space-terminated RFC-3339-second
/// stamp) to every line it writes. Returns `(Some(stamp), rest)` when the line
/// begins with that exact shape, else `(None, whole_line)` — so an unstamped
/// line (a legacy/OS file, or a pre-svclog line) falls back to the caller's
/// mtime. Cheap byte check, no chrono: exactly `len("2026-07-18T15:50:13Z")`
/// = 20 chars matching the fixed digit/punct positions, then a space.
pub fn split_leading_stamp(line: &str) -> (Option<&str>, &str) {
    const N: usize = 20; // "YYYY-MM-DDThh:mm:ssZ"
    let b = line.as_bytes();
    if b.len() < N + 1 || b[N] != b' ' {
        return (None, line);
    }
    let ok = b[..N].iter().enumerate().all(|(i, &c)| match i {
        4 | 7 => c == b'-',
        10 => c == b'T',
        13 | 16 => c == b':',
        19 => c == b'Z',
        _ => c.is_ascii_digit(),
    });
    if ok {
        (Some(&line[..N]), &line[N + 1..])
    } else {
        (None, line)
    }
}

/// Read the last [`FILE_READ_CAP`] bytes of `path` and split into lines
/// (a torn first line after seeking is dropped). Returns oldest-first.
pub fn tail_file_lines(path: &std::path::Path) -> std::io::Result<Vec<String>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    let mut torn = false;
    if len > FILE_READ_CAP {
        f.seek(SeekFrom::Start(len - FILE_READ_CAP))?;
        torn = true;
    }
    let mut buf = Vec::with_capacity(FILE_READ_CAP.min(len) as usize);
    f.take(FILE_READ_CAP).read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf);
    let mut lines: Vec<String> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.to_string())
        .collect();
    if torn && !lines.is_empty() {
        lines.remove(0);
    }
    Ok(lines)
}

/// Inverse of [`rfc3339_utc`]: parse `YYYY-MM-DDThh:mm:ssZ` back to epoch
/// seconds (for `since`/`until` compares). `None` if malformed. No chrono.
pub fn rfc3339_secs(ts: &str) -> Option<u64> {
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

// ---------------------------------------------------------------------------
// Sealed-segment cursor reader (the svclog `<seq>:<offset>` model).
//
// A "segment source" is a directory holding an append-only, immutable set of
// sealed files `<stem>.<seq>.log` (seq a monotonically-growing integer, never
// reused) PLUS a single live file `<stem>.log` (the top, still-growing segment).
// The drainer (host slog2 drainer, or the guest svclog) is the writer; this is
// the READER: forward-page across the segment spine with a reboot-safe
// `<seq>:<offset>` cursor. `seq` is a logical clock independent of the (non-
// monotonic) wall clock, so paging stays correct across a device clock jump.
//
// Cursor `<seq>:<offset>`: resume at byte `offset` within segment `seq`, reading
// forward. The live file is addressed as the virtual seq `max_sealed + 1`.
// oldest = `<min_seq>:0`; tip = `<live_seq>:<live_len>`.
// ---------------------------------------------------------------------------

/// The seq of a sealed segment file name `<stem>.<seq>.log`, or `None` for the
/// live file `<stem>.log` (no numeric segment component) / a non-match.
fn seg_seq_of(name: &str, stem: &str) -> Option<u64> {
    let rest = name.strip_prefix(stem)?.strip_prefix('.')?;
    let seq = rest.strip_suffix(".log")?;
    if seq.is_empty() || !seq.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    seq.parse::<u64>().ok()
}

/// A resolved segment: its seq (live file = `max_sealed+1`) and path.
struct Segment {
    seq: u64,
    path: std::path::PathBuf,
    is_live: bool,
}

/// Enumerate `dir` for `<stem>.<seq>.log` sealed segments + the live `<stem>.log`,
/// numerically sorted ascending (oldest→newest, live last). `min_seq` = lowest
/// sealed seq (for the oldest cursor + gap detection); `live_seq` = the live
/// file's virtual seq (`max_sealed + 1`, or the lone segment if none sealed).
///
/// The live file may live in a SEPARATE directory from the sealed segments: the
/// slog2-drainer keeps its RAM live file in `/dev/shmem` while sealing to flash
/// (`/mnt/common-rw/log/segments`). `live_dir` names where `<stem>.log` lives;
/// `None` (the guest svclog case + tests) means it's colocated in `dir`. A live
/// file found in `dir` itself is always honoured too, so a colocated layout keeps
/// working regardless of `live_dir`.
fn enumerate_segments(
    dir: &std::path::Path,
    stem: &str,
    live_dir: Option<&std::path::Path>,
) -> (Vec<Segment>, Option<u64>, u64) {
    let mut sealed: Vec<Segment> = Vec::new();
    let mut live: Option<std::path::PathBuf> = None;
    let live_name = format!("{stem}.log");
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name == live_name {
                live = Some(e.path());
            } else if let Some(seq) = seg_seq_of(&name, stem) {
                sealed.push(Segment {
                    seq,
                    path: e.path(),
                    is_live: false,
                });
            }
        }
    }
    // Live file in a separate RAM dir (the drainer's /dev/shmem case): if we
    // didn't already find a colocated live file, look for `<stem>.log` there.
    if live.is_none() {
        if let Some(ld) = live_dir {
            let p = ld.join(&live_name);
            if p.exists() {
                live = Some(p);
            }
        }
    }
    sealed.sort_by_key(|s| s.seq);
    let min_seq = sealed.first().map(|s| s.seq);
    let max_sealed = sealed.last().map(|s| s.seq);
    // Live file's virtual seq: one past the highest sealed (or 0 if none yet).
    let live_seq = max_sealed.map_or(0, |m| m + 1);
    let mut segs = sealed;
    if let Some(path) = live {
        segs.push(Segment {
            seq: live_seq,
            path,
            is_live: true,
        });
    }
    (segs, min_seq, live_seq)
}

/// Parse a `<seq>:<offset>` cursor. `None` if malformed (treated as "from start").
fn decode_seg_cursor(s: &str) -> Option<(u64, u64)> {
    let (seq, off) = s.split_once(':')?;
    Some((seq.parse().ok()?, off.parse().ok()?))
}

/// One record parsed from a stamped segment line + the source stem.
fn seg_record(line: &str, stem: &str) -> LogRecord {
    let (stamp, rest) = split_leading_stamp(line);
    // After the stamp the drainer writes `<priority> <message>`. Peel the first
    // whitespace-delimited token; if it's a known SOVD priority name, use it and
    // the remainder is the message. Otherwise there's no priority token (a line
    // that isn't drainer-formatted) — treat the whole rest as the message at the
    // `info` default.
    let (priority, message) = split_leading_priority(rest);
    LogRecord {
        timestamp: stamp.map(str::to_string).unwrap_or_else(|| rfc3339_utc(0)),
        priority: priority.unwrap_or("info").to_string(),
        message: message.to_string(),
        source: stem.to_string(),
    }
}

/// Peel a leading SOVD priority token (`emergency`..`debug`) + its trailing space
/// off `s`. Returns `(Some(priority), message)` when the first token is a known
/// priority name, else `(None, s)` (no token — message is the whole string).
fn split_leading_priority(s: &str) -> (Option<&str>, &str) {
    match s.split_once(' ') {
        Some((tok, rest)) if is_priority_name(tok) => (Some(tok), rest),
        _ => (None, s),
    }
}

/// Is `t` one of the SOVD §7.21 priority names the drainer writes?
fn is_priority_name(t: &str) -> bool {
    matches!(
        t,
        "emergency" | "alert" | "critical" | "error" | "warning" | "notice" | "info" | "debug"
    )
}

/// Forward-page a sealed-segment source. Reads from `q.after` (`<seq>:<offset>`;
/// omitted ⇒ oldest) forward up to `tail`/`limit` records, across sealed
/// segments then the live file. Emits `next_cursor` (where it stopped; `None` at
/// head), `oldest_cursor` (`<min_seq>:0`), `tip_cursor` (`<live_seq>:<live_len>`).
/// Gap: an `after` naming a culled seq is clamped forward to the oldest available.
///
/// `live_dir` names where the still-growing `<stem>.log` lives when it is NOT
/// colocated with the sealed segments (the drainer keeps it in `/dev/shmem` while
/// sealing to flash). Pass `None` when live + sealed share `dir` (guest svclog /
/// tests). Without the correct `live_dir`, a source whose history hasn't sealed
/// yet reads EMPTY even though the live tail has content — the on-device bug where
/// `slog2` returned 0 items while `/dev/shmem/slog2.log` held 608 bytes.
pub fn read_segments(
    dir: &std::path::Path,
    stem: &str,
    live_dir: Option<&std::path::Path>,
    q: &LogQuery,
) -> PagedLogs {
    use std::io::{Read, Seek, SeekFrom};

    let (segs, min_seq, live_seq) = enumerate_segments(dir, stem, live_dir);
    if segs.is_empty() {
        return PagedLogs::default();
    }
    // Tip = live file at its current EOF (or the highest sealed EOF if no live).
    let tip_seq = live_seq;
    let live_len = segs
        .last()
        .filter(|s| s.is_live)
        .and_then(|s| std::fs::metadata(&s.path).ok())
        .map(|m| m.len())
        .unwrap_or(0);
    let tip_cursor = Some(format!("{tip_seq}:{live_len}"));
    let oldest_cursor = Some(format!("{}:0", min_seq.unwrap_or(0)));

    // Resolve the start position from `after`; clamp a culled/old seq forward.
    let (mut cur_seq, mut cur_off) = match q.after.as_deref().and_then(decode_seg_cursor) {
        Some((s, o)) => (s, o),
        None => (min_seq.unwrap_or(0), 0),
    };
    if let Some(m) = min_seq {
        if cur_seq < m {
            cur_seq = m;
            cur_off = 0;
        }
    }

    let page = q.tail.unwrap_or(DEFAULT_TAIL).min(MAX_RECORDS);
    let since = q.since.as_deref().and_then(rfc3339_secs);
    let until = q.until.as_deref().and_then(rfc3339_secs);

    let mut out: Vec<LogRecord> = Vec::new();
    let mut next_cursor: Option<String> = None;

    'walk: for seg in segs.iter().filter(|s| s.seq >= cur_seq) {
        // Where in THIS segment to start: the cursor offset for the resume
        // segment, else the segment's beginning.
        let start = if seg.seq == cur_seq { cur_off } else { 0 };
        let Ok(mut f) = std::fs::File::open(&seg.path) else {
            continue;
        };
        if start > 0 && f.seek(SeekFrom::Start(start)).is_err() {
            continue;
        }
        // Cap the read so one huge segment can't OOM; read from `start` forward.
        let mut buf = Vec::new();
        if f.take(FILE_DOWNLOAD_CAP).read_to_end(&mut buf).is_err() {
            continue;
        }
        // Walk complete lines, tracking the byte offset AFTER each consumed line
        // so next_cursor points at the next unread byte.
        let mut consumed: u64 = start;
        for raw in buf.split_inclusive(|&b| b == b'\n') {
            // A trailing partial line (no '\n') in the LIVE file is not yet
            // complete — stop before it so the cursor resumes there next poll.
            if !raw.ends_with(b"\n") {
                break;
            }
            let line_len = raw.len() as u64;
            let line = String::from_utf8_lossy(raw);
            let line = line.trim_end_matches('\n');
            consumed += line_len;
            if line.trim().is_empty() {
                continue;
            }
            let rec = seg_record(line, stem);
            // Filters (source is the stem; emitter == source here).
            if let Some(src) = &q.source {
                if &rec.source != src {
                    continue;
                }
            }
            if !q.emitter_allows(&rec.source) {
                continue;
            }
            if let Some(pat) = &q.pattern {
                if !rec.message.contains(pat.as_str()) {
                    continue;
                }
            }
            if since.is_some() || until.is_some() {
                if let Some(t) = rfc3339_secs(&rec.timestamp) {
                    if since.is_some_and(|s| t < s) || until.is_some_and(|u| t > u) {
                        continue;
                    }
                }
            }
            out.push(rec);
            if out.len() >= page {
                // Page full — resume AFTER this line next time.
                next_cursor = Some(format!("{}:{}", seg.seq, consumed));
                break 'walk;
            }
        }
    }

    PagedLogs {
        items: out,
        next_cursor,
        oldest_cursor,
        tip_cursor,
    }
}

// ---------------------------------------------------------------------------
// base64url (RFC 4648 §5, url-safe alphabet, NO padding).
//
// The `/files` id scheme needs base64url, but this crate is dep-light on
// purpose (serde + serde_json only, QNX-cross-safe) and the host mirrors the
// scheme by convention — so we hand-roll it here rather than add a dep. The
// alphabet is `A-Za-z0-9-_`; no `=` padding is emitted or accepted (ids stay
// URL-clean). Matches the host's `URL_SAFE_NO_PAD` engine byte-for-byte.
// ---------------------------------------------------------------------------

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode bytes as url-safe base64 without padding.
pub fn b64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        // Pack up to 3 bytes into a 24-bit big-endian group.
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        // Emit only the sextets that carry real bits (1→2 chars, 2→3, 3→4).
        out.push(B64URL[(n >> 18 & 0x3f) as usize] as char);
        out.push(B64URL[(n >> 12 & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64URL[(n >> 6 & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64URL[(n & 0x3f) as usize] as char);
        }
    }
    out
}

/// Decode url-safe base64 (no padding). Returns `None` on any invalid input
/// (out-of-alphabet char, or a dangling single sextet that can't form a byte).
pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        // A lone sextet (chunk.len()==1) has <6 bits of payload → invalid.
        if chunk.len() == 1 {
            return None;
        }
        let mut n = 0u32;
        for &c in chunk {
            n = (n << 6) | val(c)?;
        }
        // Left-align so the top bytes are the real ones, then emit len-1.
        n <<= 6 * (4 - chunk.len());
        out.push((n >> 16 & 0xff) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8 & 0xff) as u8);
        }
        if chunk.len() > 3 {
            out.push((n & 0xff) as u8);
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// §7.20 bulk-data — the downloadable-file catalog + secure download resolver.
// ---------------------------------------------------------------------------

/// The `/files` id for a path: base64url of the absolute path's UTF-8 bytes.
/// Stateless — decodes straight back on download, no server-side id→file map.
pub fn file_id(path: &std::path::Path) -> String {
    b64url_encode(path.to_string_lossy().as_bytes())
}

/// Enumerate the downloadable plain-file log sources in `dirs` — EXACTLY the
/// set `/logs` reads via `files_from_dirs`: any file ending `.log`, plus (in
/// `/var/log`) files with no suffix at all. This is both the `/files` catalog
/// AND the `/files/{id}` download allow-list (see [`resolve_download`]).
pub fn list_log_files(dirs: &[&str]) -> Vec<FileEntry> {
    let mut out = Vec::new();
    for dir in dirs {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // Same predicate as files_from_dirs: `.log` anywhere; or ANY file
            // under /var/log (the OS log dir keeps suffixless files too).
            let is_log = path
                .extension()
                .map(|e| e == "log")
                .unwrap_or(*dir == "/var/log");
            if !is_log || !path.is_file() {
                continue;
            }
            let meta = entry.metadata().ok();
            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            let modified = meta
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let name = path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "unknown".into());
            let source = path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "unknown".into());
            out.push(FileEntry {
                id: file_id(&path),
                name,
                size,
                source,
                modified,
            });
        }
    }
    // Deterministic order so the catalog is stable across calls.
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

/// Securely resolve a `/files/{id}` request to an on-disk path.
///
/// SECURITY (mandatory guard): the id decodes to an arbitrary path, so we must
/// NOT open whatever it names — a crafted id could otherwise read any file the
/// agent can see (path traversal / arbitrary read). We re-enumerate the source
/// dirs and require the id to be one [`list_log_files`] CURRENTLY advertises
/// (compared by the deterministic id string, so a match guarantees the decoded
/// path equals a listed file byte-for-byte). Re-enumerating each time — rather
/// than trusting the decoded path — keeps the allow-list authoritative even as
/// files rotate. Anything not in the set returns `None` → the caller 404s.
pub fn resolve_download(dirs: &[&str], id: &str) -> Option<std::path::PathBuf> {
    // Decode first so a malformed id (bad base64 / non-UTF-8) is a clean 404.
    let path_str = String::from_utf8(b64url_decode(id)?).ok()?;
    let requested = std::path::PathBuf::from(path_str);
    // Allow-list check: the id must be in the live catalog.
    if list_log_files(dirs).iter().any(|f| f.id == id) {
        Some(requested)
    } else {
        None
    }
}

/// Read up to [`FILE_DOWNLOAD_CAP`] bytes of `path` for a `/files/{id}`
/// download. Bounded via `take()`: a file at or under the cap is returned
/// whole; a larger one is TRUNCATED to the cap (documented over-cap behaviour).
pub fn read_file_capped(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let f = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    f.take(FILE_DOWNLOAD_CAP).read_to_end(&mut buf)?;
    Ok(buf)
}

/// journald `PRIORITY` (0..7) -> SOVD priority name.
pub fn journald_priority_name(p: &str) -> &'static str {
    match p {
        "0" => "emergency",
        "1" => "alert",
        "2" => "critical",
        "3" => "error",
        "4" => "warning",
        "5" => "notice",
        "7" => "debug",
        _ => "info",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_known_values() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(1_784_562_613), "2026-07-20T15:50:13Z");
        assert_eq!(rfc3339_utc(951_827_696), "2000-02-29T12:34:56Z"); // leap day
    }

    #[test]
    fn split_leading_stamp_parses_svclog_lines() {
        // A stamped svclog line → (stamp, message).
        let (s, m) = split_leading_stamp("2026-07-18T15:50:13Z [vhsm] starting");
        assert_eq!(s, Some("2026-07-18T15:50:13Z"));
        assert_eq!(m, "[vhsm] starting");

        // Stamp with an empty message (just the stamp + space).
        let (s, m) = split_leading_stamp("2026-07-18T15:50:13Z ");
        assert_eq!(s, Some("2026-07-18T15:50:13Z"));
        assert_eq!(m, "");
    }

    #[test]
    fn split_leading_stamp_rejects_unstamped() {
        // No stamp → (None, whole line) so the caller falls back to mtime.
        assert_eq!(split_leading_stamp("[vtime] daemon ready").0, None);
        // Right length but wrong shape (letters where digits go).
        assert_eq!(split_leading_stamp("XXXX-07-18T15:50:13Z msg").0, None);
        // Missing the trailing space separator.
        assert_eq!(split_leading_stamp("2026-07-18T15:50:13Zmsg").0, None);
        // Too short.
        assert_eq!(split_leading_stamp("2026-07-18").0, None);
        // A line that merely CONTAINS a stamp later is not split.
        assert_eq!(split_leading_stamp("err at 2026-07-18T15:50:13Z x").0, None);
    }

    #[test]
    fn query_parse_and_apply() {
        let q = LogQuery::parse("tail=2&source=vhealth&pattern=hb%20seq");
        assert_eq!(q.tail, Some(2));
        let rec = |src: &str, msg: &str| LogRecord {
            timestamp: rfc3339_utc(0),
            priority: "info".into(),
            message: msg.into(),
            source: src.into(),
        };
        let out = q.apply(vec![
            rec("vhealth", "hb seq 1"),
            rec("vtime-sync", "hb seq 2"),
            rec("vhealth", "hb seq 3"),
            rec("vhealth", "other"),
            rec("vhealth", "hb seq 4"),
        ]);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].message, "hb seq 3");
        assert_eq!(out[1].message, "hb seq 4");
    }

    #[test]
    fn emitter_filter_parse_and_apply() {
        let rec = |src: &str| LogRecord {
            timestamp: rfc3339_utc(0),
            priority: "info".into(),
            message: "m".into(),
            source: src.into(),
        };
        let all = || {
            vec![
                rec("snova"),
                rec("devb_sdmmc_mx8x"),
                rec("vhsm"),
                rec("CAM"),
            ]
        };

        // exclude drops the firehose (prefix-matched), keeps the rest.
        let q = LogQuery::parse("x-sumo-emitter-exclude=devb_,CAM");
        assert_eq!(q.emitter_exclude.as_deref(), Some("devb_,CAM"));
        let out = q.apply(all());
        let srcs: Vec<_> = out.iter().map(|r| r.source.as_str()).collect();
        assert_eq!(srcs, ["snova", "vhsm"]);

        // include narrows to the named emitters only.
        let q = LogQuery::parse("x-sumo-emitter=snova,vhsm");
        let out = q.apply(all());
        let srcs: Vec<_> = out.iter().map(|r| r.source.as_str()).collect();
        assert_eq!(srcs, ["snova", "vhsm"]);

        // no emitter filter → passthrough (all four).
        assert_eq!(LogQuery::parse("tail=10").apply(all()).len(), 4);
    }

    #[test]
    fn tail_file_bounded() {
        let dir = std::env::temp_dir().join(format!("log-agent-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("big.log");
        let line = "x".repeat(99) + "\n"; // 100 B/line
        let n = (FILE_READ_CAP as usize / 100) * 2; // 2x the cap
        std::fs::write(&p, line.repeat(n)).unwrap();
        let lines = tail_file_lines(&p).unwrap();
        assert!(lines.len() <= FILE_READ_CAP as usize / 100);
        assert!(lines.len() > 100);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn percent_decode_basics() {
        assert_eq!(percent_decode("a%20b+c%3d"), "a b c=");
        assert_eq!(percent_decode("100%"), "100%");
    }

    #[test]
    fn b64url_round_trip() {
        // All input lengths mod 3 (1→2 chars, 2→3, 0→4) round-trip.
        for input in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            b"/var/log/vhealth.log",
            b"/dev/shmem/vtime-sync.log",
            &[0x00, 0xff, 0xfe, 0x80, 0x7f],
        ] {
            let enc = b64url_encode(input);
            // url-safe alphabet only, never padding.
            assert!(!enc.contains('='), "no padding: {enc}");
            assert!(!enc.contains('+') && !enc.contains('/'), "url-safe: {enc}");
            assert_eq!(b64url_decode(&enc).as_deref(), Some(input));
        }
        // Known vector (RFC 4648): "foobar" → "Zm9vYmFy".
        assert_eq!(b64url_encode(b"foobar"), "Zm9vYmFy");
        // Invalid input → None (out-of-alphabet, dangling sextet).
        assert!(b64url_decode("****").is_none());
        assert!(b64url_decode("A").is_none()); // lone sextet, <1 byte
        assert!(b64url_decode("Zm9vYmFy=").is_none()); // padding not accepted
    }

    #[test]
    fn list_files_shape() {
        let dir = std::env::temp_dir().join(format!("log-agent-files-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("vhealth.log"), "hb 1\nhb 2\n").unwrap();
        std::fs::write(dir.join("skip.txt"), "not a log\n").unwrap();
        let dir_str = dir.to_str().unwrap();

        let files = list_log_files(&[dir_str]);
        // Only the .log file is listed (this dir isn't /var/log, so suffixless
        // files don't count and .txt is excluded).
        assert_eq!(files.len(), 1);
        let f = &files[0];
        assert_eq!(f.name, "vhealth.log");
        assert_eq!(f.source, "vhealth");
        assert_eq!(f.size, 10);
        // id decodes back to the absolute path.
        let decoded = String::from_utf8(b64url_decode(&f.id).unwrap()).unwrap();
        assert_eq!(decoded, dir.join("vhealth.log").to_string_lossy());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn download_allow_list_guard() {
        let dir = std::env::temp_dir().join(format!("log-agent-guard-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("svc.log"), "safe bytes\n").unwrap();
        let dir_str = dir.to_str().unwrap();

        // A listed file resolves + reads whole.
        let listed = list_log_files(&[dir_str]);
        let good = resolve_download(&[dir_str], &listed[0].id).unwrap();
        assert_eq!(read_file_capped(&good).unwrap(), b"safe bytes\n");

        // An id naming a real file OUTSIDE the source dirs (e.g. /etc/passwd)
        // is rejected — the guard re-enumerates and finds no match → None.
        let evil = b64url_encode(b"/etc/passwd");
        assert!(resolve_download(&[dir_str], &evil).is_none());
        // An id inside the dir but not currently present → rejected too.
        let ghost = file_id(&dir.join("gone.log"));
        assert!(resolve_download(&[dir_str], &ghost).is_none());
        // A malformed (non-base64) id → rejected, no panic.
        assert!(resolve_download(&[dir_str], "!!!not base64!!!").is_none());

        std::fs::remove_dir_all(&dir).ok();
    }

    // ── read_segments: the sealed-segment cursor reader ──────────────────────

    /// Build a segment dir: sealed `<stem>.<seq>.log` for each (seq, lines) +
    /// an optional live `<stem>.log`. `tag` MUST be unique per test — the tests
    /// run in parallel, so a shared dir name would cross-talk.
    fn seg_dir(
        tag: &str,
        stem: &str,
        sealed: &[(u64, &[&str])],
        live: &[&str],
    ) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("seg-test-{}-{}", std::process::id(), tag));
        std::fs::create_dir_all(&dir).unwrap();
        // clean any stragglers from a prior run
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                std::fs::remove_file(e.path()).ok();
            }
        }
        let stamp = "2026-07-20T15:50:13Z ";
        let write = |name: String, lines: &[&str]| {
            let body: String = lines.iter().map(|l| format!("{stamp}{l}\n")).collect();
            std::fs::write(dir.join(name), body).unwrap();
        };
        for (seq, lines) in sealed {
            write(format!("{stem}.{seq}.log"), lines);
        }
        if !live.is_empty() {
            write(format!("{stem}.log"), live);
        }
        dir
    }

    fn msgs(p: &PagedLogs) -> Vec<String> {
        p.items.iter().map(|r| r.message.clone()).collect()
    }

    #[test]
    fn read_segments_walks_spine_oldest_first_and_names_cursors() {
        // Two sealed segments + a live file.
        let dir = seg_dir(
            "spine",
            "slog2",
            &[(100, &["a1", "a2"]), (101, &["b1"])],
            &["live1", "live2"],
        );
        let q = LogQuery {
            tail: Some(10),
            ..Default::default()
        };
        let p = read_segments(&dir, "slog2", None, &q);
        // Oldest→newest across sealed then live; NOT wall-clock sorted.
        assert_eq!(msgs(&p), ["a1", "a2", "b1", "live1", "live2"]);
        // oldest = min sealed seq; tip = live seq (max_sealed+1) : live_len.
        assert_eq!(p.oldest_cursor.as_deref(), Some("100:0"));
        let live_len = std::fs::metadata(dir.join("slog2.log")).unwrap().len();
        assert_eq!(p.tip_cursor, Some(format!("102:{live_len}")));
        // Fit in one page → no next_cursor (head reached).
        assert!(p.next_cursor.is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_segments_pages_and_resumes_via_cursor() {
        let dir = seg_dir(
            "page",
            "slog2",
            &[(1, &["x1", "x2", "x3"]), (2, &["y1", "y2"])],
            &[],
        );
        // page=2 → first two, next_cursor set.
        let q1 = LogQuery {
            tail: Some(2),
            ..Default::default()
        };
        let p1 = read_segments(&dir, "slog2", None, &q1);
        assert_eq!(msgs(&p1), ["x1", "x2"]);
        let c1 = p1.next_cursor.clone().expect("more to read");

        // Resume: next page picks up exactly after x2.
        let q2 = LogQuery {
            tail: Some(2),
            after: Some(c1),
            ..Default::default()
        };
        let p2 = read_segments(&dir, "slog2", None, &q2);
        assert_eq!(msgs(&p2), ["x3", "y1"]);
        let c2 = p2.next_cursor.clone().expect("still more");

        // Final page crosses into seg 2 and reaches head → no next_cursor.
        let q3 = LogQuery {
            tail: Some(2),
            after: Some(c2),
            ..Default::default()
        };
        let p3 = read_segments(&dir, "slog2", None, &q3);
        assert_eq!(msgs(&p3), ["y2"]);
        assert!(p3.next_cursor.is_none(), "head reached");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_segments_gap_clamps_culled_after_forward() {
        // Oldest sealed is seq 5; a client whose cursor names culled seq 2 gets
        // clamped forward to the oldest available (no panic, no silent loss).
        let dir = seg_dir("gap", "slog2", &[(5, &["m1", "m2"])], &[]);
        let q = LogQuery {
            tail: Some(10),
            after: Some("2:0".into()),
            ..Default::default()
        };
        let p = read_segments(&dir, "slog2", None, &q);
        assert_eq!(msgs(&p), ["m1", "m2"]);
        assert_eq!(p.oldest_cursor.as_deref(), Some("5:0"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_segments_tip_follow_returns_empty() {
        // after == tip → nothing new (the follow-tail steady state).
        let dir = seg_dir("tip", "slog2", &[(1, &["only"])], &["livea"]);
        let p0 = read_segments(&dir, "slog2", None, &LogQuery::default());
        let tip = p0.tip_cursor.clone().unwrap();
        let q = LogQuery {
            after: Some(tip),
            ..Default::default()
        };
        let p = read_segments(&dir, "slog2", None, &q);
        assert!(
            p.items.is_empty(),
            "at tip → no new records: {:?}",
            msgs(&p)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_segments_live_file_in_separate_dir() {
        // The drainer keeps its live file in a SEPARATE RAM dir (/dev/shmem) from
        // the sealed segments (flash). read_segments must find the live tail via
        // `live_dir`. Regression: on-device `slog2` read 0 items while
        // /dev/shmem/slog2.log held content, because the reader only scanned the
        // (empty, not-yet-sealed) sealed dir.
        let sealed = std::env::temp_dir().join(format!("splitseg-{}-s", std::process::id()));
        let live = std::env::temp_dir().join(format!("splitseg-{}-l", std::process::id()));
        std::fs::create_dir_all(&sealed).unwrap();
        std::fs::create_dir_all(&live).unwrap();
        for d in [&sealed, &live] {
            if let Ok(rd) = std::fs::read_dir(d) {
                for e in rd.flatten() {
                    std::fs::remove_file(e.path()).ok();
                }
            }
        }
        // NO sealed segments yet — only a live file in the separate dir (the exact
        // on-device state: 608 B live, empty segments dir).
        std::fs::write(
            live.join("slog2.log"),
            "2026-08-01T13:21:00Z live-one\n2026-08-01T13:21:01Z live-two\n",
        )
        .unwrap();

        // Without live_dir the reader sees an empty sealed dir → nothing.
        let none = read_segments(&sealed, "slog2", None, &LogQuery::default());
        assert!(none.items.is_empty(), "no live_dir → misses the live tail");

        // With live_dir it finds the live file and returns its lines.
        let p = read_segments(&sealed, "slog2", Some(&live), &LogQuery::default());
        assert_eq!(
            msgs(&p),
            ["live-one", "live-two"],
            "reads the separate live file"
        );
        assert!(p.tip_cursor.is_some(), "live file names a tip");

        std::fs::remove_dir_all(&sealed).ok();
        std::fs::remove_dir_all(&live).ok();
    }

    #[test]
    fn read_segments_ignores_partial_trailing_line_in_live() {
        // Live file with a complete line + a torn (no-newline) tail: only the
        // complete line is returned; the cursor stops before the partial so the
        // next poll resumes there.
        let dir = seg_dir("partial", "slog2", &[], &[]);
        std::fs::write(
            dir.join("slog2.log"),
            "2026-07-20T15:50:13Z done\n2026-07-20T15:50:14Z partial-no-newline",
        )
        .unwrap();
        let p = read_segments(&dir, "slog2", None, &LogQuery::default());
        assert_eq!(msgs(&p), ["done"], "partial line withheld until complete");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_segments_empty_dir_is_empty_page() {
        let dir = seg_dir("empty", "slog2", &[], &[]);
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        let p = read_segments(&dir, "slog2", None, &LogQuery::default());
        assert!(p.items.is_empty());
        assert!(p.next_cursor.is_none() && p.oldest_cursor.is_none() && p.tip_cursor.is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn seg_seq_of_parses_only_numeric_sealed_names() {
        assert_eq!(seg_seq_of("slog2.100.log", "slog2"), Some(100));
        assert_eq!(seg_seq_of("slog2.log", "slog2"), None); // live file
        assert_eq!(seg_seq_of("slog2.x.log", "slog2"), None); // non-numeric
        assert_eq!(seg_seq_of("other.1.log", "slog2"), None); // wrong stem
        assert_eq!(seg_seq_of("slog2.1.txt", "slog2"), None); // wrong ext
    }
}

// ===========================================================================
// Readers — the platform-native log SOURCES, extracted from the guest log-agent
// so the host (component-mgr LogSource, a future Linux host) shares them. The
// guest log-agent is now a thin HTTP wrapper calling `collect` / `collect_page`
// / `list_log_files` / `resolve_download`.
//
// Source selection is by target OS (the platform-native convention), NOT a
// deployment flag: QNX = /dev/shmem + /var/log files; Linux = journald (native
// sd_journal, journalctl fallback) with /var/log files as the fallback.
// ===========================================================================

// Native journald reader — sd_journal FFI, indexed pushed-down filters. Behind the
// `journald-native` feature (it links libsystemd, which a cross-build sysroot may
// lack); without it the journalctl CLI fallback is used.
#[cfg(all(target_os = "linux", feature = "journald-native"))]
mod journal_native;

// Native QNX slog2 reader — libslog2parse FFI over the slogger2 ring.
#[cfg(target_os = "nto")]
mod slog2_reader;

/// Read the QNX `slogger2` ring (the system log) into records — the HOST's log
/// source (supernova's own records + driver/eMMC telemetry), read back over SOVD
/// §7.21 by component-mgr's `LogSource::Slog2`. Distinct from `collect` (which is
/// the guest log-agent's file/journald path): the host explicitly asks for slog2.
///
/// QNX-only. On other targets there is no slog2 ring, so this returns an empty
/// vec (the crate still builds; a Linux host would use the journald reader).
#[cfg(target_os = "nto")]
pub fn read_slog2(q: &LogQuery) -> Vec<LogRecord> {
    slog2_reader::read(q).unwrap_or_default()
}
#[cfg(not(target_os = "nto"))]
pub fn read_slog2(_q: &LogQuery) -> Vec<LogRecord> {
    Vec::new()
}

/// One packet delivered to a [`drain_live`] sink — the raw fields a drainer needs
/// to write a stamped segment line, before any policy/formatting.
#[derive(Debug, Clone)]
pub struct DrainRecord {
    /// Packet emit time, epoch seconds (QNX CLOCK_REALTIME; non-monotonic — the
    /// drainer stamps it honestly, the segment SEQ is the ordering spine).
    pub epoch_secs: u64,
    /// SOVD priority name (emergency..debug) from the packet severity.
    pub priority: &'static str,
    /// The slog2 buffer-set name = the EMITTER (snova / vhsm / devb_sdmmc_mx8x / …).
    pub emitter: String,
    pub message: String,
}

/// Live-follow the QNX slog2 ring, invoking `sink` for every ASCII packet as it
/// arrives (via `slog2_parse_all` in DYNAMIC|CURRENT mode). BLOCKS forever (the
/// ring stream never ends) — the drainer runs this on its own thread. QNX-only;
/// a no-op that returns immediately off-target.
#[cfg(target_os = "nto")]
pub fn drain_live<F: FnMut(DrainRecord)>(sink: F) {
    slog2_reader::drain_live(sink);
}
#[cfg(not(target_os = "nto"))]
pub fn drain_live<F: FnMut(DrainRecord)>(_sink: F) {}

/// QNX: plain-file logs. `/dev/shmem/*.log` is where the OS layer hook writes
/// every declared service's output; `/var/log/*` is the OS's own.
#[cfg(target_os = "nto")]
pub fn collect(_q: &LogQuery) -> Vec<LogRecord> {
    files_from_dirs(&["/dev/shmem", "/var/log"])
}

/// Linux: journald (layer services are systemd units — their output IS journald).
/// Falls back to file sources if the journal is unavailable (minimal images).
#[cfg(not(target_os = "nto"))]
pub fn collect(q: &LogQuery) -> Vec<LogRecord> {
    let recs = journald(q);
    if !recs.is_empty() {
        return recs;
    }
    files_from_dirs(&["/var/log"])
}

/// The plain-file log source dirs — the `/files` bulk-data catalog + the
/// `/files/{id}` download allow-list. QNX: `/dev/shmem` + `/var/log`; Linux:
/// `/var/log` only (journald has no discrete files). Mirrors `collect`'s sources.
#[cfg(target_os = "nto")]
pub fn file_dirs() -> &'static [&'static str] {
    &["/dev/shmem", "/var/log"]
}
#[cfg(not(target_os = "nto"))]
pub fn file_dirs() -> &'static [&'static str] {
    &["/var/log"]
}

/// Cursor forward-paging (the `/logs/page` view) — oldest→newest, resumable.
/// QNX svclog segment model: `<seq>:<offset>` cursors; see
/// tasks/qnx-log-segments-design.md.
#[cfg(target_os = "nto")]
pub fn collect_page(q: &LogQuery) -> PagedLogs {
    let (oldest, tip) = shmem_cursor_bounds();
    let items = if after_at_or_past_tip(q.after.as_deref(), &tip) {
        Vec::new()
    } else {
        q.apply(files_from_dirs(&["/dev/shmem", "/var/log"]))
    };
    PagedLogs {
        items,
        next_cursor: None,
        oldest_cursor: oldest,
        tip_cursor: tip,
    }
}

/// (oldest_cursor, tip_cursor) for the svclog segment set in /dev/shmem.
#[cfg(target_os = "nto")]
fn shmem_cursor_bounds() -> (Option<String>, Option<String>) {
    use std::fs;
    let dir = "/dev/shmem";
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return (None, None),
    };
    let mut min_seq: Option<u64> = None;
    let mut max_seq: u64 = 0;
    let mut live_bytes: u64 = 0;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".log") {
            continue;
        }
        let sz = entry.metadata().map(|m| m.len()).unwrap_or(0);
        let base = name.strip_suffix(".log").unwrap_or(&name);
        if let Some((_, seq)) = base.rsplit_once('.') {
            if !seq.is_empty() && seq.bytes().all(|b| b.is_ascii_digit()) {
                if let Ok(n) = seq.parse::<u64>() {
                    min_seq = Some(min_seq.map_or(n, |m| m.min(n)));
                    if n > max_seq {
                        max_seq = n;
                    }
                    continue;
                }
            }
        }
        live_bytes += sz;
    }
    let oldest = format!("{}:0", min_seq.unwrap_or(0));
    let tip = format!("{max_seq}:{live_bytes}");
    (Some(oldest), Some(tip))
}

/// True when the client's `after` cursor is at or past the current tip.
#[cfg(target_os = "nto")]
fn after_at_or_past_tip(after: Option<&str>, tip: &Option<String>) -> bool {
    let (a, t) = match (after, tip.as_deref()) {
        (Some(a), Some(t)) => (a, t),
        _ => return false,
    };
    let parse = |s: &str| -> Option<(u64, u64)> {
        let (seq, off) = s.split_once(':')?;
        Some((seq.parse().ok()?, off.parse().ok()?))
    };
    match (parse(a), parse(t)) {
        (Some(av), Some(tv)) => av >= tv,
        _ => false,
    }
}

/// Linux: journald IS the monotonic, reboot-safe cursor. `__CURSOR` pages FORWARD.
#[cfg(not(target_os = "nto"))]
pub fn collect_page(q: &LogQuery) -> PagedLogs {
    let (items, next_cursor) = journald_page(q);
    if !items.is_empty() || q.after.is_some() {
        let tip_cursor = next_cursor.clone();
        return PagedLogs {
            items,
            next_cursor,
            oldest_cursor: None,
            tip_cursor,
        };
    }
    PagedLogs {
        items: q.apply(files_from_dirs(&["/var/log"])),
        ..Default::default()
    }
}

/// One FORWARD page from journald: native `sd_journal` first, then `journalctl`.
#[cfg(not(target_os = "nto"))]
fn journald_page(q: &LogQuery) -> (Vec<LogRecord>, Option<String>) {
    #[cfg(all(target_os = "linux", feature = "journald-native"))]
    if let Some(res) = journal_native::journald_page(q) {
        return res;
    }
    journald_page_cli(q)
}

/// Read one FORWARD page from journald via `journalctl` + the resume cursor.
#[cfg(not(target_os = "nto"))]
fn journald_page_cli(q: &LogQuery) -> (Vec<LogRecord>, Option<String>) {
    let limit = q.tail.unwrap_or(DEFAULT_TAIL).min(MAX_RECORDS);
    let mut cmd = std::process::Command::new("journalctl");
    cmd.arg("-o").arg("json").arg("--no-pager");
    if let Some(c) = &q.after {
        cmd.arg("--after-cursor").arg(c);
    }
    cmd.arg("-n").arg(format!("{limit}"));
    if let Some(s) = &q.since {
        cmd.arg("--since").arg(s);
    }
    if let Some(u) = &q.until {
        cmd.arg("--until").arg(u);
    }
    let output = match cmd.output() {
        Ok(o) if o.status.success() => o,
        _ => return (Vec::new(), None),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut out = Vec::new();
    let mut last_cursor: Option<String> = None;
    for line in text.lines() {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let msg = match v.get("MESSAGE") {
            Some(serde_json::Value::String(s)) => s.clone(),
            _ => continue,
        };
        let source = ["SYSLOG_IDENTIFIER", "_SYSTEMD_UNIT", "_COMM"]
            .iter()
            .find_map(|k| v.get(*k).and_then(|s| s.as_str()))
            .unwrap_or("journal")
            .trim_end_matches(".service")
            .to_string();
        if let Some(src) = &q.source {
            if source != *src {
                continue;
            }
        }
        if let Some(pat) = &q.pattern {
            if !msg.contains(pat.as_str()) {
                continue;
            }
        }
        let pri = v
            .get("PRIORITY")
            .and_then(|p| p.as_str())
            .map(journald_priority_name)
            .unwrap_or("info");
        if let Some(want) = &q.priority {
            if pri != want.as_str() {
                continue;
            }
        }
        let usec: u64 = v
            .get("__REALTIME_TIMESTAMP")
            .and_then(|t| t.as_str())
            .and_then(|t| t.parse().ok())
            .unwrap_or(0);
        if let Some(c) = v.get("__CURSOR").and_then(|c| c.as_str()) {
            last_cursor = Some(c.to_string());
        }
        out.push(LogRecord {
            timestamp: rfc3339_utc(usec / 1_000_000),
            priority: pri.into(),
            message: msg,
            source,
        });
        if out.len() >= limit {
            break;
        }
    }
    let next_cursor = if out.len() >= limit {
        last_cursor
    } else {
        None
    };
    (out, next_cursor)
}

/// Read plain-file log lines from `dirs` into records (oldest-first, bounded).
fn files_from_dirs(dirs: &[&str]) -> Vec<LogRecord> {
    let mut out = Vec::new();
    for dir in dirs {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let is_log = path
                .extension()
                .map(|e| e == "log")
                .unwrap_or(*dir == "/var/log");
            if !is_log || !path.is_file() {
                continue;
            }
            let source = log_source_of(&path);
            let mtime = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let mtime_ts = rfc3339_utc(mtime);
            let lines = match tail_file_lines(&path) {
                Ok(l) => l,
                Err(_) => continue,
            };
            for line in lines {
                let (stamp, msg) = split_leading_stamp(&line);
                out.push(LogRecord {
                    timestamp: stamp
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| mtime_ts.clone()),
                    priority: "info".into(),
                    message: msg.to_string(),
                    source: source.clone(),
                });
                if out.len() >= MAX_RECORDS {
                    return out;
                }
            }
        }
    }
    out
}

/// The service `source` label for a log file — the file stem with any svclog
/// segment number stripped (`vhsm-daemon.5.log` → `vhsm-daemon`).
fn log_source_of(path: &std::path::Path) -> String {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".into());
    let base = name.strip_suffix(".log").unwrap_or(&name);
    if let Some((stem, seq)) = base.rsplit_once('.') {
        if !seq.is_empty() && seq.bytes().all(|b| b.is_ascii_digit()) {
            return stem.to_string();
        }
    }
    base.to_string()
}

/// Tail the newest matching journald entries: native `sd_journal` first, then the
/// `journalctl` CLI fallback.
#[cfg(not(target_os = "nto"))]
fn journald(q: &LogQuery) -> Vec<LogRecord> {
    #[cfg(all(target_os = "linux", feature = "journald-native"))]
    if let Some(recs) = journal_native::journald(q) {
        return recs;
    }
    journald_cli(q)
}

#[cfg(not(target_os = "nto"))]
fn journald_cli(q: &LogQuery) -> Vec<LogRecord> {
    let mut cmd = std::process::Command::new("journalctl");
    cmd.arg("-o").arg("json").arg("--no-pager");
    let n = q.tail.unwrap_or(DEFAULT_TAIL).min(MAX_RECORDS);
    let fetch = if q.pattern.is_some() || q.source.is_some() || q.priority.is_some() {
        MAX_RECORDS * 2
    } else {
        (n * 4).min(MAX_RECORDS * 2)
    };
    cmd.arg("-n").arg(format!("{fetch}"));
    if let Some(s) = &q.since {
        cmd.arg("--since").arg(s);
    }
    if let Some(u) = &q.until {
        cmd.arg("--until").arg(u);
    }
    let output = match cmd.output() {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut out = Vec::new();
    for line in text.lines() {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let msg = match v.get("MESSAGE") {
            Some(serde_json::Value::String(s)) => s.clone(),
            _ => continue,
        };
        let usec: u64 = v
            .get("__REALTIME_TIMESTAMP")
            .and_then(|t| t.as_str())
            .and_then(|t| t.parse().ok())
            .unwrap_or(0);
        let source = ["SYSLOG_IDENTIFIER", "_SYSTEMD_UNIT", "_COMM"]
            .iter()
            .find_map(|k| v.get(*k).and_then(|s| s.as_str()))
            .unwrap_or("journal")
            .trim_end_matches(".service")
            .to_string();
        let pri = v
            .get("PRIORITY")
            .and_then(|p| p.as_str())
            .map(journald_priority_name)
            .unwrap_or("info");
        out.push(LogRecord {
            timestamp: rfc3339_utc(usec / 1_000_000),
            priority: pri.into(),
            message: msg,
            source,
        });
        if out.len() >= MAX_RECORDS {
            break;
        }
    }
    out
}
