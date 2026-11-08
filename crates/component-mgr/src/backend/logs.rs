use super::*;

// ---------------------------------------------------------------------------
// Reboot-safe log pagination — HOST-FILE tier (tasks/log-retrieval-design.md)
//
// The wire cursor is OPAQUE to clients (base64url of a compact JSON). It carries
// a per-boot epoch plus a per-source resume byte offset. WHY each piece exists:
//
//   * A byte offset into an append-only file is ALREADY reboot-safe: a byte
//     position is monotonic no matter what the host's 1970→floor→1970 wall clock
//     does. So offset alone pages PERSISTENT files (/var/log, log-rotate'd)
//     correctly across a reboot — the offset stays valid.
//   * boot_epoch has ONE job: INVALIDATE offsets for VOLATILE sources. A file
//     under /dev/shmem (QNX RAM) is wiped on reboot, so a saved offset into it is
//     meaningless post-reboot. When the cursor's boot_epoch differs from the
//     current one AND the source is volatile, we restart that source from 0.
//   * boot_epoch is NOT a per-line key (MM does not own most host log lines —
//     they're written by other producers into arbitrary glob'd files), so we do
//     NOT stamp lines with it. It is purely a cursor-invalidation tag.
// ---------------------------------------------------------------------------

/// Environment override for the boot-epoch persistence file, so tests never
/// touch `/var/lib`. When unset, [`DEFAULT_BOOT_EPOCH_FILE`] is used.
pub(super) const BOOT_EPOCH_FILE_ENV: &str = "MACHINE_MGR_BOOT_EPOCH_FILE";
/// Default persistence path for the boot-epoch counter. Deliberately a TINY
/// plain file, NOT nv-store: nv-store is safety-relevant + format-specced;
/// boot_epoch is only a log-cursor invalidation tag. Worst case if it's lost or
/// reset = volatile cursors restart from oldest = SAFE (design doc Q1).
pub(super) const DEFAULT_BOOT_EPOCH_FILE: &str = "/var/lib/machine-mgr/boot_epoch";

/// Process-wide cached boot epoch. Read + incremented + written back ONCE at the
/// first paged-log request (see [`current_boot_epoch`]); never bumped per-request.
pub(super) static BOOT_EPOCH: OnceLock<u64> = OnceLock::new();

/// The default page size (entries) when the client sets neither `limit` nor
/// `tail`, and the hard cap — matches the non-paged `host_file_logs` path.
pub(super) const PAGE_DEFAULT: usize = 200;
pub(super) const PAGE_MAX: usize = 2000;

/// Return the process-wide boot epoch, reading + incrementing + persisting the
/// counter file on first call. Its only job is to invalidate cursors for
/// volatile log sources across a reboot; a read/write failure is NON-FATAL
/// (warn + fall back to an in-memory value) because a lost epoch merely restarts
/// volatile sources from oldest, which is safe.
pub(super) fn current_boot_epoch() -> u64 {
    *BOOT_EPOCH.get_or_init(|| {
        let path = std::env::var(BOOT_EPOCH_FILE_ENV)
            .unwrap_or_else(|_| DEFAULT_BOOT_EPOCH_FILE.to_string());
        bump_boot_epoch_file(Path::new(&path))
    })
}

/// Read the u64 in `path` (0 if absent/unparseable), increment, write it back,
/// and return the incremented value. Failures to read/write are logged at
/// `warn` and treated as a 0 baseline (→ returns 1) so the daemon still boots.
pub(super) fn bump_boot_epoch_file(path: &Path) -> u64 {
    let prev = match std::fs::read_to_string(path) {
        Ok(s) => s.trim().parse::<u64>().unwrap_or(0),
        // Absent file is the normal first-boot case (not a warn); other errors
        // (permissions, IO) are unusual — surface them but keep going.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e,
                "boot_epoch file unreadable — starting from 0 (volatile cursors will restart)");
            0
        }
    };
    let next = prev.saturating_add(1);
    // Best-effort persist: create the parent dir, then write. A failure only
    // means the NEXT boot re-uses this epoch → volatile cursors restart once
    // more; still safe, so we don't propagate the error.
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(path, next.to_string()) {
        tracing::warn!(path = %path.display(), error = %e,
            "boot_epoch file unwritable — epoch not persisted this boot");
    }
    next
}

/// Path-based volatility classification (design doc step 2): a file under
/// `/dev/shmem` (QNX RAM) is VOLATILE — wiped on reboot, so a saved offset into
/// it is meaningless across boots. Everything else (log-rotate'd `/var/log`
/// files) is PERSISTENT — a byte offset survives the reboot unchanged.
pub(super) fn is_volatile(path: &Path) -> bool {
    path.starts_with("/dev/shmem")
}

/// Per-source position within the cursor: the file's rotation generation and the
/// byte offset to RESUME reading at (the offset AFTER the last complete line
/// returned). Compact single-letter keys keep the encoded cursor small.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct SourcePos {
    /// Rotation generation: 0 = the live base file `{path}`; 1 = `{path}.1`; etc.
    /// FIRST CUT: we page only the live base file, so `g` is always 0 today (see
    /// `host_file_logs_paged` TODO). It is carried so a later rotated-set pager
    /// can populate it without a cursor-format change.
    #[serde(rename = "g")]
    pub(super) gen: u64,
    /// Byte offset to resume at.
    #[serde(rename = "o")]
    pub(super) offset: u64,
}

/// The decoded log cursor. Wire form is base64url(no-pad) of this struct's JSON;
/// clients NEVER parse it (journald discipline — see design doc).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct LogCursor {
    /// The boot epoch this cursor was minted under. If it differs from the
    /// current epoch, offsets into volatile sources are void.
    #[serde(rename = "b")]
    pub(super) boot_epoch: u64,
    /// Per-source resume position, keyed by the file-stem source name that
    /// `host_file_logs` already uses. `BTreeMap` for a deterministic key order
    /// (stable encoded cursor, easier round-trip assertions).
    #[serde(rename = "s")]
    pub(super) sources: BTreeMap<String, SourcePos>,
}

impl LogCursor {
    /// Encode as an opaque base64url(no-pad) token. Reuses the crate's existing
    /// `b64url` helper (same encoding as the log-id scheme) — no new dep.
    pub(super) fn encode(&self) -> String {
        // serde_json on a small fixed struct cannot realistically fail; if it
        // ever did, an empty string decodes back to "no cursor" (start oldest),
        // which is the safe fallback rather than a 500.
        serde_json::to_vec(self)
            .map(|j| b64url(&j))
            .unwrap_or_default()
    }

    /// Decode an opaque token. Returns `None` for any malformed input so the
    /// caller treats a bad cursor as "no cursor" (start from oldest) — never a
    /// 500, per the design contract.
    pub(super) fn decode(token: &str) -> Option<LogCursor> {
        let bytes = b64url_decode(token)?;
        serde_json::from_slice(&bytes).ok()
    }
}

/// Reboot-safe, paginable variant of [`host_file_logs`]. Reads FORWARD from each
/// source's cursor offset (not a last-64KB tail), returns the entries plus a
/// `next_cursor` advanced past what it consumed, and an `oldest_cursor` pointing
/// at offset 0 for every source under the current boot epoch.
///
/// FIRST CUT — base-file-only paging: we page the live base file `{path}` (gen
/// 0) only. Rotated files (`{path}.1`, `{path}.2`, …) are NOT yet walked — that
/// is the documented follow-up (see the `gen` field). We STILL detect rotation /
/// truncation via the offset-vs-length gap check below, so we never silently
/// skip or re-read: if the file shrank under a saved offset we restart it from 0.
pub(super) fn host_file_logs_paged(
    globs: &[String],
    filter: &LogFilter,
    boot_epoch: u64,
) -> LogPage {
    let cursor = filter.after.as_deref().and_then(LogCursor::decode);
    // A cursor minted under a different boot epoch only invalidates VOLATILE
    // sources; persistent offsets stay valid (a byte position is reboot-stable).
    let cursor_epoch = cursor.as_ref().map(|c| c.boot_epoch);

    let page_size = filter
        .tail
        .or(filter.limit)
        .unwrap_or(PAGE_DEFAULT)
        .min(PAGE_MAX);

    let files = resolve_log_files(globs);

    let mut items: Vec<LogEntry> = Vec::new();
    // The next cursor's per-source offsets and the oldest (offset-0) positions.
    let mut next_sources: BTreeMap<String, SourcePos> = BTreeMap::new();
    let mut oldest_sources: BTreeMap<String, SourcePos> = BTreeMap::new();
    // Did we read anything new from ANY source? If not, next_cursor = None so a
    // client's paging loop terminates (they've reached the head).
    let mut produced_any = false;

    for path in files {
        let source = source_name(&path);
        // Every resolved source contributes an oldest (offset-0) position.
        oldest_sources.insert(source.clone(), SourcePos { gen: 0, offset: 0 });

        // Source filter: honour it exactly as host_file_logs does.
        if let Some(want) = &filter.source {
            if want != &source {
                continue;
            }
        }

        // mtime drives the entry timestamp AND the since/until pre-filter (same
        // coarse semantics as host_file_logs — these are file-level, not
        // per-line, because host lines are unstructured text with no timestamp).
        let mtime = file_mtime(&path);
        if let Some(since) = filter.since {
            if mtime < since {
                // Skipped by time — but still resume from where the cursor was so
                // a later mtime bump doesn't replay the whole file.
                if let Some(pos) = cursor.as_ref().and_then(|c| c.sources.get(&source)) {
                    next_sources.insert(source.clone(), *pos);
                }
                continue;
            }
        }
        if let Some(until) = filter.until {
            if mtime > until {
                if let Some(pos) = cursor.as_ref().and_then(|c| c.sources.get(&source)) {
                    next_sources.insert(source.clone(), *pos);
                }
                continue;
            }
        }

        let file_len = match std::fs::metadata(&path) {
            Ok(m) => m.len(),
            Err(_) => continue, // vanished/unreadable → skip (not an error)
        };

        // Determine the resume offset for this source.
        let saved = cursor.as_ref().and_then(|c| c.sources.get(&source));
        let volatile = is_volatile(&path);
        let start_offset = match saved {
            // No cursor, or this source absent from it → start at oldest.
            None => 0,
            Some(pos) => {
                if cursor_epoch != Some(boot_epoch) && volatile {
                    // Volatile source across a reboot → offset void, restart.
                    0
                } else if pos.offset > file_len {
                    // File shrank (truncated / rotated / replaced) → GAP. Restart
                    // from 0; oldest_cursor (offset 0) will be > the client's
                    // `after` so they can detect the dropped history.
                    0
                } else {
                    pos.offset
                }
            }
        };

        // Read forward from start_offset, collecting COMPLETE lines and tracking
        // the byte offset after the last complete line consumed. A torn trailing
        // partial line is NOT consumed — its bytes stay for the next call.
        let remaining = page_size.saturating_sub(items.len());
        let (lines, new_offset) = match read_lines_from(&path, start_offset, remaining) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if new_offset > start_offset {
            produced_any = true;
        }
        // Record where this source resumes next time. Even a source we didn't
        // advance keeps its position so the cursor stays complete.
        next_sources.insert(
            source.clone(),
            SourcePos {
                gen: 0,
                offset: new_offset,
            },
        );

        for line in lines {
            if let Some(pat) = &filter.pattern {
                if !line.contains(pat.as_str()) {
                    continue;
                }
            }
            // Per-line svclog stamp when present (else epoch "unknown"); the
            // message drops the stamp when one was parsed. See line_timestamp.
            let (ts, msg) = line_timestamp(&line);
            items.push(LogEntry {
                // Same content-addressed id scheme as host_file_logs so a paged
                // line re-resolves via get_log identically.
                id: line_log_id(&source, ts, msg),
                timestamp: ts,
                priority: LogPriority::Info,
                message: msg.to_string(),
                source: Some(source.clone()),
                pid: None,
                fields: None,
                log_type: None,
                size: None,
                status: None,
                href: None,
                metadata: None,
                uptime_secs: None, // host file: mtime-based, no monotonic clock
            });
        }

        if items.len() >= page_size {
            // Page full. Stop scanning; sources we never reached are carried
            // below (post-loop) so the next call resumes rather than replays
            // them. We break AFTER recording this source's advanced offset above.
            break;
        }
    }

    // Carry any source present in the INCOMING cursor that this scan didn't
    // touch (e.g. sources past a page-fill break, or one currently filtered out
    // by since/until): keep its prior offset so the next call resumes it instead
    // of replaying from oldest. New (never-seen) sources are intentionally NOT
    // synthesised here — they enter next_sources only once actually scanned.
    if let Some(c) = &cursor {
        for (source, pos) in &c.sources {
            next_sources.entry(source.clone()).or_insert(*pos);
        }
    }

    // Priority filter is "this level and above" (§7.21): lower enum value = more
    // severe. Host lines are always Info; keep the check for parity + future
    // structured sources.
    if let Some(p) = filter.priority {
        items.retain(|e| e.priority <= p);
    }

    let oldest_cursor = Some(
        LogCursor {
            boot_epoch,
            sources: oldest_sources,
        }
        .encode(),
    );

    // next_cursor = None when nothing new was read from ANY source (head
    // reached) → the client's loop stops. Otherwise carry the advanced offsets.
    let next_cursor = if produced_any {
        Some(
            LogCursor {
                boot_epoch,
                sources: next_sources,
            }
            .encode(),
        )
    } else {
        None
    };

    // tip_cursor = every current source at its CURRENT end-of-file (offset =
    // length). Polling `after=tip` returns only lines appended after this call —
    // the FOLLOW resume point. Computed from the live file lengths (not the page
    // offsets), so it names "now" even when the page stopped short of the end.
    let mut tip_sources: BTreeMap<String, SourcePos> = BTreeMap::new();
    for path in resolve_log_files(globs) {
        let src = source_name(&path);
        let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        tip_sources.insert(
            src,
            SourcePos {
                gen: 0,
                offset: len,
            },
        );
    }
    let tip_cursor = Some(
        LogCursor {
            boot_epoch,
            sources: tip_sources,
        }
        .encode(),
    );

    LogPage {
        items,
        next_cursor,
        oldest_cursor,
        tip_cursor,
    }
}

/// Resolve a set of `dir/prefix*suffix` (or literal) globs to a sorted, deduped
/// list of existing regular files. Extracted from `host_file_logs` so the paged
/// and non-paged readers resolve identically. Only ONE `*` in the filename
/// position is supported (no full glob engine) — a literal path matches itself.
pub(super) fn resolve_log_files(globs: &[String]) -> Vec<std::path::PathBuf> {
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    for g in globs {
        let p = std::path::Path::new(g);
        match p.file_name().and_then(|f| f.to_str()) {
            Some(name) if name.contains('*') => {
                let (prefix, suffix) = name.split_once('*').unwrap_or((name, ""));
                let dir = p.parent().unwrap_or(std::path::Path::new("/"));
                if let Ok(rd) = std::fs::read_dir(dir) {
                    for e in rd.flatten() {
                        let f = e.file_name();
                        let f = f.to_string_lossy();
                        if f.starts_with(prefix) && f.ends_with(suffix) && e.path().is_file() {
                            files.push(e.path());
                        }
                    }
                }
            }
            _ => {
                if p.is_file() {
                    files.push(p.to_path_buf());
                }
            }
        }
    }
    files.sort();
    files.dedup();
    files
}

/// The source name for a log file — its file stem (matches `host_file_logs`).
pub(super) fn source_name(path: &std::path::Path) -> String {
    path.file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "host".into())
}

/// A file's mtime as a UTC timestamp (UNIX epoch if unavailable) — the timestamp
/// stamped on every line from that file, matching `host_file_logs`.
pub(super) fn file_mtime(path: &std::path::Path) -> chrono::DateTime<Utc> {
    std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .map(chrono::DateTime::<Utc>::from)
        .unwrap_or(chrono::DateTime::<Utc>::UNIX_EPOCH)
}

/// Split a host log line into its own timestamp and the remaining message.
///
/// `svclog` (the guest service-log writer) prepends an ISO-8601 UTC stamp
/// (`YYYY-MM-DDThh:mm:ssZ `) to every line it writes, so a piped source carries a
/// real PER-LINE time. When that leading stamp parses, use it (and drop it from
/// the message — the SOVD `timestamp` field carries it instead).
///
/// When a line has NO self-timestamp (e.g. supernova's own un-piped stderr) we do
/// NOT substitute the file `mtime`: mtime is when the file was last written, not
/// when the line was logged, so it's worthless as a line time and — being shared
/// by every mtime-stamped line — reproduces the "all timestamps identical" bug.
/// Instead we return the UNIX epoch as an explicit "unknown" sentinel (the SOVD
/// `timestamp` is a non-optional `DateTime<Utc>`, so epoch is the honest in-type
/// way to say "no real time"), keeping the whole line as the message.
pub(super) fn line_timestamp(line: &str) -> (chrono::DateTime<Utc>, &str) {
    if let Some((head, rest)) = line.split_once(' ') {
        if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(head) {
            return (ts.with_timezone(&Utc), rest);
        }
    }
    (chrono::DateTime::<Utc>::UNIX_EPOCH, line)
}

/// Read forward from `start` in `path`, returning up to `max` COMPLETE lines and
/// the byte offset AFTER the last complete line consumed. A torn trailing partial
/// line (no terminating `\n`) is NOT consumed — its bytes are left for the next
/// call, so a line being appended concurrently is never split across pages.
/// Blank/whitespace-only lines are skipped (parity with `tail_file_lines`) but
/// their bytes still advance the offset so we don't re-scan them.
pub(super) fn read_lines_from(
    path: &std::path::Path,
    start: u64,
    max: usize,
) -> std::io::Result<(Vec<String>, u64)> {
    use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};

    let mut f = std::fs::File::open(path)?;
    // Defense-in-depth: a binary file caught by a glob (vendor fslog gzip/tar
    // artifacts, a stray binary `.log`) must not be paged out as lossy text.
    // Sample the file HEAD (offset 0, not `start`) so gzip magic is seen even
    // when resuming mid-file, then skip the whole file if it looks binary.
    {
        let mut head = [0u8; 512];
        let n = f.read(&mut head)?;
        if looks_binary(&head[..n]) {
            return Ok((Vec::new(), start));
        }
    }
    f.seek(SeekFrom::Start(start))?;
    let mut reader = BufReader::new(f);

    let mut lines: Vec<String> = Vec::new();
    let mut offset = start;
    // Read raw bytes so we can distinguish a complete line (ends in `\n`) from a
    // torn trailing partial (EOF with no newline) — `BufRead::lines` hides that.
    loop {
        if lines.len() >= max {
            break;
        }
        let mut raw: Vec<u8> = Vec::new();
        let n = reader.read_until(b'\n', &mut raw)?;
        if n == 0 {
            break; // EOF
        }
        if raw.last() != Some(&b'\n') {
            // Torn partial line at EOF — do NOT consume it or advance past it.
            break;
        }
        // Complete line: advance the offset past it regardless of whether we keep
        // it (blank lines still move the cursor so they aren't re-scanned).
        offset += n as u64;
        let text = String::from_utf8_lossy(&raw);
        let trimmed = text.trim_end_matches(['\n', '\r']);
        if !trimmed.trim().is_empty() {
            lines.push(trimmed.to_string());
        }
    }
    Ok((lines, offset))
}

/// Host-local file logs: bounded tails of every file matching the globs.
/// Only `dir/prefix*suffix` patterns (one `*`, filename position) — a
/// literal path matches itself. Lines carry the file's mtime; priority
/// Read the QNX `slogger2` ring (the [`LogSource::Slog2`] host source) into
/// `LogEntry`s. Maps the SOVD [`LogFilter`] to a `platform_log::LogQuery` (pushing
/// source/pattern/tail down; since/until as the server-resolved bare-seconds the
/// reader expects — priority handled here since slog2's scale differs), calls the
/// shared `read_slog2`, then maps records → entries with the SAME content-addressed
/// id scheme as host/guest lines so `get_log` re-resolves without server state.
/// Off QNX `read_slog2` is empty, so this yields nothing (a Linux host would use a
/// journald source instead).
pub(super) fn slog2_logs(filter: &LogFilter) -> Vec<LogEntry> {
    // The slog2 ring is ONE physical `source` ("slog2"); the per-buffer name is the
    // EMITTER (supernova, vhsm-ssd, devb_sdmmc, …), carried in `fields.emitter` —
    // not the source. So a `filter.source` naming a specific slog2 buffer would NOT
    // match here (source is always "slog2"); to narrow to one emitter a client
    // filters on the emitter field / message, not `source`. A `filter.source` set
    // to something OTHER than "slog2" means "not this source" → contribute nothing.
    if let Some(want) = &filter.source {
        if want != SLOG2_SOURCE {
            return Vec::new();
        }
    }
    let q = platform_log::LogQuery {
        tail: filter.tail.or(filter.limit),
        // Do NOT push filter.source down as a buffer-name match — under the
        // source/emitter split it's the physical source ("slog2"), already checked
        // above; the reader would otherwise treat it as a buffer filter.
        source: None,
        // Emitter include/exclude DO map to the slog2 buffer name — push them so
        // the reader drops muted emitters (e.g. the devb_* eMMC firehose) before
        // they consume the gather budget.
        emitter: filter.emitter.clone(),
        emitter_exclude: filter.emitter_exclude.clone(),
        pattern: filter.pattern.clone(),
        // slog2 severities don't line up 1:1 with SOVD "this level and above";
        // apply the priority filter below against the mapped LogPriority instead.
        priority: None,
        // read_segments parses these as bare unix-seconds (parse_secs_or_rfc3339 —
        // the END-relative sentinel the server already resolved to an absolute
        // time); pass the filter's absolute times as seconds.
        since: filter.since.map(|t| t.timestamp().to_string()),
        until: filter.until.map(|t| t.timestamp().to_string()),
        after: None,
        runtime_secs: filter.runtime_secs,
    };
    let records = platform_log::read_slog2(&q);
    let mut entries: Vec<LogEntry> = records
        .into_iter()
        .map(|r| {
            let timestamp = chrono::DateTime::parse_from_rfc3339(&r.timestamp)
                .map(|t| t.with_timezone(&Utc))
                .unwrap_or(chrono::DateTime::<Utc>::UNIX_EPOCH);
            // `r.source` from the reader is the slog2 BUFFER name → the emitter.
            let emitter = r.source;
            LogEntry {
                // Keep the emitter in the id input so two emitters' identical
                // messages/timestamps don't collide to the same log id.
                id: line_log_id(&format!("{SLOG2_SOURCE}:{emitter}"), timestamp, &r.message),
                timestamp,
                priority: priority_from_name(&r.priority),
                message: r.message,
                source: Some(SLOG2_SOURCE.to_string()),
                pid: None,
                // Emitter → structured field (queryable; matches how the journald
                // reader carries unit/identifier). source stays the physical bus.
                fields: Some(serde_json::json!({ "emitter": emitter })),
                log_type: None,
                size: None,
                status: None,
                href: None,
                metadata: None,
                uptime_secs: r.uptime_secs,
            }
        })
        .collect();
    // Priority filter is "this level and above" (§7.21): lower enum value = more
    // severe, so keep entries at or above the requested threshold.
    if let Some(p) = filter.priority {
        entries.retain(|e| e.priority <= p);
    }
    entries
}

/// The `source` for the raw QNX slog2 RING — the unfiltered, volatile live
/// firehose. Named `slog2-ring` (not `slog2`) because it is NOT the primary slog2
/// timeline: the ring's u16 `sequence_number` wraps and `slog2_parse_all` has no
/// resume API, so this source is `cursor:false` — good for "last N raw records /
/// sub-policy noise", but a client wanting the resumable slog2 log uses `slog2`
/// (the drained segments plane) instead. The per-buffer emitter
/// (supernova/vhsm-ssd/devb_sdmmc/…) is carried in `LogEntry.fields.emitter`, NOT
/// the source — slog2 is one bus, many emitters.
pub(super) const SLOG2_SOURCE: &str = "slog2-ring";

/// The `source` for the drained slog2 timeline: sealed flash segments → the live
/// drainer file, paged oldest→now as ONE reboot-safe `<seq>:<offset>` cursor
/// (`read_segments`). This is the PRIMARY, resumable slog2 log, so it takes the
/// bare `slog2` name; the raw volatile ring is `slog2-ring` (non-resumable). Both
/// planes ride the same slog2 bus — this one is the durable, cursor-pageable view.
pub(super) const SLOG2_SEGMENTS_SOURCE: &str = "slog2";

/// Build the `platform_log::LogQuery` shared by the segment read + page paths.
pub(super) fn slog2_segments_query(filter: &LogFilter) -> platform_log::LogQuery {
    platform_log::LogQuery {
        tail: filter.tail.or(filter.limit),
        source: None, // stem is passed to read_segments; source filter is the plane
        emitter: filter.emitter.clone(),
        emitter_exclude: filter.emitter_exclude.clone(),
        pattern: filter.pattern.clone(),
        priority: None, // applied below against the mapped LogPriority
        since: filter.since.map(|t| t.timestamp().to_string()),
        until: filter.until.map(|t| t.timestamp().to_string()),
        after: filter.after.clone(),
        runtime_secs: filter.runtime_secs,
    }
}

/// Map one segment `LogRecord` → a `LogEntry` (source = `slog2`, the resumable
/// drained timeline).
pub(super) fn slog2_segment_entry(r: platform_log::LogRecord) -> LogEntry {
    let timestamp = chrono::DateTime::parse_from_rfc3339(&r.timestamp)
        .map(|t| t.with_timezone(&Utc))
        .unwrap_or(chrono::DateTime::<Utc>::UNIX_EPOCH);
    LogEntry {
        id: line_log_id(SLOG2_SEGMENTS_SOURCE, timestamp, &r.message),
        timestamp,
        priority: priority_from_name(&r.priority),
        message: r.message,
        source: Some(SLOG2_SEGMENTS_SOURCE.to_string()),
        pid: None,
        fields: None,
        log_type: None,
        size: None,
        status: None,
        href: None,
        metadata: None,
        uptime_secs: r.uptime_secs,
    }
}

/// Read the PERSISTED slog2 segments (`LogSource::Slog2Segments`) as merged
/// (non-paged) entries — the tail/list view. A `filter.source` naming something
/// other than `slog2` (the resumable timeline) contributes nothing (source/plane check).
pub(super) fn slog2_segments_logs(
    dir: &str,
    stem: &str,
    live_dir: Option<&str>,
    filter: &LogFilter,
) -> Vec<LogEntry> {
    if let Some(want) = &filter.source {
        if want != SLOG2_SEGMENTS_SOURCE {
            return Vec::new();
        }
    }
    let page = platform_log::read_segments(
        std::path::Path::new(dir),
        stem,
        live_dir.map(std::path::Path::new),
        &slog2_segments_query(filter),
    );
    let mut entries: Vec<LogEntry> = page.items.into_iter().map(slog2_segment_entry).collect();
    if let Some(p) = filter.priority {
        entries.retain(|e| e.priority <= p);
    }
    entries
}

/// Paged read of the persisted slog2 segments — the reboot-safe `<seq>:<offset>`
/// cursor path (`GET /logs/sources/slog2` with `x-log-after`).
pub(super) fn slog2_segments_paged(
    dir: &str,
    stem: &str,
    live_dir: Option<&str>,
    filter: &LogFilter,
) -> LogPage {
    let page = platform_log::read_segments(
        std::path::Path::new(dir),
        stem,
        live_dir.map(std::path::Path::new),
        &slog2_segments_query(filter),
    );
    let mut items: Vec<LogEntry> = page.items.into_iter().map(slog2_segment_entry).collect();
    if let Some(p) = filter.priority {
        items.retain(|e| e.priority <= p);
    }
    LogPage {
        items,
        next_cursor: page.next_cursor,
        oldest_cursor: page.oldest_cursor,
        tip_cursor: page.tip_cursor,
    }
}

/// is `Info` (host logs are unstructured text).
pub(super) fn host_file_logs(globs: &[String], filter: &LogFilter) -> Vec<LogEntry> {
    const PER_FILE_CAP: u64 = 64 * 1024;
    const MAX_ENTRIES: usize = 2000;

    let files = resolve_log_files(globs);

    let mut entries: Vec<LogEntry> = Vec::new();
    for path in files {
        let source = source_name(&path);
        if let Some(want) = &filter.source {
            if want != &source {
                continue;
            }
        }
        let mtime = file_mtime(&path);
        if let Some(since) = filter.since {
            if mtime < since {
                continue;
            }
        }
        if let Some(until) = filter.until {
            if mtime > until {
                continue;
            }
        }
        let lines = match tail_file_lines(&path, PER_FILE_CAP) {
            Ok(l) => l,
            Err(_) => continue,
        };
        for line in lines.into_iter() {
            if let Some(pat) = &filter.pattern {
                if !line.contains(pat.as_str()) {
                    continue;
                }
            }
            // Per-line svclog stamp when present (else epoch "unknown"); the
            // message drops the stamp when one was parsed. See line_timestamp.
            let (ts, msg) = line_timestamp(&line);
            entries.push(LogEntry {
                // Stable, content-addressed id so get_log/get_log_content can
                // re-find this line by re-listing + matching (no server state,
                // stable across re-list while the line exists).
                id: line_log_id(&source, ts, msg),
                timestamp: ts,
                priority: LogPriority::Info,
                message: msg.to_string(),
                source: Some(source.clone()),
                pid: None,
                fields: None,
                log_type: None,
                size: None,
                status: None,
                href: None,
                metadata: None,
                uptime_secs: None, // host file: mtime-based, no monotonic clock
            });
            if entries.len() >= MAX_ENTRIES {
                break;
            }
        }
    }
    // Priority filter is "this level and above" (§7.21): lower enum value =
    // higher severity (Emergency=0 … Debug=7), so keep entries at or above.
    if let Some(p) = filter.priority {
        entries.retain(|e| e.priority <= p);
    }
    let tail = filter.tail.or(filter.limit).unwrap_or(200).min(MAX_ENTRIES);
    if entries.len() > tail {
        entries.drain(..entries.len() - tail);
    }
    entries
}

/// Heuristic "this is a binary file, not text" test on a sampled byte buffer.
/// A log tail is expected to be UTF-8 text; a gzip/tar archive (fslog's session
/// artifacts) or any file with NUL bytes is binary and must NOT be rendered as
/// lossy text. Cheap: gzip magic `1f 8b`, any NUL, or an outsized non-printable
/// ratio (control bytes other than tab/newline/CR) in the sampled prefix.
pub(super) fn looks_binary(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return false;
    }
    if buf.starts_with(&[0x1f, 0x8b]) {
        return true; // gzip magic (fslog .tar.gz / .log.gz)
    }
    // Sample the first 8 KiB — enough to classify without scanning huge tails.
    let sample = &buf[..buf.len().min(8 * 1024)];
    if sample.contains(&0) {
        return true; // NUL byte → not a text log
    }
    let nonprintable = sample
        .iter()
        .filter(|&&b| b < 0x20 && b != b'\t' && b != b'\n' && b != b'\r')
        .count();
    // >10% control bytes (excluding tab/newline/CR) → treat as binary.
    nonprintable * 10 > sample.len()
}

/// Last `cap` bytes of `path`, split into non-empty lines (a torn first
/// line after the seek is dropped). Mirrors the guest agent's reader.
pub(super) fn tail_file_lines(path: &std::path::Path, cap: u64) -> std::io::Result<Vec<String>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    let mut torn = false;
    if len > cap {
        f.seek(SeekFrom::Start(len - cap))?;
        torn = true;
    }
    let mut buf = Vec::with_capacity(cap.min(len) as usize);
    f.take(cap).read_to_end(&mut buf)?;
    // Defense-in-depth: never emit a binary file as lossy text. Even with
    // `*.log`-only globs, the vendor fslog persister drops gzip/tar archives in
    // /mnt/common-rw/log; a stray binary match would otherwise dump
    // replacement-char garbage to the SOVD client. Skip it (empty tail) instead.
    if looks_binary(&buf) {
        return Ok(Vec::new());
    }
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

// ---------------------------------------------------------------------------
// §7.21 log id scheme — stable, self-describing, STATELESS.
//
// `get_log`/`get_log_content`/`delete_log` must route an id back to its source
// without a server-side id→artifact map (which would be lost on restart and
// race the message-passing delete). So the id encodes everything needed:
//
//   line:<source>:<b64url(sha256(source|ts|message)[..12])>   a standard line
//   dump:host:<b64url(filename)>                               a host dump file
//   dump:<vmN>:<agent-id>                                      a guest dump (future)
//
// base64url(no-pad) keeps ids URL-clean. `dump:host` encodes only the FILE NAME
// (not the dir) — the dir comes from the component's own HostDumps config at
// fetch time, so the id can't be used to escape that dir (path-traversal safe).
// ---------------------------------------------------------------------------

/// OOM guard for a single inline bulk download (host file OR proxied guest
/// file). 32 MiB comfortably holds a rotated log file whole while bounding a
/// single response; a larger file is served truncated to this cap. Matches the
/// guest agent's `FILE_DOWNLOAD_CAP` so the two halves agree.
pub(super) const MAX_BULK_BYTES: u64 = 32 * 1024 * 1024;

pub(super) fn b64url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub(super) fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()
}

/// Content-addressed id for a standard log line (stable while the line exists).
pub(super) fn line_log_id(source: &str, ts: chrono::DateTime<Utc>, message: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(source.as_bytes());
    h.update(b"|");
    h.update(ts.to_rfc3339().as_bytes());
    h.update(b"|");
    h.update(message.as_bytes());
    let digest = h.finalize();
    format!("line:{source}:{}", b64url(&digest[..12]))
}

/// Id for a host dump file — encodes the bare filename (dir is config-supplied).
pub(super) fn dump_log_id(file_name: &str) -> String {
    format!("dump:host:{}", b64url(file_name.as_bytes()))
}

// ---------------------------------------------------------------------------
// §7.20 bulk-data item id — GUEST tier.
//
// A guest log FILE reachable via a component's `GuestAgent` source is exposed
// as a `logs` bulk-data ITEM. Its item id must be STATELESS + fully decodable
// so `get_bulk_data` can route the download back to the right agent WITHOUT a
// server-side map — carrying BOTH which guest (the agent url) and which file
// (the guest's opaque /files id). Scheme:
//
//   guest:<b64url(url)>:<guest_file_id>
//
// `guest:` is a fresh namespace (host-file items keep their bare `b64url(path)`
// id, unchanged — a host id never contains a `:`, so the two never collide and
// existing host-file behaviour + tests are preserved). The url is base64url'd
// so it can't introduce a stray `:`; the guest id is already base64url (no `:`)
// so it needs no wrapping and the split is unambiguous on the LAST-but-one `:`.
// ---------------------------------------------------------------------------

/// Build the guest-tier bulk-data item id (see the scheme comment above).
pub(super) fn guest_bulk_id(url: &str, guest_file_id: &str) -> String {
    format!("guest:{}:{}", b64url(url.as_bytes()), guest_file_id)
}

/// Decode a `guest:<b64url(url)>:<guest_file_id>` item id back to
/// `(url, guest_file_id)`. `None` for anything that isn't this scheme (a
/// host-file id — bare `b64url(path)`, no `guest:` prefix — falls through here
/// so `get_bulk_data` routes it to the existing host path).
pub(super) fn parse_guest_bulk_id(id: &str) -> Option<(String, String)> {
    let rest = id.strip_prefix("guest:")?;
    // `<b64url(url)>:<guest_file_id>` — the guest id is base64url (no `:`), so
    // the FIRST `:` cleanly separates the two halves.
    let (url_b64, guest_file_id) = rest.split_once(':')?;
    let url = String::from_utf8(b64url_decode(url_b64)?).ok()?;
    if url.is_empty() || guest_file_id.is_empty() {
        return None;
    }
    Some((url, guest_file_id.to_string()))
}

/// A parsed §7.21 log id — tells the backend how to route get/content/delete.
/// Carries only what routing consumes today; the id string itself remains the
/// authoritative key (content-addressed for lines, path-encoded for dumps).
pub(super) enum ParsedLogId {
    /// A standard journal/text line — re-found by re-listing sources and
    /// matching the full id (stable while the line exists), so no payload needed.
    Line,
    /// A host dump file: `file` is the decoded bare filename (no dir component;
    /// the dir comes from the component's `HostDumps` config).
    HostDump { file: String },
    /// A guest dump served by the guest log-agent. The routing target (vm +
    /// agent id) is re-parsed when the guest `/dumps` proxy is wired; today this
    /// only selects the "not yet supported" branch.
    GuestDump,
}

pub(super) fn parse_log_id(id: &str) -> Option<ParsedLogId> {
    let (kind, rest) = id.split_once(':')?;
    match kind {
        "line" => {
            // Shape check only: `line:<source>:<hash>` must have both colons.
            rest.rsplit_once(':')?;
            Some(ParsedLogId::Line)
        }
        "dump" => {
            let (src, key) = rest.split_once(':')?;
            if src == "host" {
                let file = String::from_utf8(b64url_decode(key)?).ok()?;
                // Reject any decoded name that isn't a bare filename — no path
                // separators, no `..` — so the id can never escape the dump dir.
                if file.contains('/') || file.contains("..") || file.is_empty() {
                    return None;
                }
                Some(ParsedLogId::HostDump { file })
            } else {
                Some(ParsedLogId::GuestDump)
            }
        }
        _ => None,
    }
}

/// Optional sidecar next to a dump file: `<name>.meta.json` → { type, status }.
#[derive(Debug, serde::Deserialize)]
pub(super) struct DumpMeta {
    #[serde(default, rename = "type")]
    pub(super) log_type: Option<String>,
    #[serde(default)]
    pub(super) status: Option<String>,
}

/// Host dump DIRECTORY as a §7.21 CUSTOM-log catalog: each regular file in
/// `dir` (excluding `*.meta.json` sidecars) is one retrievable dump entry with
/// a stable id, `size`, and `log_type`/`status` from an optional sidecar. This
/// is the discovery surface for custom logs — content/delete address the file
/// by the id's encoded filename.
pub(super) fn host_dump_logs(dir: &str, filter: &LogFilter) -> Vec<LogEntry> {
    const MAX_ENTRIES: usize = 2000;
    let mut entries: Vec<LogEntry> = Vec::new();
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return entries, // absent/unreadable dir → no dumps (not an error)
    };
    for e in rd.flatten() {
        let path = e.path();
        if !path.is_file() {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        if name.ends_with(".meta.json") {
            continue; // sidecars aren't entries
        }
        let meta = std::fs::metadata(&path).ok();
        let size = meta.as_ref().map(|m| m.len());
        let mtime = meta
            .and_then(|m| m.modified().ok())
            .map(chrono::DateTime::<Utc>::from)
            .unwrap_or(chrono::DateTime::<Utc>::UNIX_EPOCH);

        // Optional sidecar for type/status.
        let sidecar = path.with_file_name(format!("{name}.meta.json"));
        let dm: Option<DumpMeta> = std::fs::read(&sidecar)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok());
        let log_type = dm.as_ref().and_then(|m| m.log_type.clone());
        let status = match dm.as_ref().and_then(|m| m.status.as_deref()) {
            Some("retrieved") => Some(LogStatus::Retrieved),
            Some("processed") => Some(LogStatus::Processed),
            _ => Some(LogStatus::Pending),
        };

        // Filters: source (vs filename), type, status, since/until (mtime).
        if let Some(want) = &filter.source {
            if want != &name {
                continue;
            }
        }
        if let Some(t) = &filter.log_type {
            if log_type.as_deref() != Some(t.as_str()) {
                continue;
            }
        }
        if let Some(st) = filter.status {
            if status != Some(st) {
                continue;
            }
        }
        if let Some(since) = filter.since {
            if mtime < since {
                continue;
            }
        }
        if let Some(until) = filter.until {
            if mtime > until {
                continue;
            }
        }

        entries.push(LogEntry {
            id: dump_log_id(&name),
            timestamp: mtime,
            priority: LogPriority::Notice, // a dump is a notable artifact, not a line
            message: name.clone(),
            source: Some(name),
            pid: None,
            fields: None,
            log_type,
            size,
            status,
            href: None, // sovd-api synthesizes the bulk-data href from the id
            metadata: None,
            uptime_secs: None, // dump artifact: no per-line monotonic clock
        });
        if entries.len() >= MAX_ENTRIES {
            break;
        }
    }
    entries
}

impl<D: BlockDevice + Send + 'static> ComponentBackend<D> {
    // --- §7.21 log-entry resolution (stateless, by the self-describing id) ---

    /// Re-derive a log entry from its id by re-listing the relevant source and
    /// matching. Stateless: the id says which source + how to match, so a
    /// restart (or a fresh process) resolves the same id identically while the
    /// underlying line/dump still exists.
    pub(super) async fn find_log_entry(&self, log_id: &str) -> Option<LogEntry> {
        // Reject a malformed id up front (no source query for garbage). The
        // parse result isn't otherwise needed — matching is by the full id
        // string, which is content-addressed / path-encoded per kind.
        parse_log_id(log_id)?;
        // Broad re-list (no filter) of the sources, then match by id. Cheap
        // relative to the network/file cost already paid, and avoids a cache.
        let filter = LogFilter::default();
        let mut all: Vec<LogEntry> = Vec::new();
        for source in &self.config.log_sources {
            match source {
                LogSource::GuestAgent { url } => {
                    if let Some(e) = query_log_agent(url, &filter).await {
                        all.extend(e);
                    }
                }
                LogSource::HostFiles { globs } => all.extend(host_file_logs(globs, &filter)),
                LogSource::HostDumps { dir } => all.extend(host_dump_logs(dir, &filter)),
                LogSource::Slog2 => all.extend(slog2_logs(&filter)),
                LogSource::Slog2Segments {
                    dir,
                    stem,
                    live_dir,
                } => all.extend(slog2_segments_logs(dir, stem, live_dir.as_deref(), &filter)),
            }
        }
        all.into_iter().find(|e| e.id == log_id)
    }

    /// Resolve a `dump:host:<file>` id to an on-disk path under this component's
    /// configured `HostDumps` dir. Returns `EntityNotFound` if the component has
    /// no dump dir or the file isn't in it. The id carries only a bare filename
    /// (parse_log_id rejects separators/`..`), so this cannot escape the dir.
    pub(super) fn resolve_dump_path(
        &self,
        log_id: &str,
        file: &str,
    ) -> BackendResult<std::path::PathBuf> {
        for source in &self.config.log_sources {
            if let LogSource::HostDumps { dir } = source {
                let path = std::path::Path::new(dir).join(file);
                if path.is_file() {
                    return Ok(path);
                }
            }
        }
        Err(BackendError::EntityNotFound(log_id.to_string()))
    }

    /// Current log tip cursor ("now") for the §7.15 execution log-cursor bracket.
    /// Reuses the SAME logs path the component already exposes — one
    /// `get_logs_paged(&LogFilter::default())` read, returning its
    /// `tip_cursor`. `None` when the source can't name its tip (a GuestAgent
    /// journald cursor the agent didn't report, a mixed/dump source, or no log
    /// source at all) — the bracket is best-effort and stays `None` then.
    pub(super) async fn current_log_tip(&self) -> Option<String> {
        self.get_logs_paged(&LogFilter::default())
            .await
            .ok()
            .and_then(|page| page.tip_cursor)
    }
}
