use super::*;

// ---------------------------------------------------------------------------
// §7.21 log sources (see ComponentConfig::log_sources)
// ---------------------------------------------------------------------------

/// One record from the guest log-agent's `GET /logs`. Field names are the
/// wire contract, mirrored by convention with `guest-vm-sdk`'s
/// `log-agent` crate (different repo — never a git dep).
#[derive(serde::Deserialize)]
pub(super) struct AgentLogRecord {
    pub(super) timestamp: String,
    pub(super) priority: String,
    pub(super) message: String,
    pub(super) source: String,
    /// Monotonic runtime, seconds since the guest's boot (journald
    /// `__MONOTONIC_TIMESTAMP`). The `x-log-runtime` window axis. Absent on a
    /// guest agent that doesn't emit it yet → `None`.
    #[serde(default, rename = "x-log-uptime-secs")]
    pub(super) uptime_secs: Option<u64>,
}

pub(super) fn priority_name(p: LogPriority) -> &'static str {
    match p {
        LogPriority::Emergency => "emergency",
        LogPriority::Alert => "alert",
        LogPriority::Critical => "critical",
        LogPriority::Error => "error",
        LogPriority::Warning => "warning",
        LogPriority::Notice => "notice",
        LogPriority::Info => "info",
        LogPriority::Debug => "debug",
    }
}

pub(super) fn priority_from_name(s: &str) -> LogPriority {
    match s {
        "emergency" => LogPriority::Emergency,
        "alert" => LogPriority::Alert,
        "critical" => LogPriority::Critical,
        "error" => LogPriority::Error,
        "warning" => LogPriority::Warning,
        "notice" => LogPriority::Notice,
        "debug" => LogPriority::Debug,
        _ => LogPriority::Info,
    }
}

/// Percent-encode one query value (RFC 3986 unreserved pass-through).
pub(super) fn qenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `GET {url}/logs?...` against the in-guest log-agent — hand-rolled
/// HTTP/1.1 over tokio (same shape as [`query_vm_health`]; no HTTP-client
/// crate in this tree). `None` = unreachable/bad response (the caller
/// logs and serves empty). Body capped at 4 MiB.
pub(super) async fn query_log_agent(url: &str, filter: &LogFilter) -> Option<Vec<LogEntry>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let deadline = std::time::Duration::from_secs(5);
    let hostport = url.strip_prefix("http://").unwrap_or(url);
    let (hostport, base_path) = match hostport.split_once('/') {
        Some((hp, rest)) => (hp, format!("/{rest}")),
        None => (hostport, String::new()),
    };

    let mut qs: Vec<String> = Vec::new();
    if let Some(n) = filter.tail.or(filter.limit) {
        qs.push(format!("tail={n}"));
    }
    if let Some(s) = &filter.source {
        qs.push(format!("source={}", qenc(s)));
    }
    if let Some(e) = &filter.emitter {
        qs.push(format!("x-log-emitter={}", qenc(e)));
    }
    if let Some(e) = &filter.emitter_exclude {
        qs.push(format!("x-log-emitter-exclude={}", qenc(e)));
    }
    if let Some(p) = &filter.pattern {
        qs.push(format!("pattern={}", qenc(p)));
    }
    if let Some(p) = filter.priority {
        qs.push(format!("priority={}", priority_name(p)));
    }
    if let Some(t) = filter.since {
        qs.push(format!("since={}", qenc(&t.to_rfc3339())));
    }
    if let Some(t) = filter.until {
        qs.push(format!("until={}", qenc(&t.to_rfc3339())));
    }
    // Runtime window (jump-proof): forward as seconds; the guest agent parses
    // x-log-runtime and applies the boot-scoped monotonic window.
    if let Some(secs) = filter.runtime_secs {
        qs.push(format!("x-log-runtime={secs}"));
    }
    let target = if qs.is_empty() {
        format!("{base_path}/logs")
    } else {
        format!("{base_path}/logs?{}", qs.join("&"))
    };

    let mut stream = tokio::time::timeout(deadline, TcpStream::connect(hostport))
        .await
        .ok()?
        .ok()?;
    let request = format!("GET {target} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n\r\n");
    tokio::time::timeout(deadline, stream.write_all(request.as_bytes()))
        .await
        .ok()?
        .ok()?;
    let mut buf = Vec::with_capacity(64 * 1024);
    tokio::time::timeout(
        deadline,
        (&mut stream).take(4 * 1024 * 1024).read_to_end(&mut buf),
    )
    .await
    .ok()?
    .ok()?;
    let response = std::str::from_utf8(&buf).ok()?;
    let (head, body) = response.split_once("\r\n\r\n")?;
    if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
        return None;
    }
    let records: Vec<AgentLogRecord> = serde_json::from_str(body).ok()?;

    let entries = records
        .into_iter()
        .map(|r| {
            let timestamp = chrono::DateTime::parse_from_rfc3339(&r.timestamp)
                .map(|t| t.with_timezone(&Utc))
                .unwrap_or(chrono::DateTime::<Utc>::UNIX_EPOCH);
            LogEntry {
                // Content-addressed stable id (same scheme as host lines) so a
                // guest line re-resolves on get_log without server state.
                id: line_log_id(&r.source, timestamp, &r.message),
                timestamp,
                priority: priority_from_name(&r.priority),
                message: r.message,
                source: Some(r.source),
                pid: None,
                fields: None,
                log_type: None,
                size: None,
                status: None,
                href: None,
                metadata: None,
                uptime_secs: r.uptime_secs,
            }
        })
        .collect();
    Some(entries)
}

/// The guest log-agent's `GET /logs/sources` entry — one log STREAM the guest
/// serves. Mirrors `log-agent::SourceInfo` by convention (different repo):
/// `{name, kind, cursor}`. Each becomes a `LogSourceInfo` the host advertises.
#[derive(serde::Deserialize)]
pub(super) struct AgentSourceInfo {
    pub(super) name: String,
    #[serde(default)]
    pub(super) kind: String,
    #[serde(default)]
    pub(super) cursor: bool,
}

/// Ask the guest agent for its source catalog (`GET /logs/sources`) — the real
/// per-stream sources (doip-edge, doip-gateway, slog2, …), each with its own
/// cursor. Replaces the synthetic single `"guest"` source: forwarding that name
/// as a `source=` filter matched no guest record, so per-source reads were always
/// empty. `None` = agent unreachable / non-200 / unparseable (e.g. an OLDER agent
/// without the route) → the caller falls back to the single synthetic source.
pub(super) async fn query_log_agent_sources(url: &str) -> Option<Vec<AgentSourceInfo>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let deadline = std::time::Duration::from_secs(5);
    let hostport = url.strip_prefix("http://").unwrap_or(url);
    let (hostport, base_path) = match hostport.split_once('/') {
        Some((hp, rest)) => (hp, format!("/{rest}")),
        None => (hostport, String::new()),
    };
    let target = format!("{base_path}/logs/sources");

    let mut stream = tokio::time::timeout(deadline, TcpStream::connect(hostport))
        .await
        .ok()?
        .ok()?;
    let request = format!("GET {target} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n\r\n");
    tokio::time::timeout(deadline, stream.write_all(request.as_bytes()))
        .await
        .ok()?
        .ok()?;
    let mut buf = Vec::with_capacity(8 * 1024);
    tokio::time::timeout(
        deadline,
        (&mut stream).take(1024 * 1024).read_to_end(&mut buf),
    )
    .await
    .ok()?
    .ok()?;
    let response = std::str::from_utf8(&buf).ok()?;
    let (head, body) = response.split_once("\r\n\r\n")?;
    if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
        return None;
    }
    serde_json::from_str(body).ok()
}

/// The guest log-agent's `GET /logs/page` envelope — the cursor forward-paging
/// view. Mirrors `log-agent::PagedLogs` by convention (different repo).
#[derive(serde::Deserialize)]
pub(super) struct AgentPagedLogs {
    pub(super) items: Vec<AgentLogRecord>,
    #[serde(default)]
    pub(super) next_cursor: Option<String>,
    /// QNX svclog segment cursors (see the guest log-agent PagedLogs). Absent on
    /// the journald path / older agents → None (serde default).
    #[serde(default)]
    pub(super) oldest_cursor: Option<String>,
    #[serde(default)]
    pub(super) tip_cursor: Option<String>,
}

/// Page the guest's logs via its `/logs/page` (journald `__CURSOR` forward-
/// paging). `filter.after` is the opaque guest cursor, passed straight through
/// (journald's cursor is reboot-safe on its own — no host boot_epoch wrapping).
/// Returns a [`LogPage`] whose `next_cursor` is the guest's, so the host loop
/// terminates exactly when the guest reports the head. `None` = agent
/// unreachable / non-200 / unparseable → the caller degrades to an empty page.
pub(super) async fn query_log_agent_paged(url: &str, filter: &LogFilter) -> Option<LogPage> {
    let base_path = match url.strip_prefix("http://").unwrap_or(url).split_once('/') {
        Some((_, rest)) => format!("/{rest}"),
        None => String::new(),
    };
    let mut qs: Vec<String> = Vec::new();
    if let Some(n) = filter.tail.or(filter.limit) {
        qs.push(format!("tail={n}"));
    }
    if let Some(s) = &filter.source {
        qs.push(format!("source={}", qenc(s)));
    }
    if let Some(e) = &filter.emitter {
        qs.push(format!("x-log-emitter={}", qenc(e)));
    }
    if let Some(e) = &filter.emitter_exclude {
        qs.push(format!("x-log-emitter-exclude={}", qenc(e)));
    }
    if let Some(p) = &filter.pattern {
        qs.push(format!("pattern={}", qenc(p)));
    }
    if let Some(p) = filter.priority {
        qs.push(format!("priority={}", priority_name(p)));
    }
    if let Some(c) = &filter.after {
        qs.push(format!("after={}", qenc(c)));
    }
    // Runtime window (jump-proof): forward as seconds so the guest agent applies
    // the boot-scoped monotonic window on its /logs/page too. (The paged proxy
    // historically forwarded NO time window — this closes that gap for runtime.)
    if let Some(secs) = filter.runtime_secs {
        qs.push(format!("x-log-runtime={secs}"));
    }
    let target = if qs.is_empty() {
        format!("{base_path}/logs/page")
    } else {
        format!("{base_path}/logs/page?{}", qs.join("&"))
    };

    // 4 MiB cap matches query_log_agent's read bound — a single page is small.
    let body = guest_http_get(url, &target, 4 * 1024 * 1024).await?;
    let paged: AgentPagedLogs = serde_json::from_slice(&body).ok()?;

    let items = paged
        .items
        .into_iter()
        .map(|r| {
            let timestamp = chrono::DateTime::parse_from_rfc3339(&r.timestamp)
                .map(|t| t.with_timezone(&Utc))
                .unwrap_or(chrono::DateTime::<Utc>::UNIX_EPOCH);
            LogEntry {
                id: line_log_id(&r.source, timestamp, &r.message),
                timestamp,
                priority: priority_from_name(&r.priority),
                message: r.message,
                source: Some(r.source),
                pid: None,
                fields: None,
                log_type: None,
                size: None,
                status: None,
                href: None,
                metadata: None,
                uptime_secs: r.uptime_secs,
            }
        })
        .collect();
    Some(LogPage {
        items,
        // All three cursors pass straight through from the guest — the host is
        // scheme-agnostic (the guest owns the string: journald `__CURSOR`, or
        // QNX svclog `<seq>:<offset>`). tip_cursor is what feeds the §7.15
        // tester log bracket + `sovd-cli logs --follow`; oldest_cursor is gap
        // detection. All None on an older agent (serde default) → best-effort.
        next_cursor: paged.next_cursor,
        oldest_cursor: paged.oldest_cursor,
        tip_cursor: paged.tip_cursor,
    })
}

/// One entry from the guest log-agent's `GET /files` bulk-data catalog. Field
/// names are the wire contract, mirrored by convention with `guest-vm-sdk`'s
/// `log-agent::FileEntry` (different repo — never a git dep), exactly like
/// [`AgentLogRecord`] mirrors its `LogRecord`.
#[derive(serde::Deserialize)]
pub(super) struct GuestFileRecord {
    /// Opaque guest-side id: the agent's base64url of the file's absolute path.
    /// We treat it as opaque and hand it straight back on download.
    pub(super) id: String,
    /// Basename (human label). Part of the wire mirror; the host derives its
    /// item `source` from `source` (the stem), not this, so it's carried for
    /// contract fidelity but not otherwise consumed.
    #[allow(dead_code)]
    pub(super) name: String,
    /// File size in bytes.
    pub(super) size: u64,
    /// Source label (file stem).
    pub(super) source: String,
    /// Last-modified time, epoch seconds — the key we apply the bulk-data
    /// `created-before`/`created-after` filter against.
    pub(super) modified: u64,
}

/// Hand-rolled HTTP/1.1 `GET {url}{target}` over tokio, returning the raw
/// response body bytes iff the status is 200 (same transport shape as
/// [`query_log_agent`]; no HTTP-client crate in this tree). `None` =
/// unreachable / non-200 / oversized — the caller logs and degrades. Body is
/// capped at `cap` bytes via `take()`. Byte-oriented (not UTF-8) so it works
/// for both the JSON catalog and octet-stream file downloads.
pub(super) async fn guest_http_get(url: &str, target: &str, cap: u64) -> Option<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let deadline = std::time::Duration::from_secs(5);
    let hostport = url.strip_prefix("http://").unwrap_or(url);
    // A base path in the url (e.g. http://host:9300/base) prefixes the target.
    let (hostport, base_path) = match hostport.split_once('/') {
        Some((hp, rest)) => (hp, format!("/{rest}")),
        None => (hostport, String::new()),
    };
    let full_target = format!("{base_path}{target}");

    let mut stream = tokio::time::timeout(deadline, TcpStream::connect(hostport))
        .await
        .ok()?
        .ok()?;
    let request =
        format!("GET {full_target} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n\r\n");
    tokio::time::timeout(deadline, stream.write_all(request.as_bytes()))
        .await
        .ok()?
        .ok()?;
    let mut buf = Vec::with_capacity(64 * 1024);
    tokio::time::timeout(
        deadline,
        // +1 KiB headroom for the status line + headers before the body.
        (&mut stream).take(cap + 1024).read_to_end(&mut buf),
    )
    .await
    .ok()?
    .ok()?;
    // Split head/body on the raw CRLFCRLF (body may be non-UTF-8 octets).
    let sep = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = &buf[..sep];
    let body = buf[sep + 4..].to_vec();
    if !head.starts_with(b"HTTP/1.1 200") && !head.starts_with(b"HTTP/1.0 200") {
        return None;
    }
    Some(body)
}

/// `GET {url}/files` — the guest log-agent's bulk-data catalog. `None` =
/// unreachable/bad response (caller logs + contributes zero items). JSON body
/// capped at 4 MiB (a catalog is small).
pub(super) async fn fetch_guest_files(url: &str) -> Option<Vec<GuestFileRecord>> {
    let body = guest_http_get(url, "/files", 4 * 1024 * 1024).await?;
    serde_json::from_slice(&body).ok()
}

/// `GET {url}/files/{id}` — download one guest log file whole. `None` =
/// unreachable/bad response. Bytes capped at [`MAX_BULK_BYTES`] (the guest ALSO
/// caps its read); a larger file arrives truncated, matching the host-file path.
pub(super) async fn fetch_guest_file(url: &str, guest_id: &str) -> Option<Vec<u8>> {
    guest_http_get(url, &format!("/files/{guest_id}"), MAX_BULK_BYTES).await
}

/// One registered test from the guest test-agent's `GET /tests` discovery. Wire
/// shape mirrored by hand from `test-agent::TestSummary` (guest-vm-sdk, different
/// repo — never a git dep), like [`GuestFileRecord`] / [`AgentLogRecord`].
#[derive(serde::Deserialize)]
pub(super) struct AgentTestRecord {
    pub(super) id: String,
    #[serde(default)]
    pub(super) title: Option<String>,
    #[serde(default)]
    pub(super) tags: Vec<String>,
}

/// `GET {url}/tests` — the guest's registered tests (SOVD §7.15 scripts source).
/// `None` = test-agent unreachable / bad response → the caller degrades to an
/// empty scripts list. Small JSON; 256 KiB cap is ample.
pub(super) async fn query_test_agent(url: &str) -> Option<Vec<ScriptInfo>> {
    let body = guest_http_get(url, "/tests", 256 * 1024).await?;
    let recs: Vec<AgentTestRecord> = serde_json::from_slice(&body).ok()?;
    Some(
        recs.into_iter()
            .map(|r| ScriptInfo {
                id: r.id,
                title: r.title,
                tags: r.tags,
            })
            .collect(),
    )
}

/// One registered probe from the guest diag-agent's `GET /probes` discovery.
/// Wire shape mirrored BY HAND from `diag_agent::ProbeSummary` (guest-vm-sdk,
/// different repo — never a git dep), like [`AgentTestRecord`].
#[derive(serde::Deserialize)]
pub(super) struct AgentProbeRecord {
    pub(super) id: String,
    #[serde(default)]
    pub(super) title: Option<String>,
    #[serde(default)]
    pub(super) tags: Vec<String>,
}

/// `GET {url}/probes` — the guest's registered diagnostic probes (SOVD §7.9
/// source). `None` = diag-agent unreachable / bad response → the caller degrades
/// to an empty list. Small JSON; 256 KiB cap is ample.
pub(super) async fn query_diag_agent(url: &str) -> Option<Vec<DiagnosticInfo>> {
    let body = guest_http_get(url, "/probes", 256 * 1024).await?;
    let recs: Vec<AgentProbeRecord> = serde_json::from_slice(&body).ok()?;
    Some(
        recs.into_iter()
            .map(|r| DiagnosticInfo {
                id: r.id,
                title: r.title,
                tags: r.tags,
            })
            .collect(),
    )
}

/// One gathered probe from the guest diag-agent's `GET /probes/{id}`. Wire shape
/// mirrored BY HAND from `diag_agent::ProbeResult` — `{ id, ok, output?,
/// message? }` (the agent omits empty output / absent message via serde
/// skip_serializing_if, so default them here).
#[derive(serde::Deserialize)]
pub(super) struct AgentProbeResult {
    pub(super) id: String,
    pub(super) ok: bool,
    #[serde(default)]
    pub(super) output: String,
    #[serde(default)]
    pub(super) message: Option<String>,
}

/// `GET {url}/probes/{id}` — gather one probe. `None` = diag-agent unreachable /
/// bad response → the caller maps it to a `Transport` error (couldn't dispatch
/// the read). A probe that RAN and failed comes back as a valid result with
/// `ok=false` (passed through, not an error). Probe output is bounded by the
/// agent; a 1 MiB cap here is a generous backstop.
pub(super) async fn read_diag_probe(url: &str, probe_id: &str) -> Option<DiagnosticResult> {
    // Probe ids are `<layer>.<id>` (alphanumerics, dots, dashes) — URL-safe, so
    // no percent-encoding, matching the scripts proxy's raw `/tests/{id}/run`.
    let target = format!("/probes/{probe_id}");
    let body = guest_http_get(url, &target, 1024 * 1024).await?;
    let r: AgentProbeResult = serde_json::from_slice(&body).ok()?;
    Some(DiagnosticResult {
        id: r.id,
        ok: r.ok,
        output: r.output,
        message: r.message,
    })
}

// ---------------------------------------------------------------------------
// Host in-process diagnostics (host_diagnostics=true — supernova / on-box).
// The host has no guest diag-agent to proxy, so it gathers READ-ONLY probes
// locally. Scoped to storage/memory triage — the class the flash
// `No space left on device` exposed. Mirrors the guest diag-agent's source
// keys, but the host repo can't git-dep that crate so it's a small local set.
// ---------------------------------------------------------------------------

/// The host's fixed probe catalog (`host_diagnostics`). ids namespaced `host.*`
/// (parallel to the guest `<layer>.<id>`). Static — the host isn't
/// layer-contributed like the guest.
pub(super) fn host_diag_probes() -> Vec<DiagnosticInfo> {
    fn p(id: &str, title: &str, tags: &[&str]) -> DiagnosticInfo {
        DiagnosticInfo {
            id: id.to_string(),
            title: Some(title.to_string()),
            tags: tags.iter().map(|s| s.to_string()).collect(),
        }
    }
    vec![
        p(
            "host.disk",
            "Filesystem usage (df)",
            &["health", "smoke", "storage"],
        ),
        p(
            "host.mem",
            "Memory (/proc/meminfo)",
            &["health", "smoke", "resource"],
        ),
        // The flash target — where `No space left on device` bit. du, largest
        // files first, so a full /mnt/common-rw names the culprit in one call.
        p(
            "host.common-rw-usage",
            "Flash/state partition usage — /mnt/common-rw, largest first",
            &["health", "smoke", "storage"],
        ),
        p(
            "host.log-usage",
            "Host log usage — /mnt/common-rw/log, largest first",
            &["storage", "logs"],
        ),
    ]
}

/// Gather one host probe in-process. Read-only; never panics; a bad id or a
/// failed read is `ok=false` with a message (a real signal, like the guest).
pub(super) fn host_gather(probe_id: &str) -> DiagnosticResult {
    let result = match probe_id {
        "host.disk" => host_capture(&["df", "-k"]),
        "host.mem" => {
            std::fs::read_to_string("/proc/meminfo").map_err(|e| format!("/proc/meminfo: {e}"))
        }
        "host.common-rw-usage" => host_du("/mnt/common-rw", 40),
        "host.log-usage" => host_du("/mnt/common-rw/log", 40),
        other => {
            return DiagnosticResult {
                id: probe_id.to_string(),
                ok: false,
                output: String::new(),
                message: Some(format!("unknown host probe `{other}`")),
            }
        }
    };
    match result {
        Ok(out) => DiagnosticResult {
            id: probe_id.to_string(),
            ok: true,
            output: host_head(&out, 64 * 1024),
            message: None,
        },
        Err(e) => DiagnosticResult {
            id: probe_id.to_string(),
            ok: false,
            output: String::new(),
            message: Some(e),
        },
    }
}

/// Run a read-only host command, capturing stdout+stderr. Err on spawn/exit
/// failure. Bounded by the caller's head-cap.
pub(super) fn host_capture(argv: &[&str]) -> Result<String, String> {
    use std::process::Command;
    let (prog, args) = argv.split_first().ok_or("empty cmd")?;
    let out = Command::new(prog)
        .args(args)
        .output()
        .map_err(|e| format!("spawn {prog}: {e}"))?;
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.stderr.is_empty() {
        s.push_str(&String::from_utf8_lossy(&out.stderr));
    }
    Ok(s)
}

/// In-process `du`-equivalent: recursively sum file sizes under `dir`, largest
/// `n` first, KiB. No external `du` (QNX host toybox may lack it — the same
/// lesson as the guest diag-agent). Best-effort; unreadable entries skipped.
/// In-process `du`-equivalent: walk EVERY file under `dir` (no accounting cap —
/// the whole point is that "many small files" and the true total show up), then
/// report three views so it can answer "what fills this partition":
///   TOTAL   — grand total of the tree (reconciles with df's `used`)
///   FILES   — <total>, <count>
///   by dir  — cumulative KiB per immediate subdir (depth-1), largest first
///   top     — the `n` largest individual files (the specific culprits)
/// Best-effort; unreadable entries skipped; symlinks not followed.
pub(super) fn host_du(dir: &str, n: usize) -> Result<String, String> {
    fn walk(dir: &std::path::Path, out: &mut Vec<(u64, String)>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let meta = match path.symlink_metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_dir() {
                walk(&path, out);
            } else if meta.is_file() {
                out.push((meta.len(), path.to_string_lossy().into_owned()));
            }
        }
    }
    let root = std::path::Path::new(dir);
    if !root.exists() {
        return Err(format!("{dir}: not present"));
    }
    let mut files: Vec<(u64, String)> = Vec::new();
    walk(root, &mut files);

    // Grand total + count over ALL files (uncapped — the reconciling number).
    let total: u64 = files.iter().map(|(b, _)| *b).sum();
    let count = files.len();

    // Per-immediate-subdir rollup (depth-1 under `dir`): the prefix after
    // `<dir>/` up to the next `/`. A file directly in `dir` rolls up under `.`.
    let prefix = format!("{}/", dir.trim_end_matches('/'));
    let mut by_dir: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for (bytes, path) in &files {
        let seg = path.strip_prefix(&prefix).unwrap_or(path);
        let top = seg.split('/').next().filter(|s| !s.is_empty());
        let key = match top {
            Some(t) if seg.contains('/') => t.to_string(), // it's a subdir
            _ => ".".to_string(),                          // file directly in dir
        };
        *by_dir.entry(key).or_insert(0) += *bytes;
    }
    let mut dirs: Vec<(String, u64)> = by_dir.into_iter().collect();
    dirs.sort_by_key(|(_, b)| std::cmp::Reverse(*b));

    // Top-n largest individual files.
    let mut top_files = files;
    top_files.sort_by_key(|f| std::cmp::Reverse(f.0));
    top_files.truncate(n);

    let mut out = String::new();
    out.push_str(&format!(
        "TOTAL\t{} KiB\t({} files under {dir})\n\n",
        total.div_ceil(1024),
        count
    ));
    out.push_str("KiB\tsubdir (cumulative)\n");
    for (name, bytes) in &dirs {
        out.push_str(&format!("{}\t{name}\n", bytes.div_ceil(1024)));
    }
    out.push_str(&format!("\nKiB\ttop {n} files\n"));
    for (bytes, path) in &top_files {
        out.push_str(&format!("{}\t{path}\n", bytes.div_ceil(1024)));
    }
    Ok(out)
}

/// Keep the head `cap` bytes of a probe's output (a report's useful part is the
/// top), with a truncation marker.
pub(super) fn host_head(s: &str, cap: usize) -> String {
    if s.len() <= cap {
        return s.to_string();
    }
    format!("{}\n…[{} more bytes truncated]", &s[..cap], s.len() - cap)
}

/// One finished test run from the guest test-agent's `POST /tests/{id}/run`.
/// Wire shape mirrored BY HAND from `test-agent::RunResult` (guest-vm-sdk,
/// different repo — the host must NOT git-dep the guest tree), like
/// [`AgentTestRecord`] / [`GuestFileRecord`]. Keep in lockstep with the agent's
/// `RunResult`: `{ id, verdict, exit_code?, duration_ms, stdout_tail?,
/// stderr_tail?, message? }`. The agent omits empty tails (serde
/// `skip_serializing_if`), so default them here.
#[derive(serde::Deserialize)]
pub(super) struct AgentRunResult {
    /// Test id the run was for (unused here — we key by our own exec_id — but
    /// carried for contract fidelity, like `GuestFileRecord::name`).
    #[allow(dead_code)]
    pub(super) id: String,
    /// `"pass" | "fail" | "error"` — lowercase, matching the agent's `Verdict`.
    pub(super) verdict: String,
    #[serde(default)]
    pub(super) exit_code: Option<i32>,
    #[serde(default)]
    pub(super) duration_ms: u64,
    #[serde(default)]
    pub(super) stdout_tail: String,
    #[serde(default)]
    pub(super) stderr_tail: String,
    #[serde(default)]
    pub(super) message: Option<String>,
}

/// Map the guest agent's lowercase verdict string to the SOVD core enum. An
/// unrecognised value is treated as `Error` (loud, not silently "pass") — same
/// discipline as the agent's own `verdict_from_exit`.
pub(super) fn agent_verdict_to_core(verdict: &str) -> ScriptVerdict {
    match verdict {
        "pass" => ScriptVerdict::Pass,
        "fail" => ScriptVerdict::Fail,
        _ => ScriptVerdict::Error,
    }
}

/// `POST {url}/tests/{script_id}/run` — run one registered test to completion
/// (SYNCHRONOUS; the agent blocks until the test exits, bounded by the entry's
/// `timeout_ms`). `None` = agent unreachable / non-200 / unparseable → the
/// caller surfaces a `Transport` error (the run couldn't be dispatched). A test
/// run needs a longer budget than a log read, hence the dedicated timeout.
pub(super) async fn run_test_agent(url: &str, script_id: &str) -> Option<AgentRunResult> {
    let target = format!("/tests/{script_id}/run");
    // A test may run for a while — give it a generous budget (the agent itself
    // bounds the run via the entry's timeout_ms; this is the transport ceiling).
    let body = guest_http_post(
        url,
        &target,
        &[],
        256 * 1024,
        std::time::Duration::from_secs(300),
    )
    .await?;
    serde_json::from_slice(&body).ok()
}

/// Hand-rolled HTTP/1.1 `POST {url}{target}` over tokio (no HTTP-client crate in
/// this tree — same transport shape as [`guest_http_get`], but with a method +
/// body + a caller-set timeout for slow runs). Returns the raw response body
/// bytes iff the status is 200; `None` on unreachable / non-200 / oversized. The
/// body is sent as `application/json` (empty `body` → an empty JSON-less POST,
/// which the test-agent's `/run` accepts — the test id is in the path).
pub(super) async fn guest_http_post(
    url: &str,
    target: &str,
    body: &[u8],
    cap: u64,
    deadline: std::time::Duration,
) -> Option<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let hostport = url.strip_prefix("http://").unwrap_or(url);
    let (hostport, base_path) = match hostport.split_once('/') {
        Some((hp, rest)) => (hp, format!("/{rest}")),
        None => (hostport, String::new()),
    };
    let full_target = format!("{base_path}{target}");

    let mut stream = tokio::time::timeout(deadline, TcpStream::connect(hostport))
        .await
        .ok()?
        .ok()?;
    let request = format!(
        "POST {full_target} HTTP/1.1\r\nHost: {hostport}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    tokio::time::timeout(deadline, stream.write_all(request.as_bytes()))
        .await
        .ok()?
        .ok()?;
    if !body.is_empty() {
        tokio::time::timeout(deadline, stream.write_all(body))
            .await
            .ok()?
            .ok()?;
    }
    let mut buf = Vec::with_capacity(64 * 1024);
    tokio::time::timeout(
        deadline,
        (&mut stream).take(cap + 1024).read_to_end(&mut buf),
    )
    .await
    .ok()?
    .ok()?;
    let sep = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = &buf[..sep];
    let body = buf[sep + 4..].to_vec();
    if !head.starts_with(b"HTTP/1.1 200") && !head.starts_with(b"HTTP/1.0 200") {
        return None;
    }
    Some(body)
}
