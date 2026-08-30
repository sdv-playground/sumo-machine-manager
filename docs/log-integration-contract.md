# Log integration contract

How to make a component's logs retrievable through the sumo diagnostics stack.
There are **two integration paths**, and you pick exactly one per component:

- **Path A — you run your own SOVD endpoint.** Your server IS the diagnostics
  surface for that component. To be *compatible* it MUST implement the sumo
  "SOVD (extended)" profile — not just base SOVD. This is the full contract in
  §A.
- **Path B — you plug a log aggregator into our server.** You expose a small
  HTTP log-agent (or implement the backend trait); our server owns the SOVD
  surface and adapts your logs to it. Much smaller contract (§B), because our
  server supplies the extended behaviour for you.

Decision in one line: **own the HTTP surface → Path A (heavy, but full control);
just have logs to surface → Path B (light, we do the SOVD work).**

Background: [sovd-vs-extensions.md](sovd-vs-extensions.md) (what "extended" means,
route by route) and [log-retrieval.md](log-retrieval.md) (how our server captures
+ serves logs internally). The reboot-safe cursor + non-monotonic-clock rationale
in those docs is load-bearing for both paths — read it before implementing paging.

---

## Path A — provide a compatible SOVD-extended endpoint

Your endpoint is reached directly by clients (or federated behind a gateway). It
must behave as a sumo-extended SOVD server, not merely base SOVD. **Everything
below is MANDATORY** — a base-SOVD-only endpoint is NOT compatible.

### A.1 Base SOVD (required)
Standard `/vehicle/v1/` surface for the entity, minimally:
- `GET /vehicle/v1/components` and `GET .../components/{id}` — advertise the
  component and its capabilities (`logs: true`, and `bulk_data: true` if you
  serve downloadable log files).
- `GET .../{id}/logs` — the log read (extended; see A.2).
- `GET .../{id}/status` — §7.19.2 status (extended; see A.4).
- `GET /health`, `GET /version-info` — liveness + version.
Bind refuses plain HTTP unless transport security is explicitly waived (dev only).

### A.2 `GET .../logs` — the extended log contract (required)

Request query params you MUST honour:
| Param | Meaning |
|---|---|
| `x-log-after=<cursor>` | opaque resume token — return entries strictly AFTER it, oldest→newest. Omit = start at oldest available. |
| `x-log-emitter` / `x-log-emitter-exclude` | include / exclude emitters (sub-sources) — comma-separated, prefix-matched; exclude applied after include. Only meaningful if one `source` multiplexes emitters; otherwise return everything. |
| `since` / `until` | RFC 3339 **or** a sentinel: `BEGIN`, `END`/`NOW`, `END-<N>{s,m,h,d}` / `NOW-<N>…`. Resolve server-side against YOUR clock. Malformed → **400**. |
| `priority` | one of the 8 lowercase syslog levels (below) — return that level and higher. |
| `source` | filter to one physical source string. |
| `pattern` | substring/glob match on the message (best-effort). |
| `limit` / `tail` | page size / tail count. |

Response body (`LogsResponse`):
```jsonc
{
  "items": [ /* LogEntry, oldest→newest */ ],
  "total_count": 123,
  "x-log-next-cursor":   "<opaque>",   // feed back as x-log-after; null/absent = head reached
  "x-log-oldest-cursor": "<opaque>",   // earliest still-available position (gap detection)
  "x-log-tip-cursor":    "<opaque>"    // "now" — poll x-log-after=<this> to follow the tail
}
```
Each `LogEntry`:
```jsonc
{
  "id":        "<stable, content-addressed>",  // re-resolvable via GET .../logs/{id}, no server state
  "timestamp": "2026-07-31T10:00:00Z",         // RFC 3339 UTC (may be coarse / 1970 — see A.3)
  "priority":  "info",                          // emergency|alert|critical|error|warning|notice|info|debug
  "message":   "…",
  "source":    "slog2",                         // ONE physical source; sub-source goes in fields
  "fields":    { "emitter": "mydaemon" }        // structured k/v — the sub-source / journald fields
}
```

**Cursor rules (the hard part):**
- The cursor is OPAQUE to the client — you define its bytes. It MUST be
  **reboot-safe**: encode a monotonic key (byte offset, generation, journald
  `__CURSOR`), NEVER a wall-clock timestamp (A.3).
- `x-log-next-cursor` advances; `null`/absent means "head reached" — a paging
  loop stops there. `x-log-tip-cursor` is present EVEN at head, so a follower
  has a resume point.
- If a caller's `x-log-after` predates `x-log-oldest-cursor`, history rotated
  away — surface the gap via `oldest-cursor` rather than silently skipping.

### A.3 Non-monotonic clock (required assumption)
Device wall-clock is NOT monotonic (it may start at 1970 each boot, ratchet to a
safe-time floor, then reset on the next boot). Therefore:
- Do NOT use timestamps as an ordering or resume key across boots — that's the
  cursor's job. Order within a page by your monotonic key.
- Timestamps are still returned (best available); a client treats them as
  advisory, not authoritative.

### A.4 Status extension (required)
`GET .../status` returns §7.19.2 status with a flattened `x-runtime` object:
```jsonc
{ "...standard status...": "…",
  "x-runtime": { "boot_count": 12, "uptime_s": 3400, "node_boot_id": "<uuid>", "admin_state": "enabled" } }
```
`node_boot_id` (the current boot nonce) is required — it's what freshness-bound
tokens (A.5) and cross-boot cursor logic key on.

### A.5 Auth (required unless transport-isolated)

| Requirement | Rule |
|---|---|
| Bearer | Accept a JWT bearer. Implement at least `workshop-ca`: validate an `x5c`-cert JWT against a pinned CA, with your device id (HSM/device thumbprint) as the `aud` claim. |
| Freshness | Reject a token whose `boot_id` claim ≠ your live `node_boot_id`; for vehicle-wide tokens, reject `epoch` claim < your device epoch floor. (Defeats replay across boots.) |
| No minting | You do NOT mint. Expose device id + boot nonce so a minter issues a correctly-bound token; the client presents it. |
| Transport | Refuse plain HTTP unless an explicit dev override is set. |

### A.6 Optional (advertise honestly via capabilities)
- **Bulk-data (§7.20):** if logs are also downloadable files, implement
  `GET .../bulk-data`, `.../bulk-data/{category}`, `.../bulk-data/{category}/{id}`
  (200 inline / 307 redirect / 202 async) and set `capabilities.bulk_data`.
  `logs` is the conventional first category.
- **`DELETE .../logs/{id}`** + `status` (`pending|retrieved|processed`): only if
  you model the acknowledge / message-passing pattern.
- The `x-ota-*` / `x-csr` OTA/HSM routes (commit/rollback/CSR/pull-update) are NOT needed
  for a log/diagnostics endpoint — omit them.

### A.7 Conformance checklist (Path A)
- [ ] `/logs` accepts `x-log-after` and returns the three `x-log-*` cursors.
- [ ] Cursor is opaque + reboot-safe (no timestamp inside).
- [ ] `since`/`until` accept `BEGIN`/`END`/`END-<N>{s,m,h,d}` + RFC 3339; bad → 400.
- [ ] Each entry has a stable content-addressed `id`, `priority` from the 8-level
      set, one physical `source`, sub-source in `fields.emitter`.
- [ ] `/status` carries `x-runtime` incl. `node_boot_id`.
- [ ] JWT bearer with `workshop-ca` + boot/epoch freshness binding; no plain HTTP.
- [ ] Capabilities advertise `logs` (and `bulk_data` iff files are downloadable).

---

## Path B — integrate a log aggregator behind our server

Our server owns the SOVD surface and does ALL the extended behaviour (cursors,
sentinels, freshness, wire shape). You only supply the raw logs. Two sub-options,
same wire shape:

- **B1 (recommended): an HTTP log-agent.** A tiny read-only HTTP server we poll
  over a private link. This is the standard guest/aggregator seam.
- **B2: implement the backend trait.** If you're inside our server process,
  implement the log methods of the `DiagnosticBackend` trait directly.

### B1 — the log-agent HTTP contract

A **GET-only** HTTP server (anything else → 405). We poll it and adapt each
response to SOVD. Default bind is a private port on your link; the host reaches it
over the per-component private /30 (never the public network). Endpoints:

| Endpoint | Returns |
|---|---|
| `GET /healthz` | `200 "ok"` (`text/plain`) |
| `GET /logs` | JSON array of `LogRecord` — newest-first tail view |
| `GET /logs/page` | `PagedLogs` `{items, next_cursor, oldest_cursor?, tip_cursor?}` — forward paging, oldest→newest |
| `GET /files` | JSON array of `FileEntry` — catalog of downloadable log files (bulk-data) |
| `GET /files/{id}` | raw bytes (`application/octet-stream`); `{id}` re-validated against the live `/files` catalog, else 404 |

Query params (percent-decoded; unknown keys ignored): `tail`|`limit`, `source`,
`x-log-emitter`, `x-log-emitter-exclude` (include/exclude emitters —
comma-separated, prefix-matched), `pattern`, `priority`, `since`, `until`,
`after` (cursor — only `/logs/page` reads it; `/logs` ignores it).

**`LogRecord` — the field names ARE the contract** (the host parses exactly
these):
```jsonc
{
  "timestamp": "2026-07-31T10:00:00Z",   // RFC 3339 UTC
  "priority":  "info",                    // emergency|alert|critical|error|warning|notice|info|debug
  "message":   "…",
  "source":    "mydaemon"                 // your source string
}
```
**`FileEntry`** (bulk-data catalog):
```jsonc
{ "id": "<base64url of abs path>", "name": "app.log", "size": 4096,
  "source": "app", "modified": 1753939200 }   // modified = epoch seconds
```
**`PagedLogs`**: `{ "items": [LogRecord,…], "next_cursor": "<opaque>",
"oldest_cursor": "<opaque>?", "tip_cursor": "<opaque>?" }`.

**Cursor:** `/logs/page` does forward paging keyed by `after=<cursor>`. Your
cursor must be reboot-safe (byte offset, journald `__CURSOR`, …) — NOT a
timestamp (same non-monotonic-clock reason as Path A). The host passes your
`next_cursor` straight through to the client and wraps volatile-source offsets
with its own boot tag; you just page forward correctly and return
`next_cursor`/`oldest_cursor`/`tip_cursor`.

**File download guard (required):** `GET /files/{id}` MUST re-validate the id
against the current `/files` catalog before serving bytes — a crafted id must be
indistinguishable from "no such file" (404). Never decode-and-open arbitrary
paths. Apply a read/size cap.

**What the host does for you:** maps `/logs/page` → the SOVD `/logs` paged read,
`/files`+`/files/{id}` → §7.20 bulk-data (namespacing your ids so they can't
collide with host-file ids), supplies the `x-log-*` cursors, the `END[-N]`
sentinels, `x-runtime`, and all auth/freshness. You implement none of that.

### B2 — implement the backend trait directly

If you live inside our server process, implement these `DiagnosticBackend`
methods (all default to `NotSupported`/empty, so implement only what you have):
```rust
// Logs — gate with capabilities().logs = true
async fn get_logs(&self, filter: &LogFilter) -> BackendResult<Vec<LogEntry>>;        // simple tail
async fn get_logs_paged(&self, filter: &LogFilter) -> BackendResult<LogPage>;         // cursor paging — implement THIS for /logs
async fn get_log(&self, log_id: &str) -> BackendResult<LogEntry>;                     // re-resolve one id
async fn get_log_content(&self, log_id: &str) -> BackendResult<Vec<u8>>;              // optional binary
async fn delete_log(&self, log_id: &str) -> BackendResult<()>;                        // optional ack
async fn stream_logs(&self, filter: &LogFilter)
        -> BackendResult<broadcast::Receiver<LogEntry>>;                               // optional SSE

// Bulk-data (§7.20) — gate with capabilities().bulk_data = true
async fn list_bulk_data_categories(&self) -> BackendResult<Vec<BulkCategory>>;
async fn list_bulk_data(&self, category: &str, filter: &BulkDataFilter)
        -> BackendResult<Vec<BulkDataItem>>;
async fn get_bulk_data(&self, category: &str, id: &str) -> BackendResult<BulkDataDownload>;
```
`get_logs_paged` is what the SOVD `/logs` route calls; the default wraps
`get_logs` in a single terminal page, so a non-paging backend still works but
gives no cursor. Wire types: `LogFilter`/`LogPage`/`LogEntry`/`LogPriority`/
`LogStatus` (log model) and `BulkCategory`/`BulkDataItem`/`BulkDataFilter`/
`BulkDataDownload` (bulk-data model). Same reboot-safe-cursor rule applies to
`LogPage.next_cursor`.

### B.3 Conformance checklist (Path B / log-agent)
- [ ] GET-only; non-GET → 405; `/healthz` → `200 "ok"`.
- [ ] `LogRecord` uses exactly `timestamp`/`priority`/`message`/`source`;
      `priority` from the 8-level set; timestamps RFC 3339 UTC.
- [ ] `/logs/page` pages forward on `after` and returns a reboot-safe
      `next_cursor` (+ `oldest_cursor`/`tip_cursor` when known).
- [ ] `/files` catalog + `/files/{id}` with a re-validation guard (404 on
      unknown/crafted id) and a read/size cap.

---

## Side-by-side

| | Path A (own SOVD server) | Path B (aggregator behind our server) |
|---|---|---|
| You expose | full SOVD-extended HTTP surface | a GET-only log-agent (or the backend trait) |
| Cursors / sentinels / `x-log-*` | **you implement** | we implement; you page forward only |
| Auth + freshness | **you implement** (JWT, boot/epoch binding) | we implement |
| Status `x-runtime` | **you implement** | we implement |
| Wire shape owner | you | us |
| Effort | high | low |
| Use when | you need to own the endpoint / federate a full server | you just have logs to surface |

Non-negotiable in BOTH paths: the **8-level priority set**, **RFC 3339 UTC
timestamps**, a **reboot-safe (non-timestamp) cursor**, and the **file-download
re-validation guard**. Everything else differs by path.
