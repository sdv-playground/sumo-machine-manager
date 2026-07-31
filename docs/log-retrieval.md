# Log retrieval + capture (SOVD §7.21 + §7.20) — device side

How the sumo host stack CAPTURES logs (the producer side — `tracing` →
`sumo_log` → a recorder) and how `component-mgr` SERVES them (the reader side —
sources, the reboot-safe cursor, §7.20 bulk-data). The SOVD wire contract + the
client-facing paths are in SOVDd `ARCHITECTURE.md §6.3.1`; the standard-vs-vendor
split is in [sovd-vs-extensions.md](sovd-vs-extensions.md); the external
integration contract is in [log-integration-contract.md](log-integration-contract.md).

## Capture (producer side) — one facade, one capture point
Host code (the host machine manager + its companions vm-service / vhsm-ssd /
vm-sovd / host-metrics / hsm-sim-service) emits with the STANDARD `tracing`
macros. At
startup each binary calls `sumo_log::init_tracing(context)` ONCE — the ONLY place
that knows how those events are captured. It installs an Eclipse S-CORE
`score_log` recorder AND the `tracing`→`score_log` bridge, so all `tracing::*`
(ours + deps like axum/hyper) flows to the recorder. `sumo-verify` is the one
exception (a CLI launch gate — keeps its stderr fmt subscriber).

The recorder is env-selected (`SUMO_LOG_SINK` = `auto`|`stdout`|`slog2`,
`SUMO_LOG_LEVEL`); `auto` = the QNX slogger2 ring on the rig, stdout off-QNX. So
retargeting the whole fleet is an env change in the launch environment, not code.
(crates: `platform-integration/{sumo-log, score-log-tracing, score-log-slog2}`.)

## The capability split — where a log lives
The dividing line is NOT topic (app vs boot) but **"can this reach our sink
(slog2)?"**
- **CAN reach slog2** → it goes there: the host machine manager + companions,
  plus the OS driver/eMMC telemetry (`devb_*`, CAM) already on the ring. Read
  back via `LogSource::Slog2`.
- **CANNOT easily reach slog2** → its OWN file source: the boot log, `/var/log`,
  and the host-manager funnel-log RESIDUE (shell `[start-managed]` echoes + the
  manager's pre-slog2-registration stderr). Read via `LogSource::HostFiles`.
Because the daemons emit to slog2 (not the funnel), the funnel log shrinks to
residue-only, so the slog2 and file sources DON'T overlap — "additive" is safe.

## Log sources — per component, additive
A component's `ComponentConfig.log_sources` is built by `component-factory` from
its spec (`config.yaml`), additive — a component may have any combination:

| Variant | Spec key | `source` on the wire | Backing |
|---|---|---|---|
| `LogSource::Slog2` | `host_slog2: true` | `slog2` (const `SLOG2_SOURCE`) | QNX `slogger2` ring via `platform_log::read_slog2` (`libslog2parse` FFI) |
| `LogSource::HostFiles { globs }` | `host_log_globs` | the file stem | host-local text files |
| `LogSource::GuestAgent { url }` | `log_agent_url` | the guest's own source | in-guest `log-agent`, proxied over the guest↔host /30 |
| `LogSource::HostDumps { dir }` | `host_dump_dir` | — | directory of discrete dump artifacts (§7.21 message-passing) |

Per-variant detail:
- **Slog2** — ONE physical `source = "slog2"`; the per-buffer name is the EMITTER
  (the `context` each binary passes to `sumo_log::init_tracing`: hsm-sim-service →
  `hsms`, `vhsm`, the host manager → its own tag, plus OS buffers
  `devb_sdmmc_mx8x`, …), surfaced in `LogEntry.fields.emitter` — NOT `source`. A
  client selects "all host-bus logs" by `source=slog2`; the whole ring is one
  source, many emitters. QNX-only in effect (empty off-QNX; a Linux host would
  use a journald source).
  Narrow to / exclude an emitter with the `x-sumo-emitter` / `x-sumo-emitter-exclude`
  query params (comma-separated, prefix-matched — `LogFilter::{emitter,
  emitter_exclude}`). The exclude is applied in the slog2 reader callback BEFORE
  the gather cap, so muting a high-volume emitter (the `devb_*` eMMC/CAM
  firehose) stops it crowding real records out of a tail. The device still
  SERVES every emitter — this only shapes the response.
- **HostFiles** — globs like `/mnt/common-rw/log/*.log`, `/var/log/*`,
  `/dev/shmem/*.log`. The "can't reach slog2" bucket: boot/OS logs + funnel-log
  residue. Lines carry the file mtime as timestamp (coarse) unless a per-line ISO
  stamp is present.
- **GuestAgent** — QNX guests read `/dev/shmem/*.log` + `/var/log/*`; Linux guests
  read journald. The host never reads guest files directly — it proxies HTTP. The
  external-aggregator integration seam (see log-integration-contract.md).

`get_logs` merges all sources; `capabilities.logs` is true iff any source exists,
`capabilities.bulk_data` iff a HostFiles OR GuestAgent source exists (Slog2 +
HostDumps are line/message streams, NOT downloadable-file catalogs).

## Reads: tail, cursor page, and bulk-data
- `get_logs(filter)` — the merged tail/list (newest-first), the classic view.
- `get_logs_paged(filter)` — reboot-safe forward paging. Returns a `LogPage`
  {items, next_cursor, oldest_cursor, tip_cursor}. NOTE the SOVD `GET /logs` route
  calls THIS (not `get_logs`), so every `/logs` read goes through the paged path.
- `list_bulk_data_categories` / `list_bulk_data("logs", …)` / `get_bulk_data` —
  the §7.20 collection: each log file is one downloadable item, fetched whole
  (32 MiB inline cap; 202/307 streaming is future work).

### The entry shape on the wire (source + emitter)
Each entry: `{id, timestamp, priority, message, source, fields?}`. `source` is the
PHYSICAL source (`slog2` for the ring; the file stem for HostFiles; the guest's
own source for GuestAgent). For slog2 the EMITTER (buffer name) is in
`fields.emitter`, NOT `source` — the whole ring is one source, many emitters. The
log `id` is content-addressed (`line:<source-or-source:emitter>:<hash>`) so
`get_log` re-resolves it without server state. NOTE the wire passthrough:
`sovd_core::LogEntry.fields` must be copied into `sovd-api::LogEntryResponse` —
it was once dropped there, so the emitter never reached a client despite being
set (fixed; see the `fields` field on `LogEntryResponse`).

### The cursor (reboot-safe) — why not a timestamp
Device wall-clock is non-monotonic (1970 → safe-time floor → reboot → 1970), so
an absolute time is not a valid resume key. The cursor encodes the backend's
monotonic key instead:

- **Host files** (`host_file_logs_paged`): cursor = base64url of
  `{boot_epoch, per-source {gen, offset}}`. A byte OFFSET is inherently reboot-safe
  (a byte position is monotonic regardless of the clock). `boot_epoch` (a counter
  in a tiny persistent file `/var/lib/machine-mgr/boot_epoch`, NOT nv-store — it's
  only a cursor tag, safe to lose) exists ONLY to invalidate offsets for VOLATILE
  sources (`/dev/shmem`, wiped on reboot) across a boot; persistent files keep
  their offset. `tip_cursor` = every source at its current EOF (the FOLLOW anchor).
  Gap detection: a saved offset past the file length (truncated/rotated) → restart
  that source from 0 + reflect in `oldest_cursor`.
  FIRST CUT: pages the live base file only (gen 0); rotated `{path}.N` are a
  documented follow-up, but rotation is DETECTED (never silently skipped).
- **Guest (journald)**: the guest agent's `/logs/page?after=<__CURSOR>` does the
  forward paging; journald's `__CURSOR` is itself opaque + reboot-safe, so
  `query_log_agent_paged` passes `filter.after` straight through and surfaces the
  guest's `next_cursor` as ours (no host boot_epoch wrapping). Guest `tip_cursor`
  is None today (a rig-time follow-up).

## Guest bulk-data proxy — id namespacing
For a GuestAgent source, `list_bulk_data("logs")` proxies the guest agent's
`GET /files` and namespaces each item id `guest:<b64url(url)>:<guest_file_id>` so
`get_bulk_data` can route the download back to the right agent. Host-file ids are
bare base64url(path) — `parse_guest_bulk_id` requires the `guest:` prefix, so the
two never collide. get_bulk_data re-validates defense-in-depth: the url must be
one of THIS component's live GuestAgent sources AND the guest must still advertise
the id (re-list `/files`) before proxying the bytes.

## GOTCHA: InstallRouterDiag must forward new methods
`app`-type components (e.g. the host-os component) are wired through
`InstallRouterDiag`, a HAND-WRITTEN `DiagnosticBackend` forwarder that routes
install/flash to the `Component` and delegates the rest to the engine. It forwards
each method EXPLICITLY — so a NEW `DiagnosticBackend` method silently falls through
to the trait default unless a forwarder is added. This shipped a real on-device bug:
bulk-data + cursor methods weren't forwarded, so the host-os component returned
empty categories + a cursor-less `/logs` while `bank`-type `vm1` (raw
ComponentBackend) worked. If you add a `DiagnosticBackend` method, ADD A FORWARDER in
`install_router_diag.rs` (there is no compile-time guard — the default impl makes
it compile silently).

## Security: path-traversal guards (both tiers)
- Host: `get_bulk_data` decodes the id to a path, then requires it to be in the
  component's live `resolve_log_files(globs)` set — a crafted id (`/etc/passwd`)
  is indistinguishable from "no such item" (404). Re-resolving each call keeps the
  allow-list authoritative as files rotate.
- Guest: the agent's `resolve_download` applies the identical guard against its
  live `/files` catalog; the host proxy re-validates on top (defense in depth).

## Tests
`crates/component-mgr/src/backend.rs` #[cfg(test)] covers: cursor round-trip,
disjoint-page + terminate + append-after-EOF, volatile invalidation, truncation
gap, boot_epoch persist, tip-cursor follow, host `logs` category list+download,
path-traversal rejection, created-filter, guest-agent proxy (list/download/
degrade) + guest cursor paging + the guest-id round-trip. See the tests named
`log_*` / `bulk_data_*` / `logs_*`.
