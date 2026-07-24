# Log retrieval (SOVD §7.21 + §7.20) — device side

How `component-mgr` serves a component's logs: the sources it reads, the
reboot-safe cursor, and the §7.20 bulk-data download path. The SOVD wire contract
+ the two client-facing paths are documented in SOVDd `ARCHITECTURE.md §6.3.1`;
this doc is the device/backend half.

## Log sources — per component, additive
A component's `ComponentConfig.log_sources` is built by `component-factory` from
its spec (`config.yaml`), additive — a component may have any combination:

- `LogSource::HostFiles { globs }`  ← spec `host_log_globs`
  Host-local text files (globs like `/mnt/common-rw/log/*.log`, `/var/log/*`,
  `/dev/shmem/*.log`). The host's OWN daemon logs land in `log_dir`
  (`/mnt/common-rw/log/`, written by the `log-rotate` crate) — a HostFiles source
  MUST glob that dir or the daemon logs are invisible (this bit us on the CVC:
  the deployed globs only had /var/log + /dev/shmem and missed the real logs).
- `LogSource::GuestAgent { url }`   ← spec `log_agent_url`
  A guest VM's in-guest `log-agent` (guest-vm-sdk), proxied over the guest↔host
  /30. QNX guests read `/dev/shmem/*.log` + `/var/log/*`; Linux guests read
  journald. The host never reads guest files directly — it proxies HTTP.
- `LogSource::HostDumps { dir }`    ← spec `host_dump_dir`
  A directory of discrete dump artifacts (the §7.21 message-passing pattern).

`get_logs` merges all sources; `capabilities.logs` is true iff any source exists,
`capabilities.bulk_data` iff a HostFiles OR GuestAgent source exists.

## Reads: tail, cursor page, and bulk-data
- `get_logs(filter)` — the merged tail/list (newest-first), the classic view.
- `get_logs_paged(filter)` — reboot-safe forward paging. Returns a `LogPage`
  {items, next_cursor, oldest_cursor, tip_cursor}. NOTE the SOVD `GET /logs` route
  calls THIS (not `get_logs`), so every `/logs` read goes through the paged path.
- `list_bulk_data_categories` / `list_bulk_data("logs", …)` / `get_bulk_data` —
  the §7.20 collection: each log file is one downloadable item, fetched whole
  (32 MiB inline cap; 202/307 streaming is future work).

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
`app`-type components (e.g. the host-os `supernova`) are wired through
`InstallRouterDiag`, a HAND-WRITTEN `DiagnosticBackend` forwarder that routes
install/flash to the `Component` and delegates the rest to the engine. It forwards
each method EXPLICITLY — so a NEW `DiagnosticBackend` method silently falls through
to the trait default unless a forwarder is added. This shipped a real on-device bug:
bulk-data + cursor methods weren't forwarded, so `supernova` returned empty
categories + a cursor-less `/logs` while `bank`-type `vm1` (raw ComponentBackend)
worked. If you add a `DiagnosticBackend` method, ADD A FORWARDER in
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
