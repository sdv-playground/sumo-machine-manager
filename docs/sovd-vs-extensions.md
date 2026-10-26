# SOVD standard vs. sumo extensions

What of the ASAM SOVD / ISO 17978-3 standard the sumo stack **implements**, and
what it **extends** with vendor (`x-*`) routes, params, and behaviour. The
goal is one clear line between "spec" and "ours" — so a client (or an integrator
building a compatible endpoint) knows exactly which assumptions are portable and
which are sumo-specific.

Companion docs: [sovd-entrypoints.md](sovd-entrypoints.md) (which servers bind
which ports), [log-retrieval.md](log-retrieval.md) (how logs are captured +
served), [log-integration-contract.md](log-integration-contract.md) (the two ways
to provide a compatible log endpoint).

## The three-layer rule

```
  SOVDd (sovd-core traits + sovd-api router)   ← spec-pure; no vendor knowledge
        ▲
        │  merged into the router at bind time
  component_mgr::sovd::routes (sumo-mm)         ← the x-* vendor layer
        ▲
  the deployed server (vm-sovd / production host)
```

SOVDd stays spec-pure; every sumo-specific route lives in
`component_mgr::sovd::{routes, pull_update}` and is merged onto the
router at bind time (`vm-sovd/src/main.rs`, `gateway.rs`). The update-verdict
VERBS on the standard `/updates` resource are baked into the SOVDd router itself
(OTA orchestration was co-designed); C-026 closed that seam by renaming them
vendor-neutral `x-ota-*` — a generic API feature, not a sumo one — so they stay
in `sovd-api` without breaking purity. The one deliberate vendor-name residual
there is a commented arm in `sovd-api/auth.rs::route_capability` mapping sumo's
`x-ota-{commit,rollback}-trials` node operations (§2) to `UpdateVerdict`: SOVDd
serves no such route, but they ride its auth middleware in the merged router.

Everything vendor is an `x-` extension per ISO 17978-3 §6.2.7 / §5.3.6, so a
spec-conformant client that ignores unknown `x-*` names still works.

---

## 1. Standard SOVD we implement

Served by the `sovd-api` router (`sovd-api/src/lib.rs:create_router`), all under
`/vehicle/v1/` (server-level routes at the root):

| Domain (spec §) | Routes | Notes |
|---|---|---|
| Server (§7.4/7.5) | `GET /health`, `/version-info`, `/vehicle/v1/docs`, `/.well-known/sovd-extensions` | extension discovery is standard |
| Components | `GET /components`, `GET /components/{id}` | |
| Data | `GET /{id}/data`, `GET\|PUT /data/{param_id}` (`?raw=true`), `data-categories`, `data-lists` | |
| Faults | `GET\|DELETE /faults`, `/faults/{id}` (`?active_only`) | |
| **Logs (§7.21)** | `GET /logs`, `GET /logs/entries`, `GET\|PUT\|DELETE /logs/config`, `GET\|DELETE /logs/{id}` | extended behaviour — §3 |
| **Bulk-data (§7.20)** | `GET /bulk-data`, `/bulk-data/{category}`, `/bulk-data/{category}/{id}` | largely spec-native |
| Operations (§7.14) | `GET /operations`, `/operations/{id}`, `POST .../executions`, `GET\|DELETE .../executions/{id}` | |
| Modes (§7.16) | `GET\|PUT /modes/{session,security,comm-ctrl,dtcsetting}` | |
| Updates/flash (§7.13/7.18) | `POST\|GET /updates`, `/updates/{id}`, `.../bulk-data[/part]`, `/prepare`, `/execute`, `/automated`, `/status` | vendor verbs added — §2 |
| Subscriptions (§7.10) | `GET\|POST /cyclic-subscriptions`, `/{id}` (SSE content-negotiated) | |
| Status/reset (§7.19) | `GET /status`, `PUT /status/restart`, `GET /status/restart/{id}` | `status` carries vendor ext — §3 |
| Sub-entities (HPC) | `/apps`, `/apps/{id}` + data/faults/operations/modes/status mirrors | |

Present-but-stubbed (spec surface, backend TODO): configurations §7.12, locks
§7.17, triggers §7.11, communication-logs §7.22, clear-data, diagnostics §7.9,
scripts §7.15.

---

## 2. Vendor extension routes (`x-*`)

Added by sumo-mm (`component_mgr::sovd::routes` + siblings). None are in the SOVD
spec; all are `x-`-namespaced.

| Route | Method | Purpose |
|---|---|---|
| `/data/x-ota-update-state` | GET | node update-transaction state: `phase` ∈ Idle/Staging/RebootPending/Trial, `components`, `reboot_owed`, `rebooted_since_arming` — polled between campaign steps |
| `/data/x-update-state` | GET | alias of `x-ota-update-state` plus `node_boot_id` (the node's current boot id, `null` when unknown) |
| `/components/hsm/data/keys` | GET | HSM key-slot inventory (public metadata only) |
| `/components/hsm/operations/x-csr/executions` | POST | generate a PKCS#10 CSR for a key slot |
| `/components/hsm/x-ecu-id` | GET | ECU id = HSM device-key thumbprint (the token `aud`); `text/plain` |
| `/operations/x-ota-commit-trials/executions` | POST | node-level commit of all in-trial banked components |
| `/operations/x-ota-rollback-trials/executions` | POST | node-level rollback of in-trial components |
| `/operations/x-update-commit/executions` | POST | node-level commit, same as commit-trials; optional body `{"nonce"?: …}` |
| `/operations/x-update-rollback/executions` | POST | node-level rollback, same as rollback-trials; optional body `{"nonce"?: …}` |
| `/operations/x-update-verdict/executions` | POST | alias of `x-update-commit` / `x-update-rollback`, retired together with the x-ota names; the verdict is in the body (`{"verdict": "commit"\|"rollback", "nonce"?: …}`, 422 for a missing/unknown word); result key `committed`\|`rolled_back` follows the verdict |
| `/operations/x-ota-pull-update/executions` | POST | onboard pull-update (gateway mode); async 202 + poll |

Both update-state routes also carry `banks`: one entry per component that reports bank
contents, `{id, active, inactive, in_trial, pending_reset}`. `active` is the bank the component boots from
(the boot vector's selection when one is attached) with its `images` (part name →
`{size, sha256}`, sha256 lowercase hex; empty when the bank has no readable manifest).
`inactive` is the other bank in the same shape, `null` for a single-bank component or when
the other bank has neither an installed manifest nor a staging record. Each bank carries
`sealed` (`false` for an unsealed inactive bank, which reports the verified parts of an update
still being staged) and, when the executor was told it, the client's `update_id`.

A client that names its parts (`PUT …/bulk-data/{part_id}`, SOVDd's `receive_package_part`)
has them taken by name: the part id is a manifest component's payload `uri` (`#kernel`), its
on-medium name, or that name behind a `#`. A part the bank already holds is accepted with
nothing written; an absent part streams under its declared digest and is refused on a
mismatch, on file banks and raw-partition banks alike, so parts arrive in any order. An id
that names no part keeps the unnamed intake.

The updates a component holds (SOVDd's `held_updates`) come from its facts: the staging record
the target bank keeps, named by the client's registration id, is `PREPARING` while parts arrive
and `PREPARED` once sealed (the seal marks the record; activating the bank removes it); the
armed bank's sealed `update_id` is `EXECUTING` while its node reset is pending and `EXECUTED`
during the trial. Parts are reported by on-medium name. A committed or rolled-back component,
and a record an abort stripped of its id, hold nothing.
`in_trial` is true while the component runs a not-yet-committed install: with a boot vector, its booted entry differs from its committed
entry; without one, its bank set is not committed. The images come from the installed
manifests as recorded at install time, read without signature check or payload hashing; this
is a report, not a verification. Intended use: after any reboot the orchestrator compares
`inactive` with its intended release and downloads only the images that differ.

Each bank also carries `install_boot_id`: the node boot id current when the bank was sealed,
as its installed manifest records it (`null` for a manifest sealed before the field existed,
a node without a boot id, or no readable manifest). `pending_reset` is true when the
component's newly installed content needs a node reset that has not happened yet: its reset
kind is `requires_ecu_reset` and the active bank's `install_boot_id` is set and equal to the
node's current boot id. Anything else, an unknown boot id on either side included, is
`false`. It is a per-component fact read from the signed manifest, so it survives process
restarts and holds for two-bank and single-bank components alike. Intended use: continue only
when nothing you just wrote is pending a reset; whether and when to reset is the
orchestrator's.

They also carry the boot vector's transaction state. `trial_boots`: distinct node boots
counted while armed without a verdict (`null` when the boot vector has no header, or the
node is not in trial and has no recorded resolution). `trial_boot_limit`: the count
at which the node rolls itself back (`null` = disabled; set by the host). `resolution`: how
the last node transaction ended, `{"outcome": "committed"|"rolled_back", "reason":
"verdict"|"trial_boot_limit"|"boot_stage"}`, `null` while a trial is open or when none is
recorded. `boot_stage` means the boot stage restored the committed copy while the node was
down (recorded at the next start); `trial_boots` then is the count sumo observed before the
boot stage gave up (0 when the node never came up).

Residual concurrency limitation: the node commit/rollback routes serialize
against each other inside sumo-mm, but SOVDd's component-level verdict routes do
not share that mutex. Closing that cross-route TOCTOU window requires a shared
guard in the upstream SOVDd API and is intentionally outside this repository's
patch.

**Commit is not gated on-device (since 2026-10-22).** The node verdict routes and a
component's `preflight_commit` do not refuse a commit because a component is pending a
node reset. The device reports facts and the orchestrator decides:

- `x-ota-update-state.reboot_owed` lists the components pending a node reset: derived
  from each component's `pending_reset` (its install needs a node reset that has not
  happened yet), not stored. It empties once the node has rebooted.
- `x-ota-update-state.rebooted_since_arming` says whether the node has rebooted since the
  open trial was armed: the boot vector's transaction header compares the boot id recorded
  at seal with the current one, whatever the components' reset kind (`null` when
  unknown). `phase` is `RebootPending` while `reboot_owed` is non-empty and `Trial` while
  a component is in trial and none is pending.
- Orchestrator rule: `RebootPending` → reset the node first. `Trial` with
  `rebooted_since_arming` true → the components booted into their new content; check
  health, the reported running bank and `x-ota-installed-manifest`, then commit or roll
  back. `Trial` before the reboot → the step is armed; stage the remaining components,
  then reset.
- Residual risk, by design: a bootloader fall-back after the reboot is invisible to this
  process (`running_bank` is seeded from NV `active_bank`). The orchestrator must compare
  the installed manifest / running release; on hardware the bootloader's boot-status
  record is the durable answer.

The node `x-update-commit` / `x-update-rollback` operations are the same operations as
`x-ota-commit-trials` / `x-ota-rollback-trials` (same fan-out, same lock, same 200/409/500
rules, optional `nonce` body); `x-update-verdict` is their alias with the verdict carried in
the body, retired together with the x-ota names. `x-update-state` is `x-ota-update-state`
plus `node_boot_id`. The per-update `…/updates/{update_id}/x-update-commit` /
`x-update-rollback` verbs are SOVDd's and are for single-component executors and component
resets; node transactions take these operations.
The per-update `x-update.state` / `reset_kind` on the update status and
`capabilities.x-update.verdict` are served by SOVDd (see `SOVDd/docs/x-update.md`), derived
from this backend's activation state and `update_shape()`.

A new flash is still refused while any component is pending a node reset
(`reboot_owed` non-empty), or while a component is in trial and the node has rebooted
since arming (one update transaction per ECU) — that is transaction integrity, not a
verdict. Before that reboot a new flash joins the armed step.

Vendor DATA params (served through the standard `/data/{param_id}` route, not
new routes):
- `x-ota-installed-manifest` — installed SUIT manifest JSON for the serving bank.
- `x-ecu-id` (also the route above) — the ECU thumbprint.

Verbs baked into the STANDARD `/updates` router: `PUT /updates/{id}/x-ota-commit`,
`/x-ota-rollback`, `PUT /components/{id}/x-ota-force-rollback` — vendor-neutral
since C-026, so no longer vendor extensions — plus the still-vendor query param
`PUT /execute?x-ota-control=orchestrated`.

Production-only (a vendor-private sibling server, not this tree):
`GET /status/x-boot-id` and `POST /factory_reset`. In this tree the boot id
exists as `node_boot_id` feeding `x-runtime` (below).

---

## 3. Extended BEHAVIOUR on standard endpoints

Standard routes that carry vendor semantics or fields a pure-spec client wouldn't
expect. **This is the part that matters most for building a compatible endpoint.**

### Per-source log routes (vendor extension) — `sovd-api/lib.rs` + `handlers/logs_ext.rs`

Distinct log sources are NEVER merged/time-sorted (independent clocks — a live
journal at real time vs. a boot file stamped 1970). So a source is a resource you
ENUMERATE then ADDRESS, not a filter value:

| Route | Method | Returns |
|---|---|---|
| `/logs/sources` | GET | catalog: `[{ name, kind: journal\|file\|dump, cursor, emitters?, href }]` |
| `/logs/sources/{name}` | GET | ONE source's entries (same body as `/logs`), paged with its own cursor + emitter filter |

Registered as static routes ahead of the `/logs/{log_id}` catch-all (matchit
gives statics priority; the 3-segment form can't collide anyway). Bare
`GET /logs` returns the PRIMARY source (first `journal`, else first source) when
a component has >1 source — a sane default, never a cross-source merge. A
`file`/`dump` source is also downloadable whole via the spec-native
`/logs/entries` → `/bulk-data/logs/{id}` path.

On the QNX host (Tier-2) the catalog shows TWO slog2 planes: `slog2-ring` (the
raw volatile ring, `cursor:false` — a live tail, all emitters) and `slog2`
(the `slog2-drainer`'s sealed disk segments → live file, `cursor:true` — the
PRIMARY durable, reboot-safe, resumable timeline paged by `<seq>:<offset>`,
oldest→now). Tier-1 (provisioning MM) shows only `slog2-ring`. See
[log-retrieval.md](log-retrieval.md) for the drainer.

### Logs `GET /logs` (§7.21) — wire types in `sovd-api/handlers/logs.rs`

**Extra request params** (base SOVD defines none of these):

| Param | Type | Definition |
|---|---|---|
| `x-log-after` | opaque string | Cursor. Return entries strictly after this position, oldest→newest. Omit ⇒ start at oldest available. Never parsed by the client. |
| `x-log-emitter` | csv, prefix | INCLUDE only these emitters (sub-sources); comma-separated, prefix-matched (`devb` ⇒ `devb_sdmmc_mx8x`). Narrows within a multi-emitter source (the slog2 ring). Empty/absent ⇒ all. |
| `x-log-emitter-exclude` | csv, prefix | DROP these emitters (same form), applied after the include. Mutes a high-volume sub-source (e.g. the `devb_` eMMC/CAM firehose). The device still SERVES them. |
| `since` / `until` | RFC 3339 \| sentinel | Sentinels: `BEGIN` (no bound), `END`\|`NOW` (device now), `END-<N>{s,m,h,d}` \| `NOW-<N>{s,m,h,d}` (now minus duration). Resolved server-side vs. device clock. Malformed ⇒ 400. |

**Extra response fields** on the list body (all `skip_if_none`):

| Field | Definition |
|---|---|
| `x-log-next-cursor` | Cursor for the next page; feed back as `x-log-after`. `null`/absent ⇒ head reached. |
| `x-log-oldest-cursor` | Oldest position still available; an `x-log-after` older than this ⇒ history rotated away (gap). |
| `x-log-tip-cursor` | Cursor at the current head; poll `x-log-after=<this>` to follow only new entries. Present even at head. |

**Extra `LogEntry` fields / vendored value domains:**

| Field | Definition |
|---|---|
| `source` | The single physical source. `slog2` for the whole host ring; the file stem for file sources; the guest's own source for guest entries. |
| `fields` | Structured k/v map. For `source="slog2"`, `fields.emitter` = the buffer/daemon name (the sub-source). Also carries journald fields. |
| `priority` | Enum, 8 values: `emergency`\|`alert`\|`critical`\|`error`\|`warning`\|`notice`\|`info`\|`debug`. |
| `status` | Enum: `pending`\|`retrieved`\|`processed`. Present only for the acknowledge pattern (paired with `DELETE /logs/{id}`). |

**Cursor invariants** (a compatible endpoint MUST hold these):
- Opaque to the client; reboot-safe. Encodes a monotonic key — journald
  `__CURSOR`, or a host `(boot_epoch, gen, offset)` — never a wall-clock time.
- Rationale: device wall-clock is non-monotonic (1970 → safe-time floor → reset
  on reboot), so timestamps are not a valid ordering/resume key across boots.
  File-source entries carry the file mtime (coarse; may be 1970) — advisory only.

### Status `GET /status` (§7.19.2)
`EntityStatusBody` carries a spec-pure `#[serde(flatten)] extensions` map; sumo
fills it with one vendor key:

| Key | Value |
|---|---|
| `x-runtime` | The per-component runtime facts, flattened into one object — see below. |

**`x-runtime` keys.** Every key is **omitted when unknown, never `null`**: a
reader must be able to tell "no heartbeat" from "heartbeat seq 0", and "no
verdict" from "checked, and it disagrees". Readers therefore key off the map
(`.get("…")`) and treat additions as inert — the map is untyped
(`serde_json::Map`) on both sides of the wire.

| Key | Present when | Value |
|---|---|---|
| `node_boot_id` | node knows it | Node-wide per-boot nonce — stamped on EVERY component, since host-os has no heartbeat of its own. The offboard reboot witness compares it. |
| `admin_state` | component is disableable | `enabled`\|`disabled`. Tri-state by omission: a non-disableable component omits it, so a UI can tell "cannot be disabled" from "enabled". The **persisted operator decision**. |
| `reboot_pending` | `true` only | An admin change needs a reboot to take effect. |
| `hb_seq`, `boot_id`, `guest_state` | health source reports them | Raw heartbeat facts: liveness counter, per-lifetime nonce, guest-reported readiness (`1` = up). |
| `lifecycle_status` | a health source exists | **Observed axis** — `starting`\|`running`\|`unhealthy`\|`shutting_down`\|`stopped`\|`failed`\|`unknown`. |
| `lifecycle_for_ms` | ↑ | Monotonic dwell in the observed state; restarts on **every** observed transition (a `starting → failed → starting` flap zeroes it). |
| `lifecycle_since` | ↑ | Wall-clock unix secs of that transition. Advisory only — device wall-clock is non-monotonic. |
| `lifecycle_reason` | there is one | Free text, e.g. `administratively disabled`, `no active bank selected`. |
| `lifecycle_expected` | intent was recorded | **Intent axis** — `running`\|`stopped`. Absent means *nothing asked*, which is not the same as "asked to stay down"; it is derived from decisions actually taken, never read back from config. |
| `lifecycle_expected_by` | provenance known | Who asked: `autostart`\|`api`\|`stop_api`\|`reboot_sweep`\|`admin_disable`. |
| `lifecycle_expected_for_ms` | intent was recorded | Monotonic dwell of the intent; restarts only when the intent **value** changes. `min(lifecycle_for_ms, lifecycle_expected_for_ms)` is exactly the divergence dwell, so the observer owns the deadline and the device holds no threshold. |
| `lifecycle_convergence` | both axes have a basis | `converged`\|`transitioning`\|`diverged` — the verdict, computed in one place from fields published in this same body (so any client can recompute and explain it). No cell of that table reads a clock, and `diverged` is a statement about *now*, not a prediction. |

Administratively disabled components carry `lifecycle_status: "stopped"`,
`lifecycle_reason`, `lifecycle_expected: "stopped"` and
`lifecycle_expected_by: "admin_disable"` but deliberately **no**
`lifecycle_convergence`: the intent is known and nothing is observed, so a
verdict there would be invented. The same writer fills this map and
`RuntimeState::detail`, so `/status` and the trait layer cannot drift.

### Scripts (§7.15)
A test execution records an `x-log` log-cursor bracket:

| Field | Meaning |
|---|---|
| `log_from` | log tip cursor at run start; the run's window is `GET /logs?x-log-after=<log_from>` |

### Bulk-data (§7.20)
Spec-native shape; listed here only for completeness (no vendor deltas):

| Type | Fields / behaviour |
|---|---|
| `BulkDataItem` | `{ id, size, created, mime, source? }` |
| filters | `created_before`, `created_after` |
| download | 200 inline / 307 redirect / 202 async; `logs` is the first category |

---

## 4. Auth

**Bearer:** JWT, validated by the `require_auth` middleware (`sovd-api/auth.rs`).
The server never mints. Refuses plain HTTP unless explicitly allowed.

**`AuthMode`** (core):

| Mode | Validation |
|---|---|
| `disabled` | none (dev/sim) |
| `static` | shared token |
| `oidc` | JWT against trusted issuers' JWKS |
| `workshop-ca` | `x5c`-cert JWT against a pinned CA; device id as `aud` |

**Capability scopes** (`component_mgr::sovd::authz`), by tier:

| Tier | Scopes | Mintable by |
|---|---|---|
| `Operational` | `data:read/write`, `operations:execute`, `modes:set`, `update:transfer/execute/verdict`, `reset:execute`, `component-admin` | in-vehicle onboard minter |
| `HighConsequence` | `factory-reset` | external authority only |

**Freshness binding** (both tiers): token `boot_id` claim MUST equal the live
boot (§7.1); vehicle-wide tokens' `epoch` claim MUST be ≥ the device epoch floor
(§7.3).

**Token acquisition** (client steps):

| Step | Call | Yields |
|---|---|---|
| 1 | `GET .../components/hsm/x-ecu-id` | device id → token `aud` |
| 2 | `GET .../status/x-boot-id` | boot nonce → token `boot_id` |
| 3 | `POST <minter>/mint` (operator bearer) | short-lived boot-bound JWT |

---

## Summary: the sumo "SOVD (extended)" profile

A sumo-compatible SOVD endpoint = standard SOVD **plus**: the `/logs/sources`
catalog + `/logs/sources/{name}` per-source reads; the `x-log-after` cursor +
three response cursors on `/logs`; the `END[-N]`/`BEGIN` time sentinels;
reboot-safe (non-timestamp) ordering; `fields.emitter` on log entries; the
`x-runtime` status block; and the boot-bound JWT freshness model. The
`x-ota-*` / `x-csr` OTA/HSM routes are needed only for a device that participates in OTA —
a pure log/diagnostics endpoint doesn't need them. See
[log-integration-contract.md](log-integration-contract.md) for exactly what a
log endpoint must implement.
