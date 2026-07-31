# SOVD standard vs. sumo extensions

What of the ASAM SOVD / ISO 17978-3 standard the sumo stack **implements**, and
what it **extends** with vendor (`x-sumo-*`) routes, params, and behaviour. The
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
  component_mgr::sovd::routes (sumo-mm)         ← the x-sumo-* vendor layer
        ▲
  the deployed server (vm-sovd / production host)
```

SOVDd stays spec-pure; every sumo-specific route lives in
`component_mgr::sovd::{routes, admin_state, pull_update}` and is merged onto the
router at bind time (`vm-sovd/src/main.rs`, `gateway.rs`). One documented seam
breaks the purity: a few `x-sumo-*` VERBS on the standard `/updates` resource are
baked into the SOVDd router itself (OTA orchestration was co-designed) — noted
below.

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

## 2. Vendor extension routes (`x-sumo-*`)

Added by sumo-mm (`component_mgr::sovd::routes` + siblings). None are in the SOVD
spec; all are `x-`-namespaced.

| Route | Method | Purpose |
|---|---|---|
| `/data/x-sumo-update-state` | GET | node update-transaction state (phase + per-component), polled between campaign steps |
| `/components/hsm/data/keys` | GET | HSM key-slot inventory (public metadata only) |
| `/components/hsm/operations/x-sumo-csr/executions` | POST | generate a PKCS#10 CSR for a key slot |
| `/components/hsm/x-sumo-id` | GET | ECU id = HSM device-key thumbprint (the token `aud`); `text/plain` |
| `/operations/x-sumo-commit-trials/executions` | POST | node-level commit of all in-trial banked components |
| `/operations/x-sumo-rollback-trials/executions` | POST | node-level rollback of in-trial components |
| `/components/{id}/operations/x-sumo-admin-state/executions` | POST | per-component administrative disable/enable |
| `/operations/x-sumo-pull-update/executions` | POST | onboard pull-update (gateway mode); async 202 + poll |

Vendor DATA params (served through the standard `/data/{param_id}` route, not
new routes):
- `x-sumo-installed-manifest` — installed SUIT manifest JSON for the serving bank.
- `x-sumo-id` (also the route above) — the ECU thumbprint.

Vendor verbs baked into the STANDARD `/updates` router (the documented
purity break): `PUT /updates/{id}/x-sumo-commit`, `/x-sumo-rollback`,
`PUT /components/{id}/x-sumo-force-rollback`, and `PUT /execute?x-sumo-control=orchestrated`.

Production-only (a vendor-private sibling server, not this tree):
`GET /status/x-sumo-boot-id` and `POST /factory_reset`. In this tree the boot id
exists as `node_boot_id` feeding `x-sumo-runtime` (below).

---

## 3. Extended BEHAVIOUR on standard endpoints

Standard routes that carry vendor semantics or fields a pure-spec client wouldn't
expect. **This is the part that matters most for building a compatible endpoint.**

### Per-source log routes (x-sumo) — `sovd-api/lib.rs` + `handlers/logs_ext.rs`

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

### Logs `GET /logs` (§7.21) — wire types in `sovd-api/handlers/logs.rs`

**Extra request params** (base SOVD defines none of these):

| Param | Type | Definition |
|---|---|---|
| `x-sumo-after` | opaque string | Cursor. Return entries strictly after this position, oldest→newest. Omit ⇒ start at oldest available. Never parsed by the client. |
| `x-sumo-emitter` | csv, prefix | INCLUDE only these emitters (sub-sources); comma-separated, prefix-matched (`devb` ⇒ `devb_sdmmc_mx8x`). Narrows within a multi-emitter source (the slog2 ring). Empty/absent ⇒ all. |
| `x-sumo-emitter-exclude` | csv, prefix | DROP these emitters (same form), applied after the include. Mutes a high-volume sub-source (e.g. the `devb_` eMMC/CAM firehose). The device still SERVES them. |
| `since` / `until` | RFC 3339 \| sentinel | Sentinels: `BEGIN` (no bound), `END`\|`NOW` (device now), `END-<N>{s,m,h,d}` \| `NOW-<N>{s,m,h,d}` (now minus duration). Resolved server-side vs. device clock. Malformed ⇒ 400. |

**Extra response fields** on the list body (all `skip_if_none`):

| Field | Definition |
|---|---|
| `x-sumo-next-cursor` | Cursor for the next page; feed back as `x-sumo-after`. `null`/absent ⇒ head reached. |
| `x-sumo-oldest-cursor` | Oldest position still available; an `x-sumo-after` older than this ⇒ history rotated away (gap). |
| `x-sumo-tip-cursor` | Cursor at the current head; poll `x-sumo-after=<this>` to follow only new entries. Present even at head. |

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
| `x-sumo-runtime` | `{ boot_count, uptime_s, node_boot_id, admin_state }` |

### Scripts (§7.15)
A test execution records an `x-sumo` log-cursor bracket:

| Field | Meaning |
|---|---|
| `log_from` | log tip cursor at run start; the run's window is `GET /logs?x-sumo-after=<log_from>` |

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
| 1 | `GET .../components/hsm/x-sumo-id` | device id → token `aud` |
| 2 | `GET .../status/x-sumo-boot-id` | boot nonce → token `boot_id` |
| 3 | `POST <minter>/mint` (operator bearer) | short-lived boot-bound JWT |

---

## Summary: the sumo "SOVD (extended)" profile

A sumo-compatible SOVD endpoint = standard SOVD **plus**: the `/logs/sources`
catalog + `/logs/sources/{name}` per-source reads; the `x-sumo-after` cursor +
three response cursors on `/logs`; the `END[-N]`/`BEGIN` time sentinels;
reboot-safe (non-timestamp) ordering; `fields.emitter` on log entries; the
`x-sumo-runtime` status block; and the boot-bound JWT freshness model. The
`x-sumo-*` OTA/HSM routes are needed only for a device that participates in OTA —
a pure log/diagnostics endpoint doesn't need them. See
[log-integration-contract.md](log-integration-contract.md) for exactly what a
log endpoint must implement.
