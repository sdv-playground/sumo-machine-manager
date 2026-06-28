# SOVD server entrypoints

**SOVD** (ISO 17978-3 / ASAM Service-Oriented Vehicle Diagnostics) is the
diagnostics-and-OTA HTTP API the sumo stack exposes under `/vehicle/v1/...`
(components, data, operations, modes, faults, logs, and the `/updates` flash
wire). The wire is built from the **SOVDd library** (`sovd-core` traits +
`sovd-api` router); sumo-mm adds the `x-sumo-*` vendor routes on top (the
three-layer rule — SOVDd stays spec-pure, vendor extensions live here in
`component_mgr::sovd::routes`). This doc inventories every place in the
workspace that **binds a port and serves** that API, so "which server is this?"
has one answer.

## How many SOVD servers are there?

More than two. The two the team usually names — *the machine manager* and *the
vehicle gateway* — are actually **one binary (`vm-sovd`) with two run modes**.
Across the whole workspace the deployed SOVD-API servers are:

| # | Server (crate / bin) | Repo | Runs on | Default bind | What it serves |
|---|---|---|---|---|---|
| 1 | `vm-sovd` (default mode) | sumo-mm | host (dev/sim) | `0.0.0.0:4000` | host-owned components (host-os, vm1, vm2, hsm) + OTA |
| 2 | `vm-sovd --gateway` | sumo-mm | in-VM **or** on-host | `0.0.0.0:9300` (example) | guest components + onboard pull-update + proxy of host components |
| 3 | `supernova` (`supernova-machine-manager`) | sibling | host (production) | `0.0.0.0:4000` | production counterpart of #1 (same routes, real HSM, auth) |
| 4 | `sovdd` | SOVDd | standalone | `0.0.0.0:18081` (mock) | reference SOVD server (UDS↔REST, gateway, proxy) |
| 5 | `example-app` | SOVDd | standalone | `0.0.0.0:4001` | reference app-entity (tier-1 supplier) server |

Plus two **SOVD-adjacent helper servers** (HTTP, but not the `/vehicle/v1` API):
`sovd-security-helper` (seed→key) and `sovd-token-helper` (JWT minter).

Servers 1–3 are the sumo-stack deployments and share the same route library;
4–5 are the upstream reference servers shipped with the SOVDd library itself.

> Note: `vm-diagserver` (the second binary in `component-mgr`) is **not** an HTTP
> server — it is a local CLI for NV-store / bank / factory operations
> (`status`, `install`, `commit`, `rollback`, `read-did`, `factory-init`). It
> never binds a port. The host SOVD HTTP server is `vm-sovd`.

---

## 1. Host machine-manager server

The ECU's front-door SOVD/OTA server. Composes the host's updatable components
through the shared `component-factory` and serves them at the SOVD wire. There
are two binaries — a dev/sim one in this repo and a production one in a sibling
repo — that serve the **same** wire from the **same** route library.

### `vm-sovd` (dev / simulation) — this repo

- **Crate / bin:** `vm-sovd` (`crates/vm-sovd/src/main.rs`).
- **Runs on:** the host, Linux dev with file-backed NV + QEMU.
- **Serves:** the host-owned components `host-os`, `vm1`, `vm2`, `hsm` (built via
  `component_factory::build_component`), the standard SOVD surface from
  `sovd_api::create_router`, plus the sumo vendor routes —
  `hsm_router` (HSM key inventory + `x-sumo-csr`) and `update_state_router`
  (`x-sumo-update-state`). See `crates/vm-sovd/src/main.rs:462-470`.
- **Bind / port:** `0.0.0.0:4000` by default; override with `--bind <addr>` or a
  positional bind-addr (`crates/vm-sovd/src/main.rs:79`).
- **Launched by:** `example/run.sh` (alongside `sovd-security-helper` on `:9100`,
  the `hsm-sim-service` link-B backend, and `vhsm-ssd`). Connect-only to the
  pre-spawned link-B HSM backend via `--backend-socket`. Also run in host mode
  (bind `:4001`) by `examples/campaign/start-ecus.sh`, the `tests/` e2e harness,
  and the workspace-root `compose.yaml`.

### `supernova` (production) — `components/supernova-machine-manager` (sibling repo)

- **Crate / bin:** `supernova-machine-manager` / bin `supernova`.
- **Runs on:** the production host (real platform; HSE HSM backend, embedded
  `vm-service` lifecycle API + `host-metrics`).
- **Serves:** the production counterpart of `vm-sovd` — the same
  `sovd_api::create_router` + the same sumo vendor routes from this repo
  (`component_mgr::sovd::routes::{hsm_router, device_id_router,
  node_verdict_router, update_state_router}`), plus `x-sumo-boot-id`,
  `x-sumo-freshness`, and `/factory_reset`. It is **host-only — no gateway
  mode** (the "proxy" in its code is the *vhsm-ssd* HSM proxy, not SOVD
  proxying). Secure-by-default authorizer is always wired
  (`src/main.rs:1766-1856`).
- **Bind / port:** `cfg.bind`, default `0.0.0.0:4000` (`src/config.rs:427`);
  `axum::serve` at `src/main.rs:2200`.
- **Launched by:** a respawn loop with a TOML config — the `qemu-cvc` Docker
  entrypoint (`examples/qemu-cvc/entrypoint.sh`) for the emulated device, and
  `managed-qnx71/start.sh` → `bank_a/start.sh` on the rig (deployed by
  `examples/tower-provision/build-and-deploy-supernova.sh`).

---

## 2. Vehicle gateway — `vm-sovd --gateway`

The guest's single SOVD front door. **Not a separate binary** — it is the same
`vm-sovd` with `--gateway`, which swaps the default router for the federating
gateway router (`build_gateway_router` → `component_mgr::sovd::gateway::gateway_router`,
`crates/vm-sovd/src/main.rs:429-461`, `554-620`).

It serves:

- the guest's **own** components (its local `Machine`),
- the **onboard pull-update** operation `POST /vehicle/v1/operations/x-sumo-pull-update/executions`
  with **route-scoped** Operational `update:execute` authz
  (`pull_update_router`),
- **host-owned components proxied** to the host SOVD: each `--proxy-component`
  becomes a `sovd_proxy::SovdProxyBackend` forwarding to `--host-sovd-url`, so a
  proxied host component is just another entry in the SOVD entity map — that is
  the federation.

Flags (`crates/vm-sovd/src/main.rs:47-54`):

- `--gateway` — enable gateway mode.
- `--host-sovd-url <url>` — the host SOVD to proxy host components to.
- `--proxy-component <id>` — a host-owned component id to proxy (repeatable).
- `--device-id <id>` — the token `aud` (pins the onboard minter's issuer).
- `--guest-vhsm` — source HSM crypto from the **guest vHSM** (see modes below).
- `--bind <addr>` — listen address.

### Two run modes — where the crypto comes from

The gateway needs an `HsmCryptoProvider` for its authorizer's issuer anchors and
the pull-update trust anchor (the sw-authority key). The mode is chosen by
**where that crypto is sourced**, not by a separate codebase:

- **In-VM (`--guest-vhsm`)** — crypto comes from the guest vHSM via
  `vhsm_provider::VhsmProvider::connect_local()`, which forwards over the vHSM
  wire to the host `vhsm-ssd` (`crates/vm-sovd/src/main.rs:435-441`). This is the
  deployed variant: it runs **inside a guest VM** (vm1) as the
  `vehicle-gateway` layer. Example launch
  (`examples/t2-seed-dev/channels/dev/layers/vehicle-gateway/autostart.sh`):

  ```sh
  exec ./vm-sovd "$NV" --gateway \
      --host-sovd-url http://10.0.101.1:9200 \
      --proxy-component host-os \
      --device-id "$DEVICE_ID" \
      --guest-vhsm \
      --bind 0.0.0.0:9300
  ```

- **On-host (no `--guest-vhsm`)** — crypto comes from the host link-B HSM backend
  client (`--backend-socket`); the same gateway router runs on the host
  (`crates/vm-sovd/src/main.rs:442-450`). Supported by the same binary; used when
  the gateway is co-located with the host rather than inside a VM.

- **Runs on:** in-VM (guest) or on-host, per the mode above.
- **Bind / port:** deployment choice; `0.0.0.0:9300` in the t2-seed examples.
- **Launched by:** the guest's `vehicle-gateway` layer `autostart.sh` in
  `examples/t2-seed-dev` and `examples/t2-seed-cicd`.

> The `--gateway vehicle_gateway` argument seen in `examples/campaign/*.sh` is a
> **`sumo-campaign` client** flag (naming which ECU is the gateway), **not** a
> `vm-sovd` server launch — don't confuse the two.

---

## 3. Reference servers (the SOVDd library repo)

These ship with the SOVDd library as the spec-pure reference implementation and
its demo. They are not sumo-stack host deployments, but they are SOVD-API
servers present in the workspace.

### `sovdd` — `components/SOVDd/crates/sovdd`

- **Bin:** `sovdd`. The reference SOVD diagnostic server: translates the
  `/vehicle/v1` REST API to UDS over SocketCAN / DoIP / Mock, and can federate
  (`sovd-gateway`) and proxy to supplier containers (`sovd-proxy`).
- **Bind / port:** `0.0.0.0:<config port>`; default `18081` in mock mode
  (`crates/sovdd/src/main.rs:141,186`). Optional TLS via `[server.tls]`
  (`axum_server::bind_rustls`, `main.rs:215`).
- **Launched by:** `sovdd [config.toml] [--did-definitions <path>]`. In-workspace
  it runs as the UDS-ECU aggregating gateway in `examples/campaign`, the `tests/`
  e2e harness, and the root `compose.yaml` (`sovdd .../gateway.toml`, bind `:4000`).

### `example-app` — `components/SOVDd/crates/example-app`

- **Bin:** `example-app`. The reference **app-entity** (tier-1 supplier) SOVD
  HTTP server; embeds `example-ecu` for a full app→ECU stack in one process.
- **Bind / port:** `0.0.0.0:<--port>`, default `4001`
  (`crates/example-app/src/main.rs:392-396`).

---

## 4. SOVD-adjacent helper servers

HTTP servers in the SOVD ecosystem that do **not** serve the `/vehicle/v1`
diagnostic API — they back the diagnostic flow.

### `sovd-security-helper` — `components/SOVD-security-helper`

- UDS **SecurityAccess** seed→key derivation: holds ECU secrets server-side and
  computes the unlock response for authenticated callers. Routes `GET /info`,
  `POST /calculate`.
- **Bind / port:** `0.0.0.0:9100` (`--port`, `src/main.rs:645-659`).
- It is **not** the SUIT signing authority (that is `sumo-sign`, offline).

### `sovd-token-helper` — `components/sovd-token-helper`

- Offboard workshop **JWT minter**: signs short-lived ES256 client→SOVD access
  tokens that the server validates. Routes `GET /health`, `GET /info`,
  `GET /jwks`, `POST /mint`.
- **Bind / port:** `127.0.0.1:9200` (`0.0.0.0` with `--bind-all`,
  `src/main.rs:392-396`).

---

## 5. Not servers — the library, the CLIs, and the UIs

- **The SOVD library** — `sovd-core` (the `DiagnosticBackend` trait + models) and
  `sovd-api` (the `create_router` / `AppState` / `Authorizer` axum router), with
  `sovd-proxy` (`SovdProxyBackend`, used by the gateway), `sovd-gateway`,
  `sovd-uds`, `sovd-conv` (all from SOVDd). These are the **shared router/traits**
  every server above is built from; none is itself a deployed server.
- **SOVD Explorer** (`components/SOVD-explorer`) — a Tauri desktop **GUI client**;
  talks to a SOVD server, does not serve one.
- **sumo-sovd** (`components/sumo-sovd`) — the campaign **client/orchestrator**
  CLIs (`sumo-campaign`, `sumo-map`); drives SOVD servers over `sovd-client`,
  does not serve.
- **`vm-diagserver`** (`component-mgr`) and **`sovd-cli`** (SOVDd) — **CLIs**, not
  servers.

### Other (non-SOVD) HTTP servers in the workspace

Listed to prevent confusion — these bind ports but are **not** SOVD:

- `vm-service` (this repo; also embedded in `supernova`) — QEMU/qvm lifecycle
  control API (`/start`, `/restart`).
- `host-metrics` (this repo; also embedded in `supernova`) — Prometheus
  `GET /metrics`.
- `vhsm-ssd` (this repo) — the vHSM v3 wire daemon (TCP `:5100` on the `vbr-vhsm`
  bridge).
- `identity-tower` / `software-tower` (`components/sumo-provision`) — the
  provisioning Tower front-door (register device, request reset token, publish
  software), not the in-vehicle `/vehicle/v1` API.
