# Full componentization — nothing on by default (FUTURE TASK)

**Status: proposal, not started.** Extends [features.md](features.md) and
**replaces its rule 4**. Sequenced so work item 0 is independently landable and
each later item is a self-contained wave.

The end state: a binary's capability set is *declared at compile time in one
place*, and every capability — VM management, logging, the vendor extension
routes, the docs hook, the HSM simulator — is off until something asks for it.
Today the tree ships everything and configures it off at runtime; "what does
this build actually contain" has no single answer you can read.

---

## The policy change

features.md rule 4 today says:

> **Default off for optional/vendor integrations, on for core.**

That makes "is this core?" a per-crate judgement call, re-litigated per feature,
and it is what produced the current split (`sovd-docs-hook` on, `container` off,
`vm-devices` device set on, `journald-native` off). Replace it with:

> **4. Default empty.** No crate declares a `default` feature set that turns a
> capability on — `default = []`, or no `[features]` default key at all. A
> *binary* names the capabilities it wants; libraries never decide for it.
> Deployment profiles (below) exist so that naming is one flag, not twelve.

Rules 1, 2, 3, 5, 6, 7, 8 stand unchanged — additive-only, capability-named,
owner-declares/upper-forwards, gate at module/arm level, say no clearly, comment
every feature, matrix must pass. Rule 6 ("say no clearly") gets *more* load-
bearing here: with everything off by default, a build missing a capability is
the normal case, so the error naming the feature is the primary UX.

### Why bother

- **The implicit subset is already wrong somewhere and we can't see it.** One
  tree serves the QNX rig host, QEMU dev, the emulated container, and the guest
  SDK. Each wants a different subset. There is no artifact that says which.
- **There is a live untested hole today.** `container` ON with
  `sovd-docs-hook` OFF is built by nothing (see work item 0) — and that is the
  configuration of a consumer pinned to an older `sovd-api` that ships
  containers.
- **Dead flags accumulate unnoticed.** `vm-service/qnx` gates nothing:
  `grep -rn 'feature = "qnx"' --include=*.rs` returns **0 sites**.
- **Binary size and dependency surface on a bank-constrained target.** The
  application bank is partition-exact; code that no deployment calls still
  costs image bytes.

---

## Work item 0 — close the known hole (small; do this first)

Independent of the policy change, worth landing on its own.

- [ ] `cargo install cargo-hack` documented as a dev prerequisite (README +
      `install-deps.sh` in the workspace).
- [ ] Add `scripts/feature-matrix.sh` as a CI job. features.md already flags
      this: "CI runs rustfmt only today".
- [ ] Add the missing fixed point: `component-mgr` / `vm-sovd` with `container`
      ON and `sovd-docs-hook` OFF. The four current runs cover
      (hook off, container off), (hook on, container off), (hook on, container
      on) twice — never (hook off, container on).
- [ ] Fix the stale TODO at `crates/component-mgr/src/sovd/openapi.rs:107-109`.
      It says the hook "is gated off by default; drop the gate after the SOVDd
      lock bump lands the hook" — but the bump landed (features.md records
      `sovd-api` c33a01d) and `Cargo.toml` has `default = ["sovd-docs-hook"]`.
      The comment now documents the opposite of the code.

**Combination math for context.** 13 crates own 20 features = **48** real
per-crate combinations. The powerset block in `feature-matrix.sh` covers
`app-mgr` + `component-mgr` + `component-factory` = **8** of them, and only when
`cargo-hack` is installed — otherwise it prints SKIP and covers none. The four
workspace-wide runs cannot substitute, because **Cargo unifies features across a
build graph**: once any workspace member enables `component-mgr/container`,
`component-mgr` is compiled with it on for *every* member. Testing "off"
requires per-package runs. This is the whole reason the script switches to
`--package` for the powerset.

---

## Work item 1 — flip the six existing defaults

| Crate | Current default | Who silently loses what |
|---|---|---|
| `component-mgr` | `sovd-docs-hook` | `GET /vehicle/v1/docs` stops advertising vendor paths |
| `vm-sovd` | `sovd-docs-hook` | as above, in the server binary |
| `hsm` | `suit` | IVD/SUIT manifest verification — **compile error** at call sites (loud, good) |
| `sumo-log` | `tracing` | the `tracing` → `score_log` bridge; logs go nowhere |
| `vm-devices` | `health`, `time`, `can` | the three simulated devices vanish |
| `hsm-sim-backend` | `crypto`, `suit` | `SimHsm`'s crypto surface — **compile error** (loud, good) |

**The risk that makes this a wave, not a commit.** A default flipped off does
not fail a consumer's build — it silently removes a runtime capability. And the
consumers are outside this repo, pinned `branch = "main"`, so they pick it up on
the next lock bump with a green build.

`supernova-machine-manager` (the Tier-2 host image) depends on **17** crates
from this repo — `component-mgr`, `component-factory`, `vm-service`,
`vm-devices`, `app-mgr`, `host-os-mgr`, `hsm`, `hsm-sim-backend`, `sumo-log`,
`log-rotate`, `host-metrics`, `machine-mgr`, `nv-store`, `secstore`,
`hsm-rustls`, `vhsm-proto`, plus the workspace glue — and specifies features on
**exactly one** of them (`hsm = { …, features = ["crypto", "suit"] }`).
Everything else rides defaults. `vm-devices`' three devices going quiet is
exactly the shape of failure that compiles, passes CI, and ships to the rig.

- [ ] Per crate: flip to `default = []`, then audit and update every consumer in
      the same wave — `supernova-machine-manager`, `sumo-provision`,
      `sumo-autoloader`, `guest-vm-sdk` — giving each an explicit feature list.
- [ ] Follow the workspace producer→consumer order (workspace `CLAUDE.md`
      §"Build & Artifact Order"): producers first, then `./prepare-push.sh` →
      `./push-all.sh`. `prepare-push` builds each consumer whose lock would
      move, which catches the *loud* half; the silent half needs the audit.
- [ ] For each flip, state in the commit which consumer opted back in and why.

---

## Work item 2 — the `vm` capability

Facts to build on:

- `vm-sovd` does **not** depend on `vm-service` or `vm-devices`. The two-process
  architecture (`vm-service` for QEMU/qvm lifecycle, `vm-sovd` for
  diagnostics/OTA) means the VM surface in the server is IPC, not a link-time
  dependency. So a `vm` gate is mostly about *which components get composed*,
  not about the server's own code.
- `vm-devices` already has the right shape: `health` / `time` / `can` /
  `http-transport`, currently three-on-by-default.
- `vm-service/qnx` gates nothing (0 cfg sites) — delete it, or make it real if
  the QNX/`qvm` vs QEMU split should be a compile-time choice rather than the
  runtime branch it is today.
- An emulated/container deployment has no VMs at all. `supernova-mm`'s code is
  full of "emulated/container has no activator / no raw host bank" branches —
  that is a deployment shape being handled at runtime that could be a profile.

- [ ] `vm` feature owned by `component-factory` (it decides which components
      exist), forwarding to `vm-service` + `vm-devices`; `vm1`/`vm2` bank-set
      component registration gated on it.
- [ ] Decide the granularity: one `vm` flag, or `vm-qemu` / `vm-qvm` as
      mutually-informative additive flags (rule 1 forbids a negative flag, so
      "no hypervisor" is the absence of both).
- [ ] Remove or implement `vm-service/qnx`.
- [ ] Flip `vm-devices` defaults per work item 1.

---

## Work item 3 — logging

Facts:

- `component-mgr` depends on `platform-log` **unconditionally** and calls
  `platform_log::read_slog2` / `read_segments` / `LogQuery` from `backend.rs`
  (~:7243-7374) to serve §7.21 `GET /logs`.
- `vm-sovd` depends on `sumo-log` unconditionally.
- The platform-integration set is already five separate crates: `platform-log`,
  `score-log-slog2`, `score-log-tracing`, `slog2-drainer`, `sumo-log`, plus
  `log-rotate` alongside.
- The §7.21 `logs` capability is **already runtime-gated** on
  `config.log_sources` being non-empty (`backend.rs`, the `logs:` capability
  line). So a compile gate must mirror that, not duplicate it.

The producer contract is Eclipse `score_log`, not ours — the reader half is
ours. Keep the gates on the reader/transport side and leave the producer
contract ungated.

- [ ] `logs-slog2` (QNX shmem + sealed segment reader), `logs-journald`
      (rename/absorb the existing `platform-log/journald-native`), `logs-files`
      (host file + guest-agent `/files` download), each owned by `platform-log`
      and forwarded by `component-mgr`.
- [ ] `tracing` (existing, `sumo-log`) flipped off by default per work item 1.
- [ ] Make the compile gate and the `config.log_sources` runtime gate agree:
      a configured source whose backend was not compiled in must fail at
      startup naming the feature (rule 6), not silently serve an empty log.
- [ ] Decide whether `log-rotate` and `slog2-drainer` become features of a host
      binary or stay separate crates a profile selects.

---

## Work item 4 — docs hook *and* the vendor extensions

Today only the *documentation registration* is optional; the vendor routes
themselves are unconditional. That is backwards, and it hides a correctness
trap once both become optional.

The vendor surface (docs/sovd-vs-extensions.md §2) is already grouped:

| Group | Routes |
|---|---|
| OTA state | `/data/x-ota-update-state`, `x-ota-installed-manifest` |
| HSM | `/components/hsm/data/keys`, `…/operations/x-csr/executions`, `…/x-ecu-id` |
| OTA trials | `/operations/x-ota-{commit,rollback}-trials/executions` |
| Pull-update | `/operations/x-ota-pull-update/executions` (gateway mode) |

- [ ] `ext-ota-state`, `ext-hsm`, `ext-ota-trials`, `ext-pull-update` gating the
      route merge in `component_mgr::sovd::{routes, gateway, pull_update}`.
- [ ] **`sovd-docs-hook` must not be independent of them.** The hook publishes
      the vendor OpenAPI into the §7.5 capability description; if the doc is
      generated from the full `openapi()` while only some route groups are
      compiled in, `GET /vehicle/v1/docs` advertises routes that answer 404 —
      worse than not advertising them. Either derive the doc from the enabled
      groups, or make `sovd-docs-hook` require the groups it describes.
- [ ] Keep the three-layer rule intact: SOVDd stays spec-pure, so these gates
      live entirely in this repo's vendor layer.
- [ ] The `openapi_json_pretty()` byte-equality regen test becomes
      feature-dependent — either pin it to the all-extensions build or generate
      one golden per profile.

---

## Work item 5 — the HSM simulator out of the production path

`component-mgr` depends on `hsm-sim-backend` unconditionally, and constructs
`SimHsm` in **non-test** code:

- `component_adapter.rs:377, 443, 473` — the `get_csr` / `list_keys` /
  `get_device_id` fallback when no `csr_crypto` provider is injected
- `main.rs:276`, `partition_bank_provider.rs:413, 442, 444`

So the shipped Tier-2 image links a simulator and can fall back to it for CSR
signing. This is the contract-in/impl-out convention inverted: the contract
crate (`hsm`) is correctly separate, but the *simulator* is a hard dependency of
the production component.

- [ ] `hsm-sim` feature, off by default, gating the `hsm-sim-backend` dependency
      and every fallback construction site.
- [ ] Without it, the fallback path must fail naming the feature rather than
      silently signing with a simulated key — this one is a security-relevant
      "say no clearly".
- [ ] Test targets keep it via `dev-dependencies` (no feature needed for tests).

---

## Work item 6 — verification once the powerset stops being feasible

Full powerset does not survive this change. A top binary with ~8 features is
256 clippy runs; `vm-sovd` would get there quickly. Tiered strategy:

1. **Owner/leaf crates** (`app-mgr`, `platform-log`, `nv-store`, `vm-devices`,
   `hsm`) — full `cargo hack --feature-powerset`. Few features each, and this is
   where the gated code actually lives.
2. **Mid crates** (`component-mgr`, `component-factory`) —
   `cargo hack --each-feature` plus each pair that shares a code path.
3. **Binaries** (`vm-sovd`, and the consumers) — no powerset. Build the **named
   deployment profiles**, which are the configurations that actually ship.

- [ ] Define the profiles as additive feature bundles (rule 1 permits bundles;
      it forbids negative flags): `rig-qnx`, `dev-qemu`, `emulated`,
      `guest-sdk`.
- [ ] `feature-matrix.sh` grows a profile section; the profile list is the
      contract with the deploy side.
- [ ] Wire all three tiers into CI (work item 0 lands the job).

---

## Acceptance

- [ ] No crate in this workspace declares a non-empty `default`.
- [ ] Every shipping binary names its capabilities via one profile flag.
- [ ] `feature-matrix.sh` passes all three tiers in CI, and a `git grep` for
      `feature = "` finds no cfg naming a feature no `Cargo.toml` declares
      (the `vm-service/qnx` class of rot).
- [ ] Every consumer in the workspace has an explicit feature list; none relies
      on a default.
- [ ] Each capability that can be absent fails loudly, naming its feature.
