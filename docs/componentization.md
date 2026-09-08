# Full componentization — nothing on by default (FUTURE TASK)

**Status: proposal, not started.** Extends [features.md](features.md) and
**replaces its rule 4**. Sequenced by risk-retired-per-unit-work: items 0–2 are
independently landable and build the instruments the later waves need.

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
> Deployment profiles (work item 1) exist so that naming is one flag, not twelve.

Rules 1, 2, 3, 5, 6, 7, 8 stand unchanged — additive-only, capability-named,
owner-declares/upper-forwards, gate at module/arm level, say no clearly, comment
every feature, matrix must pass. Rule 6 ("say no clearly") gets *more* load-
bearing here: with everything off by default, a build missing a capability is
the normal case, so the error naming the feature is the primary UX.

### Why bother

- **The implicit subset is already wrong somewhere and we can't see it.** One
  tree serves the QNX rig host, QEMU dev, the emulated container, and the guest
  SDK. Each wants a different subset. There is no artifact that says which.
- **Features exist that nothing owns.** `container` is enabled by **no consumer
  in the workspace** — `grep -rn 'features = \[.*"container"' --include=Cargo.toml`
  across `components/`, `host-platforms/`, `guest-platforms/` returns 0 hits. It
  is built only by `feature-matrix.sh`'s fourth run. A feature with no declared
  consumer is exactly what a profile list would make visible.
- **A combination nothing builds.** `container` ON with `sovd-docs-hook` OFF is
  covered by no run today (see work item 0). No consumer is in that
  configuration *yet* — but nothing stops one, and the forwarding chain has
  never been compiled that way.
- **Dead flags accumulate unnoticed.** `vm-service/qnx` gates nothing:
  `git grep -n 'feature = "qnx"' -- '*.rs'` returns **0 sites**.
- **Binary size and dependency surface on a bank-constrained target.** The
  application bank is partition-exact; code that no deployment calls still
  costs image bytes.

---

## The consumer model (get this right before flipping anything)

Every later item depends on knowing who consumes what. Verified against the
workspace tree, not from memory:

| Consumer | smm crates | Owns one of the six defaults? | Lock |
|---|---|---|---|
| `supernova-machine-manager` | 17 | **5** — `component-mgr`, `vm-devices`, `hsm`, `hsm-sim-backend`, `sumo-log` | tracked |
| `sumo-provision` | 2 — `hsm`, `vhsm-proto` | 1 — `hsm`, already `default-features = false` | tracked |
| `guest-vm-sdk` | 5 — `vm-wire`, `vhsm-proto`, `hsm-contract`, `vhsm-client`, `vhsm-provider` | **0** | **untracked** |

`sumo-autoloader` is **not** a consumer of this repo — its lock carries SOVDd
and sumo-rs only. (An earlier draft of this document listed it; it never
depended on sumo-machine-manager.)

Two consequences that shrink the work dramatically:

- **The blast radius of the default flips is one repo**,
  `supernova-machine-manager`. `guest-vm-sdk` touches none of the six
  default-owning crates, and already names `guest-auth` explicitly on
  `vhsm-client` in `vhsm-daemon-qnx` and `vhsm-daemon-linux` — it is already a
  good citizen under the new rule.
- **`hsm` is free.** `supernova-machine-manager` already writes
  `features = ["crypto", "suit"]` and `sumo-provision` already writes
  `default-features = false`. Flipping `hsm`'s default to `[]` changes nothing
  for either. It is the zero-risk first flip.

**The untracked-lock asymmetry** (matters from work item 5 on): the two
tracked-lock consumers pick a change up through a reviewable lock bump via the
workspace's `scripts/bump-submodules.sh`, so a flip is visible in a diff.
`guest-vm-sdk` does not track its `Cargo.lock` — it resolves `branch = "main"`
fresh at build time, so a capability change there lands with **no diff
anywhere**. It has zero exposure to the six, but any later item that gates a
contract crate (`vhsm-client`, `vhsm-provider`, `vm-wire`) hits this.

---

## Work item 0 — close the known hole (small; do this first)

Independent of the policy change, worth landing on its own.

- [ ] `cargo install cargo-hack` documented as a dev prerequisite (README +
      `install-deps.sh` in the workspace). **Not installed today**, so the
      powerset block in `feature-matrix.sh` prints SKIP and covers **0**
      combinations — the script's coverage claim is currently aspirational.
- [ ] Add `scripts/feature-matrix.sh` as a CI job. features.md already flags
      this: "CI runs rustfmt only today". Everything below hangs off this job
      existing.
- [ ] Add the missing fixed point: `component-mgr` / `vm-sovd` with `container`
      ON and `sovd-docs-hook` OFF. The four current runs cover
      (hook off, container off), (hook on, container off), (hook on, container
      on) twice — never (hook off, container on).
- [ ] Fix the stale TODO at `crates/component-mgr/src/sovd/openapi.rs:107-109`.
      It says the hook "is gated off by default; drop the gate after the SOVDd
      lock bump lands the hook" — but the bump landed and `Cargo.toml` has
      `default = ["sovd-docs-hook"]`. The comment documents the opposite of the
      code. Still present as of 2026-09-08.

**Combination math for context.** 13 crates own 20 features = **48** real
per-crate combinations (verified: 2+2+4+4+2+2+2+2+2+16+2+4+4). The powerset
block in `feature-matrix.sh` covers `app-mgr` (2) + `component-mgr` (4) +
`component-factory` (2) = **8** of them, and only once `cargo-hack` is
installed. The four workspace-wide runs cannot substitute, because **Cargo
unifies features across a build graph**: once any workspace member enables
`component-mgr/container`, `component-mgr` is compiled with it on for *every*
member. Testing "off" requires per-package runs. This is the whole reason the
script switches to `--package` for the powerset.

---

## Work item 1 — define the deployment profiles (before any flip)

**This moved to the front.** An earlier draft defined the profiles last, after
telling every consumer to write an explicit feature list — which migrates
`supernova-machine-manager` twice, once to a hand-written list and again onto a
profile. Profiles are pure additive feature bundles: no code changes, no
behaviour change, just `[features]` entries. Land them first and every later
flip moves a consumer onto a profile in one edit.

Rule 1 permits bundles (they are additive); it forbids negative flags, so "no
hypervisor" is the absence of `vm-*`, not a `no-vm`.

- [ ] Define `rig-qnx`, `dev-qemu`, `emulated`, `guest-sdk` as bundles on the
      top crates. Each is a *name for a shipping configuration*, so the profile
      list becomes the contract with the deploy side.
- [ ] Seed each bundle with today's effective feature set, so adopting a profile
      is provably a no-op before any default moves. This is what makes the
      flips reviewable: profile adoption and capability change never land in the
      same commit.
- [ ] `feature-matrix.sh` grows a profile section building each one.
- [ ] Record which repo/binary claims each profile —
      `supernova-machine-manager` is `rig-qnx`, `guest-vm-sdk` is `guest-sdk`.
      A profile no binary claims is dead weight; a binary with no profile is the
      gap this whole document is about.

---

## Work item 2 — the golden capability guard (the instrument the flips need)

The risk that makes the flips a wave is *silent* capability loss: a default
turned off does not fail a consumer's build, it removes a runtime capability,
and the consumers are outside this repo on `branch = "main"` with green builds.
An earlier draft proposed a human audit for this. Make it a diff instead.

This repo already owns the right instrument — `openapi_json_pretty()` and its
byte-equality regen test. Generalize it:

- [ ] Per profile, snapshot a golden of **the §7.5 capability description plus
      the route table** — the machine-readable answer to "what does this build
      expose". Commit one golden per profile from work item 1.
- [ ] Wire the goldens into the CI job from work item 0. Every subsequent flip
      then shows its capability delta as a reviewable diff, and a flip intended
      to be a no-op is *proved* to be one.
- [ ] Cover the three capabilities that the flips can silently drop, since a
      capability description alone may not witness them: the `vm-devices`
      device set, and the `sumo-log` → `score_log` bridge actually emitting.
- [ ] Note the ordering trap: the golden must be generated per profile, not once
      for `--all-features`, or it cannot witness a difference between profiles.
      This is the same constraint work item 7 hits from the other direction.

---

## Work item 3 — the HSM simulator out of the production path

**Promoted from last to third**: it is the only item with a security
consequence, it is small and self-contained, and like work item 0 it does not
depend on the policy change at all.

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
- [ ] `supernova-machine-manager` declares `hsm-sim-backend` directly too
      (`Cargo.toml:110`) — decide in the same wave whether `rig-qnx` carries
      `hsm-sim` at all, or whether the rig must inject a real `csr_crypto`.
      That decision is the point of the item.

---

## Work item 4 — flip the six defaults

Ordered free → loud → silent, so the mechanism is proven before it can hurt.

| Order | Crate | Current default | Consequence for `supernova-machine-manager` |
|---|---|---|---|
| 1 | `hsm` | `suit` | **none** — already names `["crypto", "suit"]`. Free. |
| 2 | `hsm-sim-backend` | `crypto`, `suit` | **compile error** at call sites — loud, good |
| 3 | `component-mgr` | `sovd-docs-hook` | *silent*: `GET /vehicle/v1/docs` stops advertising vendor paths |
| 4 | `vm-sovd` | `sovd-docs-hook` | not a dependency — this repo's own binary |
| 5 | `vm-devices` | `health`, `time`, `can` | *silent*: the three simulated devices vanish |
| 6 | `sumo-log` | `tracing` | *silent*: the `tracing` → `score_log` bridge; logs go nowhere |

Three genuinely silent flips, in one consumer. Work item 2's goldens are what
turn each of those three from a judgement call into a diff — do not start this
item before that one lands.

- [ ] Per crate, in the order above: flip to `default = []`, then move
      `supernova-machine-manager` onto its `rig-qnx` profile in the same wave.
- [ ] Follow the workspace producer→consumer order (workspace `CLAUDE.md`
      §"Build & Artifact Order"): producers first, then `./prepare-push.sh` →
      `./push-all.sh`. `prepare-push` builds each consumer whose lock would
      move, which catches the *loud* half (flip 2); work item 2's goldens catch
      the silent half (flips 3, 5, 6).
- [ ] For each flip, state in the commit which consumer opted back in and why,
      and paste the golden diff (empty diff = proved no-op).

---

## Work item 5 — the `vm` capability

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
  that is a deployment shape being handled at runtime that could be a profile,
  and `emulated` from work item 1 is where it belongs.

- [ ] `vm` feature owned by `component-factory` (it decides which components
      exist), forwarding to `vm-service` + `vm-devices`; `vm1`/`vm2` bank-set
      component registration gated on it.
- [ ] Decide the granularity: one `vm` flag, or `vm-qemu` / `vm-qvm` as
      mutually-informative additive flags (rule 1 forbids a negative flag, so
      "no hypervisor" is the absence of both).
- [ ] Remove or implement `vm-service/qnx`.
- [ ] First item to touch a contract crate consumed by `guest-vm-sdk`
      (`vm-wire`) — mind the untracked-lock asymmetry above.

---

## Work item 6 — logging

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
- [ ] `tracing` (existing, `sumo-log`) is flip 6 of work item 4.
- [ ] Make the compile gate and the `config.log_sources` runtime gate agree:
      a configured source whose backend was not compiled in must fail at
      startup naming the feature (rule 6), not silently serve an empty log.
- [ ] Decide whether `log-rotate` and `slog2-drainer` become features of a host
      binary or stay separate crates a profile selects.

---

## Work item 7 — docs hook *and* the vendor extensions

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
      feature-dependent — work item 2 already made it one golden per profile,
      so this item extends that set rather than inventing a scheme.

---

## Work item 8 — verification once the powerset stops being feasible

Full powerset does not survive this change. A top binary with ~8 features is
256 clippy runs; `vm-sovd` would get there quickly. Tiered strategy:

1. **Owner/leaf crates** (`app-mgr`, `platform-log`, `nv-store`, `vm-devices`,
   `hsm`) — full `cargo hack --feature-powerset`. Few features each, and this is
   where the gated code actually lives.
2. **Mid crates** (`component-mgr`, `component-factory`) —
   `cargo hack --each-feature` plus each pair that shares a code path.
3. **Binaries** (`vm-sovd`, and the consumers) — no powerset. Build the named
   deployment profiles from work item 1, which are the configurations that
   actually ship.

- [ ] Wire all three tiers into the CI job from work item 0.
- [ ] Keep the profile section (work item 1) as the tier-3 definition — no
      second list to drift.

---

## Acceptance

- [ ] No crate in this workspace declares a non-empty `default`.
- [ ] Every shipping binary names its capabilities via one profile flag, and
      every profile is claimed by a binary.
- [ ] `feature-matrix.sh` passes all three tiers in CI, and a `git grep` for
      `feature = "` finds no cfg naming a feature no `Cargo.toml` declares
      (the `vm-service/qnx` class of rot).
- [ ] Every consumer has an explicit feature list or profile; none relies on a
      default. Consumers are `supernova-machine-manager`, `sumo-provision`,
      `guest-vm-sdk` — and that list is checked, not assumed.
- [ ] Each capability that can be absent fails loudly, naming its feature.
- [ ] A golden capability description exists per profile, and CI diffs it.
