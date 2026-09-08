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
- **A real deployment already wants a subset this tree cannot express.** A
  minimal mmgr on a Raspberry Pi 5 — no HSM silicon, no hypervisor, no banks —
  wants exactly `container` + a software HSM. `container` is enabled by **no
  consumer in the workspace** (`grep -rn 'features = \[.*"container"'
  --include=Cargo.toml` across `components/`, `host-platforms/`,
  `guest-platforms/` returns 0 hits), which invites the conclusion that the
  feature is speculative. **That conclusion is wrong** — the consumer is real,
  it is just outside this workspace, and the tree gives it no way to say what it
  wants. This is the thesis of the whole document, with a name attached; see
  "The rp5 case" below and work item 3b.
- **A combination nothing builds.** `container` ON with `sovd-docs-hook` OFF is
  covered by no run today (see work item 0), and it is the rp5 configuration —
  a headless node has no use for the vendor docs surface. The forwarding chain
  has never been compiled that way.
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

## The rp5 case — the subset the tree cannot express

A minimal machine manager on a Raspberry Pi 5: **no HSM silicon, no hypervisor,
no A/B banks.** Its whole job is container updates plus a software HSM, i.e.
`container` + `hsm`. Both of that node's components are *Singleshot* in the
`Upgradable` model (CLAUDE.md): `ContainerImageComponent` (app-mgr) and the HSM
keystore (hsm crate). It needs no banked component at all.

Transitive in-repo closure, computed from the `path` dependency edges:

| Set | Count | Crates |
|---|---|---|
| Domain logic it needs | **11** | `app-mgr`, `hsm`, `hsm-contract`, `hsm-link-b`, `hsm-sim-backend`, `machine-mgr`, `nv-store`, `vhsm-proto`, `sumo-log`, `score-log-tracing`, `score-log-slog2` |
| What `vm-sovd` links | **20** | the 11 above, `vm-sovd` itself, and the 8 below |
| Linked, unusable on rp5 | **8** | `component-mgr`, `component-factory`, `host-os-mgr`, `platform-log`, `puller`, `vhsm-client`, `vhsm-provider`, `hsm-rustls` |

The good news: **`app-mgr` does not depend on `component-mgr`** (only `nv-store`
+ `machine-mgr`), so the container component is already cleanly separable. The
`vm` gate of work item 5 would drop `vm-service` + `vm-devices` for free.

The blocker is not a feature flag:

- **`DiagnosticBackend` is implemented only in `component-mgr`** —
  `backend.rs:2680` on `ComponentBackend<D>` (the *banked VM* state machine) and
  `install_router_diag.rs:75`. The SOVD wire surface is fused to the banked
  implementation.
- **`vm-sovd` is the only SOVD server in this repo** (docs/sovd-entrypoints.md
  rows 1–2), and it depends unconditionally on `component-mgr`,
  `component-factory`, `host-os-mgr`, `hsm-rustls`, `vhsm-provider` and
  `sumo-log`. `component-factory` in turn depends unconditionally on
  `component-mgr`.
- The container SOVD route itself lives in
  `component_mgr::app_install_router`, gated by `container`.

So serving SOVD for containers + a soft HSM today means linking `host-os-mgr`'s
IFS/partition activators, `platform-log`'s QNX slog2 reader, and the guest vHSM
client/provider — none of which that node can use. **No `default = []` sweep
fixes this**; it needs the adapter separated from the banked impl (work item 3b).

`app-mgr`'s own deps are a smaller version of the same smell: `sha2`, `bytes`,
`sumo-codec` and `sumo-onboard` are used only by the container module and are
not `optional` (features.md already flags this).

---

## Work item 0 — close the known hole — **DONE 2026-09-08**

Independent of the policy change, landed on its own.

- [x] `cargo-hack` installed and added to `install-deps.sh --check` (workspace
      root, under "Rust toolchain"). It was **absent**, so the powerset block
      printed SKIP and covered **0** combinations — the script's coverage claim
      was aspirational.
- [x] **The powerset block had never worked.** `--all-targets` sat *before* the
      subcommand, so cargo-hack treated it as its own flag and built the invalid
      `cargo --all-targets clippy …`; every powerset run died on combination 1
      of N. Latent precisely because cargo-hack was never installed — the SKIP
      path masked a broken command. Moved after `clippy`; all 10 combinations
      now pass. **The instrument this document leans on was broken, and the
      thing hiding it was the missing prerequisite.**
- [x] `scripts/feature-matrix.sh` wired into CI as
      `.github/workflows/feature-matrix.yml`, split by cost: `fixed` (5
      combinations) on every push/PR, `powerset` (10 more) nightly +
      `workflow_dispatch`. The script takes `--fixed-only` for that split.
      features.md's "CI runs rustfmt only today" is now stale.
- [x] Added the missing fixed point: `vm-sovd` with `container` ON and
      `sovd-docs-hook` OFF — the fourth corner, and the rp5 configuration.
      **It compiles clean.** Never tested before; no latent breakage found.
- [x] Fixed the stale comment at `crates/component-mgr/src/sovd/openapi.rs`.
      Note what it actually said: *"drop the gate after the SOVDd lock bump
      lands the hook"* — an instruction to **delete** the gate. The bump landed,
      so a reader following that note would have removed exactly the gate work
      items 4 and 7 depend on. Replaced with why the gate stays, and a "do not
      delete it".

**Open, deliberately not blocking:** whether a GitHub runner can resolve the git
deps (SOVDd, sumo-rs) is unverified — `fmt.yml` sidesteps cargo entirely, citing
sibling PATH deps, and *that comment is stale* (every `path =` dep now resolves
inside this repo, so `cargo metadata` is fine locally). The first CI run answers
it. Also unmeasured: cold-cache wall time for the powerset job.

**Combination math for context.** 13 crates own 20 features = **48** real
per-crate combinations (verified: 2+2+4+4+2+2+2+2+2+16+2+4+4). The powerset
block covers `app-mgr` + `component-mgr` + `component-factory`. Conceptually
that is 2+4+2 = 8; cargo-hack actually runs **10** (2, 6, 2) because it
enumerates `default` as a feature in its own right, so `component-mgr`'s two
features yield six runs rather than 2². Either way the four workspace-wide runs
cannot substitute, because **Cargo unifies features across a build graph**: once
any workspace member enables `component-mgr/container`, `component-mgr` is
compiled with it on for *every* member. Testing "off" requires per-package runs.
This is the whole reason the script switches to `--package` for the powerset.

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

- [ ] Define `rig-qnx`, `dev-qemu`, `emulated`, `guest-sdk` and **`soft-node`**
      as bundles on the top crates. Each is a *name for a shipping
      configuration*, so the profile list becomes the contract with the deploy
      side.
      - `soft-node` is the rp5 case above: `container` + a software HSM, no
        hypervisor, no banks, no QNX. It is the **fifth** profile — an earlier
        draft had four and none of them describes it. `emulated` is the closest
        and is still not it: `emulated` is about supernova-mm's runtime
        "no activator / no raw host bank" branches on an otherwise full build,
        whereas `soft-node` wants those crates *absent*.
      - `soft-node` is also the profile that work item 3b unblocks; until then
        it can only be declared, not honestly built.
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

## Work item 3 — the implicit in-process HSM fallback (not "the simulator")

**Promoted from last to third**: it is the only item with a security
consequence, it is small and self-contained, and like work item 0 it does not
depend on the policy change at all.

**First, a correction of framing.** An earlier draft titled this "the HSM
simulator out of the production path". That is wrong, and the crate says so
itself — `tools/crates/hsm-sim-backend/Cargo.toml`'s own `description` reads:

> Software HSM backend (SimHsm): file keystore + RustCrypto, served over link-B
> by the `hsm-sim-service` bin. The HSM for sim/dev deployments … Provides no
> hardware key protection. Verified by `hsm-conformance`.

It is a **soft HSM**, not a test double: real RustCrypto (p256, ed25519,
aes-gcm, hkdf, hmac, cmac, x509-cert — it issues certs), a file keystore, served
**over the same link-B wire as the vendor C hardware backend**, and validated by
the same `hsm-conformance` suite. For any platform with no secure element —
rp5, dev boxes, `emulated` — it is the *correct and intended* backend, not a
degradation. Removing it from the production path would break the `soft-node`
profile.

So there are two different things, and only one is a defect:

| | What it is | Verdict |
|---|---|---|
| `hsm-sim-service` over link-B | a deliberately selected soft-HSM **deployment** | legitimate — keep, and name it honestly |
| in-process `SimHsm::new()` inside `component-mgr` | an **implicit fallback** when no `csr_crypto` is injected | the defect |

**Deployment reality, verified 2026-09-08 — the soft HSM is the production HSM.**
Not a dev convenience that leaked; the only HSM the fleet has:

- `hsm-sim-service` ships in **both** supernova packages (provisioning *and*
  full) — `assemble-package.sh:71, 89` — reaches the device in the deploy tar
  (`provisioned-cvc/prepare-device.sh:80`), and is spawned by `vhsm-ssd` via
  `--backend-cmd`, whose default is the sibling binary. **No vendor bridge
  exists yet**; `hsm.backend_cmd` is the config seam that will select one.
- The device's real private keys are **generated on the device at first boot**
  by `SimHsm::ensure_device_keys()` (`sim.rs:136+`) with
  `p256::ecdsa::SigningKey::random(OsRng)`, written as PEM under
  `/mnt/common-rw/vhsm/keys` (`managed-qnx71/config.yaml:40`, mode 700). That
  covers every device-generated role — `DeviceDecryption`, `IamSigning`,
  `IvdSigning`, `JwtSigning`, `TlsIdentity`, `Storage` (`hsm/types.rs:184-193`).

Two consequences for this work item:

1. **The out-of-process shape is already what we want.** A separate binary, an
   explicit packaging line, a config-selected `backend_cmd` — the soft HSM is
   *already* a separately stated deployment entity on the host path.
   `vhsm-ssd` completed this migration (`vhsm-ssd/src/backend.rs:1-11`: "no
   longer owns an in-process `SimHsm`; instead it spawns a backend *service*").
   `component-mgr` is the sole holdout, and its injection point already accepts
   a `LinkBClient` (`bank_provider.rs:54`). So this item **finishes** a
   migration rather than starting one.
2. **Flag-off must genuinely produce a soft-HSM-free artifact** — that is the
   whole purpose of the gate, so the claim has to be made true rather than
   qualified away. It needs gating at **two layers**, because the soft HSM
   exists at two:
   - *linked code* — `component-mgr`'s in-process `SimHsm` (the defect below).
     Already clean in `supernova`: `hsm-sim-backend` sits in
     `[dev-dependencies]` (`Cargo.toml:110`), its only use is under
     `#[cfg(test)] mod tests` (`boot_selector_signer.rs:79-81`), and production
     crypto is `Arc<hsm::link_b::LinkBClient>` (`main.rs:819, 1878`) —
     `LinkBClient` implements `HsmCryptoProvider` (`hsm/src/link_b.rs:436`).
   - *packaged binary* — `hsm-sim-service`, copied into every package
     unconditionally (`assemble-package.sh:71` **dies** if it is absent, `:89`
     copies it), installed unconditionally by CI (`.gitlab-ci.yml:208, 232`),
     and reached by `backend_cmd`'s silent sibling-binary default
     (`main.rs:1264`).

   Gate only the first and the flag becomes theatre: a supernova with no soft
   crypto compiled in still ships the soft HSM beside it and spawns it by
   default. **Layer 2 is the actual work of this item, and the line to delete
   when the vendor bridge lands.**

The defect: `component-mgr` depends on `hsm-sim-backend` unconditionally and
constructs an in-process `SimHsm` in non-test code —

- `component_adapter.rs:377, 443, 473` — the `get_csr` / `list_keys` /
  `get_device_id` fallback when no `csr_crypto` provider is injected
  (`csr_crypto` is only ever wired for `BankSet::Hsm`, and only when
  `FactoryDeps.hsm_crypto` is `Some` — `component-factory/src/lib.rs:625-627`)
- `main.rs:276` — the `vm-diagserver` CLI's factory-init `--hsm-keystore`
  bring-up

`partition_bank_provider.rs:413, 442, 444` are inside `mod tests` (line 380) and
are not part of this — an earlier draft listed them as non-test. Corrected.

**Which binary actually takes the fallback (verified 2026-09-08) — the answer is
not the same for both servers:**

| Server | `FactoryDeps.hsm_crypto` | So `get_csr` uses | Soft HSM reached |
|---|---|---|---|
| `supernova` (deployed host MM) | `Some(LinkBClient)` — `main.rs:2367`, built at `main.rs:1881` | the injected link-B handle | **out of process only**, over link-B |
| `vm-sovd` (dev / sim / the rp5 server) | **`None`** — `main.rs:445`, with `hsm_keystore: Some(..)` | `SimHsm::new(keystore)`, transient, per call | **in process, directly** |

So the earlier claim that "a build that intended hardware silently signs with a
software key" is **wrong for supernova**: it injects the link-B client, the
`if let Some(ref crypto)` arm always wins, and the fallback is unreachable in the
deployed artifact. There the defect is *build surface* — a non-optional
dependency and a code path no deployment takes — not a live crypto substitution.

In `vm-sovd` the fallback is the live and deliberately chosen path
(`main.rs:443-445`: "No crypto-only handle in the dev vm-sovd binary — keeps the
`dyn HsmProvider` path for seal / unwrap / CSR"). That is the real finding, and it
is what makes this item a prerequisite for `soft-node` rather than a tidy-up:
**deleting the fallback breaks `vm-sovd` unless `vm-sovd` starts injecting.**
It already holds a `LinkBClient` for the pre-spawned backend
(`vm-sovd/src/main.rs:180`), so the fix is small — pass it as `hsm_crypto` — and
it converges with work item (b): every server reaches the soft HSM over link-B,
as a separately stated process, and then the in-process path can be deleted
outright instead of gated.

Either way the contract-in/impl-out convention is inverted while the dependency
stands: the contract crate (`hsm`) is correctly separate, but an implementation
is a hard dependency of the production component.

- [ ] **Delete the implicit in-process fallback.** Selecting a backend becomes
      explicit; an un-injected `csr_crypto` must fail naming what is missing
      (rule 6), never substitute software crypto. This is the security-relevant
      half and it is independent of any feature flag.
- [ ] **The flag already exists in `supernova` — finish it, don't invent it.**
      `supernova`'s `hsm-sim` feature gates 5 sites, and flag-off already fails
      loudly instead of degrading: `#[cfg(not(feature = "hsm-sim"))]` on
      `HsmBackend::Sim` logs "HSM backend 'sim' not compiled in" and
      `exit(1)` (`main.rs:1869-1873`) — rule 6, already implemented. It is also
      already named explicitly in every build line
      (`.gitlab-ci.yml:193, 196, 230`, `build-qemu.sh`, `build-target.sh`), so
      it is already the visible, removable statement of deployment intent.
      **Decision (2026-09-08): keep it declared in supernova today; the point is
      that removing it later is a small, reviewable diff.** Three gaps remain:
      - [ ] It is in `default` (`default = ["hsm-sim", "ifs-dev", "vm-runtime"]`),
            so it is not yet a gate that must be turned *on*. Removing it from
            `default` should change **no shipped artifact** — every real build
            already passes `--no-default-features --features hsm-sim,…`. Verify
            that claim against all three CI build lines before flipping; if it
            holds, this is the cheapest of the six default flips in work item 4.
      - [ ] Gate layer 2 from the same decision: make the `hsm-sim-service`
            build/copy/`die` in `assemble-package.sh` and the CI `cargo install`
            conditional, and make `backend_cmd` require explicit config instead
            of silently resolving a sibling binary — so a hardware node fails
            loudly rather than quietly spawning a soft HSM.
      - [ ] Build the flag-off variant in CI (work item 0's matrix) or
            "removable later" rots into "unbuildable later".
- [ ] **Split the factory-reset dev backdoor off this flag.** `hsm-sim` also
      gates `factory_recovery_issuer_spki()` (`main.rs:579-585`, used at `:532`),
      which returns the hardcoded `hsm::payload::FACTORY_SIGNING_PUBLIC` —
      P-256 `scalar = 1` — as the factory-reset issuer anchor when the device has
      no provisioned keystore. That is a well-known-key recovery path riding the
      same switch as "which HSM backend", so any node that still needs a soft
      HSM also gets the backdoor. Two unrelated concerns, one flag: give the
      recovery path its own (`factory-recovery-anchor`), off by default.
- [ ] **Rename to match reality**: `hsm-sim-backend` → a soft-HSM name,
      `SimHsm` → `SoftHsm`. The word "sim" is what made an in-process fallback
      look acceptable, and it understates a backend that holds real keys with no
      hardware protection. Cheap now, load-bearing for how the next reader
      reasons about it.
- [ ] Prefer link-B even when the soft HSM is selected, so the boundary
      `hsm-conformance` tests is the boundary every deployment actually uses,
      and the soft/hard swap is a config change rather than a rebuild.
- [ ] Test targets keep it via `dev-dependencies` (no feature needed for tests).
      Four crates already have it that way and need nothing: `vhsm-client`,
      `vhsm-crossnode-client`, `hsm-rustls`, `vhsm-ssd`.
- [ ] **`sumo-verify` — free to fix, because it is not deployed.** An earlier
      draft of this bullet claimed its runtime dependency on `hsm-sim-backend`
      was legitimate and load-bearing in production. It is not: `sumo-verify` is
      **deliberately excluded** from both supernova packages
      (`assemble-package.sh:69` — "sumo-verify is NOT shipped") and absent from
      the device tar (`prepare-device.sh:80`). The verify-then-start orchestrator
      that invoked it was removed and "verification will move to the RT side"
      (`start-managed.sh:257-262`). It survives only in the `managed-qnx71` dev
      example. So changing it carries no deployment risk.
      What it actually needs is **not an HSM backend**: verification uses the
      *public* half only — `SimHsm::verify` → `load_ec_verifying_key` reads
      `keys/{key_id}.pub` and never opens `.priv`
      (`hsm-sim-backend/src/crypto.rs:108, 622-630`). It reaches for `SimHsm`
      purely because `ivd::verify_bank_crypto` demands
      `&dyn HsmCryptoProvider`. Give it a verify-only public-key source (or a
      `verify_bank_with`-shaped closure, which `ivd.rs:568` already exposes) and
      the dependency disappears — no feature flag needed.
- [ ] **Record why verification left the host, so it does not come back wrong.**
      A host-side launch gate that reads its trust anchor from
      `keys/ivd-signing.pub` — a PEM on the same writable partition as the banks
      it gates — is not a secure-boot gate: whoever can rewrite a bank can
      rewrite the anchor beside it and re-sign. Moving verification to the RT
      side is therefore the right call, not just a scheduling fix. If it ever
      returns host-side, the anchor must be HSM-held or in signed read-only
      storage. (Not a componentization item; it belongs to whoever owns the RT
      verify design, and this note exists so the constraint travels with it.)
- [ ] `supernova-machine-manager` declares `hsm-sim-backend` directly too
      (`Cargo.toml:110`) — decide in the same wave whether the rig runs
      `hsm-sim-service` deliberately or must inject a real `csr_crypto`. With
      the implicit fallback gone, that becomes a visible choice instead of a
      default.

---

## Work item 3b — unfuse the SOVD adapter from the banked implementation

**The largest item, and the only blocker no feature flag can lift.** Scope it
before committing to it; everything else here is additive, this one moves code.

From "The rp5 case" above: `DiagnosticBackend` exists only in `component-mgr`
(`backend.rs:2680` on the banked `ComponentBackend<D>`, and
`install_router_diag.rs:75`), and `vm-sovd` is the only SOVD server. So the
SOVD wire surface cannot be served without the banked VM stack, even for a node
whose components are all Singleshot.

- [ ] Decide the shape. Two candidates:
      - **Generic adapter** — a `DiagnosticBackend` over
        `MachineRegistry`/`dyn Component`, in `machine-mgr` or a new
        `sovd-adapter` crate, with `ComponentBackend`'s banked specifics
        behind it. Matches the `Upgradable` model: the wire should not know
        whether a component is Banked or Singleshot.
      - **Minimal second server** — a `soft-node` binary composing only the
        Singleshot components. Cheaper to reach, but forks the wire surface
        and risks the two drifting. **Superseded in part by work item 3c**,
        which picks this shape but splits by *role* rather than by feature —
        that avoids the wire-fork risk, because the gateway already serves a
        different surface (proxy + onboard pull-update) rather than a subset
        of the host one.
- [ ] Whichever shape: `component-factory`'s unconditional edge to
      `component-mgr` has to become conditional, or the factory splits.
- [ ] Work item 2's per-profile goldens are the safety net — the `rig-qnx`
      capability description must be byte-identical across this refactor.
- [ ] Only then can `soft-node` be built rather than merely declared.

---

## Work item 3c — split `vm-sovd` by role, and rename both halves

**Decision, 2026-09-08.** `vm-sovd` becomes two binaries:

1. a **reference vendor machine manager** — the worked example of how to vendor
   an MM: which components to compose, where they go, which artifacts are
   updatable;
2. an **example vehicle gateway** — which also talks to an HSM, but **as a
   client, not a controller**.

`vm-sovd` is the wrong name for both. "vm" is wrong in each case — role 1 serves
*host*-owned components (`host-os`, `vm1`, `vm2`, `hsm`), and role 2 merely
*runs* in a VM, which describes where it lives rather than what it serves. "sovd"
names the protocol, not the role, which is exactly how one name came to cover
two unrelated jobs.

- [ ] **Gateway → `vehicle-gateway`.** Not an invention: the deployment already
      uses that name in five places — `examples/t2-seed-*/services/vehicle-gateway/`,
      `channels/*/layers/vehicle-gateway/`, `/opt/vehicle-gateway`,
      `/var/sumo/vehicle-gateway-nv.bin`, the `[vehicle-gateway]` log prefix —
      and `docs/sovd-entrypoints.md` calls server #2 "the vehicle gateway". Only
      the binary is misnamed.
- [ ] **Reference MM → `example-host-mm`.** Matches the convention SOVDd already
      ships upstream (`sovdd` = reference server, `example-app` = reference
      app-entity), and reads as non-production next to
      `docs/sovd-entrypoints.md`'s #3, "the production host server".
- [ ] **This is a template, not a demo.** rp5 wants the *host-MM* role — it owns
      its own components — so `soft-node` derives from this half, not from the
      gateway. Which is why it stays a product-grade crate and does not move to
      `examples/`: a reference impl is normative, and whatever it models is what
      the next vendor copies.

### HSM as client, not controller — the seam already exists

The split the gateway needs is already carved into the trait layer, and even the
bounds encode it:

| | Trait | Crate | Shape | Who needs it |
|---|---|---|---|---|
| **client** | `HsmCryptoProvider` | `hsm-contract` | `&self`, `Send + Sync` — `sign`, `verify`, `get_public_key_der` | the gateway |
| **controller** | `HsmProvider` | `hsm` | `&mut self`, `Send` — `is_provisioned`, `provision(suit_envelope)`, `list_slots` | the host MM |

The controller takes `&mut` because it *installs keystores*; the client is
shareable and operation-only. Keystore install is a Singleshot `Upgradable` and
belongs to the host MM — a guest gateway has no business owning it.

- [ ] **Today the gateway has it exactly backwards.** The shared `FactoryDeps`
      (`vm-sovd/src/main.rs:441-446`) passes `hsm_provider: Some(..)` and
      `hsm_keystore: Some(..)` while `hsm_crypto: None` — it takes the
      controller and withholds the client. Target for the gateway half:
      `hsm_crypto: Some(gw_crypto)`, `hsm_provider: None`, `hsm_keystore: None`.
- [ ] The deployed gateway **already intends to be a client**: its command line
      is `--gateway --guest-vhsm --host-sovd-url … --proxy-component host-os`
      with **no `--hsm-keystore` and no `--backend-socket`**
      (`t2-seed-dev/…/vehicle-gateway/autostart.sh:27-32`); crypto arrives from
      `VhsmProvider` over the wire. The controller-shaped deps are inherited
      from the shared `FactoryDeps`, not asked for — the split is what stops
      them being inherited.
- [ ] Consequence to enforce, not just document: the gateway must be **unable**
      to build a `BankSet::Hsm` component. Today it could, if a config declared
      one, and it would reach the in-process `SimHsm` fallback while doing it.
- [ ] Dependency fallout for the gateway half: `hsm-contract` (+ `vhsm-provider`
      / `vhsm-client`) instead of `hsm` with `crypto`+`suit`, and no edge to
      `component-mgr`'s HSM bank component. This is the first concrete
      measurement of the rp5 closure shrinking.

Two settled details: **no `--gateway` flag** on either half — a flag that
switches role is what fused them in the first place — and the gateway **keeps
its own NV store** (a pure HSM client still owns local component state).

---

## Work item 3d — deployables leave `crates/`

**Decision, 2026-09-08.** `crates/` is for things other code *consumes*. A
server is not one of those, so `soft-node` does not get filed next to
`nv-store` and `machine-mgr`, and neither do the executables already sitting
there. Three buckets:

| Directory | Holds | Rule |
|---|---|---|
| `crates/` | consumable libraries — the SDK surface | someone `depends on` it |
| `services/` | on-device deployables | someone *runs* it on a target |
| `tools/` | host-side CLIs, build-time and dev/test tools | someone runs it on a workstation or in CI |

- [ ] **The pure executables move as-is** — `vm-sovd` (→ 3c's two halves),
      `sumo-verify`, `slog2-drainer`, `sumo-factory-reset-mint`. No lib, no
      consumers, nothing to untangle.
- [ ] **The nine mixed lib+bin crates are the actual work**: `component-mgr`
      (+`vm-diagserver`), `vhsm-ssd`, `vm-service`, `vm-boot`, `host-metrics`,
      `hsm-sim-backend` (+`hsm-sim-service`), `hsm-conformance`, `policy-build`,
      `ca-bundle-build`. Each is *both* a consumable and a deployable, which the
      rule forbids. Extract the bin into a thin crate in `services/` or `tools/`
      that depends on the lib.
- [ ] **This is not cosmetic — it makes library closures honest.** A `[[bin]]`
      shares its crate's `[dependencies]`, so a consumer taking `vm-service` or
      `component-mgr` as a *library* today also inherits everything its
      **binary** needs. That is the same class of over-linking this whole
      document is trying to measure (see "The rp5 case" — 8 linked-and-unusable
      crates). Size it per crate as the bins are extracted; do not assume the
      win is uniform.
- [ ] **Existing miscategorisation to fix in the same pass**: `hsm-sim-service`
      is a *deployed production service* — it ships in both supernova packages
      (`assemble-package.sh:71, 89`) and lands on the device — but lives under
      `tools/crates/hsm-sim-backend`. Same category error, opposite direction.

**Three cases that looked ambiguous and are not (checked 2026-09-08).**
`vm-boot`, `host-metrics` and `hsm-sim-service` all read as hard calls until you
stop treating each crate as one thing. Every one of them is lib-primary with a
thin bin, so the rule above already decides them: the lib stays in `crates/`,
the bin moves. No new judgement needed. What the check *did* surface is that
each has a different reason, and two of those reasons are findings in their own
right:

- **`host-metrics` — the clean case, and the model for the others.** supernova
  takes the lib as a plain `[dependencies]` entry (`Cargo.toml:65`) and embeds
  it; the bin is documented as "For dev / standalone deployments. In production,
  the host machine manager embeds the same library" and is in **neither**
  supernova package. Real consumer for the lib, dev convenience for the bin, and
  a 5-dep closure (axum, tokio, tracing, sumo-log, libc) that already honours
  its own header: "Lives at the workspace root so any host … can embed it
  without dragging vm-\* dependencies." Lib stays, bin → `tools/`.
- **`hsm-sim-service` — the split is the whole point.** supernova has
  `hsm-sim-backend` in **`[dev-dependencies]`** (`Cargo.toml:110`) yet
  **packages its bin** (`assemble-package.sh:71, 89`). Both are right: the
  `SimHsm` library genuinely is dev-only *to supernova*, and the binary
  genuinely is production. One crate cannot be in two dependency sections, so
  today the packaging line silently contradicts the manifest. Extracting the bin
  is what makes the manifest tell the truth — `services/hsm-sim-service`
  depending on `crates/hsm-sim-backend`, which supernova then keeps as a
  dev-dependency without also shipping it. Note also the naming: `SimHsm` in
  `hsm-sim-backend` *is* the soft HSM; `hsm-sim-service` is only its ~241-line
  link-B process wrapper (`hsm::link_b::serve`, crypto **and** provisioning).
  Work item 3's rename has to keep those two levels distinct.
- **`vm-boot` — has zero consumers, and its real-world counterpart is a shell
  script.** Nothing in this repo or any sibling depends on the `vm-boot` lib and
  nothing invokes the bin; the only workspace-wide hits are its own
  `Cargo.toml`. It is a decision function, not a service — it reads the boot
  selection (signed `SelectorBlob` PRIMARY when a `SelectorStore` is attached,
  else NV `NvBootState`), counts trial boots, auto-rolls-back past
  `MAX_TRIAL_BOOTS`, verifies SHA-256 image hashes from FW Meta, and returns one
  `BootAction` per bank set **for the caller to execute**. On the device that
  decision is actually taken by
  `host-platforms/provisioned-cvc/config/host-boot.sh` ("Interim host bootloader
  stand-in — A/B selection for the supernova OS bank"), reading the same signed
  selector. So `vm-boot` is the Rust reference implementation of a contract
  currently implemented in bash. Move the bin to `tools/` with the others, but
  the open question is about the **lib**, and it is not a layout question:
  either it is declared SDK surface — the executable spec of the selector
  contract that a real bootloader or vendor MM is expected to embed, in which
  case `host-boot.sh` is the thing that should eventually call it — or it is
  unconsumed code drifting out of sync with the script that does the job. Decide
  that on its merits; do not let the directory move imply an answer.

**Feasibility, measured 2026-09-08 — this is cheap:**

- **External consumers are unaffected.** `supernova-machine-manager` (16 deps),
  `sumo-provision` and `guest-vm-sdk` all depend by
  `git = "…sumo-machine-manager.git"` + *package name*. Cargo resolves those by
  name against the repo's workspace, not by directory, so moving a crate is
  invisible to them — no lock churn, no coordinated bump.
- **No scripts or CI reference crate directories.** Every build line addresses
  packages by name (`cargo install … vhsm-ssd hsm-sim-backend slog2-drainer`,
  `cargo build -p vm-sovd`). The only path-addressed list is the root
  `Cargo.toml` `members`.
- Churn is therefore confined to `members` plus the ~80 in-repo
  `path = "../x"` dep lines, which are mechanical.
- [ ] Do it as its own commit wave, separate from any behaviour change, so the
      diff is reviewable as a pure move.

**Payoff for work item 1:** profiles map one-to-one onto deployables, so
`services/` becomes the legible list of what the five profiles actually build.

---

## Work item 3e — the link-B service is already generic; finish the last 30 lines

*Asked 2026-09-08: "do we not have a generic link-B service to the soft HSM or
any other compliant HSM?" Answer: yes, in three layers — and `hsm-sim-service`
is not a sim-specific service, it is a sim-specific `main()` around a generic
one.*

What is **already** generic, and needs nothing:

| Layer | Where | Backend-agnostic? |
|---|---|---|
| Wire contract | `crates/hsm-link-b` (zero deps) + `include/hsm_link_b.h` + `reference/hse_service_skeleton.c` — "a complete, compilable C skeleton of the full Link-B surface", the vendor handoff | yes — "the vendor implements **Link B and nothing else**" |
| Dispatch loop | `hsm::link_b::serve<B> where B: HsmCryptoProvider + HsmProvider` (`link_b.rs:880`); `serve_crypto(&dyn HsmCryptoProvider)` (`:784`) | yes — neither mentions `SimHsm` |
| Backend selection | `vhsm-ssd --backend-cmd`, default = sibling binary (`backend.rs:23`), spawned via `link_b::spawn_and_connect` (`:706`) | yes — selects by *which process runs*, not by compiled-in code |

- [ ] **Extract the accept loop into `hsm::link_b`** — `serve_listener(listener,
      backend)` (or a `link_b::Service`) owning stale-socket removal, `bind`,
      accept, and thread-per-connection. This is the only part that is *not*
      already generic, and it is **already duplicated**: hand-rolled
      `UnixListener::bind` + accept loops at `link_b.rs:1103`,
      `hsm-sim-service.rs:125` and `:186`, `link_b_provisioning.rs:73` and
      `:184` — five sites, four of them the same loop rewritten because no
      helper exists. After the extraction, `hsm-sim-service` is ~30 lines: parse
      `--keystore`, `SimHsm::new`, `ensure_device_keys()`, hand it to
      `serve_listener`. Those three lines are the *entire* sim-specific surface
      of the binary today.
- [ ] **Do NOT build a generic service binary** with a `--backend {sim,pkcs11,…}`
      selector. Two reasons, and the second is decisive:
      1. *The vendor case is C.* A vendor implements `hsm_link_b.h` in their own
         process and never links a Rust host, so a generic Rust binary would
         serve only future **Rust** backends — of which there are zero. The only
         non-test `impl HsmCryptoProvider` in the workspace besides
         `LinkBClient` (the client half) is `SimHsm`
         (`hsm-sim-backend/src/crypto.rs:69`).
      2. *It would undo work item 3.* A binary that can **become** the soft HSM
         at runtime cannot be excluded from the image at build time — the same
         defect as the in-process `SimHsm` fallback, promoted one level. One
         thin binary per backend makes "don't ship the soft HSM" mean "don't
         ship this file", checkable by `ls` on the package. This is exactly why
         work item 3's layer 2 is a **packaging line** and not a `cfg`.
- [ ] **Consequence for the rename**: the generic/specific boundary is the thing
      the names must express. `hsm::link_b` = the service; `SimHsm` = one
      backend; the binary = that backend's `main()`. "sim" is the wrong word at
      every level for something that ships in both supernova packages today.

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
- [ ] **No implicit backend substitution anywhere.** In particular no in-process
      HSM fallback: an un-injected `csr_crypto` fails naming what is missing,
      and a soft HSM is only ever reached because a profile selected it.
- [ ] **`soft-node` builds and serves SOVD** without linking `host-os-mgr`,
      `platform-log`'s slog2 reader, or the guest vHSM crates. This is the
      acceptance test for work item 3b, and the one that proves the whole
      exercise was worth doing — it is a deployment that exists today and that
      the tree currently cannot express.
