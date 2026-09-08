# Cargo feature policy (PROPOSAL)

**Status: proposal, for the upstream discussion.** Nothing here is enforced by
tooling yet beyond `scripts/feature-matrix.sh`. The workspace already follows
most of it by convention; this writes the convention down so the next feature
doesn't have to guess.

## Rules

1. **Additive only.** A feature turns code *on*. No `no-container`,
   `disable-x`, or any flag whose absence enables something — Cargo unifies
   features across a build graph, so a negative feature silently disables code
   for every other consumer in the same build.
2. **Capability-named, kebab-case.** `container`, `guest-auth`,
   `journald-native`, `test-seams` — name the capability, not the vendor or the
   implementation.
3. **The owner crate declares it; upper crates forward by name.** The feature
   lives on the crate that owns the gated code and every crate above forwards
   it under the *same* name: `vm-sovd/container = ["component-factory/container"]`
   → `component-factory/container = ["component-mgr/container", "app-mgr/container"]`
   → `component-mgr/container = ["app-mgr/container"]` → app-mgr owns the code.
   Same shape as the existing `sovd-docs-hook` and `test-seams` chains.
4. **Default off for optional/vendor integrations, on for core.** On by default
   when every build wants it (`sovd-docs-hook`, `hsm/suit`, `sumo-log/tracing`,
   the `vm-devices` device set). Off by default when it needs something the
   target may not have — a container runtime, libsystemd, a test seam.
5. **Gate at module/arm level, never with stub types.** `#[cfg(feature = …)]`
   on the module, the enum variant, the match arm, the struct field, the `pub
   use`. Don't compile a fake implementation to keep a name alive; gate the call
   sites instead. A test target that only makes sense with a feature uses
   `required-features` (as `hsm-sim-service` already does) or `#[cfg(feature)]`.
6. **Say no clearly.** When a request needs a feature this build lacks, fail
   with a message that names the feature ("… require this build to enable the
   `container` feature"). Never fall through to a different code path.
7. **Every feature carries a comment in its Cargo.toml** saying what it enables,
   what it costs (dependencies), and why it is on or off by default.
8. **`scripts/feature-matrix.sh` must pass** — no-default-features, default and
   all-features, each as `clippy -D warnings`.

## Current features

| Crate | Feature | Default | Gates |
|---|---|---|---|
| `app-mgr` | `container` | off | `docker_image::ContainerImageComponent` — detached `#container-image` payload validation + import into Docker / Podman / containerd |
| `component-mgr` | `container` | off | forwards `app-mgr/container`; the container-image route in `app_install_router` |
| `component-mgr` | `sovd-docs-hook` | **on** | vendor OpenAPI paths/schemas into SOVDd's §7.5 capability description |
| `component-factory` | `container` | off | forwards `component-mgr/container` + `app-mgr/container` (nothing in the factory itself is gated) |
| `vm-sovd` | `container` | off | forwards `component-factory/container` |
| `vm-sovd` | `sovd-docs-hook` | **on** | forwards `component-mgr/sovd-docs-hook` |
| `hsm` | `suit` | **on** | `dep:sumo-onboard` — IVD/SUIT manifest verification |
| `hsm` | `crypto` | off | `dep:p256`, `dep:ecdsa`, `dep:sha2`, `dep:rand` — the `HsmCryptoProvider` surface |
| `hsm-sim-backend` | `crypto`, `suit` | **on** | the RustCrypto `SimHsm` and its SUIT verification deps |
| `nv-store` | `test-seams` | off | in-memory selector store + test signer |
| `machine-mgr` | `test-seams` | off | forwards `nv-store/test-seams` through this crate's re-exports |
| `vhsm-client` | `guest-auth` | off | `dep:p256`, `dep:sha2`, `dep:rand` — the guest-side CWT handshake |
| `vm-devices` | `health`, `time`, `can` | **on** | the three simulated devices |
| `vm-devices` | `http-transport` | off | `dep:axum`, `dep:tokio`, `dep:hyper`, `dep:serde` — HTTP device transport |
| `platform-log` | `journald-native` | off | `sd_journal` FFI reader (hard-links libsystemd); off so cross-build sysroots use the `journalctl` fallback |
| `sumo-log` | `tracing` | **on** | `tracing` → `score_log` bridge |
| `vm-service` | `qnx` | off | **nothing — vestigial** (see below) |

## Open items

- **A follow-up proposal would replace rule 4 outright**: see
  [componentization.md](componentization.md) — every feature off by default
  (VMs, logging, the vendor extensions, the docs hook, the HSM simulator), with
  named deployment profiles instead of per-crate "is this core?" judgements.
  The table above is its starting inventory.

- **`vm-service/qnx` is vestigial**: no `#[cfg(feature = "qnx")]` exists
  anywhere in the workspace, so the flag gates nothing. Candidate for removal —
  deliberately left in place here so the container work stays a single concern.
- **`app-mgr` deps could follow the feature**: `sha2`, `bytes`, `sumo-codec`
  and `sumo-onboard` are used only by the container module, so they could
  become `optional = true` with `container = ["dep:sha2", …]` and drop two git
  dependencies from a default build.
- CI runs rustfmt **and** `scripts/feature-matrix.sh` (.github/workflows/feature-matrix.yml,
  since 2026-09-08): fixed combinations every push/PR, the cargo-hack powerset
  nightly. `cargo-hack` is a dev prerequisite — `install-deps.sh --check` reports it.
