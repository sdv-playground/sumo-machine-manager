# The reusable-component convention

> Written 2026-09-23, alongside the extraction of `crates/machine-contract`
> (v0.1.3). The rule below had been cited in review for months without ever
> being written down in this repo — which is exactly how `ImageRecord` landed
> on the wrong side of it (see *Audit history*). This document is the citable
> version, and the checklist at the end is the part to actually use.

## Why now — the split forces the question

The deferral was explicit: *extract the traits IF and WHEN an out-of-tree
implementer appears.* Planning the split of the vendor's host machine manager
into per-board managers (`mmgr-cvc` / `mmgr-cm5` / `mmgr-ddu`) fired it. After that split
**every** implementer of a bank trait is out-of-tree, and there is no longer a
single place to add one — each board would grow its own shape of "the same"
trait, and the first cross-board campaign would discover three incompatible
activators. So the boundary had to be frozen *before* the split, not after it.

The second reason is the dependency edge. A trait defined in `machine-mgr` drags
`sovd-core` (a git dependency on SOVDd), `async-trait`, `futures`, `bytes` and
the whole `Component` surface into anyone who only wants to write a bank
activator for one board. That is the fat-contract anti-pattern: the cost of
implementing a five-method synchronous trait becomes a git dependency on a
diagnostics server.

## The convention

1. **A contract crate is thin, synchronous and dep-light.** Path dependencies
   only, at the level of `nv-store` or below; `serde` only where a type is
   genuinely a wire value. No async runtime, no HTTP, no diagnostics types.
   The whole crate should be auditable as one unit in one sitting.
2. **Implementations live with the platform.** The contract crate holds traits,
   their error types and the small value types they name — never an impl that
   a board could reasonably want to replace.
3. **The shared crate re-exports the contract.** `machine-mgr` re-exports every
   contract name, flat and through the original module paths, so no consumer
   changes an import line when a trait moves. Import-path stability is what
   makes the extraction cheap enough to do at the right moment.
4. **A trait an out-of-tree implementer will implement goes into the contract
   crate on day one.** Not "when someone asks" — by then the shape is already
   set by whatever was convenient in-tree.
5. **Audit trigger.** Re-read this list whenever a new out-of-tree implementer
   appears or a repo is split. Those are the two events that turn an internal
   trait into a published contract, whether or not anyone notices.

Rule 1 is guarded, not just asserted: `scripts/feature-matrix.sh` runs a
`cargo tree` check on `machine-contract` and fails if its dependency set grows
beyond `nv-store` + `serde`. A convention nobody enforces is the state this
document is a reaction to.

## What is in `machine-contract` — and what is not

Four synchronous traits plus the value types they name:

| Name | Also | What it is |
|---|---|---|
| `BankProvider` | `BankError`, `FirmwareIdentity`, `InstalledFile`, `InstalledFirmware` | Every bank touch: stage, seal, read-back, activate, commit, rollback |
| `BankActivator` | `BankActivatorError` | The platform-specific "make this staged dir active" step |
| `Deactivator` | `DeactivateError`, `DeactivateOutcome` | Admin-state disable for components that support it |
| `ImageRecord` | — | The per-bank installed-image record |
| `ResetKind` | — | What kind of reset makes the activated bank actually run |

It depends on `nv-store` (for `Bank` / `BankSet`) and `serde` — nothing else.
`machine-mgr` depends on it and re-exports every name above, both flat
(`machine_mgr::BankProvider`) and through the existing module paths
(`machine_mgr::bank_provider`, `::bank_activator`, `::deactivator`,
`::image_record`). No consumer changes an import.

**The `ResetKind` decision.** `ResetKind` is defined *in the contract crate*,
with a snake_case wire encoding (`"none"` / `"local"` / `"requires_ecu_reset"`)
pinned by a test there. `machine-mgr` converts exhaustively to and from
`sovd_core::ResetKind` at the SOVD edge — no wildcard match arms, so a new
variant on either side is a compile error rather than a silently dropped case.
The conversions are free functions in `machine-mgr` (`reset_kind_to_sovd` /
`reset_kind_from_sovd`), not `From` impls: both enums are foreign to
`machine-mgr`, so the orphan rule refuses `From` there (E0117), and the only
crate where `From` would be legal is the contract crate itself — which must not
know SOVDd.

The alternative was to keep the canonical definition in `sovd-core` and accept
that dependency in the contract. It was rejected: it means every out-of-tree
implementer of `BankActivator` takes a git dependency on SOVDd in order to
*name a reset kind*. The duplicate enum plus an exhaustive conversion is the
cheaper of the two, and the conversion is the place the divergence surfaces.

**What deliberately stays in `machine-mgr`:**

- `Component` — async, 23 methods, and it speaks `sovd-core` types
  throughout. `async_trait` is only a desugaring and would not be a reason on
  its own; the `sovd-core` edge is exactly the coupling rule 1 forbids, and no
  consumer has asked for the trait. It stays until one does.
- `Machine` / `MachineRegistry`, `system_bank_state`, `node_update`, `types` —
  composition and node-level state, not an implementer's surface.

`SelectorStore` / `Signer` / `SelectorBlob` are not an instance of this at all:
they were pushed *down* into `nv-store` (`crates/nv-store/src/selector.rs`)
earlier, so a low crate like `vm-boot` could read the selector without
depending up. Same instinct, different direction.

## `Capabilities` is a declaration, not a proof

`Capabilities { did_store, flash: Option<FlashCaps>, lifecycle, hsm, dtcs,
clear_dtcs }` (`crates/machine-mgr/src/types.rs`) is what a component *says*
about itself. Keeping it true is the implementer's responsibility — say so out
loud to anyone writing a board manager.

Today it is honest by construction wherever it is derived:
`component-mgr`'s `component_adapter.rs` calls `derive_capabilities()` on a
`ComponentBackend`, which always holds a `BankProvider`. `app-mgr`'s
`AppComponent` and `ContainerImageComponent` declare `flash` and self-manage
their NV banks with no `BankProvider` at all — by design, not by oversight.

There is deliberately **no** generic runtime check of the form "declares
`flash` ⇒ has a `BankProvider` linked". `Component` exposes no provider
accessor to check against, and the app-mgr shape would legitimately fail such a
check. The real guard belongs on the platform side instead: **a config that
names a capability the binary was not built with must fail at startup.** That
lands with the RT feature gating below, at `mmgr-cvc` creation.

Not covered by the model today: there is no `VmCaps` and no RT capability. VM
and RT are gated by cargo features (`vm-runtime = ["dep:vm-mgr"]` in the host machine manager)
rather than declared in `Capabilities` — which is a wire type, so adding
entries to it is a wire change.

## Deferred work (recorded, not scheduled)

- **RT out of Tier-1, as its own crate.** `mmgr-rt` depending on
  `machine-contract`, behind `rt-runtime = ["dep:mmgr-rt"]`, not in `default`.
  Tier-1 then builds as `--no-default-features --features hsm-sim,ifs-partition`,
  and the acceptance check is that no `m7loader` symbol appears in the Tier-1
  binary. This is also where the startup capability/feature check above lands.
- **The `Banked` / `Singleshot` compile-time trait split.** Not deferred —
  dropped (ARCHITECTURE.md: "it would type one outlier and not enforce the
  real invariant"; the real invariant is the never-mix-rollbackable-with-
  irreversible rule, which belongs in the campaign layer). Recorded here only
  so nobody re-opens it as a reason to hold the contract open: both shapes use
  the same four traits.
- **Moving `Component`** — see above; revisit when an out-of-tree implementer
  actually wants it, which is the same trigger that produced this crate.
- **`no_std`.** `BankError` has a `From<std::io::Error>` impl and the traits are
  I/O-shaped; std-for-now is a deliberate choice, not an oversight.
- **`Capabilities` gaining VM/RT entries.** It is a wire type; adding to it is a
  wire change and needs the consumers lined up first.

## Audit history

- **2026-09-23 (v0.1.3)** — the four traits + `ResetKind` extracted into
  `crates/machine-contract`; `machine-mgr` re-exports them; the `cargo tree`
  guard added to `scripts/feature-matrix.sh`. Trigger: the per-board split of
  the vendor's host machine manager.
- **2026-09-23 (v0.1.1)** — `ImageRecord` was added straight into `machine-mgr`,
  *after* this convention had already been discussed in review. Nothing
  enforced it, so nothing caught it. That is the argument for both the written
  rule and the CI guard.

## Checklist: adding a trait to the contract

1. **Will anyone outside this repo implement it?** If yes, it belongs in
   `machine-contract` from the first commit. If genuinely no, say why in the
   trait's doc comment — that sentence is what a later audit reads.
2. **Is it synchronous?** An async trait in the contract means the implementer
   inherits a runtime choice. Push the async to the caller.
3. **What does it name?** Every type in its signature must already live in
   `machine-contract` or below (`nv-store`). A `sovd-core` type in the
   signature means either the type gets a contract-side twin with an exhaustive
   conversion at the edge (the `ResetKind` pattern) or the trait does not
   belong here.
4. **Re-export it from `machine-mgr`** — flat *and* in the module path
   consumers already use.
5. **Check the guard still passes**: `bash scripts/feature-matrix.sh --fixed-only`
   (the `cargo tree` run fails if the contract picked up a dependency).
6. **Add a line to *Audit history*** with the date and the trigger.
