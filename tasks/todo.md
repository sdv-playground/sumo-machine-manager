# Refactor: split `hypervisor-mgr` into `diagserver` + `machine-mgr`

## Goal

Separate concerns in today's monolithic `hypervisor-mgr`:

- **`diagserver`** (renamed from `hypervisor-mgr`) — generic SOVD adapter. Stays the same across deployments. Only knows the SOVD wire protocol.
- **`machine-mgr`** (new lib) — `Machine` registry of `Component` objects. Each component is independently addressable; capability-driven so an external orchestrator (in-vehicle OTA, workshop) can plan against it.

Confirmed design choices:
- Library coupling (one process), not IPC between layers.
- Per-component objects (Shape B), not flat `MachineManager` with component arg.
- Fine-grained `Capabilities` (Option 2) — `flash: Option<FlashCaps>`, `lifecycle: Option<LifecycleCaps>`, etc.
- `vm-sovd` binary's `main()` is the customization point — picks production vs. sim composition.

## Strategy

Five PRs, each independently shippable. Behavior unchanged until PR 5.

---

## PR 1 — define traits, no behavior change  ← **DONE**

Add the `machine-mgr` skeleton. `hypervisor-mgr` doesn't depend on it yet.

- [x] Create `crates/machine-mgr/` (lib only, no binaries).
- [x] Add to workspace `members` in root `Cargo.toml`.
- [x] Define core types in `machine-mgr/src/types.rs`:
  - [x] `EntityInfo` (re-exported from `sovd-core`)
  - [x] `Capabilities { did_store, flash, lifecycle, hsm, dtcs, clear_dtcs }`
  - [x] `FlashCaps { dual_bank, supports_rollback, supports_trial_boot, max_chunk_size }`
  - [x] `LifecycleCaps { restartable, has_runtime_state }`
  - [x] `HsmCaps { supports_csr, supports_key_install }`
  - [x] `FlashId(String)`, `FlashSession`, `RuntimeState`, `RuntimeStatus`, `DidKind`, `DidFilter`, `DtcFilter`, `Csr`
  - [x] `ActivationState` re-exported from `sovd-core`; `Dtc` covered by `Fault` re-export.
  - [x] `MachineError` enum with `NotSupported / NotFound / InvalidArgument / PolicyRejected / ManifestInvalid / UnknownFlashSession / Storage / Internal` variants.
- [x] Define `Component` trait in `machine-mgr/src/component.rs`:
  - [x] All methods async, return `MachineResult<_>`.
  - [x] Default impl for every method = `Err(MachineError::NotSupported)`.
  - [x] Required: `id()`, `capabilities()`. Defaulted: everything else.
  - [x] Includes `DidEntry` helper struct.
- [x] Define `Machine` trait in `machine-mgr/src/machine.rs`:
  - [x] `entity()`, `components()`, `component(id)`.
  - [x] `MachineRegistry` concrete impl + `MachineRegistryBuilder` (`with`/`with_arc`/`build`/`try_build`).
- [x] `cargo build -p machine-mgr` succeeds.
- [x] `cargo build --workspace` still passes (existing crates unchanged).
- [x] `cargo clippy -p machine-mgr -- -D warnings` clean.

**Acceptance:** met — workspace builds, `hypervisor-mgr` and `vm-sovd` behavior unchanged.

### Notes for next PR

- `hypervisor-mgr` does NOT yet depend on `machine-mgr`. PR 2 adds the dep and implements `Component` for an extracted `VmBackendComponent` wrapper.
- `Component::list_dids` returns `Vec<DidEntry>` — confirm this is the right shape against `did.rs` when wiring in PR 2.
- HSM ops (`get_csr`, `install_keys`) are top-level methods on `Component`. Only `HsmComponent` overrides them. If we want stricter typing, we could move them to a sub-trait, but the current shape matches sovd-core's "everything defaults to NotSupported" pattern.

---

## PR 2 — wrap `VmBackend` behind `Component`, no diagserver changes  ← **DONE**

- [x] `hypervisor-mgr` depends on `machine-mgr` (`Cargo.toml`).
- [x] `crates/hypervisor-mgr/src/component_adapter.rs` — `VmBackendComponent<D>` wraps `Arc<VmBackend<D>>` and implements `Component`.
- [x] Capability mapping: `ComponentConfig` + presence of `vm_service_socket`/`hsm_provider` → `Capabilities { flash, lifecycle, hsm }`.
- [x] Wired methods (delegate to `VmBackend`):
  - `id`, `capabilities`
  - `read_did` (via `did::read_did`)
  - `write_did` (Runtime only; Factory rejected with `PolicyRejected`)
  - `activation_state`, `commit_flash`, `rollback_flash`
  - `read_dtcs`, `clear_dtcs`
  - `restart` (via `ecu_reset`)
  - `runtime_state` (stub returning `RuntimeStatus::Unknown` — wired in PR 3)
- [x] `BackendError` → `MachineError` mapping (`map_backend_error`).
- [x] `MachineRegistry::builder().with(component).try_build()` works against real `VmBackendComponent` instances.
- [x] 11 new integration tests in `component_adapter_tests.rs` — all pass.
- [x] Full workspace `cargo test --workspace` passes (no regressions).
- [x] No new clippy warnings introduced.

**Acceptance:** met. Component trait validated against real `VmBackend`. Diagserver still uses `VmBackend` directly via `DiagnosticBackend`.

### Defaulted methods (still `NotSupported`, will be wired in PR 3)

- `list_dids` — needs DID registry introspection helper.
- `prepare_flash`, `write_chunk`, `validate_flash`, `abort_flash` — today's `VmBackend` flash session is single-slot and conflates manifest+payload; needs a small refactor for the trait-shaped multi-step API.
- `get_csr`, `install_keys` — need `hsm_provider` plumbing through the adapter.

### Notes for PR 3

- New accessors added to `VmBackend`: `entity_info()`, `component_config()`, `bank_set()`, `has_vm_service()`, `has_hsm_provider()`, `running_bank()`, `nv_lock()`, `nv_lock_mut()`. PR 3 uses these from `diagserver::DiagServer` to route via `Machine`.
- `VmBackendComponent::inner()` returns the wrapped `Arc<VmBackend<D>>` so PR 3 can keep falling back to direct calls until each method is migrated.

---

## PR 3 — `ComponentDiagBackend` adapter + first method group routed  ← **DONE (partial)**

Re-scoped from "migrate every method in one PR" to **"introduce the adapter + wire one method group as proof of pattern"**. Remaining method groups split into PR 3b–3g (each small).

### Why re-scoped

Today's `VmBackend` IS the `DiagnosticBackend` impl; routing diagserver "through Machine" creates a circular path back to `VmBackend`. The clean exit is a new `ComponentDiagBackend<C>` adapter that holds *both* a `Component` and a fallback `DiagnosticBackend`. Wired methods go through `Component`; unwired methods fall through to the fallback. As more `Component` methods are wired across PR 3b–3g, fewer fall through, and PR 4 finally drops `VmBackend`'s `DiagnosticBackend` impl entirely.

### Landed in PR 3

- [x] `crates/hypervisor-mgr/src/diag_backend.rs` — `ComponentDiagBackend` adapter.
- [x] `MachineError` ↔ `BackendError` translation (`map_machine_error`).
- [x] All non-required `DiagnosticBackend` methods that `VmBackend` currently overrides are explicitly forwarded so the wrapper is observably equivalent to `VmBackend` when nothing is routed through `Component`.
- [x] **Faults wired through `Component`:** `get_faults` → `Component::read_dtcs`; `clear_faults` → `Component::clear_dtcs`. Falls through to fallback if Component returns `NotSupported`.
- [x] `vm-sovd`'s `main` (`sovd_main.rs`) wraps each `Arc<VmBackend>` with `ComponentDiagBackend` before registering. Fallback = the same `VmBackend` arc.
- [x] 6 new tests in `diag_backend_tests.rs`:
  - entity_info/capabilities delegate to fallback
  - get_faults / clear_faults route through Component
  - fallback used when Component returns NotSupported
  - MachineError → BackendError translation correctness
  - other ops still pass through (smoke)
- [x] Full `cargo test --workspace` passes (6 new + ~285 existing).

### Known gap

`sovd_tests.rs` still constructs `VmBackend` and registers it directly (not wrapped). It therefore tests the *old* direct path, not the wrapper path now used by the `vm-sovd` binary. The wrapper is only behaviorally distinguishable for routed methods (faults today). End-to-end SOVD HTTP tests against the wrapper will be added in PR 4 once enough methods are wired to make wrapper-vs-backend testing meaningful.

---

## PR 3b — wire DID reads/writes  ← **DONE**

- [x] `DidEntry`, `DID_REGISTRY`, `resolve_param`, `did_value_to_json`, `nv_bytes_to_string` made `pub(crate)` so the adapter can use them.
- [x] `ComponentDiagBackend::read_data` routes per-DID through `Component::read_did`. Health DIDs (`DID_GUEST_STATE`, `DID_HEARTBEAT_SEQ`) detected and routed to fallback (vm-service over Unix socket lives there).
- [x] `ComponentDiagBackend::write_data` checks `entry.writable` flag, then routes through `Component::write_did(_, Runtime, _)`.
- [x] `make_data_value()` helper builds the SOVD `DataValue` from u16 + bytes + entry, mirroring the format `VmBackend` produces.
- [x] `MachineError::NotSupported` falls through to fallback per-DID; `MachineError::NotFound` translates to `BackendError::ParameterNotFound`.
- [x] 6 new tests:
  - factory DID via named param ("serial_number")
  - factory DID via hex param ("0xF18C")
  - unknown param → ParameterNotFound
  - health DID falls back to fallback (returns "offline" without vm-service)
  - write+read round-trip via wrapper for runtime DID
  - write rejected for read-only DID (writable=false)
- [x] `cargo test --workspace` ✓ (86 hypervisor-mgr tests, +6 new).

`read_raw_did` / `write_raw_did` not overridden by `VmBackend`, so no adapter override needed.

## PR 3c — wire activation  ← **DONE (partial)**

- [x] `get_activation_state` → `Component::activation_state` with three-way translation:
  - `Ok(Some(state))` → return state
  - `Ok(None)` (component declines) → fall back
  - `Err(NotSupported)` → fall back
  - other errors → translate
- [x] 2 new tests: routing + None-fallback case.
- [x] `cargo test --workspace` ✓ (88 hypervisor-mgr tests, +2 new).

### Deferred: `ecu_reset` → `Component::restart`

`VmBackend::ecu_reset` returns `Ok(None)` for the *boot* component (means "reset deferred — manual reboot required") and `Ok(Some(reset_type))` everywhere else. `Component::restart` returns `()` so it can't carry that distinction without leaking SOVD wire-shape into the machine API.

Two paths to fix in a follow-up:
1. Add a capability bit (e.g., `LifecycleCaps.synchronous`) and have the adapter return `Ok(None)` for components without it.
2. Change `Component::restart` to return something like `RestartOutcome { applied: bool }`.

Either way it's a Component-API change, not a 3-line wiring. Punted.

## PR 3d — install pipeline reshape  ← **DONE**

Reshape per the orchestrator clarification: the on-board orchestrator drives multi-component campaigns by installing several components in a row (each going to "AwaitingReboot"), triggering one reboot, verifying, then committing all together. The earlier granular byte-chunk API and the alternative single-call `install_package` both proved wrong-shaped — neither fits the install/finalize separation the orchestrator needs.

### machine-mgr trait reshape (breaking change to `Component`)

- [x] Removed: `prepare_flash`, `write_chunk`, `validate_flash` (wrong granularity for SUIT envelopes).
- [x] Renamed: `commit_flash` → `commit_install`, `rollback_flash` → `rollback_install`, `abort_flash` → `abort_install`.
- [x] Added: `start_install`, `upload_envelope(id, EnvelopeStream)`, `finalize_install(id)`.
- [x] Added `EnvelopeStream` type alias = `Pin<Box<dyn Stream<Item = Result<Bytes, Box<dyn Error+Send+Sync>>> + Send>>` — same shape as sovd-core's `PackageStream` for trivial conversion.
- [x] Added `FlashCaps.abortable_after_finalize: bool` capability bit.
- [x] `futures = "0.3"` added to `machine-mgr/Cargo.toml`.

### VmBackendComponent updates

- [x] Implemented: `start_install` (delegates to `VmBackend::start_flash`), `upload_envelope` (delegates to `receive_package_stream`), `finalize_install` (delegates to `finalize_flash`).
- [x] Renamed: `commit_install`, `rollback_install`.
- [x] `abort_install` left at the trait default (`NotSupported`); `abortable_after_finalize: false` to match.
- [x] Capability mapping updated.

### diag_backend.rs wiring

- [x] `start_flash` → `Component::start_install`.
- [x] `receive_package(bytes)` and `receive_package_stream(stream)` both → `Component::upload_envelope` via a shared `upload_via_install_pipeline` helper. Single-shot wraps bytes with `futures::stream::once`. Streams aren't replayable so no fallback after consumption.
- [x] `finalize_flash` → `Component::finalize_install`.
- [x] `commit_flash` → `Component::commit_install` (renamed from previous PR).
- [x] `rollback_flash` → `Component::rollback_install` (renamed).
- [x] `abort_flash` left at trait default → falls through to fallback's `NotSupported`.

### Tests

- [x] 4 new tests using spy components:
  - `start_flash` routes through `Component::start_install` (spy returns custom session id, asserted on wire).
  - `finalize_flash` routes through `Component::finalize_install`.
  - `upload_envelope` routes the bytes through the stream — spy counts received bytes.
  - Capability mapping carries `abortable_after_finalize` correctly.
- [x] Old tests updated for renames.
- [x] `cargo test --workspace` ✓ (95 hypervisor-mgr tests, +4 new).

### Known gap (resolved in PR 3d-followup below)

~~`abort_install` still `NotSupported`.~~ Resolved.

## PR 3d-followup — wire `abort_install`  ← **DONE**

- [x] `VmBackend::clear_flash_session()` public method (clears `flash_session` / `flash_transfer` / `upload_phase` mutexes + the `packages` / `manifests` / `payloads` maps).
- [x] `VmBackend::flash_is_finalized()` public predicate (true once state ≥ `AwaitingReboot`).
- [x] `VmBackendComponent::abort_install`: pre-finalize → clears session, returns Ok; post-finalize → `MachineError::PolicyRejected("cannot abort: install already finalized")` (since today's `VmBackend` can't undo a finalized install).
- [x] `ComponentDiagBackend::abort_flash` (previously fell through to fallback's NotSupported default) → routes through `Component::abort_install`.
- [x] `FlashCaps.abortable_after_finalize` stays `false` — it's honest about what the impl can do today (no bank-pointer flip-back). Cap can flip true once `VmBackend` learns to undo finalize.
- [x] 3 new tests: pre-finalize abort succeeds via Component, abort_flash routes through Component, the `defaults_return_not_supported` test updated to assert on `install_keys` instead of `abort_install`.
- [x] `cargo test --workspace` ✓ (103 hypervisor-mgr tests, +3 new).

## PR 3e — wire HSM CSR  ← **DONE (partial)**

- [x] `VmBackend::hsm_provisioning_state()` accessor (returns `Option<Result<ProvisioningState, HsmError>>`).
- [x] `VmBackendComponent::with_csr_keystore(path, port)` builder + `csr_keystore`/`csr_hsm_port` fields.
- [x] `VmBackendComponent::get_csr` implemented: refuses with `PolicyRejected` if already provisioned, generates CSR via transient `SimHsm` if unprovisioned, returns `NotSupported` if no keystore configured. Capability `hsm.supports_csr` flips to true via the builder.
- [x] `sovd_main.rs`:
  - Builds a `MachineRegistry` alongside the backends `HashMap`. The HSM component gets `with_csr_keystore` wired.
  - The `/vehicle/v1/components/hsm/csr` axum route now calls `machine.component("hsm").get_csr()` instead of building a transient `SimHsm` inline.
- [x] 2 new tests: NotSupported without keystore; CSR generated (DER blob starts with 0x30 SEQUENCE) when configured.
- [x] `cargo test --workspace` ✓ (97 hypervisor-mgr tests, +2 new).

### Deferred: `install_keys`

HSM key install today goes through the standard SOVD package flow (`receive_package` → `Component::upload_envelope` after PR 3d). `Component::install_keys` is reserved for future direct-install use cases (e.g., orchestrator wants to install keys without wrapping in a SUIT envelope). Stays at trait default (`NotSupported`) for now.

## PR 3f — wire `list_dids`  ← **DONE**

- [x] `machine_mgr::component::DidEntry` extended with `id: String` (wire param-id) so adapter can build `ParameterInfo` without re-bookkeeping.
- [x] `VmBackendComponent::list_dids` walks `DID_REGISTRY` (filtering health DIDs when no vm-service socket) and appends NV-resident runtime DIDs.
- [x] `ComponentDiagBackend::list_parameters` routes through `Component::list_dids`, looks up `data_type` from `DID_REGISTRY` for each entry (defaulting to `"bytes"` for runtime DIDs), and builds `ParameterInfo` with the correct `href` shape.
- [x] 3 new tests:
  - registry entries appear, health DIDs filtered out without vm-service
  - runtime DIDs from NV appear after `write_did`
  - `list_parameters` produces wire-shape `ParameterInfo` (id, name, data_type, href, did all correct)
- [x] `cargo test --workspace` ✓ (100 hypervisor-mgr tests, +3 new).

## PR 3g — drop fallback

- [ ] Confirm no `Component` method falls through to fallback in any code path.
- [ ] Remove `fallback: Arc<dyn DiagnosticBackend>` from `ComponentDiagBackend`.
- [ ] Remove `DiagnosticBackend` impl from `VmBackend`.
- [ ] At this point `VmBackend` is internal implementation detail of `VmBackendComponent`.

---

## PR 4 — split `VmBackend` into per-component types

Replace the single `VmBackend` (with internal `ComponentConfig` map) with concrete component types: `VmComponent`, `HostComponent`, `HsmComponent`. Each composed of pluggable subsystem traits (`NvBackend`, `HsmProvider`, `VmLifecycle`, `BankActivator`).

- [ ] Extract `VmComponent` for vm1/vm2.
- [ ] Extract `HostComponent` for the hypervisor component (host OS itself).
- [ ] Extract `HsmComponent` for hsm.
- [ ] `Machine::builder()` API; `vm-sovd/main.rs` switches to builder.

**Acceptance:** `vm-sovd --mode=sim` and existing examples still work.

---

## PR 5 — rename `hypervisor-mgr` → `diagserver`

Pure rename. Crate dir, Cargo.toml `name`, binary names stay (`vm-diagserver`, `vm-sovd`). Update all `use` paths.

- [ ] Rename `crates/hypervisor-mgr/` → `crates/diagserver/`.
- [ ] Update workspace `members`.
- [ ] Update all dependents (`vm-service`, examples, scripts).
- [ ] Update CLAUDE.md, ARCHITECTURE.md, README.md references.

**Acceptance:** workspace builds; no references to `hypervisor-mgr` remain.

---

## Out of scope (separate work)

- The QNX-host build issues (cross-compile failures, vsock, ivshmem-replacement).
- Renaming `examples/campaign` → `examples/linux-host`.
- Renaming the `boot` crate dir.
- Any qnx-host-specific component impls (e.g., raw-partition NV, real IFS activator).

## End-to-end observations from real campaign + qnx-host runs (2026-04-17)

Both `examples/campaign/start-ecus.sh` and `qemu-qnx-host/scripts/run.sh` end-to-end
runs validate the refactor. Two observations to address as future cleanups:

### Flash state machine doesn't model "validated but not yet applied"

Today's SOVD `FlashState` collapses *upload-complete-and-validated* with
*bank-pointer-flipped* into the same state (`AwaitingActivation` / `AwaitingReboot`).
Better model splits them:

```
Transferring → AwaitingActivation → AwaitingReboot → Activated → Committed | RolledBack
                  (validated)         (pointer flipped)    (in trial)
```

Maps directly onto `Component`'s lifecycle:
- `Transferring`: `upload_envelope` calls in progress
- **`AwaitingActivation`** (NEW): uploads done, signature/secver/hash validated, on disk —
  pointer NOT flipped. Cheap abort here.
- `AwaitingReboot`: `finalize_install` ran, pointer flipped. Reboot needed.
- `Activated`: rebooted, running new code on trial.

Benefits:
1. Orchestrator can "stage all → validate all → finalize all → reboot once" with a
   clean cheap-abort point if any component fails validation pre-finalize.
2. Abort vs rollback gain a clean dividing line: did we boot the new code yet?
3. HSM lifecycle simplifies: `Transferring → AwaitingActivation → (finalize) → Activated → Committed`
   (no fake `AwaitingReboot` step).

Implementation:
- Add `FlashState::AwaitingActivation` variant in sovd-core (small wire change).
- `VmBackend` auto-transitions to it after the last successful upload validates.
- `finalize_install` transitions `AwaitingActivation → AwaitingReboot` for dual-bank,
  `AwaitingActivation → Activated` for single-bank.
- Campaign viewer renders the new state.

Wire calls (`start_flash`, `transferexit`, `ecu_reset`, `commit_flash`, `rollback_flash`)
don't change shape — the new state is just *observable* between transitions.

### QNX host update does two reboots (IFS, then hypervisor) instead of one

Real-run observation: `examples/qnx-host` updates `boot` (IFS), reboots, then updates
`hypervisor` (rootfs), reboots again. Should be one campaign:
- stage IFS install
- stage hypervisor install
- one reboot
- verify both
- commit both

The sumo-campaign tool already supports multi-component campaigns
(`start-ecus.sh` did `stage → reset → commit` for HSM as a single flow). Check
`examples/qnx-host/deploy-hypervisor.sh` — likely invokes two separate
`sumo-campaign flash` calls instead of one with `--component=boot,hypervisor`
(or whatever the multi-component invocation is).

Not a vm-mgr/diagserver issue — fix in the deploy tooling and/or
sumo-sovd-orchestrator's campaign API. Aligns with the orchestrator pattern
the trait is already designed for.

## Review section (after PR 1 lands)

_To be filled in after each PR._
