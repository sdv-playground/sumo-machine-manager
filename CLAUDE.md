# CLAUDE.md — sumo-machine-manager

## Project Overview

Platform-agnostic machine manager for automotive ECUs. Handles A/B bank
switching, boot decisions, OTA software updates with SUIT manifest validation,
encrypted firmware, and SOVD-compatible diagnostics.

Developed and tested on Linux (file-backed storage + QEMU). The `machine-mgr`
trait layer + per-crate `BlockDevice` / `SharedMemory` / `HsmCryptoProvider`
traits let the same business logic run on QNX (qvm hypervisor) once the
concrete impls exist.

### The Upgradable abstraction (lead with this)

The conceptual base is **"a thing that can be updated"**, modelled by
`machine_mgr::Component`. There are two structural shapes (today
discriminated at runtime via `Capabilities`):

| Shape | Lifecycle | Implementations |
|---|---|---|
| **Banked** — A/B + trial + commit/rollback | `start_install` → `upload_envelope` → `finalize_install` (flip pointer, reboot needed) → trial boot → `commit_install` OR auto-rollback | `ComponentAdapter` (component-mgr), `HostOsComponent` (host-os-mgr), future RT-core component, A/B-style slave-ECU component |
| **Singleshot** — write-through, no rollback | `start_install` → `upload_envelope` → `finalize_install` (write live) → `commit_install` (raise floor + audit) | HSM keystore (hsm crate), `ContainerImageComponent` (app-mgr) |

`component-mgr` is **the VM impl of `Component`**, not the base. Same for
`host-os-mgr`, `app-mgr`, and `hsm`. They're siblings under the same
trait; `MachineRegistry` (`crates/machine-mgr/src/machine.rs`) holds
them as `dyn Component` and routes by `component_id`.

The compile-time `Banked: Upgradable` / `Singleshot: Upgradable`
trait split is a deferred refactor (see `tasks/sw-update-architecture.md`
open question #1) — capability-only discrimination works today.

### Architecture

Cargo workspace with 29 crates. The load-bearing ones, bottom-up:

- **nv-store** (lib): sector-rotated NV regions (boot state, factory,
  FW meta, runtime DIDs) with CRC-32 and monotonic `write_seq`, over a
  pluggable `BlockDevice`. Platform-independent.
- **secstore** (lib): encrypted key-metadata persistence with pluggable
  `SecstoreEncryptor` + `SecstoreBackend`.
- **vm-boot** (lib+bin): boot-time logic for ALL bank sets. Reads NV boot
  state, verifies image hashes, handles trial boot counting and auto-rollback.
- **hsm** (lib): HSM management trait (`HsmProvider`, `HsmCryptoProvider`).
  `SimHsm` (dev/test: vhsm-ssd + file keystore) works; `QnxHsm` is a stub.
- **vhsm-ssd** (lib+bin): host-side daemon terminating the v3 handle-based
  vHSM wire protocol from guest `/dev/vhsm`. Transport is TCP on a
  private host bridge (`vbr-vhsm`, 10.0.200.0/24, default bind
  `10.0.200.1:5100`); guest identity is established by a CWT/IAM handshake
  at connect time, with the source IP (pinned via static MAC→IP lease) as a
  static pre-gate.
- **vm-devices** (lib): virtual CAN, health, and time simulators running
  on shared memory (ivshmem vs QNX native shm).
- **vm-service** (lib+bin): QEMU / `qvm` lifecycle, per-bank VM config,
  ivshmem-server management, QMP integration, IPC to the diagnostics daemon.
- **machine-mgr** (lib): platform-agnostic `Machine` / `Component` trait
  layer. Connects all updatable things under a single registry. Also owns
  the `BankActivator` trait + `BankActivatorError` enum.
- **host-os-mgr** (lib): Host OS update management — IFS activation, A/B
  boot partition switching, reboot coordination. `DevBankActivator` (mount+copy)
  and `PartitionBankActivator` (raw partition write) implement `machine_mgr::BankActivator`.
- **app-mgr** (lib): Application/container update management through the
  `Component` lifecycle. `ContainerImageComponent` validates detached
  `#container-image` payloads and imports them into Docker, Podman, or
  containerd.
- **component-mgr** (lib+bins: `vm-sovd`): SUIT validation, encrypted firmware
  streaming pipeline, OTA engine (install/commit/rollback), DID resolution,
  and the SOVD wire adapter. `ComponentBackend` per-component state machine;
  `ComponentDiagBackend` routes SOVD calls through `Component` trait.
  `dispatcher.rs` resolves a SUIT envelope's target `BankSet` (used by the
  /updates wire to reject mismatches with HTTP 415 before opening a session).

### Separation of Concerns

```
vm-boot        — WHEN to boot which bank (runs once at startup, all bank sets)
vm-service     — HOW to start/stop VMs (QEMU QMP, qvm lifecycle)
component-mgr         — WHAT to flash and verify (OTA engine, SUIT, SOVD wire)
host-os-mgr    — Host-specific: IFS write, partition swap, reboot
machine-mgr    — Abstract trait layer connecting them all
```

### Key Dependencies

- **sovd-core / sovd-api** (from SOVDd): `DiagnosticBackend` trait + HTTP
  routing. Wire-format compatible with `sovd-client` and SOVD Explorer.
- **sumo-onboard / sumo-crypto / sumo-codec** (from sumo-rs): SUIT manifest
  validation, streaming decryption (AES-GCM + ECDH-ES+A128KW), decompression.
- **sumo-processor**: SUIT command-sequence interpreter.

### Key Concepts

- **Bank sets**: 10 slots (`NUM_BANK_SETS=10`), 6 named — Hsm (single-bank), Bootloader (reserved), Os/host-os (A/B, IFS+rootfs atomic), Rt (Cortex-M7), Vm1, Vm2 (A/B); slots 6–9 reserved headroom
- **Two-process architecture**: `vm-service` (QEMU/qvm lifecycle) + `vm-sovd` (diagnostics/OTA)
- **Per-bank VM config**: `vm-config.yaml` in bank directories, delivered alongside firmware
- **Multi-payload SUIT**: host-os carries `#ifs` + `#rootfs` in one envelope; VMs carry kernel + rootfs + config
- **Container image payloads**: app updates use detached `#container-image` payloads imported by Docker, Podman, or containerd
- **Trial boot**: up to 10 reboots before auto-rollback to previous bank
- **Copy-on-update**: clone runtime DIDs to target bank before OTA write
- **NV persistence**: boot state, security floor survive power cycles (sector-rotated, CRC-protected)
- **Security version** (SUIT custom param -257): separate from `sequence_number`, enables A/B fleet testing
- **CRL manifests**: policy-only (no firmware), raises anti-rollback floor
- **Encrypted firmware**: AES-128-GCM + ECDH-ES+A128KW per-device key wrapping
- **Session/security**: programming session + seed/key unlock before flash
- **`SecurityProvider` trait**: pluggable key validation (`TestSecurityProvider` for dev)

### Key Files

```
crates/component-mgr/src/
  backend.rs              — ComponentBackend: per-component state machine
  component_adapter.rs    — ComponentAdapter: exposes ComponentBackend via Component
  dispatcher.rs           — F.D3 SUIT-aware target resolver (peek_target_bank_set / check_target)
  suit_provider.rs        — SUIT envelope validation
  manifest_provider.rs    — ManifestProvider trait
  ota.rs                  — OTA engine: install, commit, rollback
  streaming.rs            — upload pipeline (decrypt + decompress + hash)
  did.rs                  — UDS DID resolution (F187-F19E + custom)
  sovd/security.rs        — SecurityProvider trait + TestSecurityProvider
  main.rs                 — vm-diagserver binary entry point (SOVD/OTA server)

crates/host-os-mgr/src/
  component.rs            — HostOsComponent (implements machine_mgr::Component)
  ifs/mod.rs              — re-exports BankActivator + BankActivatorError from machine-mgr
  ifs/dev.rs              — DevBankActivator (mount + atomic copy)
  ifs/partition.rs        — PartitionBankActivator (raw block device write)

crates/app-mgr/src/
  docker_image.rs         — ContainerImageComponent and runtime import backends

crates/machine-mgr/src/
  component.rs            — Component trait (async, ~35 methods)
  machine.rs              — Machine + MachineRegistry (composition)
  types.rs                — Capabilities, RuntimeState, FlashId, ...

crates/hsm/src/
  crypto.rs               — SimHsm HsmCryptoProvider (RustCrypto)
  sim.rs                  — SimHsm lifecycle (spawns vhsm-ssd + file keys)
  payload.rs              — HsmKeystore CBOR schema

crates/vhsm-ssd/src/
  proto.rs + codec.rs     — wire format (v3, handle-based)
  handle_table.rs         — dynamic handle allocator (0x0100+)
  auth.rs / iam.rs        — CWT handshake (Principal) + statement-based authz
  handler.rs              — op dispatch -> HsmCryptoProvider
  transport.rs            — TCP on `vbr-vhsm` private bridge

example/
  build.rs                — Generate keys, encrypted firmware, CRL manifests
  run.sh                  — Start SOVD server + security helper
  factory/                — Factory provisioning YAML manifests
  config/secrets.toml     — Security helper ECU secrets
```

## Build & Test

```bash
cargo build
cargo test              # 425+ tests
cargo run --example build   # Generate SUIT artifacts
./example/run.sh --fresh    # Start server
```

## Workflow

Plan mode for non-trivial tasks, subagents for research.
Use sovd-core enums — never hand-build JSON response strings.
NV committed flag is source of truth after power cycle.
