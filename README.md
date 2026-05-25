# sumo-machine-manager

Platform-agnostic machine manager for automotive ECUs. Handles A/B bank switching, boot decisions, OTA software updates with SUIT manifest validation, encrypted firmware, and SOVD-compatible diagnostics.

## Quick Start

```bash
cargo build
cargo test                      # 425+ tests

# Generate SUIT signing keys + encrypted firmware + CRL manifests
cargo run --example build

# Start SOVD server (port 4000) with security helper (port 9100)
./example/run.sh

# Or fresh start (wipes NV store)
./example/run.sh --fresh
```

Then connect [SOVD Explorer](https://github.com/sdv-playground/SOVD-explorer) to `http://localhost:4000`.

**SOVD Explorer settings:** Helper URL `http://localhost:9100`, token `dev-secret-123`.

## Architecture

```
┌───────────────────────────────────────────────────────────┐
│ sumo-machine-manager (cargo workspace)                      │
│                                                            │
│  nv-store        NV data: boot state, FW meta, factory,    │
│  (lib)           runtime DIDs, DTCs — pluggable block dev  │
│                                                            │
│  secstore        Encrypted key-metadata persistence        │
│  (lib)           (pluggable encryptor + backend)           │
│                                                            │
│  vm-boot         Boot decisions, trial count, hash verify, │
│  (lib+bin)       auto-rollback (all bank sets)             │
│                                                            │
│  hsm             HSM management: SimHsm (dev) / QnxHsm     │
│  (lib)           (stub); HsmCryptoProvider trait           │
│                                                            │
│  vhsm-ssd        vHSM v2 daemon (handle-based protocol)    │
│  (lib+bin)       terminating guest /dev/vhsm               │
│                                                            │
│  vm-devices      Virtual CAN/health/time device simulators │
│  (lib)           on shared memory (ivshmem/QNX shm)        │
│                                                            │
│  vm-service      QEMU/qvm lifecycle, per-bank VM config,   │
│  (lib+bin)       ivshmem server, IPC to diagnostics daemon │
│                                                            │
│  machine-mgr     Platform-agnostic Machine/Component       │
│  (lib)           trait — host-os / vm1 / vm2 / hsm         │
│                                                            │
│  host-os-mgr     Host OS update: IFS activation, A/B boot  │
│  (lib)           partition, reboot coordination             │
│                                                            │
│  app-mgr         App/container updates via Component        │
│  (lib)           container image import for local runtimes  │
│                                                            │
│  vm-mgr          SUIT validation, OTA engine, DID          │
│  (lib+bins)      resolution, SOVD wire adapter             │
│       │                                                    │
│       ├── sovd-core     (DiagnosticBackend trait)          │
│       ├── sovd-api      (HTTP routing)                     │
│       ├── sumo-onboard  (SUIT validation)                  │
│       └── sumo-processor (command sequences)               │
└───────────────────────────────────────────────────────────┘
```

### Crates

| Crate | Binaries | Purpose |
|-------|----------|---------|
| `nv-store` | — | Sector-rotated NV storage with CRC-32 integrity |
| `secstore` | — | Encrypted key-metadata persistence, pluggable encryptor + backend |
| `vm-boot` | `vm-boot` | Boot decisions, trial counting, auto-rollback (all bank sets) |
| `hsm` | — | HSM management trait (`HsmProvider` / `HsmCryptoProvider`) |
| `vhsm-ssd` | `vhsm-ssd` | Host-side vHSM v2 daemon — TCP on the private `vbr-vhsm` bridge, source-IP-based identity |
| `vm-devices` | — | CAN / health / time simulators (host-side) |
| `vm-service` | `vm-service` | QEMU (+ QNX `qvm`) lifecycle, per-bank VM config, ivshmem |
| `machine-mgr` | — | `Machine` + `Component` trait layer (platform-agnostic) |
| `host-os-mgr` | — | Host OS Component: IFS activation, A/B partition, reboot |
| `app-mgr` | — | App/container Component: local container image import for Docker, Podman, or containerd |
| `vm-mgr` | `vm-sovd` | SUIT + SOVD: validation, OTA engine, DID resolution |

### Separation of concerns

```
vm-boot        — WHEN to boot which bank (runs once at startup)
vm-service     — HOW to start/stop VMs (QEMU QMP, qvm lifecycle)
vm-mgr         — WHAT to flash and verify (OTA engine, SUIT, SOVD wire)
host-os-mgr    — Host-specific: IFS write, partition swap, reboot
machine-mgr    — Abstract trait layer connecting them all
```

## SUIT Manifest Integration

Firmware updates use [RFC 9124 SUIT](https://datatracker.ietf.org/doc/draft-ietf-suit-manifest/) manifests via [sumo-rs](https://github.com/tr-sdv-sandbox/sumo-rs):

- **Signed envelopes** — COSE_Sign1 signature verification
- **Encrypted firmware** — AES-128-GCM + ECDH-ES+A128KW per-device key wrapping
- **Compressed payloads** — zstd compression before encryption
- **Security version** — custom parameter (-257), separate from sequence_number
- **CRL manifests** — policy-only (no firmware), raises anti-rollback floor
- **Multi-payload** — host-os carries `#ifs` + `#rootfs` in one envelope
- **SUIT command sequences** — manifests declare the update flow

### Security Version Model

Separates build ordering from anti-rollback policy:

```
v1.0.0 (seq=1, secver=1) ←→ v1.1.0 (seq=2, secver=1)   # A/B fleet testing
v1.2.0 (seq=3, secver=2)                                   # security-critical fix
CRL manifest (secver=2, no payload, 228 bytes)              # blocks secver < 2
```

## SOVD Server

Uses [sovd-core](https://github.com/sdv-playground/SOVDd) `DiagnosticBackend` trait — wire-format compatible with [sovd-client](https://github.com/sdv-playground/SOVDd) and [SOVD Explorer](https://github.com/sdv-playground/SOVD-explorer).

### Components

| Component | Bank Set | Description |
|-----------|----------|-------------|
| `host-os` | HostOs | Host OS (IFS + rootfs), updated atomically |
| `vm1` | Vm1 | Primary OS VM (Linux) |
| `vm2` | Vm2 | Secondary OS VM (QNX) |
| `hsm` | Hsm | HSM firmware (single-bank, no rollback) |

### Endpoints

Standard SOVD REST API including:

```
GET/PUT  /vehicle/v1/components/{id}/modes/session    # Programming session
GET/PUT  /vehicle/v1/components/{id}/modes/security    # Seed/key security unlock
POST     /vehicle/v1/components/{id}/files             # Upload firmware
POST     /vehicle/v1/components/{id}/files/{id}/verify # Verify package
POST     /vehicle/v1/components/{id}/flash/transfer    # Start flash
GET      /vehicle/v1/components/{id}/flash/activation  # Activation state
POST     /vehicle/v1/components/{id}/flash/commit      # Commit trial
POST     /vehicle/v1/components/{id}/flash/rollback    # Rollback trial
POST     /vehicle/v1/components/{id}/reset             # ECU reset
```

### Session & Security

Flash operations require programming session + security unlock:

1. `PUT /modes/session {"value": "programming"}`
2. `PUT /modes/security {"value": "level1_requestseed"}` → seed
3. `PUT /modes/security {"value": "level1", "key": "..."}` → unlocked
4. Upload + flash + commit

`SecurityProvider` trait is pluggable — `TestSecurityProvider` (XOR 0xFF) for development, production HSM for deployment. Uses [SOVD Security Helper](https://github.com/sdv-playground/SOVD-security-helper) for key derivation.

## Key Concepts

- **Four bank sets**: host-os (A/B, IFS+rootfs atomic), vm1, vm2 (A/B), hsm (single-bank)
- **Two-process architecture**: `vm-service` (QEMU/qvm lifecycle) + `vm-sovd` (diagnostics/OTA via SOVD)
- **Per-bank VM config**: vm-config.yaml in bank directories, delivered alongside firmware via OTA
- **Multi-payload SUIT**: host-os carries IFS + rootfs; VMs carry kernel + rootfs + config
- **Container image updates**: `app-mgr` accepts detached `#container-image` payloads and imports them into Docker, Podman, or containerd through the normal Component flash lifecycle
- **Trial boot**: Up to 10 reboots before auto-rollback to previous bank
- **Copy-on-update**: Runtime DIDs/DTCs cloned to target bank before OTA write
- **NV persistence**: Boot state, security floor survive power cycles (sector-rotated, CRC-protected)

## Target platforms

| Target | Maturity | Notes |
|--------|----------|-------|
| Linux dev (QEMU + file-backed NV) | full | OTA + commit + rollback end-to-end, all tests pass |
| QNX host (supernova-machine-manager) | working | Collapses vm-service + vm-mgr into single binary |
| QNX + real HSE / CAN | trait-only | Needs platform `BlockDevice`, HSE backend, CAN adapter |

Business logic (OTA engine, NV store, SUIT validation, DID resolution) is
platform-independent — only the trait implementations change per target.

## NV Store Layout

Four bank sets (NUM_BANK_SETS=4):

```
Boot State     — active bank, committed flag, boot count (per bank set)
Factory        — serial number, VIN, HW numbers (write-once)
FW Meta A/B    — firmware version, SHA-256, security version, UDS DIDs
Runtime A/B    — writable DIDs, DTCs (cloned on update)
```

## Flash Flow

```
Session → Programming → Security Unlock → Upload SUIT Envelope
  → Validate (signature + digest + security_version)
  → Install (decrypt + decompress + write to target bank)
  → Reset → Trial (activated, not committed)
  → Health check → Commit (permanent) or Rollback
```

For CRL manifests: Upload → Apply floor → Done (no flash/reset/commit).

## Related Projects

| Project | Description |
|---------|-------------|
| [sumo-rs](https://github.com/tr-sdv-sandbox/sumo-rs) | SUIT manifest library (Rust) |
| [sumo-sovd](https://github.com/sdv-playground/sumo-sovd) | Campaign orchestrator over SOVD |
| [SOVDd](https://github.com/sdv-playground/SOVDd) | SOVD diagnostic server |
| [SOVD Explorer](https://github.com/sdv-playground/SOVD-explorer) | Diagnostic GUI |
| [SOVD Security Helper](https://github.com/sdv-playground/SOVD-security-helper) | Seed/key challenge service |
