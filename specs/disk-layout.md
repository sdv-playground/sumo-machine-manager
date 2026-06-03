# Disk Layout Specification

## Overview

The QNX hypervisor manages a single storage device (eMMC or NVMe) partitioned
to support A/B banking for the hypervisor itself and up to two guest OS images.
All images are verified by the hypervisor before use. Guest OS partitions are
presented read-only to VMs.

## Partition Table (GPT)

| #  | Label          | Size    | Type    | Description                              |
|----|----------------|---------|---------|------------------------------------------|
| 1  | `boot`         | 64 MB   | raw     | QNX IPL + first-stage loader (not banked)|
| 2  | `hyp-a`        | 512 MB  | raw     | QNX hypervisor image, bank A             |
| 3  | `hyp-b`        | 512 MB  | raw     | QNX hypervisor image, bank B             |
| 4  | `vm1-a`        | 2 GB    | ext4    | VM1 image (kernel + rootfs), bank A      |
| 5  | `vm1-b`        | 2 GB    | ext4    | VM1 image (kernel + rootfs), bank B      |
| 6  | `vm2-a`        | 2 GB    | ext4    | VM2 image (kernel + rootfs), bank A      |
| 7  | `vm2-b`        | 2 GB    | ext4    | VM2 image (kernel + rootfs), bank B      |
| 8  | `nv`           | 32 MB   | raw     | NV data store (bank manager managed)     |
| 9  | `data`         | 2 GB    | ext4    | Persistent data (keys, config, app state)|
| 10 | `containers`   | varies  | ext4    | Container image store (Docker/Podman/containerd) |
| 11 | `swap`         | >= RAM  | raw     | Linux VM hibernate (resume=)             |

### Notes

- **boot**: Contains the IPL (Initial Program Loader) and first-stage bootloader.
  Not A/B banked. Updated rarely, locked down. The bootloader reads NV Boot State
  to determine which hypervisor bank to load.

- **hyp-a/b**: Full QNX hypervisor image. The bootloader verifies the SHA-256 hash
  (from NV FW Meta) before executing. Read-only at runtime.

- **vm1-a/b, vm2-a/b**: Complete guest OS stacks (kernel + rootfs + modules).
  Presented to VMs as read-only block devices. The hypervisor verifies SHA-256
  before mapping to the VM.

- **nv**: Single raw partition managed internally by the bank manager. Contains
  boot state, factory data, per-bank metadata, and application data. See
  [nv-store-format.md](nv-store-format.md) for internal layout.

- **data**: Not banked. Persists across OS updates. Contains HSM wrapped keys,
  runtime configuration, application state. Mounted read-write by the guest VM.

- **containers**: Not banked. Stores container images imported or pulled at
  runtime by Docker, Podman, or containerd. Base containers may be baked into
  the OS image; this partition holds runtime layers. Size depends on workload.

- **swap**: Not banked. Used for Linux VM hibernate (S4). Must be at least as
  large as VM RAM allocation. Kernel cmdline: `resume=/dev/vdX`.

## Partition Discovery

Partitions are identified by **GPT partition label** (not device enumeration
order) to avoid sensitivity to device probe ordering. The bank manager uses
labels to find the NV partition and image partitions.

## Sizing

The sizes above assume a 16 GB device. For larger devices, expand `containers`
and `data`. For constrained devices (8 GB), reduce VM image sizes or drop vm2.

The three A/B bank sets (hyp + vm1 + vm2) consume ~9 GB. NV + data + containers
+ swap consume the remainder.

## Application and Dependency Image Storage

VM bank sets may contain not only the base OS image but also application and
dependency filesystem images delivered via OTA. This section describes storage
allocation options at the architecture level.

### Current Containers Partition Limitation

The `containers` partition is **not banked** runtime container storage. It is
not suitable for hosting read-only app/dependency images that need:

- A/B banking semantics (separate copies per bank, atomic updates)
- Trial boot / commit / rollback coordination
- Validation before guest exposure
- Clear inventory tracking

The `containers` partition remains for runtime container image layers,
ephemeral storage, and other non-banked content managed by the guest's
container runtime.

### Storage Allocation Options

Three architecturally valid approaches exist. The choice is a BSP/factory/product
decision, not a software-only assumption.

#### Option 1: Expanded VM Bank Partitions (Simplest)

Grow each VM bank partition to include app storage alongside the base OS image.

```
Current:
  vm1-a: 2 GB (OS only)
  vm1-b: 2 GB (OS only)

After:
  vm1-a: 3 GB (OS + app images)
  vm1-b: 3 GB (OS + app images)
```

**Allocation within partition:**
- Partition contains both `vm-rootfs` and all app/dependency images
- OTA package specifies which regions to write
- Reuse means copying the entire unchanged region or using copy-on-write

**Pros:**
- Single A/B pair per VM (no additional NV state management)
- Atomic with OS image: one commit/rollback affects all
- Natural reuse: entire partition cloned if unchanged
- Clear inventory: everything in the partition is part of the bank

**Cons:**
- OTA payload includes full partition even if only one app changed
- Less granular rollback (can't rollback just the app)
- Storage duplication in A/B banks (both copies contain all images)

**Suitable for:** Phase 1, modest app payload size, strong atomicity requirement

#### Option 2: Dedicated Banked App-Image Regions

Create separate A/B bank regions specifically for app/dependency images.

```
vm1-apps-a: 1 GB
vm1-apps-b: 1 GB
vm2-apps-a: 1 GB
vm2-apps-b: 1 GB
```

**Allocation within region:**
- Each region holds multiple app/dependency images
- OTA package specifies which images go into which regions
- Reuse means copying individual images or regions

**NV state:** Each app bank region requires its own `active_bank` pointer
and security metadata, in addition to the OS bank state.

**Pros:**
- Decouples app updates from OS updates (smaller OTA payloads)
- OTA can update just app images without touching OS partition
- Reuse is per-image rather than per-partition (more granular)
- Easier to share images across multiple app contexts

**Cons:**
- More NV state per VM (two active_bank pointers, separate commit/rollback)
- More complex orchestration: must coordinate OS and app bank activation
- Dependency complexity: what if app needs runtime that only exists in new OS?
- Risk of inconsistency (app expects OS feature not present in its bank's OS)

**Suitable for:** Later phases, larger app payloads, independent app lifecycle desired

#### Option 3: Factory-Provisioned Shared Read-Only Region

Create a single read-only region (not banked) for images usable by multiple VMs,
with explicit bank/inventory tracking.

```
shared-images: 2 GB (not A/B banked)
  - runtime.base (50 MB)
  - lib.openssl (30 MB)
  - lib.zlib (20 MB)
  - app.telemetry-v2.0.0 (200 MB)
  - app.telemetry-v1.5.0 (200 MB) — retained for rollback
  - ...

vm1-bank-a inventory:
  references: [runtime.base, lib.openssl, app.telemetry-v2.0.0]

vm1-bank-b inventory:
  references: [runtime.base, lib.openssl, app.telemetry-v1.5.0]
```

**Allocation:**
- Shared region is provisioned at factory and updated rarely (offline process)
- Each bank's inventory records which images it uses (by digest)
- Garbage collection removes unreferenced images periodically

**NV state:** Each bank stores a list of image references (digests).

**Pros:**
- Storage efficiency if images shared across VMs (deduplicated)
- Clear provenance: which bank uses which image (explicit inventory)
- Offline/factory-controlled (not updated on every OTA)
- OTA payloads are smaller (just new digests, not entire images)

**Cons:**
- Shared region must never contain versions incompatible with any referencing bank
- Requires careful versioning and compatibility policy
- Garbage collection complexity (which versions are still needed for rollback?)
- Storage allocation is a product/factory decision (not self-contained per VM)

**Suitable for:** Fleet deployments, large shared dependencies, dedicated image supply chain

### Architecture Level Guidance

All three options preserve the core architecture principles:

1. **Host validates before exposure** — Regardless of storage location, the host
   validates all images before swapping a bank to active.

2. **Inventory is explicit** — Each bank records which images it contains (by
   digest). Reused images are never implicit.

3. **Rollback is atomic** — Committing a bank finalizes its inventory. Rollback
   restores the previous inventory completely.

4. **VM-OS-neutral** — Guest platform details (mount points, discovery
   mechanisms) are independent of storage allocation.

The choice between options is driven by:
- Device storage capacity
- OTA payload size budget
- Desired granularity of app updates
- Complexity tolerance for NV state management
- Multi-VM image sharing patterns
