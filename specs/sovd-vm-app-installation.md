# SOVD VM Application Installation — Architecture

> **Status:** Design, Architecture-Only  
> **Scope:** Specification for read-only application and dependency filesystem images delivered to VMs through SOVD.

---

## 1. Overview

VM applications and their dependencies arrive as read-only filesystem images delivered through the SOVD gateway. This architecture describes how those images are:

- Validated before exposure to a guest
- Composed with the VM's base OS image as a banked artifact set
- Discovered and mounted by the guest according to that VM's operating system
- Updated with manifest-driven reuse and delta semantics

The host/hypervisor is the trust boundary authority: no image is visible to a guest until the host has verified it.

---

## 2. Design Principles

1. **VM-OS neutrality** — The architecture does not mandate Linux containers, Docker, Podman, or QNX-native formats. It defines a neutral host-guest contract for delivering validated image artifacts.

2. **Banked composition** — App/dependency images are part of the target VM bank inventory, updated atomically with the base OS image. Commit and rollback apply to the complete composed bank.

3. **Validated before exposed** — Host validates envelope authenticity, payload digest, anti-rollback floor, and source-lock constraints before mounting or attaching any image to the guest.

4. **Manifest-driven reuse** — Unchanged images are copied/reused from the active bank with explicit inventory records. No implicit "missing" payloads.

5. **Standards-based framing** — Trust uses SUIT/COSE (RFC 9052/9124), immutable image integrity uses dm-verity or equivalent filesystem verification, and inventory tracking uses TUF-inspired signed manifests.

---

## 3. Current Architecture Anchors

### Bank and Storage Model

From `bank-state-machine.md`:

- Each A/B bank set (hypervisor, vm1, vm2) has independent state: `active_bank`, `committed` flag, `boot_count`.
- Bank sets are updated independently via OTA write → inactive bank, verify, swap, trial, commit, or auto-rollback.
- Security version is checked on OTA download; floor is raised on commit.

From `disk-layout.md`:

- Guest OS partitions (vm1-a, vm1-b, vm2-a, vm2-b) are presented to VMs as read-only block devices.
- The `containers` partition is not banked runtime container storage — it must not be assumed suitable for read-only app images.
- All images are verified by the hypervisor before use.

### SUIT and Manifest Model

From current component-mgr anchors:

- YAML manifests are factory-only; OTA updates use SUIT envelopes (CBOR/COSE).
- Envelopes carry signed authentication, encrypted firmware payloads, and detached or integrated dependencies.
- Security version (custom parameter -257) is separate from sequence_number, enabling A/B fleet testing and CRL-based policy updates.
- Multi-payload manifests support separate `#vm-rootfs`, `#app-image` payloads in one envelope.

### SOVD and Routing

From current SOVDd repo implementation:

- Current update route: `/vehicle/v1/components/{id}/updates` → host VM bank authority (component-scoped).
- App-scoped updates at `/vehicle/v1/components/{id}/apps/{app_id}/updates` are not currently plumbed in this repo, though they are compatible with the SOVD standard model (see SOVD Standard Alignment section below).
- App image delivery through the hypervisor-managed update route (component-scoped) is the current implementation.

On the host gateway side:

- vm1 proxy is currently Phase 2 (commented). App image delivery through the hypervisor-managed update route is the starting assumption.

---

## 4. Recommended Architecture

### 4.1 Delivery Route

App/dependency images are delivered through the existing VM update route:

```
SOVD client
  → host gateway /vehicle/v1/components/{vm1|vm2}/updates
  → host/hypervisor update authority (component-mgr)
  → compose target VM bank inventory (base OS + app images)
  → validate all artifacts
  → write to target bank
  → swap active bank on boot → TRIAL
  → VM sees read-only app image attachments after boot
```

The current repo implementation uses `/vehicle/v1/components/{id}/updates` (component-scoped) for app image delivery. This is a current implementation mapping, not a SOVD standard limitation. The ISO/SOVD model supports app-scoped updates at `/vehicle/v1/components/{id}/apps/{app_id}/updates` when an app entity exposes the standardized `updates` resource collection. App-scoped updates are deferred to a future repo iteration.

### 4.2 Trust Boundary

The **host/hypervisor is the authority** for VM image exposure:

- No image is guest-visible before the host validates it.
- Validation includes:
  - SUIT envelope authenticity (COSE_Sign1 verification)
  - Payload digest and size
  - Anti-rollback security version vs. floor
  - Source-lock digest for reuse/delta operations
  - Composed bank inventory consistency (all dependencies resolved)
- Host rejects mismatches with error before opening a write session to the guest.

### 4.3 VM Bank Composition

A target VM bank contains:

- VM rootfs image (base OS kernel + filesystem)
- Zero or more app/dependency images
- Explicit inventory records for all items (fetched or reused)

Example composed bank:

```
vm1-bank (target):
  - vm-rootfs
      action: fetch
      digest: <base-OS-sha256>
      size: 1.2GB
      security_version: 2
  - app.example
      action: fetch
      digest: <app-image-sha256>
      size: 256MB
      security_version: 2
      dependencies: [runtime.base]
  - runtime.base
      action: reuse-from-active
      source_digest: <previous-runtime-sha256>
      target_digest: (same)
      security_version: 1
```

All entries are part of the final committed bank inventory. Reused images are explicit — never implicit.

### 4.4 Manifest Structure (Architectural)

A SUIT envelope targeting vm1 with app images declares:

```
SUIT_Manifest (pseudocode, architecture-only):
  manifest_component_id: ['hypervisor', 'vm1']
  sequence_number: <serial for anti-rollback>
  common:
    vendor_id, class_id, image_size, image_digest, security_version
  payload_fetch: [
    set-component(vm-rootfs),
    override-parameters({ uri: "https://..../vm1-v3.0.0.enc", ... }),
    fetch,
    
    set-component(app.example),
    override-parameters({ uri: "https://..../app-example-v2.1.0.enc", ... }),
    fetch,
    
    set-component(runtime.base),
    # Reuse from active bank: omit payload, declare reuse intent
    override-parameters({ reuse_source_digest: <sha256>, reuse_generation: <active-bank-id> }),
  ]
  install: [
    set-component(vm-rootfs),
    directive-copy (decrypt + write to target bank),
    condition-image-match (verify written digest),
    
    set-component(app.example),
    directive-copy,
    condition-image-match,
    
    set-component(runtime.base),
    # Validation: source digest from active bank still matches
    condition-digest-match,
  ]
  validate: [
    set-component(vm-rootfs), condition-image-match,
    set-component(app.example), condition-image-match,
    set-component(runtime.base), condition-image-match,
  ]
```

Precise SUIT encoding is deferred to a later concrete design — this describes the architecture-level intent.

### 4.5 VM-OS-Neutral Exposure Contract

The host validates and exposes artifacts; the guest adapter consumes them according to that OS:

**Host responsibility:**
- Validate and write all images to the VM bank
- Provide read-only access to image artifacts
- Track inventory of what was installed

**Guest responsibility:**
- Discover available images (mount points, metadata, or equivalent)
- Mount/map read-only images into namespace according to guest OS semantics
- Execute any guest-specific discovery and activation logic (e.g., OS-native startup procedures)

**Example: Linux guest with app image (possible mapping)**

On a Linux guest, one possible mapping is:
- Host verifies and writes `app.example` image to a read-only partition
- Guest discovers the partition via GPT label or kernel device hierarchy
- Guest mounts or attaches the partition read-only into the namespace
- Guest services and applications use the mounted read-only content

Different Linux platform mappings may use different mount points, discovery mechanisms, or device models (e.g., dm-verity + loop mount, direct partition mount, container-backed storage). The architecture does not prescribe the mechanism.

**Example: QNX guest with app image (future, OS-native mapping)**

On QNX, the mapping would leverage QNX-native image and storage mechanisms:
- Host verifies and stores `app.example` image in guest accessible storage
- Guest discovers images according to QNX conventions
- Guest attaches or maps images according to hypervisor configuration and QNX semantics
- Guest startup procedures activate services using available images

Again, the architecture specifies the trust boundary (host validates) and the interface (guest can discover) but not the concrete platform mechanism.

The architecture does not mandate the mechanism — only that the host validates and the guest discovers.

---

## 5. SOVD Standard Alignment

This section clarifies how the architecture maps to the ISO 17978 (SOVD) standard model as described in `docs/sovd_iso17978_spec.yaml`.

### SOVD Entity and Resource Model

According to the standard:

- **Entity types**: `component` (HW/SW that can be updated) and `app` (application running on a component) are both valid entity types.
- **Resource collections**: Each entity type may expose standardized resource collections, including `updates`.
- **Update resource**: The `updates` collection provides endpoints to query, register, prepare, execute, and track software update packages.

The entity path for updates follows the pattern:

```
/{entity-path}/updates         # Query available packages
/{entity-path}/updates/{id}    # Read package details
/{entity-path}/updates/{id}/automated
/{entity-path}/updates/{id}/prepare
/{entity-path}/updates/{id}/execute
/{entity-path}/updates/{id}/status
/{entity-path}/updates/{id}/delete
POST /{entity-path}/updates    # Register/upload a package
```

Both `component` and `app` entities are allowed to expose `updates` and all 13 standardized resource collections per Table 8 of ISO 17978-3.

### Current Repo Implementation

The current SOVDd repo maps software updates as follows:

- **Component-scoped**: `/vehicle/v1/components/{id}/updates` is implemented and plumbed. This is the current delivery route for VM bank updates (including app images composed with the OS).
- **App-scoped**: `/vehicle/v1/components/{id}/apps/{app_id}/updates` is not currently implemented. This is a repo implementation choice, not a SOVD standard limitation.

### App-Scoped Update Behavior (Future)

When app-scoped updates are plumbed in a future repo iteration:

- An app entity would expose the `updates` resource collection.
- Clients could register and execute update packages targeting individual applications.
- The update lifecycle (query, prepare, execute, status, delete, automated) would follow the standard SOVD semantics.
- The update package content, bank composition, SUIT payload structure, and delta/reuse strategy would remain manufacturer decisions (ExVe/hypervisor architecture behind the SOVD API).
- An app-scoped update would need to satisfy the same validation rules as component-scoped updates: SUIT envelope authenticity, payload digest verification, anti-rollback checks, source-lock constraints.
- Commit and rollback semantics would follow the same trial/commit model as component updates (or an app-specific trial model, depending on implementation).

### Campaigns Extension

The endpoint `/vehicle/v1/campaigns` (and related campaign orchestration) is a repository/orchestrator extension not present in the ISO 17978 standard. This allows the repo to stage multi-ECU update campaigns and track their progress. Clients and servers that require strict ISO 17978 conformance should treat campaigns as optional/vendor-specific.

---

## 6. Alternatives

### Alternative A: VM-bank composition artifacts (RECOMMENDED)

App images are part of the target VM bank inventory, updated atomically through the existing update flow.

**Pros:**
- Atomic VM + app composition ensures consistency
- Leverages existing banked trial/commit/rollback model
- Host authority validates before exposure
- VM-OS-neutral interface

**Cons:**
- App-only updates still become VM-bank updates (more ceremony for smaller payloads)
- Requires spec additions for app-image inventory and per-image anti-rollback
- Storage allocation must be explicit

**Why recommended:** Fits the existing architecture, preserves host authority, and avoids introducing a second update route.

### Alternative B: Independent app update route (`/apps/{app_id}/updates`)

Apps become independently updateable SOVD sub-entities.

**Pros:**
- Natural app-level targeting for large fleets
- Aligned with ISO 17978 standard model (app entities can expose `updates` resource collection)
- Could enable independent app lifecycle management

**Cons:**
- Not plumbed in current SOVDd repo code
- More complex routing and security validation
- Harder to preserve VM-bank atomicity and rollback semantics
- Requires parallel update orchestration logic
- Future work, not for initial iteration

### Alternative C: Separate app-image bank sets

Create independent A/B banks for app images outside the VM bank.

**Pros:**
- App updates independent from VM rootfs updates
- Finer-grained rollback per app

**Cons:**
- Adds bank-state complexity (more state machines, more NV state)
- Requires new storage allocation and metadata model
- Complicated dependency ordering (what if app image fails before OS?)
- OTA orchestration becomes more complex

**Not recommended for phase 1.**

### Alternative D: Reuse existing app-mgr container model

Current app-mgr handles container image import/runtime.

**Pros:**
- Existing app update concept
- Works for non-critical payloads

**Cons:**
- Oriented around container runtime storage (Docker, Podman)
- Not banked, no trial/rollback semantics
- Does not match read-only filesystem image requirements
- Separate from VM OS image update lifecycle

**For app images that must be read-only and banked, Alternative A is better.**

---

## 7. SOVDd Repo Routing Model

### Initial: VM Update Route (Component-Scoped)

```
POST /vehicle/v1/components/vm1/updates
  → host/hypervisor validates request
  → opens SUIT envelope
  → peeks at component target (dispatcher)
  → routes to component-mgr OTA engine
  → composes target bank (rootfs + app images)
  → validates all artifacts
  → writes to target bank
  → swaps on next boot
```

This route is already defined in `sovd-api` and `component-mgr`. No new endpoints. This is the current SOVDd repo implementation mapping.

### Future: App Sub-entity Route (Deferred)

When `/vehicle/v1/components/{id}/apps/{app_id}/updates` is plumbed (phase 2+), it would enable:
- Direct app targeting without VM involvement
- Independent app lifecycle (though still subject to VM bank trial/commit if composed atomically)
- But adds complexity that's not required for phase 1

**Open question:** Should all app updates remain VM-bank composition updates, or transition to per-app routes in phase 2?

---

## 8. VM Bank Composition Model

### Inventory Entry Schema (Conceptual)

Each entry in the target bank inventory records:

```
Entry:
  id                  : string              # Unique within this bank (vm-rootfs, app.example, etc.)
  role                : string              # "vm-rootfs" | "app-image" | "dependency"
  action              : string              # "fetch" | "reuse-from-active" | "apply-delta"
  version             : string              # SemVer or identifier
  digest              : sha256              # Target digest after fetch/delta
  size                : uint64              # Total size in bytes
  security_version    : uint32              # Anti-rollback floor
  dependencies        : [string]            # List of other entry IDs
  
  # For reuse:
  source_digest       : sha256              # Digest in active bank
  source_generation   : bank_id             # Which active bank it came from
  
  # For delta:
  source_digest       : sha256              # Source image digest
  patch_digest        : sha256              # Delta patch digest
  patch_size          : uint64
```

On commit, the composed bank inventory is final and immutable for this bank set. Rollback restores the previous inventory.

### Reuse Semantics

**Rule 1:** Reused images are not implicit. Every item in the target inventory is explicit, including reused entries.

**Rule 2:** Source digest must match active bank digest. Mismatch rejects the update or falls back to full fetch.

**Rule 3:** Reused images are included in the final composed-bank inventory and are validated during trial boot.

### Delta Semantics (Phase 2)

Binary/chunk deltas optimize unchanged images:

**Rules:**
- Delta must declare source digest (which active-bank image to patch)
- Delta must declare target digest (what the result should be)
- Delta must declare patch digest and size
- Delta failure falls back to full image fetch or rejects update
- Successful delta output is validated like a fetched image before exposure
- No partially reconstructed image is exposed to a guest

**Delta is a deferred optimization.** The architecture supports deltas as a future enhancement after final-state reuse semantics are established and validated in phase 1. Precise delta semantics are specified in a later design iteration.

---

## 9. Manifest and Delta Semantics

### Phase 1: Final-State Manifest with Reuse

The OTA manifest describes the desired final bank. Each entry indicates fetch, reuse, or (future) delta.

**Example: vm1 update with base OS + app image, reusing common runtime**

```yaml
# Architectural representation (not SUIT CBOR encoding)
target_bank: vm1
generation: <new-gen-id>
entries:
  - id: vm-rootfs
    action: fetch
    version: 3.0.0
    digest: sha256:abc123...
    size: 1.2GB
    security_version: 2
    dependencies: []
  
  - id: app.example
    action: fetch
    version: 2.1.0
    digest: sha256:def456...
    size: 256MB
    security_version: 2
    dependencies: [runtime.base]
  
  - id: runtime.base
    action: reuse-from-active
    source_digest: sha256:runtime-prev-xyz
    source_generation: vm1-active-bank-id
    size: 50MB
    security_version: 1
    dependencies: []
```

**Validation rules:**
- `runtime.base` source_digest must match the actual digest in the active bank
- If mismatch, reject or fall back to fetching the full image
- Manifest is signed; tampering is detected
- All dependencies resolved before install begins

**Result:**
- Unchanged `runtime.base` is copied from active bank (fast)
- New `vm-rootfs` and `app.example` are fetched and verified
- Final bank contains all three, ready for trial boot

### Phase 2: Binary/Chunk Deltas (Deferred)

After reuse is stable, deltas allow:

```yaml
- id: vm-rootfs
  action: apply-delta
  source_digest: sha256:prev-rootfs
  target_digest: sha256:new-rootfs
  patch_digest: sha256:delta-patch
  patch_size: 45MB
```

Delta application:
1. Read source image from active bank (verify digest first)
2. Apply patch to produce candidate
3. Verify candidate digest matches target_digest
4. Write to target bank

Delta failure → full fetch or reject.

---

## 10. Validation-Before-Mount Contract

### Host Validation Steps

Before any image is accessible to a guest:

1. **SUIT Envelope Verification**
   - COSE_Sign1 signature verified against trust anchor
   - Envelope not corrupted or tampered

2. **Manifest Parsing**
   - Component target verified (e.g., is this really for vm1?)
   - All entries parsed and dependencies checked

3. **Inventory Validation**
   - All reused images source_digest match active bank
   - All dependencies resolved
   - No circular dependencies

4. **Payload Verification**
   - Fetched payloads: SHA-256 digest matches manifest entry
   - Reused images: digest confirmed in active bank
   - Delta images: source digest found, target digest reachable

5. **Anti-Rollback Check**
   - Each entry's security_version >= min_security_version
   - Security floor never lowered

6. **Write-to-Bank Verification**
   - Written data read back and re-verified
   - Final inventory snapshot committed to NV state

### Guest Mount Time

On boot, if trial begins:
- Guest can assume all images in its bank inventory are validated
- Guest-side validation may complement host validation but is not the architecture gate
- Guest mounts/activates according to OS semantics

If host validation failed, guest never boots the bank.

---

## 11. VM-OS-Neutral Exposure Contract

### What the Host Provides

After bank swap to TRIAL, the host exposes:

```
For each app/dependency image in inventory:
  - Read-only storage/device/partition
  - Discoverable according to platform conventions (partition labels, device hierarchy, or equivalent)
  - Immutable content (verified by host, verified in kernel/platform layer, or equivalent)
  - Accessible to guest for mounting or attachment
```

**Linux example:**
- Partition `vm1-app-example` (GPT label), mounted at `/opt/app` read-only
- Guest can read files, execute binaries

**QNX example (future):**
- QNX image device mapped as read-only
- Guest accesses via native QNX image API

**What the Guest Implements**

Guest startup discovers and activates images. The specifics are OS-dependent:

**Possible on Linux:** OS-level partition discovery, mount/attachment via kernel APIs, application services consuming mounted content.

**Possible on QNX:** Native image discovery, attachment per QNX conventions, application startup via QNX procedures.

The architecture specifies that images are available and immutable; the guest platform mechanism is not prescribed.

### Host Validation is Mandatory

The host/hypervisor validates all images before guest exposure. Guest-side validation (cryptographic verification, anti-rollback checks, etc.) may be used as an additional security layer and is optional/complementary:
- Host validation is architecture-level mandatory
- No guest-visible image is exposed before host validation succeeds
- Guest-side validation may complement host validation but is not the architecture gate
- Content is presented to guests as immutable (read-only, dm-verity, or equivalent platform-specific integrity mechanism)

---

## 12. Storage Options for App Images

The following storage models are all valid; the choice is a BSP/factory/product decision:

### Option 1: Expand VM Bank Partitions

Grow `vm1-a` / `vm1-b` partitions to include app storage.

```
Before:  vm1-a (2 GB — OS only)
After:   vm1-a (3 GB — OS + app storage)
         vm1-b (3 GB — OS + app storage)
```

**Pros:**
- Atomic with OS image (same partition)
- Simple: one bank region per VM
- Natural reuse (entire partition cloned)

**Cons:**
- OTA payload larger (full partition even if only app changed)
- Less granular rollback (can't rollback just the app)
- Storage duplication in A/B banks

### Option 2: Dedicated Banked App-Image Regions

Add separate A/B regions specifically for app/dependency images.

```
vm1-apps-a (1 GB)
vm1-apps-b (1 GB)
vm2-apps-a (1 GB)
vm2-apps-b (1 GB)
```

**Pros:**
- Decouples app storage from OS image
- OTA can be smaller (just app images update)
- Finer reuse granularity (per-app or per-image)

**Cons:**
- More NV metadata per VM (two active_bank pointers)
- Reuse logic more complex (must copy individually)
- Dependency management (what if OS needs new runtime but app hasn't updated?)

### Option 3: Factory-Provisioned Shared Read-Only Region

Create a single shared read-only region (not banked) for images used by multiple VMs, with explicit bank/inventory metadata.

```
shared-images (4 GB, not banked)
  - runtime.base (50 MB)
  - lib.openssl (30 MB)
  - app.telemetry-v1.5.0 (200 MB)
  - ...

Per-bank inventory (in NV):
  vm1-bank-a:
    references: [runtime.base, lib.openssl, app.telemetry-v1.5.0]
  vm1-bank-b:
    references: [runtime.base, lib.openssl]
```

**Pros:**
- Saves storage if images shared across VMs
- Clear image provenance and reuse tracking
- Smaller OTA for common dependencies

**Cons:**
- Shared region is not independently rolled back (careful versioning needed)
- Orphaned images must be garbage-collected
- More complex inventory and access control

### Recommendation for Phase 1

**Option 1 (Expand VM Bank Partitions)** is simplest for the first iteration:
- Aligns with existing bank model
- No new NV state management
- Clear rollback semantics
- Storage is pre-sized by BSP

**Options 2 and 3 can be evaluated after phase 1 experience.**

---

## 13. Open Questions

1. **Storage allocation strategy** — Should app images live in expanded VM bank partitions (Option 1), dedicated app banks (Option 2), or a factory-provisioned shared region (Option 3)?

2. **Per-app anti-rollback** — Does each app/dependency image need its own security_version floor, or is one floor per VM bank sufficient?

3. **Dependency versioning** — When an app depends on a shared runtime, who manages compatibility? OEM build system? Deployment logic? Guest-side version check?

4. **Shared images across VMs** — Can VM1 and VM2 share the same app/dependency image, or must each image be duplicated per VM bank?

5. **Immutable image format** — SquashFS, EROFS, QNX native image, dm-verity + ext4? Architecture is agnostic; product team chooses.

6. **Delta encoding** — Should binary deltas target specific image formats, or remain agnostic (any image format, any delta algorithm)?

7. **Guest discovery mechanism** — How do guests discover available app images: mount points, sysfs labels, explicit manifest on data partition, or equivalent?

8. **Future app routes** — When `/apps/{app_id}/updates` is plumbed, do all app updates transition to per-app routes, or remain under VM bank composition?

9. **Image lifecycle** — Are app images committed/rolled back with the VM, or independently? What if app becomes unhealthy during trial?

10. **Multi-app health criteria** — For trial boot success, must all apps pass health checks, or is VM OS health sufficient?

---

## 14. Reference Architecture Diagram

```
OEM/Backend
    |
    | SUIT envelope (vm1 + app + runtime)
    v
SOVD Client
    |
    | POST /vehicle/v1/components/vm1/updates
    v
Host Hypervisor (component-mgr)
    |
    +-- Validate SUIT envelope + signatures
    |
    +-- Peek at component (check target is vm1)
    |
    +-- Compose target bank:
    |     - fetch vm1-rootfs
    |     - fetch app.example
    |     - reuse runtime.base from active bank
    |
    +-- Validate all three images
    |
    +-- Write to vm1-inactive-bank
    |
    +-- Verify written data
    |
    +-- Swap: active_bank = inactive_bank, committed = false, boot_count = 0
    |
    v
Host NV State (bank-state-machine)
    active_bank: vm1-b (new)
    committed: false (trial)
    boot_count: 0
    inventory: [vm-rootfs, app.example, runtime.base]
    
    v
    (Next boot)
    
    v
Guest VM (on TRIAL)
    |
    +-- Boot vm1-b rootfs
    |
    +-- Discover and mount app images (OS-specific mechanism)
    |
    +-- Start services using app images
    |
    +-- Report health status to orchestrator
    |
    v
Orchestrator Health Evaluation
    |
    +-- Checks: OS health + app availability + service health
    |     |
    |     +-- ALL HEALTHY: Transition to COMMITTED
    |     |
    |     +-- UNHEALTHY: Orchestrator initiates rollback
    |
    v
Result: COMMITTED (images remain) OR auto-rollback (previous bank activated)
```

---

## 15. Architecture and Specification Boundaries

This document defines the architecture and specification for SOVD VM application installation — the concepts, trust models, routing, manifest semantics, and validation contracts. It establishes the semantic boundaries and trust relationships needed for design review and product iteration.

Future work includes concrete system design, platform-specific protocol mappings, API/struct design, and deployment orchestration. Each of those is separate from this architecture document and can be designed and debated independently.

---

## 16. Summary

SOVD VM application installation delivers read-only app/dependency filesystem images to guests through the host's trusted OTA path. The recommended architecture:

1. Integrates app images into the VM bank composition (Alternative A)
2. Validates all images before guest exposure (trust boundary)
3. Uses explicit reuse/delta semantics for efficient updates
4. Remains VM-OS-neutral (guest platform mapping detail)
5. Preserves existing trial/commit/rollback semantics
6. Defers storage allocation choice to BSP/product team
7. Preserves future flexibility for per-app update routes (phase 2+)

This design balances simplicity (reuses existing bank model), safety (host authority, validation-before-mount), and efficiency (reuse, deltas), while remaining open to refinement based on phase 1 experience.

---

## 17. Reading the installed inventory — `x-sumo-installed-manifest` (implemented)

The sections above describe *what* is composed into a bank. A SW-mapping / update
tool also needs to read *what is actually installed right now*, per VM, file by
file. That inventory already exists on the device as the committed bank's **signed
IVD manifest** (`ivd-manifest.cbor` + `ivd-signature.bin`, see §4.4). component-mgr
exposes it, signature-verified, as a single vendor SOVD data read — no new route,
no SOVDd change (SOVDd routes `/data` generically and stays spec-pure).

**`GET /vehicle/v1/components/{vm}/data/x-sumo-installed-manifest`** →

```json
{
  "ivd_version": 3, "gen": 5, "signed_at_unix": 1733000000,
  "identity": { "name", "version", "ecu_sw_number", "supplier_sw_number",
                "supplier_sw_version", "spare_part_number", "odx_file_id",
                "system_name", "programming_date", "tester_serial" },
  "files": [ { "path": "kernel",     "sha256": "<64-hex>" },
             { "path": "rootfs.img", "sha256": "<64-hex>" } ],
  "signature_b64": "<DER ECDSA-SHA256 over manifest_b64>",
  "manifest_b64":  "<exact ivd-manifest.cbor bytes the signature covers>"
}
```

**Semantics**

- Served from the **running / committed bank** — the same source as the F187–F19E
  identData DIDs, so the manifest and the DIDs can never disagree.
- **Signature-verified server-side** before return; **404** when the bank has no
  signed manifest (never flashed / no-HSM smoke path) — never fabricated.
- **Vendor (`x-sumo-`)**: lives entirely in component-mgr; SOVDd carries no vendor name.
- **Independent verification**: a consumer re-verifies `signature_b64` over
  `manifest_b64` with the **`ivd-signing` public key** (the key the device signs
  banks with at provision/flash time). `files[]` then proves the exact installed
  bits; `identity.version` is the release tag to diff against available updates.

**Implementation**

- `hsm::ivd::read_manifest(hsm, bank_dir) -> VerifiedManifest` — verifies the
  signature, decodes, and returns the full manifest + the raw signed bytes + the
  signature. `read_identity` is now a thin projection over it.
- `ComponentBackend::verified_bank_manifest(bank)` — the running bank, memoised and
  invalidated on every NV write (the same funnel as the identity-DID cache).
- Advertised in `list_parameters` (only when a committed manifest exists) and
  served in `read_data`; id const `INSTALLED_MANIFEST_PARAM_ID =
  "x-sumo-installed-manifest"`, category `identData`.
