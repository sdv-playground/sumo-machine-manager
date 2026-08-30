# Bank State Machine Specification

## Overview

Each A/B bank set (host-os, vm1, vm2) has an independent state machine
managing its update lifecycle. The HSM component uses a single bank (no A/B,
no rollback). The state machine ensures atomic updates with automatic rollback
on failure.

## States

```
                    ┌──────────────────────────────┐
                    │         COMMITTED             │
                    │  active_bank = X              │
                    │  committed = true             │
                    │  boot_count = 0               │
                    └──────────┬───────────────────┘
                               │
                         OTA complete
                     (write to inactive bank,
                      copy-on-update runtime,
                      write FW Meta,
                      swap active_bank)
                               │
                               ▼
                    ┌──────────────────────────────┐
                    │           TRIAL               │
              ┌────▶│  active_bank = Y (new)        │◀────┐
              │     │  committed = false            │     │
              │     │  boot_count = N               │     │
              │     └───┬───────────┬──────────┬───┘     │
              │         │           │          │          │
            reboot      │       COMMIT     ROLLBACK      │
         boot_count++   │       command    command        │
              │         │           │          │          │
              │         │           ▼          ▼          │
              │         │    COMMITTED    COMMITTED       │
              │         │    (bank Y)    (bank X, old)    │
              │         │                                 │
              │         │  boot_count > MAX_TRIAL_BOOTS   │
              │         └─────────────────────────────────┘
              │                auto-rollback
              └─── (boot_count <= MAX_TRIAL_BOOTS)
```

## Boot Flow (vm-boot)

On every boot, the boot manager executes:

```
1. Read NV Boot State
2. For each A/B bank set (host-os, vm1, vm2):
   a. If committed == true:
      - Boot from active_bank (normal path)
   b. If committed == false (trial mode):
      - Increment boot_count
      - If boot_count > MAX_TRIAL_BOOTS (10):
        - Swap active_bank to other bank
        - Set committed = true, boot_count = 0
        - Log: "auto-rollback after {MAX_TRIAL_BOOTS} trial boots"
      - Else:
        - Write updated boot_count to NV
        - Boot from active_bank (trial continues)
3. Verify image hash (SHA-256 from NV FW Meta) for each active bank
4. If hash verification fails:
   - If trial: immediate rollback (don't count, just swap)
   - If committed: FATAL — both banks may be corrupted
5. Start host-os from host-os active bank
6. Start VMs from vm1/vm2 active banks
```

## OTA Update Flow (component-mgr)

```
1. Receive OTA image for a bank set (e.g., vm1)
2. Preconditions:
   - Current bank set must be COMMITTED (reject if trial)
   - Image security_version >= min_security_ver (anti-rollback)
3. Determine target: inactive bank (active_bank.other())
4. Copy-on-update: clone active Runtime DIDs/DTCs → target Runtime
5. Write image to target partition (vm1-a or vm1-b)
6. Verify written image (read-back SHA-256)
7. Write NV FW Meta for target bank:
   - SW DIDs from image header
   - image_sha256 from verification
   - Preserve min_security_ver from active bank
8. Update NV Boot State:
   - active_bank = target
   - committed = false
   - boot_count = 0
9. Report success — system must reboot to activate

On next boot, bootmgr enters TRIAL state for this bank set.
```

## Commit (from orchestrator or diagnostic command)

```
1. Precondition: bank set is in TRIAL state (committed == false)
2. Set committed = true
3. Set boot_count = 0
4. If fw_secver > min_security_ver:
   - Raise min_security_ver = fw_secver (prevents downgrade)
5. Write NV Boot State + NV FW Meta
```

## Explicit Rollback (from orchestrator or diagnostic command)

```
1. Precondition: bank set is in TRIAL state
2. Swap active_bank to previous bank
3. Set committed = true (rolling back to known-good)
4. Set boot_count = 0
5. Write NV Boot State
```

## Auto-Rollback

Triggered when `boot_count > MAX_TRIAL_BOOTS` (10). This means:
- The system has rebooted 10 times in trial mode
- No orchestrator has sent COMMIT
- Something is likely wrong with the new image

The boot manager automatically:
1. Swaps active_bank back to the previous bank
2. Sets committed = true
3. Resets boot_count = 0
4. Logs the rollback event

### Why 10 boots?

Automotive key-off/key-on cycles are normal during the update window. The
orchestrator may need multiple boot cycles to:
- Verify all services start correctly
- Run integration tests
- Wait for the vehicle to stabilize after key cycles

A threshold of 10 gives ample room for normal operation while still catching
fundamentally broken updates.

## Per-bank flash, machine-wide commit

Each A/B bank set has its own state machine and is **flashed** independently — writing vm1's
inactive bank doesn't touch vm2's or the host-os's, and the banks can sit at different *flash*
states at once.

But activation and commit are **one machine-wide update session**, not per-bank. The set of
banks a session staged — the trial **boot vector** — activates together, trial-boots together,
and is **committed together** as the new state or **rolled back together** on any failure; the
node advances its boot vector atomically (the node-level `x-ota-commit-trials` / rollback
verdict fans out across the component registry to the banks in trial). There is no per-bank
independent commit. *Future:* the session widens to the whole vehicle — one update session
spanning multiple machines/ECUs, where staged per-ECU rollouts do apply.

The HSM component uses a single bank and does not participate in A/B switching
or trial boot. HSM updates are applied directly without rollback support.

## DID Resolution (read path)

When a diagnostic client reads a UDS DID, the diagnostic server resolves it:

```
1. Runtime DIDs (writable, per-bank):
   → Read from active bank's NV Runtime
   → If found, return

2. FW Meta DIDs (SW identity, per-bank):
   → Read from active bank's NV FW Meta
   → F187, F188, F189, F194, F195, F197, F198, F199, F19E

3. Factory DIDs (hardware identity, shared):
   → Read from NV Factory
   → F18A, F18B, F18C, F190, F191, F192, F193

4. Dynamic DIDs (computed):
   → Active bank indicator (A/B)
   → Committed status
   → Boot count
   → Security version info
```

## Anti-Rollback

Each bank's NV FW Meta contains:
- `fw_secver`: the security version of the installed image
- `min_security_ver`: the minimum acceptable security version (floor)

Rules:
- OTA download rejected if image `security_version < min_security_ver`
- On COMMIT: if `fw_secver > min_security_ver`, raise the floor
- The floor is **never lowered** — prevents installing old vulnerable images
- Both banks share the same floor (copied from active to target during OTA)

## VM Bank Composition with App/Dependency Images

A VM bank set may contain not only the VM image (kernel + rootfs) but also
zero or more application and dependency images. All images in the target bank
composition are treated atomically: when a bank is swapped to active on boot,
all images in that bank become available to the guest.

### Inventory Model

Each bank's inventory contains explicit entries:

```
vm1-bank-a:
  - vm-rootfs
      version: 3.0.0
      security_version: 2
      digest: sha256:vm1-abc123...
  - app.example
      version: 2.1.0
      security_version: 2
      digest: sha256:app-def456...
      dependencies: [runtime.base]
  - runtime.base
      version: 1.5.0
      security_version: 1
      digest: sha256:runtime-ghi789...
```

Reused images are explicit inventory entries, not invisible missing payloads.
If an app image in the target bank references a reused dependency from the
active bank, the inventory records that reference by digest.

### Commit Semantics

When a bank set commits from TRIAL to COMMITTED:

1. All entries in the bank's inventory are considered part of the final,
   immutable committed state.
2. Anti-rollback policy is applied according to the chosen architecture:
   either one floor for the composed VM bank or separate floors for selected
   images. The policy choice remains an architecture/product decision.
3. Rollback restores the complete previous inventory, including reused images.

### Rollback Semantics

On explicit rollback or auto-rollback:

1. The previous bank becomes active again.
2. The entire previous inventory is restored (all images, including reused ones).
3. Trial boot restarts from the previous bank with previous image composition.

Partial rollback (rolling back just one app while keeping the OS) is not
supported in the initial architecture. All images in a bank roll back together.

### Trial Success Criteria

A bank set transitions from TRIAL to COMMITTED when:

1. The VM's base OS image boots successfully.
2. All app/dependency images in the bank inventory are accessible to the guest.
3. Health signals indicate the guest and its services are operational
   (e.g., vHealth heartbeat steady, services ready flags set).

Health monitoring includes both OS-level metrics and app availability.
The exact health criteria are a product/platform decision, but the architecture
assumes that trial success includes verifying that required app images are
present and accessible.

### Anti-Rollback Policy for App Images

App/dependency images may require anti-rollback protection in addition to the
VM bank's base image floor. The exact policy is not fixed by this state machine
specification. Valid architecture choices include:

- one security floor for the whole composed VM bank;
- separate floors for selected app/dependency images;
- separate floors for every image in the inventory.

Whichever policy is chosen, OTA validation must be explicit and consistent for
all entries in the target inventory. The architecture question is whether the
floor is tracked per composed bank, per selected image, or per image. This is
preserved as an open product/security decision in
[`sovd-vm-app-installation.md`](sovd-vm-app-installation.md).

### Reuse and Source-Lock

When an OTA updates a bank set and one or more images are unchanged:

- The manifest declares the unchanged image as "reuse from active bank"
- The source digest (digest of the image in the active bank) is recorded
- During install, the unchanged image is copied from active to target bank
- The target digest must match the source digest (verify copy integrity)
- If source digest in active bank does not match the manifest's declared
  source digest, the update is rejected or falls back to fetching the full
  image (source-lock enforcement)

Source-lock prevents subtle errors where an image is silently replaced
between OTA planning and execution.
