# NV Store Format Specification

## Overview

The NV store occupies a single raw partition (`nv`, 32 MB) managed by the bank
manager. No filesystem — the bank manager reads and writes raw sectors with
CRC-32 integrity and monotonic write sequence numbers for wear leveling.

## Internal Layout

```
Offset      Size        Sectors   Content
──────      ────        ───────   ───────
0x000000    8 KB        2         Boot State (all slots)
0x002000    8 KB        2         Factory (write-once, shared)
0x004000    8 KB        2         App (shared application data)
0x006000    8 KB        2         Vehicle (freshness coordinator, §7.2)
0x008000    8 KB        2         Update Session (node update transaction)
0x00A000    24 KB       --        (reserved)

0x010000    96 KB       24        Slot 0
0x028000    96 KB       24        Slot 1
0x040000    96 KB       24        Slot 2
   ...
0x010000 + i * 0x018000           Slot i, for i in 0..slot_count()

Each 96 KB slot region, relative to its base:
+0x000000   16 KB       4         FW Meta A
+0x004000   16 KB       4         FW Meta B
+0x008000   32 KB       8         Runtime A
+0x010000   32 KB       8         Runtime B
```

Sector size: 4 KB (matches typical eMMC erase block).

The slot count is a runtime property of the store, not a constant: `NvStore::new`
computes `min(MAX_SLOTS, (device_size - 0x010000) / 0x018000)` once at open and exposes
it as `slot_count()` / `slots()` / `slot_in_range()`. `MAX_SLOTS = 32` is the hard cap
(the width of the u32 reboot-owed mask and of the boot-state record); `DEFAULT_SLOTS = 16`
is the size a fresh store is created with when the platform does not say otherwise, so
`MIN_NV_DEVICE_SIZE = nv_device_size(DEFAULT_SLOTS) = 0x190000` (1600 KB). A 1 MB device
is therefore a 10-slot store. Growing a store means recreating the device — qnx6
`ftruncate(grow)` is a silent no-op — and the "too small, recreate" guard lives in the
supernova host binary, not in this library.

Slots are numbers here and nothing else: what a slot holds is declared by the platform
profile (supernova's `id` + `slot`); the library names no slot. A component's storage
directory is its `storage_subdir` when the profile sets one, else its component id. A
single-bank component (the HSM keystore) is always bank A, always committed.

## Sector Rotation

Each NV region uses N sectors. Data is written to the sector with the lowest
`write_seq` (or first empty sector). On read, the sector with the highest valid
`write_seq` and correct CRC is used. This provides:

- **Wear leveling**: writes rotate across sectors
- **Power-loss safety**: a failed write leaves the previous sector intact
- **Corruption recovery**: CRC mismatch skips to next valid sector

## Common Sector Header

Every sector in every region starts with:

```
Offset  Size  Field
0x00    4     magic       Region-specific magic number
0x04    4     write_seq   Monotonically increasing sequence number
...           (region-specific payload)
N-4     4     crc32       CRC-32 of bytes [0..N-4)
```

Magic numbers:
- Boot State: `0x4E564231` ("NVB1")
- Factory:    `0x4E564631` ("NVF1")
- FW Meta:    `0x4E564D31` ("NVM1")
- Runtime:    `0x4E565231` ("NVR1")
- App:        `0x4E564131` ("NVA1")
- Vehicle:    `0x4E565631` ("NVV1")
- Update Session: `0x4E565531` ("NVU1")

## Boot State

Tracks the active bank, committed status, and boot count for every slot.

```
Offset        Size  Field
0x00          4     magic (NVB1)
0x04          4     write_seq
0x08 + 3*i    1     slot i: active_bank  (0=A, 1=B)
0x09 + 3*i    1     slot i: committed    (0=trial, 1=committed)
0x0A + 3*i    1     slot i: boot_count   (incremented each boot in trial mode)
              ...   one triplet per slot, for i in 0..MAX_SLOTS (32)
0x68..0xFFC   --    zero padding
0xFFC         4     crc32
```

Total: `8 + 3*32` = 104 bytes of payload; the rest of the 4 KB sector is zero padding,
and the CRC-32 over bytes [0..4092) sits at 0xFFC — as for every record in this format
(see `read_record` / `write_record` in `crates/nv-store/src/store.rs`).

Note: the record always carries `MAX_SLOTS` entries, whatever the store's
`slot_count()`. Older writers left the trailing entries as zero padding, which decodes as
`{bank A, committed: false, boot_count: 0}` — the same default the store forces onto every
entry at index >= `slot_count()`, so records from an earlier era read back correctly.
History: 5 slots (2026-05) → 10 slots (2026-05-29) → a per-store runtime count capped at
`MAX_SLOTS` = 32 (2026-09-23). The `NVB1` magic never changed.

## Factory Data

Write-once provisioning data. Set at manufacturing, never updated in the field.

```
Offset  Size  Field               UDS DID
0x00    4     magic (NVF1)
0x04    4     write_seq
0x08    32    serial_number       F18C
0x28    8     manufacturing_date  F18B
0x30    17    vin                 F190
0x41    32    ecu_hw_number       F191
0x61    32    supplier_hw_number  F192
0x81    32    supplier_hw_version F193
0xA1    32    supplier_id         F18A
0xC1    1     device_type
0xC2    2     (padding)
0xC4    4     crc32
```

## FW Meta (per-bank)

Software identity for each banked image. Written during OTA at TransferExit.

```
Offset  Size  Field                UDS DID
0x00    4     magic (NVM1)
0x04    4     write_seq
0x08    32    fw_version           F189
0x28    4     fw_seq
0x2C    4     fw_secver            (current security version)
0x30    4     fw_crc               (image CRC-32)
0x34    32    image_sha256         (image hash for boot verification)
0x54    32    spare_part_number    F187
0x74    32    ecu_sw_number        F188
0x94    32    supplier_sw_number   F194
0xB4    32    supplier_sw_version  F195
0xD4    32    odx_file_id          F19E
0xF4    32    system_name          F197
0x114   8     programming_date     F199
0x11C   32    tester_serial        F198
0x13C   4     min_security_ver     (anti-rollback floor, raised on commit)
0x140   4     crc32
```

## Runtime (per-bank)

Writable DIDs and DTCs. Cloned from active bank to target bank during OTA
(copy-on-update) so new firmware inherits configuration.

```
Offset  Size   Field
0x00    4      magic (NVR1)
0x04    4      write_seq
0x08    1      did_count (max 20)
0x09    700    dids[20] — each: did(2) + len(1) + data(32) = 35 bytes
0x2BD   1      dtc_count (max 16)
0x2BE   80     dtcs[16] — each: dtc_number(4) + status(1) = 5 bytes
0x30E   2      (padding)
0x310   4      crc32
```

## App Data

Shared application data that persists across all bank switches.

```
Offset  Size   Field
0x00    4      magic (NVA1)
0x04    4      write_seq
0x08    2048   data (application-defined)
0x808   4      crc32
```

## Vehicle

Vehicle-level mutable coordinator state — the §7.2 freshness epoch.
Vehicle-wide, persists across all bank switches; distinct from the
write-once VIN in Factory.

```
Offset  Size   Field
0x00    4      magic (NVV1)
0x04    4      write_seq
0x08    8      vehicle_epoch (u64, monotonic — bumped each power-on/online-sync)
0x10    8      reserved (retired u64 field; role now HSM-resident)
0x18    4      crc32
```

Total: 24-byte record (rest of 4 KB sector is unused/zero-padded). The
`vehicle_epoch` only ever moves forward; peer ECUs adopt `max(local,
master)` and never rewind, so a bad master can stall freshness but never
replay an old epoch into validity.

## Integrity

- Every sector is validated with CRC-32 on read
- Invalid sectors (bad magic, bad CRC) are skipped
- If all sectors in a region are invalid, the region returns "not initialized"
- The boot manager initializes default values on first boot
