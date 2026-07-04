# NV Store Format Specification

## Overview

The NV store occupies a single raw partition (`nv`, 32 MB) managed by the bank
manager. No filesystem — the bank manager reads and writes raw sectors with
CRC-32 integrity and monotonic write sequence numbers for wear leveling.

## Internal Layout

```
Offset      Size        Sectors   Content
──────      ────        ───────   ───────
0x000000    8 KB        2         Boot State (all bank sets)
0x002000    8 KB        2         Factory (write-once, shared)
0x004000    8 KB        2         App (shared application data)
0x006000    8 KB        2         Vehicle (freshness coordinator, §7.2)
0x008000    32 KB       --        (reserved)

0x010000    16 KB       4         Hypervisor FW Meta A
0x014000    16 KB       4         Hypervisor FW Meta B
0x018000    32 KB       8         Hypervisor Runtime A
0x020000    32 KB       8         Hypervisor Runtime B

0x028000    16 KB       4         VM1 FW Meta A
0x02C000    16 KB       4         VM1 FW Meta B
0x030000    32 KB       8         VM1 Runtime A
0x038000    32 KB       8         VM1 Runtime B

0x040000    16 KB       4         VM2 FW Meta A
0x044000    16 KB       4         VM2 FW Meta B
0x048000    32 KB       8         VM2 Runtime A
0x050000    32 KB       8         VM2 Runtime B

0x058000    16 KB       4         HSM FW Meta (single bank)
0x05C000    32 KB       8         HSM Runtime (single bank)

0x064000    16 KB       4         Qtd FW Meta (reserved, wire compat)
0x068000    32 KB       8         Qtd Runtime (reserved, wire compat)

0x070000    remainder   --        (reserved for future use)
```

Sector size: 4 KB (matches typical eMMC erase block).

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

## Boot State

Tracks the active bank, committed status, and boot count for each bank set.

```
Offset  Size  Field
0x00    4     magic (NVB1)
0x04    4     write_seq
0x08    1     hypervisor.active_bank  (0=A, 1=B)
0x09    1     hypervisor.committed    (0=trial, 1=committed)
0x0A    1     hypervisor.boot_count   (incremented each boot in trial mode)
0x0B    1     vm1.active_bank
0x0C    1     vm1.committed
0x0D    1     vm1.boot_count
0x0E    1     vm2.active_bank
0x0F    1     vm2.committed
0x10    1     vm2.boot_count
0x11    1     hsm.active_bank         (always 0, single-bank)
0x12    1     hsm.committed           (always 1)
0x13    1     hsm.boot_count          (always 0)
0x14    1     qtd.active_bank         (reserved, wire compat)
0x15    1     qtd.committed           (reserved)
0x16    1     qtd.boot_count          (reserved)
0x17    1     (padding)
0x18    4     crc32
```

Total: 28 bytes per sector (rest of 4 KB sector is unused/zero-padded).

Note: The wire format includes 5 bank sets (Hypervisor, VM1, VM2, HSM, Qtd)
for compatibility. HSM is single-bank (always bank A, always committed).
Qtd is reserved and unused.

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
