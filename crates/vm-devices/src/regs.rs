//! Register layouts for virtual devices.
//!
//! These constants define the shared memory wire format between host
//! simulators and guest kernel drivers. They must match the C headers:
//! - `vhealth_regs.h`
//! - `vtime_regs.h`
//! - CAN SPSC ring protocol (from vcan_core.c / qnx-host-sim.c)

/// Health device registers (vhealth_regs.h).
pub mod health {
    // Magic numbers
    pub const MAGIC: u32 = 0x48544C48; // "HLTH"
    pub const HB_MAGIC: u32 = 0x48425448; // "HBTH"
    pub const VERSION: u32 = 1;
    pub const HB_VERSION: u32 = 1;

    // Header (32 bytes @ 0x000)
    pub const OFF_MAGIC: usize = 0x00;
    pub const OFF_VERSION: usize = 0x04;
    pub const OFF_NUM_SENSORS: usize = 0x08;
    pub const OFF_UPDATE_SEQ: usize = 0x0C;
    pub const OFF_MONO_NS: usize = 0x10;
    pub const OFF_FLAGS: usize = 0x18;

    pub const HEADER_SIZE: usize = 0x20;

    // Sensor array (32 bytes each @ 0x020)
    pub const SENSOR_BASE: usize = 0x20;
    pub const SENSOR_SIZE: usize = 32;
    pub const SENSOR_MAX: usize = 63;

    // Sensor entry field offsets (relative to entry start)
    pub const SENSOR_OFF_TYPE: usize = 0x00; // u16
    pub const SENSOR_OFF_ID: usize = 0x02; // u16
    pub const SENSOR_OFF_VALUE: usize = 0x04; // i32
    pub const SENSOR_OFF_VALUE_MIN: usize = 0x08; // i32
    pub const SENSOR_OFF_VALUE_MAX: usize = 0x0C; // i32
    pub const SENSOR_OFF_THRESH_WARN: usize = 0x10; // i32
    pub const SENSOR_OFF_THRESH_CRIT: usize = 0x14; // i32
    pub const SENSOR_OFF_FLAGS: usize = 0x18; // u32

    // Guest heartbeat (64 bytes @ 0x800)
    pub const HB_BASE: usize = 0x800;
    pub const HB_OFF_MAGIC: usize = HB_BASE;
    pub const HB_OFF_VERSION: usize = HB_BASE + 0x04;
    pub const HB_OFF_SEQ: usize = HB_BASE + 0x08;
    pub const HB_OFF_GUEST_STATE: usize = HB_BASE + 0x0C;
    pub const HB_OFF_MONO_NS: usize = HB_BASE + 0x10;
    pub const HB_OFF_FLAGS: usize = HB_BASE + 0x18;
    pub const HB_OFF_BOOT_ID: usize = HB_BASE + 0x1C;

    // Host→guest commands (32 bytes @ 0x840)
    pub const CMD_BASE: usize = 0x840;
    pub const CMD_OFF_SEQ: usize = CMD_BASE;
    pub const CMD_OFF_CMD: usize = CMD_BASE + 0x04;

    // Minimum shm sizes
    pub const MIN_SIZE_HEARTBEAT: usize = 0x840; // header + sensors + heartbeat
    pub const MIN_SIZE_FULL: usize = 0x860; // + command region

    // Flags
    pub const FLAG_ACTIVE: u32 = 1 << 0;
    pub const SENSOR_FLAG_VALID: u32 = 1 << 0;
    pub const SENSOR_FLAG_THRESH_EXCEEDED: u32 = 1 << 1;
    pub const HB_FLAG_SERVICES_READY: u32 = 1 << 0;

    // Sensor types
    pub const TYPE_TEMP_SOC: u16 = 0x01;
    pub const TYPE_TEMP_BOARD: u16 = 0x02;
    pub const TYPE_TEMP_STORAGE: u16 = 0x03;
    pub const TYPE_VOLTAGE_CORE: u16 = 0x10;
    pub const TYPE_VOLTAGE_IO: u16 = 0x11;
    pub const TYPE_VOLTAGE_SUPPLY: u16 = 0x12;
    pub const TYPE_STORAGE_WEAR: u16 = 0x20;
    pub const TYPE_STORAGE_LIFE: u16 = 0x21;
    pub const TYPE_FAN_SPEED: u16 = 0x30;

    // Guest state
    pub const GUEST_BOOTING: u32 = 0;
    pub const GUEST_RUNNING: u32 = 1;
    pub const GUEST_DEGRADED: u32 = 2;
    pub const GUEST_SHUTTING_DOWN: u32 = 3;

    // Host commands
    pub const CMD_NONE: u32 = 0;
    pub const CMD_SHUTDOWN: u32 = 1;
    pub const CMD_REBOOT: u32 = 2;
    pub const CMD_SUSPEND: u32 = 3;
    pub const CMD_HIBERNATE: u32 = 4;
    pub const CMD_FREEZE: u32 = 5;
}

/// Time device registers — byte offsets for SharedMemory/MMIO access.
///
/// Wire-format constants (magic, version, source/quality enum values,
/// flags, opcodes, statuses) and the VtimeRegs/VtimeCmd structs live in
/// `vm_wire::time` — single source of truth shared with the guest.
/// This module only carries the byte offsets that are an artefact of the
/// MMIO-style layout (TimeSim writes register-by-register through a
/// SharedMemory implementation; offsets matter there but not in the
/// byte-stream TimeDevice path which encodes the whole struct at once).
pub mod time {
    // Re-export wire-format constants and types so existing callsites
    // that did `use crate::regs::time as r;` continue working.
    pub use vm_wire::{
        SyncQuality, SyncSource, VtimeCmd, VtimeRegs, VTIME_CMD_ADJUST as CMD_ADJUST,
        VTIME_FLAG_RTC_PRESENT as FLAG_RTC_PRESENT, VTIME_FLAG_SYNC_VALID as FLAG_SYNC_VALID,
        VTIME_MAGIC as MAGIC, VTIME_STATUS_APPLIED as STATUS_APPLIED,
        VTIME_STATUS_PENDING as STATUS_PENDING, VTIME_STATUS_RATE_LIMITED as STATUS_RATE_LIMITED,
        VTIME_STATUS_REJECTED as STATUS_REJECTED, VTIME_STATUS_UNAUTHORIZED as STATUS_UNAUTHORIZED,
        VTIME_VERSION as VERSION, VTIME_WIRE_SIZE as REGION_SIZE,
    };

    // Sync source codes — kept as u32 aliases for SharedMemory write_u32
    // call sites in TimeSim.
    pub const SRC_NONE: u32 = SyncSource::None as u32;
    pub const SRC_NTP: u32 = SyncSource::Ntp as u32;
    pub const SRC_SNTP: u32 = SyncSource::Sntp as u32;
    pub const SRC_GPTP: u32 = SyncSource::Gptp as u32;
    pub const SRC_ROUGHTIME: u32 = SyncSource::Roughtime as u32;
    pub const SRC_GPS: u32 = SyncSource::Gps as u32;
    pub const SRC_CELLULAR: u32 = SyncSource::Cellular as u32;
    pub const SRC_CAN_TIME: u32 = SyncSource::CanTime as u32;
    pub const SRC_RTC: u32 = SyncSource::Rtc as u32;

    pub const QUALITY_UNKNOWN: u32 = SyncQuality::Unknown as u32;
    pub const QUALITY_COARSE: u32 = SyncQuality::Coarse as u32;
    pub const QUALITY_MEDIUM: u32 = SyncQuality::Medium as u32;
    pub const QUALITY_FINE: u32 = SyncQuality::Fine as u32;

    // ---- Byte offsets (host-write half, 0x00..0x40) ----
    pub const OFF_MAGIC: usize = 0x00;
    pub const OFF_VERSION: usize = 0x04;
    pub const OFF_MONO_NS: usize = 0x08;
    pub const OFF_WALL_OFFSET_NS: usize = 0x10; // i64
    pub const OFF_LAST_SYNC_MONO_NS: usize = 0x18;
    pub const OFF_SYNC_SOURCE: usize = 0x20;
    pub const OFF_SYNC_QUALITY: usize = 0x24;
    pub const OFF_MIN_WALL_NS: usize = 0x28;
    pub const OFF_FLAGS: usize = 0x30;
    pub const OFF_UPDATE_SEQ: usize = 0x34;

    // ---- Byte offsets (cmd region, 0x40..0x80, guest writes) ----
    pub const CMD_BASE: usize = 0x40;
    pub const CMD_OFF_SEQ: usize = CMD_BASE;
    pub const CMD_OFF_OP: usize = CMD_BASE + 0x04; // u8 in low byte of u32
    pub const CMD_OFF_CORRECTION_NS: usize = CMD_BASE + 0x08; // i64
    pub const CMD_OFF_SYNC_SOURCE: usize = CMD_BASE + 0x10;
    pub const CMD_OFF_SYNC_QUALITY: usize = CMD_BASE + 0x14;
    pub const CMD_OFF_STATUS: usize = CMD_BASE + 0x18;
    pub const CMD_OFF_GUEST_ID: usize = CMD_BASE + 0x1C;
}

/// CAN SPSC ring buffer protocol.
pub mod can {
    pub const MAGIC: u32 = 0x4E414356; // "VCAN"
    pub const VERSION: u32 = 1;

    // Ring header (32 bytes at start of each ring)
    pub const RING_OFF_MAGIC: usize = 0x00;
    pub const RING_OFF_VERSION: usize = 0x04;
    pub const RING_OFF_HEAD: usize = 0x08;
    pub const RING_OFF_TAIL: usize = 0x0C;
    pub const RING_OFF_SIZE: usize = 0x10;
    pub const RING_OFF_FLAGS: usize = 0x14;
    pub const RING_HEADER_SIZE: usize = 32;

    // Frame slot (72 bytes each)
    pub const FRAME_OFF_ID: usize = 0x00; // u32 (with flags in upper bits)
    pub const FRAME_OFF_LEN: usize = 0x04; // u8
    pub const FRAME_OFF_FLAGS: usize = 0x05; // u8
    pub const FRAME_OFF_DATA: usize = 0x08; // [u8; 64]
    pub const FRAME_SIZE: usize = 72;

    // CAN ID flags (upper bits of can_id)
    pub const ID_FLAG_ERR: u32 = 1 << 29;
    pub const ID_FLAG_RTR: u32 = 1 << 30;
    pub const ID_FLAG_EFF: u32 = 1 << 31;

    // Frame flags
    pub const FRAME_FLAG_BRS: u8 = 1 << 0; // CAN FD bit rate switch
    pub const FRAME_FLAG_ESI: u8 = 1 << 1; // error state indicator
    pub const FRAME_FLAG_FDF: u8 = 1 << 2; // FD format indicator

    // Ring flags
    pub const RING_FLAG_FD: u32 = 1 << 0; // CAN FD capable
}
