//! vTime wire format — host writes regs, designated guest writes commands.
//!
//! 128-byte little-endian region split in half:
//!
//! ```text
//!   ┌─────────────────────────────────── HOST WRITES ──┐
//!   0x00..0x04  magic    = VTIME_MAGIC ("TIME")
//!   0x04..0x08  version  = VTIME_VERSION
//!   0x08..0x10  mono_ns                    (u64)
//!   0x10..0x18  wall_offset_ns             (i64; wall = mono + offset)
//!   0x18..0x20  last_sync_mono_ns          (u64; 0 = never synced)
//!   0x20..0x24  sync_source                (u32; SyncSource code)
//!   0x24..0x28  sync_quality               (u32; SyncQuality code)
//!   0x28..0x30  min_wall_ns                (u64; rollback floor)
//!   0x30..0x34  flags                      (u32; FLAG_SYNC_VALID, ...)
//!   0x34..0x38  update_seq                 (u32; bumped on each publish)
//!   0x38..0x40  reserved
//!   ┌─────────────────────────────────── GUEST WRITES ─┐
//!   0x40..0x44  cmd_seq                    (u32; bumped to signal host)
//!   0x44..0x48  op                         (u32; low byte = CMD_*)
//!   0x48..0x50  correction_ns              (i64)
//!   0x50..0x54  sync_source                (u32)
//!   0x54..0x58  sync_quality               (u32)
//!   0x58..0x5C  status                     (u32; STATUS_*)
//!   0x5C..0x60  guest_id                   (u32; auth identity)
//!   0x60..0x80  reserved
//! ```
//!
//! Pinned by `canonical_wire_bytes_*` test fixtures below.

/// Magic at offset 0 of the regs half — ASCII "TIME" little-endian.
pub const VTIME_MAGIC: u32 = 0x54494D45;

/// Wire format version. Reader rejects anything else.
pub const VTIME_VERSION: u32 = 1;

/// Total region size (regs half + cmd half).
pub const VTIME_WIRE_SIZE: usize = 128;

/// Size of just the regs (host-write) half. Useful when a transport
/// can address halves separately (two channels, MMIO offset reads).
pub const VTIME_REGS_SIZE: usize = 64;

/// Size of just the cmd (guest-write) half.
pub const VTIME_CMD_SIZE: usize = 64;

/// Offset where the cmd half starts within the 128-byte region.
pub const VTIME_CMD_OFFSET: usize = 64;

// =============================================================================
// Flags
// =============================================================================

pub const VTIME_FLAG_SYNC_VALID: u32 = 1 << 0;
pub const VTIME_FLAG_RTC_PRESENT: u32 = 1 << 1;

// =============================================================================
// Sync source + quality
// =============================================================================

/// Identifies what disciplined the host's wall offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SyncSource {
    None = 0,
    Ntp = 1,
    Sntp = 2,
    Gptp = 3,
    Roughtime = 4,
    Gps = 5,
    Cellular = 6,
    CanTime = 7,
    Rtc = 8,
}

impl SyncSource {
    pub fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::Ntp,
            2 => Self::Sntp,
            3 => Self::Gptp,
            4 => Self::Roughtime,
            5 => Self::Gps,
            6 => Self::Cellular,
            7 => Self::CanTime,
            8 => Self::Rtc,
            _ => Self::None,
        }
    }
}

/// Estimated accuracy class of the host's wall clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SyncQuality {
    Unknown = 0,
    /// > 1 second (roughtime, CAN time)
    Coarse = 1,
    /// 1 ms .. 1 s (NTP, cellular)
    Medium = 2,
    /// < 1 ms (gPTP, GPS)
    Fine = 3,
}

impl SyncQuality {
    pub fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::Coarse,
            2 => Self::Medium,
            3 => Self::Fine,
            _ => Self::Unknown,
        }
    }
}

// =============================================================================
// Cmd opcodes + statuses
// =============================================================================

pub const VTIME_CMD_ADJUST: u8 = 0x01;

pub const VTIME_STATUS_PENDING: u32 = 0x00;
pub const VTIME_STATUS_APPLIED: u32 = 0x01;
pub const VTIME_STATUS_REJECTED: u32 = 0x02;
pub const VTIME_STATUS_UNAUTHORIZED: u32 = 0x03;
pub const VTIME_STATUS_RATE_LIMITED: u32 = 0x04;

// =============================================================================
// VtimeRegs — host-write half (64 B)
// =============================================================================

/// Snapshot of the host-write half of the vtime region. Every field
/// is little-endian on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtimeRegs {
    pub mono_ns: u64,
    pub wall_offset_ns: i64,
    pub last_sync_mono_ns: u64,
    pub sync_source: SyncSource,
    pub sync_quality: SyncQuality,
    pub min_wall_ns: u64,
    pub flags: u32,
    pub update_seq: u32,
}

impl VtimeRegs {
    /// Encode into the first VTIME_REGS_SIZE bytes of a buffer.
    /// Magic + version are filled by this function; callers don't touch them.
    pub fn to_regs_bytes(&self) -> [u8; VTIME_REGS_SIZE] {
        let mut buf = [0u8; VTIME_REGS_SIZE];
        buf[0..4].copy_from_slice(&VTIME_MAGIC.to_le_bytes());
        buf[4..8].copy_from_slice(&VTIME_VERSION.to_le_bytes());
        buf[8..16].copy_from_slice(&self.mono_ns.to_le_bytes());
        buf[16..24].copy_from_slice(&self.wall_offset_ns.to_le_bytes());
        buf[24..32].copy_from_slice(&self.last_sync_mono_ns.to_le_bytes());
        buf[32..36].copy_from_slice(&(self.sync_source as u32).to_le_bytes());
        buf[36..40].copy_from_slice(&(self.sync_quality as u32).to_le_bytes());
        buf[40..48].copy_from_slice(&self.min_wall_ns.to_le_bytes());
        buf[48..52].copy_from_slice(&self.flags.to_le_bytes());
        buf[52..56].copy_from_slice(&self.update_seq.to_le_bytes());
        // 56..64 reserved (zero)
        buf
    }

    /// Decode from a buffer that contains at least VTIME_REGS_SIZE bytes
    /// starting at offset 0. Returns `None` on bad magic / version.
    pub fn from_regs_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < VTIME_REGS_SIZE {
            return None;
        }
        let magic = u32::from_le_bytes(data[0..4].try_into().ok()?);
        if magic != VTIME_MAGIC {
            return None;
        }
        let version = u32::from_le_bytes(data[4..8].try_into().ok()?);
        if version != VTIME_VERSION {
            return None;
        }
        let mono_ns = u64::from_le_bytes(data[8..16].try_into().ok()?);
        let wall_offset_ns = i64::from_le_bytes(data[16..24].try_into().ok()?);
        let last_sync_mono_ns = u64::from_le_bytes(data[24..32].try_into().ok()?);
        let sync_source = SyncSource::from_u32(u32::from_le_bytes(data[32..36].try_into().ok()?));
        let sync_quality = SyncQuality::from_u32(u32::from_le_bytes(data[36..40].try_into().ok()?));
        let min_wall_ns = u64::from_le_bytes(data[40..48].try_into().ok()?);
        let flags = u32::from_le_bytes(data[48..52].try_into().ok()?);
        let update_seq = u32::from_le_bytes(data[52..56].try_into().ok()?);
        Some(Self {
            mono_ns,
            wall_offset_ns,
            last_sync_mono_ns,
            sync_source,
            sync_quality,
            min_wall_ns,
            flags,
            update_seq,
        })
    }

    /// Computed wall time in nanoseconds. Does NOT clamp on overflow —
    /// callers checking `flags & VTIME_FLAG_SYNC_VALID` first will get
    /// a meaningful result.
    pub fn wall_ns(&self) -> i64 {
        self.mono_ns as i64 + self.wall_offset_ns
    }
}

// =============================================================================
// VtimeCmd — guest-write half (64 B)
// =============================================================================

/// Guest-issued TIME_ADJUST command. Status is host-written after
/// processing — readers should treat it as host-owned post-write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtimeCmd {
    pub seq: u32,
    pub op: u8,
    pub correction_ns: i64,
    pub sync_source: SyncSource,
    pub sync_quality: SyncQuality,
    pub status: u32,
    pub guest_id: u32,
}

impl VtimeCmd {
    /// Encode into the first VTIME_CMD_SIZE bytes of a buffer.
    pub fn to_cmd_bytes(&self) -> [u8; VTIME_CMD_SIZE] {
        let mut buf = [0u8; VTIME_CMD_SIZE];
        buf[0..4].copy_from_slice(&self.seq.to_le_bytes());
        buf[4..8].copy_from_slice(&(self.op as u32).to_le_bytes());
        buf[8..16].copy_from_slice(&self.correction_ns.to_le_bytes());
        buf[16..20].copy_from_slice(&(self.sync_source as u32).to_le_bytes());
        buf[20..24].copy_from_slice(&(self.sync_quality as u32).to_le_bytes());
        buf[24..28].copy_from_slice(&self.status.to_le_bytes());
        buf[28..32].copy_from_slice(&self.guest_id.to_le_bytes());
        // 32..64 reserved (zero)
        buf
    }

    pub fn from_cmd_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < VTIME_CMD_SIZE {
            return None;
        }
        let seq = u32::from_le_bytes(data[0..4].try_into().ok()?);
        let op = (u32::from_le_bytes(data[4..8].try_into().ok()?) & 0xFF) as u8;
        let correction_ns = i64::from_le_bytes(data[8..16].try_into().ok()?);
        let sync_source = SyncSource::from_u32(u32::from_le_bytes(data[16..20].try_into().ok()?));
        let sync_quality = SyncQuality::from_u32(u32::from_le_bytes(data[20..24].try_into().ok()?));
        let status = u32::from_le_bytes(data[24..28].try_into().ok()?);
        let guest_id = u32::from_le_bytes(data[28..32].try_into().ok()?);
        Some(Self {
            seq,
            op,
            correction_ns,
            sync_source,
            sync_quality,
            status,
            guest_id,
        })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned canonical-byte fixture for the host-write half. Any change
    /// breaks the wire format — host and guest must update together.
    #[test]
    fn canonical_regs_bytes() {
        let r = VtimeRegs {
            mono_ns: 0x1122_3344_5566_7788,
            wall_offset_ns: 0x0102_0304_0506_0708,
            last_sync_mono_ns: 0xAABB_CCDD_EEFF_0011,
            sync_source: SyncSource::Gptp,
            sync_quality: SyncQuality::Fine,
            min_wall_ns: 0xDEAD_BEEF_DEAD_BEEF,
            flags: VTIME_FLAG_SYNC_VALID | VTIME_FLAG_RTC_PRESENT,
            update_seq: 0xCAFE_BABE,
        };
        let bytes = r.to_regs_bytes();

        // magic "TIME" LE = 0x45,0x4D,0x49,0x54
        assert_eq!(&bytes[0..4], &[0x45, 0x4D, 0x49, 0x54]);
        // version = 1
        assert_eq!(&bytes[4..8], &[0x01, 0x00, 0x00, 0x00]);
        // mono_ns LE
        assert_eq!(
            &bytes[8..16],
            &[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
        );
        // wall_offset_ns LE
        assert_eq!(
            &bytes[16..24],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        // sync_source = Gptp(3)
        assert_eq!(&bytes[32..36], &[0x03, 0x00, 0x00, 0x00]);
        // sync_quality = Fine(3)
        assert_eq!(&bytes[36..40], &[0x03, 0x00, 0x00, 0x00]);
        // flags = 3 (both bits)
        assert_eq!(&bytes[48..52], &[0x03, 0x00, 0x00, 0x00]);
        // update_seq LE
        assert_eq!(&bytes[52..56], &[0xBE, 0xBA, 0xFE, 0xCA]);

        // Round-trip
        let decoded = VtimeRegs::from_regs_bytes(&bytes).expect("must decode");
        assert_eq!(decoded, r);
    }

    /// Pinned canonical-byte fixture for the guest-write half.
    #[test]
    fn canonical_cmd_bytes() {
        let c = VtimeCmd {
            seq: 0x12345678,
            op: VTIME_CMD_ADJUST,
            correction_ns: -1000,
            sync_source: SyncSource::Ntp,
            sync_quality: SyncQuality::Medium,
            status: VTIME_STATUS_PENDING,
            guest_id: 1,
        };
        let bytes = c.to_cmd_bytes();
        // seq LE
        assert_eq!(&bytes[0..4], &[0x78, 0x56, 0x34, 0x12]);
        // op (zero-extended to u32 LE) — ADJUST = 0x01
        assert_eq!(&bytes[4..8], &[0x01, 0x00, 0x00, 0x00]);
        // sync_source = Ntp(1)
        assert_eq!(&bytes[16..20], &[0x01, 0x00, 0x00, 0x00]);

        let decoded = VtimeCmd::from_cmd_bytes(&bytes).expect("must decode");
        assert_eq!(decoded, c);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = [0u8; VTIME_REGS_SIZE];
        bytes[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        assert!(VtimeRegs::from_regs_bytes(&bytes).is_none());
    }

    #[test]
    fn rejects_bad_version() {
        let mut bytes = [0u8; VTIME_REGS_SIZE];
        bytes[0..4].copy_from_slice(&VTIME_MAGIC.to_le_bytes());
        bytes[4..8].copy_from_slice(&99u32.to_le_bytes());
        assert!(VtimeRegs::from_regs_bytes(&bytes).is_none());
    }

    #[test]
    fn rejects_short_input() {
        let bytes = [0u8; VTIME_REGS_SIZE - 1];
        assert!(VtimeRegs::from_regs_bytes(&bytes).is_none());
    }

    #[test]
    fn unknown_source_decodes_to_none() {
        // Bad source value should fold to None rather than panic.
        let mut bytes = VtimeRegs {
            mono_ns: 0,
            wall_offset_ns: 0,
            last_sync_mono_ns: 0,
            sync_source: SyncSource::None,
            sync_quality: SyncQuality::Unknown,
            min_wall_ns: 0,
            flags: 0,
            update_seq: 0,
        }
        .to_regs_bytes();
        bytes[32..36].copy_from_slice(&999u32.to_le_bytes());
        let r = VtimeRegs::from_regs_bytes(&bytes).expect("decodes");
        assert_eq!(r.sync_source, SyncSource::None);
    }

    #[test]
    fn wall_ns_addition() {
        let r = VtimeRegs {
            mono_ns: 1_000_000_000,                    // 1 s of mono
            wall_offset_ns: 1_700_000_000_000_000_000, // ~2023 epoch
            last_sync_mono_ns: 0,
            sync_source: SyncSource::None,
            sync_quality: SyncQuality::Unknown,
            min_wall_ns: 0,
            flags: 0,
            update_seq: 0,
        };
        assert_eq!(r.wall_ns(), 1_700_000_001_000_000_000);
    }
}
