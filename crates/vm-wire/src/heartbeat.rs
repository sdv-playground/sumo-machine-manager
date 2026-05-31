//! Heartbeat wire format — guest publishes, host reads.
//!
//! 32-byte little-endian payload:
//!
//! ```text
//!   0..4   magic   = HEARTBEAT_MAGIC ("HBTH")
//!   4..8   version = HEARTBEAT_VERSION
//!   8..12  seq                  (u32, monotonic from guest)
//!  12..16  state                (u32, GuestState code)
//!  16..24  mono_ns              (u64, guest monotonic clock)
//!  24..28  flags                (u32, bit 0 = services_ready)
//!  28..32  boot_id              (u32, random per-boot)
//! ```
//!
//! Pinned by `canonical_wire_bytes` test fixture below — host and guest
//! consumers of this crate see identical bytes by construction.

/// Magic at offset 0 of the heartbeat wire format.
pub const HEARTBEAT_MAGIC: u32 = 0x48425448; // "HBTH"

/// Wire format version. Reader rejects anything else.
pub const HEARTBEAT_VERSION: u32 = 1;

/// Wire size in bytes — fixed by the on-the-wire format.
pub const HEARTBEAT_WIRE_SIZE: usize = 32;

/// Bit flag set by guest when all critical services are up.
pub const HB_FLAG_SERVICES_READY: u32 = 1 << 0;

/// Guest-reported state values. Numeric values are part of the wire
/// format and must not change without a `HEARTBEAT_VERSION` bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum GuestState {
    Booting = 0,
    Running = 1,
    Degraded = 2,
    ShuttingDown = 3,
}

impl GuestState {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Booting),
            1 => Some(Self::Running),
            2 => Some(Self::Degraded),
            3 => Some(Self::ShuttingDown),
            _ => None,
        }
    }
}

/// One heartbeat snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heartbeat {
    pub seq: u32,
    pub state: GuestState,
    pub mono_ns: u64,
    pub flags: u32,
    pub boot_id: u32,
}

impl Heartbeat {
    pub fn to_bytes(&self) -> [u8; HEARTBEAT_WIRE_SIZE] {
        let mut buf = [0u8; HEARTBEAT_WIRE_SIZE];
        buf[0..4].copy_from_slice(&HEARTBEAT_MAGIC.to_le_bytes());
        buf[4..8].copy_from_slice(&HEARTBEAT_VERSION.to_le_bytes());
        buf[8..12].copy_from_slice(&self.seq.to_le_bytes());
        buf[12..16].copy_from_slice(&(self.state as u32).to_le_bytes());
        buf[16..24].copy_from_slice(&self.mono_ns.to_le_bytes());
        buf[24..28].copy_from_slice(&self.flags.to_le_bytes());
        buf[28..32].copy_from_slice(&self.boot_id.to_le_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < HEARTBEAT_WIRE_SIZE {
            return None;
        }
        let magic = u32::from_le_bytes(data[0..4].try_into().ok()?);
        if magic != HEARTBEAT_MAGIC {
            return None;
        }
        let version = u32::from_le_bytes(data[4..8].try_into().ok()?);
        if version != HEARTBEAT_VERSION {
            return None;
        }
        let seq = u32::from_le_bytes(data[8..12].try_into().ok()?);
        let state = GuestState::from_u32(u32::from_le_bytes(data[12..16].try_into().ok()?))?;
        let mono_ns = u64::from_le_bytes(data[16..24].try_into().ok()?);
        let flags = u32::from_le_bytes(data[24..28].try_into().ok()?);
        let boot_id = u32::from_le_bytes(data[28..32].try_into().ok()?);
        Some(Self {
            seq,
            state,
            mono_ns,
            flags,
            boot_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned canonical-byte fixture. ANY change to this is a wire-format
    /// break — both host and guest must update together. The fixture is
    /// duplicated in legacy locations during the migration; once
    /// vm-transport is the sole source, this is the only copy.
    #[test]
    fn canonical_wire_bytes() {
        let hb = Heartbeat {
            seq: 0x11223344,
            state: GuestState::Running,
            mono_ns: 0x5566_7788_99AA_BBCC,
            flags: HB_FLAG_SERVICES_READY,
            boot_id: 0xCAFE_BABE,
        };
        let expected: [u8; HEARTBEAT_WIRE_SIZE] = [
            // magic "HBTH"
            0x48, 0x54, 0x42, 0x48, // version = 1
            0x01, 0x00, 0x00, 0x00, // seq = 0x11223344 LE
            0x44, 0x33, 0x22, 0x11, // state = Running (1)
            0x01, 0x00, 0x00, 0x00, // mono_ns = 0x5566_7788_99AA_BBCC LE
            0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, // flags = 1
            0x01, 0x00, 0x00, 0x00, // boot_id = 0xCAFE_BABE LE
            0xBE, 0xBA, 0xFE, 0xCA,
        ];
        assert_eq!(hb.to_bytes(), expected);
        let decoded = Heartbeat::from_bytes(&expected).expect("must decode");
        assert_eq!(decoded, hb);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = [0u8; HEARTBEAT_WIRE_SIZE];
        bytes[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        assert!(Heartbeat::from_bytes(&bytes).is_none());
    }

    #[test]
    fn rejects_bad_version() {
        let mut bytes = [0u8; HEARTBEAT_WIRE_SIZE];
        bytes[0..4].copy_from_slice(&HEARTBEAT_MAGIC.to_le_bytes());
        bytes[4..8].copy_from_slice(&99u32.to_le_bytes());
        assert!(Heartbeat::from_bytes(&bytes).is_none());
    }

    #[test]
    fn rejects_short_input() {
        let bytes = [0u8; HEARTBEAT_WIRE_SIZE - 1];
        assert!(Heartbeat::from_bytes(&bytes).is_none());
    }

    #[test]
    fn rejects_bad_state() {
        let hb = Heartbeat {
            seq: 1,
            state: GuestState::Booting,
            mono_ns: 0,
            flags: 0,
            boot_id: 0,
        };
        let mut bytes = hb.to_bytes();
        bytes[12..16].copy_from_slice(&99u32.to_le_bytes());
        assert!(Heartbeat::from_bytes(&bytes).is_none());
    }
}
