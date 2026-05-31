//! Power-command wire format — host publishes, guest reads.
//!
//! 8-byte little-endian payload:
//!
//! ```text
//!   0..4   seq  (u32, monotonic from host)
//!   4..8   cmd  (u32, PowerCommand code)
//! ```
//!
//! Pinned by `canonical_wire_bytes` test fixture below — host and guest
//! consumers of this crate see identical bytes by construction.

/// Wire size in bytes.
pub const POWER_WIRE_SIZE: usize = 8;

/// Power command codes. Numeric values are part of the wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PowerCommand {
    None = 0,
    Shutdown = 1,
    Reboot = 2,
    Suspend = 3,
    Hibernate = 4,
    Freeze = 5,
}

impl PowerCommand {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::Shutdown),
            2 => Some(Self::Reboot),
            3 => Some(Self::Suspend),
            4 => Some(Self::Hibernate),
            5 => Some(Self::Freeze),
            _ => None,
        }
    }
}

/// One frame on the wire — what the host published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowerCommandFrame {
    pub seq: u32,
    pub cmd: PowerCommand,
}

impl PowerCommandFrame {
    pub fn to_bytes(&self) -> [u8; POWER_WIRE_SIZE] {
        let mut buf = [0u8; POWER_WIRE_SIZE];
        buf[0..4].copy_from_slice(&self.seq.to_le_bytes());
        buf[4..8].copy_from_slice(&(self.cmd as u32).to_le_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < POWER_WIRE_SIZE {
            return None;
        }
        let seq = u32::from_le_bytes(data[0..4].try_into().ok()?);
        let cmd = PowerCommand::from_u32(u32::from_le_bytes(data[4..8].try_into().ok()?))?;
        Some(Self { seq, cmd })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned canonical-byte fixture — wire-format break detector.
    #[test]
    fn canonical_wire_bytes() {
        let frame = PowerCommandFrame {
            seq: 0x11223344,
            cmd: PowerCommand::Reboot,
        };
        let expected: [u8; POWER_WIRE_SIZE] = [
            // seq = 0x11223344 LE
            0x44, 0x33, 0x22, 0x11, // cmd = Reboot (2)
            0x02, 0x00, 0x00, 0x00,
        ];
        assert_eq!(frame.to_bytes(), expected);
        let decoded = PowerCommandFrame::from_bytes(&expected).expect("must decode");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn rejects_bad_cmd() {
        let mut bytes = [0u8; POWER_WIRE_SIZE];
        bytes[4..8].copy_from_slice(&99u32.to_le_bytes());
        assert!(PowerCommandFrame::from_bytes(&bytes).is_none());
    }

    #[test]
    fn rejects_short_input() {
        let bytes = [0u8; POWER_WIRE_SIZE - 1];
        assert!(PowerCommandFrame::from_bytes(&bytes).is_none());
    }

    #[test]
    fn power_command_round_trip_all_variants() {
        for cmd in [
            PowerCommand::None,
            PowerCommand::Shutdown,
            PowerCommand::Reboot,
            PowerCommand::Suspend,
            PowerCommand::Hibernate,
            PowerCommand::Freeze,
        ] {
            let frame = PowerCommandFrame { seq: 7, cmd };
            assert_eq!(
                PowerCommandFrame::from_bytes(&frame.to_bytes()),
                Some(frame)
            );
        }
    }
}
