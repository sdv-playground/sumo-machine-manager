//! SocketCAN backend for Linux using raw AF_CAN sockets.

use std::os::unix::io::RawFd;

use super::{CanBackend, CanError, CanFrame};

// CAN socket constants (not always in libc)
const AF_CAN: i32 = 29;
const PF_CAN: i32 = AF_CAN;
const CAN_RAW: i32 = 1;
const SOL_CAN_RAW: i32 = 101;
const CAN_RAW_FD_FRAMES: i32 = 5;

/// sockaddr_can (16 bytes)
#[repr(C)]
struct SockaddrCan {
    can_family: u16,
    can_ifindex: i32,
    _pad: [u8; 10],
}

/// SocketCAN backend — bridges CAN frames to/from a host CAN interface.
pub struct SocketCanBackend {
    fd: RawFd,
}

impl SocketCanBackend {
    /// Open a raw CAN socket bound to the named interface (e.g., "vcan1").
    pub fn open(ifname: &str) -> Result<Self, CanError> {
        let fd = unsafe { libc::socket(PF_CAN, libc::SOCK_RAW | libc::SOCK_NONBLOCK, CAN_RAW) };
        if fd < 0 {
            return Err(CanError::Io(std::io::Error::last_os_error()));
        }

        // Enable CAN FD
        let canfd_on: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                SOL_CAN_RAW,
                CAN_RAW_FD_FRAMES,
                &canfd_on as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(CanError::Io(std::io::Error::last_os_error()));
        }

        // Get interface index
        let ifindex = if_nametoindex(ifname).ok_or_else(|| {
            CanError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("CAN interface not found: {ifname}"),
            ))
        })?;

        // Bind to the interface
        let addr = SockaddrCan {
            can_family: AF_CAN as u16,
            can_ifindex: ifindex as i32,
            _pad: [0; 10],
        };
        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<SockaddrCan>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(CanError::Io(err));
        }

        Ok(Self { fd })
    }
}

impl Drop for SocketCanBackend {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}

impl CanBackend for SocketCanBackend {
    fn send(&mut self, frame: &CanFrame) -> Result<(), CanError> {
        // Use canfd_frame layout (72 bytes)
        let mut raw = [0u8; 72];
        raw[0..4].copy_from_slice(&frame.id.to_le_bytes());
        raw[4] = frame.len;
        raw[5] = frame.flags;
        let dlen = frame.len.min(64) as usize;
        raw[8..8 + dlen].copy_from_slice(&frame.data[..dlen]);

        let n = unsafe { libc::write(self.fd, raw.as_ptr() as *const libc::c_void, 72) };
        if n < 0 {
            return Err(CanError::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    fn try_recv(&mut self, frame: &mut CanFrame) -> Result<bool, CanError> {
        let mut raw = [0u8; 72];
        let n = unsafe { libc::read(self.fd, raw.as_mut_ptr() as *mut libc::c_void, 72) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(false);
            }
            return Err(CanError::Io(err));
        }
        if n < 8 {
            return Ok(false);
        }

        frame.id = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        frame.len = raw[4];
        frame.flags = raw[5];
        frame._pad = [0; 2];
        frame.data = [0; 64];
        let dlen = frame.len.min(64) as usize;
        frame.data[..dlen].copy_from_slice(&raw[8..8 + dlen]);
        Ok(true)
    }
}

fn if_nametoindex(name: &str) -> Option<u32> {
    let c_name = std::ffi::CString::new(name).ok()?;
    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if idx == 0 {
        None
    } else {
        Some(idx)
    }
}
