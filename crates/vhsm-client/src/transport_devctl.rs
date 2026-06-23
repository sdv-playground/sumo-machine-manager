//! QNX `/dev/vhsm` devctl transport.
//!
//! The privileged in-guest path: the local vhsm-daemon's resmgr publishes
//! `/dev/vhsm` and captures the caller's uid/gid/pid at open time, so each
//! `devctl(DCMD_VHSM_OP)` inherits that identity for the daemon's `devctl_allowed`
//! check. One devctl call is one full request/response round-trip.
//!
//! Wire shape (mirrors the daemon's `VhsmDevctlIo`):
//!
//! ```text
//!  0..4   op                u32
//!  4..8   session_id        u32
//!  8..12  req_payload_len   u32
//! 12..16  _pad0
//! 16..20  status            u32     (set by server)
//! 20..24  resp_payload_len  u32     (set by server)
//! 24..32  _pad1
//! 32..8032  payload[8000]   request bytes in, response bytes out
//! ```
//!
//! `DCMD_VHSM_OP` is `diotf(0x4800, 0x01, 8032)` — computed via the same `diotf`
//! formula the daemon registers with, so there is no hardcoded magic to drift.

#![cfg(target_os = "nto")]

use std::ffi::CString;
use std::io;
use std::mem::size_of;
use std::os::raw::{c_int, c_void};
use std::ptr;

use vhsm_proto::Response;

use crate::Transport;

const POSIX_DEVDIR_TOFROM: u32 = 0xC000_0000;
const DCMD_CLASS_VHSM: u32 = 0x4800;
const VHSM_DEVCTL_MAX_PAYLOAD: usize = 8000;

const fn diotf(class: u32, code: u32, size: usize) -> u32 {
    POSIX_DEVDIR_TOFROM | ((size as u32) << 16) | class | code
}

/// Must match the daemon's `DCMD_VHSM_OP`.
const DCMD_VHSM_OP: u32 = diotf(DCMD_CLASS_VHSM, 0x01, size_of::<VhsmDevctlIo>());

#[repr(C)]
#[derive(Clone, Copy)]
struct VhsmDevctlIo {
    op: u32,
    session_id: u32,
    req_payload_len: u32,
    _pad0: u32,
    status: u32,
    resp_payload_len: u32,
    _pad1: [u32; 2],
    payload: [u8; VHSM_DEVCTL_MAX_PAYLOAD],
}

const _: () = assert!(size_of::<VhsmDevctlIo>() == 8032);

impl Default for VhsmDevctlIo {
    fn default() -> Self {
        Self {
            op: 0,
            session_id: 0,
            req_payload_len: 0,
            _pad0: 0,
            status: 0,
            resp_payload_len: 0,
            _pad1: [0; 2],
            payload: [0; VHSM_DEVCTL_MAX_PAYLOAD],
        }
    }
}

// QNX libc has devctl(); the Rust libc-crate nto bindings don't re-export it,
// so declare it ourselves (same pattern as the guest device backends).
extern "C" {
    fn devctl(
        fd: c_int,
        dcmd: c_int,
        data: *mut c_void,
        n: libc::size_t,
        info: *mut c_int,
    ) -> c_int;
}

/// Default path the local vhsm-daemon resmgr publishes itself at.
pub const DEFAULT_DEVCTL_PATH: &str = "/dev/vhsm";

/// Owns an open fd on `/dev/vhsm`, issuing `DCMD_VHSM_OP` per request.
pub struct DevctlTransport {
    fd: c_int,
}

impl DevctlTransport {
    /// Open `path` (typically `/dev/vhsm`) read-write. The resmgr captures
    /// uid/gid/pid at open time; subsequent devctl calls inherit that identity.
    pub fn open(path: &str) -> io::Result<Self> {
        let cpath = CString::new(path)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
        // SAFETY: cpath is a valid C string we own; flags is a constant.
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }
}

impl Transport for DevctlTransport {
    fn request(&mut self, op: u32, session_id: u32, payload: &[u8]) -> io::Result<Response> {
        if payload.len() > VHSM_DEVCTL_MAX_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "payload exceeds VHSM_DEVCTL_MAX_PAYLOAD",
            ));
        }

        let mut io_buf = VhsmDevctlIo {
            op,
            session_id,
            req_payload_len: payload.len() as u32,
            ..VhsmDevctlIo::default()
        };
        io_buf.payload[..payload.len()].copy_from_slice(payload);

        // SAFETY: io_buf is a valid VhsmDevctlIo we own; fd is valid (set by a
        // successful open()); size is the exact struct size.
        let rc = unsafe {
            devctl(
                self.fd,
                DCMD_VHSM_OP as c_int,
                &mut io_buf as *mut _ as *mut c_void,
                size_of::<VhsmDevctlIo>(),
                ptr::null_mut(),
            )
        };
        if rc != 0 {
            // devctl returns errno directly on failure (not -1 + errno).
            return Err(io::Error::from_raw_os_error(rc));
        }

        let resp_len = io_buf.resp_payload_len as usize;
        if resp_len > VHSM_DEVCTL_MAX_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "resp_payload_len out of range",
            ));
        }

        // devctl is a synchronous syscall — no desync is possible — so echo the
        // request's op/session_id (what `VhsmClient::call` checks against).
        Ok(Response {
            op,
            session_id,
            status: io_buf.status,
            payload: io_buf.payload[..resp_len].to_vec(),
        })
    }
}

impl Drop for DevctlTransport {
    fn drop(&mut self) {
        // SAFETY: fd was set by a successful open(); we own it for self's life.
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}
