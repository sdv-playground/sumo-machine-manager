//! gPTP-corrected clock source.
//!
//! Reads the monotonic-to-gPTP wall offset from a shared memory region
//! written by ptp4l (or equivalent gPTP daemon). Falls back to system
//! wall clock if gPTP data is stale or unavailable.
//!
//! # How gPTP Feeds In
//!
//! gPTP (IEEE 802.1AS) synchronizes clocks across a network. It provides
//! a correction to apply to the local monotonic clock — not a replacement
//! clock. The `wall_offset_ns` in vtime registers is exactly this correction.
//!
//! The designated sync guest (or host) runs `ptp4l` and writes the
//! master_offset to a shared memory segment. This clock reads it.
//!
//! # Shared Memory Layout (from ptp4l --shm)
//!
//! ```text
//! Offset  Size  Field
//! 0x00    8     master_offset_ns (i64) — offset from local to grandmaster
//! 0x08    4     sync_source (u32) — VTIME_SRC_GPTP
//! 0x0C    4     sync_quality (u32) — VTIME_QUALITY_FINE
//! 0x10    8     last_update_ns (u64) — monotonic time of last update
//! ```

use std::path::Path;

use super::system::SystemClock;
use super::Clock;

/// Maximum age before gPTP data is considered stale (5 seconds).
const STALENESS_THRESHOLD_NS: u64 = 5_000_000_000;

/// gPTP correction shared memory layout.
const OFFSET_MASTER_OFFSET: usize = 0x00;
const OFFSET_LAST_UPDATE: usize = 0x10;

/// gPTP-corrected clock.
///
/// Reads the wall offset from ptp4l's shared memory. If the data is
/// stale or unavailable, falls back to the system wall clock.
pub struct GptpClock {
    system: SystemClock,
    /// Memory-mapped ptp4l shared memory region (if available).
    shm_ptr: Option<*const u8>,
    shm_size: usize,
}

unsafe impl Send for GptpClock {}
unsafe impl Sync for GptpClock {}

impl Default for GptpClock {
    fn default() -> Self {
        Self::new()
    }
}

impl GptpClock {
    /// Create without gPTP — behaves like SystemClock.
    pub fn new() -> Self {
        Self {
            system: SystemClock::new(),
            shm_ptr: None,
            shm_size: 0,
        }
    }

    /// Open gPTP correction shared memory by POSIX shm name.
    pub fn with_shm(name: &str, size: usize) -> Result<Self, std::io::Error> {
        let c_name = std::ffi::CString::new(name)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad shm name"))?;

        let fd = unsafe { libc::shm_open(c_name.as_ptr(), libc::O_RDONLY, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        unsafe { libc::close(fd) };

        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self {
            system: SystemClock::new(),
            shm_ptr: Some(ptr as *const u8),
            shm_size: size,
        })
    }

    /// Open gPTP correction from a file path (e.g., /dev/shm/ptp-offset).
    pub fn with_file(path: &Path) -> Result<Self, std::io::Error> {
        let file = std::fs::OpenOptions::new().read(true).open(path)?;
        let size = file.metadata()?.len() as usize;
        if size < 0x18 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "gPTP shm too small",
            ));
        }

        let fd = {
            use std::os::unix::io::AsRawFd;
            file.as_raw_fd()
        };

        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        std::mem::forget(file);

        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self {
            system: SystemClock::new(),
            shm_ptr: Some(ptr as *const u8),
            shm_size: size,
        })
    }

    /// Read the gPTP master offset if available and fresh.
    fn gptp_offset(&self) -> Option<i64> {
        let ptr = self.shm_ptr?;
        if self.shm_size < 0x18 {
            return None;
        }

        let last_update =
            unsafe { core::ptr::read_volatile(ptr.add(OFFSET_LAST_UPDATE) as *const u64) };
        let now = self.system.now_mono_ns();

        // Check staleness
        if now.saturating_sub(last_update) > STALENESS_THRESHOLD_NS {
            return None;
        }

        let offset =
            unsafe { core::ptr::read_volatile(ptr.add(OFFSET_MASTER_OFFSET) as *const i64) };
        Some(offset)
    }
}

impl Drop for GptpClock {
    fn drop(&mut self) {
        if let Some(ptr) = self.shm_ptr {
            unsafe { libc::munmap(ptr as *mut libc::c_void, self.shm_size) };
        }
    }
}

impl Clock for GptpClock {
    fn now_mono_ns(&self) -> u64 {
        self.system.now_mono_ns()
    }

    fn wall_offset_ns(&self) -> i64 {
        // Prefer gPTP offset if available and fresh
        if let Some(gptp_off) = self.gptp_offset() {
            return gptp_off;
        }
        // Fallback to system wall clock
        self.system.wall_offset_ns()
    }
}
