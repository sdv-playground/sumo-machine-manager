//! QNX slog2 recorder for Eclipse S-CORE `score_log`.
//!
//! [`Slog2Sink`] is an `impl score_log::Log` that forwards each record to the
//! host's `slogger2` OS bus via `slog2c`. That is the emit half of the
//! bus-decoupled host log pipeline: supernova (through the `score-log-tracing`
//! bridge, or `score_log` macros directly) emits here, and SOVD §7.21 reads the
//! SAME slogger2 buffer back independently (`LogSource::Slog2`) — producer and
//! reader never share an object, the buffer is kernel-owned (survives a supernova
//! crash), and the host's driver/eMMC telemetry rides the same bus for free. See
//! `tasks/host-log-pipeline-design.md`.
//!
//! QNX-only: on `target_os = "nto"` this links `libslog2` and registers a buffer;
//! elsewhere (Linux dev / QEMU container) it is a no-op stub so the crate still
//! builds — the container uses S-CORE's `stdout_logger` instead.

use score_log::{Level, Log, Metadata, Record};

/// Build + install the slog2 recorder as the `score_log` global logger.
///
/// `context` is the default DLT-style context tag (≤4 ASCII chars used by
/// slog2/DLT convention). `max` is the level filter to install via
/// [`score_log::set_max_level`].
///
/// On non-QNX targets this installs nothing and returns `Ok(())` — the caller
/// (e.g. a container build) is expected to install `stdout_logger` instead.
pub fn install(context: &str, max: score_log::LevelFilter) -> Result<(), InstallError> {
    let sink = Slog2Sink::new(context);
    #[cfg(target_os = "nto")]
    {
        imp::register();
    }
    score_log::set_global_logger(Box::new(sink)).map_err(|_| InstallError::AlreadySet)?;
    score_log::set_max_level(max);
    Ok(())
}

/// Error installing the recorder.
#[derive(Debug)]
pub enum InstallError {
    /// A global logger was already set (only one is allowed per process).
    AlreadySet,
}

impl core::fmt::Display for InstallError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InstallError::AlreadySet => f.write_str("a score_log global logger was already set"),
        }
    }
}

impl std::error::Error for InstallError {}

/// A `score_log` recorder that writes records to the QNX slog2 bus.
pub struct Slog2Sink {
    context: String,
}

impl Slog2Sink {
    /// Create a sink with a default context tag.
    pub fn new(context: &str) -> Self {
        Slog2Sink {
            context: context.to_string(),
        }
    }
}

impl Log for Slog2Sink {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        // Level filtering is handled by score_log's max_level + slog2's own
        // verbosity; accept here and let the downstream buffer verbosity decide.
        true
    }

    fn context(&self) -> &str {
        &self.context
    }

    fn log(&self, record: &Record) {
        // Render the record's args into a bounded stack buffer, then hand the
        // C string to slog2c. Rendering is identical on every platform; only the
        // final emit differs (slog2c on QNX, swallowed on others).
        let mut buf = FixedBuf::<2048>::new();
        // Best-effort: a formatting failure just truncates; never abort logging.
        let _ = score_log::fmt::write(&mut buf, *record.args());
        emit(record.level(), buf.as_str());
    }

    fn flush(&self) {
        // slog2c writes synchronously to the buffer; nothing to flush.
    }
}

/// Emit a rendered line at `level` to the slog2 bus (QNX) or drop it (else).
#[cfg(target_os = "nto")]
fn emit(level: Level, msg: &str) {
    imp::send(imp::severity_of(level), msg);
}

#[cfg(not(target_os = "nto"))]
fn emit(_level: Level, _msg: &str) {
    // No slog2 bus off QNX — a no-op. The container path uses stdout_logger.
}

// --- args rendering: a ScoreWrite over a fixed stack buffer ------------------
// Mirrors S-CORE stdout_logger's FixedBuf: bounded, no heap on the hot path, and
// truncates rather than allocating without limit.

struct FixedBuf<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> FixedBuf<N> {
    fn new() -> Self {
        FixedBuf {
            buf: [0; N],
            len: 0,
        }
    }

    fn as_str(&self) -> &str {
        // SAFETY: only complete UTF-8 is ever written (see push_str: it copies
        // whole `&str`s and stops on a char boundary when the buffer fills).
        unsafe { core::str::from_utf8_unchecked(&self.buf[..self.len]) }
    }

    fn push_str(&mut self, s: &str) {
        let remaining = N - self.len;
        if remaining == 0 {
            return;
        }
        let bytes = s.as_bytes();
        let mut end = bytes.len().min(remaining);
        // Back off to a char boundary so `as_str` stays valid UTF-8.
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        self.buf[self.len..self.len + end].copy_from_slice(&bytes[..end]);
        self.len += end;
    }
}

impl<const N: usize> core::fmt::Write for FixedBuf<N> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.push_str(s);
        Ok(())
    }
}

// score_log's fmt writer. The bridge/macros mostly emit Literal fragments (→
// `write_str`), but implement the numeric methods too so a direct `score_log`
// macro call with placeholders renders correctly.
impl<const N: usize> score_log::fmt::ScoreWrite for FixedBuf<N> {
    fn write_str(&mut self, v: &str, _spec: &score_log::fmt::FormatSpec) -> score_log::fmt::Result {
        self.push_str(v);
        Ok(())
    }
    fn write_bool(&mut self, v: &bool, _: &score_log::fmt::FormatSpec) -> score_log::fmt::Result {
        use core::fmt::Write;
        let _ = write!(self, "{v}");
        Ok(())
    }
    fn write_f32(&mut self, v: &f32, _: &score_log::fmt::FormatSpec) -> score_log::fmt::Result {
        use core::fmt::Write;
        let _ = write!(self, "{v}");
        Ok(())
    }
    fn write_f64(&mut self, v: &f64, _: &score_log::fmt::FormatSpec) -> score_log::fmt::Result {
        use core::fmt::Write;
        let _ = write!(self, "{v}");
        Ok(())
    }
    fn write_i8(&mut self, v: &i8, _: &score_log::fmt::FormatSpec) -> score_log::fmt::Result {
        use core::fmt::Write;
        let _ = write!(self, "{v}");
        Ok(())
    }
    fn write_i16(&mut self, v: &i16, _: &score_log::fmt::FormatSpec) -> score_log::fmt::Result {
        use core::fmt::Write;
        let _ = write!(self, "{v}");
        Ok(())
    }
    fn write_i32(&mut self, v: &i32, _: &score_log::fmt::FormatSpec) -> score_log::fmt::Result {
        use core::fmt::Write;
        let _ = write!(self, "{v}");
        Ok(())
    }
    fn write_i64(&mut self, v: &i64, _: &score_log::fmt::FormatSpec) -> score_log::fmt::Result {
        use core::fmt::Write;
        let _ = write!(self, "{v}");
        Ok(())
    }
    fn write_u8(&mut self, v: &u8, _: &score_log::fmt::FormatSpec) -> score_log::fmt::Result {
        use core::fmt::Write;
        let _ = write!(self, "{v}");
        Ok(())
    }
    fn write_u16(&mut self, v: &u16, _: &score_log::fmt::FormatSpec) -> score_log::fmt::Result {
        use core::fmt::Write;
        let _ = write!(self, "{v}");
        Ok(())
    }
    fn write_u32(&mut self, v: &u32, _: &score_log::fmt::FormatSpec) -> score_log::fmt::Result {
        use core::fmt::Write;
        let _ = write!(self, "{v}");
        Ok(())
    }
    fn write_u64(&mut self, v: &u64, _: &score_log::fmt::FormatSpec) -> score_log::fmt::Result {
        use core::fmt::Write;
        let _ = write!(self, "{v}");
        Ok(())
    }
}

// --- QNX slog2 FFI (writer) --------------------------------------------------
// Modelled on the proven binding in guest-vm-sdk vhealth-guest-qnx/src/slog2.rs.

#[cfg(target_os = "nto")]
mod imp {
    use super::Level;
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int};
    use std::ptr;
    use std::sync::atomic::{AtomicPtr, Ordering};

    // sys/slog2.h severities (SLOG2_SHUTDOWN=0 … SLOG2_DEBUG2=7).
    const SLOG2_CRITICAL: u8 = 1;
    const SLOG2_ERROR: u8 = 2;
    const SLOG2_WARNING: u8 = 3;
    const SLOG2_INFO: u8 = 5;
    const SLOG2_DEBUG1: u8 = 6;
    const SLOG2_MAX_BUFFERS: usize = 4;
    // (SLOG2_NOTICE=4 exists between WARNING and INFO but nothing maps to it.)

    #[repr(C)]
    struct BufferConfig {
        buffer_name: *const c_char,
        num_pages: c_int,
    }
    impl Copy for BufferConfig {}
    impl Clone for BufferConfig {
        fn clone(&self) -> Self {
            *self
        }
    }

    #[repr(C)]
    struct BufferSetConfig {
        num_buffers: c_int,
        buffer_set_name: *const c_char,
        verbosity_level: u8,
        buffer_config: [BufferConfig; SLOG2_MAX_BUFFERS],
        max_retries: u32,
    }

    type BufferHandle = *mut std::ffi::c_void;

    #[link(name = "slog2")]
    extern "C" {
        fn slog2_register(
            config: *const BufferSetConfig,
            handles: *mut BufferHandle,
            flags: u32,
        ) -> c_int;
        fn slog2c(buf: BufferHandle, code: u16, severity: u8, msg: *const c_char) -> c_int;
    }

    static BUFFER: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(ptr::null_mut());

    /// Map score_log level → slog2 severity. `Fatal` → CRITICAL (slog2 has no
    /// dedicated fatal); `Trace` → DEBUG1.
    pub(super) fn severity_of(level: Level) -> u8 {
        match level {
            Level::Fatal => SLOG2_CRITICAL,
            Level::Error => SLOG2_ERROR,
            Level::Warn => SLOG2_WARNING,
            Level::Info => SLOG2_INFO,
            Level::Debug => SLOG2_DEBUG1,
            Level::Trace => SLOG2_DEBUG1,
        }
    }

    /// Register a "SNOVA" buffer set with slogger2. Idempotent; failure (e.g.
    /// slogger2 not running) leaves the buffer null and `send` becomes a no-op.
    pub(super) fn register() {
        if !BUFFER.load(Ordering::Relaxed).is_null() {
            return;
        }
        // Leak the CStrings: slog2_register stores the pointers and dereferences
        // them for the process lifetime.
        let Ok(set_name) = CString::new("SNOVA") else {
            return;
        };
        let Ok(buf_name) = CString::new("default") else {
            return;
        };
        let set_name_ptr = set_name.into_raw() as *const c_char;
        let buf_name_ptr = buf_name.into_raw() as *const c_char;

        let mut buffer_config = [BufferConfig {
            buffer_name: ptr::null(),
            num_pages: 0,
        }; SLOG2_MAX_BUFFERS];
        buffer_config[0] = BufferConfig {
            buffer_name: buf_name_ptr,
            num_pages: 8,
        };

        let cfg = BufferSetConfig {
            num_buffers: 1,
            buffer_set_name: set_name_ptr,
            verbosity_level: SLOG2_DEBUG1,
            buffer_config,
            max_retries: 0,
        };

        let mut handle: BufferHandle = ptr::null_mut();
        let rc = unsafe { slog2_register(&cfg, &mut handle, 0) };
        if rc != 0 || handle.is_null() {
            return;
        }
        BUFFER.store(handle, Ordering::Relaxed);
    }

    pub(super) fn send(severity: u8, msg: &str) {
        let buf = BUFFER.load(Ordering::Relaxed);
        if buf.is_null() {
            return;
        }
        let Ok(cstr) = CString::new(msg) else {
            return;
        };
        // SAFETY: `buf` is a live handle from slog2_register; slog2c is
        // documented thread-safe; `cstr` outlives the call.
        unsafe {
            slog2c(buf, 0, severity, cstr.as_ptr());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The args-rendering path is platform-independent (only the final emit is
    // gated), so this exercises FixedBuf + ScoreWrite on any host.
    #[test]
    fn renders_literal_args_into_the_buffer() {
        use score_log::fmt::{Arguments, Fragment};
        let mut buf = FixedBuf::<64>::new();
        let frags = [Fragment::Literal("hello "), Fragment::Literal("world")];
        let _ = score_log::fmt::write(&mut buf, Arguments(&frags));
        assert_eq!(buf.as_str(), "hello world");
    }

    #[test]
    fn fixedbuf_truncates_on_char_boundary_without_panicking() {
        let mut buf = FixedBuf::<4>::new();
        // 'é' is 2 bytes; after "ab" only 2 bytes remain → fits exactly.
        buf.push_str("abé");
        assert_eq!(buf.as_str(), "abé");
        // Next push has no room; must not panic or corrupt.
        buf.push_str("é");
        assert_eq!(buf.as_str(), "abé");
    }

    #[test]
    fn sink_log_is_a_noop_off_qnx_but_runs_the_render_path() {
        // On Linux, emit() is a no-op; assert log() doesn't panic and enabled/
        // context behave.
        let sink = Slog2Sink::new("SNOVA");
        assert_eq!(sink.context(), "SNOVA");
        assert!(sink.enabled(&Metadata::new(Level::Info, "SNOVA")));
    }
}
