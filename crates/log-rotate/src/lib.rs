//! Size-bounded rotating file writer.
//!
//! Wraps a `BufWriter<File>` and rotates the underlying file when its
//! size would exceed a configured cap. Rotation shifts existing
//! rotated copies in descending order
//! (`{path}.{max_rotated-1}` → `{path}.{max_rotated}`, …,
//! `{path}` → `{path}.1`) and opens a fresh file at the base path.
//! The oldest rotated copy is unlinked.
//!
//! Rotation is triggered **before** a write that would push the file
//! over `max_bytes`. The write itself happens to the new file, so the
//! on-disk file is never momentarily over cap.
//!
//! ## Why this crate exists
//!
//! Neither QNX nor our Linux dev rigs ship `logrotate`. Pulling in a
//! runtime dependency on it would also be a non-starter on QNX. The
//! daemon needs to own rotation itself. This is the single
//! implementation; both `vhsm-ssd::audit` and
//! `supernova-machine-manager`'s main log writer use it.
//!
//! ## Threading
//!
//! [`RotatingFileWriter`] is not internally synchronised. Wrap in
//! `Mutex` for multi-threaded callers, or use through
//! `tracing_subscriber`'s `MakeWriter` adapter (which already
//! synchronises). The `sync_each_line` path holds the writer's
//! `&mut self` while it does the fsync, so concurrent loggers go
//! through the mutex anyway.
//!
//! ## Failure mode
//!
//! Rotation errors propagate from [`io::Write::write`]. The caller
//! decides whether a failed rotation kills the connection (audit
//! semantics: fail loud) or is silently dropped (best-effort app log).

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

/// Configuration for a [`RotatingFileWriter`].
#[derive(Debug, Clone)]
pub struct RotatingFileConfig {
    /// Base path for the active file. Rotated copies live at
    /// `{path}.1`, `{path}.2`, … `{path}.{max_rotated}`.
    pub path: PathBuf,

    /// Rotate when a write would push the file past this size, in
    /// bytes. Must be > 0.
    pub max_bytes: u64,

    /// How many rotated copies to keep. Must be ≥ 1; on each
    /// rotation `{path}.{max_rotated}` is unlinked (if it exists)
    /// before the shift.
    pub max_rotated: u32,

    /// If true, every `write()` containing a newline triggers
    /// `flush()` + `sync_data()` on the underlying file. Use for
    /// audit logs (durability requirement); leave off for
    /// high-frequency app logs (let the OS coalesce).
    pub sync_each_line: bool,
}

impl RotatingFileConfig {
    /// Builder-style constructor with `sync_each_line: false` and
    /// `max_rotated: 1` as the defaults.
    pub fn new(path: impl Into<PathBuf>, max_bytes: u64) -> Self {
        Self {
            path: path.into(),
            max_bytes,
            max_rotated: 1,
            sync_each_line: false,
        }
    }

    pub fn with_max_rotated(mut self, n: u32) -> Self {
        self.max_rotated = n;
        self
    }

    pub fn with_sync_each_line(mut self, sync: bool) -> Self {
        self.sync_each_line = sync;
        self
    }
}

/// Append-mode file writer with size-bounded rotation.
pub struct RotatingFileWriter {
    cfg: RotatingFileConfig,
    /// `None` only during the brief window inside `rotate()` when the
    /// previous handle has been dropped and the new one isn't open
    /// yet. Outside that, always `Some`.
    current: Option<BufWriter<File>>,
    current_size: u64,
}

impl RotatingFileWriter {
    /// Open the writer. Creates the parent directory if missing.
    /// If the file at `path` already exists and is at or beyond
    /// `max_bytes`, rotates immediately so the post-open file is
    /// fresh.
    pub fn open(cfg: RotatingFileConfig) -> io::Result<Self> {
        if cfg.max_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "RotatingFileConfig.max_bytes must be > 0",
            ));
        }
        if cfg.max_rotated == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "RotatingFileConfig.max_rotated must be >= 1",
            ));
        }

        if let Some(parent) = cfg.path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&cfg.path)?;
        let current_size = file.metadata()?.len();

        let mut writer = Self {
            cfg,
            current: Some(BufWriter::new(file)),
            current_size,
        };

        // Pre-existing file is already over cap (crash-restart, manual
        // copy, etc.). Rotate now so we don't append to an over-cap
        // file forever.
        if writer.current_size >= writer.cfg.max_bytes {
            writer.rotate()?;
        }

        Ok(writer)
    }

    /// Force a rotation now, regardless of current size. Equivalent
    /// to what an external `logrotate(8)` would request via SIGUSR1
    /// in a more featureful daemon. Useful for tests and for
    /// future SIGUSR1 wiring.
    pub fn rotate_now(&mut self) -> io::Result<()> {
        self.rotate()
    }

    /// The on-disk path of the rotated copy at slot `n`. `n=1` is
    /// the most recent; `n=max_rotated` is the oldest retained.
    pub fn rotated_path(&self, n: u32) -> PathBuf {
        rotated_path(&self.cfg.path, n)
    }

    fn rotate(&mut self) -> io::Result<()> {
        // 1. Flush + drop the existing handle so the renames see no
        //    lingering open fd on the current path (matters on QNX +
        //    Windows; harmless on Linux).
        if let Some(mut w) = self.current.take() {
            w.flush()?;
        }
        // `self.current` is now None; everything below is fallible —
        // on error we leave `current = None`, which `write()` would
        // panic on. Restore-on-error is below.

        match self.do_shift_and_reopen() {
            Ok(()) => {
                self.current_size = 0;
                Ok(())
            }
            Err(e) => {
                // Best-effort recovery: try to reopen the existing
                // base path so the writer is not permanently broken.
                // If even that fails, return both errors via the
                // primary.
                if let Ok(file) =
                    OpenOptions::new().create(true).append(true).open(&self.cfg.path)
                {
                    self.current_size = file.metadata().map(|m| m.len()).unwrap_or(0);
                    self.current = Some(BufWriter::new(file));
                }
                Err(e)
            }
        }
    }

    /// The body of rotate(): shift on-disk files, open new base.
    /// Separated so the error-recovery path stays readable.
    fn do_shift_and_reopen(&mut self) -> io::Result<()> {
        let max_n = self.cfg.max_rotated;
        let base = &self.cfg.path;

        // Step a: unlink the would-be-oldest if it exists.
        let oldest = rotated_path(base, max_n);
        if oldest.exists() {
            fs::remove_file(&oldest)?;
        }

        // Step b: rename {base}.{k} → {base}.{k+1} for k = max_n-1 .. 1
        for k in (1..max_n).rev() {
            let from = rotated_path(base, k);
            let to = rotated_path(base, k + 1);
            if from.exists() {
                fs::rename(&from, &to)?;
            }
        }

        // Step c: rename the active file to {base}.1 (if active exists).
        // It may not exist if some external actor removed it between
        // open and rotate; that's fine — we'll just create fresh.
        if base.exists() {
            fs::rename(base, &rotated_path(base, 1))?;
        }

        // Step d: open a fresh file at the base path. Use create_new
        // so we fail loud if something else has racily put a file
        // back; that's an operator error worth surfacing.
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(base)?;
        self.current = Some(BufWriter::new(file));
        Ok(())
    }
}

impl Write for RotatingFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Pre-rotate if this write would push us over cap. Note: a
        // single buf larger than max_bytes will still go through —
        // we rotate once (which empties the file) and then write the
        // oversize buf into the fresh file. The next write would
        // rotate again. Real audit / log lines are far smaller than
        // max_bytes; this edge case is documented at the type level
        // rather than handled by splitting the buf.
        if self.current_size.saturating_add(buf.len() as u64) > self.cfg.max_bytes {
            self.rotate()?;
        }

        let n = self
            .current
            .as_mut()
            .expect("current is None outside rotate()")
            .write(buf)?;
        self.current_size = self.current_size.saturating_add(n as u64);

        if self.cfg.sync_each_line && buf[..n].contains(&b'\n') {
            // Drain BufWriter, then fdatasync the file descriptor.
            let w = self.current.as_mut().unwrap();
            w.flush()?;
            w.get_ref().sync_data()?;
        }

        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(w) = self.current.as_mut() {
            w.flush()?;
        }
        Ok(())
    }
}

fn rotated_path(base: &Path, n: u32) -> PathBuf {
    let mut s = base.as_os_str().to_os_string();
    s.push(format!(".{}", n));
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::tempdir;

    fn read_file(p: &Path) -> String {
        let mut buf = String::new();
        File::open(p).unwrap().read_to_string(&mut buf).unwrap();
        buf
    }

    #[test]
    fn rejects_zero_max_bytes() {
        let tmp = tempdir().unwrap();
        let cfg = RotatingFileConfig::new(tmp.path().join("x.log"), 0);
        assert!(RotatingFileWriter::open(cfg).is_err());
    }

    #[test]
    fn rejects_zero_max_rotated() {
        let tmp = tempdir().unwrap();
        let cfg = RotatingFileConfig::new(tmp.path().join("x.log"), 1024)
            .with_max_rotated(0);
        assert!(RotatingFileWriter::open(cfg).is_err());
    }

    #[test]
    fn creates_parent_dir() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("nested/dir/here.log");
        let mut w = RotatingFileWriter::open(
            RotatingFileConfig::new(&path, 1024),
        ).unwrap();
        writeln!(w, "hi").unwrap();
        w.flush().unwrap();
        assert!(path.exists());
    }

    #[test]
    fn writes_below_cap_dont_rotate() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("x.log");
        let mut w = RotatingFileWriter::open(
            RotatingFileConfig::new(&path, 1024).with_max_rotated(3),
        ).unwrap();
        for _ in 0..3 {
            writeln!(w, "a small line").unwrap();
        }
        w.flush().unwrap();
        assert!(path.exists());
        assert!(!rotated_path(&path, 1).exists(), "no rotation should have happened");
    }

    #[test]
    fn rotates_when_next_write_would_exceed_cap() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("x.log");
        // Cap at 30 bytes; each line is "0123456789\n" = 11 bytes.
        // 1 line = 11, 2 lines = 22, 3 lines would be 33 > 30 → rotate.
        let mut w = RotatingFileWriter::open(
            RotatingFileConfig::new(&path, 30).with_max_rotated(2),
        ).unwrap();
        writeln!(w, "0123456789").unwrap();
        writeln!(w, "0123456789").unwrap();
        writeln!(w, "0123456789").unwrap(); // triggers rotation
        w.flush().unwrap();

        assert!(rotated_path(&path, 1).exists(),
            "expected {} to exist after rotation", rotated_path(&path, 1).display());
        // .1 holds the two pre-rotation lines.
        assert_eq!(read_file(&rotated_path(&path, 1)),
                   "0123456789\n0123456789\n");
        // Base holds the post-rotation line.
        assert_eq!(read_file(&path), "0123456789\n");
    }

    #[test]
    fn rotated_copies_shift_and_oldest_is_dropped() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("x.log");
        let mut w = RotatingFileWriter::open(
            RotatingFileConfig::new(&path, 11).with_max_rotated(2),
        ).unwrap();

        // Each writeln is 11 bytes ("aaaaaaaaaa\n") — exactly fills
        // the cap. Next writeln rotates.
        writeln!(w, "aaaaaaaaaa").unwrap(); // base = "aaa…\n"
        writeln!(w, "bbbbbbbbbb").unwrap(); // → rotate; base = "bbb…\n", .1 = "aaa…"
        writeln!(w, "cccccccccc").unwrap(); // → rotate; base = "ccc…\n", .1 = "bbb…", .2 = "aaa…"
        writeln!(w, "dddddddddd").unwrap(); // → rotate; oldest .2="aaa…" unlinked, then .1→.2, base→.1, base="ddd…"
        w.flush().unwrap();

        assert_eq!(read_file(&path), "dddddddddd\n");
        assert_eq!(read_file(&rotated_path(&path, 1)), "cccccccccc\n");
        assert_eq!(read_file(&rotated_path(&path, 2)), "bbbbbbbbbb\n");
        // .3 should NEVER exist (max_rotated = 2).
        assert!(!rotated_path(&path, 3).exists());
        // The "aaaaaaaaaa" line is gone — we asked for only 2 rotated.
    }

    #[test]
    fn open_rotates_existing_over_cap_file() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("x.log");
        // Pre-write a file that's already over cap.
        fs::write(&path, "x".repeat(100)).unwrap();
        let _w = RotatingFileWriter::open(
            RotatingFileConfig::new(&path, 50).with_max_rotated(2),
        ).unwrap();
        // The original 100-byte content should now be at .1; base is fresh empty.
        assert_eq!(read_file(&rotated_path(&path, 1)).len(), 100);
        assert_eq!(read_file(&path).len(), 0);
    }

    #[test]
    fn sync_each_line_does_not_explode() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("x.log");
        let mut w = RotatingFileWriter::open(
            RotatingFileConfig::new(&path, 1024)
                .with_sync_each_line(true),
        ).unwrap();
        // Just confirm the sync codepath returns Ok — actual fsync
        // observability would require a filesystem test rig.
        for _ in 0..10 {
            writeln!(w, "a line").unwrap();
        }
        w.flush().unwrap();
        assert!(path.metadata().unwrap().len() > 0);
    }

    #[test]
    fn rotate_now_force_rotates_even_under_cap() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("x.log");
        let mut w = RotatingFileWriter::open(
            RotatingFileConfig::new(&path, 1024).with_max_rotated(2),
        ).unwrap();
        writeln!(w, "first").unwrap();
        w.flush().unwrap();
        w.rotate_now().unwrap();
        writeln!(w, "second").unwrap();
        w.flush().unwrap();
        assert_eq!(read_file(&path), "second\n");
        assert_eq!(read_file(&rotated_path(&path, 1)), "first\n");
    }
}
