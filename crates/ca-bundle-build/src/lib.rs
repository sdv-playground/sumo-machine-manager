//! Build read-only CA-bundle images for distribution inside vm-bank
//! SUIT envelopes. Per-VM, one image per guest OS family.
//!
//! Two image formats supported, mirroring policy-build:
//!
//! - **squashfs** for Linux guests. Carries the full
//!   `/etc/pki/ca-trust/extracted/` tree; mounted by systemd at the
//!   same path so curl/openssl/podman/java find their bundles unchanged.
//! - **qnx6** for QNX guests. Carries a single concatenated PEM
//!   (`ca-certificates.crt`); mounted at `/etc/ssl/certs/` and
//!   surfaced to openssl via `SSL_CERT_FILE`.
//!
//! Both formats arrive at the device as a single file in the bank
//! (`bank_a/ca-bundle.sqfs` or `bank_a/ca-bundle.qnx6`). At guest
//! startup, the file is mounted before any TLS-using service starts.
//!
//! ## Build flow
//!
//! ```text
//! /path/to/source/ca-bundle/        ← directory of bundle files
//!   pem/tls-ca-bundle.pem
//!   openssl/ca-bundle.trust.crt
//!   ...
//!         │
//!         ▼  CaBundleImageBuilder::new(...)
//!         │  .with_format(ImageFormat::Squashfs)
//!         │  .build(&output_path)?;
//!         ▼
//! /path/to/output/ca-bundle.sqfs    ← read-only image, ready to ship
//! ```
//!
//! ## No input validation
//!
//! Unlike policy-build, the bundle is opaque PEM/blob content — there's
//! no schema we can parse to catch malformed input early. The builder
//! only checks that the source is a directory and contains at least
//! one regular file; everything else surfaces as an openssl-level
//! "x509: certificate signed by unknown authority" at runtime if
//! the operator shipped garbage.

use std::path::{Path, PathBuf};
use std::process::Command;

// =============================================================================
// Format selection
// =============================================================================

/// On-disk format of the produced image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    /// squashfs — Linux guests. Requires `mksquashfs` (squashfs-tools)
    /// on the host build machine.
    Squashfs,
    /// qnx6 — QNX guests. Requires `mkqnx6fsimg` from the QNX SDP and
    /// `QNX_TARGET` set in env. Mirrors policy-build's qnx6 path.
    Qnx6,
}

impl ImageFormat {
    pub fn extension(self) -> &'static str {
        match self {
            ImageFormat::Squashfs => "sqfs",
            ImageFormat::Qnx6 => "qnx6",
        }
    }
}

// =============================================================================
// Builder
// =============================================================================

/// Builder for a single CA-bundle image.
#[derive(Debug, Clone)]
pub struct CaBundleImageBuilder {
    pub source_dir: PathBuf,
    pub format: ImageFormat,
    /// Override the build tool path. Default: `mksquashfs` / `mkqnx6fsimg`
    /// from `$PATH`.
    pub tool_path: Option<PathBuf>,
    /// Override the qnx6 image's `num_sectors` (512-byte sectors).
    /// `None` → 8192 (4 MB). Same reasoning as policy-build: under
    /// ~2048 sectors trips io-blk's strict size check and devb-loopback
    /// silently drops the registration. 4 MB is plenty for a single
    /// concatenated PEM (~250 KB) with room to grow.
    pub qnx6_num_sectors: Option<u32>,
}

impl CaBundleImageBuilder {
    pub fn new(source_dir: impl AsRef<Path>, format: ImageFormat) -> Self {
        Self {
            source_dir: source_dir.as_ref().to_path_buf(),
            format,
            tool_path: None,
            qnx6_num_sectors: None,
        }
    }

    pub fn with_qnx6_num_sectors(mut self, sectors: u32) -> Self {
        self.qnx6_num_sectors = Some(sectors);
        self
    }

    pub fn with_tool_path(mut self, tool: impl AsRef<Path>) -> Self {
        self.tool_path = Some(tool.as_ref().to_path_buf());
        self
    }

    /// Build the image at `output`. Overwrites the target if it exists.
    pub fn build(&self, output: impl AsRef<Path>) -> Result<(), BuildError> {
        let output = output.as_ref();
        if !self.source_dir.is_dir() {
            return Err(BuildError::SourceNotDirectory(self.source_dir.clone()));
        }

        // Cheap sanity check: at least one regular file somewhere
        // under the source dir. An empty source would build a valid
        // but useless image — surface that as a clear error.
        if !has_any_regular_file(&self.source_dir) {
            return Err(BuildError::SourceEmpty(self.source_dir.clone()));
        }

        if let Some(parent) = output.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| BuildError::Io {
                    op: "create output parent dir",
                    path: parent.to_path_buf(),
                    error: e.to_string(),
                })?;
            }
        }

        if output.exists() {
            std::fs::remove_file(output).map_err(|e| BuildError::Io {
                op: "remove existing output",
                path: output.to_path_buf(),
                error: e.to_string(),
            })?;
        }

        match self.format {
            ImageFormat::Squashfs => self.build_squashfs(output),
            ImageFormat::Qnx6 => self.build_qnx6(output),
        }
    }

    fn build_squashfs(&self, output: &Path) -> Result<(), BuildError> {
        let tool = self
            .tool_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("mksquashfs"));

        // -comp gzip — the only compression the guest-vm-kernel build
        // enables (CONFIG_SQUASHFS_ZLIB=y; XZ/ZSTD/LZ4/LZO all off).
        // xz would shave ~3% off the bundle but `mount` refuses with
        // "Filesystem uses 'xz' compression. This is not supported."
        // If you change this, also flip CONFIG_SQUASHFS_<COMP>=y in
        // guest-vm-kernel/configs/{common,arm64,amd64}.config and
        // rebuild the kernel.
        let status = Command::new(&tool)
            .arg(&self.source_dir)
            .arg(output)
            .args([
                "-all-root",
                "-no-xattrs",
                "-noappend",
                "-comp",
                "gzip",
                "-no-progress",
            ])
            .status()
            .map_err(|e| BuildError::ToolSpawn {
                tool: tool.clone(),
                error: e.to_string(),
            })?;

        if !status.success() {
            return Err(BuildError::ToolFailed {
                tool,
                exit_code: status.code(),
            });
        }
        Ok(())
    }

    fn build_qnx6(&self, output: &Path) -> Result<(), BuildError> {
        let tool = self
            .tool_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("mkqnx6fsimg"));

        let num_sectors = self.qnx6_num_sectors.unwrap_or(8192);
        let build_file = output.with_extension("qnx6.buildfile");
        let buildfile_contents =
            format!("[num_sectors={num_sectors}]\n[num_inodes=512]\n[blksize=4096]\n");
        std::fs::write(&build_file, &buildfile_contents).map_err(|e| BuildError::Io {
            op: "write qnx6 build-file",
            path: build_file.clone(),
            error: e.to_string(),
        })?;

        let status = Command::new(&tool)
            .arg("-n")
            .arg(&build_file)
            .arg(&self.source_dir)
            .arg(output)
            .status()
            .map_err(|e| BuildError::ToolSpawn {
                tool: tool.clone(),
                error: e.to_string(),
            })?;

        let _ = std::fs::remove_file(&build_file);

        if !status.success() {
            return Err(BuildError::ToolFailed {
                tool,
                exit_code: status.code(),
            });
        }
        Ok(())
    }
}

fn has_any_regular_file(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_file() {
            return true;
        }
        if ft.is_dir() && has_any_regular_file(&entry.path()) {
            return true;
        }
    }
    false
}

// =============================================================================
// Errors
// =============================================================================

#[derive(Debug)]
pub enum BuildError {
    SourceNotDirectory(PathBuf),
    SourceEmpty(PathBuf),
    Io {
        op: &'static str,
        path: PathBuf,
        error: String,
    },
    ToolSpawn {
        tool: PathBuf,
        error: String,
    },
    ToolFailed {
        tool: PathBuf,
        exit_code: Option<i32>,
    },
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::SourceNotDirectory(p) => {
                write!(f, "source path is not a directory: {}", p.display())
            }
            BuildError::SourceEmpty(p) => {
                write!(f, "source directory has no regular files: {}", p.display())
            }
            BuildError::Io { op, path, error } => {
                write!(f, "i/o ({op}) on {}: {error}", path.display())
            }
            BuildError::ToolSpawn { tool, error } => {
                write!(f, "could not spawn {}: {error}", tool.display())
            }
            BuildError::ToolFailed { tool, exit_code } => match exit_code {
                Some(c) => write!(f, "{} exited with code {c}", tool.display()),
                None => write!(f, "{} terminated by signal", tool.display()),
            },
        }
    }
}

impl std::error::Error for BuildError {}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn populate_bundle_dir(dir: &Path) -> &Path {
        fs::create_dir_all(dir.join("pem")).unwrap();
        fs::write(
            dir.join("pem/tls-ca-bundle.pem"),
            b"-----BEGIN CERTIFICATE-----\nFAKEFAKE\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        dir
    }

    fn mksquashfs_available() -> bool {
        Command::new("mksquashfs")
            .arg("-version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[test]
    fn rejects_non_directory_source() {
        let tmp = tempfile::tempdir().unwrap();
        let not_a_dir = tmp.path().join("file");
        fs::write(&not_a_dir, b"x").unwrap();
        let err = CaBundleImageBuilder::new(&not_a_dir, ImageFormat::Squashfs)
            .build(tmp.path().join("out.sqfs"))
            .unwrap_err();
        assert!(
            matches!(err, BuildError::SourceNotDirectory(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_empty_source() {
        let tmp = tempfile::tempdir().unwrap();
        // Only an empty subdir — no regular files anywhere.
        fs::create_dir(tmp.path().join("empty-subdir")).unwrap();
        let err = CaBundleImageBuilder::new(tmp.path(), ImageFormat::Squashfs)
            .build(tmp.path().join("out.sqfs"))
            .unwrap_err();
        assert!(matches!(err, BuildError::SourceEmpty(_)), "got {err:?}");
    }

    #[test]
    fn squashfs_image_has_correct_magic() {
        if !mksquashfs_available() {
            eprintln!("(skipping — mksquashfs not on $PATH)");
            return;
        }
        let src = tempfile::tempdir().unwrap();
        populate_bundle_dir(src.path());

        let out_dir = tempfile::tempdir().unwrap();
        let img = out_dir.path().join("ca-bundle.sqfs");

        CaBundleImageBuilder::new(src.path(), ImageFormat::Squashfs)
            .build(&img)
            .expect("build squashfs");

        let header = fs::read(&img).expect("read built image");
        assert!(header.len() >= 4);
        assert_eq!(&header[0..4], b"hsqs", "squashfs magic");
    }

    #[test]
    fn squashfs_overwrites_existing_output() {
        if !mksquashfs_available() {
            eprintln!("(skipping — mksquashfs not on $PATH)");
            return;
        }
        let src = tempfile::tempdir().unwrap();
        populate_bundle_dir(src.path());

        let out_dir = tempfile::tempdir().unwrap();
        let img = out_dir.path().join("ca-bundle.sqfs");
        fs::write(&img, b"existing junk").unwrap();

        CaBundleImageBuilder::new(src.path(), ImageFormat::Squashfs)
            .build(&img)
            .expect("build overwrites");
        assert_eq!(&fs::read(&img).unwrap()[0..4], b"hsqs");
    }

    #[test]
    fn missing_tool_surfaces_clear_error() {
        let src = tempfile::tempdir().unwrap();
        populate_bundle_dir(src.path());
        let out_dir = tempfile::tempdir().unwrap();
        let img = out_dir.path().join("ca-bundle.sqfs");

        let err = CaBundleImageBuilder::new(src.path(), ImageFormat::Squashfs)
            .with_tool_path("/nonexistent/mksquashfs")
            .build(&img)
            .unwrap_err();
        assert!(matches!(err, BuildError::ToolSpawn { .. }), "got {err:?}");
    }

    #[test]
    fn extension_matches_format() {
        assert_eq!(ImageFormat::Squashfs.extension(), "sqfs");
        assert_eq!(ImageFormat::Qnx6.extension(), "qnx6");
    }

    #[test]
    fn detects_files_in_nested_subdirs() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("a/b/c")).unwrap();
        fs::write(tmp.path().join("a/b/c/cert.pem"), b"x").unwrap();
        assert!(has_any_regular_file(tmp.path()));
    }
}
