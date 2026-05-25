//! Build read-only policy images for distribution inside vm-bank /
//! host-os-bank SUIT envelopes (AUTH-ARCH-001 §4).
//!
//! Two image formats supported, one per guest OS family:
//!
//! - **squashfs** for Linux guests. Read-only, compressed, well-supported
//!   by the in-tree kernel.
//! - **qnx6** for QNX guests (and the QNX host's policy overlay).
//!   Native, read-only when mounted with `mount -o ro`.
//!
//! Both formats arrive at the device as a single file in the bank
//! (e.g. `bank_a/policy.sqfs` or `bank_a/policy.qnx6`). At guest /
//! host startup, the file is loop-mounted at `/etc/sumo/policy/`
//! before any policy-reading service starts.
//!
//! ## Build flow
//!
//! ```text
//! /path/to/source/policy/        ← directory of policy files
//!   policy.yaml
//!   launcher-policy.yaml
//!   roots/
//!   crl.yaml
//!         │
//!         ▼  PolicyImageBuilder::new(...)
//!         │  .with_format(ImageFormat::Squashfs)
//!         │  .build(&output_path)?;
//!         ▼
//! /path/to/output/policy.sqfs    ← read-only image, ready to ship in a SUIT envelope
//! ```
//!
//! ## Input validation
//!
//! The builder validates the source directory using `policy-partition`
//! before invoking the FS-builder tool. If `policy.yaml` is malformed,
//! we catch that here rather than shipping a broken image — error
//! reporting is much better at build time than at mount time on the
//! device.

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
    /// qnx6 — QNX guests + QNX host. Requires `mkqnx6fsimg` from the
    /// QNX SDP on the host build machine. Honours `QNX_TARGET` /
    /// `QNX_HOST` from the SDP env, so callers must source
    /// `qnxsdp-env.sh` before invoking (or set the env vars
    /// equivalently).
    Qnx6,
}

impl ImageFormat {
    /// Default file suffix for the output image, used by the CLI when
    /// the caller doesn't pass an explicit `--output`.
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

/// Builder for a single policy image.
#[derive(Debug, Clone)]
pub struct PolicyImageBuilder {
    pub source_dir: PathBuf,
    pub format: ImageFormat,
    /// Override the build tool. By default we look up `mksquashfs` /
    /// `mkqnx6fsimg` on `$PATH`. Set this to an absolute path for
    /// reproducible cross-build invocations (e.g. inside the QNX SDP
    /// container).
    pub tool_path: Option<PathBuf>,
    /// Override the qnx6 image's `num_sectors` (512-byte sectors).
    /// `None` → 8192 (4 MB). mkqnx6fsimg prepends a 16-sector boot
    /// wrapper that doubles as an MBR with type-0xB1 partition entry
    /// 0; values below ~2048 sectors leave the partition extending
    /// past the file end, which makes io-blk silently drop the
    /// registration in devb-loopback (`fs-qnx6.so's strict size check
    /// num_sectors == medium size` fails). 4 MB gives plenty of
    /// slack while staying small enough to ship in a partial OTA.
    pub qnx6_num_sectors: Option<u32>,
    /// Skip the `policy-partition` validation step. Used by tests
    /// that intentionally produce broken images for verification.
    /// Production callers should leave this `false`.
    pub skip_validation: bool,
}

impl PolicyImageBuilder {
    pub fn new(source_dir: impl AsRef<Path>, format: ImageFormat) -> Self {
        Self {
            source_dir: source_dir.as_ref().to_path_buf(),
            format,
            tool_path: None,
            qnx6_num_sectors: None,
            skip_validation: false,
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

    pub fn skip_validation(mut self) -> Self {
        self.skip_validation = true;
        self
    }

    /// Build the image at `output`. Overwrites the target if it
    /// already exists.
    pub fn build(&self, output: impl AsRef<Path>) -> Result<(), BuildError> {
        let output = output.as_ref();
        if !self.source_dir.is_dir() {
            return Err(BuildError::SourceNotDirectory(self.source_dir.clone()));
        }

        // Pre-flight: load + parse the source via policy-partition. A
        // broken policy.yaml will surface here as a clear error rather
        // than a "mount worked but the device default-denies everything"
        // mystery at runtime.
        if !self.skip_validation {
            // policy-partition needs an op normalizer; the build step
            // doesn't know which service will consume the policy, so
            // we use a permissive "any kebab-case string is fine"
            // normalizer. The real consumer's normalizer (vhsm-ssd's
            // for example) runs again at load time on the device.
            let normalize = |s: &str| Some(s.to_ascii_lowercase().replace('_', "-"));
            policy_partition::PolicyPartition::load_from_dir(&self.source_dir, normalize)
                .map_err(|e| BuildError::ValidationFailed(e.to_string()))?;
        }

        // Ensure the output's parent directory exists. mksquashfs /
        // mkqnx6fs both refuse to create parent dirs.
        if let Some(parent) = output.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| BuildError::Io {
                    op: "create output parent dir",
                    path: parent.to_path_buf(),
                    error: e.to_string(),
                })?;
            }
        }

        // Remove the target so the FS-builder tool starts fresh.
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

        // `-all-root`     — every file owned by root (the device boots
        //                   as root anyway, and operator-built images
        //                   shouldn't leak host UIDs).
        // `-no-xattrs`    — drop xattrs (we don't use them; reduces
        //                   image variability across build hosts).
        // `-noappend`     — don't try to append to an existing file
        //                   (we removed it above, but defensive).
        // `-comp xz`      — best compression for static text content
        //                   (policy files are tiny YAML/PEM, but
        //                   we still care about over-the-air bytes).
        // `-no-progress`  — quieter CI output.
        let status = Command::new(&tool)
            .arg(&self.source_dir)
            .arg(output)
            .args([
                "-all-root",
                "-no-xattrs",
                "-noappend",
                "-comp",
                "xz",
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

        // mkqnx6fsimg syntax: `mkqnx6fsimg [opts] <buildfile> <in-dir> <out-file>`.
        //
        // The build-file carries image attributes. Critical ones:
        //   - num_sectors: total disk size in 512-byte sectors,
        //     INCLUDING the 16-sector boot wrapper. Values below
        //     ~2048 leave the qnx6 partition extending past the
        //     file end, which makes io-blk reject the registration
        //     in devb-loopback. Default 8192 (4 MB) — plenty of
        //     slack with room for policies to grow.
        //   - num_inodes + blksize: match what the working QEMU
        //     data.img / opt.img builds use.
        //
        // `-n` strips per-run timestamps for reproducible builds —
        // same image bytes from the same source dir regardless of
        // when the build runs.
        let num_sectors = self.qnx6_num_sectors.unwrap_or(8192);
        let build_file = output.with_extension("qnx6.buildfile");
        let buildfile_contents = format!(
            "[num_sectors={num_sectors}]\n[num_inodes=512]\n[blksize=4096]\n"
        );
        std::fs::write(&build_file, &buildfile_contents).map_err(|e| BuildError::Io {
            op: "write qnx6 build-file",
            path: build_file.clone(),
            error: e.to_string(),
        })?;

        // mkqnx6fsimg reads QNX_TARGET from the environment. If the
        // caller hasn't sourced qnxsdp-env.sh, the tool errors out
        // immediately ("QNX_TARGET environment variable must be set").
        // We don't try to second-guess the SDP layout here — callers
        // pass `with_tool_path()` for a non-default install, but the
        // env vars are theirs to manage.
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

        // Clean up the build-file regardless of success — caller
        // doesn't need it past this point.
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

// =============================================================================
// Errors
// =============================================================================

#[derive(Debug)]
pub enum BuildError {
    SourceNotDirectory(PathBuf),
    ValidationFailed(String),
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
            BuildError::ValidationFailed(s) => {
                write!(f, "policy directory failed validation: {s}")
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

    /// Build a well-formed policy directory in `dir`. Returns dir.
    fn populate_policy_dir(dir: &Path) -> &Path {
        fs::write(
            dir.join("policy.yaml"),
            "version: 1\nstatements: []\n",
        )
        .unwrap();
        fs::create_dir(dir.join("roots")).unwrap();
        fs::write(
            dir.join("roots/sumo-sign.pem"),
            b"-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        fs::write(
            dir.join("crl.yaml"),
            "cert_thumbprints: []\njwt_jti: []\n",
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

    fn unsquashfs_available() -> bool {
        Command::new("unsquashfs")
            .arg("-version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[test]
    fn rejects_non_directory_source() {
        let tmp = tempfile::tempdir().unwrap();
        let not_a_dir = tmp.path().join("file");
        fs::write(&not_a_dir, b"content").unwrap();
        let builder = PolicyImageBuilder::new(&not_a_dir, ImageFormat::Squashfs);
        let err = builder.build(tmp.path().join("out.sqfs")).unwrap_err();
        assert!(matches!(err, BuildError::SourceNotDirectory(_)), "got {err:?}");
    }

    #[test]
    fn rejects_malformed_source_at_validation() {
        let tmp = tempfile::tempdir().unwrap();
        // Missing policy.yaml — partition loader rejects.
        fs::create_dir(tmp.path().join("roots")).unwrap();

        let builder = PolicyImageBuilder::new(tmp.path(), ImageFormat::Squashfs);
        let err = builder.build(tmp.path().join("out.sqfs")).unwrap_err();
        match err {
            BuildError::ValidationFailed(msg) => {
                assert!(msg.contains("policy.yaml"), "msg: {msg}");
            }
            other => panic!("expected ValidationFailed, got {other:?}"),
        }
    }

    #[test]
    fn rejects_malformed_policy_yaml() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("roots")).unwrap();
        // Valid YAML, but missing version + statements — policy-eval
        // takes version: 0 default and rejects it.
        fs::write(
            tmp.path().join("policy.yaml"),
            "this is not a policy file\n",
        )
        .unwrap();

        let builder = PolicyImageBuilder::new(tmp.path(), ImageFormat::Squashfs);
        let err = builder.build(tmp.path().join("out.sqfs")).unwrap_err();
        assert!(matches!(err, BuildError::ValidationFailed(_)), "got {err:?}");
    }

    #[test]
    fn skip_validation_allows_garbage_input() {
        // Tests use this to produce intentionally-broken images for
        // round-trip-failure tests in OTHER crates. Confirms the
        // escape hatch works.
        if !mksquashfs_available() {
            eprintln!("(skipping — mksquashfs not on $PATH)");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("only-a-file"), b"no policy.yaml here").unwrap();
        let out = tempfile::tempdir().unwrap();
        let img = out.path().join("garbage.sqfs");

        let builder = PolicyImageBuilder::new(tmp.path(), ImageFormat::Squashfs)
            .skip_validation();
        builder.build(&img).expect("builds despite garbage input");
        assert!(img.exists());
    }

    #[test]
    fn squashfs_image_has_correct_magic() {
        if !mksquashfs_available() {
            eprintln!("(skipping — mksquashfs not on $PATH)");
            return;
        }
        let src = tempfile::tempdir().unwrap();
        populate_policy_dir(src.path());

        let out_dir = tempfile::tempdir().unwrap();
        let img = out_dir.path().join("policy.sqfs");

        PolicyImageBuilder::new(src.path(), ImageFormat::Squashfs)
            .build(&img)
            .expect("build squashfs");

        // squashfs magic: 'hsqs' little-endian = 0x73717368 → bytes [0x68, 0x73, 0x71, 0x73]
        let header = fs::read(&img).expect("read built image");
        assert!(header.len() >= 4);
        assert_eq!(
            &header[0..4],
            b"hsqs",
            "first 4 bytes should be squashfs magic"
        );
    }

    #[test]
    fn squashfs_round_trip_through_unsquashfs_loads_via_partition() {
        if !mksquashfs_available() || !unsquashfs_available() {
            eprintln!(
                "(skipping — mksquashfs/unsquashfs not on $PATH; install squashfs-tools)"
            );
            return;
        }

        let src = tempfile::tempdir().unwrap();
        populate_policy_dir(src.path());

        let out_dir = tempfile::tempdir().unwrap();
        let img = out_dir.path().join("policy.sqfs");
        PolicyImageBuilder::new(src.path(), ImageFormat::Squashfs)
            .build(&img)
            .expect("build squashfs");

        // Extract via unsquashfs — avoids needing loop-mount privileges
        // in CI. The on-device path is "mount the image"; the extract
        // path is equivalent for verifying contents.
        let extract_dir = tempfile::tempdir().unwrap();
        let extracted = extract_dir.path().join("policy");
        let status = Command::new("unsquashfs")
            .arg("-q")
            .arg("-f")
            .arg("-d")
            .arg(&extracted)
            .arg(&img)
            .status()
            .expect("spawn unsquashfs");
        assert!(status.success(), "unsquashfs failed");

        // Re-load through policy-partition from the extracted dir.
        // The whole point of the image: contents that go through
        // mksquashfs → unsquashfs → load must be byte-identical to
        // the source contents.
        let normalize = |s: &str| Some(s.to_ascii_lowercase().replace('_', "-"));
        let p = policy_partition::PolicyPartition::load_from_dir(&extracted, normalize)
            .expect("partition loads from extracted image");
        assert_eq!(p.authorisation.num_statements(), 0);
        assert_eq!(p.roots.len(), 1);
        assert!(p.root("sumo-sign.pem").is_some());
        assert!(p.crl.is_some());
        assert!(!p.crl.unwrap().is_cert_revoked("anything"));
    }

    #[test]
    fn squashfs_overwrites_existing_output() {
        if !mksquashfs_available() {
            eprintln!("(skipping — mksquashfs not on $PATH)");
            return;
        }
        let src = tempfile::tempdir().unwrap();
        populate_policy_dir(src.path());

        let out_dir = tempfile::tempdir().unwrap();
        let img = out_dir.path().join("policy.sqfs");
        // Pre-existing content the build must replace.
        fs::write(&img, b"existing junk").unwrap();
        let builder = PolicyImageBuilder::new(src.path(), ImageFormat::Squashfs);
        builder.build(&img).expect("build overwrites");

        let header = fs::read(&img).unwrap();
        assert_eq!(&header[0..4], b"hsqs", "should be a fresh squashfs");
    }

    #[test]
    fn missing_tool_surfaces_clear_error() {
        let src = tempfile::tempdir().unwrap();
        populate_policy_dir(src.path());

        let out_dir = tempfile::tempdir().unwrap();
        let img = out_dir.path().join("policy.sqfs");
        let builder = PolicyImageBuilder::new(src.path(), ImageFormat::Squashfs)
            .with_tool_path("/nonexistent/mksquashfs");
        let err = builder.build(&img).unwrap_err();
        assert!(matches!(err, BuildError::ToolSpawn { .. }), "got {err:?}");
    }

    #[test]
    fn extension_matches_format() {
        assert_eq!(ImageFormat::Squashfs.extension(), "sqfs");
        assert_eq!(ImageFormat::Qnx6.extension(), "qnx6");
    }
}
