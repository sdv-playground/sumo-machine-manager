//! Helpers for partial-bank-update support.
//!
//! Today's OTA path streams every component the SUIT envelope carries
//! into the target bank, leaving anything the envelope omitted as a
//! gap (the target ends up partial). For policy-only updates we want
//! the opposite: a SUIT envelope carrying just `policy.sqfs` should
//! produce a complete bank where `kernel`, `rootfs.img`, and
//! `vm-config.yaml` come from the active bank verbatim and only
//! `policy.sqfs` is the new payload.
//!
//! The mechanism: after all streaming is done but before the bank
//! gets signed by IVD + activated, copy any files from the active
//! bank to the target bank that the streaming step didn't write.
//! "Didn't write" = "the path doesn't exist in target yet". This
//! cleanly handles full updates (target has everything → seed copies
//! nothing) and partial updates (target has only the new bits →
//! seed fills in the rest).
//!
//! This module provides the pure mechanism; wiring it into the OTA
//! state machine is a separate decision (always-on vs manifest-flag
//! gated vs explicit operator opt-in).

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Walk `source_dir` and copy every file that doesn't already exist
/// in `target_dir` (relative to its source-side path). Subdirectories
/// recursive. Symlinks preserved (read + recreate). File modes
/// preserved (mode bits propagated through `std::fs::copy` + an
/// explicit `set_permissions` to cover the cases where the target
/// FS doesn't preserve them automatically).
///
/// Returns the relative paths of files that were created in the
/// target. Useful for audit / diagnostic logging.
///
/// Idempotent for the partial-update case: if every file in source
/// already exists in target, returns an empty Vec and touches nothing.
///
/// `target_dir` must already exist (the caller's
/// `prepare_target_bank_dir` is responsible for that).
pub fn seed_missing_files(source_dir: &Path, target_dir: &Path) -> io::Result<Vec<PathBuf>> {
    if !source_dir.is_dir() {
        // No source = nothing to seed. Not an error — the active bank
        // is allowed to be empty (factory state, e.g.).
        return Ok(Vec::new());
    }
    if !target_dir.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("target dir does not exist: {}", target_dir.display()),
        ));
    }

    let mut copied = Vec::new();
    walk_and_seed(source_dir, target_dir, Path::new(""), &mut copied)?;
    Ok(copied)
}

fn walk_and_seed(
    source_root: &Path,
    target_root: &Path,
    rel: &Path,
    copied: &mut Vec<PathBuf>,
) -> io::Result<()> {
    let source_dir = source_root.join(rel);
    let target_dir = target_root.join(rel);

    // Ensure the target subdirectory exists. For the rel="" case this
    // is a no-op (caller already created it).
    if !target_dir.exists() {
        fs::create_dir_all(&target_dir)?;
        // Mirror the source dir's mode so executable / RX bits on
        // policy/roots/ (rare but allowed) survive.
        if let Ok(meta) = source_dir.metadata() {
            let _ = fs::set_permissions(&target_dir, meta.permissions());
        }
    }

    for entry in fs::read_dir(&source_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let rel_entry = rel.join(&name);
        let target_path = target_root.join(&rel_entry);

        let ft = entry.file_type()?;
        if ft.is_symlink() {
            // Skip if target already has this name — preserves
            // anything the streaming step put there.
            if target_path.symlink_metadata().is_ok() {
                continue;
            }
            let link_dest = fs::read_link(entry.path())?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(&link_dest, &target_path)?;
            #[cfg(not(unix))]
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "symlink seed not supported on this platform",
            ));
            copied.push(rel_entry);
        } else if ft.is_dir() {
            // Recurse — subdirectory contents are seeded individually,
            // not as a block. This lets a partial update overwrite a
            // single file inside a subdir (e.g. policy.sqfs is a
            // file, but a future tree-of-files component could
            // partially overlap).
            walk_and_seed(source_root, target_root, &rel_entry, copied)?;
        } else if ft.is_file() {
            // Streaming-wrote-this check — if the target already
            // has it, leave the streaming result alone.
            if target_path.exists() {
                continue;
            }
            fs::copy(entry.path(), &target_path)?;
            // Explicitly carry mode bits forward. std::fs::copy
            // does this on Unix already, but being explicit costs
            // nothing and survives future portability.
            if let Ok(meta) = entry.metadata() {
                let _ = fs::set_permissions(
                    &target_path,
                    fs::Permissions::from_mode(meta.permissions().mode()),
                );
            }
            copied.push(rel_entry);
        }
        // Anything else (sockets, fifos, devices) — ignored. A
        // bank shouldn't contain those; if it does, the operator
        // has bigger problems than partial-update semantics.
    }

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn write_file(p: &Path, contents: &[u8]) {
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, contents).unwrap();
    }

    fn read_file(p: &Path) -> Vec<u8> {
        let mut f = fs::File::open(p).unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        buf
    }

    #[test]
    fn empty_source_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let target = tmp.path().join("target");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&target).unwrap();

        let copied = seed_missing_files(&source, &target).unwrap();
        assert!(copied.is_empty());
    }

    #[test]
    fn missing_source_is_noop() {
        // A bank with no active predecessor (factory first-flash)
        // should not error. seed_missing_files quietly returns empty.
        let tmp = tempfile::tempdir().unwrap();
        let nonexistent = tmp.path().join("never-existed");
        let target = tmp.path().join("target");
        fs::create_dir_all(&target).unwrap();
        let copied = seed_missing_files(&nonexistent, &target).unwrap();
        assert!(copied.is_empty());
    }

    #[test]
    fn missing_target_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        fs::create_dir_all(&source).unwrap();
        let err = seed_missing_files(&source, &tmp.path().join("does-not-exist")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn empty_target_gets_full_source() {
        // "Source has files, target is empty" = full update, but the
        // SUIT envelope had no components. Result: target ends up
        // identical to source. (This is the degenerate full-seed case.)
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let target = tmp.path().join("target");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&target).unwrap();
        write_file(&source.join("kernel"), b"kernel bytes");
        write_file(&source.join("rootfs.img"), &vec![0xAB; 4096]);
        write_file(&source.join("policy.sqfs"), b"squashfs goes here");

        let copied = seed_missing_files(&source, &target).unwrap();
        assert_eq!(copied.len(), 3);
        assert_eq!(read_file(&target.join("kernel")), b"kernel bytes");
        assert_eq!(
            read_file(&target.join("policy.sqfs")),
            b"squashfs goes here"
        );
    }

    #[test]
    fn target_with_overlapping_files_keeps_target_version() {
        // The canonical partial-update case:
        //   source (active bank): kernel, rootfs.img, policy.sqfs (old)
        //   target (post-stream): policy.sqfs (NEW)
        // After seed: target has kernel + rootfs.img from source,
        // policy.sqfs from the streaming step.
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let target = tmp.path().join("target");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&target).unwrap();
        write_file(&source.join("kernel"), b"old kernel");
        write_file(&source.join("rootfs.img"), b"old rootfs");
        write_file(&source.join("policy.sqfs"), b"OLD policy");
        // Target only has the new policy.sqfs — the streaming step.
        write_file(&target.join("policy.sqfs"), b"NEW policy");

        let copied = seed_missing_files(&source, &target).unwrap();
        assert_eq!(copied.len(), 2, "should seed kernel + rootfs.img only");
        // Streaming result preserved.
        assert_eq!(read_file(&target.join("policy.sqfs")), b"NEW policy");
        // Seed brought in the rest.
        assert_eq!(read_file(&target.join("kernel")), b"old kernel");
        assert_eq!(read_file(&target.join("rootfs.img")), b"old rootfs");
    }

    #[test]
    fn fully_overlapping_target_seeds_nothing() {
        // SUIT envelope had every component → target already has
        // everything → seed is a no-op. The full-update case must
        // still work after wiring this in.
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let target = tmp.path().join("target");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&target).unwrap();
        write_file(&source.join("kernel"), b"old");
        write_file(&source.join("rootfs.img"), b"old");
        write_file(&target.join("kernel"), b"new");
        write_file(&target.join("rootfs.img"), b"new");

        let copied = seed_missing_files(&source, &target).unwrap();
        assert!(copied.is_empty());
        assert_eq!(read_file(&target.join("kernel")), b"new");
    }

    #[test]
    fn subdirectories_recursively_seeded() {
        // Forward-looking: a future bank component might be a
        // directory tree (not just a single .sqfs file).
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let target = tmp.path().join("target");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&target).unwrap();
        write_file(&source.join("sub/a.bin"), b"A");
        write_file(&source.join("sub/b.bin"), b"B");
        write_file(&source.join("sub/deeper/c.bin"), b"C");

        let copied = seed_missing_files(&source, &target).unwrap();
        assert_eq!(copied.len(), 3);
        assert_eq!(read_file(&target.join("sub/a.bin")), b"A");
        assert_eq!(read_file(&target.join("sub/deeper/c.bin")), b"C");
    }

    #[test]
    fn nested_partial_overlap_seeds_only_missing_subtree_files() {
        // Target has sub/a.bin (streaming), source has sub/a.bin
        // and sub/b.bin. After seed: target has the streaming
        // a.bin + the seeded b.bin.
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let target = tmp.path().join("target");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&target).unwrap();
        write_file(&source.join("sub/a.bin"), b"old A");
        write_file(&source.join("sub/b.bin"), b"old B");
        write_file(&target.join("sub/a.bin"), b"new A");

        let copied = seed_missing_files(&source, &target).unwrap();
        assert_eq!(copied.len(), 1);
        assert_eq!(read_file(&target.join("sub/a.bin")), b"new A");
        assert_eq!(read_file(&target.join("sub/b.bin")), b"old B");
    }

    #[cfg(unix)]
    #[test]
    fn file_mode_preserved() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let target = tmp.path().join("target");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&target).unwrap();
        let p = source.join("script.sh");
        write_file(&p, b"#!/bin/sh\necho hi\n");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();

        seed_missing_files(&source, &target).unwrap();

        let mode = fs::metadata(target.join("script.sh"))
            .unwrap()
            .permissions()
            .mode();
        // Mask off type bits; the perms portion is the low 12 bits.
        assert_eq!(mode & 0o7777, 0o755, "executable bit must survive seed");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_in_source_recreated_in_target() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let target = tmp.path().join("target");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&target).unwrap();
        write_file(&source.join("target.bin"), b"linkdest");
        std::os::unix::fs::symlink("target.bin", source.join("link")).unwrap();

        let copied = seed_missing_files(&source, &target).unwrap();
        assert!(copied.iter().any(|p| p == Path::new("link")));

        let link_target = fs::read_link(target.join("link")).unwrap();
        assert_eq!(link_target, Path::new("target.bin"));
    }

    #[cfg(unix)]
    #[test]
    fn existing_target_symlink_preserved() {
        // Streaming step wrote a symlink (or anything) at the same
        // path — seed must leave it alone.
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let target = tmp.path().join("target");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink("old", source.join("link")).unwrap();
        std::os::unix::fs::symlink("new", target.join("link")).unwrap();

        seed_missing_files(&source, &target).unwrap();

        assert_eq!(
            fs::read_link(target.join("link")).unwrap(),
            Path::new("new")
        );
    }
}
