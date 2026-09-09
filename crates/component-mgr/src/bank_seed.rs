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
//! gets signed by IVD + activated, take the part list the sealed
//! manifest DECLARES and settle each part Ship-or-Reuse — either the
//! streaming step already shipped it into the target (skip) or it is
//! copied from the active bank (Reuse). A declared part in neither
//! place is a hard error: the bank cannot be completed.
//!
//! What this deliberately does NOT do is walk the active bank. Files
//! the active bank holds that the sealed manifest does not declare
//! belong to a DIFFERENT manifest — a cross-channel flash leaves
//! exactly that — so copying them would contaminate the target bank
//! with parts outside its own manifest. Worse, merely opening one is
//! enough to fail the whole seal: on QNX an image a running guest
//! holds through devb-loopback rejects the second opener with EBUSY.
//!
//! This module provides the pure mechanism; wiring it into the OTA
//! state machine is a separate decision (always-on vs manifest-flag
//! gated vs explicit operator opt-in).

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// What one seed pass over the sealed manifest's required parts did.
#[derive(Debug, Default)]
pub struct SeedOutcome {
    /// Required parts the streaming step didn't ship, copied from the
    /// active bank (genuine Reuse). Useful for audit / diagnostic logging.
    pub copied: Vec<PathBuf>,
    /// Names the active bank holds that this manifest does NOT declare —
    /// never touched, reported so a cross-channel leftover is visible in
    /// the log. Empty when nothing is required (nothing to compare against).
    pub foreign: Vec<String>,
}

/// Settle every part `required` by the manifest being sealed: skip the ones
/// the streaming step already shipped into `target_dir`, copy the rest from
/// `source_dir` (the active bank). Symlinks preserved (read + recreate). File
/// modes preserved (mode bits propagated through `std::fs::copy` + an explicit
/// `set_permissions` to cover the cases where the target FS doesn't preserve
/// them automatically). Parent directories of a `sub/dir/part` name are created.
///
/// A required part present in NEITHER place is an error naming it — the bank
/// cannot be completed, and sealing a partial bank is never the answer.
///
/// Only `required` is ever read from the source: everything else the active
/// bank holds is left alone (and only listed, for the caller's summary log).
/// A manifest that ships every part it declares therefore makes this a
/// provable no-op — no source file is opened at all, which is what keeps a
/// full flash clear of the devb-loopback EBUSY on the running bank's images.
///
/// `target_dir` must already exist (the caller's `prepare_target_bank_dir` is
/// responsible for that).
pub fn seed_missing_files(
    source_dir: &Path,
    target_dir: &Path,
    required: &[String],
) -> io::Result<SeedOutcome> {
    let mut outcome = SeedOutcome::default();
    if required.is_empty() {
        // Nothing declared ⇒ nothing to settle. Don't even list the source.
        return Ok(outcome);
    }
    if !target_dir.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("target dir does not exist: {}", target_dir.display()),
        ));
    }

    for name in required {
        let target_path = target_dir.join(name);
        // Ship: the streaming step (or the copy-forward reconcile) already put
        // this part in the target. Leave it, and never open the active bank's
        // copy — that open is what EBUSYs on a devb-attached image.
        if target_path.symlink_metadata().is_ok() {
            continue;
        }

        // Reuse: the manifest declares this part but nothing shipped it, so it
        // comes from the active bank verbatim.
        //
        // KNOWN LIMITATION (out of scope here): a genuine Reuse of an image a
        // RUNNING guest holds through devb-loopback can still fail on this read
        // — QNX refuses the second opener with EBUSY. Read-open semantics for a
        // devb-attached source are settled on the bench, not here.
        let source_path = source_dir.join(name);
        let meta = match source_path.symlink_metadata() {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "required file {name:?} is in neither the target bank ({}) nor the \
                         active bank ({}) — the bank cannot be completed",
                        target_dir.display(),
                        source_dir.display(),
                    ),
                ));
            }
            Err(e) => return Err(e),
        };
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let ft = meta.file_type();
        if ft.is_symlink() {
            let link_dest = fs::read_link(&source_path)?;
            std::os::unix::fs::symlink(&link_dest, &target_path)?;
        } else if ft.is_file() {
            fs::copy(&source_path, &target_path)?;
            // Explicitly carry mode bits forward. std::fs::copy does this on
            // Unix already, but being explicit costs nothing and survives
            // future portability.
            let _ = fs::set_permissions(
                &target_path,
                fs::Permissions::from_mode(meta.permissions().mode()),
            );
        } else {
            // A directory / socket / fifo under a declared part's name. A bank
            // shouldn't contain those; refuse rather than seal something the
            // manifest can't describe.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "required file {name:?} in the active bank ({}) is neither a file nor a symlink",
                    source_dir.display(),
                ),
            ));
        }
        outcome.copied.push(PathBuf::from(name));
    }

    outcome.foreign = foreign_entries(source_dir, required);
    Ok(outcome)
}

/// Top-level names in `source_dir` that no `required` part claims — the parts
/// of a DIFFERENT manifest (what a cross-channel flash leaves behind in the
/// active bank). Diagnostic only; these are never copied. IVD's own artefacts
/// aren't parts, so they don't count. A missing/unreadable source dir (factory
/// first-flash) simply has nothing to report.
fn foreign_entries(source_dir: &Path, required: &[String]) -> Vec<String> {
    let Ok(entries) = fs::read_dir(source_dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| {
            name != hsm::ivd::IVD_MANIFEST_FILE
                && name != hsm::ivd::IVD_SIGNATURE_FILE
                // `sub/dir/part` names are claimed by their first segment.
                && !required
                    .iter()
                    .any(|r| r.split('/').next() == Some(name.as_str()))
        })
        .collect()
}

/// Error from a digest-verified copy-forward of one bank file.
#[derive(Debug)]
pub enum CopyForwardError {
    /// The active bank has no file to copy forward for this component.
    MissingActive(PathBuf),
    /// The active bank's on-disk content doesn't hash to the digest the
    /// manifest declared for this component — the vehicle does NOT already have
    /// this content, so copying it forward would seal a stale bank.
    DigestMismatch {
        name: String,
        expected: Vec<u8>,
        actual: [u8; 32],
    },
    /// Filesystem I/O error, with the path it occurred on.
    Io(io::Error, PathBuf),
}

impl std::fmt::Display for CopyForwardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CopyForwardError::MissingActive(p) => {
                write!(f, "active bank has no file to copy forward: {}", p.display())
            }
            CopyForwardError::DigestMismatch {
                name,
                expected,
                actual,
            } => write!(
                f,
                "{name}: active bank digest {} != manifest-declared {} — vehicle does not already have this content",
                hex::encode(actual),
                hex::encode(expected),
            ),
            CopyForwardError::Io(e, p) => write!(f, "copy-forward io {}: {e}", p.display()),
        }
    }
}

impl std::error::Error for CopyForwardError {}

/// Copy one file `name` from `active_dir` to `target_dir`, VERIFIED against the
/// manifest's declared plaintext image digest.
///
/// This is the digest-checked counterpart to [`seed_missing_files`], for the
/// manifest-only / partial-push "the vehicle already has this" case. Rather than
/// copying whatever is present (presence-based), it copies the active bank's file
/// for a manifested-but-un-pushed component ONLY when the file's SHA-256 equals
/// `expected` — the digest the offboard manifest declared. A mismatch (stale /
/// wrong content) or a missing active file returns an error so the caller can
/// FAIL the install instead of sealing a bank whose bytes don't match the
/// manifest's promise.
///
/// Streams the file through the hasher in chunks (constant memory — a bank
/// includes the multi-hundred-MB rootfs) while writing it to the target, and
/// preserves the active file's mode bits. On a digest mismatch the
/// partially-written target file is removed so no unverified bytes linger in the
/// bank. Returns `(sha256, size)` of the copied file on success.
///
/// `target_dir` (and any parent implied by `name`) is created as needed.
pub fn copy_forward_file(
    active_dir: &Path,
    target_dir: &Path,
    name: &str,
    expected: &[u8],
) -> Result<([u8; 32], u64), CopyForwardError> {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};

    let src = active_dir.join(name);
    let mut input = match fs::File::open(&src) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(CopyForwardError::MissingActive(src));
        }
        Err(e) => return Err(CopyForwardError::Io(e, src)),
    };

    let dst = target_dir.join(name);
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).map_err(|e| CopyForwardError::Io(e, parent.to_path_buf()))?;
    }
    let mut output = fs::File::create(&dst).map_err(|e| CopyForwardError::Io(e, dst.clone()))?;

    // 4 MiB chunks — same rationale as the IVD hash pass: large sequential reads,
    // no whole-file allocation for the big rootfs.
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 4 * 1024 * 1024];
    let mut size: u64 = 0;
    loop {
        let n = input
            .read(&mut buf)
            .map_err(|e| CopyForwardError::Io(e, src.clone()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        output
            .write_all(&buf[..n])
            .map_err(|e| CopyForwardError::Io(e, dst.clone()))?;
        size += n as u64;
    }
    output
        .flush()
        .map_err(|e| CopyForwardError::Io(e, dst.clone()))?;

    let actual: [u8; 32] = hasher.finalize().into();
    if actual.as_slice() != expected {
        // Don't leave unverified bytes staged in the target bank.
        let _ = fs::remove_file(&dst);
        return Err(CopyForwardError::DigestMismatch {
            name: name.to_string(),
            expected: expected.to_vec(),
            actual,
        });
    }

    // Preserve the active file's mode bits (executable / RX survive the copy).
    if let Ok(meta) = input.metadata() {
        let _ = fs::set_permissions(&dst, fs::Permissions::from_mode(meta.permissions().mode()));
    }

    Ok((actual, size))
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

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn nothing_required_is_noop() {
        // CRL / disable / HSM-keystore installs declare no payloads. Nothing to
        // settle ⇒ the source is never even listed, and a target dir that isn't
        // there yet is not an error.
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        write_file(&source.join("kernel"), b"old kernel");

        let outcome = seed_missing_files(&source, &tmp.path().join("no-target"), &[]).unwrap();
        assert!(outcome.copied.is_empty());
        assert!(outcome.foreign.is_empty());
    }

    #[test]
    fn cross_channel_flash_copies_nothing_from_the_active_bank() {
        // The field failure: a cicd→skan8f vm1 flash ships all the parts its
        // manifest declares, while the active bank still holds cicd-only images
        // the RUNNING guest has open via devb-loopback. Seed must not go near
        // them — reading one is what raised EBUSY and failed the seal.
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("bank_b");
        let target = tmp.path().join("bank_a");
        write_file(&source.join("kernel"), b"cicd kernel");
        write_file(&source.join("rootfs.img"), b"cicd rootfs");
        write_file(&source.join("rt-link"), b"cicd-only image");
        write_file(&source.join("diagnostics"), b"cicd-only image");
        // Every declared part was streamed into the target.
        write_file(&target.join("kernel"), b"skan8f kernel");
        write_file(&target.join("rootfs.img"), b"skan8f rootfs");

        let outcome =
            seed_missing_files(&source, &target, &names(&["kernel", "rootfs.img"])).unwrap();

        assert!(outcome.copied.is_empty(), "a full ship seeds nothing");
        assert!(
            !target.join("rt-link").exists() && !target.join("diagnostics").exists(),
            "parts outside the manifest must never reach the target bank"
        );
        // Streamed bytes untouched.
        assert_eq!(read_file(&target.join("kernel")), b"skan8f kernel");
        // …and the leftovers are reported so the operator can see them.
        let mut foreign = outcome.foreign.clone();
        foreign.sort();
        assert_eq!(foreign, vec!["diagnostics".to_string(), "rt-link".into()]);
    }

    #[test]
    fn declared_part_the_stream_did_not_ship_is_reused_from_active() {
        // Genuine Reuse: the manifest declares vm-config.yaml, the push didn't
        // carry it, the active bank has it → copy, mode and all.
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let target = tmp.path().join("target");
        fs::create_dir_all(&target).unwrap();
        write_file(&source.join("kernel"), b"old kernel");
        let cfg = source.join("vm-config.yaml");
        write_file(&cfg, b"old: config");
        fs::set_permissions(&cfg, fs::Permissions::from_mode(0o755)).unwrap();
        write_file(&target.join("kernel"), b"new kernel");

        let outcome =
            seed_missing_files(&source, &target, &names(&["kernel", "vm-config.yaml"])).unwrap();

        assert_eq!(outcome.copied, vec![PathBuf::from("vm-config.yaml")]);
        assert_eq!(read_file(&target.join("kernel")), b"new kernel");
        assert_eq!(read_file(&target.join("vm-config.yaml")), b"old: config");
        let mode = fs::metadata(target.join("vm-config.yaml"))
            .unwrap()
            .permissions()
            .mode();
        // Mask off type bits; the perms portion is the low 12 bits.
        assert_eq!(mode & 0o7777, 0o755, "mode bits must survive the reuse");
    }

    #[test]
    fn declared_part_missing_everywhere_errors_naming_it() {
        // Neither shipped nor reusable — the bank cannot be completed, and
        // sealing a partial one is never the answer.
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let target = tmp.path().join("target");
        fs::create_dir_all(&target).unwrap();
        write_file(&source.join("kernel"), b"old kernel");

        let err = seed_missing_files(&source, &target, &names(&["kernel", "rootfs.img"]))
            .expect_err("a part in neither bank must fail the seal");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(
            err.to_string().contains("rootfs.img"),
            "the error must name the missing part, got: {err}"
        );
    }

    #[test]
    fn foreign_files_stay_put_even_when_a_reuse_happens() {
        // Reuse of a declared part must not drag the rest of the active bank
        // along with it.
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let target = tmp.path().join("target");
        fs::create_dir_all(&target).unwrap();
        write_file(&source.join("kernel"), b"old kernel");
        write_file(&source.join("rt-link"), b"cicd-only image");
        write_file(&target.join("rootfs.img"), b"new rootfs");

        let outcome =
            seed_missing_files(&source, &target, &names(&["kernel", "rootfs.img"])).unwrap();

        assert_eq!(outcome.copied, vec![PathBuf::from("kernel")]);
        assert_eq!(read_file(&target.join("kernel")), b"old kernel");
        assert!(
            !target.join("rt-link").exists(),
            "an undeclared file must not ride along with a reuse"
        );
        assert_eq!(outcome.foreign, vec!["rt-link".to_string()]);
    }

    #[test]
    fn missing_target_dir_errors_when_parts_are_required() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        write_file(&source.join("kernel"), b"old kernel");
        let err = seed_missing_files(&source, &tmp.path().join("no-target"), &names(&["kernel"]))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn factory_first_flash_has_no_active_bank_to_reuse_from() {
        // No active predecessor on disk. Everything the manifest declares was
        // streamed, so the seed succeeds without touching the missing source.
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        write_file(&target.join("policy.sqfs"), b"new");

        let outcome = seed_missing_files(
            &tmp.path().join("never-existed"),
            &target,
            &names(&["policy.sqfs"]),
        )
        .unwrap();
        assert!(outcome.copied.is_empty());
        assert!(outcome.foreign.is_empty());
    }

    #[test]
    fn required_subpath_creates_its_parent_dirs() {
        // A declared part may live in a subdirectory of the bank.
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let target = tmp.path().join("target");
        fs::create_dir_all(&target).unwrap();
        write_file(&source.join("policy/policy.yaml"), b"version: 1");
        write_file(&source.join("policy/roots/sumo-sign.pem"), b"pem");

        let outcome = seed_missing_files(
            &source,
            &target,
            &names(&["policy/policy.yaml", "policy/roots/sumo-sign.pem"]),
        )
        .unwrap();

        assert_eq!(outcome.copied.len(), 2);
        assert_eq!(read_file(&target.join("policy/policy.yaml")), b"version: 1");
        assert_eq!(
            read_file(&target.join("policy/roots/sumo-sign.pem")),
            b"pem"
        );
        assert!(
            outcome.foreign.is_empty(),
            "`policy/...` parts claim the `policy` dir — not a leftover"
        );
    }

    #[cfg(unix)]
    #[test]
    fn required_symlink_recreated_in_target() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let target = tmp.path().join("target");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&target).unwrap();
        write_file(&source.join("target.bin"), b"linkdest");
        std::os::unix::fs::symlink("target.bin", source.join("link")).unwrap();

        let outcome = seed_missing_files(&source, &target, &names(&["link"])).unwrap();
        assert_eq!(outcome.copied, vec![PathBuf::from("link")]);
        assert_eq!(
            fs::read_link(target.join("link")).unwrap(),
            Path::new("target.bin")
        );
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

        seed_missing_files(&source, &target, &names(&["link"])).unwrap();

        assert_eq!(
            fs::read_link(target.join("link")).unwrap(),
            Path::new("new")
        );
    }

    // -------------------------------------------------------------------------
    // copy_forward_file: digest-verified single-file copy-forward
    // -------------------------------------------------------------------------

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(bytes).into()
    }

    #[test]
    fn copy_forward_file_copies_on_digest_match() {
        let tmp = tempfile::tempdir().unwrap();
        let active = tmp.path().join("bank_a");
        let target = tmp.path().join("bank_b");
        fs::create_dir_all(&active).unwrap();
        fs::create_dir_all(&target).unwrap();
        let content = b"the vehicle already has this rootfs";
        write_file(&active.join("rootfs.img"), content);

        let expected = sha256(content);
        let (hash, size) =
            copy_forward_file(&active, &target, "rootfs.img", &expected).expect("digest matches");

        assert_eq!(hash, expected, "returns the verified digest");
        assert_eq!(size, content.len() as u64);
        assert_eq!(
            read_file(&target.join("rootfs.img")),
            content,
            "target gets the active bank's bytes"
        );
    }

    #[test]
    fn copy_forward_file_rejects_digest_mismatch_and_removes_partial() {
        // Active bank holds a DIFFERENT version than the manifest declares —
        // "the vehicle already has this" is false. The copy must be refused and
        // must NOT leave stale bytes staged in the target bank.
        let tmp = tempfile::tempdir().unwrap();
        let active = tmp.path().join("bank_a");
        let target = tmp.path().join("bank_b");
        fs::create_dir_all(&active).unwrap();
        fs::create_dir_all(&target).unwrap();
        write_file(&active.join("rootfs.img"), b"STALE active content");

        let manifest_digest = sha256(b"the version the manifest expects");
        let err = copy_forward_file(&active, &target, "rootfs.img", &manifest_digest).unwrap_err();
        match err {
            CopyForwardError::DigestMismatch {
                name,
                expected,
                actual,
            } => {
                assert_eq!(name, "rootfs.img");
                assert_eq!(expected, manifest_digest.to_vec());
                assert_eq!(actual, sha256(b"STALE active content"));
            }
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
        assert!(
            !target.join("rootfs.img").exists(),
            "a mismatched copy must not linger in the target bank"
        );
    }

    #[test]
    fn copy_forward_file_missing_active_errors() {
        // Manifest claims the vehicle already has a component, but the active
        // bank has no such file — must error, not silently produce an empty file.
        let tmp = tempfile::tempdir().unwrap();
        let active = tmp.path().join("bank_a");
        let target = tmp.path().join("bank_b");
        fs::create_dir_all(&active).unwrap();
        fs::create_dir_all(&target).unwrap();

        let err = copy_forward_file(&active, &target, "kernel", &sha256(b"x")).unwrap_err();
        assert!(
            matches!(err, CopyForwardError::MissingActive(_)),
            "expected MissingActive, got {err:?}"
        );
        assert!(!target.join("kernel").exists());
    }

    #[cfg(unix)]
    #[test]
    fn copy_forward_file_preserves_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let active = tmp.path().join("bank_a");
        let target = tmp.path().join("bank_b");
        fs::create_dir_all(&active).unwrap();
        fs::create_dir_all(&target).unwrap();
        let content = b"#!/bin/sh\necho hi\n";
        let p = active.join("hook.sh");
        write_file(&p, content);
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();

        copy_forward_file(&active, &target, "hook.sh", &sha256(content)).expect("copy");

        let mode = fs::metadata(target.join("hook.sh"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o7777,
            0o755,
            "executable bit must survive copy-forward"
        );
    }
}
