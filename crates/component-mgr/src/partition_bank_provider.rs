//! `PartitionBankProvider` — a [`machine_mgr::BankProvider`] for **raw-partition
//! A/B banks** that stream straight to the eMMC partition (no staging file).
//!
//! This is the reusable pattern behind the host OS bank today, and RT/M7 + the
//! future bootloader bank tomorrow: a raw eMMC partition holding a
//! **partition-exact** image (built to EXACTLY the partition size — mandatory for
//! the raw qnx6 mount: `fs-qnx6.so` needs `num_sectors == medium size`), with no
//! filesystem "bank dir" to boot from. The OTA payload is written ONCE, straight
//! to the partition; the IVD manifest is computed by **hashing the partition back**
//! (so it attests the real boot medium, catching a bad/short write), and the tiny
//! IVD manifest + signature live in a small side dir (they can't sit in the
//! full image or on the full partition).
//!
//! Contrast with the file path ([`IvdBankProvider`]): that streams to
//! `target_bank_dir/<name>` and boots the bank dir. The old host path ALSO staged
//! to a file, then a `BankActivator` did `fs::read`(whole image → Vec) +
//! `fs::write`(raw to the partition) — a double write + a full-image RAM read (the
//! same whole-file-read OOM pattern fixed for verify). This provider removes both:
//! the sink IS the partition.
//!
//! # Composition
//! It composes an [`IvdBankProvider`] (built with `bank_activator = None`, so its
//! `activate()` is the boot-selector flip ONLY — no byte-copy) for all the NV /
//! selector / commit / rollback bookkeeping, and OVERRIDES the three device-facing
//! methods:
//! - [`open_payload_writer`](PartitionBankProvider::open_payload_writer) → opens the
//!   A/B partition device as the write sink (not a staging file).
//! - [`seal`](PartitionBankProvider::seal) → hashes each written partition back and
//!   signs an IVD manifest over that digest (no dir-walk).
//! - [`verify_payload`](PartitionBankProvider::verify_payload) → re-hashes the
//!   partition device (partition-exact ⇒ hash-to-EOF == image hash).
//!
//! Per-consumer variance is only the part→partition A/B path map ([`PartitionPart`],
//! data). host/rt/bootloader each construct the provider with their own map.

use std::path::PathBuf;
use std::sync::Arc;

use nv_store::block::BlockDevice;
use nv_store::types::Bank;

use machine_mgr::bank_provider::{BankError, BankProvider, FirmwareIdentity, InstalledFirmware};
use machine_mgr::ResetKind;

use crate::bank_provider::{firmware_to_ivd_identity, IvdBankProvider};

/// One part of a raw-partition bank: its on-disk payload name (the SUIT
/// component-id's last segment, e.g. `application.img`) and the A/B eMMC device
/// paths it is written to. The map is deployment config, not code — the consumer
/// (host/rt/bootloader) fills it at construction.
#[derive(Debug, Clone)]
pub struct PartitionPart {
    /// Payload name as it arrives on the wire (`payload_target_name_for_id`).
    pub file: String,
    /// Device path for bank A (e.g. `/dev/emmc0.lnxdata.bank0-application`).
    pub partition_a: String,
    /// Device path for bank B (e.g. `/dev/emmc0.lnxdata.bank1-application`).
    pub partition_b: String,
}

impl PartitionPart {
    /// The device path for `bank`.
    fn device(&self, bank: Bank) -> &str {
        match bank {
            Bank::A => &self.partition_a,
            Bank::B => &self.partition_b,
        }
    }
}

/// A `File` sink that forces its writes DURABLE to the device on `flush`
/// (`sync_all` = fsync). The OTA streaming pipeline calls `flush()` once when the
/// payload is fully written, so wrapping the device file in this guarantees the
/// bytes are on the eMMC before seal hashes the partition back and before any
/// post-flash reboot — a raw partition left with dirty pages wedges the node on
/// reboot (the kernel flushes 133 MB on the way down). `BufWriter` calls this
/// inner `flush` when the buffer drains, so a `BufWriter<SyncingWriter>` fsyncs on
/// its terminal flush.
struct SyncingWriter {
    inner: std::fs::File,
    path: String,
}

impl std::io::Write for SyncingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        // fsync the device — the whole point. sync_all (not just flush) forces
        // dirty pages out to the eMMC so a subsequent reboot has nothing to drain.
        self.inner.sync_all()?;
        tracing::info!(device = %self.path, "partition bank: fsync'd device (payload durable)");
        Ok(())
    }
}

/// A [`BankProvider`] that streams raw-partition banks straight to their eMMC
/// device. See the module docs.
pub struct PartitionBankProvider<D: BlockDevice + Send + 'static> {
    inner: IvdBankProvider<D>,
    parts: Vec<PartitionPart>,
    /// HSM provisioning authority — `seal` gates signing on `is_provisioned()`,
    /// mirroring `IvdBankProvider::seal`. Same handle the inner holds.
    hsm: Option<Arc<std::sync::Mutex<dyn hsm::HsmProvider>>>,
    /// Crypto handle `seal` signs the IVD manifest with (its lone `sign` op).
    hsm_crypto: Option<Arc<dyn hsm::HsmCryptoProvider>>,
}

impl<D: BlockDevice + Send + 'static> PartitionBankProvider<D> {
    /// Build a raw-partition provider. `inner` MUST be constructed with
    /// `bank_activator = None` (its `activate()` becomes the selector flip only).
    /// `hsm` + `hsm_crypto` are the same handles the inner was given — held here
    /// so the overridden `seal` can gate + sign without reaching into `inner`.
    pub fn new(
        inner: IvdBankProvider<D>,
        parts: Vec<PartitionPart>,
        hsm: Option<Arc<std::sync::Mutex<dyn hsm::HsmProvider>>>,
        hsm_crypto: Option<Arc<dyn hsm::HsmCryptoProvider>>,
    ) -> Self {
        Self {
            inner,
            parts,
            hsm,
            hsm_crypto,
        }
    }

    /// The small side dir holding the IVD manifest + signature for `bank`
    /// (`images_dir/<dir_name>/bank_{a,b}`). The partition holds the image; this
    /// dir holds only the ~200 B of IVD metadata `read_installed` reads back.
    fn metadata_dir(&self, bank: Bank) -> Result<PathBuf, BankError> {
        self.inner
            .target_bank_dir(bank)
            .ok_or_else(|| BankError::Failed("no images_dir configured".into()))
    }

    /// Hash a device path to EOF, streamed (never slurps the whole image). For a
    /// partition-exact image, hash-to-EOF == the image sha256.
    fn hash_device(path: &str) -> Result<(u64, [u8; 32]), BankError> {
        let file = std::fs::File::open(path)
            .map_err(|e| BankError::Failed(format!("open {path} for hashing: {e}")))?;
        crate::streaming::hash_reader(std::io::BufReader::new(file))
            .map_err(|e| BankError::Failed(format!("hash {path}: {e}")))
    }
}

impl<D: BlockDevice + Send + 'static> BankProvider for PartitionBankProvider<D> {
    // --- reads / bookkeeping: delegate to the inner IvdBankProvider ------------
    fn active_bank(&self) -> Bank {
        self.inner.active_bank()
    }
    fn selected_bank(&self) -> Option<Bank> {
        self.inner.selected_bank()
    }
    fn target_bank(&self) -> Bank {
        self.inner.target_bank()
    }
    fn prepare_target(&self, bank: Bank) -> Result<(), BankError> {
        // Clears the metadata dir (old manifest/sig) — the partition itself is
        // overwritten by the stream. Reuses the inner's dir prep.
        self.inner.prepare_target(bank)
    }
    fn read_installed(&self, bank: Bank) -> Result<InstalledFirmware, BankError> {
        // The IVD manifest+sig live in the metadata dir exactly as for a file
        // bank, so the inner's report-only read works unchanged.
        self.inner.read_installed(bank)
    }
    fn activate(&self, bank: Bank) -> Result<ResetKind, BankError> {
        // inner has NO activator → activate() is the boot-selector stage+seal
        // only (the bytes are already on the partition from the sink). No
        // byte-copy, no RAM read.
        self.inner.activate(bank)
    }
    fn commit(&self) -> Result<(), BankError> {
        self.inner.commit()
    }
    fn rollback(&self) -> Result<(), BankError> {
        self.inner.rollback()
    }
    fn reset_kind(&self) -> ResetKind {
        // A raw partition takes effect only after the node reboots + the
        // bootloader re-selects — always a full ECU reset.
        ResetKind::RequiresEcuReset
    }

    // --- device-facing overrides ----------------------------------------------

    /// Open the A/B partition device for `name` as the payload sink. `File::create`
    /// on a block device does NOT truncate/resize the partition (the kernel
    /// ignores O_TRUNC on block devices); it opens the node for writing. A name
    /// not in the part map falls back to the inner's staging-file sink (defensive
    /// — shouldn't happen for a configured raw-partition bank).
    fn open_payload_writer(
        &self,
        bank: Bank,
        name: &str,
    ) -> Result<Box<dyn std::io::Write + Send>, BankError> {
        let Some(part) = self.parts.iter().find(|p| p.file == name) else {
            tracing::warn!(
                part = %name,
                "partition bank: part not in the partition map — falling back to staging-file sink"
            );
            return self.inner.open_payload_writer(bank, name);
        };
        let device = part.device(bank);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(device)
            .map_err(|e| BankError::Failed(format!("open partition {device} for write: {e}")))?;
        tracing::info!(part = %name, device = %device, ?bank, "partition bank: streaming payload straight to device");
        // 4 MiB buffer — same rationale as IvdBankProvider (the eMMC write is the
        // #1 upload stage post decrypt/decompress speedups). Wrapped in a
        // SyncingWriter so the pipeline's terminal `flush()` forces the dirty
        // pages to the eMMC (fsync). WITHOUT this the 133 MB sits in the kernel
        // page cache: seal's hash-back reads through the cache and PASSES, but the
        // bytes aren't durable — then the post-flash `reboot` wedges the node
        // flushing 133 MB of dirty pages on the way down (observed on the rig:
        // froze, no reboot, needed a power cycle). The old HostBankActivator did
        // `Command::new("sync")` for exactly this; the redesign must not lose it.
        const WRITE_BUF: usize = 4 * 1024 * 1024;
        let sink = SyncingWriter {
            inner: file,
            path: device.to_string(),
        };
        Ok(Box::new(std::io::BufWriter::with_capacity(WRITE_BUF, sink)))
    }

    /// Seal by hashing the written partition(s) BACK and signing an IVD manifest
    /// over those digests. No dir-walk (there are no staged files); the manifest
    /// + signature are written into the small metadata dir.
    fn seal(&self, bank: Bank, identity: FirmwareIdentity, gen: u64) -> Result<(), BankError> {
        let metadata_dir = self.metadata_dir(bank)?;
        std::fs::create_dir_all(&metadata_dir).map_err(|e| {
            BankError::Failed(format!(
                "create metadata dir {}: {e}",
                metadata_dir.display()
            ))
        })?;

        // Build the IVD file list by hashing each present partition device.
        let mut files = Vec::with_capacity(self.parts.len());
        for part in &self.parts {
            let device = part.device(bank);
            // A part whose device is absent (e.g. #ifs/#rootfs not yet produced)
            // is skipped — a 1-part (#application-only) bank is normal today.
            if !std::path::Path::new(device).exists() {
                tracing::debug!(part = %part.file, device = %device, "partition bank: device absent — skipping in seal");
                continue;
            }
            let (size, sha) = Self::hash_device(device)?;
            tracing::info!(part = %part.file, device = %device, size, "partition bank: hashed partition for IVD");
            files.push(hsm::ivd::IvdFile {
                relative_path: part.file.clone(),
                sha256: sha.to_vec(),
                size,
            });
        }
        if files.is_empty() {
            return Err(BankError::Failed(
                "partition bank seal: no partition device present to hash — nothing to sign".into(),
            ));
        }

        // Provisioning gate — mirror IvdBankProvider::seal: HSM must be present +
        // provisioned before signing (a not-yet-provisioned HSM ⇒ skip, the bank
        // is intentionally un-sealed until re-flashed post-provision).
        let hsm_arc = self.hsm.as_ref().ok_or_else(|| {
            BankError::Failed("partition bank seal: no HSM provider attached — wiring bug".into())
        })?;
        {
            let hsm = hsm_arc
                .lock()
                .map_err(|_| BankError::Failed("partition bank seal: hsm mutex poisoned".into()))?;
            match hsm.is_provisioned() {
                Ok(true) => {}
                Ok(false) => {
                    tracing::warn!(
                        "partition bank seal: HSM not yet provisioned — skipping (bank not boot-eligible until re-flashed post-provision)"
                    );
                    return Ok(());
                }
                Err(e) => {
                    return Err(BankError::Failed(format!(
                        "partition bank seal: hsm provisioning probe failed: {e}"
                    )))
                }
            }
        }

        let crypto = self.hsm_crypto.as_ref().ok_or_else(|| {
            BankError::Failed(
                "partition bank seal: no HSM crypto handle — IVD signing needs an HsmCryptoProvider (wiring bug)".into(),
            )
        })?;
        hsm::ivd::sign_bank_with_files_crypto(
            crypto.as_ref(),
            &metadata_dir,
            gen,
            firmware_to_ivd_identity(&identity),
            files,
            None,
        )
        .map_err(|e| BankError::Failed(format!("partition bank seal: ivd sign: {e}")))?;
        tracing::info!(metadata_dir = %metadata_dir.display(), gen, "partition bank sealed (IVD signed over partition hash)");
        Ok(())
    }

    /// Verify a part by re-hashing its partition device (partition-exact ⇒
    /// hash-to-EOF == the image hash).
    fn verify_payload(
        &self,
        bank: Bank,
        name: &str,
        expected_sha256: &[u8; 32],
    ) -> Result<(), BankError> {
        let Some(part) = self.parts.iter().find(|p| p.file == name) else {
            return self.inner.verify_payload(bank, name, expected_sha256);
        };
        let device = part.device(bank);
        let (_len, recomputed) = Self::hash_device(device)?;
        if &recomputed == expected_sha256 {
            Ok(())
        } else {
            Err(BankError::Unverifiable(format!(
                "{name}: partition {device} sha256 mismatch — recomputed {} vs expected {}",
                hex::encode(recomputed),
                hex::encode(expected_sha256)
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nv_store::block::MemBlockDevice;
    use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
    use nv_store::types::{BankSet, NvBootState};
    use std::io::Write;
    use std::sync::Mutex;

    // A file stands in for the eMMC partition device: File::create + hash-back
    // behave identically to a block device for the provider's logic (the
    // block-device-specific concern — O_TRUNC being ignored — doesn't affect
    // correctness of the stream+hash path we test here).
    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("pbp-test-{name}"));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn nv() -> Arc<Mutex<NvStore<MemBlockDevice>>> {
        let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
        nv.write_boot_state(&mut NvBootState::default()).unwrap();
        Arc::new(Mutex::new(nv))
    }

    /// Provision the IVD signing slot in a fresh keystore dir and return the dir.
    /// (SimHsm isn't Clone, so callers open their own SimHsm handles over the same
    /// dir — a keystore path is all a SimHsm is.)
    fn provisioned_keystore(tag: &str) -> PathBuf {
        use hsm::payload::*;
        let ks_dir = std::env::temp_dir().join(format!("pbp-ks-{tag}"));
        let _ = std::fs::remove_dir_all(&ks_dir);
        std::fs::create_dir_all(&ks_dir).unwrap();
        let hsm = hsm_sim_backend::SimHsm::new(ks_dir.clone());
        hsm.write_keystore(&HsmKeystore {
            schema_version: SCHEMA_VERSION,
            security_version: 1,
            identities: vec![],
            slots: vec![KeySlot {
                key_id: hsm::ivd::IVD_KEY_ID.to_string(),
                key_kind: KEY_TYPE_EC_P256,
                anchor_public_key: None,
                allowed_guests: None,
                allowed_ops: Some(vec![OP_SIGN, OP_VERIFY, OP_GET_PUBKEY]),
            }],
            certificates: Vec::new(),
            trust_anchors: Vec::new(),
        })
        .unwrap();
        std::fs::write(ks_dir.join("provision_state"), b"1\n").unwrap();
        ks_dir
    }

    fn build(images_dir: PathBuf, parts: Vec<PartitionPart>, tag: &str) -> PartitionBankProvider<MemBlockDevice> {
        let ks = provisioned_keystore(tag);
        // Two independent SimHsm handles over the same keystore dir — one as the
        // provisioning-gate HsmProvider, one as the signing HsmCryptoProvider.
        let hsm: Arc<Mutex<dyn hsm::HsmProvider>> =
            Arc::new(Mutex::new(hsm_sim_backend::SimHsm::new(ks.clone())));
        let crypto: Arc<dyn hsm::HsmCryptoProvider> =
            Arc::new(hsm_sim_backend::SimHsm::new(ks.clone()));
        let inner = IvdBankProvider::new(
            nv(),
            BankSet::Os,
            false,
            Some(images_dir),
            "os".into(),
            Some(hsm.clone()),
            None, // activator = None → activate() is selector-flip only
            None,
        )
        .with_hsm_crypto(crypto.clone());
        PartitionBankProvider::new(inner, parts, Some(hsm), Some(crypto))
    }

    #[test]
    fn open_writer_targets_the_mapped_device_and_streams() {
        let base = tmp("write");
        let dev_a = base.join("bankA.img");
        let dev_b = base.join("bankB.img");
        // Pre-create the "devices" (OpenOptions::write needs them to exist, like
        // a real partition node does).
        std::fs::write(&dev_a, b"").unwrap();
        std::fs::write(&dev_b, b"").unwrap();
        let parts = vec![PartitionPart {
            file: "application.img".into(),
            partition_a: dev_a.to_string_lossy().into(),
            partition_b: dev_b.to_string_lossy().into(),
        }];
        let p = build(base.join("images"), parts, "write");

        let mut w = p.open_payload_writer(Bank::B, "application.img").unwrap();
        w.write_all(b"PARTITION-PAYLOAD-B").unwrap();
        w.flush().unwrap();
        drop(w);

        assert_eq!(std::fs::read(&dev_b).unwrap(), b"PARTITION-PAYLOAD-B");
        // bank B write must not touch bank A
        assert_eq!(std::fs::read(&dev_a).unwrap(), b"");
    }

    #[test]
    fn seal_hashes_partition_back_and_verify_matches() {
        let base = tmp("seal");
        let dev_a = base.join("bankA.img");
        let payload = b"the real host application image bytes";
        std::fs::write(&dev_a, payload).unwrap();
        let parts = vec![PartitionPart {
            file: "application.img".into(),
            partition_a: dev_a.to_string_lossy().into(),
            partition_b: base.join("bankB.img").to_string_lossy().into(),
        }];
        let p = build(base.join("images"), parts, "seal");

        // Seal → hashes dev_a back, signs a manifest into the metadata dir.
        p.seal(Bank::A, FirmwareIdentity::default(), 1).unwrap();

        // The IVD artefacts landed in the metadata dir (NOT a 133MB staging file).
        let md = p.metadata_dir(Bank::A).unwrap();
        assert!(md.join(hsm::ivd::IVD_MANIFEST_FILE).exists(), "manifest written");
        assert!(md.join(hsm::ivd::IVD_SIGNATURE_FILE).exists(), "signature written");
        assert!(!md.join("application.img").exists(), "NO staged image in metadata dir");

        // verify_payload re-hashes the partition and matches the true digest.
        let expected = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(payload);
            let d: [u8; 32] = h.finalize().into();
            d
        };
        p.verify_payload(Bank::A, "application.img", &expected).unwrap();

        // A wrong digest is rejected.
        let bad = [0u8; 32];
        assert!(matches!(
            p.verify_payload(Bank::A, "application.img", &bad),
            Err(BankError::Unverifiable(_))
        ));
    }

    #[test]
    fn unmapped_part_name_falls_back_to_inner() {
        // A name not in the partition map must not panic — it delegates to the
        // inner staging-file sink (which, with an images_dir, opens a file).
        let base = tmp("fallback");
        let parts = vec![PartitionPart {
            file: "application.img".into(),
            partition_a: base.join("a.img").to_string_lossy().into(),
            partition_b: base.join("b.img").to_string_lossy().into(),
        }];
        let p = build(base.join("images"), parts, "fallback");
        // "ifs" is not mapped → inner opens images/os/bank_a/ifs
        let w = p.open_payload_writer(Bank::A, "ifs");
        assert!(w.is_ok(), "unmapped name should fall back, not error");
    }
}
