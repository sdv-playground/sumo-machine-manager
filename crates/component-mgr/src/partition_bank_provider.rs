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

use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use nv_store::block::BlockDevice;
use nv_store::types::{Bank, BankSet};

use machine_mgr::bank_provider::{BankError, BankProvider, FirmwareIdentity, InstalledFirmware};
use machine_mgr::{ImageRecord, ResetKind};

use crate::bank_provider::{firmware_to_ivd_identity, IvdBankProvider};

/// One part of a raw-partition bank: its on-disk payload name (the SUIT
/// component-id's last segment, e.g. `application.img`) and the A/B eMMC device
/// paths it is written to. The map is deployment config, not code — the consumer
/// (host/rt/bootloader) fills it at construction.
#[derive(Clone)]
pub struct PartitionPart {
    /// Payload name as it arrives on the wire (`payload_target_name_for_id`).
    pub file: String,
    /// Device path for bank A (e.g. `/dev/emmc0.lnxdata.bank0-application`).
    pub partition_a: String,
    /// Device path for bank B (e.g. `/dev/emmc0.lnxdata.bank1-application`).
    pub partition_b: String,
    /// The platform's own record of this part's image (a hardware boot manager's
    /// image table), when the deployment has one. `None` — the default — is
    /// today's behaviour exactly: nothing recorded, nothing routed.
    pub record: Option<Arc<dyn ImageRecord>>,
}

// Hand-written because `ImageRecord` is `Send + Sync` only (a record is a
// platform handle, not a value); the part renders it as present/absent.
impl std::fmt::Debug for PartitionPart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartitionPart")
            .field("file", &self.file)
            .field("partition_a", &self.partition_a)
            .field("partition_b", &self.partition_b)
            .field("record", &self.record.is_some())
            .finish()
    }
}

impl PartitionPart {
    /// Attach the platform's image record to this part — see [`ImageRecord`] for
    /// the ordering the provider then guarantees.
    pub fn with_record(mut self, r: Arc<dyn ImageRecord>) -> Self {
        self.record = Some(r);
        self
    }

    /// The device path for `bank`.
    fn device(&self, bank: Bank) -> &str {
        match bank {
            Bank::A => &self.partition_a,
            Bank::B => &self.partition_b,
        }
    }
}

/// A sink whose terminal `flush` forces its accumulated writes DURABLE to the
/// medium (`sync_all` = fsync). The OTA streaming pipeline calls `flush()` once
/// when the payload is fully written, so wrapping the device file guarantees the
/// bytes are on the eMMC before `seal` hashes the partition back, before the
/// readback-verify, and before any post-flash reboot/reset — a raw partition left
/// with dirty pages either wedges the node on reboot (the kernel flushes 133 MB
/// on the way down) or, worse, is TRUNCATED when a post-"staged" node reset races
/// the write-behind flush (observed twice on RDB3). `BufWriter` calls this inner
/// `flush` when the buffer drains, so a `BufWriter<SyncingWriter>` fsyncs on its
/// terminal flush.
///
/// The device is also opened `O_SYNC` (see [`open_payload_writer`]), so in
/// production every write is already write-through and this `flush` is a
/// belt-and-suspenders barrier. The [`DurableSink`] seam keeps the barrier
/// unit-testable: production wraps a `std::fs::File` (fsync); a test double
/// substitutes a recorder that observes the sync fires AFTER the last write.
///
/// [`open_payload_writer`]: PartitionBankProvider::open_payload_writer
trait DurableSink: std::io::Write {
    fn sync(&self) -> std::io::Result<()>;
}

impl DurableSink for std::fs::File {
    fn sync(&self) -> std::io::Result<()> {
        self.sync_all()
    }
}

struct SyncingWriter<W: DurableSink> {
    inner: W,
    path: String,
}

impl<W: DurableSink> std::io::Write for SyncingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        // fsync the device — the whole point. sync (not just a buffer drain)
        // forces dirty pages out to the eMMC so a subsequent reboot/reset has
        // nothing to drain and cannot truncate the just-written partition.
        self.inner.sync()?;
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

    /// Point every attached [`ImageRecord`] at `bank`. Called by `activate` and
    /// `rollback` BEFORE the boot selector moves — never by `commit`. Parts with
    /// no record (the default) make this a no-op.
    fn route_records(&self, bank: Bank) -> Result<(), BankError> {
        for part in &self.parts {
            if let Some(r) = &part.record {
                r.route(bank)?;
            }
        }
        Ok(())
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
    fn pending_reboot(&self) -> bool {
        self.inner.pending_reboot()
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
        // Route FIRST: every attached record points at `bank` BEFORE the inner
        // switches the boot selector to it, so the platform is never asked to
        // boot a bank it has not been pointed at. A route error returns here,
        // with the selector still on the old bank.
        self.route_records(bank)?;
        // inner has NO activator → activate() is the boot-selector stage+seal
        // only (the bytes are already on the partition from the sink). No
        // byte-copy, no RAM read.
        self.inner.activate(bank)
    }
    fn commit(&self) -> Result<(), BankError> {
        // No routing here, ever: commit confirms the bank that ALREADY booted —
        // it moves nothing, so there is nothing to point a record at.
        self.inner.commit()
    }
    fn rollback(&self) -> Result<(), BankError> {
        // Same ordering as `activate`, with the target read rather than handed
        // in: `rollback_target` is the bank NV will land on (the sibling of NV
        // `active_bank`, from the boot state `ota::rollback` itself swaps), so
        // the records are pointed at it BEFORE the flip.
        let target = self.inner.rollback_target()?;
        self.route_records(target)?;
        self.inner.rollback()
    }
    fn record_disabled(&self, set: BankSet, disabled: bool) -> Result<(), BankError> {
        self.inner.record_disabled(set, disabled)
    }
    fn disabled(&self, set: BankSet) -> bool {
        self.inner.disabled(set)
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
        // Open write-through (`O_SYNC`): each write reaches the eMMC before it
        // returns, so there is NO write-behind cache for a post-flash node reset
        // to race. Without it the 133 MB sits in the block driver's cache: seal's
        // hash-back + the readback-verify read THROUGH that cache and PASS, but the
        // bytes aren't durable — then either the post-flash reboot wedges the node
        // flushing 133 MB on the way down, or (observed twice on RDB3) a node reset
        // fired seconds after the "staged" ack truncates the partition mid-flush,
        // leaving a bank the qnx6 mount rejects. Write-through also keeps the driver
        // cache coherent with the medium, so the readback-verify reflects what
        // actually landed. The old HostBankActivator ran `sync(1)` for this; the
        // streaming redesign must not lose durability.
        let file = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_SYNC)
            .open(device)
            .map_err(|e| BankError::Failed(format!("open partition {device} for write: {e}")))?;
        tracing::info!(part = %name, device = %device, ?bank, "partition bank: streaming payload straight to device (O_SYNC)");
        // 4 MiB buffer — same rationale as IvdBankProvider (the eMMC write is the
        // #1 upload stage post decrypt/decompress speedups). Wrapped in a
        // SyncingWriter so the pipeline's terminal `flush()` fsyncs as a final
        // barrier on top of O_SYNC.
        const WRITE_BUF: usize = 4 * 1024 * 1024;
        let sink = SyncingWriter {
            inner: file,
            path: device.to_string(),
        };
        Ok(Box::new(std::io::BufWriter::with_capacity(WRITE_BUF, sink)))
    }

    /// Seal by hashing the written partition(s) BACK and signing an IVD manifest
    /// over those digests. No dir-walk (there are no staged files); the manifest
    /// and its signature are written into the small metadata dir. `required` is
    /// unused: the inventory is `self.parts` (raw devices, nothing to seed from
    /// a peer bank dir).
    fn seal(
        &self,
        bank: Bank,
        identity: FirmwareIdentity,
        gen: u64,
        _required: &[String],
    ) -> Result<(), BankError> {
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
            // The record learns the image from the medium BEFORE the bank is
            // signed: a refusal aborts here, with no IvdFile pushed for the
            // parts after this one and nothing signed below.
            if let Some(r) = &part.record {
                r.sealed(bank, size, &sha)?;
            }
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
    use machine_mgr::system_bank_state::{
        InMemorySelectorStore, SharedSystemBankState, SystemBankManager, TestSigner,
    };
    use nv_store::block::MemBlockDevice;
    use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
    use nv_store::types::{BankBootState, BankSet, NvBootState};
    use std::io::Write;
    use std::sync::{Mutex, RwLock};

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

    fn build(
        images_dir: PathBuf,
        parts: Vec<PartitionPart>,
        tag: &str,
    ) -> PartitionBankProvider<MemBlockDevice> {
        build_with(images_dir, parts, tag, nv(), None)
    }

    /// `build` with the boot authorities handed in: an NV store seeded by the
    /// caller and (optionally) a shared boot selector, so the record tests can
    /// watch the switch the records are ordered against.
    fn build_with(
        images_dir: PathBuf,
        parts: Vec<PartitionPart>,
        tag: &str,
        nv: Arc<Mutex<NvStore<MemBlockDevice>>>,
        selector: Option<SharedSystemBankState>,
    ) -> PartitionBankProvider<MemBlockDevice> {
        let ks = provisioned_keystore(tag);
        // Two independent SimHsm handles over the same keystore dir — one as the
        // provisioning-gate HsmProvider, one as the signing HsmCryptoProvider.
        let hsm: Arc<Mutex<dyn hsm::HsmProvider>> =
            Arc::new(Mutex::new(hsm_sim_backend::SimHsm::new(ks.clone())));
        let crypto: Arc<dyn hsm::HsmCryptoProvider> =
            Arc::new(hsm_sim_backend::SimHsm::new(ks.clone()));
        let inner = IvdBankProvider::new(
            nv,
            BankSet::Os,
            false,
            Some(images_dir),
            "os".into(),
            Some(hsm.clone()),
            None, // activator = None → activate() is selector-flip only
            selector,
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
            record: None,
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
            record: None,
        }];
        let p = build(base.join("images"), parts, "seal");

        // Seal → hashes dev_a back, signs a manifest into the metadata dir.
        p.seal(Bank::A, FirmwareIdentity::default(), 1, &[])
            .unwrap();

        // The IVD artefacts landed in the metadata dir (NOT a 133MB staging file).
        let md = p.metadata_dir(Bank::A).unwrap();
        assert!(
            md.join(hsm::ivd::IVD_MANIFEST_FILE).exists(),
            "manifest written"
        );
        assert!(
            md.join(hsm::ivd::IVD_SIGNATURE_FILE).exists(),
            "signature written"
        );
        assert!(
            !md.join("application.img").exists(),
            "NO staged image in metadata dir"
        );

        // verify_payload re-hashes the partition and matches the true digest.
        let expected = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(payload);
            let d: [u8; 32] = h.finalize().into();
            d
        };
        p.verify_payload(Bank::A, "application.img", &expected)
            .unwrap();

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
            record: None,
        }];
        let p = build(base.join("images"), parts, "fallback");
        // "ifs" is not mapped → inner opens images/os/bank_a/ifs
        let w = p.open_payload_writer(Bank::A, "ifs");
        assert!(w.is_ok(), "unmapped name should fall back, not error");
    }

    // A DurableSink double that records the order of writes vs the durability
    // barrier (sync), so we can assert the fsync fires only AFTER the last byte is
    // written — the property the post-flash node reset depends on. A sync that ran
    // before the final write would leave dirty bytes for the reset to lose.
    #[derive(Clone, Default)]
    struct SyncLog(Arc<Mutex<Vec<&'static str>>>);
    struct RecordingSink(SyncLog);
    impl std::io::Write for RecordingSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 .0.lock().unwrap().push("write");
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl DurableSink for RecordingSink {
        fn sync(&self) -> std::io::Result<()> {
            self.0 .0.lock().unwrap().push("sync");
            Ok(())
        }
    }

    #[test]
    fn syncing_writer_syncs_after_all_writes() {
        // Mirror production: BufWriter<SyncingWriter<_>>. The terminal flush must
        // drain every buffered byte to the sink (`write`s) and THEN fsync (`sync`),
        // with nothing written after the barrier.
        let log = SyncLog::default();
        let mut w = std::io::BufWriter::new(SyncingWriter {
            inner: RecordingSink(log.clone()),
            path: "test-device".into(),
        });
        w.write_all(b"first-chunk").unwrap();
        w.write_all(b"second-chunk").unwrap();
        w.flush().unwrap();

        let events = log.0.lock().unwrap().clone();
        let sync_pos = events
            .iter()
            .position(|e| *e == "sync")
            .expect("durability barrier (sync) must fire");
        assert_eq!(
            sync_pos,
            events.len() - 1,
            "sync is the terminal op — nothing written after the barrier: {events:?}"
        );
        assert!(
            events[..sync_pos].iter().all(|e| *e == "write"),
            "every write precedes the sync: {events:?}"
        );
        assert!(
            sync_pos >= 1,
            "at least one write reached the sink before the sync"
        );
    }

    #[test]
    fn verify_payload_fails_on_truncated_partition() {
        // Models the RDB3 failure: the streaming pipeline computed the hash of the
        // FULL image, but a node reset raced the flush and only part of it landed
        // on the medium. verify_payload re-hashes what is actually on the device
        // and must reject it — so the staged/finalized ack fails loudly (both
        // hashes in the error) instead of sealing a partition the post-reset boot
        // can't mount.
        let base = tmp("truncated");
        let dev_a = base.join("bankA.img");
        let full_image = vec![0xABu8; 4096];
        let expected_full = {
            use sha2::{Digest, Sha256};
            let d: [u8; 32] = Sha256::digest(&full_image).into();
            d
        };
        // Only the first 1 KiB actually landed (short/interrupted write).
        std::fs::write(&dev_a, &full_image[..1024]).unwrap();
        let parts = vec![PartitionPart {
            file: "application.img".into(),
            partition_a: dev_a.to_string_lossy().into(),
            partition_b: base.join("bankB.img").to_string_lossy().into(),
            record: None,
        }];
        let p = build(base.join("images"), parts, "truncated");

        match p.verify_payload(Bank::A, "application.img", &expected_full) {
            Err(BankError::Unverifiable(msg)) => {
                assert!(
                    msg.contains(&hex::encode(expected_full)),
                    "loud failure must carry the expected hash: {msg}"
                );
            }
            other => panic!("truncated partition must fail verify, got {other:?}"),
        }
    }

    // --- ImageRecord: the ordering seam ---------------------------------------

    /// One recorded call: the op, the bank it was given, and — for `sealed` —
    /// the `(size, sha256)` that came with it.
    type RecCall = (&'static str, Bank, Option<(u64, [u8; 32])>);

    /// A recording [`ImageRecord`]. Beyond the call log it captures, INSIDE
    /// `route`, what the boot authorities said at that moment — the ordering
    /// guarantee ("routed before the switch") is only observable from in there.
    #[derive(Default)]
    struct Rec {
        calls: Mutex<Vec<RecCall>>,
        fail_sealed: bool,
        fail_route: bool,
        /// Authorities to read at `route` time; `None` in tests that only count.
        witness: Option<(SharedSystemBankState, Arc<Mutex<NvStore<MemBlockDevice>>>)>,
        /// `(selector PRIMARY, NV active_bank)` as of each `route` call.
        seen_at_route: Mutex<Vec<(Option<Bank>, Bank)>>,
    }

    impl Rec {
        fn watching(
            selector: &SharedSystemBankState,
            nv: &Arc<Mutex<NvStore<MemBlockDevice>>>,
        ) -> Self {
            Self {
                witness: Some((selector.clone(), nv.clone())),
                ..Self::default()
            }
        }

        /// The ops recorded so far, in order.
        fn ops(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().iter().map(|c| c.0).collect()
        }

        /// The banks `route` was called with, in order.
        fn routes(&self) -> Vec<Bank> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|c| c.0 == "route")
                .map(|c| c.1)
                .collect()
        }
    }

    impl ImageRecord for Rec {
        fn sealed(&self, bank: Bank, size: u64, sha256: &[u8; 32]) -> Result<(), BankError> {
            self.calls
                .lock()
                .unwrap()
                .push(("sealed", bank, Some((size, *sha256))));
            if self.fail_sealed {
                return Err(BankError::Failed("record refuses this image".into()));
            }
            Ok(())
        }

        fn route(&self, bank: Bank) -> Result<(), BankError> {
            if let Some((sel, nv)) = &self.witness {
                let selected = sel.read().unwrap().active_bank(BankSet::Os);
                self.seen_at_route
                    .lock()
                    .unwrap()
                    .push((selected, nv_os(nv).active_bank));
            }
            self.calls.lock().unwrap().push(("route", bank, None));
            if self.fail_route {
                return Err(BankError::Failed("record refuses this route".into()));
            }
            Ok(())
        }
    }

    /// A mapped part with no record attached; tests add one with `with_record`.
    fn part(file: &str, a: &std::path::Path, b: &std::path::Path) -> PartitionPart {
        PartitionPart {
            file: file.into(),
            partition_a: a.to_string_lossy().into(),
            partition_b: b.to_string_lossy().into(),
            record: None,
        }
    }

    /// NV for the Os set in the state an install+activate leaves: `active` is
    /// the next-boot bank, armed but not yet booted (`committed=false`,
    /// `boot_count=0`) — the only state `ota::rollback` accepts.
    fn nv_armed(active: Bank) -> Arc<Mutex<NvStore<MemBlockDevice>>> {
        let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
        let mut state = NvBootState::default();
        state.banks[BankSet::Os.as_index()] = BankBootState {
            active_bank: active,
            committed: false,
            boot_count: 0,
        };
        nv.write_boot_state(&mut state).unwrap();
        Arc::new(Mutex::new(nv))
    }

    /// The Os slot's boot state as NV has it right now.
    fn nv_os(nv: &Arc<Mutex<NvStore<MemBlockDevice>>>) -> BankBootState {
        nv.lock().unwrap().read_boot_state().unwrap().banks[BankSet::Os.as_index()].clone()
    }

    /// A boot selector whose PRIMARY (booted selection) for Os is `bank`.
    fn selector_on(bank: Bank) -> SharedSystemBankState {
        let mgr =
            SystemBankManager::load(Box::new(InMemorySelectorStore::new()), Box::new(TestSigner));
        let shared: SharedSystemBankState = Arc::new(RwLock::new(mgr));
        {
            let mut g = shared.write().unwrap();
            g.stage(BankSet::Os, bank);
            assert!(g.seal());
        }
        shared
    }

    /// A boot selector mid-trial: PRIMARY = `armed`, rollback floor = `floor`.
    fn selector_armed(floor: Bank, armed: Bank) -> SharedSystemBankState {
        let shared = selector_on(floor);
        {
            let mut g = shared.write().unwrap();
            g.commit(); // floor := the booted selection
            g.stage(BankSet::Os, armed);
            assert!(g.seal()); // PRIMARY := the trial bank
        }
        shared
    }

    fn sha_of(bytes: &[u8]) -> (u64, [u8; 32]) {
        use sha2::{Digest, Sha256};
        (bytes.len() as u64, Sha256::digest(bytes).into())
    }

    #[test]
    fn sealed_called_once_per_part_with_hash_device_values() {
        let base = tmp("rec-sealed");
        let appl = base.join("bankA-appl.img");
        let ifs = base.join("bankA-ifs.img");
        std::fs::write(&appl, b"the real host application image bytes").unwrap();
        std::fs::write(&ifs, vec![0x5Au8; 3000]).unwrap();
        let rec = Arc::new(Rec::default());
        let parts = vec![
            part("application.img", &appl, &base.join("bankB-appl.img")).with_record(rec.clone()),
            part("ifs", &ifs, &base.join("bankB-ifs.img")).with_record(rec.clone()),
            // Absent device → skipped before hashing, so never recorded either.
            part("rootfs", &base.join("absent-a"), &base.join("absent-b")).with_record(rec.clone()),
        ];
        let p = build(base.join("images"), parts, "rec-sealed");

        p.seal(Bank::A, FirmwareIdentity::default(), 1, &[])
            .unwrap();

        let calls = rec.calls.lock().unwrap().clone();
        assert_eq!(
            calls.len(),
            2,
            "one `sealed` per PRESENT mapped part (the absent device stays skipped): {calls:?}"
        );
        // The values are what an independent read+hash of the partition gives —
        // i.e. what came BACK off the medium, not what the wire claimed.
        assert_eq!(
            calls[0],
            (
                "sealed",
                Bank::A,
                Some(sha_of(&std::fs::read(&appl).unwrap()))
            )
        );
        assert_eq!(
            calls[1],
            (
                "sealed",
                Bank::A,
                Some(sha_of(&std::fs::read(&ifs).unwrap()))
            )
        );
    }

    #[test]
    fn sealed_error_aborts_seal_before_signing() {
        let base = tmp("rec-sealed-err");
        let appl = base.join("bankA-appl.img");
        let ifs = base.join("bankA-ifs.img");
        std::fs::write(&appl, b"application image bytes").unwrap();
        std::fs::write(&ifs, b"ifs image bytes").unwrap();
        let rec = Arc::new(Rec {
            fail_sealed: true,
            ..Rec::default()
        });
        let parts = vec![
            part("application.img", &appl, &base.join("bankB-appl.img")).with_record(rec.clone()),
            part("ifs", &ifs, &base.join("bankB-ifs.img")).with_record(rec.clone()),
        ];
        let p = build(base.join("images"), parts, "rec-sealed-err");

        assert!(matches!(
            p.seal(Bank::A, FirmwareIdentity::default(), 1, &[]),
            Err(BankError::Failed(_))
        ));

        // Aborted AT the refusing part: the next part was never hashed…
        assert_eq!(rec.ops(), ["sealed"], "seal stopped at the refusing part");
        // …and nothing was signed — the success test's observables, inverted.
        let md = p.metadata_dir(Bank::A).unwrap();
        assert!(
            !md.join(hsm::ivd::IVD_MANIFEST_FILE).exists(),
            "no manifest written"
        );
        assert!(
            !md.join(hsm::ivd::IVD_SIGNATURE_FILE).exists(),
            "no signature written"
        );
        assert!(matches!(
            p.read_installed(Bank::A),
            Err(BankError::NotInstalled)
        ));
    }

    #[test]
    fn activate_routes_before_the_switch() {
        let base = tmp("rec-activate");
        let nv = nv();
        let selector = selector_on(Bank::A);
        let rec = Arc::new(Rec::watching(&selector, &nv));
        let parts = vec![
            part("application.img", &base.join("a.img"), &base.join("b.img"))
                .with_record(rec.clone()),
        ];
        let p = build_with(
            base.join("images"),
            parts,
            "rec-activate",
            nv,
            Some(selector),
        );
        assert_eq!(
            p.selected_bank(),
            Some(Bank::A),
            "selector starts on the old bank"
        );

        p.activate(Bank::B).unwrap();

        assert_eq!(rec.routes(), [Bank::B], "routed at the activated bank");
        assert_eq!(
            rec.seen_at_route.lock().unwrap().clone(),
            vec![(Some(Bank::A), Bank::A)],
            "the record was routed while the boot authority still said A"
        );
        assert_eq!(
            p.selected_bank(),
            Some(Bank::B),
            "…and only then did the switch happen"
        );
    }

    #[test]
    fn route_error_leaves_selector_untouched() {
        let base = tmp("rec-route-err");
        let selector = selector_on(Bank::A);
        let rec = Arc::new(Rec {
            fail_route: true,
            ..Rec::default()
        });
        let parts = vec![
            part("application.img", &base.join("a.img"), &base.join("b.img"))
                .with_record(rec.clone()),
        ];
        let p = build_with(
            base.join("images"),
            parts,
            "rec-route-err",
            nv(),
            Some(selector),
        );

        assert!(matches!(p.activate(Bank::B), Err(BankError::Failed(_))));
        assert_eq!(
            p.selected_bank(),
            Some(Bank::A),
            "a refused route aborts with the selector still on the old bank"
        );
    }

    #[test]
    fn commit_never_routes() {
        let base = tmp("rec-commit");
        let dev_a = base.join("bankA.img");
        std::fs::write(&dev_a, b"host application image").unwrap();
        // Armed on A: the trial `commit` then has real work to do.
        let nv = nv_armed(Bank::A);
        let selector = selector_on(Bank::A);
        let rec = Arc::new(Rec::default());
        let parts =
            vec![part("application.img", &dev_a, &base.join("bankB.img")).with_record(rec.clone())];
        let p = build_with(
            base.join("images"),
            parts,
            "rec-commit",
            nv.clone(),
            Some(selector),
        );

        p.seal(Bank::A, FirmwareIdentity::default(), 1, &[])
            .unwrap();
        p.activate(Bank::A).unwrap();
        let routes_before = rec.routes().len();
        p.commit().unwrap();

        assert_eq!(routes_before, 1, "the one route came from activate");
        assert_eq!(
            rec.routes().len(),
            routes_before,
            "commit routed nothing — it confirms the booted bank, it moves nothing"
        );
        assert!(
            nv_os(&nv).committed,
            "…and it was a real commit, not a no-op"
        );
    }

    #[test]
    fn rollback_routes_the_bank_nv_lands_on() {
        let base = tmp("rec-rollback");
        // Armed-not-booted (boot_count 0): NV says the trial bank B is next, the
        // selector's PRIMARY is B over an A floor. NOTE `active_bank()` is B
        // here — routing that (instead of the rollback target) is the bug this
        // test exists to catch.
        let nv = nv_armed(Bank::B);
        let selector = selector_armed(Bank::A, Bank::B);
        let rec = Arc::new(Rec::watching(&selector, &nv));
        let parts = vec![
            part("application.img", &base.join("a.img"), &base.join("b.img"))
                .with_record(rec.clone()),
        ];
        let p = build_with(
            base.join("images"),
            parts,
            "rec-rollback",
            nv.clone(),
            Some(selector),
        );
        assert_eq!(p.active_bank(), Bank::B, "the trial bank is the active one");

        p.rollback().unwrap();

        // Routed at the bank NV actually landed on …
        assert_eq!(nv_os(&nv).active_bank, Bank::A, "rollback landed NV on A");
        assert_eq!(p.active_bank(), Bank::A, "…and the selector with it");
        assert_eq!(rec.routes(), [p.active_bank()]);
        // … and routed BEFORE either authority flipped (both still on B).
        assert_eq!(
            rec.seen_at_route.lock().unwrap().clone(),
            vec![(Some(Bank::B), Bank::B)],
            "the record was routed before ota/selector flipped to A"
        );
    }

    #[test]
    fn rollback_ignores_the_providers_cached_running_bank() {
        let base = tmp("rec-rollback-stale");
        // The provider is long-lived: it cached `running_bank` = A at boot, and
        // the install that armed the trial on B ran later. Routing off that
        // cache — or off its sibling — points at the wrong bank; only the NV
        // boot state says where `ota::rollback` will actually land.
        let nv = nv();
        let rec = Arc::new(Rec::default());
        let parts = vec![
            part("application.img", &base.join("a.img"), &base.join("b.img"))
                .with_record(rec.clone()),
        ];
        let p = build_with(
            base.join("images"),
            parts,
            "rec-rollback-stale",
            nv.clone(),
            None, // no selector → active_bank() IS the cached running bank
        );
        assert_eq!(p.active_bank(), Bank::A, "cached at construction");
        {
            // The install lands: NV arms the trial on B (what `ota::install`
            // writes), while the cache still names the booted bank A.
            let mut g = nv.lock().unwrap();
            let mut state = g.read_boot_state().unwrap();
            state.banks[BankSet::Os.as_index()] = BankBootState {
                active_bank: Bank::B,
                committed: false,
                boot_count: 0,
            };
            g.write_boot_state(&mut state).unwrap();
        }

        p.rollback().unwrap();

        assert_eq!(nv_os(&nv).active_bank, Bank::A, "rollback landed NV on A");
        assert_eq!(
            rec.routes(),
            [Bank::A],
            "routed where NV landed — not the cached bank's sibling (B)"
        );
    }

    #[test]
    fn rollback_on_a_committed_set_routes_nothing() {
        let base = tmp("rec-rollback-committed");
        // Committed: there is no trial to discard, so `ota::rollback` refuses.
        // The refusal must come BEFORE any record is touched — a rollback that
        // does not happen must not leave a record pointed somewhere.
        let nv = nv(); // NvBootState default = committed on A
        let selector = selector_on(Bank::A);
        let rec = Arc::new(Rec::default());
        let parts = vec![
            part("application.img", &base.join("a.img"), &base.join("b.img"))
                .with_record(rec.clone()),
        ];
        let p = build_with(
            base.join("images"),
            parts,
            "rec-rollback-committed",
            nv.clone(),
            Some(selector),
        );
        assert!(nv_os(&nv).committed, "the set starts committed");

        // The error is the one `ota::rollback` would have raised — identical
        // with or without a record attached.
        match p.rollback() {
            Err(BankError::Failed(msg)) => {
                assert_eq!(msg, crate::ota::OtaError::NotInTrial.to_string())
            }
            other => panic!("a committed set must refuse rollback, got {other:?}"),
        }
        assert!(
            rec.routes().is_empty(),
            "a refused rollback routes nothing: {:?}",
            rec.routes()
        );
        assert_eq!(
            p.active_bank(),
            Bank::A,
            "…and leaves the boot authority alone"
        );
    }
}
