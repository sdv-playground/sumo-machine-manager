/// NV store operations — typed read/write with sector rotation and CRC integrity.
///
/// CRC-32 covers the entire 4 KB sector (minus the last 4 bytes which hold the CRC).
/// Records are serialized into the sector, zero-padded, then CRC'd.
use crate::block::{BlockDevice, BlockError};
use crate::types::*;

pub const SECTOR_SIZE: usize = 4096;
const CRC_OFFSET: usize = SECTOR_SIZE - 4;

/// NV partition layout within the single NV block device.
pub mod layout {
    pub const BOOT_OFFSET: u64 = 0x000000;
    pub const BOOT_SECTORS: usize = 2;

    pub const FACTORY_OFFSET: u64 = 0x002000;
    pub const FACTORY_SECTORS: usize = 2;

    pub const APP_OFFSET: u64 = 0x004000;
    pub const APP_SECTORS: usize = 2;

    // Vehicle-level coordinator state (§7.2 freshness epoch). Lives in the
    // pre-bankset header region (0x6000..0x8000), well below BANKSET_BASE.
    pub const VEHICLE_OFFSET: u64 = 0x006000;
    pub const VEHICLE_SECTORS: usize = 2;

    // Node update-transaction state (the "reboot owed" record). Header region,
    // after VEHICLE (0x8000..0xA000), still below BANKSET_BASE.
    pub const UPDATE_SESSION_OFFSET: u64 = 0x008000;
    pub const UPDATE_SESSION_SECTORS: usize = 2;

    pub const BANKSET_BASE: u64 = 0x010000;
    pub const BANKSET_STRIDE: u64 = 0x018000; // 96 KB per bank set

    pub const FW_META_A_REL: u64 = 0x000000;
    pub const FW_META_B_REL: u64 = 0x004000;
    pub const FW_META_SECTORS: usize = 4;

    pub const RUNTIME_A_REL: u64 = 0x008000;
    pub const RUNTIME_B_REL: u64 = 0x010000;
    pub const RUNTIME_SECTORS: usize = 8;

    pub fn bankset_offset(set: super::BankSet) -> u64 {
        BANKSET_BASE + (set.as_index() as u64) * BANKSET_STRIDE
    }

    pub fn fw_meta_offset(set: super::BankSet, bank: super::Bank) -> u64 {
        let base = bankset_offset(set);
        base + match bank {
            super::Bank::A => FW_META_A_REL,
            super::Bank::B => FW_META_B_REL,
        }
    }

    pub fn runtime_offset(set: super::BankSet, bank: super::Bank) -> u64 {
        let base = bankset_offset(set);
        base + match bank {
            super::Bank::A => RUNTIME_A_REL,
            super::Bank::B => RUNTIME_B_REL,
        }
    }
}

// --- Low-level sector rotation ---

/// Read the latest valid sector from a rotated region. Returns deserialized record.
pub fn read_record<T: NvRecord>(
    dev: &dyn BlockDevice,
    offset: u64,
    num_sectors: usize,
) -> Option<T> {
    let mut best: Option<(u32, T)> = None;

    for i in 0..num_sectors {
        let sector_offset = offset + (i as u64) * SECTOR_SIZE as u64;
        let mut buf = vec![0u8; SECTOR_SIZE];
        if dev.read(sector_offset, &mut buf).is_err() {
            continue;
        }

        // Check magic
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != T::MAGIC {
            continue;
        }

        // Verify CRC (covers first 4092 bytes, CRC at offset 4092)
        let stored_crc = u32::from_le_bytes([
            buf[CRC_OFFSET],
            buf[CRC_OFFSET + 1],
            buf[CRC_OFFSET + 2],
            buf[CRC_OFFSET + 3],
        ]);
        let computed_crc = crc32fast::hash(&buf[..CRC_OFFSET]);
        if stored_crc != computed_crc {
            continue;
        }

        // Deserialize
        let Some(record) = T::deserialize(&buf) else {
            continue;
        };

        let seq = record.write_seq();
        if best.as_ref().is_none_or(|(best_seq, _)| seq > *best_seq) {
            best = Some((seq, record));
        }
    }

    best.map(|(_, record)| record)
}

/// Write a record to the next sector in a rotated region.
pub fn write_record<T: NvRecord>(
    dev: &mut dyn BlockDevice,
    offset: u64,
    num_sectors: usize,
    record: &mut T,
) -> Result<(), BlockError> {
    // Find current max write_seq and oldest slot
    let mut max_seq: u32 = 0;
    let mut min_seq: u32 = u32::MAX;
    let mut min_idx: usize = 0;
    let mut empty_idx: Option<usize> = None;

    for i in 0..num_sectors {
        let sector_offset = offset + (i as u64) * SECTOR_SIZE as u64;
        let mut header = [0u8; 8];
        if dev.read(sector_offset, &mut header).is_err() {
            continue;
        }

        let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        if magic != T::MAGIC {
            if empty_idx.is_none() {
                empty_idx = Some(i);
            }
            continue;
        }

        let seq = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        if seq > max_seq {
            max_seq = seq;
        }
        if seq < min_seq {
            min_seq = seq;
            min_idx = i;
        }
    }

    let target_idx = empty_idx.unwrap_or(min_idx);
    let new_seq = max_seq.wrapping_add(1);
    record.set_write_seq(new_seq);

    // Serialize into a full sector (zero-padded)
    let mut sector = vec![0u8; SECTOR_SIZE];
    record.serialize(&mut sector);

    // CRC covers first 4092 bytes
    let crc = crc32fast::hash(&sector[..CRC_OFFSET]);
    sector[CRC_OFFSET..CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());

    let target_offset = offset + (target_idx as u64) * SECTOR_SIZE as u64;
    dev.write(target_offset, &sector)?;
    dev.sync()?;

    Ok(())
}

// --- High-level typed NV store ---

/// High-level NV store providing typed access to all NV regions.
pub struct NvStore<D: BlockDevice> {
    dev: D,
    /// How many bank slots this store can address — derived from the device
    /// size once, at open (see [`NvStore::slot_count`]). Not a compile-time
    /// constant: the same binary runs against NV files of different sizes.
    slot_count: usize,
}

/// Outcome of [`NvStore::confirm_running_bank`] — whether the node is running
/// the bank it armed for a bank set, and thus whether that set's node-level
/// reboot-owed marker was cleared. The caller logs the distinction
/// (trial-live vs still-owed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunningBankVerdict {
    /// The running bank matches the armed bank: the reboot-owed bit was cleared
    /// (or was already clear) — the banked trial is live and may be committed.
    Confirmed { bank: Bank },
    /// The running bank differs from the armed bank — a trial boot that fell
    /// back to the recovery bank. The reboot-owed bit is LEFT set, so the node
    /// stays `RebootPending` and a commit is refused (the safety property).
    Mismatch { running: Bank, armed: Bank },
    /// No boot state recorded yet (a fresh device): nothing to confirm.
    NoBootState,
}

impl<D: BlockDevice> NvStore<D> {
    pub fn new(dev: D) -> Self {
        let slot_count = MAX_SLOTS.min(
            (dev.size().saturating_sub(layout::BANKSET_BASE) / layout::BANKSET_STRIDE) as usize,
        );
        tracing::info!("nv store: {slot_count} slots ({} bytes)", dev.size());
        Self { dev, slot_count }
    }

    pub fn into_inner(self) -> D {
        self.dev
    }

    pub fn device(&self) -> &D {
        &self.dev
    }

    /// How many bank slots this device has room for, capped at [`MAX_SLOTS`]
    /// (the width of the reboot-owed mask and of the boot-state record).
    /// Computed once in [`NvStore::new`] — the device is fixed for the store's
    /// life.
    pub fn slot_count(&self) -> usize {
        self.slot_count
    }

    /// Every slot this store can address, low to high. The runtime replacement
    /// for iterating a compile-time slot constant.
    pub fn slots(&self) -> impl Iterator<Item = BankSet> {
        (0..self.slot_count).map(|i| BankSet(i as u8))
    }

    /// Whether `set` is a slot this store can address. False ⇒ its bank region
    /// lies past the end of the device.
    pub fn slot_in_range(&self, set: BankSet) -> bool {
        set.as_index() < self.slot_count
    }

    // --- Boot State ---

    pub fn read_boot_state(&self) -> Option<NvBootState> {
        let mut state: NvBootState =
            read_record(&self.dev, layout::BOOT_OFFSET, layout::BOOT_SECTORS)?;
        // The record always carries MAX_SLOTS entries, but a store only owns
        // the ones its device has room for. Reset the rest: a slot whose banks
        // cannot be read must never look armed or uncommitted to the boot /
        // commit logic.
        for bs in state.banks.iter_mut().skip(self.slot_count) {
            *bs = BankBootState::default();
        }
        Some(state)
    }

    pub fn write_boot_state(&mut self, state: &mut NvBootState) -> Result<(), BlockError> {
        write_record(
            &mut self.dev,
            layout::BOOT_OFFSET,
            layout::BOOT_SECTORS,
            state,
        )
    }

    // --- Factory ---

    pub fn read_factory(&self) -> Option<NvFactory> {
        read_record(&self.dev, layout::FACTORY_OFFSET, layout::FACTORY_SECTORS)
    }

    pub fn write_factory(&mut self, factory: &mut NvFactory) -> Result<(), BlockError> {
        write_record(
            &mut self.dev,
            layout::FACTORY_OFFSET,
            layout::FACTORY_SECTORS,
            factory,
        )
    }

    // --- App ---

    pub fn read_app(&self) -> Option<NvApp> {
        read_record(&self.dev, layout::APP_OFFSET, layout::APP_SECTORS)
    }

    pub fn write_app(&mut self, app: &mut NvApp) -> Result<(), BlockError> {
        write_record(&mut self.dev, layout::APP_OFFSET, layout::APP_SECTORS, app)
    }

    // --- Vehicle (freshness coordinator state, §7.2) ---

    pub fn read_vehicle_state(&self) -> Option<NvVehicle> {
        read_record(&self.dev, layout::VEHICLE_OFFSET, layout::VEHICLE_SECTORS)
    }

    pub fn write_vehicle_state(&mut self, vehicle: &mut NvVehicle) -> Result<(), BlockError> {
        write_record(
            &mut self.dev,
            layout::VEHICLE_OFFSET,
            layout::VEHICLE_SECTORS,
            vehicle,
        )
    }

    /// Bump the monotonic vehicle-epoch (§7.2) and return the new value.
    /// Read-modify-write: reads the latest persisted record (or default),
    /// increments the epoch, writes it back. Because `write_record` always
    /// rotates to a higher `write_seq` and `read_record` returns the
    /// highest, the epoch never rewinds across reboots — the master's
    /// freshness counter only moves forward.
    pub fn bump_vehicle_epoch(&mut self) -> Result<u64, BlockError> {
        let mut v = self.read_vehicle_state().unwrap_or_default();
        v.vehicle_epoch = v.vehicle_epoch.saturating_add(1);
        self.write_vehicle_state(&mut v)?;
        Ok(v.vehicle_epoch)
    }

    // --- Update session (node update-transaction state) ---

    pub fn read_update_session(&self) -> Option<NvUpdateSession> {
        read_record(
            &self.dev,
            layout::UPDATE_SESSION_OFFSET,
            layout::UPDATE_SESSION_SECTORS,
        )
    }

    pub fn write_update_session(
        &mut self,
        session: &mut NvUpdateSession,
    ) -> Result<(), BlockError> {
        write_record(
            &mut self.dev,
            layout::UPDATE_SESSION_OFFSET,
            layout::UPDATE_SESSION_SECTORS,
            session,
        )
    }

    /// Clear the open update session (no reboot owed): write a zeroed record so
    /// the rotation advances `write_seq` and the cleared state is what
    /// `read_update_session` returns after the next reboot.
    pub fn clear_update_session(&mut self) -> Result<(), BlockError> {
        let mut s = NvUpdateSession::default();
        self.write_update_session(&mut s)
    }

    /// Confirm the node is running the bank it armed for `bank_set` and, on a
    /// match, clear that set's node-level reboot-owed bit — the banked-trial
    /// confirmation the `RebootPending` commit gate relies on.
    ///
    /// Contract: `running_bank` is a TRUSTED boot-time signal — the bank the
    /// bootloader actually launched (e.g. the `SELECTED_OS_BANK` env the
    /// bootloader exports), NOT a value re-derived from the NV the device could
    /// have mis-flipped. The ARMED bank is read from NV (`active_bank` for the
    /// set — the pointer `finalize_flash` flipped). The reboot-owed bit is
    /// cleared ONLY when `running_bank == armed`; a mismatch (a trial that fell
    /// back to the recovery bank) LEAVES it set, so the node stays
    /// `RebootPending` and a commit is refused. Idempotent: a match with the bit
    /// already clear is a no-op `Confirmed`.
    ///
    /// The counterpart to component-mgr's `set_reboot_owed(true)` mark at
    /// finalize/arm: mark on arm, clear on confirmed `running == armed`.
    pub fn confirm_running_bank(
        &mut self,
        bank_set: BankSet,
        running_bank: Bank,
    ) -> Result<RunningBankVerdict, BlockError> {
        let Some(mut state) = self.read_boot_state() else {
            return Ok(RunningBankVerdict::NoBootState);
        };
        let bank_index = bank_set.as_index();
        let armed = state.banks[bank_index].active_bank;
        if running_bank != armed {
            return Ok(RunningBankVerdict::Mismatch {
                running: running_bank,
                armed,
            });
        }

        // Persist the positive boot witness before clearing reboot_owed. The
        // component commit gate requires this counter after process restart;
        // clearing the reboot marker first could otherwise make a witnessed
        // hardware trial permanently uncommittable if the boot-state write
        // failed.
        if !state.banks[bank_index].committed && state.banks[bank_index].boot_count == 0 {
            state.banks[bank_index].boot_count = 1;
            self.write_boot_state(&mut state)?;
        }

        let mut s = self.read_update_session().unwrap_or_default();
        let bit = 1u32 << bank_set.as_index();
        if s.reboot_owed & bit != 0 {
            s.reboot_owed &= !bit;
            self.write_update_session(&mut s)?;
        }
        Ok(RunningBankVerdict::Confirmed { bank: armed })
    }

    /// The error a per-slot write gets for a slot this store cannot address.
    /// Names the region the write WOULD have landed on, so the message reads
    /// the same as the `OutOfBounds` the device itself would raise.
    fn out_of_range(&self, set: BankSet) -> BlockError {
        BlockError::OutOfBounds {
            offset: layout::bankset_offset(set),
            len: layout::BANKSET_STRIDE as usize,
            size: self.dev.size(),
        }
    }

    // --- FW Meta (per bank set, per bank) ---

    /// `None` for a slot past [`NvStore::slot_count`] — the same answer as a
    /// never-written record, which is what an unaddressable slot is.
    pub fn read_fw_meta(&self, set: BankSet, bank: Bank) -> Option<NvFwMeta> {
        if !self.slot_in_range(set) {
            return None;
        }
        let offset = layout::fw_meta_offset(set, bank);
        read_record(&self.dev, offset, layout::FW_META_SECTORS)
    }

    pub fn write_fw_meta(
        &mut self,
        set: BankSet,
        bank: Bank,
        meta: &mut NvFwMeta,
    ) -> Result<(), BlockError> {
        if !self.slot_in_range(set) {
            return Err(self.out_of_range(set));
        }
        let offset = layout::fw_meta_offset(set, bank);
        write_record(&mut self.dev, offset, layout::FW_META_SECTORS, meta)
    }

    // --- Runtime (per bank set, per bank) ---

    /// `None` for a slot past [`NvStore::slot_count`] — see
    /// [`read_fw_meta`](Self::read_fw_meta).
    pub fn read_runtime(&self, set: BankSet, bank: Bank) -> Option<NvRuntime> {
        if !self.slot_in_range(set) {
            return None;
        }
        let offset = layout::runtime_offset(set, bank);
        read_record(&self.dev, offset, layout::RUNTIME_SECTORS)
    }

    pub fn write_runtime(
        &mut self,
        set: BankSet,
        bank: Bank,
        runtime: &mut NvRuntime,
    ) -> Result<(), BlockError> {
        if !self.slot_in_range(set) {
            return Err(self.out_of_range(set));
        }
        let offset = layout::runtime_offset(set, bank);
        write_record(&mut self.dev, offset, layout::RUNTIME_SECTORS, runtime)
    }

    /// Copy runtime data from one bank to another (copy-on-update for OTA).
    pub fn copy_runtime(&mut self, set: BankSet, from: Bank, to: Bank) -> Result<(), BlockError> {
        let Some(mut runtime) = self.read_runtime(set, from) else {
            // Source has no runtime data — write empty default to target
            let mut empty = NvRuntime::default();
            return self.write_runtime(set, to, &mut empty);
        };
        self.write_runtime(set, to, &mut runtime)
    }
}

/// Device size that holds the full NV layout for exactly `slots` bank slots:
/// the fixed header region plus one `BANKSET_STRIDE` window per slot. The
/// inverse of [`NvStore::slot_count`] — what a creator asks for, versus what
/// an opener derives.
pub const fn nv_device_size(slots: usize) -> u64 {
    layout::BANKSET_BASE + slots as u64 * layout::BANKSET_STRIDE
}

/// The size a fresh store is created with: a [`DEFAULT_SLOTS`]-slot store
/// (`0x190000` = 1.5625 MiB). NOT a floor a store must meet — a store's real
/// slot count is derived from its device at open ([`NvStore::slot_count`]),
/// so a smaller file is simply a smaller store, and a larger one addresses
/// more slots (up to [`MAX_SLOTS`]).
///
/// History: 0x88000 (5 slots) → 0x100000 (10 slots) on 2026-05-29, when the
/// RT/Cortex-M7 component landed on a slot the file had no room for; →
/// 0x190000 (16 slots) on 2026-09-23 with the runtime slot count. The name is
/// kept because ~60 test fixtures and the supernova host address it.
///
/// Growing an existing on-device file is the HOST's job, not this library's:
/// `supernova-machine-manager/src/main.rs` compares the file against the size
/// it wants and re-creates (wipes) it when it falls short — operators
/// re-provision via the factory_reset / provisioning flow. This repo's `boot`
/// and `vm-sovd` binaries only create the file when it is MISSING; they never
/// resize one that exists (and could not: qnx6's `ftruncate(grow)` is a silent
/// no-op — see `FileBlockDevice::create`).
pub const MIN_NV_DEVICE_SIZE: u64 = nv_device_size(DEFAULT_SLOTS);
