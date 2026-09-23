//! Core types for the NV store bank management system.
//!
//! Independent A/B bank sets on a fixed semantic slot layout
//! (low slot → high in the boot order):
//!
//! - Hsm (Hardware Security Module — single-banked, non-rollbackable) — slot 0
//! - Bootloader (reserved, unused) — slot 1
//! - Os (host OS: IFS + rootfs, updated atomically; the host rides here) — slot 2
//! - Rt (realtime / Cortex-M7 core) — slot 3
//! - Vm1 (Linux or QNX VM) — slot 4
//! - Vm2 (Linux or QNX VM) — slot 5

/// Identifies which bank is active within a bank set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum Bank {
    A = 0,
    B = 1,
}

impl Bank {
    pub fn other(self) -> Self {
        match self {
            Bank::A => Bank::B,
            Bank::B => Bank::A,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Bank::A),
            1 => Some(Bank::B),
            _ => None,
        }
    }
}

/// Identifies which bank set — a numeric slot index in the NV
/// partition layout. The slot index is a fixed semantic layout
/// (`Hsm=0`, `Bootloader=1`, `Os=2`, `Rt=3`, `Vm1=4`, `Vm2=5`)
/// exposed as associated constants; the type itself is opaque, so
/// any slot index in `0..MAX_SLOTS` is a valid `BankSet` — whether a
/// given store can *address* it is a per-store question
/// ([`NvStore::slot_in_range`](crate::store::NvStore::slot_in_range)).
///
/// Phase 2 moves the per-slot behavior (dir name, file-naming
/// layout) off the type and into a deployment-config-supplied
/// `BankSetSpec`. Phase 3 makes the slot assignment itself
/// config-driven so deployments add components without touching
/// these constants.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct BankSet(pub u8);

#[allow(non_upper_case_globals)]
impl BankSet {
    // Fixed semantic slot layout. The slot index encodes the
    // component's role in the boot order, low to high:
    //   Hsm (security root) → Bootloader → Os (host) → Rt
    //   (realtime core) → the application VMs.
    pub const Hsm: BankSet = BankSet(0);
    pub const Bootloader: BankSet = BankSet(1);
    pub const Os: BankSet = BankSet(2);
    pub const Rt: BankSet = BankSet(3);
    pub const Vm1: BankSet = BankSet(4);
    pub const Vm2: BankSet = BankSet(5);

    /// Map this slot to its array index in NV records (`banks[i]`).
    /// Replaces `bank_set as usize`.
    pub fn as_index(self) -> usize {
        self.0 as usize
    }

    /// Parse a config-string name to a well-known slot. Phase 3 will
    /// remove this entirely — slot assignment moves into the
    /// component spec, no string-to-slot lookups left.
    ///
    /// Intentionally not the `std::str::FromStr` trait method — the
    /// trait requires an `Err` type and an infallible parse semantics
    /// we don't want here (unknown strings legitimately return None,
    /// not a hard error).
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "hsm" => Some(BankSet::Hsm),
            "bootloader" | "boot" => Some(BankSet::Bootloader),
            "os" | "host" | "host-os" | "host_os" | "supernova" | "app" => Some(BankSet::Os),
            "rt" | "custom" => Some(BankSet::Rt),
            "os1" | "vm1" => Some(BankSet::Vm1),
            "os2" | "vm2" => Some(BankSet::Vm2),
            _ => None,
        }
    }
}

/// Hard ceiling on bank slots: the width of the `NvUpdateSession`
/// reboot-owed bitmask (u32) AND the capacity of the `NvBootState`
/// `banks` array. How many slots a given store *addresses* is a
/// runtime property derived from its device size
/// ([`NvStore::slot_count`](crate::store::NvStore::slot_count)); this
/// is only the bound neither can exceed.
pub const MAX_SLOTS: usize = 32;

/// Slot count a fresh store is created with when the platform doesn't
/// say otherwise — the CVC contract's image count. An existing store
/// keeps whatever its device size gives it; only the create path
/// (`nv_device_size(DEFAULT_SLOTS)`) uses this.
pub const DEFAULT_SLOTS: usize = 16;

pub const MAX_TRIAL_BOOTS: u8 = 10;

// NV partition magic numbers (sector validation)
pub const MAGIC_BOOT: u32 = 0x4E564231; // "NVB1"
pub const MAGIC_FACTORY: u32 = 0x4E564631; // "NVF1"
pub const MAGIC_FW_META: u32 = 0x4E564D32; // "NVM2" (v2: SW identity moved to signed IVD manifest)
pub const MAGIC_RUNTIME: u32 = 0x4E565231; // "NVR1"
pub const MAGIC_APP: u32 = 0x4E564131; // "NVA1"
pub const MAGIC_VEHICLE: u32 = 0x4E565631; // "NVV1"
pub const MAGIC_UPDATE_SESSION: u32 = 0x4E565531; // "NVU1" (node update transaction)

/// Trait for NV records that can be serialized to/from raw sector bytes.
///
/// CRC is NOT part of the record — it's a sector-level concern handled by
/// `read_latest_sector` / `write_next_sector`. Records include magic and
/// write_seq in their serialization.
pub trait NvRecord: Sized {
    const MAGIC: u32;

    /// Serialize this record into `buf`. Caller guarantees `buf.len() >= Self::size()`.
    /// Writes magic at [0..4] and write_seq at [4..8].
    fn serialize(&self, buf: &mut [u8]);

    /// Deserialize from `buf`. Returns None if data is invalid.
    /// Magic already validated by sector reader; write_seq at [4..8].
    fn deserialize(buf: &[u8]) -> Option<Self>;

    /// Serialized size of this record (excluding sector padding and CRC).
    fn size() -> usize;

    /// Get the write_seq from this record.
    fn write_seq(&self) -> u32;

    /// Set the write_seq on this record.
    fn set_write_seq(&mut self, seq: u32);
}

// --- Helper functions for serialization ---

fn put_u32_le(buf: &mut [u8], offset: usize, val: u32) {
    buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

fn get_u32_le(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

fn put_u64_le(buf: &mut [u8], offset: usize, val: u64) {
    buf[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
}

fn get_u64_le(buf: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ])
}

fn put_u16_le(buf: &mut [u8], offset: usize, val: u16) {
    buf[offset..offset + 2].copy_from_slice(&val.to_le_bytes());
}

fn get_u16_le(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

fn put_bytes(buf: &mut [u8], offset: usize, src: &[u8]) {
    buf[offset..offset + src.len()].copy_from_slice(src);
}

fn get_bytes<const N: usize>(buf: &[u8], offset: usize) -> [u8; N] {
    let mut arr = [0u8; N];
    arr.copy_from_slice(&buf[offset..offset + N]);
    arr
}

// --- Per-bank-set boot state ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BankBootState {
    pub active_bank: Bank,
    pub committed: bool,
    pub boot_count: u8,
}

impl Default for BankBootState {
    fn default() -> Self {
        Self {
            active_bank: Bank::A,
            committed: true,
            boot_count: 0,
        }
    }
}

/// Complete boot state for every slot the record can carry.
///
/// Wire format (`8 + 3*MAX_SLOTS` = 104 bytes): a fixed header, then one
/// 3-byte entry per slot at a fixed stride, in slot-index order.
/// ```text
/// [0..4]       magic (NVB1)
/// [4..8]       write_seq
/// [8 + i*3]    banks[i].active_bank   for i in 0..MAX_SLOTS
/// [9 + i*3]    banks[i].committed
/// [10 + i*3]   banks[i].boot_count
/// ```
///
/// The base and stride have never moved, so the record only ever grew in
/// place and the magic was never bumped: 5 slots → 10 on 2026-05-29 (the
/// RT component needed a slot the file had no room for), 10 →
/// `MAX_SLOTS` on 2026-09-23 (the addressable count became a per-store
/// runtime value derived from the device size). A record written by an
/// older, fewer-slot writer leaves the trailing entries as the sector's
/// zero padding, which decodes as `{Bank::A, committed: false,
/// boot_count: 0}` — harmless, because
/// [`read_boot_state`](crate::store::NvStore::read_boot_state) resets
/// every entry past the store's own slot count to the default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvBootState {
    pub write_seq: u32,
    pub banks: [BankBootState; MAX_SLOTS],
}

impl Default for NvBootState {
    fn default() -> Self {
        Self {
            write_seq: 0,
            banks: std::array::from_fn(|_| BankBootState::default()),
        }
    }
}

impl NvRecord for NvBootState {
    const MAGIC: u32 = MAGIC_BOOT;

    fn size() -> usize {
        8 + 3 * MAX_SLOTS // 4 magic + 4 seq + 3 bytes per slot
    }

    fn write_seq(&self) -> u32 {
        self.write_seq
    }

    fn set_write_seq(&mut self, seq: u32) {
        self.write_seq = seq;
    }

    fn serialize(&self, buf: &mut [u8]) {
        put_u32_le(buf, 0, Self::MAGIC);
        put_u32_le(buf, 4, self.write_seq);
        for (i, bs) in self.banks.iter().enumerate() {
            let off = 8 + i * 3;
            buf[off] = bs.active_bank as u8;
            buf[off + 1] = bs.committed as u8;
            buf[off + 2] = bs.boot_count;
        }
    }

    fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::size() {
            return None;
        }
        let write_seq = get_u32_le(buf, 4);
        let mut banks: [BankBootState; MAX_SLOTS] = std::array::from_fn(|_| Default::default());
        #[allow(clippy::needless_range_loop)]
        for i in 0..MAX_SLOTS {
            let off = 8 + i * 3;
            banks[i] = BankBootState {
                active_bank: Bank::from_u8(buf[off])?,
                committed: buf[off + 1] != 0,
                boot_count: buf[off + 2],
            };
        }
        Some(Self { write_seq, banks })
    }
}

/// Factory data — write-once, shared across all banks.
///
/// Wire format (200 bytes):
/// ```text
/// [0..4]     magic (NVF1)
/// [4..8]     write_seq
/// [8..40]    serial_number (32)     F18C
/// [40..48]   manufacturing_date (8) F18B
/// [48..65]   vin (17)               F190
/// [65..97]   ecu_hw_number (32)     F191
/// [97..129]  supplier_hw_number (32) F192
/// [129..161] supplier_hw_version (32) F193
/// [161..193] supplier_id (32)       F18A
/// [193]      device_type
/// [194..200] padding
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NvFactory {
    pub write_seq: u32,
    pub serial_number: [u8; 32],
    pub manufacturing_date: [u8; 8],
    pub vin: [u8; 17],
    pub ecu_hw_number: [u8; 32],
    pub supplier_hw_number: [u8; 32],
    pub supplier_hw_version: [u8; 32],
    pub supplier_id: [u8; 32],
    pub device_type: u8,
}

impl NvRecord for NvFactory {
    const MAGIC: u32 = MAGIC_FACTORY;

    fn size() -> usize {
        200
    }

    fn write_seq(&self) -> u32 {
        self.write_seq
    }

    fn set_write_seq(&mut self, seq: u32) {
        self.write_seq = seq;
    }

    fn serialize(&self, buf: &mut [u8]) {
        put_u32_le(buf, 0, Self::MAGIC);
        put_u32_le(buf, 4, self.write_seq);
        put_bytes(buf, 8, &self.serial_number);
        put_bytes(buf, 40, &self.manufacturing_date);
        put_bytes(buf, 48, &self.vin);
        put_bytes(buf, 65, &self.ecu_hw_number);
        put_bytes(buf, 97, &self.supplier_hw_number);
        put_bytes(buf, 129, &self.supplier_hw_version);
        put_bytes(buf, 161, &self.supplier_id);
        buf[193] = self.device_type;
    }

    fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::size() {
            return None;
        }
        Some(Self {
            write_seq: get_u32_le(buf, 4),
            serial_number: get_bytes(buf, 8),
            manufacturing_date: get_bytes(buf, 40),
            vin: get_bytes(buf, 48),
            ecu_hw_number: get_bytes(buf, 65),
            supplier_hw_number: get_bytes(buf, 97),
            supplier_hw_version: get_bytes(buf, 129),
            supplier_id: get_bytes(buf, 161),
            device_type: buf[193],
        })
    }
}

/// Per-bank firmware metadata — boot/install state only.
///
/// SW-identity DIDs (F187-F19E: fw_version, spare/ecu/supplier sw
/// numbers + versions, odx file id, system name, programming date,
/// tester serial) used to live here too. They were a hand-synced
/// duplicate of the bank's signed IVD manifest and a drift risk, so
/// they now live ONLY in the manifest (`hsm::ivd::IvdIdentity`) — the
/// single signed source. `component_mgr::did` derives the identification DIDs
/// from there on read. This record keeps only the fields the boot /
/// OTA-install path needs.
///
/// Wire format (64 bytes):
/// ```text
/// [0..4]     magic (NVM2)
/// [4..8]     write_seq
/// [8..12]    fw_seq
/// [12..16]   fw_secver
/// [16..20]   fw_crc
/// [20..52]   image_sha256 (32)
/// [52..56]   min_security_ver
/// [56..64]   gen (u64, install-time generation counter)
/// ```
///
/// The MAGIC bumped (NVM1 → NVM2) with this layout change, so any v1
/// blob on an existing device is rejected on read and forces a
/// re-flash — the same contract as the v2→v3 IVD manifest bump that
/// carries the identity now.
///
/// `gen` is the IVD anti-rollback counter:
/// - At install time the caller writes `nv.committed_gen + 1` here
///   AND embeds the same value in the bank's signed IVD manifest.
/// - At commit time the previously-trial bank becomes the new
///   committed bank; its stored `gen` is now the implicit
///   `committed_gen` for the bank set (read it via
///   `nv.read_fw_meta(set, active_committed_bank).gen`).
/// - The launch-time IVD verifier cross-checks
///   `manifest.gen == this_bank.gen` (slot binding) and
///   `manifest.gen >= committed_gen` (rollback floor).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NvFwMeta {
    pub write_seq: u32,
    pub fw_seq: u32,
    pub fw_secver: u32,
    pub fw_crc: u32,
    pub image_sha256: [u8; 32],
    pub min_security_ver: u32,
    pub gen: u64,
}

impl NvRecord for NvFwMeta {
    const MAGIC: u32 = MAGIC_FW_META;

    fn size() -> usize {
        64
    }

    fn write_seq(&self) -> u32 {
        self.write_seq
    }

    fn set_write_seq(&mut self, seq: u32) {
        self.write_seq = seq;
    }

    fn serialize(&self, buf: &mut [u8]) {
        put_u32_le(buf, 0, Self::MAGIC);
        put_u32_le(buf, 4, self.write_seq);
        put_u32_le(buf, 8, self.fw_seq);
        put_u32_le(buf, 12, self.fw_secver);
        put_u32_le(buf, 16, self.fw_crc);
        put_bytes(buf, 20, &self.image_sha256);
        put_u32_le(buf, 52, self.min_security_ver);
        put_u64_le(buf, 56, self.gen);
    }

    fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::size() {
            return None;
        }
        Some(Self {
            write_seq: get_u32_le(buf, 4),
            fw_seq: get_u32_le(buf, 8),
            fw_secver: get_u32_le(buf, 12),
            fw_crc: get_u32_le(buf, 16),
            image_sha256: get_bytes(buf, 20),
            min_security_ver: get_u32_le(buf, 52),
            gen: get_u64_le(buf, 56),
        })
    }
}

/// A single writable DID entry in the runtime partition.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DidEntry {
    pub did: u16,
    pub len: u8,
    pub data: [u8; 32],
}

impl DidEntry {
    pub const WIRE_SIZE: usize = 35; // 2 + 1 + 32
}

/// A single DTC entry in the runtime partition.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DtcEntry {
    pub dtc_number: u32,
    pub status: u8,
}

impl DtcEntry {
    pub const WIRE_SIZE: usize = 5; // 4 + 1
}

pub const MAX_DIDS: usize = 20;
pub const MAX_DTCS: usize = 16;

/// Per-bank runtime data — writable DIDs and DTCs.
///
/// Wire format (792 bytes):
/// ```text
/// [0..4]     magic (NVR1)
/// [4..8]     write_seq
/// [8]        did_count
/// [9..709]   dids[20] (20 * 35 = 700 bytes)
/// [709]      dtc_count
/// [710..790] dtcs[16] (16 * 5 = 80 bytes)
/// [790..792] padding
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvRuntime {
    pub write_seq: u32,
    pub did_count: u8,
    pub dids: [DidEntry; MAX_DIDS],
    pub dtc_count: u8,
    pub dtcs: [DtcEntry; MAX_DTCS],
}

impl Default for NvRuntime {
    fn default() -> Self {
        Self {
            write_seq: 0,
            did_count: 0,
            dids: std::array::from_fn(|_| DidEntry::default()),
            dtc_count: 0,
            dtcs: std::array::from_fn(|_| DtcEntry::default()),
        }
    }
}

impl NvRecord for NvRuntime {
    const MAGIC: u32 = MAGIC_RUNTIME;

    fn size() -> usize {
        792
    }

    fn write_seq(&self) -> u32 {
        self.write_seq
    }

    fn set_write_seq(&mut self, seq: u32) {
        self.write_seq = seq;
    }

    fn serialize(&self, buf: &mut [u8]) {
        put_u32_le(buf, 0, Self::MAGIC);
        put_u32_le(buf, 4, self.write_seq);
        buf[8] = self.did_count;
        for (i, did) in self.dids.iter().enumerate() {
            let off = 9 + i * DidEntry::WIRE_SIZE;
            put_u16_le(buf, off, did.did);
            buf[off + 2] = did.len;
            put_bytes(buf, off + 3, &did.data);
        }
        let dtc_count_off = 9 + MAX_DIDS * DidEntry::WIRE_SIZE;
        buf[dtc_count_off] = self.dtc_count;
        for (i, dtc) in self.dtcs.iter().enumerate() {
            let off = dtc_count_off + 1 + i * DtcEntry::WIRE_SIZE;
            put_u32_le(buf, off, dtc.dtc_number);
            buf[off + 4] = dtc.status;
        }
    }

    fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::size() {
            return None;
        }
        let write_seq = get_u32_le(buf, 4);
        let did_count = buf[8];
        if did_count as usize > MAX_DIDS {
            return None;
        }
        let mut dids: [DidEntry; MAX_DIDS] = std::array::from_fn(|_| DidEntry::default());
        #[allow(clippy::needless_range_loop)]
        for i in 0..MAX_DIDS {
            let off = 9 + i * DidEntry::WIRE_SIZE;
            dids[i] = DidEntry {
                did: get_u16_le(buf, off),
                len: buf[off + 2],
                data: get_bytes(buf, off + 3),
            };
        }
        let dtc_count_off = 9 + MAX_DIDS * DidEntry::WIRE_SIZE;
        let dtc_count = buf[dtc_count_off];
        if dtc_count as usize > MAX_DTCS {
            return None;
        }
        let mut dtcs: [DtcEntry; MAX_DTCS] = std::array::from_fn(|_| DtcEntry::default());
        #[allow(clippy::needless_range_loop)]
        for i in 0..MAX_DTCS {
            let off = dtc_count_off + 1 + i * DtcEntry::WIRE_SIZE;
            dtcs[i] = DtcEntry {
                dtc_number: get_u32_le(buf, off),
                status: buf[off + 4],
            };
        }
        Some(Self {
            write_seq,
            did_count,
            dids,
            dtc_count,
            dtcs,
        })
    }
}

/// Shared application data — cert revocation, timestamps, config.
///
/// Wire format (2060 bytes):
/// ```text
/// [0..4]      magic (NVA1)
/// [4..8]      write_seq
/// [8..2056]   data (2048 bytes)
/// [2056..2060] padding
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvApp {
    pub write_seq: u32,
    pub data: [u8; 2048],
}

impl Default for NvApp {
    fn default() -> Self {
        Self {
            write_seq: 0,
            data: [0; 2048],
        }
    }
}

impl NvRecord for NvApp {
    const MAGIC: u32 = MAGIC_APP;

    fn size() -> usize {
        2060
    }

    fn write_seq(&self) -> u32 {
        self.write_seq
    }

    fn set_write_seq(&mut self, seq: u32) {
        self.write_seq = seq;
    }

    fn serialize(&self, buf: &mut [u8]) {
        put_u32_le(buf, 0, Self::MAGIC);
        put_u32_le(buf, 4, self.write_seq);
        put_bytes(buf, 8, &self.data);
    }

    fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::size() {
            return None;
        }
        Some(Self {
            write_seq: get_u32_le(buf, 4),
            data: get_bytes(buf, 8),
        })
    }
}

/// Vehicle-level mutable coordinator state — the §7.2 freshness epoch.
///
/// `vehicle_epoch` is a monotonic counter the master freshness
/// coordinator bumps at each power-on / online-sync; peer ECUs adopt
/// `max(local, master)` and never rewind, so a bad master can stall
/// freshness but never replay an old epoch into validity. Vehicle-wide
/// (not per-bank) and distinct from the write-once VIN in [`NvFactory`].
///
/// A `[16..24]` u64 field once lived here but was retired: its role is now
/// served by the HSM's rollback-proof monotonic counter
/// (`HsmProvider::{read,raise}_monotonic`) — one anti-rollback value in one
/// place, in the same tamper domain as the keystore `security_version` counter,
/// instead of the split-source anti-pattern a rollback defense must not have.
/// Those bytes stay reserved (kept in the layout so the record size and sector
/// rotation are unchanged; no format bump).
///
/// Wire format (24 bytes):
/// ```text
/// [0..4]    magic (NVV1)
/// [4..8]    write_seq
/// [8..16]   vehicle_epoch (u64)
/// [16..24]  reserved (retired field; role now HSM-resident)
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NvVehicle {
    pub write_seq: u32,
    pub vehicle_epoch: u64,
}

impl NvRecord for NvVehicle {
    const MAGIC: u32 = MAGIC_VEHICLE;

    fn size() -> usize {
        24
    }

    fn write_seq(&self) -> u32 {
        self.write_seq
    }

    fn set_write_seq(&mut self, seq: u32) {
        self.write_seq = seq;
    }

    fn serialize(&self, buf: &mut [u8]) {
        put_u32_le(buf, 0, Self::MAGIC);
        put_u32_le(buf, 4, self.write_seq);
        put_u64_le(buf, 8, self.vehicle_epoch);
        // [16..24] reserved (retired field) — leave zeroed.
    }

    fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::size() {
            return None;
        }
        Some(Self {
            write_seq: get_u32_le(buf, 4),
            vehicle_epoch: get_u64_le(buf, 8),
            // [16..24] reserved — ignored on read.
        })
    }
}

/// Node update-transaction state — the durable half of the per-ECU update
/// session. Written once a node activation reboot is *owed*: that's the one bit
/// that can't be reconstructed from the per-bank `committed` flags after a power
/// cycle (a singleshot write-through commits immediately, so "a reboot is still
/// owed to run the new code" lives nowhere else). The gate reads it to refuse a
/// new flash while a reboot is pending; the orchestrator reads it (over SOVD) to
/// reconstruct where a campaign was. `reboot_owed == 0` ⇒ no open session.
///
/// ```text
/// [0..4]    magic (NVU1)
/// [4..8]    write_seq
/// [8..40]   session_id (32 bytes; the transaction's provenance — zero = none)
/// [40..44]  reboot_owed (u32 bitmask over bank sets; bit i = BankSet(i))
/// ```
///
/// `reboot_owed` was a u16 at `[40..42]` until 2026-09-23, when the slot
/// count became a per-store runtime value bounded by `MAX_SLOTS`. Being the
/// LAST field, widening it is a pure extension — a u16-era record's two
/// trailing bytes are the sector's zero padding, so it decodes with the
/// upper half zero and the magic did not need a bump.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NvUpdateSession {
    pub write_seq: u32,
    /// The update transaction's session id — its provenance, so a re-run can tell
    /// *its own* interrupted transaction from a different one. Interim: the
    /// vehicle-release content identity; later the SUIT L1 campaign-manifest id
    /// (both reduced to 32 bytes). All-zero ⇒ no open session.
    pub session_id: [u8; 32],
    /// Bank sets that owe the coalesced node reboot (bit i ⇒ `BankSet(i)`).
    /// Nonzero ⇒ the node is `RebootPending`.
    pub reboot_owed: u32,
}

impl NvUpdateSession {
    /// True when a node reboot is owed — an open transaction awaits its
    /// activation reboot.
    pub fn reboot_pending(&self) -> bool {
        self.reboot_owed != 0
    }

    /// True when bank set `set` owes the pending node reboot.
    pub fn owes(&self, set: BankSet) -> bool {
        self.reboot_owed & (1u32 << set.as_index()) != 0
    }
}

impl NvRecord for NvUpdateSession {
    const MAGIC: u32 = MAGIC_UPDATE_SESSION;

    fn size() -> usize {
        44
    }

    fn write_seq(&self) -> u32 {
        self.write_seq
    }

    fn set_write_seq(&mut self, seq: u32) {
        self.write_seq = seq;
    }

    fn serialize(&self, buf: &mut [u8]) {
        put_u32_le(buf, 0, Self::MAGIC);
        put_u32_le(buf, 4, self.write_seq);
        put_bytes(buf, 8, &self.session_id);
        put_u32_le(buf, 40, self.reboot_owed);
    }

    fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::size() {
            return None;
        }
        Some(Self {
            write_seq: get_u32_le(buf, 4),
            session_id: get_bytes::<32>(buf, 8),
            reboot_owed: get_u32_le(buf, 40),
        })
    }
}
