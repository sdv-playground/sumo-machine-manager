//! DID resolution — reads from the correct NV source based on DID number.
//!
//! Resolution order:
//!
//! 1. Runtime DIDs (writable, per-bank) — active bank's NV Runtime
//! 2. FW Meta DIDs (SW identity, per-bank) — active bank's NV FW Meta
//! 3. Factory DIDs (hardware identity, shared) — NV Factory
//! 4. Dynamic DIDs (computed at runtime)
#![allow(clippy::field_reassign_with_default)]

use nv_store::block::BlockDevice;
use nv_store::store::NvStore;
use nv_store::types::*;

// Standard UDS DID numbers
pub const DID_SPARE_PART_NUMBER: u16 = 0xF187;
pub const DID_ECU_SW_NUMBER: u16 = 0xF188;
pub const DID_FW_VERSION: u16 = 0xF189;
pub const DID_SUPPLIER_ID: u16 = 0xF18A;
pub const DID_MANUFACTURING_DATE: u16 = 0xF18B;
pub const DID_SERIAL_NUMBER: u16 = 0xF18C;
pub const DID_VIN: u16 = 0xF190;
pub const DID_ECU_HW_NUMBER: u16 = 0xF191;
pub const DID_SUPPLIER_HW_NUMBER: u16 = 0xF192;
pub const DID_SUPPLIER_HW_VERSION: u16 = 0xF193;
pub const DID_SUPPLIER_SW_NUMBER: u16 = 0xF194;
pub const DID_SUPPLIER_SW_VERSION: u16 = 0xF195;
pub const DID_SYSTEM_NAME: u16 = 0xF197;
pub const DID_TESTER_SERIAL: u16 = 0xF198;
pub const DID_PROGRAMMING_DATE: u16 = 0xF199;
pub const DID_ODX_FILE_ID: u16 = 0xF19E;

// Custom diagnostic DIDs
pub const DID_ACTIVE_BANK: u16 = 0xFD00;
pub const DID_COMMITTED: u16 = 0xFD01;
pub const DID_MIN_SECURITY_VER: u16 = 0xFD02;
pub const DID_CURRENT_SECURITY_VER: u16 = 0xFD03;
pub const DID_BOOT_COUNT: u16 = 0xFD04;
pub const DID_GUEST_STATE: u16 = 0xFD05;
pub const DID_HEARTBEAT_SEQ: u16 = 0xFD06;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DidValue {
    /// Fixed-length byte data (from NV, zero-padded)
    Bytes(Vec<u8>),
    /// Not found
    NotFound,
}

impl DidValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            DidValue::Bytes(b) => {
                let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
                std::str::from_utf8(&b[..end]).ok()
            }
            DidValue::NotFound => None,
        }
    }
}

/// Read a DID for a given bank set. Resolves from Runtime → FW Meta → Factory → Dynamic.
///
/// `running_bank`: the bank the ECU is actually running on. This may differ
/// from NV `active_bank` after install (which stages the next-boot bank).
/// Pass `None` to use NV active_bank (e.g. during boot before running_bank is known).
pub fn read_did<D: BlockDevice>(
    nv: &NvStore<D>,
    set: BankSet,
    did: u16,
    running_bank: Option<Bank>,
) -> DidValue {
    let state = match nv.read_boot_state() {
        Some(s) => s,
        None => return DidValue::NotFound,
    };
    let active = running_bank.unwrap_or(state.banks[set.as_index()].active_bank);

    // 1. Check runtime DIDs (writable, per-bank)
    if let Some(runtime) = nv.read_runtime(set, active) {
        for i in 0..runtime.did_count as usize {
            if runtime.dids[i].did == did {
                let len = runtime.dids[i].len as usize;
                return DidValue::Bytes(runtime.dids[i].data[..len].to_vec());
            }
        }
    }

    // 2. Check FW Meta DIDs (SW identity, per-bank)
    if let Some(meta) = nv.read_fw_meta(set, active) {
        let val = match did {
            DID_SPARE_PART_NUMBER => Some(meta.spare_part_number.to_vec()),
            DID_ECU_SW_NUMBER => Some(meta.ecu_sw_number.to_vec()),
            DID_FW_VERSION => Some(meta.fw_version.to_vec()),
            DID_SUPPLIER_SW_NUMBER => Some(meta.supplier_sw_number.to_vec()),
            DID_SUPPLIER_SW_VERSION => Some(meta.supplier_sw_version.to_vec()),
            DID_SYSTEM_NAME => Some(meta.system_name.to_vec()),
            DID_TESTER_SERIAL => Some(meta.tester_serial.to_vec()),
            DID_PROGRAMMING_DATE => Some(meta.programming_date.to_vec()),
            DID_ODX_FILE_ID => Some(meta.odx_file_id.to_vec()),
            _ => None,
        };
        if let Some(v) = val {
            return DidValue::Bytes(v);
        }
    }

    // 3. Check Factory DIDs (hardware identity, shared)
    if let Some(factory) = nv.read_factory() {
        let val = match did {
            DID_SUPPLIER_ID => Some(factory.supplier_id.to_vec()),
            DID_MANUFACTURING_DATE => Some(factory.manufacturing_date.to_vec()),
            DID_SERIAL_NUMBER => Some(factory.serial_number.to_vec()),
            DID_VIN => Some(factory.vin.to_vec()),
            DID_ECU_HW_NUMBER => Some(factory.ecu_hw_number.to_vec()),
            DID_SUPPLIER_HW_NUMBER => Some(factory.supplier_hw_number.to_vec()),
            DID_SUPPLIER_HW_VERSION => Some(factory.supplier_hw_version.to_vec()),
            _ => None,
        };
        if let Some(v) = val {
            return DidValue::Bytes(v);
        }
    }

    // 4. Dynamic DIDs (computed)
    let bs = &state.banks[set.as_index()];
    match did {
        DID_ACTIVE_BANK => {
            // Report the bank we're actually running on, not the staged next-boot bank
            DidValue::Bytes(vec![if active == Bank::A { b'A' } else { b'B' }])
        }
        DID_COMMITTED => DidValue::Bytes(vec![bs.committed as u8]),
        DID_BOOT_COUNT => DidValue::Bytes(vec![bs.boot_count]),
        DID_MIN_SECURITY_VER | DID_CURRENT_SECURITY_VER => {
            if let Some(meta) = nv.read_fw_meta(set, active) {
                let val = if did == DID_MIN_SECURITY_VER {
                    meta.min_security_ver
                } else {
                    meta.fw_secver
                };
                DidValue::Bytes(val.to_le_bytes().to_vec())
            } else {
                DidValue::Bytes(0u32.to_le_bytes().to_vec())
            }
        }
        _ => DidValue::NotFound,
    }
}

/// Write a runtime DID for a given bank set's active bank.
/// Returns true if written, false if runtime is full.
pub fn write_did<D: BlockDevice>(
    nv: &mut NvStore<D>,
    set: BankSet,
    did: u16,
    data: &[u8],
) -> Result<bool, nv_store::block::BlockError> {
    let state = match nv.read_boot_state() {
        Some(s) => s,
        None => return Ok(false),
    };
    let active = state.banks[set.as_index()].active_bank;

    let mut runtime = nv.read_runtime(set, active).unwrap_or_default();

    // Check if DID already exists — update it
    for i in 0..runtime.did_count as usize {
        if runtime.dids[i].did == did {
            let len = data.len().min(32);
            runtime.dids[i].data = [0u8; 32];
            runtime.dids[i].data[..len].copy_from_slice(&data[..len]);
            runtime.dids[i].len = len as u8;
            nv.write_runtime(set, active, &mut runtime)?;
            return Ok(true);
        }
    }

    // New DID — append if space
    if (runtime.did_count as usize) >= MAX_DIDS {
        return Ok(false);
    }

    let idx = runtime.did_count as usize;
    let len = data.len().min(32);
    runtime.dids[idx].did = did;
    runtime.dids[idx].data = [0u8; 32];
    runtime.dids[idx].data[..len].copy_from_slice(&data[..len]);
    runtime.dids[idx].len = len as u8;
    runtime.did_count += 1;
    nv.write_runtime(set, active, &mut runtime)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nv_store::block::MemBlockDevice;
    use nv_store::store::MIN_NV_DEVICE_SIZE;

    fn make_nv() -> NvStore<MemBlockDevice> {
        NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize))
    }

    fn init_boot_state(nv: &mut NvStore<MemBlockDevice>) {
        let mut state = NvBootState::default();
        // Bank A active, committed — applies to all sets by default.
        for b in &mut state.banks {
            b.active_bank = Bank::A;
            b.committed = true;
        }
        nv.write_boot_state(&mut state).unwrap();
    }

    #[test]
    fn didvalue_as_str_trims_nul_padding() {
        let mut bytes = vec![0u8; 16];
        bytes[..3].copy_from_slice(b"VIN");
        let v = DidValue::Bytes(bytes);
        assert_eq!(v.as_str(), Some("VIN"));
    }

    #[test]
    fn didvalue_as_str_no_nul_uses_full_slice() {
        let v = DidValue::Bytes(b"ABC".to_vec());
        assert_eq!(v.as_str(), Some("ABC"));
    }

    #[test]
    fn didvalue_as_str_rejects_invalid_utf8() {
        let v = DidValue::Bytes(vec![0xFF, 0xFE]);
        assert!(v.as_str().is_none());
    }

    #[test]
    fn didvalue_as_str_notfound_returns_none() {
        assert!(DidValue::NotFound.as_str().is_none());
    }

    #[test]
    fn read_did_with_uninitialized_nv_returns_notfound() {
        // No boot state written yet — every read should short-circuit.
        let nv = make_nv();
        assert_eq!(
            read_did(&nv, BankSet::Vm1, DID_VIN, None),
            DidValue::NotFound
        );
    }

    #[test]
    fn read_did_fw_meta_returns_spare_part_number() {
        let mut nv = make_nv();
        init_boot_state(&mut nv);

        let mut meta = NvFwMeta::default();
        meta.spare_part_number[..5].copy_from_slice(b"SP-42");
        nv.write_fw_meta(BankSet::Vm1, Bank::A, &mut meta).unwrap();

        match read_did(&nv, BankSet::Vm1, DID_SPARE_PART_NUMBER, None) {
            DidValue::Bytes(b) => assert_eq!(&b[..5], b"SP-42"),
            DidValue::NotFound => panic!("expected bytes"),
        }
    }

    #[test]
    fn read_did_factory_returns_vin() {
        let mut nv = make_nv();
        init_boot_state(&mut nv);

        let mut f = NvFactory::default();
        f.vin[..17].copy_from_slice(b"WBALI00000TEST001");
        nv.write_factory(&mut f).unwrap();

        match read_did(&nv, BankSet::Vm1, DID_VIN, None) {
            DidValue::Bytes(b) => assert_eq!(&b, b"WBALI00000TEST001"),
            DidValue::NotFound => panic!("expected VIN bytes"),
        }
    }

    #[test]
    fn read_did_dynamic_active_bank() {
        let mut nv = make_nv();
        init_boot_state(&mut nv);

        match read_did(&nv, BankSet::Vm1, DID_ACTIVE_BANK, None) {
            DidValue::Bytes(b) => assert_eq!(b, b"A"),
            DidValue::NotFound => panic!("expected active bank letter"),
        }
        match read_did(&nv, BankSet::Vm1, DID_ACTIVE_BANK, Some(Bank::B)) {
            DidValue::Bytes(b) => assert_eq!(b, b"B"),
            DidValue::NotFound => panic!("expected B"),
        }
    }

    #[test]
    fn read_did_dynamic_committed_reflects_flag() {
        let mut nv = make_nv();
        let mut state = NvBootState::default();
        let idx = BankSet::Vm1.as_index();
        state.banks[idx].active_bank = Bank::A;
        state.banks[idx].committed = false;
        state.banks[idx].boot_count = 3;
        nv.write_boot_state(&mut state).unwrap();

        let committed = read_did(&nv, BankSet::Vm1, DID_COMMITTED, None);
        assert_eq!(committed, DidValue::Bytes(vec![0]));

        let boot_count = read_did(&nv, BankSet::Vm1, DID_BOOT_COUNT, None);
        assert_eq!(boot_count, DidValue::Bytes(vec![3]));
    }

    #[test]
    fn read_did_dynamic_security_ver_without_fw_meta_is_zero() {
        let mut nv = make_nv();
        init_boot_state(&mut nv);
        let v = read_did(&nv, BankSet::Vm1, DID_CURRENT_SECURITY_VER, None);
        assert_eq!(v, DidValue::Bytes(0u32.to_le_bytes().to_vec()));
    }

    #[test]
    fn read_did_dynamic_security_ver_uses_fw_meta() {
        let mut nv = make_nv();
        init_boot_state(&mut nv);
        let mut meta = NvFwMeta::default();
        meta.fw_secver = 0x1234_5678;
        meta.min_security_ver = 0x0000_00AB;
        nv.write_fw_meta(BankSet::Vm1, Bank::A, &mut meta).unwrap();

        let cur = read_did(&nv, BankSet::Vm1, DID_CURRENT_SECURITY_VER, None);
        assert_eq!(cur, DidValue::Bytes(0x1234_5678u32.to_le_bytes().to_vec()));

        let min = read_did(&nv, BankSet::Vm1, DID_MIN_SECURITY_VER, None);
        assert_eq!(min, DidValue::Bytes(0x0000_00ABu32.to_le_bytes().to_vec()));
    }

    #[test]
    fn read_did_unknown_did_returns_notfound() {
        let mut nv = make_nv();
        init_boot_state(&mut nv);
        let v = read_did(&nv, BankSet::Vm1, 0x1234, None);
        assert_eq!(v, DidValue::NotFound);
    }

    #[test]
    fn write_did_then_read_did_roundtrip_via_runtime() {
        let mut nv = make_nv();
        init_boot_state(&mut nv);

        let ok = write_did(&mut nv, BankSet::Vm1, DID_SYSTEM_NAME, b"vm1-linux").unwrap();
        assert!(ok);

        match read_did(&nv, BankSet::Vm1, DID_SYSTEM_NAME, None) {
            DidValue::Bytes(b) => assert_eq!(&b, b"vm1-linux"),
            DidValue::NotFound => panic!("runtime did not mask fw_meta read"),
        }
    }

    #[test]
    fn write_did_updates_existing_did_in_place() {
        let mut nv = make_nv();
        init_boot_state(&mut nv);

        write_did(&mut nv, BankSet::Vm1, 0xFD10, b"old").unwrap();
        write_did(&mut nv, BankSet::Vm1, 0xFD10, b"newer-value").unwrap();

        let v = read_did(&nv, BankSet::Vm1, 0xFD10, None);
        assert_eq!(v, DidValue::Bytes(b"newer-value".to_vec()));

        // Should still be a single DID (update in place, not append).
        let rt = nv.read_runtime(BankSet::Vm1, Bank::A).unwrap();
        let count = (0..rt.did_count as usize)
            .filter(|i| rt.dids[*i].did == 0xFD10)
            .count();
        assert_eq!(count, 1, "duplicate DID entry after update");
    }

    #[test]
    fn write_did_truncates_payload_to_32_bytes() {
        let mut nv = make_nv();
        init_boot_state(&mut nv);
        let payload = vec![0xAAu8; 50];
        write_did(&mut nv, BankSet::Vm1, 0xFD11, &payload).unwrap();
        match read_did(&nv, BankSet::Vm1, 0xFD11, None) {
            DidValue::Bytes(b) => assert_eq!(b.len(), 32),
            DidValue::NotFound => panic!("expected truncated bytes"),
        }
    }

    #[test]
    fn write_did_without_boot_state_returns_false() {
        let mut nv = make_nv();
        let ok = write_did(&mut nv, BankSet::Vm1, 0xFD12, b"x").unwrap();
        assert!(!ok);
    }
}
