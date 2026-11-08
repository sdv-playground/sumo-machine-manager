use super::*;

// ---------------------------------------------------------------------------
// DID helpers (adapted from old models.rs)
// ---------------------------------------------------------------------------

pub(crate) struct DidEntry {
    pub(crate) id: &'static str,
    pub(crate) did: u16,
    pub(crate) name: &'static str,
    pub(crate) data_type: &'static str,
    pub(crate) writable: bool,
}

pub(crate) static DID_REGISTRY: &[DidEntry] = &[
    DidEntry {
        id: "spare_part_number",
        did: did::DID_SPARE_PART_NUMBER,
        name: "Spare Part Number",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "ecu_sw_number",
        did: did::DID_ECU_SW_NUMBER,
        name: "ECU Software Number",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "fw_version",
        did: did::DID_FW_VERSION,
        name: "Firmware Version",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "supplier_id",
        did: did::DID_SUPPLIER_ID,
        name: "Supplier ID",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "manufacturing_date",
        did: did::DID_MANUFACTURING_DATE,
        name: "Manufacturing Date",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "serial_number",
        did: did::DID_SERIAL_NUMBER,
        name: "Serial Number",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "vin",
        did: did::DID_VIN,
        name: "VIN",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "ecu_hw_number",
        did: did::DID_ECU_HW_NUMBER,
        name: "ECU Hardware Number",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "supplier_hw_number",
        did: did::DID_SUPPLIER_HW_NUMBER,
        name: "Supplier HW Number",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "supplier_hw_version",
        did: did::DID_SUPPLIER_HW_VERSION,
        name: "Supplier HW Version",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "supplier_sw_number",
        did: did::DID_SUPPLIER_SW_NUMBER,
        name: "Supplier SW Number",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "supplier_sw_version",
        did: did::DID_SUPPLIER_SW_VERSION,
        name: "Supplier SW Version",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "system_name",
        did: did::DID_SYSTEM_NAME,
        name: "System Name",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "tester_serial",
        did: did::DID_TESTER_SERIAL,
        name: "Tester Serial",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "programming_date",
        did: did::DID_PROGRAMMING_DATE,
        name: "Programming Date",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "odx_file_id",
        did: did::DID_ODX_FILE_ID,
        name: "ODX File ID",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "active_bank",
        did: did::DID_ACTIVE_BANK,
        name: "Active Bank",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "committed",
        did: did::DID_COMMITTED,
        name: "Committed",
        data_type: "bool",
        writable: false,
    },
    DidEntry {
        id: "min_security_ver",
        did: did::DID_MIN_SECURITY_VER,
        name: "Min Security Version",
        data_type: "uint32",
        writable: false,
    },
    DidEntry {
        id: "current_security_ver",
        did: did::DID_CURRENT_SECURITY_VER,
        name: "Current Security Version",
        data_type: "uint32",
        writable: false,
    },
    DidEntry {
        id: "guest_state",
        did: did::DID_GUEST_STATE,
        name: "Guest State",
        data_type: "string",
        writable: false,
    },
    DidEntry {
        id: "heartbeat_seq",
        did: did::DID_HEARTBEAT_SEQ,
        name: "Heartbeat Seq",
        data_type: "uint32",
        writable: false,
    },
];

pub(crate) fn resolve_param(param_id: &str) -> Option<(u16, Option<&'static DidEntry>)> {
    if let Some(entry) = DID_REGISTRY.iter().find(|d| d.id == param_id) {
        return Some((entry.did, Some(entry)));
    }
    let hex_str = param_id
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .trim_start_matches("runtime_");
    if let Ok(did) = u16::from_str_radix(hex_str, 16) {
        let reg = DID_REGISTRY.iter().find(|d| d.did == did);
        return Some((did, reg));
    }
    None
}

pub(crate) fn did_value_to_json(
    _did_num: u16,
    value: &[u8],
    reg: Option<&DidEntry>,
) -> serde_json::Value {
    let data_type = reg.map(|r| r.data_type).unwrap_or("bytes");
    match data_type {
        "bool" => serde_json::Value::Bool(value.first().copied().unwrap_or(0) != 0),
        "uint8" => serde_json::json!(value.first().copied().unwrap_or(0)),
        "uint32" => {
            let v = if value.len() >= 4 {
                u32::from_le_bytes([value[0], value[1], value[2], value[3]])
            } else {
                0
            };
            serde_json::json!(v)
        }
        "string" => {
            let s = ComponentBackend::<nv_store::block::MemBlockDevice>::nv_bytes_to_string(value);
            serde_json::Value::String(s)
        }
        _ => {
            let end = value.iter().position(|&c| c == 0).unwrap_or(value.len());
            if let Ok(s) = std::str::from_utf8(&value[..end]) {
                if !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                    return serde_json::Value::String(s.to_string());
                }
            }
            let hex: String = value.iter().map(|b| format!("{b:02x}")).collect();
            serde_json::Value::String(format!("0x{hex}"))
        }
    }
}

/// The SW-identity DIDs (subset of the F187–F19E range) sourced ONLY from the
/// running bank's signed IVD manifest — never from NV. These are exactly the
/// DIDs `identity_to_did_bytes` overlays into `did_cache`, so they read back
/// (and may be listed) only when `verified_bank_manifest` finds a committed
/// manifest. The other F18x/F19x DIDs in `DID_REGISTRY` (supplier_id F18A,
/// manufacturing_date F18B, serial_number F18C, vin F190, ecu_hw_number F191,
/// supplier_hw_number F192, supplier_hw_version F193) are HARDWARE identity
/// read from the NV Factory blob regardless of any manifest — they are NOT
/// here and stay listed unconditionally.
pub(crate) const IDENTITY_DIDS: [u16; 9] = [
    did::DID_SPARE_PART_NUMBER,
    did::DID_ECU_SW_NUMBER,
    did::DID_FW_VERSION,
    did::DID_SUPPLIER_SW_NUMBER,
    did::DID_SUPPLIER_SW_VERSION,
    did::DID_SYSTEM_NAME,
    did::DID_TESTER_SERIAL,
    did::DID_PROGRAMMING_DATE,
    did::DID_ODX_FILE_ID,
];

/// Whether `did` is a manifest-sourced SW-identity DID (see [`IDENTITY_DIDS`]).
pub(crate) fn is_identity_did(did: u16) -> bool {
    IDENTITY_DIDS.contains(&did)
}

/// Convert a [`FirmwareIdentity`] into the `(did, bytes)` pairs for the 9
/// SW-identity DIDs, each rendered in the historical fixed-width UDS byte
/// form (UTF-8, NUL-padded / truncated to the width that DID used when it
/// lived in NvFwMeta — 32 bytes, except programming_date's 8). Absent
/// (`None` / empty) identity fields are skipped (DID stays not-found), so a
/// blank manifest identity behaves like an unprovisioned field.
pub(super) fn identity_to_did_bytes(identity: &FirmwareIdentity) -> Vec<(u16, Vec<u8>)> {
    /// Pad/truncate a UTF-8 string to `width` bytes, NUL-padded — the
    /// same fixed-width form `read_did` used to return from NvFwMeta.
    fn fixed(s: &str, width: usize) -> Vec<u8> {
        let mut buf = vec![0u8; width];
        let n = s.len().min(width);
        buf[..n].copy_from_slice(&s.as_bytes()[..n]);
        buf
    }

    // (did, value, field-width). `version` → F189, `system_name` → F197.
    let fields: [(u16, &Option<String>, usize); 9] = [
        (did::DID_FW_VERSION, &identity.version, 32),
        (did::DID_ECU_SW_NUMBER, &identity.ecu_sw_number, 32),
        (
            did::DID_SUPPLIER_SW_NUMBER,
            &identity.supplier_sw_number,
            32,
        ),
        (
            did::DID_SUPPLIER_SW_VERSION,
            &identity.supplier_sw_version,
            32,
        ),
        (did::DID_SPARE_PART_NUMBER, &identity.spare_part_number, 32),
        (did::DID_ODX_FILE_ID, &identity.odx_file_id, 32),
        (did::DID_SYSTEM_NAME, &identity.system_name, 32),
        (did::DID_PROGRAMMING_DATE, &identity.programming_date, 8),
        (did::DID_TESTER_SERIAL, &identity.tester_serial, 32),
    ];
    fields
        .iter()
        .filter_map(|(did, s, width)| {
            s.as_deref()
                .filter(|v| !v.is_empty())
                .map(|v| (*did, fixed(v, *width)))
        })
        .collect()
}

/// Render the installed firmware as the `x-ota-installed-manifest` JSON
/// body: the signed identity + per-file `(path, sha256-hex)` inventory + the
/// base64 of the raw signature and manifest bytes (so a SW-mapping tool can
/// re-verify the device signature independently).
///
/// IVD-specific scalar fields (`ivd_version`, `signed_at_unix`) aren't part
/// of the kind-agnostic [`InstalledFirmware`], so they're decoded back out of
/// the raw signed CBOR here — this is component-mgr's IVD serving path, which is
/// allowed to know the IVD wire (`fw.raw` is exactly those CBOR bytes).
pub(super) fn installed_manifest_json(fw: &InstalledFirmware) -> serde_json::Value {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;

    // Render an identity field exactly as before — the IVD manifest stored
    // readable strings (empty for absent), so map `None` back to "".
    fn s(o: &Option<String>) -> &str {
        o.as_deref().unwrap_or("")
    }

    let files: Vec<serde_json::Value> = fw
        .files
        .iter()
        .map(|f| {
            serde_json::json!({
                "path": f.name,
                "sha256": hex::encode(f.sha256),
            })
        })
        .collect();

    // Recover the two IVD-only scalars from the signed CBOR. Absent / undecodable
    // raw (non-IVD kinds) falls back to the manifest version + 0.
    let (ivd_version, signed_at_unix) = fw
        .raw
        .as_deref()
        .and_then(|b| hsm::ivd::decode_manifest(b).ok())
        .map(|m| (m.ivd_version, m.signed_at_unix))
        .unwrap_or((hsm::ivd::IVD_MANIFEST_VERSION, 0));

    serde_json::json!({
        "ivd_version": ivd_version,
        "gen": fw.gen,
        "signed_at_unix": signed_at_unix,
        "identity": {
            "name": s(&fw.identity.name),
            "version": s(&fw.identity.version),
            "ecu_sw_number": s(&fw.identity.ecu_sw_number),
            "supplier_sw_number": s(&fw.identity.supplier_sw_number),
            "supplier_sw_version": s(&fw.identity.supplier_sw_version),
            "spare_part_number": s(&fw.identity.spare_part_number),
            "odx_file_id": s(&fw.identity.odx_file_id),
            "system_name": s(&fw.identity.system_name),
            "programming_date": s(&fw.identity.programming_date),
            "tester_serial": s(&fw.identity.tester_serial),
        },
        "files": files,
        "signature_b64": b64.encode(fw.signature.as_deref().unwrap_or(&[])),
        "manifest_b64": b64.encode(fw.raw.as_deref().unwrap_or(&[])),
    })
}

// `bank_dir_is_payload_empty` + `bank_dir_name` moved to
// `crate::bank_provider` alongside the IVD bank-layout logic that uses
// them — the engine no longer touches bank dirs directly, it routes
// every write through `BankProvider::open_payload_writer`.
// `bank_set_dir_name` / `bank_file_names` retired earlier — the on-disk
// dir name lives on `BankSetSpec` in `crate::bank_spec` now and is read
// off `self.bank_spec.dir_name`. Bank filenames are the SUIT component-id
// part taken verbatim (`bank_spec::payload_target_name_for_id`), no remap.

pub(super) fn map_ota_error(e: ota::OtaError) -> BackendError {
    match e {
        ota::OtaError::InTrial => BackendError::Busy("bank set is in trial mode".into()),
        ota::OtaError::AlreadyCommitted => BackendError::Busy("already committed".into()),
        ota::OtaError::NotInTrial => BackendError::Busy("not in trial mode".into()),
        ota::OtaError::SecurityVersionTooLow { image, floor } => BackendError::InvalidRequest(
            format!("security version {image} below anti-rollback floor {floor}"),
        ),
        other => BackendError::Internal(format!("{other}")),
    }
}
