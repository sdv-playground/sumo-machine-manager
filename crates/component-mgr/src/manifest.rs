/// YAML manifests for factory provisioning and initial FW metadata.
///
/// OTA manifests use SUIT envelopes via [`SuitProvider`](crate::suit_provider).
/// These YAML types are only used for factory-init (offline provisioning).
use crate::ota::ImageMeta;
use nv_store::types::BankSet;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Firmware manifest (YAML)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareManifest {
    pub component_id: Vec<String>,
    #[serde(default)]
    pub vendor_id: Option<String>,
    #[serde(default)]
    pub class_id: Option<String>,

    pub sequence_number: u32,
    pub version: String,

    #[serde(default)]
    pub image_size: Option<u64>,
    #[serde(default)]
    pub image_sha256: Option<String>,

    // UDS DID identity fields
    #[serde(default)]
    pub spare_part_number: Option<String>,
    #[serde(default)]
    pub ecu_sw_number: Option<String>,
    #[serde(default)]
    pub supplier_sw_number: Option<String>,
    #[serde(default)]
    pub supplier_sw_version: Option<String>,
    #[serde(default)]
    pub system_name: Option<String>,
    #[serde(default)]
    pub odx_file_id: Option<String>,
    #[serde(default)]
    pub programming_date: Option<String>,
    #[serde(default)]
    pub tester_serial: Option<String>,
}

impl FirmwareManifest {
    pub fn from_yaml(yaml: &str) -> Result<Self, String> {
        serde_yaml::from_str(yaml).map_err(|e| format!("manifest parse error: {e}"))
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::from_yaml(&content)
    }

    /// Resolve the BankSet from component_id.
    /// Accepts ["vm1"], ["hypervisor"], or ["vendor", "vm1"], etc.
    pub fn resolve_bank_set(&self) -> Option<BankSet> {
        let tag = self.component_id.last()?;
        BankSet::from_str(tag)
    }

    /// Convert to the existing ImageMeta type used by ota::install().
    pub fn to_image_meta(&self) -> ImageMeta {
        let mut meta = ImageMeta::default();
        copy_str_to_array(&self.version, &mut meta.fw_version);
        meta.fw_seq = self.sequence_number;
        meta.fw_secver = self.sequence_number;
        if let Some(ref s) = self.spare_part_number {
            copy_str_to_array(s, &mut meta.spare_part_number);
        }
        if let Some(ref s) = self.ecu_sw_number {
            copy_str_to_array(s, &mut meta.ecu_sw_number);
        }
        if let Some(ref s) = self.supplier_sw_number {
            copy_str_to_array(s, &mut meta.supplier_sw_number);
        }
        if let Some(ref s) = self.supplier_sw_version {
            copy_str_to_array(s, &mut meta.supplier_sw_version);
        }
        if let Some(ref s) = self.system_name {
            copy_str_to_array(s, &mut meta.system_name);
        }
        if let Some(ref s) = self.odx_file_id {
            copy_str_to_array(s, &mut meta.odx_file_id);
        }
        if let Some(ref s) = self.programming_date {
            let n = s.len().min(8);
            meta.programming_date[..n].copy_from_slice(&s.as_bytes()[..n]);
        }
        if let Some(ref s) = self.tester_serial {
            copy_str_to_array(s, &mut meta.tester_serial);
        }
        meta
    }
}

fn copy_str_to_array(s: &str, dst: &mut [u8]) {
    let n = s.len().min(dst.len());
    dst[..n].copy_from_slice(&s.as_bytes()[..n]);
}

// ---------------------------------------------------------------------------
// Factory manifest (YAML)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactoryManifest {
    pub serial_number: String,
    pub vin: String,
    #[serde(default)]
    pub manufacturing_date: Option<String>,
    #[serde(default)]
    pub ecu_hw_number: Option<String>,
    #[serde(default)]
    pub supplier_hw_number: Option<String>,
    #[serde(default)]
    pub supplier_hw_version: Option<String>,
    #[serde(default)]
    pub supplier_id: Option<String>,
    #[serde(default)]
    pub device_type: Option<u8>,
}

impl FactoryManifest {
    pub fn from_yaml(yaml: &str) -> Result<Self, String> {
        serde_yaml::from_str(yaml).map_err(|e| format!("factory manifest parse error: {e}"))
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::from_yaml(&content)
    }

    pub fn to_nv_factory(&self) -> nv_store::types::NvFactory {
        let mut f = nv_store::types::NvFactory::default();
        copy_str_to_array(&self.serial_number, &mut f.serial_number);
        let vlen = self.vin.len().min(17);
        f.vin[..vlen].copy_from_slice(&self.vin.as_bytes()[..vlen]);
        if let Some(ref s) = self.manufacturing_date {
            let n = s.len().min(8);
            f.manufacturing_date[..n].copy_from_slice(&s.as_bytes()[..n]);
        }
        if let Some(ref s) = self.ecu_hw_number {
            copy_str_to_array(s, &mut f.ecu_hw_number);
        }
        if let Some(ref s) = self.supplier_hw_number {
            copy_str_to_array(s, &mut f.supplier_hw_number);
        }
        if let Some(ref s) = self.supplier_hw_version {
            copy_str_to_array(s, &mut f.supplier_hw_version);
        }
        if let Some(ref s) = self.supplier_id {
            copy_str_to_array(s, &mut f.supplier_id);
        }
        if let Some(dt) = self.device_type {
            f.device_type = dt;
        }
        f
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_parse_full() {
        let yaml = r#"
component_id: ["vm1"]
vendor_id: "fa6b4a53-d5ad-5fdf-be9d-e4e97d85cd2b"
class_id: "1492af14-2569-5e48-bf42-9b2d51f2ab45"
sequence_number: 3
version: "1.2.0"
image_size: 67108864
spare_part_number: "SP-VM1"
ecu_sw_number: "ECU-SW-001"
system_name: "VM1-Linux"
"#;
        let m = FirmwareManifest::from_yaml(yaml).unwrap();
        assert_eq!(m.component_id, vec!["vm1"]);
        assert_eq!(m.sequence_number, 3);
        assert_eq!(m.version, "1.2.0");
        assert_eq!(m.resolve_bank_set(), Some(BankSet::Vm1));
    }

    #[test]
    fn manifest_parse_minimal() {
        let yaml = r#"
component_id: ["host-os"]
sequence_number: 1
version: "1.0.0"
"#;
        let m = FirmwareManifest::from_yaml(yaml).unwrap();
        assert_eq!(m.resolve_bank_set(), Some(BankSet::Os));
        assert!(m.spare_part_number.is_none());
    }

    #[test]
    fn manifest_to_image_meta() {
        let yaml = r#"
component_id: ["vm1"]
sequence_number: 5
version: "2.0.0"
spare_part_number: "SP-001"
ecu_sw_number: "ECU-001"
"#;
        let m = FirmwareManifest::from_yaml(yaml).unwrap();
        let meta = m.to_image_meta();
        assert_eq!(meta.fw_seq, 5);
        assert_eq!(meta.fw_secver, 5);
        assert_eq!(&meta.fw_version[..5], b"2.0.0");
        assert_eq!(&meta.spare_part_number[..6], b"SP-001");
        assert_eq!(&meta.ecu_sw_number[..7], b"ECU-001");
    }

    #[test]
    fn factory_manifest_parse() {
        let yaml = r#"
serial_number: "SN-001"
vin: "WBALI00000TEST001"
manufacturing_date: "20260323"
ecu_hw_number: "HW-001"
device_type: 1
"#;
        let f = FactoryManifest::from_yaml(yaml).unwrap();
        assert_eq!(f.serial_number, "SN-001");
        assert_eq!(f.device_type, Some(1));
        let nv = f.to_nv_factory();
        assert_eq!(&nv.serial_number[..6], b"SN-001");
        assert_eq!(&nv.vin[..17], b"WBALI00000TEST001");
    }
}
