//! Identification data read from KEY=VALUE version records (`ident_data:`).
//!
//! Images a node flashes outside OTA (a platform image, a bootloader) are not
//! components, so component-mgr has no record of them. Such an image can leave
//! a KEY=VALUE version record on target; this module serves configured items
//! of such a record as read-only SOVD `identData` on an entity of its own. The
//! entity ids, record paths and items are the node's configuration.
//!
//! The model is another node SOVD server's `ident_data`
//! (`IdentFileDataProvider`):
//! - configured `{entity, file, items: [{id, name, key}]}`;
//! - every item is `identData`, its value the file's string;
//! - the file is read on every request, so the values are the booted image's;
//! - an item whose key the file lacks (or has empty) is not listed, and reading
//!   it is 404;
//! - `sw-version` = `{"version", "items": [{"name", "version"}]}`.
//!
//! The entity answers only `/data`. Everything else is the
//! `DiagnosticBackend` default (`NotSupported`), and it is never part of the
//! `MachineRegistry`, so it cannot reach OTA, the coordinator or the boot
//! selector.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::Deserialize;
use sovd_core::{
    BackendError, BackendResult, Capabilities, DataCategory, DataValue, DiagnosticBackend,
    EntityInfo, FaultFilter, FaultsResult, OperationExecution, OperationInfo, ParameterInfo,
};

/// Version records are a few hundred bytes; anything past this is not one.
const MAX_RECORD_BYTES: u64 = 4096;

/// The data id of the composite version item (as on the DDU).
pub const SW_VERSION_ID: &str = "sw-version";

/// One `ident_data:` entry: an entity served from one version record.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct IdentDataSpec {
    /// The SOVD entity id (`/vehicle/v1/components/{entity}`).
    pub entity: String,
    /// Human-readable entity name; defaults to `entity`.
    #[serde(default)]
    pub name: Option<String>,
    /// The KEY=VALUE version record.
    pub file: PathBuf,
    /// `sw-version`; absent = not served.
    #[serde(default)]
    pub sw_version: Option<SwVersionSpec>,
    /// The single-value `identData` items.
    #[serde(default)]
    pub items: Vec<IdentItemSpec>,
}

/// One single-value `identData` item: data id ← file key.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct IdentItemSpec {
    pub id: String,
    pub name: String,
    pub key: String,
}

/// `sw-version`: `version` from `key`, `items` from every key starting with
/// `items_prefix` (prefix stripped), except the keys in `items_exclude`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct SwVersionSpec {
    pub key: String,
    #[serde(default)]
    pub items_prefix: Option<String>,
    #[serde(default)]
    pub items_exclude: Vec<String>,
}

impl IdentDataSpec {
    /// Config errors that make the entry unusable: empty ids, a duplicate data
    /// id (`sw-version` included) or an empty key.
    pub fn validate(&self) -> Result<(), String> {
        if self.entity.trim().is_empty() {
            return Err("ident_data: empty entity".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        if self.sw_version.is_some() {
            seen.insert(SW_VERSION_ID.to_string());
        }
        for item in &self.items {
            if item.id.trim().is_empty() || item.key.trim().is_empty() {
                return Err(format!(
                    "ident_data `{}`: item with an empty id or key",
                    self.entity
                ));
            }
            if !seen.insert(item.id.clone()) {
                return Err(format!(
                    "ident_data `{}`: duplicate data id `{}`",
                    self.entity, item.id
                ));
            }
        }
        if let Some(sw) = &self.sw_version {
            if sw.key.trim().is_empty() {
                return Err(format!(
                    "ident_data `{}`: sw_version with an empty key",
                    self.entity
                ));
            }
        }
        Ok(())
    }
}

/// Parse a KEY=VALUE record: split each line on the first `=`, strip a
/// trailing `\r`, skip blank / `#` lines and lines without `=`, keep only
/// non-empty values, a later duplicate key wins.
pub fn parse_record(text: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            if !key.is_empty() && !value.is_empty() {
                values.insert(key.to_string(), value.to_string());
            }
        }
    }
    values
}

/// Read and parse a record, at most [`MAX_RECORD_BYTES`]; a missing or
/// unreadable file is an empty record (every item unlisted), never an error.
pub fn read_record(path: &Path) -> BTreeMap<String, String> {
    let mut buf = Vec::new();
    match std::fs::File::open(path) {
        Ok(f) => {
            if let Err(e) = f.take(MAX_RECORD_BYTES).read_to_end(&mut buf) {
                tracing::debug!(file = %path.display(), error = %e, "ident_data: read failed");
                return BTreeMap::new();
            }
        }
        Err(e) => {
            tracing::debug!(file = %path.display(), error = %e, "ident_data: no record");
            return BTreeMap::new();
        }
    }
    parse_record(&String::from_utf8_lossy(&buf))
}

/// A read-only SOVD entity serving one version record's `identData`.
pub struct IdentDataBackend {
    spec: IdentDataSpec,
    info: EntityInfo,
    caps: Capabilities,
}

impl IdentDataBackend {
    pub fn new(spec: IdentDataSpec) -> Self {
        let info = EntityInfo {
            id: spec.entity.clone(),
            name: spec.name.clone().unwrap_or_else(|| spec.entity.clone()),
            entity_type: "ecu-software".into(),
            description: Some(format!("identification read from {}", spec.file.display())),
            href: format!("/vehicle/v1/components/{}", spec.entity),
            status: None,
        };
        let caps = Capabilities {
            read_data: true,
            ..Default::default()
        };
        Self { spec, info, caps }
    }

    fn param(&self, id: &str, name: &str, data_type: &str) -> ParameterInfo {
        ParameterInfo {
            id: id.to_string(),
            name: name.to_string(),
            description: None,
            unit: None,
            data_type: Some(data_type.to_string()),
            read_only: true,
            href: format!("{}/data/{}", self.info.href, id),
            did: None,
            category: Some(DataCategory::IdentData),
        }
    }

    fn sw_version_value(
        sw: &SwVersionSpec,
        record: &BTreeMap<String, String>,
    ) -> Option<serde_json::Value> {
        let version = record.get(&sw.key)?;
        let items: Vec<serde_json::Value> = match &sw.items_prefix {
            Some(prefix) => record
                .iter()
                .filter(|(k, _)| !sw.items_exclude.contains(k))
                .filter_map(|(k, v)| {
                    k.strip_prefix(prefix.as_str())
                        .filter(|name| !name.is_empty())
                        .map(|name| serde_json::json!({ "name": name, "version": v }))
                })
                .collect(),
            None => Vec::new(),
        };
        Some(serde_json::json!({ "version": version, "items": items }))
    }

    /// The value of one data id against a freshly read record.
    fn value_of(
        &self,
        id: &str,
        record: &BTreeMap<String, String>,
    ) -> Option<(String, serde_json::Value)> {
        if id == SW_VERSION_ID {
            let sw = self.spec.sw_version.as_ref()?;
            return Self::sw_version_value(sw, record).map(|v| ("SW version".to_string(), v));
        }
        let item = self.spec.items.iter().find(|i| i.id == id)?;
        record
            .get(&item.key)
            .map(|v| (item.name.clone(), serde_json::Value::String(v.clone())))
    }
}

#[async_trait]
impl DiagnosticBackend for IdentDataBackend {
    fn entity_info(&self) -> &EntityInfo {
        &self.info
    }

    fn capabilities(&self) -> &Capabilities {
        &self.caps
    }

    /// An ident entity only serves its file; it has no restart of its own, so
    /// its status carries no `restart` link (ISO 17978-3 §7.19.2 Table 280 C2).
    fn supports_restart(&self) -> bool {
        false
    }

    async fn list_parameters(&self) -> BackendResult<Vec<ParameterInfo>> {
        let record = read_record(&self.spec.file);
        let mut params = Vec::new();
        if let Some(sw) = &self.spec.sw_version {
            if record.contains_key(&sw.key) {
                params.push(self.param(SW_VERSION_ID, "SW version", "object"));
            }
        }
        for item in &self.spec.items {
            if record.contains_key(&item.key) {
                params.push(self.param(&item.id, &item.name, "string"));
            }
        }
        Ok(params)
    }

    async fn read_data(&self, param_ids: &[String]) -> BackendResult<Vec<DataValue>> {
        let record = read_record(&self.spec.file);
        param_ids
            .iter()
            .map(|id| {
                self.value_of(id, &record)
                    .map(|(name, value)| DataValue::new(id.clone(), name, value))
                    .ok_or_else(|| BackendError::ParameterNotFound(id.clone()))
            })
            .collect()
    }

    async fn get_faults(&self, _filter: Option<&FaultFilter>) -> BackendResult<FaultsResult> {
        Err(BackendError::NotSupported("faults".into()))
    }

    async fn list_operations(&self) -> BackendResult<Vec<OperationInfo>> {
        Err(BackendError::NotSupported("operations".into()))
    }

    async fn start_operation(
        &self,
        _operation_id: &str,
        _params: &[u8],
    ) -> BackendResult<OperationExecution> {
        Err(BackendError::NotSupported("operations".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Arc;

    const PLATFORM: &str = "component=host-platform\n\
        image=nor_ifs\n\
        version=PLATFORM_1.10-0-g1a2b3c4\n\
        tag=PLATFORM_1.10\n\
        branch=release/platform\n\
        commit=b8626380060cc0ad1c83cf1d350459a7406bcc97\n\
        dirty=no\n\
        ci_job_url=\n\
        manifest_version=1.0\n\
        manifest_aux_firmware_tgz=1.7.0\n\
        manifest_hsm_firmware_rev1=0.2.64.0\n";

    const OLD_BOOT: &str = "component=host-boot\n\
        status=no version record in /dev/fs0p0 0x00000000..0x00800000 (boot older than the record)\n";

    fn write(dir: &tempfile::TempDir, name: &str, text: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::File::create(&path)
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
        path
    }

    fn platform_spec(file: PathBuf) -> IdentDataSpec {
        IdentDataSpec {
            entity: "platform".into(),
            name: Some("Host platform".into()),
            file,
            sw_version: Some(SwVersionSpec {
                key: "version".into(),
                items_prefix: Some("manifest_".into()),
                items_exclude: vec!["manifest_version".into()],
            }),
            items: vec![
                IdentItemSpec {
                    id: "platform-version".into(),
                    name: "Platform version".into(),
                    key: "version".into(),
                },
                IdentItemSpec {
                    id: "platform-ci-job-url".into(),
                    name: "Platform CI job".into(),
                    key: "ci_job_url".into(),
                },
                IdentItemSpec {
                    id: "m7-firmware-version".into(),
                    name: "M7 firmware version".into(),
                    key: "manifest_aux_firmware_tgz".into(),
                },
            ],
        }
    }

    #[test]
    fn parse_record_rules() {
        let r = parse_record("a=1\r\n\n# c=3\nnoeq\nb=x=y\nempty=\n=v\na=2\n");
        assert_eq!(r.get("a").map(String::as_str), Some("2"), "last wins");
        assert_eq!(
            r.get("b").map(String::as_str),
            Some("x=y"),
            "first `=` splits"
        );
        assert!(!r.contains_key("empty"), "empty value dropped");
        assert!(!r.contains_key("# c"), "comment skipped");
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn read_record_missing_and_oversize() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_record(&dir.path().join("nope")).is_empty());
        let mut big = "version=1\n".to_string();
        big.push_str(&"x".repeat(MAX_RECORD_BYTES as usize));
        big.push_str("\ntail=lost\n");
        let r = read_record(&write(&dir, "big", &big));
        assert_eq!(r.get("version").map(String::as_str), Some("1"));
        assert!(!r.contains_key("tail"), "read capped");
    }

    #[test]
    fn validate_rejects_duplicates() {
        let mut spec = platform_spec(PathBuf::from("/x"));
        assert!(spec.validate().is_ok());
        spec.items.push(IdentItemSpec {
            id: SW_VERSION_ID.into(),
            name: "clash".into(),
            key: "version".into(),
        });
        assert!(spec.validate().is_err());
    }

    #[tokio::test]
    async fn lists_present_items_as_ident_data() {
        let dir = tempfile::tempdir().unwrap();
        let b = IdentDataBackend::new(platform_spec(write(&dir, "v", PLATFORM)));
        let params = b.list_parameters().await.unwrap();
        let ids: Vec<&str> = params.iter().map(|p| p.id.as_str()).collect();
        // ci_job_url is empty in the file -> not listed.
        assert_eq!(
            ids,
            ["sw-version", "platform-version", "m7-firmware-version"]
        );
        assert!(params
            .iter()
            .all(|p| p.category == Some(DataCategory::IdentData) && p.read_only));
        assert_eq!(
            params[1].href,
            "/vehicle/v1/components/platform/data/platform-version"
        );
    }

    #[tokio::test]
    async fn reads_items_and_sw_version() {
        let dir = tempfile::tempdir().unwrap();
        let b = IdentDataBackend::new(platform_spec(write(&dir, "v", PLATFORM)));
        let v = b
            .read_data(&["platform-version".into(), "sw-version".into()])
            .await
            .unwrap();
        assert_eq!(v[0].value, "PLATFORM_1.10-0-g1a2b3c4");
        assert_eq!(
            v[1].value,
            serde_json::json!({
                "version": "PLATFORM_1.10-0-g1a2b3c4",
                "items": [
                    {"name": "aux_firmware_tgz", "version": "1.7.0"},
                    {"name": "hsm_firmware_rev1", "version": "0.2.64.0"},
                ]
            })
        );
        let err = b.read_data(&["platform-ci-job-url".into()]).await;
        assert!(matches!(err, Err(BackendError::ParameterNotFound(_))));
    }

    #[tokio::test]
    async fn reads_the_file_on_every_request() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "v", "version=1\n");
        let b = IdentDataBackend::new(platform_spec(path.clone()));
        let ids = vec!["platform-version".to_string()];
        assert_eq!(b.read_data(&ids).await.unwrap()[0].value, "1");
        write(&dir, "v", "version=2\n");
        assert_eq!(b.read_data(&ids).await.unwrap()[0].value, "2");
    }

    #[tokio::test]
    async fn old_boot_lists_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let spec = IdentDataSpec {
            entity: "boot".into(),
            name: None,
            file: write(&dir, "b", OLD_BOOT),
            sw_version: Some(SwVersionSpec {
                key: "version".into(),
                items_prefix: None,
                items_exclude: vec![],
            }),
            items: vec![IdentItemSpec {
                id: "boot-version".into(),
                name: "Boot version".into(),
                key: "version".into(),
            }],
        };
        let b = IdentDataBackend::new(spec);
        assert!(b.list_parameters().await.unwrap().is_empty());
        assert!(b.read_data(&["sw-version".into()]).await.is_err());
        assert_eq!(b.entity_info().name, "boot");
    }

    /// Through SOVDd's real router: listed in /components, `GET /data` with
    /// the identData filter, a read, a 404, and an empty `/updates`.
    #[tokio::test]
    async fn served_through_the_sovd_router() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let dir = tempfile::tempdir().unwrap();
        let backend: Arc<dyn DiagnosticBackend> = Arc::new(IdentDataBackend::new(platform_spec(
            write(&dir, "v", PLATFORM),
        )));
        let mut backends = std::collections::HashMap::new();
        backends.insert("platform".to_string(), backend);
        let router = sovd_api::create_router(sovd_api::AppState::new(backends));

        let get = |uri: &str| {
            let router = router.clone();
            let req = Request::get(uri).body(Body::empty()).unwrap();
            async move {
                let resp = router.oneshot(req).await.unwrap();
                let status = resp.status();
                let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
                    .await
                    .unwrap();
                let json = serde_json::from_slice::<serde_json::Value>(&bytes)
                    .unwrap_or(serde_json::Value::Null);
                (status, json)
            }
        };

        let (s, body) = get("/vehicle/v1/components").await;
        assert_eq!(s, StatusCode::OK);
        assert!(body.to_string().contains("\"platform\""), "{body}");

        let (s, body) = get("/vehicle/v1/components/platform/data?categories=identData").await;
        assert_eq!(s, StatusCode::OK);
        let text = body.to_string();
        assert!(
            text.contains("platform-version") && text.contains("identData"),
            "{text}"
        );

        let (s, body) = get("/vehicle/v1/components/platform/data/platform-version").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(body["value"], "PLATFORM_1.10-0-g1a2b3c4", "{body}");

        let (s, _) = get("/vehicle/v1/components/platform/data/platform-ci-job-url").await;
        assert_eq!(s, StatusCode::NOT_FOUND);

        // SOVDd answers the collection itself; an ident entity offers nothing.
        let (s, body) = get("/vehicle/v1/components/platform/updates").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(body, serde_json::json!({ "items": [] }));

        // No restart of its own: no `restart` link in its status.
        let (s, body) = get("/v1/components/platform/status").await;
        assert_eq!(s, StatusCode::OK);
        assert!(body.get("restart").is_none(), "{body}");
    }

    #[test]
    fn has_no_restart_of_its_own() {
        let b = IdentDataBackend::new(platform_spec(PathBuf::from("/x")));
        assert!(!b.supports_restart());
    }
}
