use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use futures::StreamExt;
use sha2::{Digest, Sha256};

use machine_mgr::component::Component;
use machine_mgr::error::{MachineError, MachineResult};
use machine_mgr::types::{Capabilities, FlashCaps, FlashId, FlashSession, LifecycleCaps};

/// Configuration for the container image-store validation/import seam.
///
/// The component sits behind `machine_mgr::Component` so SOVD uploads can enter
/// through the normal install lifecycle while runtime-specific handling remains
/// scoped to local image-store validation/import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerImageConfig {
    pub id: String,
    pub images_dir: PathBuf,
    pub expected_ref: String,
    pub runtime: ContainerRuntimeKind,
}

impl ContainerImageConfig {
    pub fn new(id: impl Into<String>, images_dir: impl Into<PathBuf>) -> Self {
        Self {
            id: id.into(),
            images_dir: images_dir.into(),
            expected_ref: DEFAULT_CONTAINER_IMAGE_REF.into(),
            runtime: ContainerRuntimeKind::Docker,
        }
    }

    pub fn with_runtime(mut self, runtime: ContainerRuntimeKind) -> Self {
        self.runtime = runtime;
        self
    }
}

pub const DEFAULT_CONTAINER_IMAGE_REF: &str = "localhost/sumo-sovd-test:1.0.0";
pub const CONTAINER_IMAGE_PAYLOAD_URI: &str = "#container-image";
const COPY_BUF_SIZE: usize = 64 * 1024;
const MANIFEST_JSON_LIMIT: usize = 1024 * 1024;
const MANIFEST_UPLOAD_LIMIT: usize = 1024 * 1024;
const PAYLOAD_UPLOAD_HARD_LIMIT: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerRuntimeKind {
    Docker,
    Podman,
    Containerd { namespace: String },
}

impl ContainerRuntimeKind {
    pub fn containerd(namespace: impl Into<String>) -> Self {
        Self::Containerd {
            namespace: namespace.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerImageImportRequest {
    pub source_path: PathBuf,
    pub expected_sha256: [u8; 32],
    pub expected_size: u64,
    pub expected_ref: String,
}

impl ContainerImageImportRequest {
    pub fn new(
        source_path: impl Into<PathBuf>,
        expected_sha256: [u8; 32],
        expected_size: u64,
        expected_ref: impl Into<String>,
    ) -> Self {
        Self {
            source_path: source_path.into(),
            expected_sha256,
            expected_size,
            expected_ref: expected_ref.into(),
        }
    }
}

/// Explicit Component owner for local container image-store validation.
///
/// The explicit adapter validates a detached compressed container image archive
/// before importing it into the configured local runtime. Existing VM firmware/rootfs
/// behavior stays unchanged because only this component handles container-image
/// payload URIs.
pub struct ContainerImageComponent {
    config: ContainerImageConfig,
    capabilities: Capabilities,
    session: Mutex<Option<DockerImageSession>>,
}

impl ContainerImageComponent {
    pub fn new(config: ContainerImageConfig) -> Self {
        Self {
            config,
            capabilities: Capabilities {
                did_store: false,
                flash: Some(FlashCaps {
                    dual_bank: false,
                    supports_rollback: false,
                    supports_trial_boot: false,
                    abortable_after_finalize: true,
                }),
                lifecycle: Some(LifecycleCaps {
                    restartable: false,
                    has_runtime_state: false,
                }),
                hsm: None,
                dtcs: false,
                clear_dtcs: false,
            },
            session: Mutex::new(None),
        }
    }

    pub fn images_dir(&self) -> &Path {
        &self.config.images_dir
    }

    pub fn expected_ref(&self) -> &str {
        &self.config.expected_ref
    }

    pub fn import_archive(&self, request: &ContainerImageImportRequest) -> MachineResult<()> {
        fs::create_dir_all(&self.config.images_dir)
            .map_err(|e| MachineError::Storage(format!("docker_image.create_staging_dir: {e}")))?;

        let staged = StagedDockerArchive::copy_from(
            &request.source_path,
            &self.config.images_dir,
            request.expected_size,
            &request.expected_sha256,
        )?;

        self.config
            .runtime
            .validate_archive(staged.path(), &request.expected_ref)?;
        self.config.runtime.load_archive(staged.path())?;
        if !self.config.runtime.image_present(&request.expected_ref)? {
            return Err(MachineError::ManifestInvalid(format!(
                "ContainerImageInspectFailed: {}: runtime {} did not report imported image",
                request.expected_ref,
                self.config.runtime.name()
            )));
        }

        Ok(())
    }
}

#[derive(Debug)]
struct DockerImageSession {
    manifest: Option<DockerImageManifest>,
    payload_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DockerImageManifest {
    payload_uri: String,
    expected_sha256: [u8; 32],
    expected_size: u64,
    expected_ref: String,
}

impl DockerImageSession {
    fn new() -> Self {
        Self {
            manifest: None,
            payload_path: None,
        }
    }
}

struct StagedDockerArchive {
    path: PathBuf,
}

impl StagedDockerArchive {
    fn copy_from(
        source: &Path,
        staging_dir: &Path,
        expected_size: u64,
        expected_sha256: &[u8; 32],
    ) -> MachineResult<Self> {
        let path = staging_dir.join(format!(
            ".docker-image-{}.tar.gz.staged",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));

        let mut input = File::open(source).map_err(|e| {
            MachineError::InvalidArgument(format!(
                "DockerImageSourceOpen: {}: {e}",
                source.display()
            ))
        })?;
        let mut output = File::create(&path)
            .map_err(|e| MachineError::Storage(format!("DockerImageStageCreate: {e}")))?;
        let cleanup = FileCleanup::new(path.clone());

        let mut hasher = Sha256::new();
        let mut total = 0u64;
        let mut buf = vec![0u8; COPY_BUF_SIZE];
        loop {
            let n = input.read(&mut buf).map_err(|e| {
                MachineError::InvalidArgument(format!("DockerImageSourceRead: {e}"))
            })?;
            if n == 0 {
                break;
            }
            output
                .write_all(&buf[..n])
                .map_err(|e| MachineError::Storage(format!("DockerImageStageWrite: {e}")))?;
            hasher.update(&buf[..n]);
            total += n as u64;
        }
        output
            .sync_all()
            .map_err(|e| MachineError::Storage(format!("DockerImageStageSync: {e}")))?;

        if total != expected_size {
            return Err(MachineError::ManifestInvalid(format!(
                "DockerImageSizeMismatch: expected {expected_size} bytes, got {total} bytes"
            )));
        }
        let digest: [u8; 32] = hasher.finalize().into();
        if &digest != expected_sha256 {
            return Err(MachineError::ManifestInvalid(
                "DockerImageDigestMismatch".into(),
            ));
        }

        cleanup.disarm();
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StagedDockerArchive {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn parse_docker_image_manifest(
    bytes: &[u8],
    expected_ref: &str,
) -> MachineResult<DockerImageManifest> {
    parse_suit_docker_image_manifest(bytes, expected_ref)
        .or_else(|_| parse_pending_text_manifest(bytes, expected_ref))
}

fn parse_suit_docker_image_manifest(
    bytes: &[u8],
    expected_ref: &str,
) -> MachineResult<DockerImageManifest> {
    let envelope = sumo_codec::decode::decode_envelope(bytes)
        .map_err(|e| MachineError::ManifestInvalid(format!("DockerImageManifestDecode: {e:?}")))?;
    let manifest = sumo_onboard::manifest::Manifest { envelope };
    let payload_uri = manifest
        .uri(0)
        .ok_or_else(|| MachineError::ManifestInvalid("DockerImagePayloadUriMissing".into()))?
        .to_string();
    validate_payload_uri(&payload_uri)?;

    let expected_size = manifest
        .image_size(0)
        .ok_or_else(|| MachineError::ManifestInvalid("DockerImagePayloadSizeMissing".into()))?;
    let digest = manifest
        .image_digest(0)
        .ok_or_else(|| MachineError::ManifestInvalid("DockerImagePayloadDigestMissing".into()))?
        .0
        .bytes
        .clone();
    let expected_sha256: [u8; 32] = digest
        .as_slice()
        .try_into()
        .map_err(|_| MachineError::ManifestInvalid("DockerImagePayloadDigestNotSha256".into()))?;

    Ok(DockerImageManifest {
        payload_uri,
        expected_sha256,
        expected_size,
        expected_ref: expected_ref.to_string(),
    })
}

fn parse_pending_text_manifest(
    bytes: &[u8],
    expected_ref: &str,
) -> MachineResult<DockerImageManifest> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| MachineError::ManifestInvalid("DockerImageManifestNotSuitOrText".into()))?;
    if !text.starts_with("SUIT-L2-DETACHED-PENDING\n") {
        return Err(MachineError::ManifestInvalid(
            "DockerImageManifestNotSuitOrText".into(),
        ));
    }

    let payload_uri = text_field(text, "payload_uri")?;
    validate_payload_uri(&payload_uri)?;
    let image = text_field(text, "image")?;
    if image != expected_ref {
        return Err(MachineError::ManifestInvalid(format!(
            "DockerImageExpectedRefMismatch: expected {expected_ref}, got {image}"
        )));
    }
    let expected_size = text_field(text, "payload_size")?
        .parse::<u64>()
        .map_err(|_| MachineError::ManifestInvalid("DockerImagePayloadSizeInvalid".into()))?;
    let expected_sha256 = parse_sha256_hex(&text_field(text, "payload_digest")?)?;

    Ok(DockerImageManifest {
        payload_uri,
        expected_sha256,
        expected_size,
        expected_ref: expected_ref.to_string(),
    })
}

fn text_field(text: &str, key: &str) -> MachineResult<String> {
    let prefix = format!("{key}=");
    text.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map(str::to_string)
        .ok_or_else(|| {
            MachineError::ManifestInvalid(format!("DockerImageManifestFieldMissing: {key}"))
        })
}

fn validate_payload_uri(uri: &str) -> MachineResult<()> {
    if uri == CONTAINER_IMAGE_PAYLOAD_URI {
        Ok(())
    } else if uri.starts_with('#') {
        Err(MachineError::ManifestInvalid(format!(
            "DockerImagePayloadUriMismatch: expected {CONTAINER_IMAGE_PAYLOAD_URI}, got {uri}"
        )))
    } else {
        Err(MachineError::ManifestInvalid(format!(
            "DockerImageExternalPayloadUnsupported: {uri}"
        )))
    }
}

fn parse_sha256_hex(value: &str) -> MachineResult<[u8; 32]> {
    let hex = value.strip_prefix("sha256:").unwrap_or(value);
    if hex.len() != 64 {
        return Err(MachineError::ManifestInvalid(
            "DockerImagePayloadDigestInvalid".into(),
        ));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let s = std::str::from_utf8(chunk)
            .map_err(|_| MachineError::ManifestInvalid("DockerImagePayloadDigestInvalid".into()))?;
        out[i] = u8::from_str_radix(s, 16)
            .map_err(|_| MachineError::ManifestInvalid("DockerImagePayloadDigestInvalid".into()))?;
    }
    Ok(out)
}

async fn collect_manifest_stream(
    mut stream: machine_mgr::types::EnvelopeStream,
) -> MachineResult<Vec<u8>> {
    let mut data = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| MachineError::Internal(format!("DockerImageManifestRead: {e}")))?;
        if data.len() + chunk.len() > MANIFEST_UPLOAD_LIMIT {
            return Err(MachineError::ManifestInvalid(format!(
                "DockerImageManifestTooLarge: max {MANIFEST_UPLOAD_LIMIT} bytes"
            )));
        }
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

async fn save_payload_stream(
    mut stream: machine_mgr::types::EnvelopeStream,
    output_path: &Path,
    expected_size: u64,
) -> MachineResult<()> {
    let max_size = expected_size.min(PAYLOAD_UPLOAD_HARD_LIMIT);
    let mut file = File::create(output_path)
        .map_err(|e| MachineError::Storage(format!("DockerImagePayloadStageCreate: {e}")))?;
    let cleanup = FileCleanup::new(output_path.to_path_buf());
    let mut total = 0u64;
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| MachineError::Internal(format!("DockerImagePayloadRead: {e}")))?;
        total = total
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| MachineError::ManifestInvalid("DockerImagePayloadTooLarge".into()))?;
        if total > max_size {
            return Err(MachineError::ManifestInvalid(format!(
                "DockerImagePayloadTooLarge: max {max_size} bytes"
            )));
        }
        file.write_all(&chunk)
            .map_err(|e| MachineError::Storage(format!("DockerImagePayloadStageWrite: {e}")))?;
    }
    file.sync_all()
        .map_err(|e| MachineError::Storage(format!("DockerImagePayloadStageSync: {e}")))?;
    cleanup.disarm();
    Ok(())
}

fn validate_gzip(path: &Path) -> MachineResult<()> {
    let status = Command::new("gzip")
        .arg("-t")
        .arg(path)
        .status()
        .map_err(|e| MachineError::Internal(format!("DockerImageGzipValidatorUnavailable: {e}")))?;
    if !status.success() {
        return Err(MachineError::ManifestInvalid(
            "DockerImageCorruptGzip".into(),
        ));
    }
    Ok(())
}

trait ContainerRuntime {
    fn name(&self) -> &'static str;
    fn validate_archive(&self, path: &Path, expected_ref: &str) -> MachineResult<()>;
    fn load_archive(&self, path: &Path) -> MachineResult<()>;
    fn image_present(&self, expected_ref: &str) -> MachineResult<bool>;
}

impl ContainerRuntime for ContainerRuntimeKind {
    fn name(&self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
            Self::Containerd { .. } => "containerd",
        }
    }

    fn validate_archive(&self, path: &Path, expected_ref: &str) -> MachineResult<()> {
        validate_gzip(path)?;
        match self {
            Self::Docker | Self::Podman => validate_docker_archive(path, expected_ref),
            Self::Containerd { .. } => validate_oci_or_docker_archive(path, expected_ref),
        }
    }

    fn load_archive(&self, path: &Path) -> MachineResult<()> {
        match self {
            Self::Docker => docker_load(path),
            Self::Podman => podman_load(path),
            Self::Containerd { namespace } => containerd_import(namespace, path),
        }
    }

    fn image_present(&self, expected_ref: &str) -> MachineResult<bool> {
        match self {
            Self::Docker => docker_inspect(expected_ref),
            Self::Podman => podman_inspect(expected_ref),
            Self::Containerd { namespace } => containerd_image_present(namespace, expected_ref),
        }
    }
}

fn validate_oci_or_docker_archive(path: &Path, expected_ref: &str) -> MachineResult<()> {
    match validate_oci_archive(path, expected_ref) {
        Ok(()) => Ok(()),
        Err(err) if err.to_string().contains("ContainerImageOciIndexMissing") => {
            validate_docker_archive(path, expected_ref)
        }
        Err(err) => Err(err),
    }
}

fn validate_oci_archive(path: &Path, expected_ref: &str) -> MachineResult<()> {
    let index = extract_archive_entry(path, "index.json", "ContainerImageOciIndexMissing")?;
    if !oci_index_has_ref(&index, expected_ref)? {
        return Err(MachineError::ManifestInvalid(format!(
            "ContainerImageExpectedRefMissing: {expected_ref}"
        )));
    }

    Ok(())
}

fn oci_index_has_ref(index: &[u8], expected_ref: &str) -> MachineResult<bool> {
    let index: serde_json::Value = serde_json::from_slice(index).map_err(|e| {
        MachineError::ManifestInvalid(format!("ContainerImageOciIndexInvalid: {e}"))
    })?;
    let manifests = index
        .get("manifests")
        .and_then(|manifests| manifests.as_array())
        .ok_or_else(|| MachineError::ManifestInvalid("ContainerImageOciIndexNoManifests".into()))?;
    Ok(manifests.iter().any(|manifest| {
        manifest
            .get("annotations")
            .and_then(|annotations| annotations.get("org.opencontainers.image.ref.name"))
            .and_then(|name| name.as_str())
            == Some(expected_ref)
    }))
}

fn validate_docker_archive(path: &Path, expected_ref: &str) -> MachineResult<()> {
    let manifest = extract_manifest_json(path)?;
    if !archive_manifest_has_ref(&manifest, expected_ref)? {
        return Err(MachineError::ManifestInvalid(format!(
            "DockerImageExpectedTagMissing: {expected_ref}"
        )));
    }

    Ok(())
}

fn archive_manifest_has_ref(manifest: &[u8], expected_ref: &str) -> MachineResult<bool> {
    let entries: serde_json::Value = serde_json::from_slice(manifest).map_err(|e| {
        MachineError::ManifestInvalid(format!("DockerImageManifestJsonInvalid: {e}"))
    })?;
    let entries = entries
        .as_array()
        .ok_or_else(|| MachineError::ManifestInvalid("DockerImageManifestJsonNotArray".into()))?;
    Ok(entries.iter().any(|entry| {
        entry
            .get("RepoTags")
            .and_then(|repo_tags| repo_tags.as_array())
            .map(|repo_tags| {
                repo_tags
                    .iter()
                    .any(|tag| tag.as_str() == Some(expected_ref))
            })
            .unwrap_or(false)
    }))
}

fn docker_load(path: &Path) -> MachineResult<()> {
    docker_load_with_command(&mut Command::new("docker"), path)
}

fn docker_load_with_command(command: &mut Command, path: &Path) -> MachineResult<()> {
    run_command(
        command.arg("load").arg("--input").arg(path),
        "DockerImageDockerUnavailable",
        "DockerImageLoadFailed",
    )
}

fn docker_inspect(expected_ref: &str) -> MachineResult<bool> {
    image_inspect_with_command(
        Command::new("docker")
            .arg("image")
            .arg("inspect")
            .arg(expected_ref),
        "DockerImageDockerUnavailable",
    )
}

fn podman_load(path: &Path) -> MachineResult<()> {
    podman_load_with_command(&mut Command::new("podman"), path)
}

fn podman_load_with_command(command: &mut Command, path: &Path) -> MachineResult<()> {
    run_command(
        command.arg("load").arg("--input").arg(path),
        "ContainerImagePodmanUnavailable",
        "ContainerImagePodmanLoadFailed",
    )
}

fn podman_inspect(expected_ref: &str) -> MachineResult<bool> {
    image_inspect_with_command(
        Command::new("podman")
            .arg("image")
            .arg("inspect")
            .arg(expected_ref),
        "ContainerImagePodmanUnavailable",
    )
}

fn containerd_import(namespace: &str, path: &Path) -> MachineResult<()> {
    containerd_import_with_command(&mut Command::new("ctr"), namespace, path)
}

fn containerd_import_with_command(
    command: &mut Command,
    namespace: &str,
    path: &Path,
) -> MachineResult<()> {
    run_command(
        command
            .arg("-n")
            .arg(namespace)
            .arg("images")
            .arg("import")
            .arg(path),
        "ContainerImageContainerdUnavailable",
        "ContainerImageContainerdImportFailed",
    )
}

fn containerd_image_present(namespace: &str, expected_ref: &str) -> MachineResult<bool> {
    let output = Command::new("ctr")
        .arg("-n")
        .arg(namespace)
        .arg("images")
        .arg("list")
        .arg("-q")
        .arg(format!("name=={expected_ref}"))
        .output()
        .map_err(|e| MachineError::Internal(format!("ContainerImageContainerdUnavailable: {e}")))?;
    if !output.status.success() {
        return Err(MachineError::ManifestInvalid(format!(
            "ContainerImageContainerdInspectFailed: {expected_ref}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|line| line.trim() == expected_ref))
}

fn image_inspect_with_command(command: &mut Command, unavailable: &str) -> MachineResult<bool> {
    let output = command
        .output()
        .map_err(|e| MachineError::Internal(format!("{unavailable}: {e}")))?;
    Ok(output.status.success())
}

fn run_command(command: &mut Command, unavailable: &str, failure: &str) -> MachineResult<()> {
    let output = command
        .output()
        .map_err(|e| MachineError::Internal(format!("{unavailable}: {e}")))?;
    if !output.status.success() {
        return Err(MachineError::Internal(format!(
            "{failure}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn extract_manifest_json(path: &Path) -> MachineResult<Vec<u8>> {
    extract_archive_entry(path, "manifest.json", "DockerImageManifestMissing")
}

fn extract_archive_entry(path: &Path, entry: &str, missing_label: &str) -> MachineResult<Vec<u8>> {
    let mut child = Command::new("tar")
        .arg("-xOzf")
        .arg(path)
        .arg(entry)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| MachineError::Internal(format!("{missing_label}: {e}")))?;

    let mut stdout = child.stdout.take().ok_or_else(|| {
        let _ = child.kill();
        let _ = child.wait();
        MachineError::Internal(format!("{missing_label}: stdout unavailable"))
    })?;

    let mut manifest = Vec::new();
    let mut buf = [0u8; COPY_BUF_SIZE];
    loop {
        let n = match stdout.read(&mut buf) {
            Ok(n) => n,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(MachineError::Internal(format!(
                    "ContainerImageArchiveEntryRead: {e}"
                )));
            }
        };
        if n == 0 {
            break;
        }
        if manifest.len() > MANIFEST_JSON_LIMIT.saturating_sub(n) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(MachineError::ManifestInvalid(format!(
                "DockerImageManifestTooLarge: max {MANIFEST_JSON_LIMIT} bytes"
            )));
        }
        manifest.extend_from_slice(&buf[..n]);
    }

    let status = child
        .wait()
        .map_err(|e| MachineError::Internal(format!("{missing_label}: {e}")))?;
    if !status.success() {
        return Err(MachineError::ManifestInvalid(missing_label.into()));
    }
    Ok(manifest)
}

#[async_trait]
impl Component for ContainerImageComponent {
    fn id(&self) -> &str {
        &self.config.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    async fn start_install(&self) -> MachineResult<FlashSession> {
        fs::create_dir_all(&self.config.images_dir)
            .map_err(|e| MachineError::Storage(format!("docker_image.create_staging_dir: {e}")))?;
        let mut session = self.session.lock().unwrap();
        if session.is_some() {
            return Err(MachineError::InvalidArgument(
                "docker_image install session already active".into(),
            ));
        }
        *session = Some(DockerImageSession::new());
        Ok(FlashSession {
            id: FlashId::new("docker-image"),
            target_bank: None,
            max_chunk_size: 16 * 1024 * 1024,
        })
    }

    async fn upload_envelope(
        &self,
        _id: &FlashId,
        stream: machine_mgr::types::EnvelopeStream,
    ) -> MachineResult<String> {
        let manifest = {
            let session = self.session.lock().unwrap();
            let session = session.as_ref().ok_or_else(|| {
                MachineError::UnknownFlashSession("no active docker_image session".into())
            })?;
            session.manifest.clone()
        };

        if manifest.is_none() {
            let manifest_bytes = collect_manifest_stream(stream).await?;
            let manifest = parse_docker_image_manifest(&manifest_bytes, &self.config.expected_ref)?;
            let mut session = self.session.lock().unwrap();
            let session = session.as_mut().ok_or_else(|| {
                MachineError::UnknownFlashSession("no active docker_image session".into())
            })?;
            if session.manifest.is_some() {
                return Err(MachineError::InvalidArgument(
                    "docker_image manifest already uploaded".into(),
                ));
            }
            session.manifest = Some(manifest);
            Ok("docker-image-manifest".into())
        } else {
            let manifest = manifest.expect("manifest checked above");
            {
                let session = self.session.lock().unwrap();
                let session = session.as_ref().ok_or_else(|| {
                    MachineError::UnknownFlashSession("no active docker_image session".into())
                })?;
                if session.payload_path.is_some() {
                    return Err(MachineError::InvalidArgument(
                        "docker_image payload already uploaded".into(),
                    ));
                }
            }

            let payload_path = self.config.images_dir.join(format!(
                ".docker-image-upload-{}.tar.gz",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or_default()
            ));
            save_payload_stream(stream, &payload_path, manifest.expected_size).await?;
            let mut session = self.session.lock().unwrap();
            assign_payload_path(&mut *session, payload_path)?;
            Ok("docker-image-payload".into())
        }
    }

    async fn finalize_install(&self, _id: &FlashId) -> MachineResult<()> {
        let session = {
            let mut session = self.session.lock().unwrap();
            session.take().ok_or_else(|| {
                MachineError::UnknownFlashSession("no active docker_image session".into())
            })?
        };
        let manifest = session.manifest.ok_or_else(|| {
            MachineError::ManifestInvalid("DockerImageManifestNotUploaded".into())
        })?;
        let payload_path = session
            .payload_path
            .ok_or_else(|| MachineError::ManifestInvalid("DockerImagePayloadNotUploaded".into()))?;
        let cleanup = UploadedDockerArchive {
            path: payload_path.clone(),
        };
        let request = ContainerImageImportRequest::new(
            &payload_path,
            manifest.expected_sha256,
            manifest.expected_size,
            manifest.expected_ref,
        );
        let result = self.import_archive(&request);
        drop(cleanup);
        result
    }

    async fn commit_install(&self, _id: &FlashId) -> MachineResult<()> {
        Ok(())
    }
}

fn assign_payload_path(
    session: &mut Option<DockerImageSession>,
    payload_path: PathBuf,
) -> MachineResult<()> {
    let cleanup = FileCleanup::new(payload_path.clone());
    let session = session.as_mut().ok_or_else(|| {
        MachineError::UnknownFlashSession("no active docker_image session".into())
    })?;
    if session.payload_path.is_some() {
        return Err(MachineError::InvalidArgument(
            "docker_image payload already uploaded".into(),
        ));
    }
    session.payload_path = Some(payload_path);
    cleanup.disarm();
    Ok(())
}

struct UploadedDockerArchive {
    path: PathBuf,
}

impl Drop for UploadedDockerArchive {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

struct FileCleanup {
    path: PathBuf,
    armed: std::cell::Cell<bool>,
}

impl FileCleanup {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            armed: std::cell::Cell::new(true),
        }
    }

    fn disarm(&self) {
        self.armed.set(false);
    }
}

impl Drop for FileCleanup {
    fn drop(&mut self) {
        if self.armed.get() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    use tempfile::TempDir;

    const BAD_DOCKER_IMAGE_REF: &str = "localhost/sumo-sovd-test:bad";

    #[test]
    fn docker_image_component_names_image_store_owner() {
        let component = ContainerImageComponent::new(ContainerImageConfig::new(
            "docker-image",
            "/var/lib/sumo/docker-images",
        ));

        assert_eq!(component.id(), "docker-image");
        assert_eq!(
            component.images_dir(),
            Path::new("/var/lib/sumo/docker-images")
        );
        assert!(component.capabilities().flash.is_some());
        assert_eq!(component.expected_ref(), DEFAULT_CONTAINER_IMAGE_REF);
    }

    #[test]
    fn container_image_component_keeps_component_trait_shape() {
        fn assert_component<T: Component>() {}

        assert_component::<ContainerImageComponent>();
    }

    #[test]
    fn container_image_config_can_select_each_runtime() {
        let docker = ContainerImageConfig::new("container-image", "/tmp/images");
        assert_eq!(docker.runtime, ContainerRuntimeKind::Docker);

        let podman = ContainerImageConfig::new("container-image", "/tmp/images")
            .with_runtime(ContainerRuntimeKind::Podman);
        assert_eq!(podman.runtime.name(), "podman");

        let containerd = ContainerImageConfig::new("container-image", "/tmp/images")
            .with_runtime(ContainerRuntimeKind::containerd("k8s.io"));
        assert_eq!(containerd.runtime.name(), "containerd");
    }

    #[test]
    fn size_mismatch_fails_before_archive_validation_and_cleans_staging() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("payload.tar.gz");
        fs::write(&source, b"not a gzip").unwrap();
        let component = ContainerImageComponent::new(ContainerImageConfig::new(
            "docker-image",
            tmp.path().join("staging"),
        ));

        let request = ContainerImageImportRequest::new(
            &source,
            sha256_file(&source),
            999,
            DEFAULT_CONTAINER_IMAGE_REF,
        );

        let err = component.import_archive(&request).unwrap_err();
        assert_error_contains(err, "DockerImageSizeMismatch");
        assert_no_staged_files(component.images_dir());
    }

    #[test]
    fn digest_mismatch_fails_before_archive_validation_and_cleans_staging() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("payload.tar.gz");
        fs::write(&source, b"not a gzip").unwrap();
        let component = ContainerImageComponent::new(ContainerImageConfig::new(
            "docker-image",
            tmp.path().join("staging"),
        ));
        let mut bad_digest = sha256_file(&source);
        bad_digest[0] ^= 0xff;

        let request = ContainerImageImportRequest::new(
            &source,
            bad_digest,
            fs::metadata(&source).unwrap().len(),
            DEFAULT_CONTAINER_IMAGE_REF,
        );

        let err = component.import_archive(&request).unwrap_err();
        assert_error_contains(err, "DockerImageDigestMismatch");
        assert_no_staged_files(component.images_dir());
    }

    #[test]
    fn corrupt_gzip_is_named_and_cleans_staging() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("payload.tar.gz");
        fs::write(&source, b"not a gzip").unwrap();
        let component = ContainerImageComponent::new(ContainerImageConfig::new(
            "docker-image",
            tmp.path().join("staging"),
        ));

        let request = valid_request_for(&source, DEFAULT_CONTAINER_IMAGE_REF);
        let err = component.import_archive(&request).unwrap_err();
        assert_error_contains(err, "DockerImageCorruptGzip");
        assert_no_staged_files(component.images_dir());
    }

    #[test]
    fn empty_archive_is_named_and_cleans_staging() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("empty.tar.gz");
        create_tar_gz(&source, None);
        let component = ContainerImageComponent::new(ContainerImageConfig::new(
            "docker-image",
            tmp.path().join("staging"),
        ));

        let err = component
            .import_archive(&valid_request_for(&source, DEFAULT_CONTAINER_IMAGE_REF))
            .unwrap_err();
        assert_error_contains(err, "DockerImageManifestMissing");
        assert_no_staged_files(component.images_dir());
    }

    #[test]
    fn non_docker_tar_is_named_and_cleans_staging() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("not-docker.tar.gz");
        create_tar_gz(&source, Some(("file.txt", b"hello")));
        let component = ContainerImageComponent::new(ContainerImageConfig::new(
            "docker-image",
            tmp.path().join("staging"),
        ));

        let err = component
            .import_archive(&valid_request_for(&source, DEFAULT_CONTAINER_IMAGE_REF))
            .unwrap_err();
        assert_error_contains(err, "DockerImageManifestMissing");
        assert_no_staged_files(component.images_dir());
    }

    #[test]
    fn missing_expected_tag_is_named_and_cleans_staging() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("docker-missing-tag.tar.gz");
        create_tar_gz(
            &source,
            Some((
                "manifest.json",
                br#"[{"Config":"cfg.json","RepoTags":["localhost/other:1.0.0"],"Layers":[]}]"#,
            )),
        );
        let component = ContainerImageComponent::new(ContainerImageConfig::new(
            "docker-image",
            tmp.path().join("staging"),
        ));

        let err = component
            .import_archive(&valid_request_for(&source, DEFAULT_CONTAINER_IMAGE_REF))
            .unwrap_err();
        assert_error_contains(err, "DockerImageExpectedTagMissing");
        assert_no_staged_files(component.images_dir());
    }

    #[test]
    fn docker_archive_rejects_deceptive_expected_ref_outside_repo_tags() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("docker-deceptive-ref.tar.gz");
        create_tar_gz(
            &source,
            Some((
                "manifest.json",
                br#"[{
                    "Config":"cfg.json",
                    "RepoTags":["localhost/other:1.0.0"],
                    "Labels":{"looks-like-tag":"localhost/sumo-sovd-test:1.0.0"},
                    "Layers":[]
                }]"#,
            )),
        );

        let err = validate_docker_archive(&source, DEFAULT_CONTAINER_IMAGE_REF).unwrap_err();
        assert_error_contains(err, "DockerImageExpectedTagMissing");
    }

    #[test]
    fn docker_archive_accepts_expected_ref_among_multiple_tags_and_images() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("docker-multiple-tags-images.tar.gz");
        create_tar_gz(
            &source,
            Some((
                "manifest.json",
                br#"[
                    {"Config":"cfg-a.json","RepoTags":["localhost/other:1.0.0","localhost/sumo-sovd-test:1.0.0"],"Layers":[]},
                    {"Config":"cfg-b.json","RepoTags":["localhost/other:2.0.0"],"Layers":[]}
                ]"#,
            )),
        );

        validate_docker_archive(&source, DEFAULT_CONTAINER_IMAGE_REF).unwrap();
    }

    #[test]
    fn docker_archive_without_repo_tags_uses_expected_ref_semantics() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("docker-no-repo-tags.tar.gz");
        create_tar_gz(
            &source,
            Some(("manifest.json", br#"[{"Config":"cfg.json","Layers":[]}]"#)),
        );

        let err = validate_docker_archive(&source, DEFAULT_CONTAINER_IMAGE_REF).unwrap_err();
        assert_error_contains(err, "DockerImageExpectedTagMissing");
    }

    #[test]
    fn docker_archive_accepts_exact_expected_ref_in_repo_tags() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("docker-exact-tag.tar.gz");
        create_tar_gz(
            &source,
            Some((
                "manifest.json",
                br#"[{"Config":"cfg.json","RepoTags":["localhost/sumo-sovd-test:1.0.0"],"Layers":[]}]"#,
            )),
        );

        validate_docker_archive(&source, DEFAULT_CONTAINER_IMAGE_REF).unwrap();
    }

    #[test]
    fn docker_archive_rejects_manifest_json_over_limit() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("docker-large-manifest.tar.gz");
        let manifest = vec![b'['; MANIFEST_JSON_LIMIT + 1];
        create_tar_gz(&source, Some(("manifest.json", &manifest)));

        let err = validate_docker_archive(&source, DEFAULT_CONTAINER_IMAGE_REF)
            .unwrap_err()
            .to_string();
        assert!(err.contains("DockerImageManifestTooLarge"), "{err}");
        assert!(err.contains(&MANIFEST_JSON_LIMIT.to_string()), "{err}");
    }

    #[test]
    fn docker_load_daemon_unavailable_failure_is_named_and_does_not_hang() {
        let mut fake_docker = Command::new("sh");
        fake_docker
            .arg("-c")
            .arg("printf 'Cannot connect to the Docker daemon' >&2; exit 1")
            .arg("fake-docker");

        let err = docker_load_with_command(&mut fake_docker, Path::new("unused.tar.gz"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("DockerImageLoadFailed"), "{err}");
        assert!(err.contains("Cannot connect to the Docker daemon"), "{err}");
    }

    #[test]
    fn podman_load_uses_podman_compatible_arguments() {
        let mut fake_podman = Command::new("sh");
        fake_podman
            .arg("-c")
            .arg("test \"$1\" = load && test \"$2\" = --input && test \"$3\" = image.tar.gz")
            .arg("fake-podman");

        podman_load_with_command(&mut fake_podman, Path::new("image.tar.gz")).unwrap();
    }

    #[test]
    fn containerd_import_uses_namespace_and_import_arguments() {
        let mut fake_ctr = Command::new("sh");
        fake_ctr
            .arg("-c")
            .arg("test \"$1\" = -n && test \"$2\" = k8s.io && test \"$3\" = images && test \"$4\" = import && test \"$5\" = image.tar.gz")
            .arg("fake-ctr");

        containerd_import_with_command(&mut fake_ctr, "k8s.io", Path::new("image.tar.gz")).unwrap();
    }

    #[test]
    fn containerd_accepts_oci_archive_index_ref() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("oci-image.tar.gz");
        create_tar_gz(
            &source,
            Some((
                "index.json",
                br#"{
                    "schemaVersion": 2,
                    "manifests": [{
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "size": 1,
                        "annotations": {
                            "org.opencontainers.image.ref.name": "localhost/sumo-sovd-test:1.0.0"
                        }
                    }]
                }"#,
            )),
        );

        validate_oci_archive(&source, DEFAULT_CONTAINER_IMAGE_REF).unwrap();
    }

    #[test]
    fn containerd_rejects_oci_archive_without_expected_ref() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("oci-other-image.tar.gz");
        create_tar_gz(
            &source,
            Some((
                "index.json",
                br#"{"schemaVersion":2,"manifests":[{"annotations":{"org.opencontainers.image.ref.name":"localhost/other:1.0.0"}}]}"#,
            )),
        );

        let err = validate_oci_archive(&source, DEFAULT_CONTAINER_IMAGE_REF).unwrap_err();
        assert_error_contains(err, "ContainerImageExpectedRefMissing");
    }

    #[test]
    fn containerd_does_not_fall_back_when_oci_index_is_malformed() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("oci-malformed-index.tar.gz");
        create_tar_gz(&source, Some(("index.json", b"not json")));

        let err = validate_oci_or_docker_archive(&source, DEFAULT_CONTAINER_IMAGE_REF).unwrap_err();
        assert_error_contains(err, "ContainerImageOciIndexInvalid");
    }

    #[test]
    fn pending_manifest_rejects_invalid_payload_size_and_digest_values() {
        let bad_size = format!(
            "SUIT-L2-DETACHED-PENDING\ncomponent=container_image\nimage={}\npayload_uri={}\npayload_digest=sha256:{}\npayload_size=not-a-number\n",
            DEFAULT_CONTAINER_IMAGE_REF,
            CONTAINER_IMAGE_PAYLOAD_URI,
            "00".repeat(32)
        );
        let err = parse_pending_text_manifest(bad_size.as_bytes(), DEFAULT_CONTAINER_IMAGE_REF)
            .unwrap_err();
        assert_error_contains(err, "DockerImagePayloadSizeInvalid");

        let bad_digest = format!(
            "SUIT-L2-DETACHED-PENDING\ncomponent=container_image\nimage={}\npayload_uri={}\npayload_digest=sha256:not-hex\npayload_size=1\n",
            DEFAULT_CONTAINER_IMAGE_REF, CONTAINER_IMAGE_PAYLOAD_URI
        );
        let err = parse_pending_text_manifest(bad_digest.as_bytes(), DEFAULT_CONTAINER_IMAGE_REF)
            .unwrap_err();
        assert_error_contains(err, "DockerImagePayloadDigestInvalid");
    }

    #[test]
    fn manifest_stream_allows_exact_limit_and_rejects_one_byte_over() {
        let exact = vec![b'a'; MANIFEST_UPLOAD_LIMIT];
        let collected = futures::executor::block_on(collect_manifest_stream(bytes_stream(exact)))
            .unwrap();
        assert_eq!(collected.len(), MANIFEST_UPLOAD_LIMIT);

        let oversized = vec![b'a'; MANIFEST_UPLOAD_LIMIT + 1];
        let err = futures::executor::block_on(collect_manifest_stream(bytes_stream(oversized)))
            .unwrap_err();
        assert_error_contains(err, "DockerImageManifestTooLarge");
    }

    #[test]
    fn payload_stream_allows_exact_expected_size() {
        let tmp = TempDir::new().unwrap();
        let output_path = tmp.path().join("payload.tar.gz");
        let payload = b"exact payload".to_vec();

        futures::executor::block_on(save_payload_stream(
            bytes_stream(payload.clone()),
            &output_path,
            payload.len() as u64,
        ))
        .unwrap();

        assert_eq!(fs::read(output_path).unwrap(), payload);
    }

    #[test]
    fn lifecycle_rejects_payload_uri_mismatch_before_payload_upload() {
        let tmp = TempDir::new().unwrap();
        let component = ContainerImageComponent::new(ContainerImageConfig::new(
            "docker_image",
            tmp.path().join("staging"),
        ));

        futures::executor::block_on(component.start_install()).unwrap();
        let err = futures::executor::block_on(component.upload_envelope(
            &FlashId::new(""),
            bytes_stream(pending_manifest(
                "#other",
                DEFAULT_CONTAINER_IMAGE_REF,
                [0u8; 32],
                0,
            )),
        ))
        .unwrap_err();

        assert_error_contains(err, "DockerImagePayloadUriMismatch");
        assert_no_staged_files(component.images_dir());
    }

    #[test]
    fn lifecycle_rejects_external_payload_uri_for_mvp() {
        let tmp = TempDir::new().unwrap();
        let component = ContainerImageComponent::new(ContainerImageConfig::new(
            "docker_image",
            tmp.path().join("staging"),
        ));

        futures::executor::block_on(component.start_install()).unwrap();
        let err = futures::executor::block_on(component.upload_envelope(
            &FlashId::new(""),
            bytes_stream(pending_manifest(
                "https://registry.example.invalid/image.tar.gz",
                DEFAULT_CONTAINER_IMAGE_REF,
                [0u8; 32],
                0,
            )),
        ))
        .unwrap_err();

        assert_error_contains(err, "DockerImageExternalPayloadUnsupported");
        assert_no_staged_files(component.images_dir());
    }

    #[test]
    fn lifecycle_rejects_legacy_docker_payload_uri_after_alias_removal() {
        let tmp = TempDir::new().unwrap();
        let component = ContainerImageComponent::new(ContainerImageConfig::new(
            "container_image",
            tmp.path().join("staging"),
        ));

        futures::executor::block_on(component.start_install()).unwrap();
        let err = futures::executor::block_on(component.upload_envelope(
            &FlashId::new(""),
            bytes_stream(pending_manifest(
                "#docker-image",
                DEFAULT_CONTAINER_IMAGE_REF,
                [0u8; 32],
                0,
            )),
        ))
        .unwrap_err();

        assert_error_contains(err, "DockerImagePayloadUriMismatch");
        assert_no_staged_files(component.images_dir());
    }

    #[test]
    fn lifecycle_rejects_corrupt_payload_before_docker_import() {
        let tmp = TempDir::new().unwrap();
        let component = ContainerImageComponent::new(ContainerImageConfig::new(
            "docker_image",
            tmp.path().join("staging"),
        ));
        let payload = b"not a gzip-compressed Docker save archive".to_vec();
        let digest: [u8; 32] = Sha256::digest(&payload).into();

        futures::executor::block_on(component.start_install()).unwrap();
        futures::executor::block_on(component.upload_envelope(
            &FlashId::new(""),
            bytes_stream(pending_manifest(
                CONTAINER_IMAGE_PAYLOAD_URI,
                DEFAULT_CONTAINER_IMAGE_REF,
                digest,
                payload.len() as u64,
            )),
        ))
        .unwrap();
        futures::executor::block_on(
            component.upload_envelope(&FlashId::new(""), bytes_stream(payload)),
        )
        .unwrap();

        let err =
            futures::executor::block_on(component.finalize_install(&FlashId::new(""))).unwrap_err();

        assert_error_contains(err, "DockerImageCorruptGzip");
        assert_no_staged_files(component.images_dir());
    }

    #[test]
    fn lifecycle_rejects_duplicate_payload_without_replacing_or_leaking_upload() {
        let tmp = TempDir::new().unwrap();
        let component = ContainerImageComponent::new(ContainerImageConfig::new(
            "docker_image",
            tmp.path().join("staging"),
        ));
        let payload = b"first payload bytes".to_vec();
        let digest: [u8; 32] = Sha256::digest(&payload).into();

        futures::executor::block_on(component.start_install()).unwrap();
        futures::executor::block_on(component.upload_envelope(
            &FlashId::new(""),
            bytes_stream(pending_manifest(
                CONTAINER_IMAGE_PAYLOAD_URI,
                DEFAULT_CONTAINER_IMAGE_REF,
                digest,
                payload.len() as u64,
            )),
        ))
        .unwrap();
        futures::executor::block_on(
            component.upload_envelope(&FlashId::new(""), bytes_stream(payload)),
        )
        .unwrap();

        let err = futures::executor::block_on(component.upload_envelope(
            &FlashId::new(""),
            bytes_stream(b"second payload must not replace first".to_vec()),
        ))
        .unwrap_err();

        assert_error_contains(err, "docker_image payload already uploaded");
        assert_eq!(upload_file_count(component.images_dir()), 1);
    }

    #[test]
    fn payload_assignment_cleans_upload_when_session_disappeared() {
        let tmp = TempDir::new().unwrap();
        let payload_path = tmp.path().join(".docker-image-upload-race.tar.gz");
        fs::write(&payload_path, b"newly staged payload").unwrap();
        let mut session = None;

        let err = assign_payload_path(&mut session, payload_path).unwrap_err();

        assert_error_contains(err, "no active docker_image session");
        assert_no_staged_files(tmp.path());
    }

    #[test]
    fn lifecycle_rejects_oversized_payload_and_cleans_partial_upload() {
        let tmp = TempDir::new().unwrap();
        let component = ContainerImageComponent::new(ContainerImageConfig::new(
            "docker_image",
            tmp.path().join("staging"),
        ));
        let payload = b"too many bytes".to_vec();
        let digest: [u8; 32] = Sha256::digest(&payload).into();

        futures::executor::block_on(component.start_install()).unwrap();
        futures::executor::block_on(component.upload_envelope(
            &FlashId::new(""),
            bytes_stream(pending_manifest(
                CONTAINER_IMAGE_PAYLOAD_URI,
                DEFAULT_CONTAINER_IMAGE_REF,
                digest,
                (payload.len() - 1) as u64,
            )),
        ))
        .unwrap();

        let err = futures::executor::block_on(
            component.upload_envelope(&FlashId::new(""), bytes_stream(payload)),
        )
        .unwrap_err();

        assert_error_contains(err, "DockerImagePayloadTooLarge");
        assert_no_staged_files(component.images_dir());
    }

    #[test]
    fn lifecycle_rejects_manifest_bytes_in_payload_phase_without_leaking_upload() {
        let tmp = TempDir::new().unwrap();
        let component = ContainerImageComponent::new(ContainerImageConfig::new(
            "docker_image",
            tmp.path().join("staging"),
        ));

        futures::executor::block_on(component.start_install()).unwrap();
        futures::executor::block_on(component.upload_envelope(
            &FlashId::new(""),
            bytes_stream(pending_manifest(
                CONTAINER_IMAGE_PAYLOAD_URI,
                DEFAULT_CONTAINER_IMAGE_REF,
                [1u8; 32],
                1,
            )),
        ))
        .unwrap();

        let err = futures::executor::block_on(component.upload_envelope(
            &FlashId::new(""),
            bytes_stream(pending_manifest(
                CONTAINER_IMAGE_PAYLOAD_URI,
                DEFAULT_CONTAINER_IMAGE_REF,
                [2u8; 32],
                2,
            )),
        ))
        .unwrap_err();

        assert_error_contains(err, "DockerImagePayloadTooLarge");
        assert_no_staged_files(component.images_dir());
    }

    #[test]
    #[ignore = "requires local Docker daemon and fixture archive"]
    fn valid_docker_archive_imports_and_inspects_expected_ref() {
        let archive = std::env::var_os("SUMO_DOCKER_IMAGE_ARCHIVE")
            .map(PathBuf::from)
            .expect("set SUMO_DOCKER_IMAGE_ARCHIVE to a Docker save .tar.gz fixture");
        let tmp = TempDir::new().unwrap();
        let _guard = DockerImageCleanup::new(DEFAULT_CONTAINER_IMAGE_REF);
        let component = ContainerImageComponent::new(ContainerImageConfig::new(
            "docker-image",
            tmp.path().join("staging"),
        ));

        component
            .import_archive(&valid_request_for(&archive, DEFAULT_CONTAINER_IMAGE_REF))
            .unwrap();
        assert_no_staged_files(component.images_dir());
    }

    #[test]
    #[ignore = "requires local Docker daemon and fixture archive"]
    fn lifecycle_imports_valid_docker_archive_idempotently_and_inspects_expected_ref() {
        let archive = std::env::var_os("SUMO_DOCKER_IMAGE_ARCHIVE")
            .map(PathBuf::from)
            .expect("set SUMO_DOCKER_IMAGE_ARCHIVE to a Docker save .tar.gz fixture");
        let tmp = TempDir::new().unwrap();
        let _guard = DockerImageCleanup::new(DEFAULT_CONTAINER_IMAGE_REF);
        let component = ContainerImageComponent::new(ContainerImageConfig::new(
            "docker_image",
            tmp.path().join("staging"),
        ));

        run_valid_lifecycle(&component, &archive);
        assert!(
            docker_image_present(DEFAULT_CONTAINER_IMAGE_REF),
            "expected docker image inspect to find {DEFAULT_CONTAINER_IMAGE_REF} after first lifecycle import"
        );

        run_valid_lifecycle(&component, &archive);
        assert!(
            docker_image_present(DEFAULT_CONTAINER_IMAGE_REF),
            "expected docker image inspect to find {DEFAULT_CONTAINER_IMAGE_REF} after duplicate lifecycle import"
        );
        assert_no_staged_files(component.images_dir());
    }

    #[test]
    #[ignore = "requires local Docker daemon and fixture archive"]
    fn invalid_expected_ref_does_not_leave_bad_image_inspectable() {
        let archive = std::env::var_os("SUMO_DOCKER_IMAGE_ARCHIVE")
            .map(PathBuf::from)
            .expect("set SUMO_DOCKER_IMAGE_ARCHIVE to a Docker save .tar.gz fixture");
        let tmp = TempDir::new().unwrap();
        let _guard = DockerImageCleanup::new(BAD_DOCKER_IMAGE_REF);
        let component = ContainerImageComponent::new(ContainerImageConfig::new(
            "docker-image",
            tmp.path().join("staging"),
        ));

        let err = component
            .import_archive(&valid_request_for(&archive, BAD_DOCKER_IMAGE_REF))
            .unwrap_err();

        assert_error_contains(err, "DockerImageExpectedTagMissing");
        assert!(
            !docker_image_present(BAD_DOCKER_IMAGE_REF),
            "negative import must not leave {BAD_DOCKER_IMAGE_REF} inspectable"
        );
        assert_no_staged_files(component.images_dir());
    }

    fn run_valid_lifecycle(component: &ContainerImageComponent, archive: &Path) {
        let digest = sha256_file(&archive);
        let size = fs::metadata(&archive).unwrap().len();
        let manifest = std::env::var_os("SUMO_DOCKER_IMAGE_MANIFEST")
            .map(fs::read)
            .map(Result::unwrap)
            .unwrap_or_else(|| {
                pending_manifest(
                    CONTAINER_IMAGE_PAYLOAD_URI,
                    DEFAULT_CONTAINER_IMAGE_REF,
                    digest,
                    size,
                )
            });

        futures::executor::block_on(component.start_install()).unwrap();
        futures::executor::block_on(
            component.upload_envelope(&FlashId::new(""), bytes_stream(manifest)),
        )
        .unwrap();
        let payload = fs::read(&archive).unwrap();
        futures::executor::block_on(
            component.upload_envelope(&FlashId::new(""), bytes_stream(payload)),
        )
        .unwrap();

        futures::executor::block_on(component.finalize_install(&FlashId::new(""))).unwrap();
        futures::executor::block_on(component.commit_install(&FlashId::new(""))).unwrap();
    }

    fn valid_request_for(source: &Path, expected_ref: &str) -> ContainerImageImportRequest {
        ContainerImageImportRequest::new(
            source,
            sha256_file(source),
            fs::metadata(source).unwrap().len(),
            expected_ref,
        )
    }

    fn bytes_stream(data: Vec<u8>) -> machine_mgr::types::EnvelopeStream {
        Box::pin(futures::stream::once(async move {
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(bytes::Bytes::from(data))
        }))
    }

    fn pending_manifest(uri: &str, image: &str, digest: [u8; 32], size: u64) -> Vec<u8> {
        let digest_hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        format!(
            "SUIT-L2-DETACHED-PENDING\ncomponent=docker_image\nimage={image}\npayload_uri={uri}\npayload_digest=sha256:{digest_hex}\npayload_size={size}\ndigest_size_source=compressed-bytes\n"
        )
        .into_bytes()
    }

    fn sha256_file(path: &Path) -> [u8; 32] {
        let mut file = File::open(path).unwrap();
        let mut hasher = Sha256::new();
        let mut buf = [0u8; COPY_BUF_SIZE];
        loop {
            let n = file.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        hasher.finalize().into()
    }

    fn create_tar_gz(path: &Path, entry: Option<(&str, &[u8])>) {
        let parent = path.parent().unwrap();
        let tar_path = path.with_extension("tar");
        let mut command = Command::new("tar");
        command.arg("-cf").arg(&tar_path);
        match entry {
            Some((name, contents)) => {
                let entry_path = parent.join(name);
                fs::write(&entry_path, contents).unwrap();
                command.arg("-C").arg(parent).arg(name);
            }
            None => {
                command.arg("--files-from").arg(OsStr::new("/dev/null"));
            }
        }
        assert!(command.status().unwrap().success());

        let output = Command::new("gzip")
            .arg("-n")
            .arg("-c")
            .arg(&tar_path)
            .output()
            .unwrap();
        assert!(output.status.success());
        fs::write(path, output.stdout).unwrap();
    }

    fn assert_error_contains(err: MachineError, needle: &str) {
        assert!(
            err.to_string().contains(needle),
            "expected {needle} in {err}"
        );
    }

    fn assert_no_staged_files(dir: &Path) {
        if !dir.exists() {
            return;
        }
        let staged = fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                name.contains(".staged") || name.starts_with(".docker-image-upload-")
            })
            .count();
        assert_eq!(staged, 0);
    }

    fn upload_file_count(dir: &Path) -> usize {
        fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".docker-image-upload-")
            })
            .count()
    }

    fn docker_image_present(image_ref: &str) -> bool {
        Command::new("docker")
            .args(["image", "inspect", image_ref])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    struct DockerImageCleanup<'a> {
        image_ref: &'a str,
    }

    impl<'a> DockerImageCleanup<'a> {
        fn new(image_ref: &'a str) -> Self {
            let cleanup = Self { image_ref };
            cleanup.remove();
            cleanup
        }

        fn remove(&self) {
            let _ = Command::new("docker")
                .args(["image", "rm", "-f", self.image_ref])
                .output();
        }
    }

    impl Drop for DockerImageCleanup<'_> {
        fn drop(&mut self) {
            self.remove();
        }
    }
}
