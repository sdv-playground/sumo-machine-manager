use std::fs;
use std::path::PathBuf;

use machine_mgr::error::{MachineError, MachineResult};
use machine_mgr::types::EnvelopeStream;
use nv_store::types::Bank;

use futures::StreamExt;

pub struct InstallSession {
    target_bank: Bank,
    target_dir: PathBuf,
    payload: Option<Vec<u8>>,
}

impl InstallSession {
    pub fn new(target_bank: Bank, target_dir: PathBuf) -> Self {
        Self {
            target_bank,
            target_dir,
            payload: None,
        }
    }

    pub fn target_bank(&self) -> Bank {
        self.target_bank
    }

    /// Collect the envelope stream and store it for extraction.
    pub async fn upload(&mut self, mut stream: EnvelopeStream) -> MachineResult<String> {
        let mut buf = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| MachineError::Internal(format!("stream error: {e}")))?;
            buf.extend_from_slice(&chunk);
        }

        if buf.is_empty() {
            return Err(MachineError::InvalidArgument("empty payload".into()));
        }

        tracing::info!(
            size = buf.len(),
            bank = ?self.target_bank,
            "app: received install payload"
        );
        self.payload = Some(buf);
        Ok(format!("app-upload-{:?}", self.target_bank))
    }

    /// Validate the payload is a valid tar archive and extract to the target bank dir.
    pub fn validate_payload(self) -> MachineResult<()> {
        let payload = self
            .payload
            .ok_or_else(|| MachineError::InvalidArgument("no payload uploaded".into()))?;

        // Clean target directory
        if self.target_dir.exists() {
            fs::remove_dir_all(&self.target_dir)
                .map_err(|e| MachineError::Storage(format!("clean target dir: {e}")))?;
        }
        fs::create_dir_all(&self.target_dir)
            .map_err(|e| MachineError::Storage(format!("create target dir: {e}")))?;

        // Extract tar payload
        let cursor = std::io::Cursor::new(&payload);
        let mut archive = tar::Archive::new(cursor);
        archive
            .unpack(&self.target_dir)
            .map_err(|e| MachineError::ManifestInvalid(format!("tar extraction failed: {e}")))?;

        // Verify required file exists: the binary
        let has_binary = fs::read_dir(&self.target_dir)
            .map(|entries| {
                entries.filter_map(|e| e.ok()).any(|e| {
                    let name = e.file_name();
                    let name = name.to_string_lossy();
                    // Accept any executable-looking file that isn't config/start.sh
                    !name.ends_with(".yaml")
                        && !name.ends_with(".sh")
                        && !name.starts_with('.')
                        && e.path().is_file()
                })
            })
            .unwrap_or(false);

        if !has_binary {
            return Err(MachineError::ManifestInvalid(
                "tar payload must contain at least one binary".into(),
            ));
        }

        // Generate default start.sh if not present in archive
        let start_script = self.target_dir.join("start.sh");
        if !start_script.exists() {
            let content = generate_start_script();
            fs::write(&start_script, content)
                .map_err(|e| MachineError::Storage(format!("write start.sh: {e}")))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&start_script, fs::Permissions::from_mode(0o755));
            }
        }

        tracing::info!(dir = %self.target_dir.display(), "app: payload extracted");
        Ok(())
    }
}

fn generate_start_script() -> String {
    r#"#!/bin/sh
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/supernova" \
    --config "$SCRIPT_DIR/config.yaml" \
    "$@"
"#
    .to_string()
}
