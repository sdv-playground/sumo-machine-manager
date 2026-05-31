//! Outbound puller for FLEET-REPO-001 fleet repositories.
//!
//! Fetches signed manifests + content-addressable blobs over HTTPS.
//! Wire format is CBOR per `tasks/fleet-repo-contract.md` Q1
//! (resolved): the manifest signature is COSE_Sign1 over canonical
//! CBOR; serving JSON would break the signature path.  This crate
//! consumes CBOR only.
//!
//! ## Scope (F.D7)
//!
//! This is the building-block crate.  It exposes two operations:
//!
//! - [`Puller::fetch_manifest`] — pull a manifest by URI, run it
//!   through sumo-onboard's SUIT validator against the supplied
//!   trust anchors.  Returns the parsed manifest on success.
//! - [`Puller::fetch_blob`] — stream payload bytes by URI, hashing
//!   incrementally and rejecting on sha mismatch.  Supports
//!   `Range` resumption.
//!
//! Callers (future `sumo-onboard-agent` fleet-pull mode, the SOVDd
//! URL-referenced upload path, etc.) compose these primitives; the
//! puller doesn't drive update lifecycle by itself.
//!
//! TLS root pinning against `fleet-repo.pem` is the caller's
//! responsibility — pass a pre-configured [`reqwest::Client`] to
//! [`Puller::with_client`].  The default constructor uses the
//! system root store + sumo-mm conventions; tighten in production.

mod error;

use std::io::SeekFrom;
use std::path::Path;

use bytes::Bytes;
use futures::StreamExt;
use reqwest::Client;
use sha2::{Digest, Sha256};
use sumo_crypto::rustcrypto::RustCryptoBackend;
use sumo_onboard::manifest::Manifest;
use sumo_onboard::validator::Validator;
use tokio::fs::File;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tracing::{debug, instrument, warn};
use url::Url;

pub use error::{PullerError, PullerResult};

/// Validated manifest + the canonical CBOR bytes it parsed from.
///
/// Callers typically want the parsed `Manifest` for traversal, but
/// the original bytes are kept so that subsequent hash references
/// (e.g. `manifest_id: "sha256:<hex>"` in the fleet-repo index)
/// can be confirmed against what was actually consumed.
pub struct ValidatedManifest {
    pub manifest: Manifest,
    pub raw: Vec<u8>,
    pub sha256: [u8; 32],
}

impl std::fmt::Debug for ValidatedManifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatedManifest")
            .field("sha256", &hex::encode(self.sha256))
            .field("raw_bytes", &self.raw.len())
            .finish()
    }
}

/// FLEET-REPO-001 puller.
///
/// One instance per fleet repo (or per workshop appliance mirror) —
/// the base URL pins the origin.  Trust anchors come from the
/// device's policy partition (`sumo-sign-update.pem`) and are
/// long-lived; reconstruct the puller when policy rotates.
pub struct Puller {
    http: Client,
    base: Url,
    validator: Validator,
    crypto: RustCryptoBackend,
}

impl Puller {
    /// Construct with a fresh `reqwest::Client` using the system
    /// root store.  Suitable for dev / integration tests.
    ///
    /// For production, build a [`reqwest::Client`] with the
    /// `fleet-repo.pem` trust root pinned and pass it to
    /// [`Self::with_client`].
    /// `trust_anchor` is the CBOR encoding of a COSE_Key — the same
    /// format sumo-onboard's [`Validator`] expects.  This is what
    /// `sumo-sign-update.pem` produces after the X.509 → COSE_Key
    /// conversion in the device's policy partition tooling.
    ///
    /// Additional anchors can be pushed via [`Self::add_trust_anchor`]
    /// (e.g. during the workshop-appliance root rotation window).
    pub fn new(base_url: &str, trust_anchor: &[u8]) -> PullerResult<Self> {
        let http = Client::builder()
            .user_agent(concat!("sumo-puller/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| PullerError::Transport(format!("build client: {e}")))?;
        Self::with_client(base_url, trust_anchor, http)
    }

    pub fn with_client(base_url: &str, trust_anchor: &[u8], http: Client) -> PullerResult<Self> {
        let base = Url::parse(base_url)
            .map_err(|e| PullerError::Config(format!("bad base_url {base_url:?}: {e}")))?;
        let mut validator = Validator::new(trust_anchor, /* device_id = */ None);
        // The puller doesn't enforce anti-rollback here — that's the
        // job of the calling install pipeline which knows the
        // per-component security floor.  The validator's
        // sequence/timestamp gates are intentionally left wide open.
        // Sub-task: revisit when the puller composes with the
        // dispatcher (F.D8+).
        validator.set_min_sequence(0);
        Ok(Self {
            http,
            base,
            validator,
            crypto: RustCryptoBackend,
        })
    }

    /// Push an additional trust anchor (CBOR-encoded COSE_Key).
    /// Used during root rotation windows when both old and new
    /// anchors must be honoured.
    pub fn add_trust_anchor(&mut self, anchor_cbor: &[u8]) -> PullerResult<()> {
        self.validator
            .add_trust_anchor(anchor_cbor)
            .map_err(|e| PullerError::Config(format!("invalid trust anchor: {e:?}")))
    }

    fn resolve(&self, path_or_uri: &str) -> PullerResult<Url> {
        // Manifests reference blobs by URI relative to the repo's
        // base URL (FLEET-REPO-001 §6) — but absolute URIs are
        // permitted.  Try absolute first, fall back to base-relative.
        if let Ok(u) = Url::parse(path_or_uri) {
            if u.scheme() == "http" || u.scheme() == "https" {
                return Ok(u);
            }
        }
        self.base
            .join(path_or_uri)
            .map_err(|e| PullerError::Config(format!("bad uri {path_or_uri:?}: {e}")))
    }

    /// Fetch a manifest by URI and verify it against the configured
    /// trust anchors.  Returns the parsed manifest plus the canonical
    /// CBOR bytes it was decoded from.
    ///
    /// Validation runs sumo-onboard's full SUIT validator: digest +
    /// signature + sequence + (optional) timestamp + device-identity
    /// conditions.  Failures are surfaced as [`PullerError::Validation`].
    #[instrument(skip(self), fields(uri = %manifest_uri))]
    pub async fn fetch_manifest(&self, manifest_uri: &str) -> PullerResult<ValidatedManifest> {
        let url = self.resolve(manifest_uri)?;
        let resp = self
            .http
            .get(url.clone())
            .header(
                reqwest::header::ACCEPT,
                "application/vnd.sumo.manifest+cbor",
            )
            .send()
            .await
            .map_err(|e| PullerError::Transport(format!("GET {url}: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(PullerError::Http {
                url: url.to_string(),
                status: status.as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| PullerError::Transport(format!("read manifest body: {e}")))?
            .to_vec();
        let sha256 = sha256_bytes(&bytes);

        let manifest = self
            .validator
            .validate_envelope(&bytes, &self.crypto, /* trusted_time = */ 0)
            .map_err(|e| PullerError::Validation(format!("{e:?}")))?;

        debug!(
            sha256 = %hex::encode(sha256),
            bytes = bytes.len(),
            "manifest validated",
        );
        Ok(ValidatedManifest {
            manifest,
            raw: bytes,
            sha256,
        })
    }

    /// Stream a blob to `dst_path`, hashing as it goes and rejecting
    /// on sha256 mismatch.  Supports `Range` resumption — if the
    /// destination already has bytes, the puller asks for the suffix
    /// and continues; if the server doesn't honour `Range`, restart
    /// from scratch.
    ///
    /// The destination file is left in a deterministic state:
    ///
    /// - On success: the file's contents are exactly the verified
    ///   payload bytes, length `expected_size`.
    /// - On hash mismatch / size mismatch: the file is truncated to
    ///   zero before returning the error, so a retry doesn't append
    ///   garbage to the partial.
    /// - On transient transport error mid-stream: the partial bytes
    ///   are kept; the caller can retry with the same args and the
    ///   puller will resume.
    #[instrument(skip(self, dst_path), fields(uri = %blob_uri, sha = %hex::encode(expected_sha256)))]
    pub async fn fetch_blob(
        &self,
        blob_uri: &str,
        expected_sha256: [u8; 32],
        expected_size: u64,
        dst_path: &Path,
    ) -> PullerResult<()> {
        let url = self.resolve(blob_uri)?;

        let mut file = open_for_resume(dst_path).await?;
        let resume_offset = file
            .metadata()
            .await
            .map_err(|e| PullerError::Io(format!("stat partial: {e}")))?
            .len();

        if resume_offset > expected_size {
            warn!(
                resume = resume_offset,
                expected = expected_size,
                "partial larger than expected; truncating and restarting"
            );
            file.set_len(0)
                .await
                .map_err(|e| PullerError::Io(format!("truncate over-grown partial: {e}")))?;
            file.seek(SeekFrom::Start(0))
                .await
                .map_err(|e| PullerError::Io(format!("seek to 0: {e}")))?;
        } else {
            file.seek(SeekFrom::Start(resume_offset))
                .await
                .map_err(|e| PullerError::Io(format!("seek to resume offset: {e}")))?;
        }

        let resume_offset = file
            .metadata()
            .await
            .map_err(|e| PullerError::Io(format!("stat after seek: {e}")))?
            .len();

        // Re-hash the bytes already on disk so the final sha covers
        // the full payload regardless of where we resumed.
        let mut hasher = Sha256::new();
        if resume_offset > 0 {
            use tokio::io::AsyncReadExt;
            let mut prefix = File::open(dst_path)
                .await
                .map_err(|e| PullerError::Io(format!("reopen for prefix hash: {e}")))?;
            let mut buf = [0u8; 64 * 1024];
            let mut remaining = resume_offset;
            while remaining > 0 {
                let n = prefix
                    .read(&mut buf)
                    .await
                    .map_err(|e| PullerError::Io(format!("read prefix: {e}")))?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                remaining = remaining.saturating_sub(n as u64);
            }
        }

        let mut req = self.http.get(url.clone());
        if resume_offset > 0 {
            req = req.header(reqwest::header::RANGE, format!("bytes={resume_offset}-"));
        }
        let resp = req
            .send()
            .await
            .map_err(|e| PullerError::Transport(format!("GET {url}: {e}")))?;

        let status = resp.status();
        // 206 Partial Content is what we want for a resumed download;
        // 200 means the server ignored Range and is starting over.
        let server_resumed = status == reqwest::StatusCode::PARTIAL_CONTENT;
        if status == reqwest::StatusCode::OK && resume_offset > 0 {
            warn!("server returned 200 instead of 206; restarting download from scratch");
            file.set_len(0)
                .await
                .map_err(|e| PullerError::Io(format!("truncate for restart: {e}")))?;
            file.seek(SeekFrom::Start(0))
                .await
                .map_err(|e| PullerError::Io(format!("seek to 0 for restart: {e}")))?;
            hasher = Sha256::new();
        } else if !status.is_success() {
            return Err(PullerError::Http {
                url: url.to_string(),
                status: status.as_u16(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        let starting_offset = if server_resumed { resume_offset } else { 0 };
        let mut written = starting_offset;

        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk: Bytes =
                chunk.map_err(|e| PullerError::Transport(format!("stream chunk: {e}")))?;
            hasher.update(&chunk);
            file.write_all(&chunk)
                .await
                .map_err(|e| PullerError::Io(format!("write chunk: {e}")))?;
            written += chunk.len() as u64;
        }

        file.flush()
            .await
            .map_err(|e| PullerError::Io(format!("flush: {e}")))?;

        if written != expected_size {
            file.set_len(0)
                .await
                .map_err(|e| PullerError::Io(format!("truncate on size mismatch: {e}")))?;
            return Err(PullerError::SizeMismatch {
                expected: expected_size,
                actual: written,
            });
        }

        let actual: [u8; 32] = hasher.finalize().into();
        if actual != expected_sha256 {
            file.set_len(0)
                .await
                .map_err(|e| PullerError::Io(format!("truncate on hash mismatch: {e}")))?;
            return Err(PullerError::HashMismatch {
                expected: expected_sha256,
                actual,
            });
        }

        Ok(())
    }
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

async fn open_for_resume(path: &Path) -> PullerResult<File> {
    tokio::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .await
        .map_err(|e| PullerError::Io(format!("open {path:?}: {e}")))
}
