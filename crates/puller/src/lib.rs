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

    /// Size of a blob via a `HEAD` request — the ciphertext (outer) byte
    /// count needed to drive [`Self::fetch_blob`], which the SUIT manifest
    /// does not carry (its `image_size` is the plaintext size). The value is
    /// untrusted-but-harmless: a lying `Content-Length` fails `fetch_blob`'s
    /// size/sha checks anyway.
    #[instrument(skip(self), fields(uri = %blob_uri))]
    pub async fn blob_size(&self, blob_uri: &str) -> PullerResult<u64> {
        let url = self.resolve(blob_uri)?;
        let resp = self
            .http
            .head(url.clone())
            .send()
            .await
            .map_err(|e| PullerError::Transport(format!("HEAD {url}: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(PullerError::Http {
                url: url.to_string(),
                status: status.as_u16(),
                body: String::new(),
            });
        }
        resp.headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or_else(|| PullerError::Transport(format!("HEAD {url}: no Content-Length")))
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

/// Extract the sha256 **content-address** from a content-addressed blob URI.
///
/// The fetched OUTER integrity is anchored by content-addressing: the blob's
/// sha256 IS its address, and that address rides inside the (T2-signed) SUIT
/// manifest's `uri` parameter — so the digest the device verifies against is
/// itself signed. This recognises:
/// - the FLEET-REPO-001 `sha256:<hex>` scheme, and
/// - a content-addressed path/URL whose terminal segment is the 64-char hex
///   digest (e.g. `blobs/<hex>`, `https://repo/cas/<hex>`, `.../sha256:<hex>`).
///
/// Returns `None` when the URI carries no parseable content-address. Callers
/// MUST treat that as a hard reject for a remote fetch — without the address
/// the outer bytes can't be verified (secure-by-default; no silent trust of an
/// unverifiable CDN URL).
pub fn content_address_sha256(uri: &str) -> Option<[u8; 32]> {
    // Drop any query / fragment before looking for the digest.
    let path = uri.split(['?', '#']).next().unwrap_or(uri);
    // Whole-URI `sha256:<hex>` scheme, else the terminal path segment, then
    // tolerate a `sha256:` prefix on that segment too.
    let candidate = path
        .strip_prefix("sha256:")
        .unwrap_or_else(|| path.rsplit('/').next().unwrap_or(path));
    let candidate = candidate.strip_prefix("sha256:").unwrap_or(candidate);
    decode_hex32(candidate)
}

/// Map a content-addressed URI onto the path it is fetched from.
///
/// A bare `sha256:<hex>` scheme names content but is not directly fetchable —
/// [`Puller::resolve`] would treat it as an absolute non-http URL. The
/// FLEET-REPO-001 / repo convention stores blobs at `blobs/<hex>`, so map the
/// scheme onto that path. Every other URI (relative path, absolute http(s))
/// passes through untouched.
pub fn cas_fetch_path(uri: &str) -> String {
    match uri.strip_prefix("sha256:") {
        Some(hex) if decode_hex32(hex).is_some() => format!("blobs/{hex}"),
        _ => uri.to_string(),
    }
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
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

#[cfg(test)]
mod content_address_tests {
    use super::content_address_sha256;

    // 16 bytes 00,11,22,…,ff repeated → 32 bytes, as 64 hex chars.
    const HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn expected() -> [u8; 32] {
        let mut e = [0u8; 32];
        for i in 0..16u8 {
            e[i as usize] = i.wrapping_mul(0x11);
            e[i as usize + 16] = i.wrapping_mul(0x11);
        }
        e
    }

    #[test]
    fn parses_sha256_scheme() {
        assert_eq!(
            content_address_sha256(&format!("sha256:{HEX}")),
            Some(expected())
        );
    }

    #[test]
    fn parses_content_addressed_path_or_url() {
        for uri in [
            format!("blobs/{HEX}"),
            format!("https://repo/cas/{HEX}"),
            format!("https://repo/cas/sha256:{HEX}"),
        ] {
            assert_eq!(content_address_sha256(&uri), Some(expected()), "uri={uri}");
        }
    }

    #[test]
    fn strips_query_and_fragment() {
        assert_eq!(
            content_address_sha256(&format!("https://repo/cas/{HEX}?token=abc")),
            Some(expected())
        );
        assert_eq!(
            content_address_sha256(&format!("https://repo/cas/{HEX}#frag")),
            Some(expected())
        );
    }

    #[test]
    fn rejects_non_content_addressed() {
        // No digest at all, too-short, empty, and 64 non-hex chars.
        assert_eq!(content_address_sha256("https://repo/firmware.bin"), None);
        assert_eq!(content_address_sha256("blobs/deadbeef"), None);
        assert_eq!(content_address_sha256(""), None);
        assert_eq!(content_address_sha256(&"z".repeat(64)), None);
    }

    #[test]
    fn cas_fetch_path_maps_sha256_scheme_to_blob_path() {
        use super::cas_fetch_path;
        assert_eq!(
            cas_fetch_path(&format!("sha256:{HEX}")),
            format!("blobs/{HEX}")
        );
        // Already-fetchable forms pass through untouched.
        assert_eq!(
            cas_fetch_path(&format!("blobs/{HEX}")),
            format!("blobs/{HEX}")
        );
        assert_eq!(
            cas_fetch_path(&format!("https://repo/cas/{HEX}")),
            format!("https://repo/cas/{HEX}")
        );
        // A malformed digest is not a content-address; leave it alone rather
        // than inventing a blob path for it.
        assert_eq!(cas_fetch_path("sha256:deadbeef"), "sha256:deadbeef");
    }
}
