//! Streaming SUIT envelope processor.
//!
//! Parses a SUIT envelope from a byte stream, validates the small header
//! (auth wrapper + manifest), then streams the "#firmware" payload through
//! decrypt → decompress → hash → write-to-disk without buffering the full payload.

use std::io::{self, Read, Write as IoWrite};
use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use futures::StreamExt;
use hsm::ivd::IvdFile;
use nv_store::types::{Bank, BankSet};
use sha2::{Digest, Sha256};
use sumo_crypto::RustCryptoBackend;
use sumo_onboard::decryptor::StreamingDecryptor;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_util::io::StreamReader;

use crate::bank_spec::payload_target_name_for_id;
use crate::manifest_provider::{ManifestProvider, ManifestType, ValidatedFirmware};

use machine_mgr::bank_provider::BankProvider;

use sovd_core::{BackendError, PackageStream};

use puller::{content_address_sha256, Puller};

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// Maximum envelope size we'll buffer for non-firmware manifests (e.g. HSM keys).
const HSM_ENVELOPE_MAX: u64 = 100 * 1024;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Process a SUIT envelope from a streaming source.
///
/// 1. Parse CBOR envelope header (auth + manifest, ~1KB)
/// 2. Validate signature, digest, anti-rollback
/// 3. Stream "#firmware" payload through decrypt → decompress → hash → file write
///
/// Returns (package_id_hint, validated_firmware) where image_data is empty
/// (firmware was written directly to disk).
pub async fn process_envelope_stream(
    stream: PackageStream,
    manifest_provider: &dyn ManifestProvider,
    min_security_ver: u32,
    bank_provider: Option<&dyn BankProvider>,
    bank_set: BankSet,
    target_bank: Bank,
) -> Result<ValidatedFirmware, BackendError> {
    // Convert PackageStream → AsyncRead
    let reader = StreamReader::new(stream.map(|r| r.map_err(io::Error::other)));
    tokio::pin!(reader);

    // Step 1: Parse CBOR envelope header, collect pending payloads
    let (header_bytes, pending_payloads, map_entry_count) =
        parse_envelope_header(&mut reader).await?;

    // Step 2: Validate using header-only envelope (no payload)
    let mut validated =
        validate_header(manifest_provider, &header_bytes, min_security_ver, bank_set)?;

    // HSM key manifests: small enough to buffer entirely, pass raw to HSM provider.
    if validated.manifest_type == ManifestType::HsmKeys {
        if pending_payloads.is_empty() {
            // Already fully buffered (no integrated payloads)
            return manifest_provider
                .validate(&header_bytes, min_security_ver)
                .map_err(|e| BackendError::InvalidRequest(format!("manifest validation: {e}")));
        }
        // Read the single payload and reconstruct full envelope
        let pp = &pending_payloads[0];
        if pp.len > HSM_ENVELOPE_MAX {
            return Err(BackendError::InvalidRequest(format!(
                "HSM key envelope too large: {} bytes (max {HSM_ENVELOPE_MAX})",
                pp.len
            )));
        }
        let mut payload = vec![0u8; pp.len as usize];
        reader.read_exact(&mut payload).await.map_err(map_io)?;
        let raw_envelope = rebuild_envelope_with_payload(&header_bytes, map_entry_count, &payload)?;
        return manifest_provider
            .validate(&raw_envelope, min_security_ver)
            .map_err(|e| BackendError::InvalidRequest(format!("manifest validation: {e}")));
    }

    // If no payloads (CRL or administrative-disable manifest), detect a
    // `suit-directive-disable` from the header so the caller can enact it via
    // the component's `Deactivator`, then return early. A genuine CRL/policy
    // manifest carries no such directive → `disable_target` stays None → the
    // caller no-ops exactly as before.
    if pending_payloads.is_empty() {
        let envelope = sumo_codec::decode::decode_envelope(&header_bytes)
            .map_err(|_| BackendError::Internal("failed to re-parse envelope header".into()))?;
        let manifest = sumo_onboard::manifest::Manifest { envelope };
        validated.disable_target = manifest.disable_target();
        return Ok(validated);
    }

    // Parse manifest to get per-component encryption info and digests
    let envelope = sumo_codec::decode::decode_envelope(&header_bytes)
        .map_err(|_| BackendError::Internal("failed to re-parse envelope header".into()))?;
    let manifest = sumo_onboard::manifest::Manifest { envelope };

    // Set up decryptor keys (shared across all components)
    let suit_trust_anchor = manifest_provider.software_authority_key().ok_or_else(|| {
        BackendError::Internal(
            "no software authority key for streaming — HSM not yet provisioned".into(),
        )
    })?;
    // CEK unwrap is delegated to the HSM via the KeyUnwrap trait —
    // no raw device-key bytes flow through this pipeline anymore.
    let suit_key_unwrap = manifest_provider.key_unwrap_for_decryption();

    // Map payload keys to component indices by matching URIs in the manifest
    let component_count = manifest.component_count();

    // Step 3: Process each integrated payload sequentially
    let mut last_image_size = 0usize;
    let mut last_image_hash = [0u8; 32];
    let mut streamed_files: Vec<IvdFile> = Vec::with_capacity(pending_payloads.len());

    for pp in &pending_payloads {
        // Find which component this payload belongs to (match by URI)
        let comp_idx = (0..component_count)
            .find(|&i| manifest.uri(i).map(|u| u == pp.key).unwrap_or(false))
            .unwrap_or(0);

        let expected_digest = manifest
            .image_digest(comp_idx)
            .map(|d| d.0.bytes.clone())
            .ok_or_else(|| {
                BackendError::Internal(format!(
                    "no digest for component {} (payload {})",
                    comp_idx, pp.key
                ))
            })?;

        let has_encryption = manifest.encryption_info(comp_idx).is_some();

        // Name from the component-id part, not the (possibly content-address)
        // payload key — see `payload_target_name_for_id`.
        let target_name = payload_target_name_for_id(manifest.component_id(comp_idx));

        // Open the payload sink through the bank provider — it owns where the
        // bytes land (a file in the target bank dir for IVD, a raw-partition
        // region for other kinds). `None` provider = in-memory / no-images-dir
        // path: hash-only, no write. The writer is a sync `BufWriter`; it's
        // moved into the blocking pipeline below and flushed there.
        let writer =
            match bank_provider {
                Some(bp) => Some(bp.open_payload_writer(target_bank, &target_name).map_err(
                    |e| BackendError::Internal(format!("open payload sink {target_name}: {e}")),
                )?),
                None => None,
            };

        tracing::info!(
            payload_key = %pp.key,
            component = comp_idx,
            size = pp.len,
            target = %target_name,
            "streaming component payload"
        );

        // Build the async→sync processing pipeline
        let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(32);

        let header_for_decrypt = header_bytes.clone();
        let trust_anchor = suit_trust_anchor.clone();
        let key_unwrap = suit_key_unwrap.clone();
        let expected_digest_clone = expected_digest.clone();

        let process_handle = tokio::task::spawn_blocking(move || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                process_payload_sync(
                    rx,
                    &header_for_decrypt,
                    has_encryption,
                    comp_idx,
                    &trust_anchor,
                    key_unwrap.as_deref(),
                    &expected_digest_clone,
                    writer,
                )
            }))
            .unwrap_or_else(|panic| {
                let msg = panic
                    .downcast_ref::<String>()
                    .map(|s| s.as_str())
                    .or_else(|| panic.downcast_ref::<&str>().copied())
                    .unwrap_or("unknown panic");
                Err(format!("panic in payload processing: {msg}"))
            })
        });

        // Stream this payload's bytes to the processing thread
        let mut remaining = pp.len as usize;
        let mut buf = vec![0u8; 64 * 1024];
        let mut send_failed = false;

        while remaining > 0 {
            let to_read = buf.len().min(remaining);
            let n = reader.read(&mut buf[..to_read]).await.map_err(|e| {
                BackendError::Internal(format!("stream read error ({}): {e}", pp.key))
            })?;
            if n == 0 {
                break;
            }
            remaining -= n;
            if tx.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                send_failed = true;
                break;
            }
        }
        drop(tx);

        let (image_size, image_hash) = match process_handle.await {
            Ok(Ok(result)) => {
                if send_failed {
                    return Err(BackendError::Internal(format!(
                        "payload stream {} ended early",
                        pp.key
                    )));
                }
                result
            }
            Ok(Err(e)) => {
                return Err(BackendError::Internal(format!(
                    "payload processing failed ({}): {e}",
                    pp.key
                )));
            }
            Err(e) => {
                return Err(BackendError::Internal(format!(
                    "payload processing panicked ({}): {e}",
                    pp.key
                )));
            }
        };

        tracing::info!(
            payload_key = %pp.key,
            image_size,
            "component payload written to disk"
        );

        streamed_files.push(IvdFile {
            relative_path: target_name,
            sha256: image_hash.to_vec(),
            size: image_size as u64,
        });

        last_image_size = image_size;
        last_image_hash = image_hash;
    }

    tracing::info!(
        components = pending_payloads.len(),
        "all components written to disk"
    );

    Ok(ValidatedFirmware {
        bank_set: validated.bank_set,
        manifest_type: validated.manifest_type,
        image_meta: validated.image_meta,
        image_data: Vec::new(),
        version_display: validated.version_display,
        image_sha256: Some(last_image_hash),
        image_size: Some(last_image_size as u64),
        raw_envelope: None,
        streamed_files,
        // Carry the verified manifest's signing time through the streaming path.
        signing_time_secs: validated.signing_time_secs,
        // This is the payload (firmware-install) return; a disable manifest has
        // no payload and returns from the early branch above.
        disable_target: None,
    })
}

// ---------------------------------------------------------------------------
// CBOR envelope header parser
// ---------------------------------------------------------------------------

/// An integrated payload pending in the stream (not yet read).
struct PendingPayload {
    /// Payload key (e.g., "#firmware", "#kernel").
    key: String,
    /// Payload length in bytes.
    len: u64,
}

/// Parse the SUIT envelope CBOR from an async reader.
///
/// Reads the envelope as a CBOR map entry by entry. Non-payload entries
/// (integer-keyed: auth, manifest, severable) are collected as ciborium
/// Values. Text-keyed entries (integrated payloads) are NOT buffered —
/// their key and length are returned so the caller can stream each one.
///
/// Returns (header_bytes, pending_payloads, original_map_entry_count).
async fn parse_envelope_header<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<(Vec<u8>, Vec<PendingPayload>, u64), BackendError> {
    // Buffer enough to read the outer CBOR structure. We read entry by entry:
    // for non-payload entries, we buffer the raw bytes into a growing vec and
    // use ciborium to decode each entry. For payload entries, we just record
    // the key and length.
    //
    // Strategy: accumulate all bytes into a buffer. When we encounter a text
    // key (payload), note the position and skip reading its value bytes.
    // After all entries, the buffer contains a valid CBOR map minus payloads.

    // Read all bytes for non-payload map entries into this buffer.
    // We'll also track which entries are payloads vs non-payload.
    let mut all_bytes = Vec::new();
    let mut pending_payloads = Vec::new();

    // Read until we have the map header
    let initial = read_byte(reader).await?;
    all_bytes.push(initial);
    let (major, additional) = (initial >> 5, initial & 0x1f);

    // Handle optional Tag(107) wrapper
    let map_entry_count;
    if major == 6 {
        let _tag_val = read_cbor_uint(reader, additional, &mut all_bytes).await?;
        let map_byte = read_byte(reader).await?;
        all_bytes.push(map_byte);
        let (m, a) = (map_byte >> 5, map_byte & 0x1f);
        if m != 5 {
            return Err(BackendError::Internal(
                "expected CBOR map in envelope".into(),
            ));
        }
        map_entry_count = read_cbor_uint(reader, a, &mut all_bytes).await?;
    } else if major == 5 {
        map_entry_count = read_cbor_uint(reader, additional, &mut all_bytes).await?;
    } else {
        return Err(BackendError::Internal(format!(
            "expected CBOR map or tag, got major type {major}"
        )));
    }

    // Read each map entry
    for _ in 0..map_entry_count {
        // Peek at the key to determine if this is a payload entry
        let key_byte = read_byte(reader).await?;
        let (key_major, _key_add) = (key_byte >> 5, key_byte & 0x1f);

        if key_major == 3 {
            // Text key — this is an integrated payload. Read key name,
            // read payload length, but DON'T read payload bytes.
            let mut temp = vec![key_byte];
            let key_len = read_cbor_uint(reader, _key_add, &mut temp).await?;
            let mut key_str = vec![0u8; key_len as usize];
            reader.read_exact(&mut key_str).await.map_err(map_io)?;
            let key_name = String::from_utf8_lossy(&key_str).to_string();

            let val_byte = read_byte(reader).await?;
            let (val_major, val_add) = (val_byte >> 5, val_byte & 0x1f);
            if val_major != 2 {
                return Err(BackendError::Internal(format!(
                    "expected byte string for {key_name} payload"
                )));
            }
            let mut temp2 = Vec::new();
            let payload_len = read_cbor_uint(reader, val_add, &mut temp2).await?;

            pending_payloads.push(PendingPayload {
                key: key_name,
                len: payload_len,
            });
            // Payload data stays in the stream for the caller to read.
        } else {
            // Non-payload entry — buffer the key + value raw bytes.
            // We need to read the complete CBOR item (key + value).
            all_bytes.push(key_byte);
            read_cbor_key_rest(reader, key_major, _key_add, &mut all_bytes).await?;
            // Now read the value
            let val_byte = read_byte(reader).await?;
            all_bytes.push(val_byte);
            let (val_major, val_add) = (val_byte >> 5, val_byte & 0x1f);
            read_cbor_value_rest(reader, val_major, val_add, &mut all_bytes).await?;
        }
    }

    // Rebuild: the buffer has the wrong map count (original N, but only N-P entries).
    // Rewrite the map header with the correct count.
    let non_payload_count = map_entry_count - pending_payloads.len() as u64;
    let header_bytes = if pending_payloads.is_empty() {
        all_bytes
    } else {
        rewrite_map_count(&all_bytes, non_payload_count)?
    };

    Ok((header_bytes, pending_payloads, map_entry_count))
}

/// Read a CBOR key's additional bytes (the key initial byte is already in buf).
/// SUIT envelope keys are integers (positive/negative) or byte strings.
async fn read_cbor_key_rest<R: AsyncRead + Unpin>(
    reader: &mut R,
    major: u8,
    additional: u8,
    buf: &mut Vec<u8>,
) -> Result<(), BackendError> {
    match major {
        0 | 1 => {
            let _val = read_cbor_uint(reader, additional, buf).await?;
        }
        2 => {
            // Byte string key (digest refs in severable)
            let len = read_cbor_uint(reader, additional, buf).await?;
            let mut data = vec![0u8; len as usize];
            reader.read_exact(&mut data).await.map_err(map_io)?;
            buf.extend_from_slice(&data);
        }
        6 => {
            // Tag wrapping a key — read tag value, then inner key
            let _tag = read_cbor_uint(reader, additional, buf).await?;
            let inner = read_byte(reader).await?;
            buf.push(inner);
            let (im, ia) = (inner >> 5, inner & 0x1f);
            // Inner key is an integer
            if im == 0 || im == 1 {
                let _val = read_cbor_uint(reader, ia, buf).await?;
            }
        }
        _ => {
            return Err(BackendError::Internal(format!(
                "unexpected CBOR key major type {major}"
            )));
        }
    }
    Ok(())
}

/// Read a CBOR value completely into buf (the value initial byte is already in buf).
/// SUIT envelope values at the top level are always bstr.
async fn read_cbor_value_rest<R: AsyncRead + Unpin>(
    reader: &mut R,
    major: u8,
    additional: u8,
    buf: &mut Vec<u8>,
) -> Result<(), BackendError> {
    let len = read_cbor_uint(reader, additional, buf).await?;
    if major == 2 || major == 3 {
        // Byte/text string — read len bytes
        let mut data = vec![0u8; len as usize];
        reader.read_exact(&mut data).await.map_err(map_io)?;
        buf.extend_from_slice(&data);
    }
    // For other types (arrays/maps at top level of envelope), the length
    // encoding suffices since we buffered it. The actual content follows
    // but SUIT envelope values are always bstr at the top level.
    Ok(())
}

/// Rewrite the CBOR map header to have the given entry count.
/// The body bytes stay the same — only the count in the map header changes.
fn rewrite_map_count(raw: &[u8], new_count: u64) -> Result<Vec<u8>, BackendError> {
    let mut result = Vec::with_capacity(raw.len());

    let mut pos = 0;
    let first = raw[pos];
    let (major, additional) = (first >> 5, first & 0x1f);
    pos += 1;

    if major == 6 {
        // Tag — copy tag header
        result.push(first);
        let (_tag_val, bytes_consumed) = decode_cbor_uint(additional, &raw[pos..]);
        result.extend_from_slice(&raw[pos..pos + bytes_consumed]);
        pos += bytes_consumed;

        // Now the map header
        let map_byte = raw[pos];
        pos += 1;
        let (_, map_add) = (map_byte >> 5, map_byte & 0x1f);
        let (_, map_bytes_consumed) = decode_cbor_uint(map_add, &raw[pos..]);
        pos += map_bytes_consumed;

        // Write new map header
        encode_cbor_uint(5, new_count, &mut result);
    } else if major == 5 {
        // Map — skip original count
        let (_, bytes_consumed) = decode_cbor_uint(additional, &raw[pos..]);
        pos += bytes_consumed;

        // Write new map header
        encode_cbor_uint(5, new_count, &mut result);
    } else {
        return Err(BackendError::Internal("unexpected header structure".into()));
    }

    // Copy remaining entries as-is
    result.extend_from_slice(&raw[pos..]);
    Ok(result)
}

/// Reconstruct a full SUIT envelope from the stripped header + payload.
///
/// `header_without_firmware` has map count = original - 1 and no #firmware entry.
/// This restores the original count and appends `#firmware: bstr(payload)`.
fn rebuild_envelope_with_payload(
    header_without_firmware: &[u8],
    original_count: u64,
    payload: &[u8],
) -> Result<Vec<u8>, BackendError> {
    let mut result = Vec::with_capacity(header_without_firmware.len() + payload.len() + 32);

    let mut pos = 0;
    let first = header_without_firmware[pos];
    let (major, additional) = (first >> 5, first & 0x1f);
    pos += 1;

    if major == 6 {
        // Tag — copy tag header
        result.push(first);
        let (_tag_val, bytes_consumed) =
            decode_cbor_uint(additional, &header_without_firmware[pos..]);
        result.extend_from_slice(&header_without_firmware[pos..pos + bytes_consumed]);
        pos += bytes_consumed;

        // Skip the (N-1) map header
        let map_byte = header_without_firmware[pos];
        pos += 1;
        let (_, map_add) = (map_byte >> 5, map_byte & 0x1f);
        let (_, map_bytes_consumed) = decode_cbor_uint(map_add, &header_without_firmware[pos..]);
        pos += map_bytes_consumed;

        // Write restored map header with original count
        encode_cbor_uint(5, original_count, &mut result);
    } else if major == 5 {
        // Skip the (N-1) map count
        let (_, bytes_consumed) = decode_cbor_uint(additional, &header_without_firmware[pos..]);
        pos += bytes_consumed;

        encode_cbor_uint(5, original_count, &mut result);
    } else {
        return Err(BackendError::Internal("unexpected header structure".into()));
    }

    // Copy existing map entries
    result.extend_from_slice(&header_without_firmware[pos..]);

    // Append "#firmware": bstr(payload)
    let key = b"#firmware";
    encode_cbor_uint(3, key.len() as u64, &mut result); // text string key
    result.extend_from_slice(key);
    encode_cbor_uint(2, payload.len() as u64, &mut result); // byte string value
    result.extend_from_slice(payload);

    Ok(result)
}

// ---------------------------------------------------------------------------
// Sync payload processing pipeline
// ---------------------------------------------------------------------------

/// Process the firmware payload synchronously: decrypt → decompress → hash →
/// write to the bank-provider-opened `writer`.
///
/// Runs in a blocking thread. `writer` is the provider's payload sink (already
/// opened by the caller, e.g. via `open_payload_writer`), or `None` for
/// in-memory / no-images-dir paths that still verify the hash. Returns
/// (total_image_size, image_sha256).
#[allow(clippy::too_many_arguments)]
fn process_payload_sync(
    rx: tokio::sync::mpsc::Receiver<Bytes>,
    header_bytes: &[u8],
    has_encryption: bool,
    component_index: usize,
    _trust_anchor: &[u8],
    key_unwrap: Option<&(dyn sumo_onboard::decryptor::KeyUnwrap + Send + Sync)>,
    expected_digest: &[u8],
    writer: Option<Box<dyn IoWrite + Send>>,
) -> Result<(usize, [u8; 32]), String> {
    let crypto = RustCryptoBackend::new();

    let mut channel_reader = ChannelReader {
        rx,
        current: Bytes::new(),
    };

    if has_encryption {
        // Parse envelope to get manifest for decryptor setup
        let envelope = sumo_codec::decode::decode_envelope(header_bytes)
            .map_err(|e| format!("re-parse envelope: {e:?}"))?;
        let manifest = sumo_onboard::manifest::Manifest { envelope };

        let unwrap =
            key_unwrap.ok_or("encrypted payload but no CEK unwrapper (HSM not provisioned?)")?;

        let decryptor = StreamingDecryptor::new(&manifest, component_index, unwrap, &crypto)
            .map_err(|e| format!("decryptor setup: {e:?}"))?;

        let mut decrypt_reader = DecryptReader::new(channel_reader, decryptor);

        // Read first chunk to detect zstd
        let mut first_buf = [0u8; 4];
        let first_n = read_exact_or_eof(&mut decrypt_reader, &mut first_buf)?;

        if first_n >= 4 && first_buf[..4] == ZSTD_MAGIC {
            // Encrypted + compressed: chain through zstd (libzstd)
            let prefixed = PrefixReader::new(&first_buf[..first_n], decrypt_reader);
            process_decompressed(prefixed, expected_digest, writer)
        } else {
            // Encrypted, not compressed: hash + write directly
            let prefixed = PrefixReader::new(&first_buf[..first_n], decrypt_reader);
            process_plain(prefixed, expected_digest, writer)
        }
    } else {
        // Unencrypted — read first bytes to check for zstd
        let mut first_buf = [0u8; 4];
        let first_n = read_exact_or_eof(&mut channel_reader, &mut first_buf)?;

        if first_n >= 4 && first_buf[..4] == ZSTD_MAGIC {
            let prefixed = PrefixReader::new(&first_buf[..first_n], channel_reader);
            process_decompressed(prefixed, expected_digest, writer)
        } else {
            let prefixed = PrefixReader::new(&first_buf[..first_n], channel_reader);
            process_plain(prefixed, expected_digest, writer)
        }
    }
}

/// Process a plain (uncompressed) stream: hash + write to the provider's sink.
///
/// `writer` is the bank-provider-opened payload sink (a `BufWriter`); `None`
/// for in-memory / no-images-dir paths that still verify the hash. Flushed
/// before returning so the BufWriter's tail reaches the sink.
fn process_plain<R: Read>(
    mut reader: R,
    expected_digest: &[u8],
    mut writer: Option<Box<dyn IoWrite + Send>>,
) -> Result<(usize, [u8; 32]), String> {
    let mut hasher = Sha256::new();
    let mut total = 0usize;
    let mut buf = vec![0u8; 64 * 1024];

    loop {
        let n = reader.read(&mut buf).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        if let Some(ref mut w) = writer {
            w.write_all(&buf[..n]).map_err(|e| format!("write: {e}"))?;
        }
        total += n;
    }

    if let Some(ref mut w) = writer {
        w.flush().map_err(|e| format!("flush: {e}"))?;
    }

    let hash = verify_digest(hasher, expected_digest)?;
    Ok((total, hash))
}

/// SHA-256 a reader in bounded 64 KiB chunks — the same streaming idiom as
/// [`process_plain`], factored out for the hash-only callers (bank verify) that
/// must NOT slurp a whole image into RAM. Returns `(bytes_read, digest)`; the
/// caller compares the digest. O(64 KiB) resident regardless of file size — the
/// whole point (a `std::fs::read` of a multi-hundred-MB rootfs OOMs a
/// memory-pressured CVC; this doesn't). Errors are read errors, stringified.
pub(crate) fn hash_reader<R: Read>(mut reader: R) -> Result<(u64, [u8; 32]), String> {
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((total, hasher.finalize().into()))
}

/// Accumulates time + bytes spent in an inner reader. Lets the upload pipeline
/// split decrypt vs decompress: the zstd decoder reads *through* this shim, so
/// the time recorded here is the decrypt/channel cost, and the decoder's own
/// read time minus this is the pure decompress cost. Bytes counted are the
/// compressed (post-decrypt) bytes the decoder consumed.
#[derive(Default)]
struct ReadStats {
    nanos: std::sync::atomic::AtomicU64,
    bytes: std::sync::atomic::AtomicU64,
}
struct TimedReader<R> {
    inner: R,
    stats: std::sync::Arc<ReadStats>,
}
impl<R: Read> Read for TimedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let t = std::time::Instant::now();
        let n = self.inner.read(buf)?;
        let o = std::sync::atomic::Ordering::Relaxed;
        self.stats.nanos.fetch_add(t.elapsed().as_nanos() as u64, o);
        self.stats.bytes.fetch_add(n as u64, o);
        Ok(n)
    }
}

/// Process a compressed stream: decompress → hash → write to the provider's
/// sink. PIPELINED — THIS thread runs decrypt+decompress and hands decompressed
/// chunks over a recycled buffer pool to a spawned consumer thread that hashes +
/// writes them, so the two halves overlap and wall-time is ~max(decrypt+
/// decompress, hash+write) instead of their sum. The consumer is the spawned
/// side because the decrypt reader is not `Send`, whereas the hasher and the
/// `'static + Send` writer are. Buffers are recycled (not per-chunk allocated)
/// so the producer's alloc and consumer's free don't serialize on the global
/// allocator lock. Output order is preserved, so the digest is unchanged. Same
/// `writer` contract as [`process_plain`] (flushed before return).
fn process_decompressed<R: Read>(
    reader: R,
    expected_digest: &[u8],
    writer: Option<Box<dyn IoWrite + Send>>,
) -> Result<(usize, [u8; 32]), String> {
    use std::sync::mpsc::sync_channel;

    let in_stats = std::sync::Arc::new(ReadStats::default());
    let wall = std::time::Instant::now();
    // Buffer POOL, not per-chunk allocation. The producer fills a recycled
    // buffer and hands it over (`full`); the consumer processes it and returns
    // it (`free`). Recycling avoids ~9500 per-chunk 64 KiB malloc/free per
    // upload — on QNX the global allocator lock otherwise serializes the
    // producer's alloc against the consumer's free. The pool must also be LARGER
    // than the write burst: the 4 MiB BufWriter flushes eMMC in bursts, and a
    // pool smaller than that stalls the producer (full pool) during every flush,
    // so the two halves never overlap. 256 * 64 KiB = 16 MiB covers several
    // flushes of runway (the device has GBs free).
    const POOL: usize = 256;
    const CHUNK: usize = 64 * 1024;
    let (full_tx, full_rx) = sync_channel::<Vec<u8>>(POOL);
    let (free_tx, free_rx) = sync_channel::<Vec<u8>>(POOL);
    for _ in 0..POOL {
        free_tx.send(vec![0u8; CHUNK]).ok();
    }

    // Consumer thread: hash + write each chunk in stream (receive = send) order.
    // Returns the computed digest + busy times; the caller checks the digest
    // (expected_digest is borrowed, so it stays on this thread).
    let consumer = std::thread::spawn(move || -> Result<(usize, [u8; 32], u64, u64), String> {
        let mut hasher = Sha256::new();
        let mut writer = writer;
        let mut total = 0usize;
        let (mut hash_ns, mut write_ns) = (0u64, 0u64);
        while let Ok(chunk) = full_rx.recv() {
            let t1 = std::time::Instant::now();
            hasher.update(&chunk);
            hash_ns += t1.elapsed().as_nanos() as u64;
            if let Some(w) = writer.as_mut() {
                let t2 = std::time::Instant::now();
                w.write_all(&chunk).map_err(|e| format!("write: {e}"))?;
                write_ns += t2.elapsed().as_nanos() as u64;
            }
            total += chunk.len();
            // Return the buffer for reuse (producer may be gone → ignore).
            let mut chunk = chunk;
            chunk.clear();
            let _ = free_tx.send(chunk);
        }
        if let Some(w) = writer.as_mut() {
            w.flush().map_err(|e| format!("flush: {e}"))?;
        }
        let digest: [u8; 32] = hasher.finalize().into();
        Ok((total, digest, hash_ns, write_ns))
    });

    // Producer (this thread): decrypt (via the timing shim) + decompress, stream
    // chunks to the consumer. Run in a closure so a producer error doesn't skip
    // joining the consumer.
    let timed = TimedReader {
        inner: reader,
        stats: in_stats.clone(),
    };
    let mut up_ns = 0u64;
    let produce = (|| -> Result<(), String> {
        // Native libzstd — ~10x pure-Rust ruzstd on the A53; deterministic
        // output, so the bank digest is unchanged.
        let mut decoder =
            zstd::stream::read::Decoder::new(timed).map_err(|e| format!("zstd init: {e}"))?;
        loop {
            // Take a recycled buffer (alloc only if the pool ever runs dry).
            let mut buf = free_rx.recv().unwrap_or_else(|_| vec![0u8; CHUNK]);
            buf.resize(CHUNK, 0);
            let t0 = std::time::Instant::now();
            let n = decoder
                .read(&mut buf)
                .map_err(|e| format!("decompress: {e}"))?;
            up_ns += t0.elapsed().as_nanos() as u64;
            if n == 0 {
                break;
            }
            buf.truncate(n);
            // Err => consumer dropped full_rx (write error): stop early.
            if full_tx.send(buf).is_err() {
                break;
            }
        }
        Ok(())
    })();
    drop(full_tx); // signal the consumer that no more chunks are coming

    // Consumer errors (write/flush/panic) surface first; then the producer error.
    let (total, digest, hash_ns, write_ns) = consumer
        .join()
        .map_err(|_| "hash/write thread panicked".to_string())??;
    produce?;

    // Per-stage BUSY times: decrypt/decompress (this thread) and hash/write (the
    // consumer) overlap, so their sum exceeds `wall_ms` — that gap is the win.
    // `decrypt_mb_s` is over ciphertext bytes; the rest over decompressed output.
    let o = std::sync::atomic::Ordering::Relaxed;
    let decrypt_ms = in_stats.nanos.load(o) / 1_000_000;
    let in_bytes = in_stats.bytes.load(o);
    let decompress_ms = (up_ns / 1_000_000).saturating_sub(decrypt_ms);
    let mb_s = |bytes: u64, ms: u64| -> u64 {
        if ms == 0 {
            0
        } else {
            bytes.saturating_mul(1000) / (ms * 1024 * 1024)
        }
    };
    tracing::info!(
        out_mb = total / (1024 * 1024),
        wall_ms = wall.elapsed().as_millis() as u64,
        decrypt_ms,
        decrypt_mb_s = mb_s(in_bytes, decrypt_ms),
        decompress_ms,
        decompress_mb_s = mb_s(total as u64, decompress_ms),
        hash_ms = hash_ns / 1_000_000,
        hash_mb_s = mb_s(total as u64, hash_ns / 1_000_000),
        write_ms = write_ns / 1_000_000,
        write_mb_s = mb_s(total as u64, write_ns / 1_000_000),
        "payload pipeline stage timing (pipelined; sum > wall_ms)",
    );

    if digest.as_slice() != expected_digest {
        return Err("image digest mismatch".into());
    }
    Ok((total, digest))
}

fn verify_digest(hasher: Sha256, expected: &[u8]) -> Result<[u8; 32], String> {
    let computed: [u8; 32] = hasher.finalize().into();
    if computed.as_slice() != expected {
        return Err("image digest mismatch".into());
    }
    Ok(computed)
}

// ---------------------------------------------------------------------------
// Validation using header-only envelope
// ---------------------------------------------------------------------------

fn validate_header(
    manifest_provider: &dyn ManifestProvider,
    header_bytes: &[u8],
    min_security_ver: u32,
    expected_bank_set: BankSet,
) -> Result<ValidatedFirmware, BackendError> {
    // Validate using the header-only envelope (no #firmware payload).
    // The validator checks auth + manifest — doesn't need the payload.
    let validated = manifest_provider
        .validate_header_only(header_bytes, min_security_ver)
        .map_err(|e| BackendError::InvalidRequest(format!("manifest validation: {e}")))?;

    if validated.bank_set != expected_bank_set {
        return Err(BackendError::InvalidRequest(format!(
            "manifest targets {:?}, but this is {:?}",
            validated.bank_set, expected_bank_set
        )));
    }

    Ok(validated)
}

// ---------------------------------------------------------------------------
// ChannelReader — sync Read over mpsc::Receiver<Bytes>
// ---------------------------------------------------------------------------

struct ChannelReader {
    rx: tokio::sync::mpsc::Receiver<Bytes>,
    current: Bytes,
}

impl Read for ChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.current.is_empty() {
            // blocking_recv() is safe here — we run inside spawn_blocking
            match self.rx.blocking_recv() {
                Some(bytes) => self.current = bytes,
                None => return Ok(0), // channel closed = EOF
            }
        }
        let n = buf.len().min(self.current.len());
        buf[..n].copy_from_slice(&self.current[..n]);
        self.current = self.current.slice(n..);
        Ok(n)
    }
}

// ---------------------------------------------------------------------------
// DecryptReader — wraps StreamingDecryptor as std::io::Read
// ---------------------------------------------------------------------------

struct DecryptReader<R: Read> {
    inner: R,
    decryptor: StreamingDecryptor,
    out_buf: Vec<u8>,
    out_pos: usize,
    out_len: usize,
    finished: bool,
}

impl<R: Read> DecryptReader<R> {
    fn new(inner: R, decryptor: StreamingDecryptor) -> Self {
        Self {
            inner,
            decryptor,
            out_buf: vec![0u8; 4096 + 256], // CHUNK_SIZE + slack for GCM
            out_pos: 0,
            out_len: 0,
            finished: false,
        }
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Drain buffered output first
        if self.out_pos < self.out_len {
            let n = buf.len().min(self.out_len - self.out_pos);
            buf[..n].copy_from_slice(&self.out_buf[self.out_pos..self.out_pos + n]);
            self.out_pos += n;
            return Ok(n);
        }

        if self.finished {
            return Ok(0);
        }

        // Read a chunk from inner and decrypt
        let mut in_buf = [0u8; 4096];
        let n = self.inner.read(&mut in_buf)?;

        if n == 0 {
            // EOF — finalize decryption (verify GCM tag)
            self.finished = true;
            let pt_len = self
                .decryptor
                .finalize(&mut self.out_buf)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))?;
            self.out_pos = 0;
            self.out_len = pt_len;

            if pt_len == 0 {
                return Ok(0);
            }
            let copy = buf.len().min(pt_len);
            buf[..copy].copy_from_slice(&self.out_buf[..copy]);
            self.out_pos = copy;
            return Ok(copy);
        }

        let pt_len = self
            .decryptor
            .update(&in_buf[..n], &mut self.out_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))?;

        if pt_len == 0 {
            // Decryptor buffering (e.g. GCM tag) — recurse to get more data
            return self.read(buf);
        }

        self.out_pos = 0;
        self.out_len = pt_len;

        let copy = buf.len().min(pt_len);
        buf[..copy].copy_from_slice(&self.out_buf[..copy]);
        self.out_pos = copy;
        Ok(copy)
    }
}

// ---------------------------------------------------------------------------
// PrefixReader — prepend already-read bytes to a reader
// ---------------------------------------------------------------------------

struct PrefixReader<R: Read> {
    prefix: Vec<u8>,
    prefix_pos: usize,
    inner: R,
}

impl<R: Read> PrefixReader<R> {
    fn new(prefix: &[u8], inner: R) -> Self {
        Self {
            prefix: prefix.to_vec(),
            prefix_pos: 0,
            inner,
        }
    }
}

impl<R: Read> Read for PrefixReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.prefix_pos < self.prefix.len() {
            let remaining = &self.prefix[self.prefix_pos..];
            let n = buf.len().min(remaining.len());
            buf[..n].copy_from_slice(&remaining[..n]);
            self.prefix_pos += n;
            Ok(n)
        } else {
            self.inner.read(buf)
        }
    }
}

// ---------------------------------------------------------------------------
// CBOR helpers
// ---------------------------------------------------------------------------

async fn read_byte<R: AsyncRead + Unpin>(reader: &mut R) -> Result<u8, BackendError> {
    let mut b = [0u8; 1];
    reader.read_exact(&mut b).await.map_err(map_io)?;
    Ok(b[0])
}

/// Read a CBOR unsigned integer given the additional info from the initial byte.
/// Appends raw bytes to `buf` for recording.
async fn read_cbor_uint<R: AsyncRead + Unpin>(
    reader: &mut R,
    additional: u8,
    buf: &mut Vec<u8>,
) -> Result<u64, BackendError> {
    match additional {
        0..=23 => Ok(additional as u64),
        24 => {
            let mut b = [0u8; 1];
            reader.read_exact(&mut b).await.map_err(map_io)?;
            buf.extend_from_slice(&b);
            Ok(b[0] as u64)
        }
        25 => {
            let mut b = [0u8; 2];
            reader.read_exact(&mut b).await.map_err(map_io)?;
            buf.extend_from_slice(&b);
            Ok(u16::from_be_bytes(b) as u64)
        }
        26 => {
            let mut b = [0u8; 4];
            reader.read_exact(&mut b).await.map_err(map_io)?;
            buf.extend_from_slice(&b);
            Ok(u32::from_be_bytes(b) as u64)
        }
        27 => {
            let mut b = [0u8; 8];
            reader.read_exact(&mut b).await.map_err(map_io)?;
            buf.extend_from_slice(&b);
            Ok(u64::from_be_bytes(b))
        }
        _ => Err(BackendError::Internal(format!(
            "unsupported CBOR additional info: {additional}"
        ))),
    }
}

/// Decode a CBOR uint from a byte slice (sync version for header rebuild).
fn decode_cbor_uint(additional: u8, data: &[u8]) -> (u64, usize) {
    match additional {
        0..=23 => (additional as u64, 0),
        24 => (data[0] as u64, 1),
        25 => (u16::from_be_bytes([data[0], data[1]]) as u64, 2),
        26 => (
            u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64,
            4,
        ),
        27 => (
            u64::from_be_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]),
            8,
        ),
        _ => (0, 0),
    }
}

/// Encode a CBOR major type + uint value.
fn encode_cbor_uint(major: u8, value: u64, buf: &mut Vec<u8>) {
    let mt = major << 5;
    if value < 24 {
        buf.push(mt | value as u8);
    } else if value <= u8::MAX as u64 {
        buf.push(mt | 24);
        buf.push(value as u8);
    } else if value <= u16::MAX as u64 {
        buf.push(mt | 25);
        buf.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u32::MAX as u64 {
        buf.push(mt | 26);
        buf.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        buf.push(mt | 27);
        buf.extend_from_slice(&value.to_be_bytes());
    }
}

fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, String> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) => return Err(format!("read: {e}")),
        }
    }
    Ok(total)
}

fn map_io(e: io::Error) -> BackendError {
    BackendError::Internal(format!("I/O error: {e}"))
}

// =============================================================================
// Raw payload processor (separate manifest + payload uploads)
// =============================================================================

/// Process a raw payload file using a pre-validated manifest.
///
/// Unlike `process_envelope_stream` which parses CBOR, this reads a raw
/// encrypted byte stream (no CBOR framing) and processes it using the
/// manifest's encryption_info for the specified component.
///
/// Flow: read raw file → decrypt (AES-GCM) → decompress (zstd) → verify hash → write
pub fn process_raw_payload(
    payload_path: &Path,
    manifest_bytes: &[u8],
    component_index: usize,
    key_unwrap: Option<&(dyn sumo_onboard::decryptor::KeyUnwrap + Send + Sync)>,
    expected_digest: &[u8],
    writer: Box<dyn IoWrite + Send>,
) -> Result<(usize, [u8; 32]), String> {
    let crypto = RustCryptoBackend::new();

    let envelope = sumo_codec::decode::decode_envelope(manifest_bytes)
        .map_err(|e| format!("decode manifest: {e:?}"))?;
    let manifest = sumo_onboard::manifest::Manifest { envelope };

    let has_encryption = manifest.encryption_info(component_index).is_some();

    let file = std::fs::File::open(payload_path)
        .map_err(|e| format!("open payload {}: {e}", payload_path.display()))?;
    let mut reader = std::io::BufReader::new(file);

    if has_encryption {
        let unwrap =
            key_unwrap.ok_or("encrypted payload but no CEK unwrapper (HSM not provisioned?)")?;

        let decryptor = StreamingDecryptor::new(&manifest, component_index, unwrap, &crypto)
            .map_err(|e| format!("decryptor setup: {e:?}"))?;

        let mut decrypt_reader = DecryptReader::new(reader, decryptor);

        // Detect zstd
        let mut first_buf = [0u8; 4];
        let first_n = read_exact_or_eof(&mut decrypt_reader, &mut first_buf)?;

        if first_n >= 4 && first_buf[..4] == ZSTD_MAGIC {
            let prefixed = PrefixReader::new(&first_buf[..first_n], decrypt_reader);
            process_decompressed(prefixed, expected_digest, Some(writer))
        } else {
            let prefixed = PrefixReader::new(&first_buf[..first_n], decrypt_reader);
            process_plain(prefixed, expected_digest, Some(writer))
        }
    } else {
        // Unencrypted — detect zstd
        let mut first_buf = [0u8; 4];
        let first_n = read_exact_or_eof(&mut reader, &mut first_buf)?;

        if first_n >= 4 && first_buf[..4] == ZSTD_MAGIC {
            let prefixed = PrefixReader::new(&first_buf[..first_n], reader);
            process_decompressed(prefixed, expected_digest, Some(writer))
        } else {
            let prefixed = PrefixReader::new(&first_buf[..first_n], reader);
            process_plain(prefixed, expected_digest, Some(writer))
        }
    }
}

/// Fetch a content-addressed payload and install it into the target component
/// bank — the **PULL** counterpart to the pushed [`process_payload_stream`].
///
/// Instead of the orchestrator streaming bytes over SOVD, the device
/// dereferences the (T2-signed) content-addressed `blob_uri` itself. Integrity
/// is layered and unchanged from the push path:
/// - **OUTER**: [`puller::Puller::fetch_blob`] verifies the fetched ciphertext
///   against the sha parsed from the content-addressed URI — and that address
///   rides *inside* the signed manifest, so the digest we check is itself
///   signed. Resumable (`Range`); safe because content-addressed bytes are
///   immutable, so a partial + continue can't be poisoned.
/// - **INNER**: [`process_raw_payload`] decrypts/decompresses and verifies the
///   plaintext against the manifest's `image_digest` (+ the AES-GCM tag).
///
/// The fetched ciphertext is staged in `tmp_dir`, named by its content-address
/// so a re-attempt resumes the same partial; it is removed on a successful
/// install and left in place on error (for resume).
///
/// Returns `(image_size, image_sha256)` of the installed (plaintext) image.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_and_install_component(
    puller: &Puller,
    blob_uri: &str,
    expected_size: u64,
    manifest_bytes: &[u8],
    component_index: usize,
    key_unwrap: Option<Arc<dyn sumo_onboard::decryptor::KeyUnwrap + Send + Sync>>,
    image_digest: &[u8],
    writer: Box<dyn IoWrite + Send>,
    tmp_dir: &Path,
) -> Result<(usize, [u8; 32]), BackendError> {
    // The outer integrity anchor is the content-address embedded in the (signed)
    // URI. No address ⇒ we cannot verify the fetched bytes ⇒ hard reject rather
    // than trust an unverifiable CDN URL.
    let outer_sha = content_address_sha256(blob_uri).ok_or_else(|| {
        BackendError::InvalidRequest(format!(
            "remote payload uri is not content-addressed (cannot verify outer integrity): {blob_uri}"
        ))
    })?;

    let tmp = tmp_dir.join(format!("cas-{}.part", hex::encode(outer_sha)));

    // OUTER: resumable GET + verify content-address. fetch_blob leaves the
    // partial on transient errors (resume next time) and truncates on a
    // hash/size mismatch (no poisoned bytes survive on disk).
    puller
        .fetch_blob(blob_uri, outer_sha, expected_size, &tmp)
        .await
        .map_err(|e| BackendError::Internal(format!("fetch {blob_uri}: {e}")))?;

    // INNER: decrypt → decompress → verify image_digest → write to the bank.
    // process_raw_payload is sync/blocking (file I/O + crypto), so off-thread it.
    let manifest_bytes = manifest_bytes.to_vec();
    let image_digest = image_digest.to_vec();
    let tmp_for_task = tmp.clone();
    let installed = tokio::task::spawn_blocking(move || {
        process_raw_payload(
            &tmp_for_task,
            &manifest_bytes,
            component_index,
            key_unwrap.as_deref(),
            &image_digest,
            writer,
        )
    })
    .await
    .map_err(|e| BackendError::Internal(format!("install task join: {e}")))?
    .map_err(|e| BackendError::Internal(format!("install {blob_uri}: {e}")))?;

    // Success → drop the staged ciphertext (left in place on the error paths
    // above so a retry can resume).
    let _ = std::fs::remove_file(&tmp);

    Ok(installed)
}

/// Resolve every dependency's L2 envelope from a **pre-validated** L1 campaign
/// manifest — the pull-aware analog of the dependency loop in
/// `sumo-onboard::process_campaign`, adapted for the host path.
///
/// Integrated (`#`) dependencies come from the L1's embedded payloads. Remote
/// dependencies are fetched by their content-addressed URI:
/// [`puller::Puller::fetch_manifest`] validates the L2 signature, and we
/// additionally bind the fetched bytes' sha to the content-address carried in
/// the (signed) L1 — so a swapped CDN object is rejected (it would have to be
/// separately T2-signed *and* collide on sha to pass).
///
/// Returns the L2 envelope bytes in dependency order. The caller validates the
/// L1 signature *before* calling, then installs each L2 — routed to its target
/// bank via [`process_envelope_stream`] for an integrated payload, or
/// [`fetch_and_install_component`] for a remote content-addressed payload.
/// Validate a T2-signed L1 campaign envelope against the device's pinned
/// sw-authority anchor (CBOR COSE_Key) — the caller-side precondition
/// [`resolve_campaign_dependencies`] documents. Mirrors
/// [`puller::Puller::fetch_manifest`]'s validation of remote L2s, so the L1
/// and every L2 pass through the same signature gate; without it an unsigned
/// L1 could compose individually-signed L2s into an unauthorized campaign.
///
/// Anti-rollback stays per-component: the sequence gate is left open here
/// (`min_sequence = 0`) because each L2 is re-validated with the component's
/// NV security floor at upload.
pub fn validate_l1(
    l1_bytes: &[u8],
    trust_anchor: &[u8],
) -> Result<sumo_onboard::manifest::Manifest, BackendError> {
    let mut validator = sumo_onboard::validator::Validator::new(trust_anchor, None);
    validator.set_min_sequence(0);
    validator
        .validate_envelope(
            l1_bytes,
            &sumo_crypto::rustcrypto::RustCryptoBackend,
            /* trusted_time = */ 0,
        )
        .map_err(|e| BackendError::InvalidRequest(format!("L1 campaign validation failed: {e:?}")))
}

pub async fn resolve_campaign_dependencies(
    l1: &sumo_onboard::manifest::Manifest,
    puller: &Puller,
) -> Result<Vec<Vec<u8>>, BackendError> {
    if !l1.is_campaign() {
        return Err(BackendError::InvalidRequest(
            "not a campaign manifest (no dependencies)".into(),
        ));
    }

    let dep_count = l1.dependency_count();
    let mut l2_envelopes = Vec::with_capacity(dep_count);

    for idx in 0..dep_count {
        let uri = l1.dependency_uri(idx).ok_or_else(|| {
            BackendError::InvalidRequest(format!("campaign dependency {idx} has no uri"))
        })?;

        let l2 = if uri.starts_with('#') {
            // Integrated L2 envelope embedded in the (signed) L1.
            l1.integrated_payload(uri)
                .ok_or_else(|| {
                    BackendError::InvalidRequest(format!(
                        "campaign references integrated dependency {uri} but it is absent"
                    ))
                })?
                .to_vec()
        } else {
            // Remote, content-addressed L2 manifest. fetch_manifest validates
            // the L2 signature; we additionally bind the fetched bytes to the
            // content-address from the signed L1.
            let outer = content_address_sha256(uri).ok_or_else(|| {
                BackendError::InvalidRequest(format!(
                    "campaign dependency uri is not content-addressed: {uri}"
                ))
            })?;
            let validated = puller
                .fetch_manifest(uri)
                .await
                .map_err(|e| BackendError::Internal(format!("fetch L2 manifest {uri}: {e}")))?;
            if validated.sha256 != outer {
                return Err(BackendError::InvalidRequest(format!(
                    "fetched L2 manifest sha does not match content-address for {uri}"
                )));
            }
            validated.raw
        };

        l2_envelopes.push(l2);
    }

    Ok(l2_envelopes)
}

/// Stream a payload from the network straight through decrypt →
/// decompress → hash → write to disk in a single pass.
///
/// Replaces the older `save_raw_payload` (ciphertext → .tmp) followed
/// by `process_raw_payload` (.tmp → final) pair. That pattern wrote the
/// payload to flash twice — once as the encrypted/compressed tmp and
/// once as the unpacked final file — doubling the I/O cost on the
/// device's flash storage for no benefit.
///
/// Returns `(inbound_bytes, image_size, image_sha256)`:
/// - `inbound_bytes`: total ciphertext + zstd bytes read from the
///   stream (i.e. the "on-wire" size — useful for compression-ratio
///   logging).
/// - `image_size`: plaintext + decompressed bytes written to disk.
/// - `image_sha256`: digest of the written bytes (matches the
///   manifest's `image_digest` for this component).
pub async fn process_payload_stream(
    stream: PackageStream,
    manifest_bytes: Vec<u8>,
    component_index: usize,
    key_unwrap: Option<Arc<dyn sumo_onboard::decryptor::KeyUnwrap + Send + Sync>>,
    expected_digest: Vec<u8>,
    writer: Box<dyn IoWrite + Send>,
) -> Result<(u64, usize, [u8; 32]), BackendError> {
    let envelope = sumo_codec::decode::decode_envelope(&manifest_bytes)
        .map_err(|e| BackendError::Internal(format!("decode manifest: {e:?}")))?;
    let has_encryption = sumo_onboard::manifest::Manifest { envelope }
        .encryption_info(component_index)
        .is_some();

    let reader = StreamReader::new(stream.map(|r| r.map_err(io::Error::other)));
    tokio::pin!(reader);

    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(32);

    let process_handle = tokio::task::spawn_blocking(move || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            process_payload_sync(
                rx,
                &manifest_bytes,
                has_encryption,
                component_index,
                &[],
                key_unwrap.as_deref(),
                &expected_digest,
                Some(writer),
            )
        }))
        .unwrap_or_else(|panic| {
            let msg = panic
                .downcast_ref::<String>()
                .map(|s| s.as_str())
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .unwrap_or("unknown panic");
            Err(format!("panic in payload processing: {msg}"))
        })
    });

    let mut inbound: u64 = 0;
    let mut buf = vec![0u8; 64 * 1024];
    let mut send_failed = false;

    loop {
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|e| BackendError::Internal(format!("stream read error: {e}")))?;
        if n == 0 {
            break;
        }
        inbound += n as u64;
        if tx.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
            send_failed = true;
            break;
        }
    }
    drop(tx);

    let (image_size, image_hash) = match process_handle.await {
        Ok(Ok(result)) => {
            if send_failed {
                return Err(BackendError::Internal("payload stream ended early".into()));
            }
            result
        }
        Ok(Err(e)) => {
            return Err(BackendError::Internal(format!(
                "payload processing failed: {e}"
            )));
        }
        Err(e) => {
            return Err(BackendError::Internal(format!(
                "payload processing panicked: {e}"
            )));
        }
    };

    Ok((inbound, image_size, image_hash))
}

/// Stream a raw payload from an async stream to disk (no CBOR, no processing).
/// Just write bytes + compute SHA256 for later verification.
pub async fn save_raw_payload(
    stream: PackageStream,
    output_path: &Path,
) -> Result<(u64, [u8; 32]), BackendError> {
    let reader = StreamReader::new(stream.map(|r| r.map_err(io::Error::other)));
    tokio::pin!(reader);

    let mut file = tokio::fs::File::create(output_path)
        .await
        .map_err(|e| BackendError::Internal(format!("create {}: {e}", output_path.display())))?;

    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut buf = vec![0u8; 64 * 1024];

    loop {
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|e| BackendError::Internal(format!("stream read: {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        tokio::io::AsyncWriteExt::write_all(&mut file, &buf[..n])
            .await
            .map_err(|e| BackendError::Internal(format!("write: {e}")))?;
        total += n as u64;
    }

    let hash: [u8; 32] = hasher.finalize().into();
    Ok((total, hash))
}

/// Validate a manifest (small CBOR envelope, no payload).
/// Uses header-only validation — payloads are uploaded separately.
pub fn validate_manifest(
    manifest_bytes: &[u8],
    manifest_provider: &dyn ManifestProvider,
    min_security_ver: u32,
) -> Result<ValidatedFirmware, BackendError> {
    manifest_provider
        .validate_header_only(manifest_bytes, min_security_ver)
        .map_err(|e| BackendError::InvalidRequest(format!("manifest validation: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::Cursor;
    use std::sync::{Arc, Mutex};

    /// In-memory `Write` sink to capture exactly what the pipeline produced.
    struct VecSink(Arc<Mutex<Vec<u8>>>);
    impl IoWrite for VecSink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The pipelined decompress must reproduce the exact bytes IN ORDER and the
    /// correct digest — the property the producer/consumer split could break.
    #[test]
    fn pipelined_decompress_roundtrips_bytes_and_digest() {
        // ~3 MiB (> the 2 MiB channel) so the bounded channel fills and the
        // producer/consumer overlap + backpressure across many chunks.
        let original: Vec<u8> = (0..3_000_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let expected = Sha256::digest(&original).to_vec();
        let compressed = zstd::encode_all(&original[..], 3).unwrap();

        let out = Arc::new(Mutex::new(Vec::new()));
        let writer: Box<dyn IoWrite + Send> = Box::new(VecSink(out.clone()));
        let (total, digest) =
            process_decompressed(Cursor::new(compressed), &expected, Some(writer)).unwrap();

        assert_eq!(total, original.len(), "byte count");
        assert_eq!(digest.as_slice(), expected.as_slice(), "digest");
        assert_eq!(*out.lock().unwrap(), original, "bytes match, in order");
    }

    /// A wrong expected digest must still be rejected after pipelining.
    #[test]
    fn pipelined_decompress_rejects_wrong_digest() {
        let original = vec![0x5Au8; 500_000];
        let compressed = zstd::encode_all(&original[..], 3).unwrap();
        let out = Arc::new(Mutex::new(Vec::new()));
        let writer: Box<dyn IoWrite + Send> = Box::new(VecSink(out));
        let res = process_decompressed(Cursor::new(compressed), &[0u8; 32], Some(writer));
        assert!(res.is_err(), "wrong digest must be rejected");
    }
}
