use super::*;

impl<D: BlockDevice + Send + 'static> ComponentBackend<D> {
    /// Reconcile the manifested-but-un-pushed components `absent` (component
    /// indices, in manifest order) so the target bank is
    /// content-complete, each part DIGEST-VERIFIED against the manifest's
    /// declared plaintext image digest. Per part, in order:
    ///
    /// 1. **Copy-forward** from the active bank when its on-disk content hashes
    ///    to exactly what the manifest declared ("the vehicle already has
    ///    this" — the push path's manifest-only case, and the pull path's
    ///    cheap local half of copy-vs-fetch).
    /// 2. **Fetch by content-address** when copy-forward can't satisfy the
    ///    part AND the pull route provided a session [`machine_mgr::InstallSource`]
    ///    AND the (T2-signed) manifest URI carries a content-address: the blob
    ///    streams from the untrusted CAS through the two-checksum pipeline
    ///    (outer = signed content-address, inner = manifest `image_digest`)
    ///    straight into the target bank.
    /// 3. Otherwise FAIL the install rather than sealing a bank whose bytes
    ///    don't match the manifest's promise.
    ///
    /// Returns the copied files as an [`hsm::ivd::IvdFile`] inventory so the caller
    /// can fold them into the flash transfer's `streamed_files` (parity with the
    /// pushed path). A no-op returning empty when there are no un-pushed components.
    pub(super) async fn reconcile_unpushed(
        &self,
        manifest_bytes: &[u8],
        absent: &[usize],
        target: Bank,
    ) -> BackendResult<Vec<hsm::ivd::IvdFile>> {
        if absent.is_empty() {
            return Ok(Vec::new());
        }
        let images_dir = self.images_dir.as_ref().ok_or_else(|| {
            BackendError::Internal(
                "manifest-only push needs an images_dir to reconcile the target bank".into(),
            )
        })?;

        // Resolve the active bank from NV; `target` is its sibling (never self-copy).
        let active = {
            let nv = self
                .nv
                .lock()
                .map_err(|_| BackendError::Internal("nv lock".into()))?;
            let state = nv
                .read_boot_state()
                .ok_or_else(|| BackendError::Internal("no boot state".into()))?;
            state.banks[self.bank_set.as_index()].active_bank
        };
        if active == target {
            return Err(BackendError::Internal(
                "copy-forward: target bank == active bank — refusing to self-copy".into(),
            ));
        }

        let set_name = self.bank_spec.dir_name.as_str();
        let active_dir = images_dir
            .join(set_name)
            .join(crate::bank_provider::bank_dir_name(active));
        let target_dir = images_dir
            .join(set_name)
            .join(crate::bank_provider::bank_dir_name(target));

        // Decode the stored manifest — `validated.image_sha256` is None for a
        // header-only manifest, so the per-component expected digest comes from
        // the SUIT manifest itself.
        let envelope = sumo_codec::decode::decode_envelope(manifest_bytes)
            .map_err(|e| BackendError::Internal(format!("reconcile decode manifest: {e:?}")))?;
        let manifest = sumo_onboard::manifest::Manifest { envelope };

        // One puller per reconcile pass, built lazily on the first part that
        // needs a fetch — push-path finalizes never pay for it.
        let mut cas_puller: Option<puller::Puller> = None;

        let mut done = Vec::with_capacity(absent.len());
        for &i in absent {
            let expected = manifest
                .image_digest(i)
                .map(|d| d.0.bytes.clone())
                .ok_or_else(|| {
                    BackendError::Internal(format!(
                        "reconcile: manifest has no image_digest for component {i}"
                    ))
                })?;
            // Name from the component-id part, not the (content-address) uri.
            let name = crate::bank_spec::payload_target_name_for_id(manifest.component_id(i))?;

            match crate::bank_seed::copy_forward_file(&active_dir, &target_dir, &name, &expected) {
                Ok((sha256, size)) => {
                    tracing::info!(
                        component = i,
                        file = %name,
                        size,
                        "reconcile: active bank content matches manifest digest — copied to target",
                    );
                    done.push(hsm::ivd::IvdFile {
                        relative_path: name,
                        sha256: sha256.to_vec(),
                        size,
                    });
                }
                Err(copy_err) => {
                    // Copy-forward can't satisfy this part — fall back to
                    // fetching it by content-address IF the pull route provided
                    // a session source and the (signed) manifest URI carries an
                    // address. Otherwise the copy-forward refusal stands: never
                    // seal a bank whose bytes don't match the manifest promise.
                    let source = self.install_source.lock().unwrap().clone();
                    let uri = manifest.uri(i).map(str::to_owned);
                    let fetchable = source
                        .zip(uri)
                        .filter(|(_, u)| puller::content_address_sha256(u).is_some());
                    let Some((src, uri)) = fetchable else {
                        return Err(BackendError::Internal(format!(
                            "reconcile refused for component {i}: {copy_err}; \
                             no fetch source / content-addressed uri to fall back to"
                        )));
                    };
                    if cas_puller.is_none() {
                        cas_puller = Some(
                            puller::Puller::new(&src.cas_base_url, &src.trust_anchor).map_err(
                                |e| BackendError::Internal(format!("reconcile: build puller: {e}")),
                            )?,
                        );
                    }
                    let p = cas_puller.as_ref().unwrap();
                    // `sha256:<hex>` names content but isn't fetchable as-is —
                    // map it onto the repo's blob path. The mapped path still
                    // carries the content-address for the outer verify.
                    let path = puller::cas_fetch_path(&uri);
                    let outer_size = p.blob_size(&path).await.map_err(|e| {
                        BackendError::Internal(format!(
                            "reconcile: blob size for component {i}: {e}"
                        ))
                    })?;
                    // CAS temp lives beside the bank dirs (NOT inside the
                    // target bank) so the bank's prune at the next manifest
                    // never destroys a resumable partial.
                    let cas_tmp = images_dir.join(set_name).join("cas");
                    std::fs::create_dir_all(&cas_tmp).map_err(|e| {
                        BackendError::Internal(format!("reconcile: create cas tmp dir: {e}"))
                    })?;
                    let writer = self
                        .bank_provider
                        .open_payload_writer(target, &name)
                        .map_err(|e| {
                            sink_error(&format!("reconcile: open bank writer for {name}"), e)
                        })?;
                    let key_unwrap = self.manifest_provider.key_unwrap_for_decryption();
                    let fetched = crate::streaming::fetch_and_install_component(
                        p,
                        &path,
                        outer_size,
                        manifest_bytes,
                        i,
                        key_unwrap,
                        &expected,
                        writer,
                        &cas_tmp,
                    )
                    .await;
                    let (size, sha256) = match fetched {
                        Ok(x) => x,
                        Err(e) => {
                            // `open_payload_writer` pre-created the bank file;
                            // a failed fetch must not leave even a partial
                            // artifact in the target bank (mirror of
                            // copy_forward_file's remove-on-mismatch). The
                            // resumable ciphertext partial in `cas/` is kept.
                            let _ = std::fs::remove_file(target_dir.join(&name));
                            return Err(e);
                        }
                    };
                    tracing::info!(
                        component = i,
                        file = %name,
                        size,
                        uri = %uri,
                        "reconcile: fetched by content-address into the target bank \
                         (copy-forward said: {copy_err})",
                    );
                    done.push(hsm::ivd::IvdFile {
                        relative_path: name,
                        sha256: sha256.to_vec(),
                        size: size as u64,
                    });
                }
            }
        }
        Ok(done)
    }

    /// Drop any in-flight flash session state. Safe to call when no session
    /// is in flight (no-op). Does NOT undo a finalized install (bank pointer
    /// stays where it was) — that's the caller's responsibility, gated by
    /// `FlashCaps.abortable_after_finalize`.
    pub fn clear_flash_session(&self) {
        *self.flash_session.lock().unwrap() = None;
        *self.flash_transfer.lock().unwrap() = None;
        *self.upload_phase.lock().unwrap() = None;
        *self.install_source.lock().unwrap() = None;
        self.packages.lock().unwrap().clear();
        self.manifests.lock().unwrap().clear();
        self.payloads.lock().unwrap().clear();
        self.manifest_describe.lock().unwrap().clear();
    }

    /// Terminal session teardown shared by every abort path: drop the staging
    /// session AND resolve this component's node-transaction membership (the
    /// gate staged it at `start_flash`). Pre-finalize only — callers reject
    /// post-finalize aborts first. The verified parts the target bank holds
    /// stay, with the staging record; the record forgets the update id, so
    /// it is a part cache now, not a held update. The next manifest keeps
    /// the parts it can re-verify and removes the rest. Best-effort: a record
    /// error logs but doesn't mask the abort.
    pub fn abort_session(&self) -> BackendResult<()> {
        let had_session = self.flash_session.lock().unwrap().is_some();
        self.clear_flash_session();
        *self.update_id.lock().unwrap() = None;
        // Only touch the record when a session was actually in flight: with
        // no session, target_bank() may be the LIVE bank (single-bank
        // components target their only bank) and this is called as a
        // stale-DELETE no-op.
        if had_session {
            let bank = self.bank_provider.target_bank();
            let forgotten = self
                .bank_provider
                .staging_record(bank)
                .and_then(|rec| match rec {
                    Some(mut rec) if rec.update_id.is_some() => {
                        rec.update_id = None;
                        self.bank_provider.write_staging_record(bank, Some(&rec))
                    }
                    _ => Ok(()),
                });
            if let Err(e) = forgotten {
                tracing::warn!(error = %e, "abort: staging record still names the update");
            }
        }
        self.resolve_node_transaction()
    }

    /// A fresh staging record for `parts`, stamped with this session's update
    /// id, the node boot id and the time now.
    pub(super) fn new_staging_record(&self, parts: Vec<StagedPart>) -> StagingRecord {
        StagingRecord {
            version: StagingRecord::VERSION,
            update_id: self.update_id.lock().unwrap().clone(),
            node_boot_id: self.node_boot_id.clone(),
            started_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            parts,
            sealed: false,
        }
    }

    /// Settle `bank` against a freshly validated manifest before any payload
    /// arrives. Each part the staging record names is kept when it is the
    /// on-medium part of a manifest component, its recorded digest is that
    /// component's `image_digest`, and the bytes still hash to it; anything
    /// else the bank holds toward an install goes (`prune_target`), and torn
    /// staging leftovers with it. The record is rewritten with the kept parts
    /// — or removed when the manifest owes no payload.
    ///
    /// Returns the kept parts as the transfer's inventory, with the component
    /// index each one settles.
    pub(super) fn reconcile_staging(
        &self,
        bank: Bank,
        manifest: &sumo_onboard::manifest::Manifest,
        parts: &[usize],
    ) -> BackendResult<Vec<(usize, hsm::ivd::IvdFile)>> {
        let record = self
            .bank_provider
            .staging_record(bank)
            .map_err(|e| BackendError::Internal(format!("read staging record: {e}")))?;
        let mut kept: Vec<(usize, hsm::ivd::IvdFile)> = Vec::new();
        for staged in record.iter().flat_map(|r| r.parts.iter()) {
            let component = parts.iter().copied().find(|&i| {
                !kept.iter().any(|(k, _)| *k == i)
                    && crate::bank_spec::payload_target_name_for_id(manifest.component_id(i))
                        .is_ok_and(|n| n == staged.name)
                    && manifest
                        .image_digest(i)
                        .is_some_and(|d| hex::encode(&d.0.bytes) == staged.sha256)
            });
            let Some(i) = component else {
                tracing::info!(part = %staged.name, "staged part is not a part of this manifest — dropped");
                continue;
            };
            let declared = &manifest.image_digest(i).expect("matched on digest").0.bytes;
            let Ok(digest) = <[u8; 32]>::try_from(declared.as_slice()) else {
                continue;
            };
            match self
                .bank_provider
                .verify_payload(bank, &staged.name, &digest)
            {
                Ok(()) => {
                    tracing::info!(component = i, part = %staged.name, "staged part kept — re-verified by digest");
                    kept.push((
                        i,
                        hsm::ivd::IvdFile {
                            relative_path: staged.name.clone(),
                            sha256: digest.to_vec(),
                            size: staged.size,
                        },
                    ));
                }
                Err(e) => {
                    tracing::warn!(part = %staged.name, error = %e, "staged part no longer verifies — dropped");
                }
            }
        }
        let keep: Vec<String> = kept.iter().map(|(_, f)| f.relative_path.clone()).collect();
        self.bank_provider
            .prune_target(bank, &keep)
            .map_err(|e| BackendError::Internal(e.to_string()))?;
        let record = (!parts.is_empty()).then(|| {
            self.new_staging_record(
                kept.iter()
                    .map(|(_, f)| StagedPart {
                        name: f.relative_path.clone(),
                        size: f.size,
                        sha256: hex::encode(&f.sha256),
                    })
                    .collect(),
            )
        });
        self.bank_provider
            .write_staging_record(bank, record.as_ref())
            .map_err(|e| BackendError::Internal(format!("write staging record: {e}")))?;
        Ok(kept)
    }

    /// Note one verified part in `bank`'s staging record, BEFORE the upload
    /// is acknowledged: a part the record names survives a restart.
    pub(super) fn record_staged_part(
        &self,
        bank: Bank,
        part: &hsm::ivd::IvdFile,
    ) -> BackendResult<()> {
        let mut record = self
            .bank_provider
            .staging_record(bank)
            .map_err(|e| BackendError::Internal(format!("read staging record: {e}")))?
            .unwrap_or_else(|| self.new_staging_record(Vec::new()));
        record.update_id = self.update_id.lock().unwrap().clone();
        record.parts.retain(|p| p.name != part.relative_path);
        record.parts.push(StagedPart {
            name: part.relative_path.clone(),
            size: part.size,
            sha256: hex::encode(&part.sha256),
        });
        self.bank_provider
            .write_staging_record(bank, Some(&record))
            .map_err(|e| BackendError::Internal(format!("write staging record: {e}")))
    }

    /// Whether a flash session is currently in flight.
    ///
    /// Used by destructive ops (e.g. factory_reset) that must refuse rather
    /// than corrupt mid-write banks.
    pub fn flash_in_progress(&self) -> bool {
        self.flash_session.lock().unwrap().is_some()
    }

    /// True if the in-flight flash session has progressed past finalize
    /// (i.e. the staged bank is now the next-boot bank, awaiting reset).
    pub fn flash_is_finalized(&self) -> bool {
        let ft = self.flash_transfer.lock().unwrap();
        match ft.as_ref().map(|t| t.state) {
            Some(FlashState::AwaitingReboot)
            | Some(FlashState::Activated)
            | Some(FlashState::Committed)
            | Some(FlashState::RolledBack) => true,
            _ => false,
        }
    }

    pub fn ensure_flash_can_start(&self) -> BackendResult<()> {
        // A disabled component is admitted here, and nothing is cleared: a flash
        // re-enables structurally. It seals a real IVD into the target bank and
        // `activate` moves the selector there, so the serving bank reads a real
        // inventory; a rollback returns to the sentinel bank, disabled again.
        // "Disabled ⇒ never uncommitted" holds because the disable enact refuses
        // a component mid-trial, not by refusing the flash.

        if !self.config.single_bank && self.bank_provider.banks().is_some_and(|b| b.in_trial) {
            return Err(BackendError::Busy(format!(
                "bank set {:?} is in trial mode (active={:?}, uncommitted) — \
                 commit or rollback the pending upgrade before starting a new one",
                self.bank_set,
                self.bank_provider.active_bank()
            )));
        }

        // Node-level update-transaction gate (see `machine_mgr::node_update`):
        // refuse a new flash while any component is pending a node reset, or
        // while a component is in trial and the node has rebooted since arming
        // (the trial awaits its verdict). Before that reboot an in-trial
        // component is an armed sibling of the same campaign step, so this one
        // joins: one step, one reboot, one verdict. On admit, this component
        // joins the staging set. No-op until `vm-sovd` injects the coordinator.
        if let Some(coord) = &self.node_coordinator {
            coord
                .gate_new_session(&self.entity_info.id)
                .map_err(|r| BackendError::Busy(r.to_string()))?;
        }

        Ok(())
    }

    // =================================================================
    // Separate manifest + payload upload methods (new flash path)
    // =================================================================

    /// Upload a manifest (small CBOR envelope without integrated payloads).
    /// Validates signature + anti-rollback. Returns manifest_id.
    pub fn receive_manifest(&self, data: &[u8]) -> BackendResult<String> {
        let min_security_ver = {
            let nv = self
                .nv
                .lock()
                .map_err(|_| BackendError::Internal("lock".into()))?;
            let rb = *self.running_bank.lock().unwrap();
            nv.read_fw_meta(self.bank_set, rb)
                .map(|m| m.min_security_ver)
                .unwrap_or(0)
        };

        let _validated = crate::streaming::validate_manifest(
            data,
            self.manifest_provider.as_ref(),
            min_security_ver,
        )?;

        let id = self.next_id();
        let mut manifests = self.manifests.lock().unwrap();
        manifests.insert(
            id.clone(),
            StoredManifest {
                raw_bytes: data.to_vec(),
            },
        );

        tracing::info!(manifest_id = %id, "manifest uploaded and validated");
        Ok(id)
    }

    /// Upload a raw payload (encrypted bytes, no CBOR).
    /// Streams to disk + computes SHA256. Returns payload_id.
    pub async fn receive_payload_stream(
        &self,
        stream: PackageStream,
        filename: Option<&str>,
    ) -> BackendResult<String> {
        let id = self.next_id();
        let dir = self
            .images_dir
            .as_ref()
            .ok_or_else(|| BackendError::Internal("no images_dir configured".into()))?;

        let fname = filename.unwrap_or("payload");
        let path = dir.join(format!("upload-{id}-{fname}"));

        let (size, _sha256) = crate::streaming::save_raw_payload(stream, &path).await?;

        let mut payloads = self.payloads.lock().unwrap();
        payloads.insert(id.clone(), StoredPayload { path });

        tracing::info!(payload_id = %id, size, "payload uploaded to disk");
        Ok(id)
    }

    /// Flash using a pre-uploaded manifest + payload(s).
    /// Processes each payload through decrypt → decompress → verify → write.
    pub fn start_flash_multi(
        &self,
        manifest_id: &str,
        payload_ids: &std::collections::HashMap<String, String>, // uri → payload_id
    ) -> BackendResult<String> {
        let manifests = self.manifests.lock().unwrap();
        let manifest = manifests.get(manifest_id).ok_or_else(|| {
            BackendError::InvalidRequest(format!("manifest {manifest_id} not found"))
        })?;

        let payloads = self.payloads.lock().unwrap();

        // Parse manifest to get component info
        let envelope = sumo_codec::decode::decode_envelope(&manifest.raw_bytes)
            .map_err(|e| BackendError::Internal(format!("decode manifest: {e:?}")))?;
        let suit_manifest = sumo_onboard::manifest::Manifest { envelope };

        let key_unwrap = self.manifest_provider.key_unwrap_for_decryption();

        let target_bank = self.determine_target_bank()?;

        // Process each payload
        for (uri, payload_id) in payload_ids {
            let stored_payload = payloads.get(payload_id).ok_or_else(|| {
                BackendError::InvalidRequest(format!("payload {payload_id} not found"))
            })?;

            // Find component index by URI
            let comp_count = suit_manifest.component_count();
            let comp_idx = (0..comp_count)
                .find(|&i| {
                    suit_manifest
                        .uri(i)
                        .map(|u| u == uri.as_str())
                        .unwrap_or(false)
                })
                .ok_or_else(|| {
                    BackendError::InvalidRequest(format!("no component with uri={uri} in manifest"))
                })?;

            let expected_digest = suit_manifest
                .image_digest(comp_idx)
                .map(|d| d.0.bytes.clone())
                .ok_or_else(|| {
                    BackendError::Internal(format!("no digest for component {comp_idx}"))
                })?;

            // Name from the component-id part, not the (possibly content-address)
            // uri — see `payload_target_name_for_id`.
            let target_name =
                crate::bank_spec::payload_target_name_for_id(suit_manifest.component_id(comp_idx))?;

            // Open the payload sink through the bank provider — it owns where
            // the bytes land and creates the bank dir as needed.
            let writer = self
                .bank_provider
                .open_payload_writer(target_bank, &target_name)
                .map_err(|e| sink_error(&format!("open payload sink {target_name}"), e))?;

            tracing::info!(
                uri = %uri,
                component = comp_idx,
                payload = %stored_payload.path.display(),
                output = %target_name,
                "processing payload"
            );

            // `size` is the input file (compressed); the function returns the
            // uncompressed/written size. Cheap fs::metadata for context.
            let compressed = std::fs::metadata(&stored_payload.path)
                .map(|m| m.len())
                .unwrap_or(0);
            let process_started = std::time::Instant::now();
            let (image_size, _hash) = crate::streaming::process_raw_payload(
                &stored_payload.path,
                &manifest.raw_bytes,
                comp_idx,
                key_unwrap.as_deref(),
                &expected_digest,
                writer,
            )
            .map_err(|e| BackendError::Internal(format!("payload processing ({uri}): {e}")))?;
            let process_elapsed = process_started.elapsed();

            let compressed_mb = compressed as f64 / 1_048_576.0;
            let uncompressed_mb = image_size as f64 / 1_048_576.0;
            let secs = process_elapsed.as_secs_f64();
            let mb_per_sec = if secs > 0.0 {
                uncompressed_mb / secs
            } else {
                0.0
            };
            tracing::info!(
                uri = %uri,
                elapsed_ms = process_elapsed.as_millis() as u64,
                "payload written: {} ({:.2} MB compressed → {:.2} MB at {:.2} MB/s)",
                target_name,
                compressed_mb, uncompressed_mb, mb_per_sec,
            );
        }

        // Create a validated result for the OTA install
        let transfer_id = self.next_id();
        Ok(transfer_id)
    }

    /// Handle manifest upload (first file in flash session).
    pub(super) async fn handle_manifest_upload(
        &self,
        stream: PackageStream,
        _content_length: Option<u64>,
    ) -> BackendResult<String> {
        use futures::StreamExt;

        // Buffer the manifest entirely (it's small, <100KB).  Hash
        // as we go so `verify_part` can compare against the SOVD
        // layer's upload-time SHA-256.
        use sha2::Digest;
        let mut data = Vec::new();
        let mut hasher = sha2::Sha256::new();
        let mut stream = stream;
        while let Some(chunk) = stream.next().await {
            let bytes = chunk.map_err(|e| BackendError::Internal(format!("stream: {e}")))?;
            hasher.update(&bytes);
            data.extend_from_slice(&bytes);
            if data.len() > 100 * 1024 {
                return Err(BackendError::InvalidRequest(
                    "manifest too large (>100KB)".into(),
                ));
            }
        }

        tracing::info!(size = data.len(), "manifest uploaded, validating");

        // Validate
        let min_security_ver = {
            let nv = self
                .nv
                .lock()
                .map_err(|_| BackendError::Internal("lock".into()))?;
            let rb = *self.running_bank.lock().unwrap();
            nv.read_fw_meta(self.bank_set, rb)
                .map(|m| m.min_security_ver)
                .unwrap_or(0)
        };

        let mut validated = crate::streaming::validate_manifest(
            &data,
            self.manifest_provider.as_ref(),
            min_security_ver,
        )?;

        // Check if this is an integrated envelope (has inline payloads)
        let envelope = sumo_codec::decode::decode_envelope(&data)
            .map_err(|e| BackendError::Internal(format!("decode manifest: {e:?}")))?;
        let has_integrated = !envelope.integrated_payloads.is_empty();
        let manifest = sumo_onboard::manifest::Manifest { envelope };
        let total_components = manifest.component_count();
        // Detached payload PARTS — not the same thing as components. A part
        // exists only where the manifest declares an `image_digest`, which is
        // exactly what `handle_payload_upload` and `reconcile_unpushed` demand
        // per part. An administrative-disable manifest carries one component and
        // NO digest, so it owes ZERO uploads; counting components instead told
        // the session to await a payload that could never arrive.
        let parts: Vec<usize> = (0..total_components)
            .filter(|i| manifest.image_digest(*i).is_some())
            .collect();
        let payload_parts = parts.len();
        // Fail-closed pre-flight for a bank that declares its parts (a
        // raw-partition bank): a manifest naming a part this bank does not have
        // is refused HERE — before the session moves out of AwaitingManifest and
        // before the operator uploads a single payload byte. The provider would
        // refuse the sink anyway, but only after the whole image had crossed the
        // link. 415 is the same answer the F.D3 dispatcher gives a package
        // addressed to the wrong component: retrying these bytes cannot help.
        if let Some(declared) = &self.declared_parts {
            for i in 0..total_components {
                if manifest.image_digest(i).is_none() {
                    continue; // no payload owed (disable / policy component)
                }
                let name = crate::bank_spec::payload_target_name_for_id(manifest.component_id(i))?;
                if !declared.contains(&name) {
                    return Err(BackendError::UnsupportedMediaType(format!(
                        "manifest part '{name}' is not a part of bank '{}' (declared: {})",
                        self.entity_info.id,
                        declared
                            .iter()
                            .map(String::as_str)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )));
                }
            }
        }
        // Header-only validation is the SHARED metadata extraction and leaves
        // `disable_target` to whoever has the parsed manifest in hand (as
        // `SuitProvider::validate` and the streaming path both do). Fill it in
        // here when the provider had no opinion — `finalize_flash` reads it off
        // the parked session to route a disable manifest to enact, not install.
        if validated.disable_target.is_none() {
            validated.disable_target = manifest.disable_target();
        }

        // The target bank is settled against this manifest now, not at
        // `start_flash`: the parts an earlier staging left and that still
        // verify against this manifest's digests are kept; the rest of the
        // bank is cleared. An integrated envelope carries its payloads inline,
        // so it keeps nothing.
        let target_bank = self.determine_target_bank()?;
        let kept = self.reconcile_staging(
            target_bank,
            &manifest,
            if has_integrated { &[] } else { &parts },
        )?;

        let id = self.next_id();

        // Cache the SUIT-derived Table-261 facts keyed by this upload's
        // file_id, so `describe_update_package` can enrich GET /updates/{id}
        // later (the raw envelope is dropped after this; describe-time
        // re-parsing isn't possible). `id` is exactly the file_id the SOVD
        // wire records for the `"manifest"` part.
        {
            let meta = extract_describe_meta(&manifest, &validated.version_display);
            self.manifest_describe
                .lock()
                .unwrap()
                .insert(id.clone(), meta);
        }

        if has_integrated {
            // Integrated envelope (HSM keys, small packages) — all data present.
            // Validate and stage. Actual installation happens at ecu_reset.
            tracing::info!(manifest_id = %id, "integrated envelope — validating and staging");

            let full_validated = self
                .manifest_provider
                .validate(&data, min_security_ver)
                .inspect_err(|e| self.ratchet_time_floor_on_reject(e))
                .map_err(|e| BackendError::InvalidRequest(format!("manifest: {e}")))?;

            // Store as verified+staged package (ready for install at reset time)
            {
                let mut packages = self.packages.lock().unwrap();
                packages.insert(
                    id.clone(),
                    StoredPackage {
                        id: id.clone(),
                        validated: full_validated,
                        status: PackageStatus::Verified,
                    },
                );
            }
            let upload_sha256: [u8; 32] = hasher.clone().finalize().into();
            self.uploaded_parts
                .lock()
                .unwrap()
                .insert(id.clone(), UploadedPartLocation::Manifest { upload_sha256 });

            // Session complete — no payload uploads needed
            {
                let mut session = self.flash_session.lock().unwrap();
                *session = Some(FlashSessionState::Complete);
            }

            // Flash transfer → AwaitingActivation (staged, ready for finalize + reset)
            {
                let mut ft = self.flash_transfer.lock().unwrap();
                if let Some(ref mut t) = *ft {
                    t.state = FlashState::AwaitingActivation;
                    t.package_id = id.clone();
                }
            }

            // Self-sign the staged bank so external secure boot can
            // validate it before launch. `ivd_sign_staged_bank` (via the
            // provider's `seal`) first seeds unstreamed files from the active
            // bank so the signature covers a complete bank, then signs;
            // soft-skips when the HSM has no ivd-signing slot yet.
            self.ivd_sign_staged_bank(target_bank)?;

            return Ok(id);
        } else {
            // Manifest-only — wait for separate payload uploads.
            if payload_parts == 0 {
                tracing::info!(
                    manifest_id = %id,
                    components = total_components,
                    "manifest validated — declares no payload, nothing to transfer",
                );
            } else {
                tracing::info!(
                    manifest_id = %id,
                    components = total_components,
                    kept = kept.len(),
                    "manifest validated — awaiting {} payload(s)",
                    payload_parts - kept.len(),
                );
            }
            let present: BTreeSet<usize> = kept.iter().map(|(i, _)| *i).collect();
            let all_present = payload_parts > 0 && present.len() == payload_parts;

            // Store as package so finalize_flash can find it
            {
                let mut packages = self.packages.lock().unwrap();
                packages.insert(
                    id.clone(),
                    StoredPackage {
                        id: id.clone(),
                        validated: validated.clone(),
                        status: PackageStatus::Verified,
                    },
                );
            }
            let upload_sha256: [u8; 32] = hasher.clone().finalize().into();
            self.uploaded_parts
                .lock()
                .unwrap()
                .insert(id.clone(), UploadedPartLocation::Manifest { upload_sha256 });

            // Set package_id on flash transfer. With no payload part owed there
            // is nothing left to transfer, so settle the transfer HERE:
            // no upload will ever arrive to advance it, and the caller's
            // flash-settled wait would otherwise burn its whole window and time
            // out. The session still parks in `AwaitingPayload` — that is what
            // `finalize_flash` reads at execute to route a disable to enact.
            //
            // The kept parts are the transfer's inventory from the start; when
            // they are every part, the bank is content-complete already and is
            // sealed here, exactly as the final payload upload would.
            {
                let mut ft = self.flash_transfer.lock().unwrap();
                if let Some(ref mut t) = *ft {
                    t.package_id = id.clone();
                    t.streamed_files = kept.into_iter().map(|(_, f)| f).collect();
                    if payload_parts == 0 || all_present {
                        t.state = FlashState::AwaitingActivation;
                    }
                }
            }

            if all_present {
                *self.flash_session.lock().unwrap() = Some(FlashSessionState::Complete);
                tracing::info!("every part already staged — ready for transferexit");
                self.ivd_sign_staged_bank(target_bank)?;
            } else {
                *self.flash_session.lock().unwrap() = Some(FlashSessionState::AwaitingPayload {
                    manifest_bytes: data,
                    validated,
                    parts,
                    present,
                });
            }
        }

        Ok(id)
    }

    /// Handle payload upload (subsequent files in flash session).
    /// Streams directly through decrypt → decompress → verify → write to bank.
    ///
    /// A part the client names (`addressed`, a component index resolved by
    /// [`resolve_part`]) is taken as that component: one the bank already
    /// holds is accepted without a byte written; an absent one streams under
    /// its declared digest — through a staging file renamed into the bank on
    /// a provider that stages (a file bank), straight to its part on one that
    /// cannot (fixed devices). Either way, parts arrive in any order.
    ///
    /// An unnamed part keeps the older intake: a provider that can stage bytes
    /// before their part is known takes the payload by CONTENT — the stream
    /// lands in a staging file, its inner digest names the manifest component
    /// it is, and only then is it renamed into the bank as that component's
    /// part. A provider that cannot takes them in manifest order, each
    /// streamed straight to its part.
    pub(super) async fn handle_payload_upload(
        &self,
        stream: PackageStream,
        addressed: Option<usize>,
    ) -> BackendResult<String> {
        // Extract session state
        let (manifest_bytes, parts, present) = {
            let session = self.flash_session.lock().unwrap();
            match session.as_ref() {
                Some(FlashSessionState::AwaitingPayload {
                    manifest_bytes,
                    parts,
                    present,
                    ..
                }) => (manifest_bytes.clone(), parts.clone(), present.clone()),
                _ => {
                    return Err(BackendError::InvalidRequest(
                        "no active flash session".into(),
                    ))
                }
            }
        };
        let absent = absent_parts(&parts, &present);
        let total = parts.len();

        let key_unwrap = self.manifest_provider.key_unwrap_for_decryption();

        // Parse manifest for this component's info
        let envelope = sumo_codec::decode::decode_envelope(&manifest_bytes)
            .map_err(|e| BackendError::Internal(format!("decode manifest: {e:?}")))?;
        let manifest = sumo_onboard::manifest::Manifest { envelope };
        let digest_of = |i: usize| -> BackendResult<Vec<u8>> {
            manifest
                .image_digest(i)
                .map(|d| d.0.bytes.clone())
                .ok_or_else(|| BackendError::Internal(format!("no digest for component {i}")))
        };

        let target_bank = self.determine_target_bank()?;

        // A part the bank already holds, sent again: accepted as it stands,
        // nothing written.
        let already_staged = |i: usize, image_hash: [u8; 32]| -> BackendResult<String> {
            let name = crate::bank_spec::payload_target_name_for_id(manifest.component_id(i))?;
            tracing::info!(component = i, part = %name, "payload is a part already staged — accepted, discarded");
            let id = self.next_id();
            self.uploaded_parts.lock().unwrap().insert(
                id.clone(),
                UploadedPartLocation::OnDisk {
                    bank: target_bank,
                    name,
                    inner_sha256: image_hash,
                },
            );
            Ok(id)
        };
        if let Some(i) = addressed.filter(|i| present.contains(i)) {
            use futures::StreamExt;
            let mut stream = stream;
            while let Some(chunk) = stream.next().await {
                chunk.map_err(|e| BackendError::Internal(format!("stream: {e}")))?;
            }
            let digest = <[u8; 32]>::try_from(digest_of(i)?.as_slice())
                .map_err(|_| BackendError::Internal(format!("digest of component {i}")))?;
            return already_staged(i, digest);
        }

        // The part this upload streams as: the one named, else the next in
        // manifest order — what a sequential intake expects, and whose
        // decryption context a content-addressed intake uses.
        let Some(next) = addressed.or_else(|| absent.first().copied()) else {
            return Err(BackendError::InvalidRequest(
                "every part of the manifest is already staged".into(),
            ));
        };

        // Stream straight through: network → decrypt → decompress →
        // hash → sink. No on-disk ciphertext scratch — flash I/O
        // is the dominant cost on the device and writing the payload
        // twice (once as .tmp, once unpacked) doubles it for nothing.
        let process_started = std::time::Instant::now();
        let (comp_idx, target_name, inbound, image_size, image_hash) = match self
            .bank_provider
            .open_staging_writer(target_bank)
        {
            Ok((writer, handle)) => {
                tracing::info!(
                    "processing payload ({} of {} parts still owed) — {}",
                    absent.len(),
                    total,
                    if addressed.is_some() {
                        "addressed by name"
                    } else {
                        "matched by content"
                    },
                );
                let processed = crate::streaming::process_payload_stream(
                    stream,
                    manifest_bytes.clone(),
                    next,
                    key_unwrap.clone(),
                    addressed.map(digest_of).transpose()?,
                    writer,
                )
                .await;
                let (inbound, image_size, image_hash) = match processed {
                    Ok(x) => x,
                    Err(e) => {
                        let _ = self.bank_provider.discard_staged(target_bank, handle);
                        return Err(e);
                    }
                };
                let matches = |i: &usize| {
                    manifest
                        .image_digest(*i)
                        .is_some_and(|d| d.0.bytes.as_slice() == image_hash.as_slice())
                };
                let found = addressed.or_else(|| absent.iter().copied().find(matches));
                let Some(comp_idx) = found else {
                    let _ = self.bank_provider.discard_staged(target_bank, handle);
                    if let Some(i) = parts.iter().copied().find(matches) {
                        return already_staged(i, image_hash);
                    }
                    return Err(BackendError::Internal(
                        "payload matches no component of the manifest".into(),
                    ));
                };
                let target_name =
                    crate::bank_spec::payload_target_name_for_id(manifest.component_id(comp_idx))?;
                if let Err(e) =
                    self.bank_provider
                        .commit_staged(target_bank, handle.clone(), &target_name)
                {
                    let _ = self.bank_provider.discard_staged(target_bank, handle);
                    return Err(sink_error(&format!("commit staged {target_name}"), e));
                }
                (comp_idx, target_name, inbound, image_size, image_hash)
            }
            Err(BankError::Unsupported(_)) => {
                let comp_idx = next;
                // Name the bank file from the component-id part, NOT the
                // payload uri: the uri is the content-address fetch
                // reference (sha256:<outer>) and would otherwise land the
                // file as `sha256:…` (un-bootable).
                let target_name =
                    crate::bank_spec::payload_target_name_for_id(manifest.component_id(comp_idx))?;
                // Open the payload sink through the bank provider — it owns
                // where the bytes land and creates the bank dir as needed.
                let writer = self
                    .bank_provider
                    .open_payload_writer(target_bank, &target_name)
                    .map_err(|e| sink_error(&format!("open payload sink {target_name}"), e))?;
                tracing::info!(
                    component = comp_idx,
                    target = %target_name,
                    "processing payload {}/{}",
                    comp_idx + 1,
                    total,
                );
                let (inbound, image_size, image_hash) = crate::streaming::process_payload_stream(
                    stream,
                    manifest_bytes.clone(),
                    comp_idx,
                    key_unwrap.clone(),
                    Some(digest_of(comp_idx)?),
                    writer,
                )
                .await?;
                (comp_idx, target_name, inbound, image_size, image_hash)
            }
            Err(e) => return Err(sink_error("open staging sink", e)),
        };
        let process_elapsed = process_started.elapsed();
        let uri = manifest.uri(comp_idx).unwrap_or("#firmware").to_string();

        // Readback-verify BEFORE this upload is acked: re-hash the bytes now on
        // the medium and confirm they match what the streaming pipeline wrote.
        // A short/interrupted write (e.g. the node reset that raced the "staged"
        // ack on the rig) is caught HERE as a staging failure, so we never seal +
        // ack a bank the post-reset boot can't mount. Mirrors `verify_part`'s
        // mapping: wrong bytes on disk = 4xx, read fault = 5xx.
        //
        // How much this proves DEPENDS ON THE SINK. The raw-partition sink is
        // `O_SYNC` + fsync (`PartitionBankProvider`), so there the re-hash really
        // does read the eMMC. The staging-FILE sink (VMs, hsm, rt) has no barrier,
        // so this re-hash can read straight back through the page cache it just
        // filled and pass with dirty bytes. Adding a per-file `fsync` here was
        // tried (sumo-machine-manager 26fc2d9) and REVERTED: it made rig reboots
        // hang far more often, and it turned an infallible `File::flush` into a
        // fallible one, so an `fsync` refusal failed the upload outright. The
        // durability barrier for file-backed banks is still an OPEN QUESTION and
        // belongs at ONE point before the reset, not interleaved per file here —
        // see tasks/vm-flash-durability-and-commit-witness.md.
        self.bank_provider
            .verify_payload(target_bank, &target_name, &image_hash)
            .map_err(|e| sink_error(&format!("staging verify {target_name}"), e))?;

        // Note the part beside the bank BEFORE the upload is acked, then
        // record the freshly-hashed file for `ivd_sign_staged_bank` so it
        // doesn't need to re-walk + re-hash this payload from disk when
        // sealing the bank.
        let staged = hsm::ivd::IvdFile {
            relative_path: target_name.clone(),
            sha256: image_hash.to_vec(),
            size: image_size as u64,
        };
        self.record_staged_part(target_bank, &staged)?;
        {
            let mut ft = self.flash_transfer.lock().unwrap();
            if let Some(ref mut t) = *ft {
                t.streamed_files.push(staged);
            }
        }

        let compressed_mb = inbound as f64 / 1_048_576.0;
        let uncompressed_mb = image_size as f64 / 1_048_576.0;
        let secs = process_elapsed.as_secs_f64();
        // Throughput is uncompressed bytes per second — the sustained
        // decrypt+decompress+write rate, which is what determines wall time.
        let mb_per_sec = if secs > 0.0 {
            uncompressed_mb / secs
        } else {
            0.0
        };
        tracing::info!(
            component = comp_idx,
            uri = %uri,
            elapsed_ms = process_elapsed.as_millis() as u64,
            "payload written: {} ({:.2} MB compressed → {:.2} MB at {:.2} MB/s)",
            target_name,
            compressed_mb, uncompressed_mb, mb_per_sec,
        );

        // Advance session state
        let all_done = {
            let mut session = self.flash_session.lock().unwrap();
            let all_present = match *session {
                Some(FlashSessionState::AwaitingPayload {
                    ref parts,
                    ref mut present,
                    ..
                }) => {
                    present.insert(comp_idx);
                    absent_parts(parts, present).is_empty()
                }
                _ => false,
            };
            if all_present {
                // All payloads received
                *session = Some(FlashSessionState::Complete);
                tracing::info!("all payloads received — ready for transferexit");

                // Update flash transfer state to AwaitingActivation
                let mut ft = self.flash_transfer.lock().unwrap();
                if let Some(ref mut t) = *ft {
                    t.state = FlashState::AwaitingActivation;
                    t.image_size = image_size as u64;
                }
            }
            all_present
        };

        if all_done {
            // Bank dir is content-final; IVD-sign before the caller proceeds
            // to finalize_flash. `ivd_sign_staged_bank` (via the provider's
            // `seal`) seeds unstreamed files from the active bank first so the
            // signature covers a complete bank.
            self.ivd_sign_staged_bank(target_bank)?;
        }

        let id = self.next_id();
        self.uploaded_parts.lock().unwrap().insert(
            id.clone(),
            UploadedPartLocation::OnDisk {
                bank: target_bank,
                name: target_name.clone(),
                inner_sha256: image_hash,
            },
        );
        Ok(id)
    }
}
