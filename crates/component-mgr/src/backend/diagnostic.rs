use super::*;

#[async_trait]
impl<D: BlockDevice + Send + 'static> DiagnosticBackend for ComponentBackend<D> {
    fn entity_info(&self) -> &EntityInfo {
        &self.entity_info
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    /// F.D5: report the lifecycle shape so SOVDd's /campaigns
    /// coordinator orders Banked-vs-Singleshot finalize correctly
    /// (sw-update-architecture.md §5).  HSM and other single-bank
    /// targets are singleshot; everything else (host-os, VMs, RT
    /// core, slave-ECU components) is banked.
    fn update_shape(&self) -> &'static str {
        if self.config.single_bank {
            "singleshot"
        } else {
            "banked"
        }
    }

    // --- Data ---

    async fn list_parameters(&self) -> BackendResult<Vec<ParameterInfo>> {
        let nv = self
            .nv
            .lock()
            .map_err(|_| BackendError::Internal("lock".into()))?;
        let comp_id = &self.entity_info.id;

        let has_health = self.vm_service_addr.is_some();

        // Bank + manifest presence are resolved ONCE here and reused for both
        // the identity-DID list gate (below) and the vendor
        // `x-ota-installed-manifest` advertisement (further down) — same
        // authority `read_data` / the cache overlay use. `verified_bank_manifest`
        // memoises per-bank, so the later x-ota check is a cache hit.
        let serving = self.serving_bank();
        let manifest_present = self.verified_bank_manifest(serving).is_some();

        let mut params: Vec<ParameterInfo> = DID_REGISTRY
            .iter()
            .filter(|d| {
                has_health || (d.did != did::DID_GUEST_STATE && d.did != did::DID_HEARTBEAT_SEQ)
            })
            // Advertise the F187–F19E SW-identity DIDs ONLY when the serving
            // bank has a committed signed manifest — they read from `did_cache`
            // via the manifest overlay, so on a manifest-less bank they would
            // be LISTED but 404 on read (list/read disagreement, spec C-031).
            // Hardware-identity + factory + runtime + dynamic DIDs read from NV
            // regardless and stay listed unconditionally.
            .filter(|d| manifest_present || !is_identity_did(d.did))
            .map(|d| ParameterInfo {
                id: d.id.to_string(),
                name: d.name.to_string(),
                description: None,
                unit: None,
                data_type: Some(d.data_type.to_string()),
                read_only: !d.writable,
                href: format!("/vehicle/v1/components/{comp_id}/data/{}", d.id),
                did: Some(format!("{:04X}", d.did)),
                category: Some(DataCategory::from_did(d.did)),
            })
            .collect();

        // Add runtime DIDs
        {
            let active = *self.running_bank.lock().unwrap();
            if let Some(runtime) = nv.read_runtime(self.bank_set, active) {
                for i in 0..runtime.did_count as usize {
                    let did_num = runtime.dids[i].did;
                    if DID_REGISTRY.iter().any(|d| d.did == did_num) {
                        continue;
                    }
                    let id = format!("runtime_{:04X}", did_num);
                    params.push(ParameterInfo {
                        id: id.clone(),
                        name: format!("Runtime DID 0x{:04X}", did_num),
                        description: None,
                        unit: None,
                        data_type: Some("bytes".to_string()),
                        read_only: false,
                        href: format!("/vehicle/v1/components/{comp_id}/data/{id}"),
                        did: Some(format!("{:04X}", did_num)),
                        category: Some(DataCategory::from_did(did_num)),
                    });
                }
            }
        }

        // Vendor data parameter: the booted bank's signed IVD manifest
        // (per-file inventory + identity + signature). Advertised only when a
        // verifiable manifest actually exists — absent on the no-HSM smoke path
        // or a never-flashed bank, so we don't fabricate a parameter that would
        // 404 on read. Reuses the `serving` bank + `manifest_present` resolved
        // at the top (same authority gating the identity DIDs above), so this
        // and the identity-DID gate can never disagree.
        tracing::info!(component = %self.entity_info.id, serving_bank = ?serving, running_bank = ?*self.running_bank.lock().unwrap(), "ivd-route: list_data picking bank for installed-manifest advertisement");
        if manifest_present {
            params.push(ParameterInfo {
                id: INSTALLED_MANIFEST_PARAM_ID.to_string(),
                name: "Installed firmware manifest (signed IVD)".to_string(),
                description: Some(
                    "Committed bank's signature-verified IVD manifest: \
                     per-file name + sha256 inventory, firmware SW identity, \
                     and the device signature + manifest bytes (base64) for \
                     downstream re-verification."
                        .to_string(),
                ),
                unit: None,
                data_type: Some("object".to_string()),
                read_only: true,
                href: format!(
                    "/vehicle/v1/components/{comp_id}/data/{INSTALLED_MANIFEST_PARAM_ID}"
                ),
                did: None,
                category: Some(DataCategory::IdentData),
            });
        }

        // Vendor data parameter: this component's update-mode (banked &
        // rollbackable vs single-bank & irreversible). A STABLE config property —
        // advertised + readable unconditionally (even pre-flash), unlike the
        // installed manifest, so an offboard twin can sync rollback-capability the
        // same way it syncs firmware identity.
        params.push(ParameterInfo {
            id: UPDATE_MODE_PARAM_ID.to_string(),
            name: "Component update-mode".to_string(),
            description: Some(
                "How this component updates: banked (A/B + trial + rollback) or \
                 singleshot (single-bank, write-through, irreversible — e.g. the \
                 HSM keystore). Carries update_mode / supports_rollback / \
                 dual_bank / reset_kind. Stable per-component config; readable any \
                 time, even before first flash."
                    .to_string(),
            ),
            unit: None,
            data_type: Some("object".to_string()),
            read_only: true,
            href: format!("/vehicle/v1/components/{comp_id}/data/{UPDATE_MODE_PARAM_ID}"),
            did: None,
            category: Some(DataCategory::IdentData),
        });

        Ok(params)
    }

    /// SOVD §7.21 `GET /components/{id}/logs` — served only when the
    /// deployment config gives this component a [`LogSource`]
    /// (`capabilities.logs` gates the route in sovd-api). A guest VM is
    /// proxied to its in-guest log-agent; the host component tails its
    /// own files. Errors degrade to an EMPTY list with one `warn` — a
    /// down VM must not turn a log read into a 500.
    async fn get_logs(&self, filter: &LogFilter) -> BackendResult<Vec<LogEntry>> {
        // Query every configured source and merge. Each entry carries a stable,
        // self-describing id (see `log_id_*`) so get_log / get_log_content /
        // delete_log can route back to the right source without server state.
        let mut entries: Vec<LogEntry> = Vec::new();
        for source in &self.config.log_sources {
            match source {
                LogSource::GuestAgent { url } => match query_log_agent(url, filter).await {
                    Some(e) => entries.extend(e),
                    None => tracing::warn!(
                        component = %self.entity_info.id, url = %url,
                        "log-agent unreachable — skipping this source"
                    ),
                },
                LogSource::HostFiles { globs } => entries.extend(host_file_logs(globs, filter)),
                LogSource::HostDumps { dir } => entries.extend(host_dump_logs(dir, filter)),
                LogSource::Slog2 => entries.extend(slog2_logs(filter)),
                LogSource::Slog2Segments {
                    dir,
                    stem,
                    live_dir,
                } => entries.extend(slog2_segments_logs(dir, stem, live_dir.as_deref(), filter)),
            }
        }
        // Merge order: newest first (mirrors the gateway + single-source shape).
        entries.sort_by_key(|e| std::cmp::Reverse(e.timestamp));
        Ok(entries)
    }

    /// SOVD §7.21 paged log access + our reboot-safe cursor extension
    /// (`tasks/log-retrieval-design.md`). Overrides the trait default (one
    /// terminal page) ONLY for the pure HOST-FILE component: a component whose
    /// every source is [`LogSource::HostFiles`] pages forward over a
    /// `(boot_epoch, per-source byte offset)` cursor via [`host_file_logs_paged`].
    ///
    /// Multi-source handling (design doc step 5): a component that mixes in a
    /// GuestAgent or HostDumps source falls back to the DEFAULT single terminal
    /// page (the whole `get_logs` result, `next_cursor = None`). Those sources
    /// have no monotonic ordering key yet (guest paging is the journald-cursor
    /// follow-up; dumps are a whole-file catalog, not a line stream), and
    /// conflating a paged host offset with an unpaged dump list in one cursor
    /// would be incorrect. Picking the simplest correct option: paginate iff the
    /// source set is purely HostFiles; otherwise defer to the terminal-page
    /// default. A client's "loop until next_cursor is None" still terminates in
    /// one step against the fallback, exactly as with any non-paging backend.
    async fn get_logs_paged(&self, filter: &LogFilter) -> BackendResult<LogPage> {
        let only_host_files = !self.config.log_sources.is_empty()
            && self
                .config
                .log_sources
                .iter()
                .all(|s| matches!(s, LogSource::HostFiles { .. }));

        if only_host_files {
            // Merge every HostFiles source's globs into one source set — the
            // per-source cursor keys on the file stem, so multiple globs page
            // as one coherent resource.
            let mut globs: Vec<String> = Vec::new();
            for s in &self.config.log_sources {
                if let LogSource::HostFiles { globs: g } = s {
                    globs.extend(g.iter().cloned());
                }
            }
            return Ok(host_file_logs_paged(&globs, filter, current_boot_epoch()));
        }

        // A read SCOPED to one file source (`filter.source` names a resolved file
        // stem, set by the per-source route `/logs/sources/{name}`) pages via that
        // file's reboot-safe byte-offset cursor — even on a MULTI-source host
        // component (HostFiles + Slog2 ring + Slog2Segments), because the source
        // scope makes it unambiguous (mirrors the slog2-history branch below).
        // `host_file_logs_paged` filters to `filter.source` internally, so passing
        // the merged globs yields just that source's page + cursor. Without this,
        // a per-file read on Tier-2 fell through to the terminal default and
        // returned next_cursor=None despite the catalog advertising cursor:true.
        if let Some(src) = filter.source.as_deref() {
            let mut globs: Vec<String> = Vec::new();
            for s in &self.config.log_sources {
                if let LogSource::HostFiles { globs: g } = s {
                    globs.extend(g.iter().cloned());
                }
            }
            if !globs.is_empty()
                && resolve_log_files(&globs)
                    .iter()
                    .any(|p| source_name(p) == src)
            {
                return Ok(host_file_logs_paged(&globs, filter, current_boot_epoch()));
            }
        }

        // A SOLE GuestAgent source pages via the guest's `/logs/page` (journald
        // `__CURSOR` — opaque + reboot-safe on its own, so it passes straight
        // through as our cursor; no host boot_epoch wrapping needed). Only the
        // single-GuestAgent case: mixing a guest cursor with host offsets or a
        // dump catalog in one opaque token would be incorrect (same reasoning as
        // the HostFiles-only gate). An unreachable guest degrades to an empty
        // terminal page, never a 500.
        if self.config.log_sources.len() == 1 {
            if let LogSource::GuestAgent { url } = &self.config.log_sources[0] {
                return Ok(match query_log_agent_paged(url, filter).await {
                    Some(page) => page,
                    None => {
                        tracing::warn!(
                            component = %self.entity_info.id, url = %url,
                            "log-agent /logs/page unreachable — empty terminal page"
                        );
                        LogPage {
                            items: Vec::new(),
                            next_cursor: None,
                            oldest_cursor: None,
                            tip_cursor: None,
                        }
                    }
                });
            }
        }

        // A read scoped to the persisted-segments source (`filter.source ==
        // "slog2" — the resumable timeline, set by the per-source route
        // `/logs/sources/{name}`)
        // pages via the reboot-safe <seq>:<offset> cursor — even on a MULTI-source
        // host component (Slog2 + HostFiles + Slog2Segments), because the source
        // scope makes it unambiguous. Find the configured segments source.
        if filter.source.as_deref() == Some(SLOG2_SEGMENTS_SOURCE) {
            if let Some(LogSource::Slog2Segments {
                dir,
                stem,
                live_dir,
            }) = self
                .config
                .log_sources
                .iter()
                .find(|s| matches!(s, LogSource::Slog2Segments { .. }))
            {
                return Ok(slog2_segments_paged(dir, stem, live_dir.as_deref(), filter));
            }
        }

        // Everything else (mixed sources, dumps): one terminal page (mirrors the
        // trait default). A client's "loop until next_cursor is None" terminates
        // in one step.
        Ok(LogPage {
            items: self.get_logs(filter).await?,
            next_cursor: None,
            oldest_cursor: None,
            tip_cursor: None,
        })
    }

    // =====================================================================
    // SOVD §7.20 bulk-data — HOST-FILE log download (C-120 + C-121).
    //
    // The inline `LogPage` cursor above is the quick, non-normative view of a
    // component's logs; this is the spec-native "get ALL logs" path: a `logs`
    // bulk-data category whose ITEMS are the individual host log files, each
    // downloaded whole via `GET .../bulk-data/logs/{id}`.
    //
    // Scope: HOST-FILE sources (host-local log files) AND GUEST sources (a
    // guest VM's log files, proxied from its in-guest log-agent's `/files`
    // bulk-data endpoint) both contribute items to the `logs` category. Guest
    // and host items live in the SAME category, distinguished by their item-id
    // scheme (see `guest_bulk_id` / the host `b64url(path)` scheme). HostDumps
    // (which carries its own `dump:host:*` id scheme under the §7.21 log routes)
    // is still NOT a bulk-data category here. We override only the three
    // bulk-data trait methods; get_logs / get_logs_paged / the dump routes are
    // untouched.
    // =====================================================================

    /// `GET /components/{id}/bulk-data` — the categories this component exposes.
    /// A component with at least one [`LogSource::HostFiles`] OR
    /// [`LogSource::GuestAgent`] source offers a single `logs` category (its
    /// downloadable log files — host-local and/or guest). HostDumps-only
    /// components fall back to the trait default (empty).
    /// `GET /logs/sources` — the per-source catalog (vendor extension). Expands the
    /// device-internal `LogSource` set into the wire `LogSourceInfo` list a client
    /// enumerates then reads one at a time (never a cross-source merge). Dynamic:
    /// `HostFiles` globs are RESOLVED here, so one glob config yields one entry per
    /// currently-present file stem — newly-dropped files appear automatically.
    async fn list_log_sources(&self) -> BackendResult<Vec<LogSourceInfo>> {
        let mut out: Vec<LogSourceInfo> = Vec::new();
        for source in &self.config.log_sources {
            match source {
                // The QNX ring: ONE journal source, many emitters (in
                // fields.emitter). cursor:false — no reboot-safe ring cursor yet
                // (tasks/qnx-log-segments-design.md); emitters:[] — enumerating
                // them is a full ring walk, deferred (a client discovers them via
                // fields.emitter / x-log-emitter-exclude).
                LogSource::Slog2 => out.push(LogSourceInfo {
                    name: SLOG2_SOURCE.to_string(),
                    kind: LogSourceKind::Journal,
                    cursor: false,
                    emitters: Vec::new(),
                }),
                // Each resolved file is its OWN source (its stem). File sources
                // page reboot-safely (byte-offset cursor via host_file_logs_paged).
                LogSource::HostFiles { globs } => {
                    for path in resolve_log_files(globs) {
                        out.push(LogSourceInfo {
                            name: source_name(&path),
                            kind: LogSourceKind::File,
                            cursor: true,
                            emitters: Vec::new(),
                        });
                    }
                }
                // A dump directory is one Dump source (message-passing artifacts).
                LogSource::HostDumps { .. } => out.push(LogSourceInfo {
                    name: "dumps".to_string(),
                    kind: LogSourceKind::Dump,
                    cursor: false,
                    emitters: Vec::new(),
                }),
                // Phase 2: enumerate the guest's OWN sources via its
                // `GET /logs/sources` (one per stream: doip-edge, slog2, …), each
                // with its own cursor. The name round-trips as a real `source=`
                // filter the guest can satisfy — fixing the Phase-1 bug where the
                // synthetic `"guest"` name matched no guest record so per-source
                // reads were always empty. An OLDER agent (no route) or an
                // unreachable guest → fall back to the single synthetic source, so
                // a Phase-1 guest still lists (and reads bare `/logs`).
                LogSource::GuestAgent { url } => match query_log_agent_sources(url).await {
                    Some(sources) if !sources.is_empty() => {
                        for s in sources {
                            out.push(LogSourceInfo {
                                name: s.name,
                                kind: if s.kind == "file" {
                                    LogSourceKind::File
                                } else {
                                    LogSourceKind::Journal
                                },
                                cursor: s.cursor,
                                emitters: Vec::new(),
                            });
                        }
                    }
                    _ => out.push(LogSourceInfo {
                        name: "guest".to_string(),
                        kind: LogSourceKind::Journal,
                        cursor: true,
                        emitters: Vec::new(),
                    }),
                },
                // The drainer's persisted ring: a durable, reboot-safe journal
                // paged by the <seq>:<offset> cursor — cursor:true (unlike the
                // volatile `slog2` ring).
                LogSource::Slog2Segments { .. } => out.push(LogSourceInfo {
                    name: SLOG2_SEGMENTS_SOURCE.to_string(),
                    kind: LogSourceKind::Journal,
                    cursor: true,
                    emitters: Vec::new(),
                }),
            }
        }
        // Stable order + dedup by name (two globs could resolve the same stem, OR
        // a file stem could collide with a built-in source name — e.g. a
        // `/dev/shmem/slog2.log` glob vs the drained `slog2` segments source). On a
        // name collision, PREFER the higher-value source so a plain file can never
        // shadow a cursor-pageable journal: sort by name, then cursor-capable
        // first, then Journal-kind first — `dedup_by` keeps the first of each
        // equal-named run, so the preferred one survives.
        fn kind_rank(k: &LogSourceKind) -> u8 {
            match k {
                LogSourceKind::Journal => 0,
                LogSourceKind::File => 1,
                LogSourceKind::Dump => 2,
            }
        }
        out.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| b.cursor.cmp(&a.cursor)) // cursor:true before false
                .then_with(|| kind_rank(&a.kind).cmp(&kind_rank(&b.kind)))
        });
        out.dedup_by(|a, b| a.name == b.name);
        Ok(out)
    }

    async fn list_bulk_data_categories(&self) -> BackendResult<Vec<BulkCategory>> {
        let has_files = self.config.log_sources.iter().any(|s| {
            matches!(
                s,
                LogSource::HostFiles { .. } | LogSource::GuestAgent { .. }
            )
        });
        if has_files {
            Ok(vec![BulkCategory {
                name: "logs".to_string(),
            }])
        } else {
            Ok(vec![])
        }
    }

    /// `GET /components/{id}/bulk-data/{category}` — the downloadable items in a
    /// category, honouring the created-before/after filter. Only `logs` is known
    /// here; any other name → `EntityNotFound` (the trait-default contract the
    /// api layer maps to 404).
    ///
    /// Each item is one downloadable log file. HOST items: one file resolved
    /// from every `HostFiles` source's globs, id = base64url of the file's FULL
    /// path bytes (stateless — [`get_bulk_data`] decodes it straight back;
    /// re-validated against the live glob set on download). GUEST items: one
    /// file from each `GuestAgent`'s `/files` catalog, id = [`guest_bulk_id`]
    /// (namespaced so download can route it back to that agent). A down guest
    /// contributes zero items (never an error) — see the warn-and-skip below.
    async fn list_bulk_data(
        &self,
        category: &str,
        filter: &BulkDataFilter,
    ) -> BackendResult<Vec<BulkDataItem>> {
        // `logs` is the only category, and it exists only when the component
        // has a HostFiles OR GuestAgent source — otherwise it is as unknown as
        // any other name (a HostDumps-only component must 404 here, matching
        // list_bulk_data_categories which returns []).
        let has_files = self.config.log_sources.iter().any(|s| {
            matches!(
                s,
                LogSource::HostFiles { .. } | LogSource::GuestAgent { .. }
            )
        });
        if category != "logs" || !has_files {
            return Err(BackendError::EntityNotFound(format!(
                "bulk-data category: {category}"
            )));
        }

        // Gather every file from every HostFiles source (globs resolve to a
        // sorted, deduped file set — same resolver the tail/paged readers use,
        // so the catalog and the line views agree on what "the logs" are).
        let mut items: Vec<BulkDataItem> = Vec::new();
        for source in &self.config.log_sources {
            match source {
                LogSource::GuestAgent { url } => {
                    // Proxy the guest's `/files` catalog. A down/unreachable guest
                    // contributes ZERO items (warn + skip) — a component with a
                    // down VM must still answer 200 with whatever else it has, never
                    // a 500 (mirrors get_logs' degrade-gracefully contract).
                    let files = match fetch_guest_files(url).await {
                        Some(f) => f,
                        None => {
                            tracing::warn!(
                                component = %self.entity_info.id, url = %url,
                                "log-agent /files unreachable — skipping guest bulk-data"
                            );
                            continue;
                        }
                    };
                    for f in files {
                        // Filter on the guest file's `modified` (epoch secs) → UTC,
                        // matching the host-file mtime filter. A modified we can't
                        // represent is treated as the epoch (kept unless filtered).
                        let created = chrono::DateTime::<Utc>::from_timestamp(f.modified as i64, 0)
                            .unwrap_or(chrono::DateTime::<Utc>::UNIX_EPOCH);
                        if let Some(after) = filter.created_after {
                            if created <= after {
                                continue;
                            }
                        }
                        if let Some(before) = filter.created_before {
                            if created >= before {
                                continue;
                            }
                        }
                        items.push(BulkDataItem {
                            // Namespaced id carrying (url, guest file id) so
                            // get_bulk_data routes the download back to this agent.
                            id: guest_bulk_id(url, &f.id),
                            size: f.size,
                            created,
                            mime: "text/plain".to_string(),
                            source: Some(f.source),
                        });
                    }
                }
                LogSource::HostFiles { globs } => {
                    for path in resolve_log_files(globs) {
                        // The id is base64url of the path's UTF-8 text, so download
                        // can decode it straight back (no unsafe OS-string round-trip,
                        // portable to QNX). A non-UTF-8 path can't produce a stable
                        // text id — skip it (log file paths are UTF-8 in practice).
                        let Some(path_str) = path.to_str() else {
                            continue;
                        };
                        let created = file_mtime(&path);
                        // Filter: keep items created STRICTLY after created_after and
                        // STRICTLY before created_before (matches the model docs).
                        if let Some(after) = filter.created_after {
                            if created <= after {
                                continue;
                            }
                        }
                        if let Some(before) = filter.created_before {
                            if created >= before {
                                continue;
                            }
                        }
                        // size: best-effort file length (0 if metadata unavailable).
                        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                        items.push(BulkDataItem {
                            // Full path (UTF-8 text), base64url — decodable back to
                            // the path on download (stateless + stable across restarts).
                            id: b64url(path_str.as_bytes()),
                            size,
                            created,
                            mime: "text/plain".to_string(),
                            source: Some(source_name(&path)),
                        });
                    }
                }
                // HostDumps carries its own §7.21 `dump:host:*` catalog — not a
                // bulk-data source here (see the scope note above).
                LogSource::HostDumps { .. } => {}
                // Slog2 is a live line stream (like HostFiles' tails), not a set of
                // downloadable whole files — no bulk-data catalog contribution.
                LogSource::Slog2 => {}
                // Slog2Segments is a journal (line stream, cursor-paged), not a
                // whole-file download catalog — no bulk-data contribution either.
                LogSource::Slog2Segments { .. } => {}
            }
        }

        // Deterministic order so listings are stable: by created, then id.
        items.sort_by(|a, b| a.created.cmp(&b.created).then_with(|| a.id.cmp(&b.id)));
        Ok(items)
    }

    /// `GET /components/{id}/bulk-data/logs/{id}` — download one log file whole.
    /// Returns the bytes inline ([`BulkDataDownload::Inline`]). Routes by id
    /// scheme: a `guest:` id (see [`guest_bulk_id`]) is proxied to that guest's
    /// log-agent; anything else is a host-file id (bare base64url path).
    ///
    /// The whole point of bulk-data is "get ALL logs", so — unlike the 64 KiB
    /// tail reader — we do NOT truncate to a small window. We do cap the read at
    /// [`MAX_BULK_BYTES`] to guard against OOM on a runaway file: a file at or
    /// under the cap is served whole; a larger file is served TRUNCATED to the
    /// first `MAX_BULK_BYTES`. (Future work: when a file exceeds the cap, answer
    /// `202`/`307` via [`BulkDataDownload::Async`]/`Redirect` and stream it
    /// out-of-band instead of truncating — not implemented in this step.)
    async fn get_bulk_data(&self, category: &str, id: &str) -> BackendResult<BulkDataDownload> {
        if category != "logs" {
            return Err(BackendError::EntityNotFound(format!(
                "bulk-data category: {category}"
            )));
        }

        // GUEST tier: a `guest:<b64url(url)>:<guest_id>` id names a file behind
        // one of this component's GuestAgent sources. Route it back to that
        // agent and proxy the download.
        if let Some((url, guest_id)) = parse_guest_bulk_id(id) {
            // SECURITY / defense-in-depth (mandatory): the guest agent ALSO
            // guards its own /files/{id} allow-list, but the HOST must never
            // proxy an id it didn't itself just advertise. Two checks:
            //   1. the url must be one of THIS component's live GuestAgent
            //      sources — a crafted id can't make us connect anywhere else;
            //   2. re-list that agent's /files and require guest_id to be in the
            //      set right now — so we only proxy a file the agent currently
            //      offers. Either failing is indistinguishable from "no such
            //      item" → EntityNotFound.
            let url_is_ours = self
                .config
                .log_sources
                .iter()
                .any(|s| matches!(s, LogSource::GuestAgent { url: u } if u == &url));
            if !url_is_ours {
                return Err(BackendError::EntityNotFound(format!(
                    "bulk-data item: {id}"
                )));
            }
            // Re-validate against the live guest catalog. A down guest (None) or
            // an id no longer present → 404 (a down guest never yields a 500).
            let advertised = fetch_guest_files(&url)
                .await
                .map(|files| files.iter().any(|f| f.id == guest_id))
                .unwrap_or(false);
            if !advertised {
                return Err(BackendError::EntityNotFound(format!(
                    "bulk-data item: {id}"
                )));
            }
            // Proxy the download. An unreachable agent at THIS point (raced with
            // the re-list) is again a 404, not a 500.
            let bytes = fetch_guest_file(&url, &guest_id)
                .await
                .ok_or_else(|| BackendError::EntityNotFound(format!("bulk-data item: {id}")))?;
            return Ok(BulkDataDownload::Inline {
                mime: "text/plain".to_string(),
                bytes,
            });
        }

        // HOST tier: decode the id back to a path. The id is base64url of the path's UTF-8
        // text (see list_bulk_data); a malformed id, or bytes that aren't valid
        // UTF-8, can't name one of our log files → 404.
        let path_str = b64url_decode(id)
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or_else(|| BackendError::EntityNotFound(format!("bulk-data item: {id}")))?;
        let requested = std::path::PathBuf::from(path_str);

        // SECURITY (mandatory): the id encodes an arbitrary path, so we must NOT
        // read whatever it decodes to — a crafted id could otherwise point at
        // `/etc/passwd` or any file the daemon can read (path-traversal /
        // arbitrary-read). We re-resolve the component's live HostFiles globs and
        // require the requested path to be one of the files that set currently
        // yields. Anything not in the set is indistinguishable from "no such
        // item" → EntityNotFound. This confines download to exactly the files
        // `list_bulk_data` advertised, and re-resolving (rather than trusting the
        // decoded path) keeps the allow-list authoritative even as files rotate.
        let in_allowed_set = self.config.log_sources.iter().any(|s| {
            matches!(s, LogSource::HostFiles { globs }
                if resolve_log_files(globs).iter().any(|p| p == &requested))
        });
        if !in_allowed_set {
            return Err(BackendError::EntityNotFound(format!(
                "bulk-data item: {id}"
            )));
        }

        // Read up to the cap. Bounded by MAX_BULK_BYTES via take(); a file at or
        // under the cap is served whole, a larger one is truncated to the cap.
        use std::io::Read;
        let file = std::fs::File::open(&requested).map_err(|e| {
            BackendError::Internal(format!("read log {}: {e}", requested.display()))
        })?;
        let mut bytes = Vec::new();
        file.take(MAX_BULK_BYTES)
            .read_to_end(&mut bytes)
            .map_err(|e| {
                BackendError::Internal(format!("read log {}: {e}", requested.display()))
            })?;

        Ok(BulkDataDownload::Inline {
            mime: "text/plain".to_string(),
            bytes,
        })
    }

    /// SOVD §7.15 `GET /components/{id}/scripts` — the registered TESTS a guest
    /// exposes, proxied from its in-guest test-agent `/tests`. Only when a
    /// `test_agent_url` is configured (guest-VM only today); otherwise none. An
    /// unreachable agent degrades to an empty list (warn), never a 500 — same
    /// discipline as the log proxy.
    async fn list_scripts(&self) -> BackendResult<Vec<ScriptInfo>> {
        let Some(url) = &self.config.test_agent_url else {
            return Ok(vec![]);
        };
        match query_test_agent(url).await {
            Some(scripts) => Ok(scripts),
            None => {
                tracing::warn!(
                    component = %self.entity_info.id, url = %url,
                    "test-agent /tests unreachable — empty scripts list"
                );
                Ok(vec![])
            }
        }
    }

    /// SOVD §7.15 `POST /components/{id}/scripts/{script}/executions` — run a
    /// registered test. The guest test-agent `POST /tests/{id}/run` is
    /// SYNCHRONOUS: it runs the test to completion (bounded by the entry's
    /// `timeout_ms`) and answers with a `RunResult`, so by the time this proxy
    /// call returns the run is already finished. We therefore build a terminal
    /// (`status = Done`) [`ScriptExecution`], store it under a generated exec_id
    /// (`<script_id>-<n>`, monotonic per process — no `rand` in this QNX tree),
    /// and return it. SOVDd answers 202+Location regardless; a follow-up GET
    /// reads the stored terminal result.
    ///
    /// Log-cursor BRACKET: we snapshot the component's log tip BEFORE and AFTER
    /// the run via the same paged-logs path the component already exposes
    /// (`get_logs_paged(&LogFilter::default()).tip_cursor`), so a tester can page
    /// exactly this run's window. `None` bracket = the tip was unavailable for
    /// this component's log source (e.g. a guest cursor the agent didn't report).
    ///
    /// Errors, never panics: no `test_agent_url` → `NotSupported`; an unreachable
    /// / erroring agent → `Transport` (the run couldn't be dispatched).
    async fn start_script(&self, script_id: &str) -> BackendResult<ScriptExecution> {
        let Some(url) = self.config.test_agent_url.clone() else {
            return Err(BackendError::NotSupported(format!(
                "component '{}' exposes no scripts (no test_agent_url)",
                self.entity_info.id
            )));
        };

        // Snapshot the log tip just before spawning the run (bracket lower bound).
        let log_from = self.current_log_tip().await;
        let started = Utc::now();

        let run = run_test_agent(&url, script_id).await.ok_or_else(|| {
            BackendError::Transport(format!(
                "test-agent POST /tests/{script_id}/run unreachable at {url}"
            ))
        })?;

        // Snapshot the tip again after the run finished (bracket upper bound).
        let ended = Utc::now();
        let log_to = self.current_log_tip().await;

        let n = self.script_exec_seq.fetch_add(1, Ordering::Relaxed);
        let exec_id = format!("{script_id}-{n}");
        let exec = ScriptExecution {
            exec_id: exec_id.clone(),
            script_id: script_id.to_string(),
            status: ScriptStatus::Done,
            verdict: Some(agent_verdict_to_core(&run.verdict)),
            exit_code: run.exit_code,
            duration_ms: Some(run.duration_ms),
            message: run.message,
            stdout_tail: (!run.stdout_tail.is_empty()).then_some(run.stdout_tail),
            stderr_tail: (!run.stderr_tail.is_empty()).then_some(run.stderr_tail),
            started: started.to_rfc3339(),
            ended: Some(ended.to_rfc3339()),
            log_from,
            log_to,
        };
        self.script_executions
            .lock()
            .unwrap()
            .insert(exec_id, exec.clone());
        Ok(exec)
    }

    /// SOVD §7.15 `GET …/scripts/{script}/executions/{exec}` — read a stored
    /// execution. `EntityNotFound` if the exec_id is unknown (rolled off / typo).
    async fn get_script_execution(
        &self,
        _script_id: &str,
        exec_id: &str,
    ) -> BackendResult<ScriptExecution> {
        self.script_executions
            .lock()
            .unwrap()
            .get(exec_id)
            .cloned()
            .ok_or_else(|| BackendError::EntityNotFound(exec_id.to_string()))
    }

    /// SOVD §7.15 `GET …/scripts/{script}/executions` — the exec ids recorded
    /// for this script (this process's lifetime; in-memory only).
    async fn list_script_executions(&self, script_id: &str) -> BackendResult<Vec<String>> {
        let mut ids: Vec<String> = self
            .script_executions
            .lock()
            .unwrap()
            .values()
            .filter(|e| e.script_id == script_id)
            .map(|e| e.exec_id.clone())
            .collect();
        ids.sort();
        Ok(ids)
    }

    /// SOVD §7.9 `GET /components/{id}/diagnostics` — the READ-ONLY system probes
    /// a guest exposes, proxied from its in-guest diag-agent `/probes`. Only when
    /// a `diag_agent_url` is configured (guest-VM only); otherwise none. An
    /// unreachable agent degrades to an empty list (warn), never a 500 — same
    /// discipline as the log / scripts proxies.
    async fn list_diagnostics(&self) -> BackendResult<Vec<DiagnosticInfo>> {
        // Host in-process probes (supernova / on-box components).
        if self.config.host_diagnostics {
            return Ok(host_diag_probes());
        }
        let Some(url) = &self.config.diag_agent_url else {
            return Ok(vec![]);
        };
        match query_diag_agent(url).await {
            Some(probes) => Ok(probes),
            None => {
                tracing::warn!(
                    component = %self.entity_info.id, url = %url,
                    "diag-agent /probes unreachable — empty diagnostics list"
                );
                Ok(vec![])
            }
        }
    }

    /// SOVD §7.9 `GET /components/{id}/diagnostics/{probe}` — gather one probe,
    /// proxied from the guest diag-agent `GET /probes/{id}`. The agent gathers
    /// synchronously and returns its own `{ok, output, message}`; we pass it
    /// through. No `diag_agent_url` → `NotSupported`; an unreachable agent →
    /// `Transport` (couldn't dispatch the read — distinct from a probe that ran
    /// and reported `ok=false`).
    async fn read_diagnostic(&self, probe_id: &str) -> BackendResult<DiagnosticResult> {
        // Host in-process gather (supernova / on-box components).
        if self.config.host_diagnostics {
            return Ok(host_gather(probe_id));
        }
        let Some(url) = self.config.diag_agent_url.clone() else {
            return Err(BackendError::NotSupported(format!(
                "component '{}' exposes no diagnostics (no diag_agent_url)",
                self.entity_info.id
            )));
        };
        match read_diag_probe(&url, probe_id).await {
            Some(result) => Ok(result),
            None => Err(BackendError::Transport(format!(
                "diag-agent unreachable at {url} for probe '{probe_id}'"
            ))),
        }
    }

    /// SOVD §7.21 `GET /components/{id}/logs/{id}` — one entry's metadata.
    /// The id is self-describing (`<kind>:<source>:<key>`); we re-derive the
    /// entry from its backing source rather than hold server state.
    async fn get_log(&self, log_id: &str) -> BackendResult<LogEntry> {
        self.find_log_entry(log_id)
            .await
            .ok_or_else(|| BackendError::EntityNotFound(log_id.to_string()))
    }

    /// SOVD §7.21 `GET …/logs/{id}` with `Accept: application/octet-stream` —
    /// the entry's raw bytes. For a dump this is the file; for a standard line
    /// it is the line text (utf-8).
    async fn get_log_content(&self, log_id: &str) -> BackendResult<Vec<u8>> {
        match parse_log_id(log_id) {
            Some(ParsedLogId::HostDump { file }) => {
                let path = self.resolve_dump_path(log_id, &file)?;
                std::fs::read(&path).map_err(|e| {
                    BackendError::Internal(format!("read dump {}: {e}", path.display()))
                })
            }
            Some(ParsedLogId::Line) => {
                // A standard line's "content" is the line itself.
                let entry = self
                    .find_log_entry(log_id)
                    .await
                    .ok_or_else(|| BackendError::EntityNotFound(log_id.to_string()))?;
                Ok(entry.message.into_bytes())
            }
            Some(ParsedLogId::GuestDump) => Err(BackendError::NotSupported(
                "guest dump content (guest /dumps proxy not yet wired)".to_string(),
            )),
            None => Err(BackendError::EntityNotFound(log_id.to_string())),
        }
    }

    /// SOVD §7.21 `DELETE …/logs/{id}` — ack/remove. Only meaningful for a
    /// retrievable dump (unlink the file + sidecar); a standard journal/text
    /// line is not individually deletable.
    async fn delete_log(&self, log_id: &str) -> BackendResult<()> {
        match parse_log_id(log_id) {
            Some(ParsedLogId::HostDump { file }) => {
                let path = self.resolve_dump_path(log_id, &file)?;
                std::fs::remove_file(&path).map_err(|e| {
                    BackendError::Internal(format!("delete dump {}: {e}", path.display()))
                })?;
                // Best-effort sidecar removal. It is `<name>.meta.json` (the full
                // filename + suffix, per host_dump_logs) — NOT with_extension,
                // which would drop the dump's own extension (crash.bin →
                // crash.meta.json) and orphan the real sidecar.
                let _ = std::fs::remove_file(path.with_file_name(format!("{file}.meta.json")));
                Ok(())
            }
            Some(ParsedLogId::Line) => Err(BackendError::NotSupported(
                "a standard log line cannot be individually deleted".to_string(),
            )),
            Some(ParsedLogId::GuestDump) => Err(BackendError::NotSupported(
                "guest dump delete (guest /dumps proxy not yet wired)".to_string(),
            )),
            None => Err(BackendError::EntityNotFound(log_id.to_string())),
        }
    }

    async fn read_data(&self, param_ids: &[String]) -> BackendResult<Vec<DataValue>> {
        // No NV mutex acquired here. Health DIDs go through query_vm_health
        // (a fast HTTP loopback to vm-service); all other DIDs are served
        // from the in-memory `did_cache`, populated at startup and kept in
        // sync after every NV write. This eliminates the NV-mutex
        // contention that turned the campaign-viewer's poll cycle into
        // a 10-15 s blocked dance during flash on QNX/eMMC.
        let mut values = Vec::new();

        for param_id in param_ids {
            // Vendor parameter: the booted bank's signed IVD manifest.
            // Intercepted before `resolve_param` (which only knows
            // DID-registry / hex ids). 404 when no committed manifest exists —
            // never fabricated. Bank comes from the boot selector (the
            // authority the VM boots from), not the stale `running_bank` cache.
            if param_id == INSTALLED_MANIFEST_PARAM_ID {
                let serving = self.serving_bank();
                tracing::info!(component = %self.entity_info.id, serving_bank = ?serving, running_bank = ?*self.running_bank.lock().unwrap(), "ivd-route: read_data x-ota-installed-manifest requested");
                let vm = match self.verified_bank_manifest(serving) {
                    Some(vm) => {
                        tracing::info!(
                            component = %self.entity_info.id,
                            bank = ?serving,
                            gen = vm.gen,
                            "ivd-route: read_data x-ota-installed-manifest served",
                        );
                        vm
                    }
                    None => {
                        tracing::info!(
                            component = %self.entity_info.id,
                            bank = ?serving,
                            "ivd-route: read_data x-ota-installed-manifest 404 (NotInstalled)",
                        );
                        return Err(BackendError::EntityNotFound(format!(
                            "{INSTALLED_MANIFEST_PARAM_ID}: no committed IVD manifest for {} bank {:?}",
                            self.entity_info.id, serving
                        )));
                    }
                };
                values.push(DataValue {
                    id: param_id.clone(),
                    name: "Installed firmware manifest (signed IVD)".to_string(),
                    value: installed_manifest_json(&vm),
                    unit: None,
                    timestamp: Utc::now(),
                    raw: None,
                    did: None,
                    length: None,
                });
                continue;
            }

            // Vendor parameter: this component's update-mode. Stable config —
            // always served (no 404), even pre-flash, so the offboard twin can
            // classify rollback-capability for the composition guard.
            if param_id == UPDATE_MODE_PARAM_ID {
                values.push(DataValue {
                    id: param_id.clone(),
                    name: "Component update-mode".to_string(),
                    value: self.update_mode_json(),
                    unit: None,
                    timestamp: Utc::now(),
                    raw: None,
                    did: None,
                    length: None,
                });
                continue;
            }

            let (did_num, reg) = resolve_param(param_id)
                .ok_or_else(|| BackendError::ParameterNotFound(param_id.clone()))?;

            // Health DIDs — query vm-service HTTP API, or fall back to a
            // configured health probe for activator-backed components that
            // have no vm-service (RT/M7 surfaces its state via `m7loader -q`
            // wrapped by `HealthProbe`).
            if did_num == did::DID_GUEST_STATE || did_num == did::DID_HEARTBEAT_SEQ {
                let health = match self.vm_service_addr.as_ref() {
                    Some(sock) => query_vm_health(sock, &self.entity_info.id).await,
                    None => self.health_probe.as_ref().and_then(|p| p.probe()),
                };
                let (value, raw) = match (did_num, &health) {
                    (did::DID_GUEST_STATE, Some(h)) => {
                        let s = guest_state_str(h.guest_state);
                        (
                            serde_json::Value::String(s.to_string()),
                            format!("{:08x}", h.guest_state),
                        )
                    }
                    (did::DID_GUEST_STATE, None) => (
                        serde_json::Value::String("offline".to_string()),
                        "ffffffff".to_string(),
                    ),
                    (did::DID_HEARTBEAT_SEQ, Some(h)) => {
                        (serde_json::json!(h.hb_seq), format!("{:08x}", h.hb_seq))
                    }
                    (did::DID_HEARTBEAT_SEQ, None) => {
                        (serde_json::json!(0), "00000000".to_string())
                    }
                    _ => unreachable!(),
                };
                let name = reg.map(|r| r.name).unwrap_or(param_id.as_str());
                values.push(DataValue {
                    id: param_id.clone(),
                    name: name.to_string(),
                    value,
                    unit: None,
                    timestamp: Utc::now(),
                    raw: Some(raw),
                    did: Some(format!("{:04X}", did_num)),
                    length: Some(4),
                });
                continue;
            }

            // `committed` follows the bank report, not NV, so it is read live.
            let cached = if did_num == did::DID_COMMITTED {
                Some(self.committed_did_bytes())
            } else {
                self.did_cache
                    .read()
                    .expect("did_cache poisoned")
                    .get(&did_num)
                    .cloned()
            };
            match cached {
                Some(bytes) => {
                    let value = did_value_to_json(did_num, &bytes, reg);
                    let raw_hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                    let name = reg.map(|r| r.name).unwrap_or(param_id.as_str());
                    values.push(DataValue {
                        id: param_id.clone(),
                        name: name.to_string(),
                        value,
                        unit: None,
                        timestamp: Utc::now(),
                        raw: Some(raw_hex),
                        did: Some(format!("{:04X}", did_num)),
                        length: Some(bytes.len()),
                    });
                }
                None => {
                    return Err(BackendError::ParameterNotFound(param_id.clone()));
                }
            }
        }

        Ok(values)
    }

    async fn write_data(&self, param_id: &str, value: &[u8]) -> BackendResult<()> {
        let (did_num, reg) = resolve_param(param_id)
            .ok_or_else(|| BackendError::ParameterNotFound(param_id.to_string()))?;

        if let Some(r) = reg {
            if !r.writable {
                return Err(BackendError::InvalidRequest(format!(
                    "DID 0x{:04X} ({}) is read-only",
                    did_num, r.name
                )));
            }
        }

        let mut nv = self.nv_write()?;
        match did::write_did(&mut *nv, self.bank_set, did_num, value) {
            Ok(true) => Ok(()),
            Ok(false) => Err(BackendError::Internal("runtime DID store full".into())),
            Err(e) => Err(BackendError::Internal(e.to_string())),
        }
    }

    // --- Faults ---

    async fn get_faults(&self, _filter: Option<&FaultFilter>) -> BackendResult<FaultsResult> {
        let nv = self
            .nv
            .lock()
            .map_err(|_| BackendError::Internal("lock".into()))?;
        let active = *self.running_bank.lock().unwrap();
        let runtime = nv.read_runtime(self.bank_set, active).unwrap_or_default();

        let faults: Vec<Fault> = (0..runtime.dtc_count as usize)
            .map(|i| {
                let dtc = &runtime.dtcs[i];
                let code = format!("{:06X}", dtc.dtc_number);
                let active = dtc.status & 0x01 != 0;
                Fault {
                    id: format!("dtc_{code}"),
                    code: code.clone(),
                    severity: if active {
                        FaultSeverity::Error
                    } else {
                        FaultSeverity::Warning
                    },
                    message: format!("DTC {code}"),
                    category: None,
                    first_occurrence: None,
                    last_occurrence: None,
                    occurrence_count: None,
                    active,
                    status: Some(serde_json::json!(dtc.status)),
                    href: format!(
                        "/vehicle/v1/components/{}/faults/dtc_{code}",
                        self.entity_info.id
                    ),
                }
            })
            .collect();

        Ok(FaultsResult {
            faults,
            status_availability_mask: None,
        })
    }

    async fn clear_faults(&self, _group: Option<u32>) -> BackendResult<ClearFaultsResult> {
        let mut nv = self.nv_write()?;
        let active = *self.running_bank.lock().unwrap();
        let mut runtime = nv.read_runtime(self.bank_set, active).unwrap_or_default();

        let cleared = runtime.dtc_count as u32;
        runtime.dtc_count = 0;
        runtime.dtcs = std::array::from_fn(|_| DtcEntry::default());

        nv.write_runtime(self.bank_set, active, &mut runtime)
            .map_err(|e| BackendError::Internal(e.to_string()))?;

        Ok(ClearFaultsResult {
            success: true,
            cleared_count: cleared,
            message: format!("Cleared {cleared} faults"),
        })
    }

    // --- Operations ---

    /// Cheap discoverability: the host/device component advertises the vendor
    /// `x-attest-time` op (id + name + href); everything else keeps the
    /// empty list. That op's execution is served by `start_operation`.
    async fn list_operations(&self) -> BackendResult<Vec<OperationInfo>> {
        let mut ops = Vec::new();
        let id = &self.entity_info.id;
        // attest-time is device-global (ratchets the shared safe-time floor); it
        // needs an HSM (the floor slot) and is advertised ONCE, on the component
        // the platform nominates via `with_attest_time`, so it doesn't appear
        // per-firmware-component.
        if self.hsm_provider.is_some() && self.attest_time {
            let op = ATTEST_TIME_OP_ID;
            ops.push(OperationInfo {
                id: op.to_string(),
                name: "Attest trusted time (advance the safe-time floor)".to_string(),
                description: Some(
                    "POST a SoftwareAuthority-signed SUIT manifest (hex); the device \
                     ratchets its safe-time floor from the manifest's signed signing_time."
                        .to_string(),
                ),
                parameters: vec![],
                requires_security: false,
                security_level: 0,
                href: format!("/vehicle/v1/components/{id}/operations/{op}/executions"),
            });
        }
        Ok(ops)
    }

    async fn start_operation(
        &self,
        operation_id: &str,
        params: &[u8],
    ) -> BackendResult<OperationExecution> {
        match operation_id {
            // Attest trusted time: verify a SoftwareAuthority-signed SUIT manifest
            // (params = the raw SUIT envelope bytes) and ratchet the safe-time floor
            // from its signed signing_time. Verify-only — validate_header_only does
            // signature+digest against the sw-authority anchor, no payload/bank work;
            // min_security_ver = 0 so an OLD manifest is accepted here (its signed
            // time is still a trusted lower bound; the floor is monotonic, so an
            // older-than-floor value is a harmless no-op).
            ATTEST_TIME_OP_ID => {
                let validated = self
                    .manifest_provider
                    .validate_header_only(params, 0)
                    .map_err(|e| {
                        BackendError::InvalidRequest(format!("attest-time manifest: {e}"))
                    })?;
                match validated.signing_time_secs {
                    Some(iat) => {
                        self.ratchet_time_floor(iat);
                        let floor = self
                            .hsm_provider
                            .as_ref()
                            .and_then(|h| h.lock().ok())
                            .and_then(|g| crate::sovd::time_floor::TimeFloor::read(&*g).ok())
                            .unwrap_or(iat);
                        Ok(OperationExecution::completed(
                            operation_id,
                            operation_id,
                            serde_json::json!({ "signing_time_secs": iat, "floor_secs": floor }),
                        ))
                    }
                    // Signature verified, but the manifest carried no signing_time —
                    // nothing to attest. A caller error (send one with an iat).
                    None => Err(BackendError::InvalidRequest(
                        "attest-time manifest has no signed signing_time to attest".to_string(),
                    )),
                }
            }
            _ => Err(BackendError::OperationNotFound(operation_id.to_string())),
        }
    }

    // --- Update package catalog (ISO 17978-3 §7.18.3 Table 261) ---

    /// Enrich `GET /updates/{id}` from the uploaded SUIT manifest.
    ///
    /// Starts from the format-agnostic [`default_descriptor_from_context`]
    /// base, then overrides the fields the SUIT envelope genuinely provides:
    /// a meaningful `update_name`, optional release `notes`, and the
    /// `updated`/`affected` component entity-paths.
    ///
    /// The manifest's SUIT facts were cached when the `"manifest"` bulk-data
    /// part arrived, keyed by that part's `file_id`. We locate the
    /// `part_id == "manifest"` part in the context, look the facts up by its
    /// `file_id`, and enrich. Absent/garbled manifest → the default base is
    /// returned unchanged (the GET never errors). No locks are held across an
    /// `.await` (the lookup returns owned clones; there is no `.await` here).
    async fn describe_update_package(
        &self,
        ctx: &UpdatePackageContext<'_>,
    ) -> BackendResult<UpdatePackageDescriptor> {
        let mut desc = default_descriptor_from_context(ctx);

        // The orchestrator uploads the SUIT envelope as the part whose
        // part_id is exactly "manifest"; its file_id is the cache key.
        let Some(manifest_part) = ctx.parts.iter().find(|p| p.part_id == "manifest") else {
            return Ok(desc);
        };
        let Some((update_name, notes, component_paths)) =
            self.manifest_describe_facts(manifest_part.file_id)
        else {
            // No cached facts (parse failed, or this file_id isn't a
            // manifest) — keep the honest default.
            return Ok(desc);
        };

        if let Some(name) = update_name {
            desc.update_name = name;
        }
        if let Some(n) = notes {
            desc.notes = Some(n);
        }

        // The manifest names this component; the SOVD-addressable entity it
        // maps to is this backend's own component id (the bank set this
        // ComponentBackend serves). Report it as both updated (version changed) and
        // affected. `default_descriptor_from_context` already seeded
        // `affected_components` with this same path; set `updated_components`
        // only when the manifest actually carried component identifiers.
        if !component_paths.is_empty() {
            let entity_path = format!("/vehicle/v1/components/{}", self.entity_info.id);
            desc.updated_components = vec![entity_path.clone()];
            desc.affected_components = vec![entity_path];
        }

        Ok(desc)
    }

    // --- Package management ---

    async fn receive_package(&self, data: &[u8]) -> BackendResult<String> {
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

        let validated = self
            .manifest_provider
            .validate(data, min_security_ver)
            .inspect_err(|e| self.ratchet_time_floor_on_reject(e))
            .map_err(|e| BackendError::InvalidRequest(format!("manifest validation: {e}")))?;

        if validated.component_name != self.entity_info.id {
            return Err(BackendError::InvalidRequest(format!(
                "manifest targets '{}', but this is '{}'",
                validated.component_name, self.entity_info.id
            )));
        }

        // Administrative-disable manifest: no payload to stage — enact the
        // disable against this component's `Deactivator` instead of storing a
        // package.
        if validated.disable_target.is_some() {
            self.enact_disable_manifest().await?;
            return Ok(self.next_id());
        }

        let id = self.next_id();

        // Single-shot upload still carries the raw envelope here, so cache
        // the SUIT describe facts keyed by this file_id for GET /updates/{id}.
        if let Ok(envelope) = sumo_codec::decode::decode_envelope(data) {
            let manifest = sumo_onboard::manifest::Manifest { envelope };
            let meta = extract_describe_meta(&manifest, &validated.version_display);
            self.manifest_describe
                .lock()
                .unwrap()
                .insert(id.clone(), meta);
        }

        let mut packages = self.packages.lock().unwrap();
        packages.insert(
            id.clone(),
            StoredPackage {
                id: id.clone(),
                validated,
                status: PackageStatus::Verified,
            },
        );

        Ok(id)
    }

    async fn receive_package_stream(
        &self,
        stream: PackageStream,
        content_length: Option<u64>,
    ) -> BackendResult<String> {
        // Check flash session state — determines how to handle this upload
        let session_state = {
            let session = self.flash_session.lock().unwrap();
            match session.as_ref() {
                Some(FlashSessionState::AwaitingManifest) => Some("manifest"),
                Some(FlashSessionState::AwaitingPayload { .. }) => Some("payload"),
                _ => None,
            }
        };

        match session_state {
            Some("manifest") => {
                return self.handle_manifest_upload(stream, content_length).await;
            }
            Some("payload") => {
                return self.handle_payload_upload(stream, None).await;
            }
            _ => {
                // No active flash session — legacy integrated envelope path
            }
        }

        // --- Legacy path: integrated SUIT envelope (HSM keys, etc.) ---

        // This path never went through `start_flash`, so it must enforce the
        // same trial-mode guard here before touching any bank. Otherwise a flash
        // issued while a trial is uncommitted resolves the target to the
        // *committed* bank (`active.other()`) and `prepare_target_bank_dir` wipes
        // the rollback target. (No-op for single-bank/HSM, which has no trial.)
        self.ensure_flash_can_start()?;

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

        tracing::info!(
            bank_set = ?self.bank_set,
            content_length = ?content_length,
            "streaming package upload (legacy envelope)"
        );

        // Legacy single-POST envelope path doesn't go through start_flash, so
        // it has to set up the target bank dir itself (clear inactive bank +
        // wipe orphaned staged files) before streaming the payload.
        let target_bank = self.determine_target_bank()?;
        self.prepare_target_bank_dir(target_bank)?;

        let transfer_id = self.next_id();
        {
            let mut ft = self.flash_transfer.lock().unwrap();
            *ft = Some(FlashTransferState {
                transfer_id: transfer_id.clone(),
                package_id: String::new(),
                state: FlashState::Transferring,
                pre_reset_health: None,
                image_size: content_length.unwrap_or(0),
                streamed_files: Vec::new(),
            });
        }

        *self.upload_phase.lock().unwrap() = Some(FlashState::Transferring);

        let validated = match crate::streaming::process_envelope_stream(
            stream,
            self.manifest_provider.as_ref(),
            min_security_ver,
            Some(self.bank_provider.as_ref()),
            &self.entity_info.id,
            target_bank,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                *self.upload_phase.lock().unwrap() = None;
                let mut ft = self.flash_transfer.lock().unwrap();
                if let Some(ref mut t) = *ft {
                    t.state = FlashState::Failed;
                }
                return Err(e);
            }
        };

        *self.upload_phase.lock().unwrap() = None;

        // Administrative-disable manifest: no payload was staged — enact the
        // disable against this component's `Deactivator` and finish (there is
        // no bank to prepare). Identical enact to the single-shot path.
        if validated.disable_target.is_some() {
            *self.flash_transfer.lock().unwrap() = None;
            self.enact_disable_manifest().await?;
            return Ok(self.next_id());
        }

        {
            let mut ft = self.flash_transfer.lock().unwrap();
            if let Some(ref mut t) = *ft {
                t.state = FlashState::Preparing;
                // Hand the per-file hash inventory captured by the
                // streaming pipeline through to `ivd_sign_staged_bank`
                // so it can build the IVD manifest without re-reading
                // the bank from disk.
                t.streamed_files = validated.streamed_files.clone();
            }
        }

        let id = self.next_id();
        let mut packages = self.packages.lock().unwrap();
        packages.insert(
            id.clone(),
            StoredPackage {
                id: id.clone(),
                validated,
                status: PackageStatus::Verified,
            },
        );

        Ok(id)
    }

    /// A part the client names. While payloads are owed, a name that
    /// resolves to a part of the manifest ([`resolve_part`]) is taken as that
    /// part, in any order; one that resolves to nothing keeps the unnamed
    /// intake. Anything else — the manifest, a legacy envelope — is
    /// [`receive_package_stream`](Self::receive_package_stream).
    async fn receive_package_part(
        &self,
        part_id: &str,
        stream: PackageStream,
        content_length: Option<u64>,
    ) -> BackendResult<String> {
        let addressed = {
            let session = self.flash_session.lock().unwrap();
            match session.as_ref() {
                Some(FlashSessionState::AwaitingPayload {
                    manifest_bytes,
                    parts,
                    ..
                }) if part_id != "manifest" => {
                    let envelope = sumo_codec::decode::decode_envelope(manifest_bytes)
                        .map_err(|e| BackendError::Internal(format!("decode manifest: {e:?}")))?;
                    Some(resolve_part(
                        &sumo_onboard::manifest::Manifest { envelope },
                        parts,
                        part_id,
                    ))
                }
                _ => None,
            }
        };
        match addressed {
            Some(addressed) => {
                if addressed.is_none() {
                    tracing::info!(part = %part_id, "part id names no part of the manifest — unnamed intake");
                }
                self.handle_payload_upload(stream, addressed).await
            }
            None => self.receive_package_stream(stream, content_length).await,
        }
    }

    async fn list_packages(&self) -> BackendResult<Vec<PackageInfo>> {
        let packages = self.packages.lock().unwrap();
        Ok(packages
            .values()
            .map(|p| PackageInfo {
                id: p.id.clone(),
                size: p.validated.image_data.len(),
                target_ecu: Some(self.entity_info.id.clone()),
                version: Some(p.validated.version_display.clone()),
                status: p.status,
                created_at: None,
            })
            .collect())
    }

    async fn get_package(&self, package_id: &str) -> BackendResult<PackageInfo> {
        let packages = self.packages.lock().unwrap();
        let p = packages
            .get(package_id)
            .ok_or_else(|| BackendError::EntityNotFound(package_id.to_string()))?;
        Ok(PackageInfo {
            id: p.id.clone(),
            size: p.validated.image_data.len(),
            target_ecu: Some(self.entity_info.id.clone()),
            version: Some(p.validated.version_display.clone()),
            status: p.status,
            created_at: None,
        })
    }

    async fn verify_package(&self, package_id: &str) -> BackendResult<VerifyResult> {
        let packages = self.packages.lock().unwrap();
        let p = packages
            .get(package_id)
            .ok_or_else(|| BackendError::EntityNotFound(package_id.to_string()))?;

        use sha2::{Digest, Sha256};
        let hash: [u8; 32] = Sha256::digest(&p.validated.image_data).into();
        let hash_hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();

        Ok(VerifyResult {
            valid: true,
            checksum: Some(hash_hex),
            algorithm: Some("sha256".to_string()),
            error: None,
        })
    }

    async fn verify_part(&self, file_id: &str, expected_sha256: &str) -> BackendResult<()> {
        // Re-verification semantics:
        //
        // * Manifest part — the SOVD layer's `expected_sha256` is the
        //   outer (wire-bytes) hash recorded during PUT /bulk-data.
        //   We stored the same value at upload time; compare directly.
        //
        // * Detached payload — we cannot re-verify the outer hash
        //   without keeping the raw ciphertext bytes around (multi-MB
        //   per payload — flash I/O cost doubles).  Outer integrity
        //   was already validated during streaming.  Re-verify the
        //   inner hash instead: re-read the on-disk decrypted content
        //   and compare to the inner SHA-256 the streaming pipeline
        //   captured at write time (already cross-checked against the
        //   manifest's image_digest).  The SOVD-passed
        //   `expected_sha256` (outer) is informational only here.
        let location = {
            let parts = self.uploaded_parts.lock().unwrap();
            parts
                .get(file_id)
                .ok_or_else(|| {
                    BackendError::EntityNotFound(format!("no uploaded part with file_id {file_id}"))
                })
                .map(|loc| match loc {
                    UploadedPartLocation::Manifest { upload_sha256 } => {
                        UploadedPartLocation::Manifest {
                            upload_sha256: *upload_sha256,
                        }
                    }
                    UploadedPartLocation::OnDisk {
                        bank,
                        name,
                        inner_sha256,
                    } => UploadedPartLocation::OnDisk {
                        bank: *bank,
                        name: name.clone(),
                        inner_sha256: *inner_sha256,
                    },
                })?
        };
        match location {
            UploadedPartLocation::Manifest { upload_sha256 } => {
                let stored = hex::encode(upload_sha256);
                if stored.eq_ignore_ascii_case(expected_sha256) {
                    Ok(())
                } else {
                    Err(BackendError::InvalidRequest(format!(
                        "verify_part {file_id}: outer sha256 mismatch — \
                         stored {stored}, expected {expected_sha256}",
                    )))
                }
            }
            UploadedPartLocation::OnDisk {
                bank,
                name,
                inner_sha256,
            } => {
                // Re-read the staged part through the provider (it owns the
                // on-medium layout) and confirm the captured inner hash. Map
                // the provider error back to the wire variants the inline
                // version used: a hash mismatch is a bad request (the data on
                // disk is wrong), a read failure is our-fault internal.
                self.bank_provider
                    .verify_payload(bank, &name, &inner_sha256)
                    .map_err(|e| sink_error(&format!("verify_part {file_id}"), e))
            }
        }
    }

    async fn delete_package(&self, package_id: &str) -> BackendResult<()> {
        let mut packages = self.packages.lock().unwrap();
        packages
            .remove(package_id)
            .ok_or_else(|| BackendError::EntityNotFound(package_id.to_string()))?;
        Ok(())
    }

    // --- Flash ---

    async fn start_flash(&self) -> BackendResult<String> {
        self.ensure_flash_can_start()?;
        // The target bank is NOT cleared here: what it holds is settled against
        // the manifest when it arrives (`reconcile_staging`), which keeps the
        // parts an earlier staging left that still verify and removes the rest
        // before any payload streams in. Refuse a pending reboot as before.
        self.determine_target_bank()?;

        // Initialize flash session — next upload will be treated as manifest
        {
            let mut session = self.flash_session.lock().unwrap();
            *session = Some(FlashSessionState::AwaitingManifest);
        }

        // Clear stale packages from previous flash cycles so we don't
        // accidentally pick up an old verified package.
        {
            let mut packages = self.packages.lock().unwrap();
            packages.clear();
        }
        // Drop the previous cycle's part-location records; new uploads
        // re-populate as they arrive.
        self.uploaded_parts.lock().unwrap().clear();
        // Same for the manifest describe-cache — stale SUIT facts from a
        // prior flash must not leak into this session's catalog entry.
        self.manifest_describe.lock().unwrap().clear();

        let transfer_id = self.next_id();
        tracing::info!(transfer_id = %transfer_id, "flash session started — awaiting manifest upload");

        // Check if we already have a verified package (legacy integrated envelope path)
        let package_id = {
            let packages = self.packages.lock().unwrap();
            packages
                .iter()
                .find(|(_, p)| p.status == PackageStatus::Verified)
                .map(|(id, _)| id.clone())
        };

        // If no verified package yet, return the transfer_id.
        // Payloads will be processed as they arrive via receive_package_stream.
        let Some(package_id) = package_id else {
            let mut ft = self.flash_transfer.lock().unwrap();
            *ft = Some(FlashTransferState {
                transfer_id: transfer_id.clone(),
                package_id: String::new(),
                state: FlashState::Transferring,
                pre_reset_health: None,
                image_size: 0,
                streamed_files: Vec::new(),
            });
            return Ok(transfer_id);
        };
        let (
            meta,
            image_data,
            image_size,
            pre_sha256,
            pre_size,
            manifest_type,
            raw_envelope,
            signing_time_secs,
        ) = {
            let packages = self.packages.lock().unwrap();
            let p = packages
                .get(&package_id)
                .ok_or_else(|| BackendError::EntityNotFound(package_id.to_string()))?;
            let size = if let Some(s) = p.validated.image_size {
                s
            } else {
                p.validated.image_data.len() as u64
            };
            (
                p.validated.image_meta.clone(),
                p.validated.image_data.clone(),
                size,
                p.validated.image_sha256,
                p.validated.image_size,
                p.validated.manifest_type,
                p.validated.raw_envelope.clone(),
                p.validated.signing_time_secs,
            )
        };

        // Safe-time floor: ratchet from the verified manifest's signing time (iat).
        // See ratchet_time_floor — monotonic, best-effort, done as soon as the
        // manifest is verified (not gated on trial-boot / commit).
        if let Some(iat) = signing_time_secs {
            self.ratchet_time_floor(iat);
        }

        // HSM key material — route to HsmProvider, skip normal image write
        if manifest_type == ManifestType::HsmKeys {
            let envelope = raw_envelope.as_deref().ok_or_else(|| {
                BackendError::Internal("HSM key manifest missing raw envelope".into())
            })?;
            let hsm = self.hsm_provider.as_ref().ok_or_else(|| {
                BackendError::Internal("no HSM provider configured for key provisioning".into())
            })?;
            {
                let mut hsm_guard = hsm
                    .lock()
                    .map_err(|_| BackendError::Internal("HSM provider lock".into()))?;
                hsm_guard
                    .provision(envelope)
                    .map_err(|e| BackendError::Internal(format!("HSM provision: {e}")))?;

                // After provisioning, load the public trust anchors and
                // wire an HSM-backed CEK unwrapper. Device decryption
                // key bytes never leave the HSM — `HsmKeyUnwrap` calls
                // `HsmProvider::unwrap_cek_*` for each decryption.
                match hsm_guard.get_public_key(hsm::KeyRole::SoftwareAuthority) {
                    Ok(sw_key) => {
                        let ka = hsm_guard.get_public_key(hsm::KeyRole::KeyAuthority).ok();
                        drop(hsm_guard);
                        // CEK unwrap routes through the crypto handle
                        // (`HsmCryptoProvider`) — the device key never leaves the
                        // HSM. A provisioned HSM with no crypto handle is a wiring
                        // bug; surface it rather than silently skip unwrap.
                        let Some(crypto) = self.hsm_crypto.as_ref() else {
                            return Err(BackendError::Internal(
                                "HSM provisioned but no HsmCryptoProvider attached — CEK unwrap requires crypto".into(),
                            ));
                        };
                        let unwrap: std::sync::Arc<
                            dyn sumo_onboard::decryptor::KeyUnwrap + Send + Sync,
                        > = std::sync::Arc::new(hsm::HsmKeyUnwrap::from_crypto(
                            crypto.clone(),
                            hsm::KeyRole::DeviceDecryption.handle(),
                        ));
                        self.manifest_provider.update_keys(sw_key, Some(unwrap), ka);
                        tracing::info!(
                            "loaded sw-authority + key-authority; CEK unwrap routed through HSM"
                        );
                    }
                    Err(e) => {
                        tracing::warn!("HSM provisioned but failed to load sw-authority: {e}");
                    }
                }
            }

            // Update NV metadata (security_version, fw_version) via single-bank path
            let mut nv = self.nv_write()?;
            let _result =
                ota::install(&mut *nv, self.bank_set, &[], &meta, true).map_err(map_ota_error)?;

            let transfer_id = self.next_id();
            {
                let mut ft = self.flash_transfer.lock().unwrap();
                *ft = Some(FlashTransferState {
                    transfer_id: transfer_id.clone(),
                    package_id: package_id.to_string(),
                    state: FlashState::AwaitingActivation,
                    pre_reset_health: None,
                    image_size: 0,
                    streamed_files: Vec::new(),
                });
            }
            // No-op for HSM single-bank (no bank dir under images_dir; the
            // keystore lives separately) but kept for uniformity — any future
            // component with content here gets signed automatically.
            // `ivd_sign_staged_bank` (provider `seal`) seeds then signs.
            let target_bank = self.determine_target_bank()?;
            self.ivd_sign_staged_bank(target_bank)?;
            return Ok(transfer_id);
        }

        // Streaming path: image_data is empty but image was already written to disk
        let is_streamed = image_data.is_empty() && pre_sha256.is_some();
        let is_crl = image_data.is_empty() && pre_sha256.is_none();

        // The bank that install_precomputed / install just made active.
        // Captured here so the activator block below uses the
        // authoritative answer instead of re-deriving via
        // determine_target_bank() — which is racy on first-ever flash
        // (it resolves the *target* as the sibling of NV `active_bank`,
        // which install_precomputed has by then flipped, returning the
        // WRONG bank). For CRL (no install), stays None and the activator
        // block is skipped via `if !is_crl`.
        let mut installed_bank: Option<Bank> = None;
        if is_crl {
            // CRL / security-floor-only manifest — raise floor without flashing.
            let mut nv = self.nv_write()?;
            let active = *self.running_bank.lock().unwrap();
            if let Some(mut fw_meta) = nv.read_fw_meta(self.bank_set, active) {
                if meta.fw_secver > fw_meta.min_security_ver {
                    fw_meta.min_security_ver = meta.fw_secver;
                    nv.write_fw_meta(self.bank_set, active, &mut fw_meta)
                        .map_err(|e| BackendError::Internal(format!("NV write: {e}")))?;
                }
            }
        } else if is_streamed {
            // Streaming path — image already written to staged file, use pre-computed hash
            let mut nv = self.nv_write()?;
            let result = ota::install_precomputed(
                &mut *nv,
                self.bank_set,
                pre_sha256.unwrap(),
                pre_size.unwrap_or(0),
                &meta,
                self.config.single_bank,
            )
            .map_err(map_ota_error)?;

            // Payloads were already streamed directly into the target bank dir
            // at upload time. install_precomputed flipped NV — nothing else to
            // do here.
            tracing::info!(
                bank_set = ?self.bank_set,
                target_bank = ?result.target_bank,
                "OTA install committed (files already in bank dir)"
            );
            installed_bank = Some(result.target_bank);
        } else {
            // Buffered path — install from memory
            let mut nv = self.nv_write()?;
            let result = ota::install(
                &mut *nv,
                self.bank_set,
                &image_data,
                &meta,
                self.config.single_bank,
            )
            .map_err(map_ota_error)?;

            // Write firmware payload to bank directory
            if let Some(ref images_dir) = self.images_dir {
                let set_name = self.bank_spec.dir_name.as_str();
                let bank_dir_name = match result.target_bank {
                    Bank::A => "bank_a",
                    Bank::B => "bank_b",
                };
                let bank_dir = images_dir.join(set_name).join(bank_dir_name);
                let _ = std::fs::create_dir_all(&bank_dir);
                let image_path = bank_dir.join("rootfs.img");
                tracing::info!(
                    "writing {} bytes to {}",
                    image_data.len(),
                    image_path.display()
                );
                std::fs::write(&image_path, &image_data).map_err(|e| {
                    BackendError::Internal(format!(
                        "failed to write image to {}: {e}",
                        image_path.display()
                    ))
                })?;
            }
            installed_bank = Some(result.target_bank);
        }

        // Bank activation: route through the provider's `activate`, which runs
        // the activator (if any) then records the activation in the boot
        // selector. Use installed_bank captured from install_precomputed /
        // install above — that's the authoritative answer. Re-deriving via
        // determine_target_bank() here would return the OLD (now-inactive)
        // bank on first-ever flash because NV has been flipped, so its sibling
        // is the prior bank. `activate` runs on the bank we just wrote payloads
        // to. For VMs (no activator) `activate` only seals the selector —
        // matching the old activator-gated block that was skipped without an
        // activator.
        if !is_crl {
            let wrote_to = installed_bank.ok_or_else(|| {
                BackendError::Internal("installed_bank unset — unreachable for !is_crl".into())
            })?;
            if let Err(e) = self.bank_provider.activate(wrote_to) {
                tracing::error!(
                    bank_set = ?self.bank_set,
                    bank = ?wrote_to,
                    error = %e,
                    "bank activation failed during install finalize — rolling back"
                );
                let mut nv = self.nv_write()?;
                let _ = ota::rollback(&mut *nv, self.bank_set);
                return Err(BackendError::Internal(format!(
                    "bank activation failed: {e}"
                )));
            }
        }

        if !is_crl {
            let (transfer_id, target_bank) = {
                let mut ft = self.flash_transfer.lock().unwrap();
                let tb = self.determine_target_bank()?;
                if let Some(ref mut t) = *ft {
                    // Reuse existing transfer from streaming upload path
                    t.package_id = package_id.to_string();
                    t.state = FlashState::AwaitingActivation;
                    t.image_size = image_size;
                    (t.transfer_id.clone(), tb)
                } else {
                    // Buffered path — create new transfer
                    let id = self.next_id();
                    *ft = Some(FlashTransferState {
                        transfer_id: id.clone(),
                        package_id: package_id.to_string(),
                        state: FlashState::AwaitingActivation,
                        pre_reset_health: None,
                        image_size,
                        streamed_files: Vec::new(),
                    });
                    (id, tb)
                }
            };
            // Self-sign before returning. `ivd_sign_staged_bank` (provider
            // `seal`) seeds unstreamed files from the active bank first so the
            // signature covers a complete bank, then signs; no-ops when the
            // bank dir is absent (e.g. HSM single-bank components).
            self.ivd_sign_staged_bank(target_bank)?;
            return Ok(transfer_id);
        }
        // CRL: no flash transfer state — floor already applied, nothing to poll/finalize/commit

        Ok(self.next_id())
    }

    async fn get_flash_status(&self, transfer_id: &str) -> BackendResult<FlashStatus> {
        let ft = self.flash_transfer.lock().unwrap();
        let t = ft
            .as_ref()
            .ok_or_else(|| BackendError::EntityNotFound(transfer_id.to_string()))?;

        Ok(FlashStatus {
            transfer_id: t.transfer_id.clone(),
            package_id: t.package_id.clone(),
            state: t.state,
            progress: Some(FlashProgress {
                bytes_transferred: t.image_size,
                bytes_total: t.image_size,
                blocks_transferred: 1,
                blocks_total: 1,
                percent: 100.0,
            }),
            error: None,
        })
    }

    async fn finalize_flash(&self) -> BackendResult<()> {
        // Campaign/session disable enact — decided HERE, on the validated
        // manifest, POST-validation and PRE-trial, before any of the
        // reconcile/install/activate work below. A no-payload disable manifest is
        // parked in `AwaitingPayload` by the manifest upload (no payload follows),
        // so its `validated.disable_target` is the campaign path's disable signal.
        let is_disable = {
            let session = self.flash_session.lock().unwrap();
            matches!(
                session.as_ref(),
                Some(FlashSessionState::AwaitingPayload { validated, .. })
                    if validated.disable_target.is_some()
            )
        };
        if is_disable {
            // Enact against this component's Deactivator (deactivate, then the
            // sentinel record + gen ratchet, then reboot-owed), then finish like
            // an activated singleshot: a disable stages no payload and installs
            // nothing, so the reconcile/install/activate path below does not
            // apply and would otherwise hard-error demanding an image_digest the
            // disable lacks.
            self.enact_disable_manifest().await?;
            *self.flash_session.lock().unwrap() = Some(FlashSessionState::Complete);
            {
                let mut ft = self.flash_transfer.lock().unwrap();
                if let Some(ref mut t) = *ft {
                    t.state = FlashState::Activated;
                }
            }
            *self.install_source.lock().unwrap() = None;
            return Ok(());
        }
        // No re-enable step for a normal flash of a disabled component: it
        // re-enables structurally. The flash seals a real IVD into the target and
        // `activate` below moves the selector there, so `serving_bank()` reads a
        // real inventory; a rollback returns the selector to the sentinel bank,
        // i.e. disabled again.

        // Manifest-only / partial push reconciliation. The orchestrator pushed
        // the L2 manifest but no payload for some components — "the vehicle
        // already has these" (push path) or "fetch them yourself" (pull path).
        // Those components were never streamed, so the seal/sign that the
        // final payload upload normally fires never ran — finalize would
        // otherwise activate an empty, unsigned target bank (the guest can't
        // boot it → trial-boot exhaustion → auto-rollback). Detect the
        // un-pushed (absent) components and reconcile
        // it per part: copy-forward from the active bank (digest-verified),
        // else fetch by the signed content-address when the pull route
        // provided a session source; then seal the now-complete bank. Only
        // meaningful with an on-disk bank (`images_dir`); in-memory test
        // backends have no bank to reconcile and keep their prior behaviour.
        let manifest_only = if self.images_dir.is_some() {
            let session = self.flash_session.lock().unwrap();
            match session.as_ref() {
                Some(FlashSessionState::AwaitingPayload {
                    manifest_bytes,
                    parts,
                    present,
                    ..
                }) => Some((manifest_bytes.clone(), absent_parts(parts, present)))
                    .filter(|(_, absent)| !absent.is_empty()),
                _ => None,
            }
        } else {
            None
        };
        if let Some((manifest_bytes, absent)) = manifest_only {
            let target = self.determine_target_bank()?;
            let reconciled = self
                .reconcile_unpushed(&manifest_bytes, &absent, target)
                .await?;
            // Fold the reconciled files into the transfer inventory (parity with
            // the streamed path) — that inventory IS the declared part list the
            // seal below settles — then seal the now-complete bank. `seal`'s own
            // seed no-ops the just-written files and IVD-signs the full bank so
            // external secure boot / commit accept it.
            {
                let mut ft = self.flash_transfer.lock().unwrap();
                if let Some(ref mut t) = *ft {
                    t.streamed_files.extend(reconciled);
                }
            }
            self.ivd_sign_staged_bank(target)?;
            // Content-complete: advance exactly like the final payload upload would.
            *self.flash_session.lock().unwrap() = Some(FlashSessionState::Complete);
            {
                let mut ft = self.flash_transfer.lock().unwrap();
                if let Some(ref mut t) = *ft {
                    t.state = FlashState::AwaitingActivation;
                }
            }
            tracing::info!(
                bank_set = ?self.bank_set,
                target = ?target,
                reconciled_components = absent.len(),
                "manifest-only push reconciled: un-pushed components copied forward or fetched; target sealed",
            );
        }

        // Process staged package (HSM keys, firmware OTA install)
        let package_id = {
            let ft = self.flash_transfer.lock().unwrap();
            ft.as_ref()
                .map(|t| t.package_id.clone())
                .unwrap_or_default()
        };

        if !package_id.is_empty() {
            let packages = self.packages.lock().unwrap();
            if let Some(p) = packages.get(&package_id) {
                let manifest_type = p.validated.manifest_type;
                let raw_envelope = p.validated.raw_envelope.clone();
                drop(packages);

                // HSM key provisioning
                if manifest_type == ManifestType::HsmKeys {
                    if let Some(envelope) = raw_envelope.as_deref() {
                        if let Some(ref hsm) = self.hsm_provider {
                            let mut hsm_guard = hsm
                                .lock()
                                .map_err(|_| BackendError::Internal("HSM lock".into()))?;
                            hsm_guard.provision(envelope).map_err(|e| {
                                BackendError::Internal(format!("HSM provision: {e}"))
                            })?;

                            // Reload the HSM so it picks up the freshly-written
                            // keystore. The daemon's lifecycle is owned externally
                            // now (the host spawns the link-B backend); when a
                            // `post_provision_reload` hook is set, call it so the
                            // orchestrator reloads against the new keystore. There
                            // is no in-process daemon restart anymore.
                            if let Some(ref reload) = self.post_provision_reload {
                                reload();
                                tracing::info!(
                                    "HSM reloaded via post-provision hook (external daemon lifecycle)"
                                );
                            }

                            // Load keys from HSM into manifest provider.
                            // Public trust anchors come out as bytes;
                            // the device decryption key stays inside
                            // the HSM and is invoked via HsmKeyUnwrap.
                            let ka = hsm_guard.get_public_key(hsm::KeyRole::KeyAuthority).ok();
                            match hsm_guard.get_public_key(hsm::KeyRole::SoftwareAuthority) {
                                Ok(sw_key) => {
                                    drop(hsm_guard);
                                    // CEK unwrap routes through the crypto handle
                                    // (`HsmCryptoProvider`); the device key never
                                    // leaves the HSM. No crypto handle while
                                    // provisioned is a wiring bug.
                                    let Some(crypto) = self.hsm_crypto.as_ref() else {
                                        return Err(BackendError::Internal(
                                            "HSM provisioned but no HsmCryptoProvider attached — CEK unwrap requires crypto".into(),
                                        ));
                                    };
                                    let unwrap: std::sync::Arc<
                                        dyn sumo_onboard::decryptor::KeyUnwrap + Send + Sync,
                                    > = std::sync::Arc::new(hsm::HsmKeyUnwrap::from_crypto(
                                        crypto.clone(),
                                        hsm::KeyRole::DeviceDecryption.handle(),
                                    ));
                                    self.manifest_provider.update_keys(sw_key, Some(unwrap), ka);
                                    tracing::info!(
                                        "HSM keys provisioned; CEK unwrap routed through HSM"
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "HSM provisioned but failed to load sw-authority: {e}"
                                    );
                                }
                            }
                        }
                    }
                }

                // Firmware OTA: run install (rename staged files, update NV)
                if manifest_type == ManifestType::Firmware {
                    // Staged files already written during payload uploads.
                    // OTA install (NV update + rename) happens here.
                    let (meta, sha, size) = {
                        let pkg = self.packages.lock().unwrap();
                        let p = pkg.get(&package_id);
                        (
                            p.map(|p| p.validated.image_meta.clone()),
                            p.and_then(|p| p.validated.image_sha256),
                            p.and_then(|p| p.validated.image_size).unwrap_or(0),
                        )
                    };
                    if let Some(meta) = meta {
                        let mut nv = self.nv_write()?;
                        if let Err(e) = crate::ota::install_precomputed(
                            &mut *nv,
                            self.bank_set,
                            sha.unwrap_or([0; 32]),
                            size,
                            &meta,
                            self.config.single_bank,
                        ) {
                            tracing::warn!(
                                bank_set = ?self.bank_set,
                                error = %e,
                                "install_precomputed failed during finalize (NV metadata not updated)"
                            );
                        }
                    }
                }
            }
        }

        // Bank activation: route through the provider's `activate`, which runs
        // the activator (if any) then records the activation in the boot
        // selector. Read NV.active_bank directly — install_precomputed (above,
        // when it ran) just flipped it to the just-installed bank, which is
        // exactly the bank that has the payloads the activator needs.
        // determine_target_bank() would return the OTHER bank (active.other())
        // on first flash — that's empty and would make the activator fail with
        // "firmware not found". See 2c9d2d8 for the original fix to this race;
        // d25d967 re-introduced the determine_target_bank() call and reopened
        // the bug for first-ever-flash on activator-backed components. For VMs
        // (no activator) `activate` only seals the selector, so this runs
        // unconditionally.
        {
            let wrote_to = {
                let nv = self
                    .nv
                    .lock()
                    .map_err(|_| BackendError::Internal("nv lock".into()))?;
                let state = nv
                    .read_boot_state()
                    .ok_or_else(|| BackendError::Internal("no boot state".into()))?;
                state.banks[self.bank_set.as_index()].active_bank
            };
            if let Err(e) = self.bank_provider.activate(wrote_to) {
                tracing::error!(
                    bank_set = ?self.bank_set,
                    bank = ?wrote_to,
                    error = %e,
                    "bank activation failed during finalize — rolling back"
                );
                let mut nv = self.nv_write()?;
                let _ = ota::rollback(&mut *nv, self.bank_set);
                return Err(BackendError::Internal(format!(
                    "bank activation failed: {e}"
                )));
            }
        }

        let mut ft = self.flash_transfer.lock().unwrap();
        if let Some(ref mut t) = *ft {
            // Single-bank components (HSM): finalize *writes* the new keys
            // immediately to the live store. There's no reboot trial — the
            // new state is in effect now. Skip AwaitingReboot and report
            // Activated directly so the orchestrator/viewer don't see a
            // theatrical "awaiting reboot" step that never happens.
            //
            // Dual-bank (boot, hypervisor, vm1, vm2): finalize flips the
            // next-boot bank pointer; new code starts running after the
            // orchestrator-driven `ecu_reset`.
            t.state = if self.config.single_bank {
                FlashState::Activated
            } else {
                FlashState::AwaitingReboot
            };
        }

        // Any component that owes a full node ECU reset to run its just-armed
        // state marks the durable reboot-owed bit — the only record of "a node
        // reboot is owed" that survives a power cycle (or a failed/refused
        // reset), which the in-memory flash state does not. It stays set until
        // the trial is resolved (commit/rollback/abort →
        // `resolve_node_transaction`); nothing clears it at boot. It is the
        // durable "this node transaction is unresolved and needed a node reboot"
        // marker the flash gate refuses on, reported on
        // `x-ota-update-state.reboot_owed`, with `rebooted_since_arming` (from the
        // node boot id recorded here) saying whether the reboot has happened.
        //
        // This now covers BANKED `RequiresEcuReset` components (host-os), not
        // just write-through singleshots (rt). Why banked needs it: after arm,
        // `committed == false` alone reads as phase `Trial` (commit-allowed),
        // but the node hasn't rebooted into the armed bank yet — and a trial
        // that falls back to the recovery bank never will. The owed bit keeps
        // the transaction unresolved from arm until the verdict. `Local`-reset
        // components (VMs: qvm/process cycle) never owe a node reboot and are
        // excluded. Sibling-safe: the orchestrator
        // stages every component before any finalize (the ordering rt's
        // existing mark already relies on), so marking here never refuses a
        // not-yet-started sibling. See docs/design/node-update-state.md.
        if self.reset_kind() == machine_mgr::ResetKind::RequiresEcuReset {
            self.set_reboot_owed(true)?;
        }
        // The install is applied — the session-scoped pull source has served
        // its purpose (a later commit/rollback never fetches).
        *self.install_source.lock().unwrap() = None;
        Ok(())
    }

    async fn validate(&self) -> BackendResult<()> {
        // Idempotent re-validation. Accepts either pre-finalize
        // (AwaitingActivation) or post-finalize (AwaitingReboot, dual-bank)
        // — the latter lets the orchestrator down-shift to Validated for
        // re-verification across power cycles before committing to reset.
        // Already in Validated is a no-op.
        //
        // Today this is a state-only transition; a follow-up will re-read
        // the inactive bank and re-verify the SUIT signature + image hash.
        let mut ft = self.flash_transfer.lock().unwrap();
        let transfer = ft
            .as_mut()
            .ok_or_else(|| BackendError::EntityNotFound("No flash transfer in progress".into()))?;
        match transfer.state {
            FlashState::AwaitingActivation | FlashState::Validated | FlashState::AwaitingReboot => {
                transfer.state = FlashState::Validated;
                Ok(())
            }
            // Already activated — the activation event has happened, so there is
            // nothing left to validate and the state must NOT be walked back.
            // The disable manifest is the path that lands here on a banked
            // component: it wrote no bank content, and `finalize_flash` already
            // enacted it and parked the transfer Activated, so the execute
            // wire's validate step is a no-op. Also makes an execute retry safe.
            FlashState::Activated => Ok(()),
            other => Err(BackendError::InvalidRequest(format!(
                "validate() requires AwaitingActivation, Validated, AwaitingReboot, or Activated, got {:?}",
                other
            ))),
        }
    }

    async fn invalidate(&self) -> BackendResult<()> {
        // Demote a previously-validated transfer back to AwaitingActivation —
        // the orchestrator should re-call validate() before proceeding. Used
        // when the bank can't be hardware-sealed and a power cycle could
        // have introduced drift.
        let mut ft = self.flash_transfer.lock().unwrap();
        let transfer = ft
            .as_mut()
            .ok_or_else(|| BackendError::EntityNotFound("No flash transfer in progress".into()))?;
        match transfer.state {
            FlashState::Validated => {
                transfer.state = FlashState::AwaitingActivation;
                Ok(())
            }
            other => Err(BackendError::InvalidRequest(format!(
                "invalidate() requires Validated, got {:?}",
                other
            ))),
        }
    }

    async fn activate(&self) -> BackendResult<()> {
        // Schedule activation. For dual-bank components the activation
        // event is the reboot — we move to AwaitingReboot and the
        // orchestrator must call ecu_reset() to complete. For single-bank
        // components (HSM, config) the artifact write itself was the
        // activation event during finalize, so we go straight to
        // Activated; the orchestrator should then commit_flash() to
        // reach the Complete terminal.
        let mut ft = self.flash_transfer.lock().unwrap();
        let transfer = ft
            .as_mut()
            .ok_or_else(|| BackendError::EntityNotFound("No flash transfer in progress".into()))?;
        match transfer.state {
            FlashState::Validated => {
                transfer.state = if self.config.single_bank {
                    FlashState::Activated
                } else {
                    FlashState::AwaitingReboot
                };
                Ok(())
            }
            // Already activated — nothing left to schedule, and a banked
            // transfer must NOT be pushed on to AwaitingReboot from here: a
            // disable manifest wrote no bank content, so arming an owed reboot
            // for it would gate the node on a reset nothing needs. `finalize_flash`
            // enacted the disable and parked the transfer Activated; this step is
            // a no-op. Also makes an execute retry safe.
            FlashState::Activated => Ok(()),
            other => Err(BackendError::InvalidRequest(format!(
                "activate() requires Validated or Activated, got {:?}",
                other
            ))),
        }
    }

    /// Read the entity's runtime status — ISO 17978-3 §7.19.2. Liveness comes
    /// from the guest heartbeat (`ready` = running + a fresh heartbeat; otherwise
    /// `notReady`); non-guest components (no vm-service addr) are present-by-
    /// definition → `ready`. The vendor `x-runtime` block (§5.4.5) carries
    /// the heartbeat `boot_id` (a per-lifetime nonce — the orchestrator's reboot
    /// witness: a *changed* boot_id proves a fresh guest lifetime, including a
    /// node reboot), and the heartbeat `hb_seq` (liveness).
    async fn read_entity_status(&self) -> BackendResult<EntityStatusBody> {
        // Administratively disabled ⇒ skip the vm-service probe entirely (the
        // VM is down BY DESIGN — probing would only burn the health timeout)
        // and report the spec `status` as an honest `notReady`; the vendor
        // `admin_state` field below tells readers WHY.
        let disableable = self.is_disableable();
        let admin_disabled = self.admin_disabled();
        let health = if admin_disabled {
            None
        } else {
            self.query_lifecycle().await
        };
        let status = if admin_disabled {
            EntityStatus::NotReady
        } else if self.vm_service_addr.is_none() && self.health_probe.is_none() {
            // No health source at all (app-style components): presence = ready.
            EntityStatus::Ready
        } else if health.as_ref().is_some_and(|lc| lc.is_up()) {
            EntityStatus::Ready
        } else {
            EntityStatus::NotReady
        };

        let mut runtime = serde_json::Map::new();
        // Node reboot witness for the offboard flash gate — present on EVERY
        // component (it's a node-wide fact). The per-component heartbeat `boot_id`
        // below only exists for VM/RT; host-os has none, so the gate would fall
        // back to catching the transient SOVD down→up window, which a fast reboot
        // misses → the gate times out despite a clean reboot. `node_boot_id`
        // changes on every node reboot (fresh supernova process) and is durable —
        // the gate compares it and can't miss the reboot. See
        // tasks/health-gate-node-bootid.md.
        if let Some(nb) = &self.node_boot_id {
            runtime.insert("node_boot_id".into(), serde_json::json!(nb));
        }
        // The observed lifecycle: `hb_seq`, `boot_id`, `guest_state`, plus the
        // `lifecycle_*` block (status, monotonic dwell time, wall-clock
        // transition, reason). One writer for this and `runtime_state`, so
        // /status and the trait layer cannot drift.
        //
        // `boot_id` is a per-lifetime nonce — it changes on every guest (re)boot
        // (node reboot OR per-VM relaunch). The orchestrator's reboot witness: a
        // changed boot_id proves a fresh guest lifetime and can't be faked by a
        // stale heartbeat (which carries the OLD boot_id). It also witnesses a
        // node reboot.
        //
        // `lifecycle_for_ms` is the field an offboard waiter needs and never
        // had: "starting" alone can't distinguish a guest 2s into boot from one
        // wedged for 10 minutes, and no threshold is applied here — the
        // observer owns the deadline.
        if let Some(lc) = &health {
            lc.insert_runtime_fields(&mut runtime);
        } else if admin_disabled {
            // Disabled ⇒ nothing was polled, so there is no observation to
            // publish — but there IS an intent, and it is the whole answer:
            // `expected: stopped` by `admin_disable`. This used to emit no
            // `lifecycle_*` at all while `runtime_state` hand-built a
            // `lifecycle_status`, so the two views of the same component
            // disagreed. One writer now, and it also supplies the
            // `lifecycle_status: "stopped"` this body was missing.
            crate::lifecycle::insert_admin_disabled_fields(&mut runtime);
        }
        // Tri-state admin read-back: disableable components carry
        // `admin_state: "enabled" | "disabled"`; non-disableable ones omit
        // the field entirely — so UIs can tell "cannot be disabled" apart
        // from "enabled" and never offer a dead toggle.
        if disableable {
            runtime.insert(
                "admin_state".into(),
                serde_json::json!(if admin_disabled {
                    "disabled"
                } else {
                    "enabled"
                }),
            );
        }
        // Probe-contributed metadata rides the SAME uniform node as every
        // other per-component fact — never a bespoke per-component route.
        // Standard fields stay authoritative on key collision (or_insert);
        // a disabled component's read stays minimal.
        if !admin_disabled {
            if let Some(probe) = &self.health_probe {
                for (k, v) in probe.runtime_extensions() {
                    runtime.entry(k).or_insert(v);
                }
            }
        } else if let Some(probe) = &self.health_probe {
            // A deactivation that ARMS a node reboot (rt: the erase — the M7
            // keeps executing from SRAM until the node restarts) must stay
            // OBSERVABLE after the op response is gone. Derived, not stored:
            // disabled + the probe still reporting a running application ⇒
            // the reboot hasn't happened yet. Clears itself on the real
            // reboot (the loader finds an empty slot ⇒ probe goes quiet) —
            // immune to supernova respawns, no NV clearing to get wrong.
            if probe.probe().is_some() {
                runtime.insert("reboot_pending".into(), serde_json::json!(true));
            }
        }
        let mut extensions = serde_json::Map::new();
        extensions.insert("x-runtime".into(), serde_json::Value::Object(runtime));

        Ok(EntityStatusBody {
            status,
            extensions,
            ..Default::default()
        })
    }

    async fn ecu_reset(&self, _reset_type: u8) -> BackendResult<Option<u8>> {
        // A VM reset queues the relaunch and enters Verifying; health polling
        // records the bank switch only after a fresh ready boot. Components
        // without vm-service switch the running bank directly.

        // A reset must never resurrect an administratively disabled component
        // — skip the pre-reset health probe AND the vm-service (re)start
        // notify below. (vm-service's own admin gate would refuse the start
        // anyway; skipping keeps this end fail-closed too and avoids the
        // phantom probe timeout against a deliberately-stopped guest.)
        let admin_disabled = self.admin_disabled();

        // Establish the pre-reset witness before issuing any runtime request.
        // A running guest supplies the boot-id baseline and uses "restart";
        // confirmed absence uses "start". Query failure must abort rather than
        // create a baseline-free reset that could accept an old guest later.
        let pre_reset_health = if self.config.single_bank || admin_disabled {
            None
        } else {
            match self.vm_service_addr.as_ref() {
                Some(sock) => Some(
                    query_vm_health_state(sock, &self.entity_info.id)
                        .await
                        .map_err(|e| {
                            BackendError::Transport(format!(
                                "failed to query vm-service health for {}: {e}",
                                self.entity_info.id
                            ))
                        })?
                        .baseline(),
                ),
                None => None,
            }
        };
        let was_running = matches!(pre_reset_health, Some(PreResetHealth::Running(_)));

        // Bank activation happens at install-finalize (finalize_flash),
        // not here. ecu_reset requests the runtime launch, then transitions
        // the flash state.

        // Pick "restart" vs "start" based on whether the guest was actually
        // running pre-reset (the `was_running` probe above). For an offline
        // guest (factory provision, post-crash) the shutdown step is a phantom
        // — vm-service would handle it (NotRunning → fall through to start_vm)
        // but the orchestrator-/GUI-visible intent should be "start", not
        // "restart", so the cluster tile doesn't display "Shutting Down" for a
        // guest that never ran.
        let action = if was_running { "restart" } else { "start" };

        let target_bank = if self.config.single_bank {
            Bank::A
        } else {
            self.nv
                .lock()
                .map_err(|_| BackendError::Internal("nv lock".into()))?
                .read_boot_state()
                .ok_or_else(|| BackendError::Internal("no boot state".into()))?
                .banks[self.bank_set.as_index()]
            .active_bank
        };

        // Notify vm-service to (re)launch the guest on the just-activated bank.
        // The boot selector is the authority for which bank actually boots; we
        // no longer flip a per-component `current` symlink here. We still carry
        // the running bank explicitly so vm-service relaunches THIS bank, not
        // the stale boot-time `def.bank` (the "kernel not found" bug).
        if let Some(ref socket_path) = self.vm_service_addr {
            if admin_disabled {
                tracing::info!(
                    component = %self.entity_info.id,
                    "administratively disabled — skipping the vm-service relaunch after reset"
                );
            } else {
                let id = &self.entity_info.id;
                Self::notify_vm_service(socket_path, id, action, Some(target_bank))
                    .await
                    .map_err(|e| {
                        BackendError::Transport(format!(
                            "failed to notify vm-service for {id}: {e}"
                        ))
                    })?;
                tracing::info!("vm-service {action} requested for {id}");
            }
        }

        if !self.config.single_bank && self.vm_service_addr.is_some() {
            if !admin_disabled {
                let mut ft = self.flash_transfer.lock().unwrap();
                if let Some(ref mut transfer) = *ft {
                    transfer.pre_reset_health = pre_reset_health;
                    transfer.state = FlashState::Verifying;
                }
            }
            return Ok(None);
        }

        // Components without vm-service switch to the activated bank here; the
        // served DIDs follow the running bank.
        if !self.config.single_bank {
            *self.running_bank.lock().unwrap() = target_bank;
            let nv = self
                .nv
                .lock()
                .map_err(|_| BackendError::Internal("nv lock".into()))?;
            self.refresh_did_cache_locked(&nv);
        }

        // Single-bank components have no bank switch.

        // Advance only after the runtime request succeeded.
        {
            let mut ft = self.flash_transfer.lock().unwrap();
            if let Some(ref mut t) = *ft {
                t.state = FlashState::Activated;
            }
        }

        Ok(None)
    }

    async fn list_flash_transfers(&self) -> BackendResult<Vec<FlashStatus>> {
        let ft = self.flash_transfer.lock().unwrap();
        match ft.as_ref() {
            Some(t) => Ok(vec![FlashStatus {
                transfer_id: t.transfer_id.clone(),
                package_id: t.package_id.clone(),
                state: t.state,
                progress: Some(FlashProgress {
                    bytes_transferred: t.image_size,
                    bytes_total: t.image_size,
                    blocks_transferred: 1,
                    blocks_total: 1,
                    percent: 100.0,
                }),
                error: None,
            }]),
            None => Ok(vec![]),
        }
    }

    async fn get_activation_state(&self) -> BackendResult<ActivationState> {
        // Check upload phase first (streaming firmware download in progress)
        let upload_state = *self.upload_phase.lock().unwrap();

        let verification = {
            let ft = self.flash_transfer.lock().unwrap();
            ft.as_ref()
                .filter(|transfer| transfer.state == FlashState::Verifying)
                .map(|transfer| (transfer.transfer_id.clone(), transfer.pre_reset_health))
        };
        if let (Some((transfer_id, baseline)), Some(socket)) =
            (verification, self.vm_service_addr.as_ref())
        {
            let fresh_health = query_vm_health_state(socket, &self.entity_info.id)
                .await
                .ok()
                .and_then(VmHealthState::running)
                .filter(|health| health.status == "running" && health.guest_state == 1)
                .filter(|health| match baseline {
                    Some(PreResetHealth::Running(boot_id)) => boot_id != health.boot_id,
                    Some(PreResetHealth::NotRunning) => true,
                    None => false,
                });
            if fresh_health.is_some() {
                // NV first matches verdict/rollback lock order. Re-check the
                // transfer under the lock before recording a polled response.
                //
                // NV is READ ONLY here: the promotion no longer bumps the boot
                // counter. Writing one from this in-memory promotion made the
                // counter look durable while it was really just "this process
                // stayed alive across the guest reboot" — see `preflight_commit`.
                // The guest's own fresh `boot_id` (checked above against the
                // pre-reset baseline) is the reboot evidence; the orchestrator
                // owns the durable half of that comparison.
                let nv = self
                    .nv
                    .lock()
                    .map_err(|_| BackendError::Internal("nv lock".into()))?;
                let mut ft = self.flash_transfer.lock().unwrap();
                let transfer = ft.as_mut().filter(|transfer| {
                    transfer.transfer_id == transfer_id
                        && transfer.state == FlashState::Verifying
                        && transfer.pre_reset_health == baseline
                });
                if let Some(transfer) = transfer {
                    let idx = self.bank_set.as_index();
                    let state = nv
                        .read_boot_state()
                        .ok_or_else(|| BackendError::Internal("no boot state".into()))?;
                    let target_bank = state.banks[idx].active_bank;
                    drop(nv);
                    *self.running_bank.lock().unwrap() = target_bank;
                    transfer.state = FlashState::Activated;
                    transfer.pre_reset_health = None;
                }
            }
        }

        let flash_state = {
            let ft = self.flash_transfer.lock().unwrap();
            ft.as_ref().map(|t| t.state)
        };
        // Before the NV lock: the provider's report takes it.
        let banks = self.bank_provider.banks();
        let in_trial = banks.as_ref().is_some_and(|b| b.in_trial);
        let pending_reset = banks.as_ref().is_some_and(|b| b.pending_reset);

        let nv = self
            .nv
            .lock()
            .map_err(|_| BackendError::Internal("lock".into()))?;

        // Use running_bank for versions (not NV active_bank which may be staged)
        let rb = *self.running_bank.lock().unwrap();
        let active_meta = nv.read_fw_meta(self.bank_set, rb);
        let previous_meta = nv.read_fw_meta(self.bank_set, rb.other());

        // Priority: upload phase > flash transfer > the bank report.
        // A component with no fw_meta on either bank has never been
        // OTA-written — report Initial regardless of the trial flag
        // (defends against stale NV layouts that may show !committed for
        // never-touched slots).
        let state = match upload_state {
            Some(s) => s, // Transferring during firmware download
            None => match flash_state {
                Some(s) => s,
                None if active_meta.is_none() && previous_meta.is_none() => FlashState::Initial,
                // A reconstructed trial still pending its node reset is awaiting
                // that reboot: SOVDd's x-update maps AwaitingReboot → ACTIVATING
                // and Activated → ACTIVATED_UNCOMMITTED. An observation, not a
                // veto — the commit preflight only reads the in-memory transfer.
                None if in_trial && pending_reset => FlashState::AwaitingReboot,
                None if in_trial => FlashState::Activated, // trial without transfer (e.g. after restart)
                None => FlashState::Complete,              // idle — no active update
            },
        };

        // Version strings now come from each bank's signed IVD manifest
        // identity (F189), not NvFwMeta. Present a version only when the
        // bank both has FW meta (has been written) AND a verifiable
        // manifest carrying a non-empty version.
        let version_of = |bank: Bank| -> Option<String> {
            self.verified_bank_identity(bank)
                .and_then(|id| id.version)
                .filter(|v| !v.is_empty())
        };
        let active_version = active_meta.as_ref().and_then(|_| version_of(rb));
        let previous_version = previous_meta.as_ref().and_then(|_| version_of(rb.other()));

        Ok(ActivationState {
            supports_rollback: self.config.supports_rollback,
            state,
            active_version,
            previous_version,
            // Surface the activator's declared reset kind on the wire so the
            // orchestrator can route restarts correctly. Default Local when no
            // activator is configured. `ActivationState` is the SOVD wire
            // type, so the contract enum crosses the edge here.
            reset_kind: machine_mgr::reset_kind_to_sovd(self.reset_kind()),
        })
    }

    /// The client's id for the update being registered. Recorded before
    /// `start_flash` (the registration order), so the manifest and every part
    /// after it carry it; with a session already open, the staging record
    /// the target bank keeps is renamed to it now.
    async fn note_update_id(&self, update_id: &str) -> BackendResult<()> {
        self.set_update_id(Some(update_id.to_string()));
        if !self.flash_in_progress() {
            return Ok(());
        }
        let bank = self.bank_provider.target_bank();
        match self
            .bank_provider
            .staging_record(bank)
            .map_err(|e| BackendError::Internal(format!("read staging record: {e}")))?
        {
            Some(mut rec) if rec.update_id.as_deref() != Some(update_id) => {
                rec.update_id = Some(update_id.to_string());
                self.bank_provider
                    .write_staging_record(bank, Some(&rec))
                    .map_err(|e| BackendError::Internal(format!("write staging record: {e}")))
            }
            _ => Ok(()),
        }
    }

    /// The update this component holds, from its facts alone: the target
    /// bank's staging record names one being staged (`Preparing`) or sealed
    /// and not yet armed (`Prepared`); once armed, the record is gone and the
    /// armed bank's sealed update id is `Executing` until the reboot is
    /// observed, then `Executed` while the trial runs. A committed or
    /// rolled-back component holds nothing; nor does a record without an id
    /// (a part cache).
    async fn held_updates(&self) -> BackendResult<Vec<HeldUpdate>> {
        fn letter(bank: Bank) -> String {
            match bank {
                Bank::A => "A",
                Bank::B => "B",
            }
            .to_string()
        }
        let mut held = Vec::new();
        let bank = self.bank_provider.target_bank();
        let record = self
            .bank_provider
            .staging_record(bank)
            .map_err(|e| BackendError::Internal(format!("read staging record: {e}")))?;
        if let Some(rec) = record {
            if let Some(id) = rec.update_id {
                held.push(HeldUpdate {
                    id,
                    bank: letter(bank),
                    state: if rec.sealed {
                        HeldState::Prepared
                    } else {
                        HeldState::Preparing
                    },
                    parts: rec
                        .parts
                        .into_iter()
                        .map(|p| HeldPart {
                            name: p.name,
                            size: p.size,
                            sha256: p.sha256,
                        })
                        .collect(),
                });
            }
        }
        if let Some(banks) = self.bank_provider.banks() {
            let state = if banks.pending_reset {
                Some(HeldState::Executing)
            } else if banks.in_trial {
                Some(HeldState::Executed)
            } else {
                None
            };
            let active = banks.active;
            if let (Some(state), Some(id)) = (state, active.update_id) {
                held.push(HeldUpdate {
                    id,
                    bank: letter(active.bank),
                    state,
                    parts: active
                        .images
                        .into_iter()
                        .map(|(name, img)| HeldPart {
                            name,
                            size: img.size,
                            sha256: hex::encode(img.sha256),
                        })
                        .collect(),
                });
            }
        }
        Ok(held)
    }

    async fn commit_flash(&self) -> BackendResult<()> {
        self.preflight_commit()?;
        // NV commit routed through the bank provider (it folds AlreadyCommitted
        // into Ok for CRL / idempotent commits). The provider writes NV with a
        // plain lock, so refresh the DID cache afterwards — the `nv_write()`
        // guard used to do this on drop, and the served identity/manifest must
        // reflect the just-committed bank.
        self.bank_provider
            .commit()
            .map_err(|e| BackendError::Internal(e.to_string()))?;
        // Trial resolved — return the node toward Idle (clear reboot-owed + drop
        // from staging). Shared with rollback_flash via resolve_node_transaction.
        self.resolve_node_transaction()?;
        {
            let nv = self
                .nv
                .lock()
                .map_err(|_| BackendError::Internal("nv lock poisoned".into()))?;
            self.refresh_did_cache_locked(&nv);
        }

        // Arm in-band enrolment for this VM's principal. The guest
        // will boot the just-promoted bank, connect to vhsm-ssd,
        // and run HELLO → ENROLL_ASSISTED; the daemon resolves
        // identity by source IP and consumes this pending flag.
        // Components that are not vm principals (e.g. host-os, hsm)
        // skip — enrol is a vm-principal concept.
        if self.vm_principal {
            if let Some(ref hsm) = self.hsm_provider {
                let mut guard = hsm
                    .lock()
                    .map_err(|_| BackendError::Internal("hsm provider mutex poisoned".into()))?;
                // ttl=None: operator-managed lifecycle. Pending stays
                // until consumed; re-installs simply re-arm.
                if let Err(e) = guard.arm_enrollment(&self.entity_info.id, None) {
                    // Non-fatal — operator can re-arm manually, or the
                    // existing cert (if any) lets the guest keep
                    // working. Trial-boot rollback also handles the
                    // "new bank can't enrol" case.
                    tracing::warn!(
                        vm_id = %self.entity_info.id,
                        error = %e,
                        "arm_enrollment after commit failed; guest may need manual arm"
                    );
                } else {
                    tracing::info!(
                        vm_id = %self.entity_info.id,
                        "armed ENROLL_ASSISTED after commit_flash"
                    );
                }
            }
        }

        // Clear flash transfer state
        *self.flash_transfer.lock().unwrap() = None;
        Ok(())
    }

    async fn rollback_flash(&self) -> BackendResult<()> {
        if !self.config.supports_rollback {
            return Err(BackendError::InvalidRequest(
                "rollback not supported for this component".into(),
            ));
        }
        // NV rollback routed through the bank provider. Refresh the DID cache
        // afterwards (the provider writes NV with a plain lock; the old
        // `nv_write()` guard refreshed on drop).
        self.bank_provider
            .rollback()
            .map_err(|e| BackendError::Internal(e.to_string()))?;
        // The rolled-back trial bank is dead content: wipe it now instead of
        // leaving hundreds of MB staged until the next flash's `prepare_target`
        // — on a space-constrained partition those leftovers are what turn the
        // next in-place update into an ENOSPC. Must run AFTER the NV/selector
        // rollback above so `target_bank()` flips back to the (now dead) trial
        // bank. Best-effort: a wipe failure logs, it doesn't fail the rollback.
        if let Err(e) = self
            .bank_provider
            .prepare_target(self.bank_provider.target_bank())
        {
            tracing::warn!(
                error = %e,
                "rollback: trial bank dir not wiped — space reclaims at next flash"
            );
        }
        // Transaction resolved (reverted) — return the node toward Idle, same as
        // commit. Without this a rolled-back banked component stays in the
        // coordinator's staging and the node never leaves Staging/Trial.
        self.resolve_node_transaction()?;
        {
            let nv = self
                .nv
                .lock()
                .map_err(|_| BackendError::Internal("nv lock poisoned".into()))?;
            self.refresh_did_cache_locked(&nv);
        }
        // Rolling back a re-enable lands on the sentinel bank again: disabled,
        // yet the guest launched for the trial may still be up — stop it.
        // Best-effort: a failed stop warns and never fails the rollback (a VM
        // deactivator reads an already-stopped guest as converged).
        if self.admin_disabled() {
            if let Some(deactivator) = self.deactivator.clone() {
                match tokio::task::spawn_blocking(move || deactivator.deactivate()).await {
                    // Surfaced, not armed: the rollback does not record the
                    // reset as owed.
                    Ok(Ok(outcome)) if outcome.reboot_required => tracing::warn!(
                        component = %self.entity_info.id,
                        reboot_required = true,
                        "rollback landed on a disabled bank — component deactivated, but the \
                         deactivation needs an ECU reset that is not recorded as owed"
                    ),
                    Ok(Ok(_)) => tracing::info!(
                        component = %self.entity_info.id,
                        "rollback landed on a disabled bank — component deactivated"
                    ),
                    Ok(Err(e)) => tracing::warn!(
                        component = %self.entity_info.id,
                        error = %e,
                        "rollback landed on a disabled bank — deactivation failed"
                    ),
                    Err(e) => tracing::warn!(
                        component = %self.entity_info.id,
                        error = %e,
                        "rollback landed on a disabled bank — deactivator task join error"
                    ),
                }
            }
        }
        // Clear flash transfer state after rollback
        *self.flash_transfer.lock().unwrap() = None;
        Ok(())
    }

    async fn abort_flash(&self, _transfer_id: &str) -> BackendResult<()> {
        // Mirror `ComponentAdapter::abort_install` exactly — the round-trip the
        // directly-wired bank/hsm engine no longer goes through. Pre-finalize
        // abort is always allowed: drop the staging session (the same shared
        // `clear_flash_session` the adapter calls). Post-finalize the bank
        // pointer has already flipped to the next-boot bank and the engine
        // can't unflip it, so refuse rather than silently no-op — surfaced as
        // `InvalidRequest`, the exact wire mapping `map_machine_error` produces
        // from the adapter's `PolicyRejected`, so the direct (bank/hsm) and
        // routed (vm2/app) abort paths return identical HTTP.
        if self.flash_is_finalized() {
            return Err(BackendError::InvalidRequest(
                "cannot abort: install already finalized".into(),
            ));
        }
        // Drop the session AND the coordinator staging membership (the gate
        // staged this component at start_flash; an abort is a terminal
        // resolution too). reboot-owed clear is a no-op here — abort is
        // rejected post-finalize above, so nothing was ever marked.
        self.abort_session()?;
        Ok(())
    }

    // No `modes/session` / `modes/security` here: this is a native SOVD
    // server, not a UDS ECU front. Privileged `/updates` writes are
    // authorized by the JWT bearer token at the sovd-api layer (ISO 17978-3
    // §5.4.4); in-vehicle UDS seed/key unlock is performed transparently
    // server-side by the UDS-device handler (SOVDd). Both mode routes fall
    // through to the `DiagnosticBackend` defaults (`NotSupported` → 501).
}
