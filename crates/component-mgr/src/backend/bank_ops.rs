use super::*;

impl<D: BlockDevice + Send + 'static> ComponentBackend<D> {
    /// Ratchet the HSM's monotonic safe-time floor to `iat` (a manifest's signed
    /// `signing_time`, seconds) and discipline the host wall clock forward to the
    /// resulting floor. `iat` MUST come from a manifest whose signature already
    /// verified to a trusted root — it is a signed lower bound on real time
    /// (`docs/safe-time-floor.md`).
    ///
    /// The floor is monotonic (`raise_monotonic` = max), so this is safe to call on
    /// ANY trust-root-verified manifest — including one the caller then REJECTS for
    /// anti-rollback / device-identity reasons: a stale manifest's `iat` can only be
    /// a no-op against the floor, never a rewind, and a rejected manifest still
    /// carried a truthful signed lower bound on time. Advancing here (not gated on
    /// acceptance / trial-boot / commit) is what lets an offline device move its
    /// floor forward whenever it sees trusted signed time. Best-effort: a floor
    /// hiccup never fails an otherwise-valid operation.
    pub(super) fn ratchet_time_floor(&self, iat: u64) {
        let Some(hsm) = self.hsm_provider.as_ref() else {
            return;
        };
        let mut hsm_guard = match hsm.lock() {
            Ok(g) => g,
            Err(_) => {
                tracing::warn!("HSM provider lock poisoned — skipped time-floor ratchet");
                return;
            }
        };
        match crate::sovd::time_floor::TimeFloor::advance(&mut *hsm_guard, iat) {
            Ok(floor) => {
                tracing::info!(
                    iat,
                    floor,
                    "safe-time floor ratcheted from manifest signing time"
                );
                // Discipline the host wall clock forward to the resulting
                // (post-ratchet, max) floor, so every reader of CLOCK_REALTIME sees
                // max(now, floor) without a separate cache. Forward-only + best-effort.
                drop(hsm_guard);
                self.wall_clock_floor.discipline_to(floor);
            }
            Err(e) => {
                tracing::warn!(iat, error = %e, "could not ratchet safe-time floor from manifest iat")
            }
        }
    }

    /// Salvage the trusted signed time from a manifest we're about to REJECT.
    /// A `RollbackRejected` manifest still had its signature verified to a trusted
    /// root, so its `signing_time` is a truthful lower bound on real time — ratchet
    /// the floor from it before the rejection propagates. Other rejections (bad
    /// signature, parse error) carry no trusted time and are ignored.
    pub(super) fn ratchet_time_floor_on_reject(
        &self,
        err: &crate::manifest_provider::ManifestError,
    ) {
        if let crate::manifest_provider::ManifestError::RollbackRejected {
            signing_time_secs: Some(iat),
            ..
        } = err
        {
            tracing::info!(iat, "ratcheting safe-time floor from a rejected (too-old) but trust-root-signed manifest");
            self.ratchet_time_floor(*iat);
        }
    }

    /// The component's observed lifecycle, from whichever health source backs
    /// it. `None` when there is no health source at all (app-style components),
    /// or when the query failed — a failed probe is deliberately not
    /// synthesised into a state, because "I could not ask" is not an
    /// observation about the component.
    pub(super) async fn query_lifecycle(&self) -> Option<GuestLifecycle> {
        match &self.vm_service_addr {
            Some(socket) => query_vm_lifecycle(socket, &self.entity_info.id)
                .await
                .ok()
                .flatten(),
            // No vm-service backing: an injected HealthProbe (e.g. RT/M7) is
            // the health source — cheap by trait contract (cached).
            None => self
                .health_probe
                .as_ref()
                .and_then(|p| p.probe())
                .as_ref()
                .map(GuestLifecycle::from_probe),
        }
    }

    /// `Component::runtime_state` for this backend — the coarse status plus
    /// every observed fact as detail.
    ///
    /// Administratively disabled short-circuits to `Stopped`: the component is
    /// down BY DESIGN, so probing would only burn the health timeout, and
    /// `Faulted` would be a lie. It is no longer a special case in the body,
    /// though — the intent axis says `expected: stopped` by `admin_disable`,
    /// which is what makes "down and fine" a first-class answer instead of
    /// something every reader had to infer from `admin_state`.
    pub async fn runtime_state_snapshot(&self) -> RuntimeState {
        if self.admin_disabled() {
            let mut detail = serde_json::Map::new();
            crate::lifecycle::insert_admin_disabled_fields(&mut detail);
            return RuntimeState {
                status: RuntimeStatus::Stopped,
                detail: serde_json::Value::Object(detail),
            };
        }
        match self.query_lifecycle().await {
            Some(lc) => lc.runtime_state(),
            None => RuntimeState {
                status: RuntimeStatus::Unknown,
                detail: serde_json::Value::Null,
            },
        }
    }

    /// Reset kind declared by this component's bank provider (folds in the
    /// activator's `reset_kind`, or [`ResetKind::Local`] when no activator is
    /// configured — e.g. VM components without a custom activator, whose
    /// qvm/process cycle is local). `derive_capabilities` reads this to
    /// populate `FlashCaps.reset_kind`.
    pub fn reset_kind(&self) -> machine_mgr::ResetKind {
        self.bank_provider.reset_kind()
    }

    /// Render this component's update-mode as the `x-ota-update-mode` JSON
    /// value: `banked` (A/B + trial + rollback) vs `singleshot` (single-bank,
    /// write-through, irreversible — the HSM keystore), plus the flash-cap
    /// fields an offboard twin keys its composition guard on. Stable config —
    /// no NV / manifest dependency, so it serves even pre-flash.
    pub(super) fn update_mode_json(&self) -> serde_json::Value {
        let update_mode = if self.config.single_bank {
            "singleshot"
        } else {
            "banked"
        };
        serde_json::json!({
            "update_mode": update_mode,
            "supports_rollback": self.config.supports_rollback,
            "dual_bank": !self.config.single_bank,
            "reset_kind": self.reset_kind(),
        })
    }

    /// The bank an OTA upload should write to — the sibling of the RUNNING bank
    /// (NV `active_bank`), delegated to the bank provider. `Bank::A` for
    /// single-bank.
    ///
    /// Refuses with a clear error when a reboot is PENDING (the boot selector's
    /// next-boot selection disagrees with the running bank — the state a
    /// rollback-without-reboot leaves). In that window the running bank is
    /// loopback-mounted (unwriteable) and the target is ambiguous; forcing a flash
    /// anyway tried to write the running bank → `Resource busy` (rig-observed).
    /// The operator must reboot (which reconverges selector ↔ running) first.
    pub(super) fn determine_target_bank(&self) -> BackendResult<Bank> {
        if self.bank_provider.pending_reboot() {
            return Err(BackendError::InvalidRequest(
                "a reboot is pending (boot selector disagrees with the running bank — \
                 e.g. after a rollback); reboot the ECU before starting a new update"
                    .into(),
            ));
        }
        Ok(self.bank_provider.target_bank())
    }

    /// Self-sign the staged bank with the HSM's `ivd-signing` key so
    /// external secure boot can validate it before launch. Called at
    /// each `AwaitingActivation` transition — bank contents are
    /// final, but the bank pointer hasn't flipped yet, so the sig
    /// lives WITH the staged bank. Rollback wipes the bank and its
    /// sig together; trial flip just exposes the staged bank with
    /// its existing sig intact.
    ///
    /// Contract: signing is REQUIRED for every flash that produces a
    /// real bank dir with real payloads. Three skip paths and no
    /// others:
    ///
    /// 1. No `images_dir` (in-memory test) — backend has no place to
    ///    put files; tests assert via NV state.
    /// 2. Bank dir missing (pre-streaming code path) — caller hasn't
    ///    staged anything yet, nothing to sign.
    /// 3. Bank dir is payload-empty (HSM single-bank, where the
    ///    keystore lives at `keystore_path` not in the bank dir, and
    ///    attestation rides on the provisioning envelope chain).
    ///
    /// Pre-provisioning exception: if the HSM is reachable but
    /// `is_provisioned()` is false, the `ivd-signing` key doesn't
    /// exist yet — log a warning and skip. Banks produced in this
    /// state aren't boot-eligible once verified launch is wired in;
    /// the next flash post-provision will land sigs as expected.
    ///
    /// Any other condition (no HSM provider when payloads are
    /// present, signing failure, mutex poisoned) returns an error
    /// rather than silently shipping an unsigned bank.
    pub(super) fn ivd_sign_staged_bank(&self, target: Bank) -> BackendResult<()> {
        // Bank mechanics (seed → skip-checks → HSM-provisioned gate → sign)
        // moved to `IvdBankProvider::seal`. The engine still owns the three
        // inputs that come from its OTA state: the install-time `gen` (from NV),
        // the firmware SW identity (from the package the flash transfer points
        // at, mapped to the kind-agnostic `FirmwareIdentity`), and the part
        // inventory this install's manifest declares.
        let gen = self.install_gen_for(target)?;
        let identity = self.current_install_identity();
        let required = self.declared_bank_parts();
        self.bank_provider
            .seal(target, identity, gen, &required)
            .map_err(|e| BackendError::Internal(e.to_string()))
    }

    /// The part names the bank being sealed must hold: the inventory this
    /// install's manifest declares. That is exactly the flash transfer's
    /// accumulated file list — every declared component reaches it either by
    /// being streamed in (`handle_payload_upload`) or by being reconciled from
    /// the active bank / CAS (`reconcile_unpushed`, folded in at transferexit).
    ///
    /// The provider's seed uses it as the REQUIRED set: anything the active
    /// bank holds outside it belongs to a different manifest (a cross-channel
    /// flash) and must never be copied — nor even opened, since a running guest
    /// may hold it through devb-loopback. Empty when the install declares no
    /// payloads (CRL / disable / HSM keystore / buffered no-transfer paths),
    /// which makes the seed a no-op.
    pub(super) fn declared_bank_parts(&self) -> Vec<String> {
        let ft = self.flash_transfer.lock().ok();
        ft.and_then(|g| {
            g.as_ref().map(|t| {
                t.streamed_files
                    .iter()
                    .map(|f| f.relative_path.clone())
                    .collect()
            })
        })
        .unwrap_or_default()
    }

    /// Compute the install-time generation counter (`gen`) directly from NV
    /// state. Must agree with what `ota::install_inner` writes into target's
    /// NvFwMeta — both derive it as `committed_bank.gen + 1`. Computed here
    /// (not read back from NvFwMeta) because in the multi-POST upload path the
    /// sign happens at "all payloads received", before `install_precomputed`
    /// writes the target's NvFwMeta at transferexit. The OTA flow is serialized
    /// (start_flash rejects concurrent flashes), so both arrive at the same
    /// gen. The committed bank is whichever of {active, active.other()} has
    /// committed=true.
    pub(super) fn install_gen_for(&self, _target: Bank) -> BackendResult<u64> {
        let nv = self
            .nv
            .lock()
            .map_err(|_| BackendError::Internal("ivd sign: nv mutex poisoned".into()))?;
        let state = nv
            .read_boot_state()
            .ok_or_else(|| BackendError::Internal("ivd sign: NV boot state missing".into()))?;
        let idx = self.bank_set.as_index();
        let committed_bank = if state.banks[idx].committed {
            state.banks[idx].active_bank
        } else {
            state.banks[idx].active_bank.other()
        };
        let committed_gen = nv
            .read_fw_meta(self.bank_set, committed_bank)
            .map(|m| m.gen)
            .unwrap_or(0);
        Ok(committed_gen + 1)
    }

    /// The firmware SW identity to seal into the IVD manifest being signed:
    /// derived from the SUIT-extracted `ImageMeta` of the package the current
    /// flash transfer points at, mapped to the kind-agnostic
    /// [`FirmwareIdentity`]. All-`None` when no package is in scope (e.g. a
    /// re-sign with no active transfer) — the manifest then carries a blank
    /// identity, which reads back as all-NUL DIDs (prior behaviour preserved).
    pub(super) fn current_install_identity(&self) -> FirmwareIdentity {
        let package_id = {
            let ft = self.flash_transfer.lock().ok();
            ft.and_then(|g| g.as_ref().map(|t| t.package_id.clone()))
                .unwrap_or_default()
        };
        if package_id.is_empty() {
            return FirmwareIdentity::default();
        }
        let packages = match self.packages.lock() {
            Ok(p) => p,
            Err(_) => return FirmwareIdentity::default(),
        };
        packages
            .get(&package_id)
            .map(|p| p.validated.image_meta.to_firmware_identity())
            .unwrap_or_default()
    }

    /// Bank to serve installed-manifest / identity from: the boot selector's
    /// active bank (the authority the VM boots), falling back to the
    /// `running_bank` cache only when the selector has no selection.
    ///
    /// `selected_bank()` is the selector's selection ALONE (`None` when no
    /// selector is wired — tests / the no-HSM smoke path / RT-without-config);
    /// it deliberately does NOT use the provider's own NV-seeded fallback, so
    /// we fall back to THIS backend's live `running_bank` (updated on
    /// `ecu_reset`), not the provider's frozen construction-time copy. The
    /// previous serve path read `*self.running_bank.lock()` directly and so
    /// missed the just-flashed bank the selector had already switched to.
    pub(super) fn serving_bank(&self) -> Bank {
        self.bank_provider
            .selected_bank()
            .unwrap_or_else(|| *self.running_bank.lock().unwrap())
    }

    /// Read a bank's installed firmware **report-only** via the bank provider
    /// (decode the on-disk signed manifest; NO HSM verify) and return it as
    /// [`InstalledFirmware`], caching it per-bank so repeated diagnostics reads
    /// share one decode. The cache is invalidated on every NV write (see
    /// `refresh_did_cache_locked`), so the served firmware always reflects the
    /// latest install/commit/ecu_reset.
    ///
    /// Returns `Some` whenever the manifest file is present + decodable, `None`
    /// only on `NotInstalled` (no images_dir, no manifest yet) or a corrupt
    /// manifest. The served object carries the raw manifest bytes + signature
    /// so a client verifies independently; the on-device gate stays in
    /// `verify_bank` (install/boot/launch), unchanged. The `Unverifiable` warn
    /// arm below is therefore unreachable on this report-only path — it is left
    /// in place but never fires.
    ///
    /// Used for the RUNNING/committed bank: `read_data` of the identity DIDs
    /// and the vendor `x-ota-installed-manifest` parameter both pass
    /// `*self.running_bank`, the same bank whose identity overlay is built in
    /// `refresh_did_cache_locked`.
    pub(super) fn verified_bank_manifest(&self, bank: Bank) -> Option<Arc<InstalledFirmware>> {
        // Fast path: return the cached firmware if it's for this bank.
        {
            let cache = self
                .verified_manifest_cache
                .lock()
                .expect("verified_manifest_cache poisoned");
            if let Some((cached_bank, fw)) = cache.as_ref() {
                if *cached_bank == bank {
                    tracing::debug!(component = %self.entity_info.id, bank = ?bank, "ivd-route: cache hit -> serving");
                    return Some(Arc::clone(fw));
                }
            }
        }

        // Slow path: read + verify via the provider, then memoise for this bank.
        match self.bank_provider.read_installed(bank) {
            Ok(fw) => {
                tracing::info!(component = %self.entity_info.id, bank = ?bank, "ivd-route: installed firmware OK -> serving + caching");
                let fw = Arc::new(fw);
                *self
                    .verified_manifest_cache
                    .lock()
                    .expect("verified_manifest_cache poisoned") = Some((bank, Arc::clone(&fw)));
                Some(fw)
            }
            Err(machine_mgr::bank_provider::BankError::Unverifiable(msg)) => {
                tracing::warn!(
                    component = %self.entity_info.id,
                    bank_set = ?self.bank_set,
                    bank = ?bank,
                    "ivd-route: installed firmware unverifiable ({msg}); refusing to serve it",
                );
                None
            }
            Err(e) => {
                // NotInstalled / no images_dir / no HSM etc. — normal absence.
                // INFO (not debug) so a fresh-device 404 on the manifest shows
                // exactly which bank had no installed firmware and why.
                tracing::info!(
                    component = %self.entity_info.id,
                    bank = ?bank,
                    error = %e,
                    "ivd-route: no installed manifest for serving bank -> None",
                );
                None
            }
        }
    }

    /// The installed firmware's SW [`FirmwareIdentity`] for `bank` — the single
    /// source for the SW-identity DIDs (F187-F19E) and version labels now that
    /// they're out of NvFwMeta. Thin projection over
    /// [`Self::verified_bank_manifest`].
    pub(super) fn verified_bank_identity(&self, bank: Bank) -> Option<FirmwareIdentity> {
        self.verified_bank_manifest(bank)
            .map(|fw| fw.identity.clone())
    }

    /// The `(did, bytes)` pairs for the 9 SW-identity DIDs of `bank`, each
    /// converted to its historical fixed-width UDS byte form. Empty when the
    /// bank has no verifiable identity (see [`Self::verified_bank_identity`]).
    pub(super) fn identity_did_bytes(&self, bank: Bank) -> Vec<(u16, Vec<u8>)> {
        match self.verified_bank_manifest(bank) {
            Some(fw) => identity_to_did_bytes(&fw.identity),
            None => Vec::new(),
        }
    }

    /// Wipe the target bank dir + reclaim space — delegated to the provider's
    /// `prepare_target`. Called at flash-session start so the incoming payload
    /// lands in a clean, space-reclaimed location on the same filesystem as its
    /// final home.
    pub(super) fn prepare_target_bank_dir(&self, target: Bank) -> BackendResult<()> {
        self.bank_provider
            .prepare_target(target)
            .map_err(|e| BackendError::Internal(e.to_string()))
    }

    pub fn running_bank(
        &self,
    ) -> Result<Bank, std::sync::PoisonError<std::sync::MutexGuard<'_, Bank>>> {
        self.running_bank.lock().map(|g| *g)
    }

    /// Provide the session-scoped pull source for the NEXT install session —
    /// see [`machine_mgr::InstallSource`]. Called by the pull route before
    /// `start_flash`; overwrites any previous value. Enables the fetch
    /// fallback in `finalize_flash`'s reconciliation.
    pub fn set_install_source(&self, source: machine_mgr::InstallSource) {
        *self.install_source.lock().unwrap() = Some(source);
    }

    /// Name the client's update being staged (`None` forgets it). The next
    /// manifest and every part after it record the id beside the bank, and
    /// the seal carries it into the bank's signed manifest.
    pub fn set_update_id(&self, id: Option<String>) {
        *self.update_id.lock().unwrap() = id;
    }

    /// The node boot id this process sees now: the coordinator's when it carries
    /// one, else the one injected via [`with_node_boot_id`](Self::with_node_boot_id).
    pub(super) fn current_node_boot_id(&self) -> Option<String> {
        self.node_coordinator
            .as_ref()
            .and_then(|c| c.node_boot_id())
            .map(str::to_owned)
            .or_else(|| self.node_boot_id.clone())
    }

    /// Set or clear this component's bit in the node-level reboot-owed record
    /// (`NvUpdateSession`). Arming (`owed == true`) also records the current
    /// node boot id (`armed_boot_id`); clearing leaves the armed id alone (it is
    /// irrelevant once the mask is empty). Read-modify-write of the shared node
    /// NV; idempotent (writes only on a change). Only the armed boot id is read
    /// back, by [`Self::nv_rebooted_probe`] when no boot vector is wired.
    pub(super) fn set_reboot_owed(&self, owed: bool) -> BackendResult<()> {
        let boot_id = self.current_node_boot_id();
        let mut nv = self
            .nv
            .lock()
            .map_err(|_| BackendError::Internal("nv lock".into()))?;
        let mut s = nv.read_update_session().unwrap_or_default();
        let mut changed = s.set_owed(self.bank_set, owed);
        if owed {
            changed |= s.record_armed_boot_id(boot_id.as_deref());
        }
        if changed {
            nv.write_update_session(&mut s)
                .map_err(|e| BackendError::Internal(format!("nv write update-session: {e:?}")))?;
        }
        Ok(())
    }

    /// Refuse a banked commit only on facts this process can see: an in-memory
    /// AwaitingReboot transfer, a selected bank that disagrees with the bank this
    /// process booted from, or a provider that reports a pending reboot. The ECU
    /// does NOT veto on a pending node reset: the orchestrator proves the reboot from
    /// `x-ota-update-state` (`rebooted_since_arming`), `x-runtime.node_boot_id`
    /// and the heartbeat `boot_id`, and decides commit/rollback. A bootloader
    /// fall-back is invisible to this process (`running_bank` is seeded from NV
    /// `active_bank`), so that too is the orchestrator's call. Read-only so a node
    /// verdict can preflight every candidate before any mutates durable state.
    pub fn preflight_commit(&self) -> BackendResult<()> {
        if self.config.single_bank {
            return Ok(());
        }

        if self
            .flash_transfer
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|transfer| transfer.state == FlashState::AwaitingReboot)
        {
            return Err(BackendError::Busy(
                "commit refused: component is awaiting reboot".into(),
            ));
        }

        let selected = match self.bank_provider.selected_bank() {
            Some(bank) => bank,
            None => {
                self.nv
                    .lock()
                    .map_err(|_| BackendError::Internal("nv lock".into()))?
                    .read_boot_state()
                    .ok_or_else(|| BackendError::Internal("no boot state".into()))?
                    .banks[self.bank_set.as_index()]
                .active_bank
            }
        };

        let running = *self.running_bank.lock().unwrap();
        if selected != running {
            return Err(BackendError::Busy(format!(
                "commit refused: selected bank {selected:?} does not match running bank {running:?}"
            )));
        }
        if self.bank_provider.pending_reboot() {
            return Err(BackendError::Busy(
                "commit refused: bank provider reports a pending reboot".into(),
            ));
        }

        Ok(())
    }

    /// A node update-transaction for this component has resolved — committed OR
    /// rolled back. Clear its durable reboot-owed bit and drop it from the
    /// coordinator's staging, so a fully-resolved transaction returns the node to
    /// `Idle`. Called from BOTH `commit_flash` and `rollback_flash` (the two
    /// resolution points) so neither path can leave the node wedged in
    /// `RebootPending`/`Staging`. The reboot-owed clear is a no-op for banked
    /// components (they never set it) — kept for symmetry and as a safety net.
    pub(super) fn resolve_node_transaction(&self) -> BackendResult<()> {
        self.set_reboot_owed(false)?;
        if let Some(coord) = &self.node_coordinator {
            coord.remove_from_staging(&self.entity_info.id);
        }
        Ok(())
    }

    // =================================================================
    // Per-component administrative state (disable/enable)
    // =================================================================

    /// True when this component is administratively disableable — i.e. the
    /// factory equipped it with a [`machine_mgr::Deactivator`]. Structural
    /// capability, never a name list.
    pub fn is_disableable(&self) -> bool {
        self.deactivator.is_some()
    }

    /// The component's *effective* administrative state: `true` only for a
    /// disableable component whose SERVING bank (`serving_bank()`: the boot
    /// selector's selection, else `running_bank`) holds a signature-verified
    /// disable sentinel at that bank's NvFwMeta gen — the record
    /// `enact_disable_manifest` writes and the launch gate refuses to start.
    /// Everything else reads as enabled:
    ///
    /// - a sentinel at any other gen: stale (a moved or pre-ratchet record);
    ///   warned, and the launch gate's gen pin refuses it anyway;
    /// - a real inventory, no record, or one whose signature does not verify;
    /// - a record that cannot be read (`Err`): warned and NOT cached, so the
    ///   next read retries;
    /// - any record on a component with no deactivator (the deployment shape
    ///   changed) — the equipped deactivator is the authority on
    ///   disableability.
    ///
    /// Derived lazily and cached per serving bank (`admin_disabled_cache`,
    /// cleared on every NV write; a derivation that raced a clear is returned
    /// but not cached). A userspace/post-boot gate: read to gate start / flash,
    /// never consulted at vm-boot.
    ///
    /// PRECONDITION: never call with the NV mutex held — a cache miss takes it,
    /// briefly, for the expected gen.
    pub fn admin_disabled(&self) -> bool {
        if !self.is_disableable() {
            return false;
        }
        let bank = self.serving_bank();
        let observed = {
            let cache = self
                .admin_disabled_cache
                .lock()
                .expect("admin_disabled_cache poisoned");
            if let Some((cached_bank, disabled)) = cache.value {
                if cached_bank == bank {
                    return disabled;
                }
            }
            cache.epoch
        };

        // Miss. NV only for the expected gen; the record read + HSM verify run
        // with NV and the cache released. The answer is stored only if nothing
        // cleared the cache meanwhile: a clear means state moved under this
        // derivation (e.g. a disable landed), so it is returned, not cached.
        let expected_gen = self
            .nv
            .lock()
            .unwrap()
            .read_fw_meta(self.bank_set, bank)
            .map(|m| m.gen);
        let disabled = match self.bank_provider.disabled_record(bank) {
            Ok(Some(gen)) if Some(gen) == expected_gen => true,
            Ok(Some(gen)) => {
                tracing::warn!(
                    component = %self.entity_info.id,
                    bank = ?bank,
                    gen,
                    expected_gen = ?expected_gen,
                    "stale sentinel gen on the serving bank — reading as enabled",
                );
                false
            }
            Ok(None) => false,
            Err(e) => {
                tracing::warn!(
                    component = %self.entity_info.id,
                    bank = ?bank,
                    error = %e,
                    "disable record unreadable — reading as enabled (not cached)",
                );
                return false;
            }
        };
        self.admin_disabled_cache
            .lock()
            .expect("admin_disabled_cache poisoned")
            .store_if_epoch(observed, bank, disabled);
        disabled
    }

    /// Enact a SUIT administrative-*disable* manifest — the no-payload
    /// counterpart to a firmware install. Runs THIS component's `Deactivator`
    /// (the manifest was POSTed to this component's upload endpoint, and the
    /// caller's `bank_set` check already rejected a manifest naming another
    /// component). The sync deactivator runs off the async worker and
    /// `reboot_required` is surfaced.
    ///
    /// The disable is persisted as the SERVING bank's signed sentinel record at
    /// a ratcheted gen (`NvFwMeta.gen + 1`, NV following the record), which is
    /// what `admin_disabled()` and the launch gate read. Nothing is persisted
    /// before the deactivator succeeds, and the deactivator runs only once the
    /// cheap checks pass: the component is idle (committed, no reboot pending
    /// or owed — `Busy` otherwise, as `ensure_flash_can_start` answers), the
    /// serving bank has an installed-firmware gen to ratchet, and the provider
    /// can persist the record (`PreconditionFailed` otherwise). `NotSupported`
    /// when the component is not disableable (no `Deactivator`).
    pub(super) async fn enact_disable_manifest(&self) -> BackendResult<()> {
        let Some(deactivator) = self.deactivator.clone() else {
            return Err(BackendError::NotSupported(
                "component does not support administrative disable".into(),
            ));
        };

        // Admission: idle only. A sentinel sealed mid-trial, or with a reboot
        // pending or owed, lands on a bank the verdict or the reboot may still
        // move away from. `pending_reboot` reads NV itself — ask it first.
        let busy = || {
            BackendError::Busy(
                "disable refused: component is mid-trial or owes a reboot — retry when idle".into(),
            )
        };
        if self.bank_provider.pending_reboot() {
            return Err(busy());
        }
        let serving = self.serving_bank();
        let gen = {
            let nv = self
                .nv
                .lock()
                .map_err(|_| BackendError::Internal("nv lock".into()))?;
            let idx = self.bank_set.as_index();
            let committed = self.config.single_bank
                || nv
                    .read_boot_state()
                    .ok_or_else(|| BackendError::Internal("no boot state".into()))?
                    .banks[idx]
                    .committed;
            let owed = nv
                .read_update_session()
                .unwrap_or_default()
                .owes(self.bank_set);
            if !committed || owed {
                return Err(busy());
            }
            nv.read_fw_meta(self.bank_set, serving).map(|m| m.gen)
        };
        // Pre-flight, before anything is enacted. Never invent gen 0: the
        // launch gate pins the sentinel's gen to NvFwMeta, so a bank with no
        // installed generation has nothing to disable.
        let Some(gen) = gen else {
            return Err(BackendError::PreconditionFailed(
                "no installed-firmware generation for the serving bank — nothing to disable".into(),
            ));
        };
        self.bank_provider
            .can_persist_disabled_record()
            .map_err(|e| {
                BackendError::PreconditionFailed(format!(
                    "disable refused: the disable record cannot be persisted: {e}"
                ))
            })?;

        let enact = tokio::task::spawn_blocking(move || deactivator.deactivate()).await;
        let reboot_required = match enact {
            Ok(Ok(outcome)) => outcome.reboot_required,
            Ok(Err(e)) => return Err(BackendError::Internal(format!("deactivation failed: {e}"))),
            Err(e) => {
                return Err(BackendError::Internal(format!(
                    "deactivator task join error: {e}"
                )))
            }
        };

        // Deactivation succeeded — persist the disable: the serving bank's signed
        // record becomes the sentinel at gen + 1, its images left in place. An
        // error returns before NV moves; a crash between the two IVD files
        // leaves a pair that does not verify, which the launch gate refuses.
        let gen = gen + 1;
        self.bank_provider
            .write_disabled_record(serving, gen)
            .map_err(|e| BackendError::Internal(format!("write disable record: {e}")))?;
        // Ratchet NvFwMeta to the sentinel's gen so the launch gate's gen pin
        // matches it. Through `nv_write`: its drop clears the derived caches.
        {
            let mut nv = self.nv_write()?;
            let mut meta = nv.read_fw_meta(self.bank_set, serving).ok_or_else(|| {
                BackendError::Internal("nv fw meta vanished during disable".into())
            })?;
            meta.gen = gen;
            nv.write_fw_meta(self.bank_set, serving, &mut meta)
                .map_err(|e| BackendError::Internal(format!("nv write fw meta: {e:?}")))?;
        }
        self.admin_disabled_cache
            .lock()
            .expect("admin_disabled_cache poisoned")
            .clear();

        // A deactivation that owes an ECU reset records the node reboot in the
        // same durable NV marker `finalize_flash` uses for firmware singleshots,
        // so the reboot survives a power cycle and the node-update gate refuses a
        // new flash until it runs. No-op when the deactivation is fully realized.
        if reboot_required {
            self.set_reboot_owed(true)?;
        }

        tracing::info!(
            component = %self.entity_info.id,
            bank_set = ?self.bank_set,
            bank = ?serving,
            gen,
            reboot_required,
            "component disabled via SUIT disable manifest"
        );
        Ok(())
    }
}
