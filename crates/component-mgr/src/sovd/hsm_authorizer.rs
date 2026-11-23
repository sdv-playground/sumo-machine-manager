//! The HSM-keystore-backed [`Authorizer`]: build a [`TieredAuthorizer`] from the
//! issuer anchors and delegation root a device is provisioned with, and rebuild it
//! when that keystore changes.
//!
//! ```text
//!   request ─► CachedHsmAuthorizer::authorize
//!                 │  keystore/manifest mtime changed?
//!          no ────┤──── yes ─► build_authorizer_now
//!                 │               │ anchor_der: keystore first, then extra_anchor
//!                 │               ▼
//!                 │            issuer_keys::authorizer_from_anchors
//!                 │               ├─ with_boot_id      (destructive surface)
//!                 │               ├─ with_read_open    (general surface)
//!                 │               └─ with_time_floor + with_floor_sink
//!                 ▼
//!           cached TieredAuthorizer ─► authorize
//!           (only a build that read every key; a degraded one is rebuilt)
//! ```
//!
//! # Why this is here and not in a machine manager
//!
//! It is built entirely out of this crate's own pieces —
//! [`issuer_keys::authorizer_from_anchors`], [`identity::ecu_id`],
//! [`TieredAuthorizer`] — so it is the same layer as those, not a layer above
//! them. It was living in one deployment's `main.rs`, which meant the next node
//! family's manager would reimplement the caching, the two surface flavours and
//! the fail-closed behaviour from scratch. None of it is board- or OEM-specific:
//! the verb taxonomy and the issuer→ceiling policy are already in
//! [`super::authz`], and what is added here is only "read those anchors out of an
//! HSM keystore, and notice when they change".
//!
//! # The two surfaces, and why they differ
//!
//! - [`HsmAuthorizerDeps::destructive`] — factory-reset and ECU reboot.
//!   `boot_id`-bound (per-boot anti-replay), never read-open, and it never opens
//!   during the bootstrap window: the destructive routes call `authorize`
//!   directly and must enforce even on an unprovisioned device.
//! - [`HsmAuthorizerDeps::general`] — the routine SOVD path. Read-open (a
//!   tokenless low-consequence read is served anonymously; writes still need a
//!   token) and bootstrap-open while unprovisioned, because there are no issuer
//!   anchors yet to enforce with and the keystore install is itself
//!   envelope-authenticated.
//!
//! # Fail closed
//!
//! A failed build yields a `TieredAuthorizer` with **no** trusted issuers, so
//! every token is rejected. The failure mode of "cannot read the keystore" is
//! locked out, never wide open.
//!
//! A keystore read has three outcomes, and they are kept apart: the key is
//! there, the keystore has no such key, or the HSM could not be read. Only the
//! second is a fact about the keystore. An unreadable anchor contributes no
//! trust (except where the deployment's [`ExtraAnchor`] answers for it — the
//! dev recovery key, deliberately, and logged), and a build that saw any read
//! error is never cached: the next request rebuilds, so the unit heals by
//! itself once the HSM answers, with no restart and no keystore push.
//!
//! # No ECU id
//!
//! The ECU id is every token's expected `aud`. When it cannot be had (no device
//! key, or it could not be read) no keystore issuer and no delegate is trusted:
//! there is no audience to match them to. A build with an [`ExtraAnchor`] keeps
//! the unit resettable: the issuer ids that anchor answers for (resolved as
//! usual, keystore first) are trusted with the audience `""` — the one audience
//! a reset tool can use while the device cannot tell it its id — for ECU restart
//! and factory reset only.
//!
//! # What the deployment still owns
//!
//! - **The keystore path** — one `PathBuf`, not a config type. (It was a clone of
//!   an entire deployment `Config` struct held to reach exactly this field.)
//! - **The floor sink** — making a floor advance durable needs the host's clock;
//!   injected as [`FloorSink`] (`host_clock::ClockDiscipliningFloorSink` on a real
//!   node, `NoopFloorSink` elsewhere).
//! - **`extra_anchor`** — an out-of-keystore anchor lookup, consulted only where
//!   the keystore has no key for an id, or could not be read for it (logged).
//!   This is where a dev build puts the well-known factory recovery key so a rig
//!   with an empty keystore (or an unreadable HSM) is still factory-resettable.
//!   Deliberately NOT here: which builds get a dev escape
//!   hatch, and which key backs it, is a deployment policy decision.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use std::cell::RefCell;

use hsm::{HsmCryptoProvider, HsmError};
use sovd_api::{AccessRequest, AuthError, Authorizer, Capability, ClientContext};

use super::authz::{FloorSink, TieredAuthorizer};
use super::{identity, issuer_keys};

/// An out-of-keystore anchor lookup by key id, consulted only when the keystore
/// itself has no key for that id, or could not be read for it. See the module
/// docs.
pub type ExtraAnchor = Arc<dyn Fn(&str) -> Option<Vec<u8>> + Send + Sync>;

/// SPKI-DER of the well-known factory bootstrap key (`FACTORY_SIGNING_PUBLIC`,
/// P-256 `scalar=1` public). In dev builds it backs the factory-reset issuer
/// so a rig with no provisioned keystore is still factory-resettable — the same
/// public key the HSM already trusts to verify the first keystore install. A
/// deployment feeds it to the authorizer as its [`ExtraAnchor`]; whether and
/// under which condition is the deployment's (see the module docs).
#[cfg(feature = "dev-recovery-anchor")]
pub fn dev_recovery_anchor() -> Option<Vec<u8>> {
    use p256::pkcs8::EncodePublicKey;
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&hsm::payload::FACTORY_SIGNING_PUBLIC)
        .ok()?
        .to_public_key_der()
        .ok()
        .map(|doc| doc.into_vec())
}

/// The cache cell.
#[derive(Default)]
struct CacheCell {
    /// The last complete build: the keystore-manifest mtime it was built from
    /// (`None` = no manifest, i.e. unprovisioned), and the authorizer.
    built: Option<(Option<std::time::SystemTime>, Arc<dyn Authorizer>)>,
    /// The key ids the last build could not read (empty = it was complete), so
    /// a degraded state is logged when it starts and ends, not per request.
    unreadable: Vec<String>,
}

/// Everything an HSM-backed authorizer needs from its deployment. Build one, then
/// call [`Self::destructive`] or [`Self::general`] to get the surface you want.
pub struct HsmAuthorizerDeps {
    /// The HSM keystore directory. Its `manifest` file is both the
    /// "is this device provisioned?" marker and the cache-invalidation clock —
    /// `install-keystore` rewrites it on every push.
    pub keystore: PathBuf,
    /// Shared crypto handle: reads the issuer-anchor and delegation-root SPKI
    /// pubkeys each time the authorizer is (re)built.
    pub crypto: Arc<dyn HsmCryptoProvider>,
    /// Shared live safe-time floor (UNIX seconds). Handed to every rebuilt
    /// `TieredAuthorizer` so the delegated (`x5c`) path judges cert validity
    /// against `max(now, floor)` — the clockless-device fix. Read live per
    /// request inside the authorizer, so a runtime ratchet is picked up without a
    /// cache rebuild.
    pub time_floor_secs: Arc<AtomicU64>,
    /// Makes a floor advance durable (HSM ratchet + wall clock). See the module docs.
    pub floor_sink: Arc<dyn FloorSink>,
    /// Optional out-of-keystore anchor lookup. See [`ExtraAnchor`].
    pub extra_anchor: Option<ExtraAnchor>,
}

impl HsmAuthorizerDeps {
    /// The authorizer for destructive operator routes (factory-reset, ECU reboot):
    /// `boot_id`-bound, never read-open, always enforcing.
    pub fn destructive(self, boot_id: &str) -> Arc<dyn Authorizer> {
        Arc::new(CachedHsmAuthorizer {
            boot_id: Some(boot_id.to_string()),
            read_open: false,
            bootstrap_open: false,
            force_open: false,
            deps: self,
            cache: Default::default(),
        })
    }

    /// The authorizer for the general SOVD path: read-open, not `boot_id`-bound,
    /// bootstrap-open while unprovisioned. `allow_unauthenticated` is the dev
    /// escape hatch that keeps it open even once provisioned.
    pub fn general(self, allow_unauthenticated: bool) -> Arc<dyn Authorizer> {
        Arc::new(CachedHsmAuthorizer {
            boot_id: None,
            read_open: true,
            bootstrap_open: true,
            force_open: allow_unauthenticated,
            deps: self,
            cache: Default::default(),
        })
    }
}

/// Where an anchor's SPKI-DER comes from: the keystore first, then the
/// deployment's [`ExtraAnchor`] if it has one.
///
/// Takes the keystore lookup as a closure rather than a `&dyn HsmCryptoProvider`
/// so the precedence rule — which is the whole content of this function — is
/// testable without standing up an HSM. The order matters: a provisioned device
/// must use its OWN anchor, never a build-time fallback that happens to share the
/// key id.
fn anchor_der(
    from_keystore: impl Fn(&str) -> Option<Vec<u8>>,
    extra: Option<&ExtraAnchor>,
    id: &str,
) -> Option<Vec<u8>> {
    from_keystore(id).or_else(|| extra.and_then(|f| f(id)))
}

/// A keystore read with "the keystore has no such key" (`Ok(None)`) kept apart
/// from "the HSM could not be read" (`Err`). `NotProvisioned` is an empty
/// keystore, so it is absence too.
fn keystore_read(read: Result<Vec<u8>, HsmError>) -> Result<Option<Vec<u8>>, HsmError> {
    match read {
        Ok(der) => Ok(Some(der)),
        Err(HsmError::KeyNotFound(_) | HsmError::NotProvisioned) => Ok(None),
        Err(e) => Err(e),
    }
}

/// The audience a recovery-anchor token carries while the unit has no ECU id.
/// See the module docs.
const NO_ID_RECOVERY_AUDIENCE: &str = "";

/// One build, and the keystore reads it could not make — `(key id, error)`.
/// A build with any is degraded and must not be cached.
struct Built {
    authorizer: Arc<dyn Authorizer>,
    unreadable: Vec<(String, String)>,
}

/// Read the HSM keystore (issuer anchors + the delegation root via
/// `get_trust_anchor_der`) and construct the tiered authorizer. Re-run whenever
/// the keystore changes. `boot_id = Some` binds accepted tokens to the current
/// boot (destructive routes); `read_open` serves tokenless reads anonymously
/// (general path).
///
/// Fails closed: a build error yields an authorizer trusting no issuer, and an
/// anchor the HSM could not read is trusted only where `extra_anchor` answers
/// for it. See the module docs for the no-ECU-id rule.
pub fn build_authorizer_now(
    crypto: &dyn HsmCryptoProvider,
    boot_id: Option<&str>,
    read_open: bool,
    time_floor_secs: Arc<AtomicU64>,
    floor_sink: Arc<dyn FloorSink>,
    extra_anchor: Option<&ExtraAnchor>,
) -> Arc<dyn Authorizer> {
    build(
        crypto,
        boot_id,
        read_open,
        time_floor_secs,
        floor_sink,
        extra_anchor,
    )
    .authorizer
}

fn build(
    crypto: &dyn HsmCryptoProvider,
    boot_id: Option<&str>,
    read_open: bool,
    time_floor_secs: Arc<AtomicU64>,
    floor_sink: Arc<dyn FloorSink>,
    extra_anchor: Option<&ExtraAnchor>,
) -> Built {
    let unreadable = RefCell::new(Vec::new());
    // A read error is recorded (the build is then degraded) and contributes
    // nothing from the keystore; it is never taken as "the keystore has no such
    // key".
    let or_note = |id: &str, read: Result<Option<Vec<u8>>, HsmError>| {
        read.unwrap_or_else(|e| {
            unreadable
                .borrow_mut()
                .push((id.to_string(), e.to_string()));
            None
        })
    };
    let from_keystore = |id: &str| -> Option<Vec<u8>> {
        let h = hsm::vhsm_proto::handle_for_key_id(id)?;
        or_note(
            id,
            keystore_read(crypto.get_public_key_der(hsm::KeyHandle::new(h))),
        )
    };
    // Both closures capture only shared references, so they are `Copy` — `der_for`
    // can be passed by value to both consumers below. An unreadable anchor falls
    // through to `extra_anchor` here: where the deployment has one (dev recovery)
    // that is deliberate, and it is logged with the degraded state.
    let der_for = |id: &str| anchor_der(from_keystore, extra_anchor, id);
    // The delegation root rides the SAME keystore as the issuer anchors: when the
    // device provisioned one, `authorizer_from_anchors` pins it and the x5c
    // delegated path (a workshop delegate's reset token) is accepted for the
    // High-consequence reset / factory-reset routes. Absent = delegation stays
    // off, only the pinned issuers are trusted.
    let anchor_for = |id: &str| match crypto.get_trust_anchor_der(id) {
        // The provider has no trust-anchor store (the trait default): no root.
        Err(HsmError::NotSupported(_)) => None,
        read => or_note(id, keystore_read(read)),
    };
    // `audience` = this ECU's own id (its device-key thumbprint), the cross-ECU
    // replay guard.
    let audience = identity::ecu_id(der_for);
    let recovery_only = audience.is_none() && extra_anchor.is_some();
    let built = match (audience.as_deref(), extra_anchor) {
        (Some(aud), _) => issuer_keys::authorizer_from_anchors(der_for, anchor_for, aud),
        // No id: no audience to match a keystore issuer or a delegate to. Only
        // the ids the recovery anchor answers for stay trusted (keystore first,
        // as everywhere), with the no-id audience; `RecoveryOnly` below limits
        // them to restart and factory reset.
        (None, Some(extra)) => issuer_keys::authorizer_from_anchors(
            |id| extra(id).and_then(|_| der_for(id)),
            |_| None,
            NO_ID_RECOVERY_AUDIENCE,
        ),
        (None, None) => Ok(TieredAuthorizer::new(Vec::new())),
    };
    let base = match built {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("authorizer build failed: {e}");
            TieredAuthorizer::new(Vec::new())
        }
    };
    // boot_id binding (destructive routes only) + read-open (general path only).
    let base = match boot_id {
        Some(b) => base.with_boot_id(b),
        None => base,
    };
    let base = if read_open {
        base.with_read_open()
    } else {
        base
    };
    // Share the live safe-time floor so the delegated path uses max(now, floor),
    // and a sink that makes a ratchet from a verified delegate's not_before
    // durable — so the JWT time checks (raw wall clock) also see it.
    let base = base
        .with_time_floor(time_floor_secs)
        .with_floor_sink(floor_sink);
    let authorizer: Arc<dyn Authorizer> = if recovery_only {
        Arc::new(RecoveryOnly(base))
    } else {
        Arc::new(base)
    };
    Built {
        authorizer,
        unreadable: unreadable.into_inner(),
    }
}

/// The authorizer of a unit with no ECU id on a build with a recovery anchor:
/// a token may only restart the ECU or factory-reset it. Anything else that
/// carries a token is refused before the issuer check; tokenless reads still
/// reach the inner authorizer's read-open rule.
struct RecoveryOnly(TieredAuthorizer);

#[async_trait::async_trait]
impl Authorizer for RecoveryOnly {
    async fn authorize(&self, req: &AccessRequest<'_>) -> Result<ClientContext, AuthError> {
        if req.bearer.is_some()
            && !matches!(
                req.capability,
                Capability::ResetExecute | Capability::FactoryReset
            )
        {
            return Err(AuthError::Forbidden(
                "no ECU id: only ECU restart and factory reset are authorised".into(),
            ));
        }
        self.0.authorize(req).await
    }
}

/// The `is_open` decision (surface unauthenticated), factored out for testing.
/// Open when the dev escape hatch is set, or — general path (`bootstrap_open`) —
/// while the device is unprovisioned: no keystore `manifest` yet, so no issuer
/// anchors to enforce with, and the keystore install is envelope-authenticated.
/// Once the manifest lands the surface closes and writes enforce.
pub fn surface_is_open(keystore: &Path, bootstrap_open: bool, force_open: bool) -> bool {
    force_open || (bootstrap_open && !keystore.join("manifest").exists())
}

/// Caches an HSM-keystore-backed authorizer (destructive or general surface),
/// rebuilding it only when the keystore is (re)provisioned — detected via the
/// keystore manifest's mtime, which `install-keystore` rewrites on every push. So a
/// delegation root or issuer anchor installed after boot is honoured on the next
/// request, with no per-request rebuild.
struct CachedHsmAuthorizer {
    deps: HsmAuthorizerDeps,
    boot_id: Option<String>,
    read_open: bool,
    /// Report `is_open` (surface unauthenticated) while the device is unprovisioned
    /// — the bootstrap window, before any issuer anchor exists. General path only.
    bootstrap_open: bool,
    /// Dev escape hatch: report `is_open` unconditionally (open even when
    /// provisioned). General path only.
    force_open: bool,
    cache: tokio::sync::Mutex<CacheCell>,
}

impl CachedHsmAuthorizer {
    /// Log a degraded build when the set of unreadable keys changes — not on
    /// every request, though a degraded authorizer is rebuilt on every request.
    fn log_state_change(&self, cell: &mut CacheCell, unreadable: &[(String, String)]) {
        let ids: Vec<String> = unreadable.iter().map(|(id, _)| id.clone()).collect();
        if ids == cell.unreadable {
            return;
        }
        if unreadable.is_empty() {
            tracing::info!("HSM keystore readable again: authorizer rebuilt and cached");
        }
        for (id, e) in unreadable {
            let recovery = self.deps.extra_anchor.as_ref().and_then(|f| f(id));
            if recovery.is_some() {
                tracing::error!(
                    "HSM keystore unreadable for '{id}' ({e}): using the build's recovery anchor"
                );
            } else {
                tracing::error!(
                    "HSM keystore unreadable for '{id}' ({e}): not trusted; \
                     authorizer not cached, rebuilt per request until the HSM answers"
                );
            }
        }
        cell.unreadable = ids;
    }
}

#[async_trait::async_trait]
impl Authorizer for CachedHsmAuthorizer {
    fn is_open(&self) -> bool {
        surface_is_open(&self.deps.keystore, self.bootstrap_open, self.force_open)
    }

    async fn authorize(
        &self,
        req: &sovd_api::AccessRequest<'_>,
    ) -> Result<sovd_api::ClientContext, sovd_api::AuthError> {
        // "Did the HSM change?" = the keystore manifest's mtime; install-keystore
        // rewrites it on every (re)provision. A missing manifest (un-provisioned)
        // reads as None and rebuilds the same way.
        let manifest = self.deps.keystore.join("manifest");
        let mtime = std::fs::metadata(&manifest).and_then(|m| m.modified()).ok();
        let authz = {
            let mut cell = self.cache.lock().await;
            match &cell.built {
                Some((m, a)) if *m == mtime => a.clone(),
                _ => {
                    let built = build(
                        self.deps.crypto.as_ref(),
                        self.boot_id.as_deref(),
                        self.read_open,
                        self.deps.time_floor_secs.clone(),
                        self.deps.floor_sink.clone(),
                        self.deps.extra_anchor.as_ref(),
                    );
                    self.log_state_change(&mut cell, &built.unreadable);
                    // Cache only a complete build. A degraded one serves this
                    // request (failing closed) and the next request rebuilds.
                    cell.built = built
                        .unreadable
                        .is_empty()
                        .then(|| (mtime, built.authorizer.clone()));
                    built.authorizer
                }
            }
        };
        authz.authorize(req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn general_path_opens_while_unprovisioned_closes_once_keystore_lands() {
        let dir = std::env::temp_dir().join("component-mgr-surface-is-open-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // General path (bootstrap_open), no manifest yet → open (bootstrap window).
        assert!(surface_is_open(&dir, true, false));
        // Keystore lands (manifest written) → closed; writes now enforce.
        std::fs::write(dir.join("manifest"), b"x").unwrap();
        assert!(!surface_is_open(&dir, true, false));
        // Dev escape hatch: open even with a keystore present.
        assert!(surface_is_open(&dir, true, true));

        // Destructive path (bootstrap_open = false) never opens here — provisioned
        // or not.
        assert!(!surface_is_open(&dir, false, false));
        let missing = PathBuf::from("/no/such/keystore");
        assert!(!surface_is_open(&missing, false, false));
        // ...but a bootstrap_open authorizer on a missing keystore IS open.
        assert!(surface_is_open(&missing, true, false));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A provisioned device must use its OWN anchor. If the deployment also
    /// supplies a fallback under the same key id — which is exactly what a dev
    /// build's factory-recovery key does — the keystore still wins, or a
    /// provisioned unit could be authorised by a build-time key.
    #[test]
    fn the_keystore_anchor_wins_over_the_deployment_fallback() {
        let extra: ExtraAnchor = Arc::new(|_| Some(b"fallback".to_vec()));
        let got = anchor_der(
            |_| Some(b"from-keystore".to_vec()),
            Some(&extra),
            "factory-reset-issuer",
        );
        assert_eq!(got.as_deref(), Some(&b"from-keystore"[..]));
    }

    /// The fallback is reached only where the keystore has nothing — the empty- or
    /// un-provisioned-keystore case it exists for.
    #[test]
    fn the_fallback_is_used_only_where_the_keystore_is_empty() {
        let extra: ExtraAnchor = Arc::new(|id| (id == "known").then(|| b"fallback".to_vec()));
        assert_eq!(
            anchor_der(|_| None, Some(&extra), "known").as_deref(),
            Some(&b"fallback"[..])
        );
        // A fallback that does not know the id yields nothing, not a default.
        assert_eq!(anchor_der(|_| None, Some(&extra), "other"), None);
    }

    /// No fallback wired (the production shape) → the keystore is the only source,
    /// and a missing anchor stays missing. `authorizer_from_anchors` then skips
    /// that issuer, which is the fail-closed direction.
    #[cfg(feature = "dev-recovery-anchor")]
    #[test]
    fn dev_recovery_anchor_round_trips_to_the_factory_key() {
        use p256::pkcs8::DecodePublicKey;
        let spki = dev_recovery_anchor().expect("recovery spki present");
        let vk = p256::ecdsa::VerifyingKey::from_public_key_der(&spki).expect("valid P-256 SPKI");
        assert_eq!(
            vk.to_encoded_point(false).as_bytes(),
            &hsm::payload::FACTORY_SIGNING_PUBLIC[..],
            "the dev recovery anchor must be the well-known factory key"
        );
    }

    #[test]
    fn without_a_fallback_a_missing_anchor_stays_missing() {
        assert_eq!(anchor_der(|_| None, None, "factory-reset-issuer"), None);
        assert_eq!(
            anchor_der(|_| Some(b"k".to_vec()), None, "x").as_deref(),
            Some(&b"k"[..])
        );
    }

    // ---- keystore read outcomes, the no-id rule, and the cache ----------

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use hsm::{KeyHandle, KeyRole, SlotInfo};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};

    use super::super::authz::NoopFloorSink;

    const FRI: &str = "factory-reset-issuer";

    /// What the fake keystore answers for one key.
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Slot {
        Has,
        Absent,
        Unreadable,
    }

    fn key(scalar: u8) -> SigningKey {
        let mut s = [0u8; 32];
        s[31] = scalar;
        SigningKey::from_bytes(&p256::FieldBytes::from(s)).unwrap()
    }
    fn spki(k: &SigningKey) -> Vec<u8> {
        k.verifying_key().to_public_key_der().unwrap().into_vec()
    }
    /// The device key (its thumbprint is the ECU id).
    fn device_key() -> SigningKey {
        key(7)
    }
    /// The unit's own provisioned factory-reset issuer.
    fn keystore_issuer() -> SigningKey {
        key(5)
    }
    /// The build's recovery anchor (the well-known `scalar=1` dev key).
    fn recovery_issuer() -> SigningKey {
        key(1)
    }
    fn ecu_id() -> String {
        identity::ecu_id_from_spki_der(&spki(&device_key()))
    }
    fn recovery_extra() -> ExtraAnchor {
        Arc::new(|id| (id == FRI).then(|| spki(&recovery_issuer())))
    }

    /// An HSM whose device key, factory-reset-issuer anchor and delegation root
    /// can each be present, absent or unreadable, and that counts key reads.
    struct FakeHsm {
        device_key: Mutex<Slot>,
        reset_issuer: Mutex<Slot>,
        delegation_root: Mutex<Slot>,
        pubkey_reads: AtomicUsize,
    }

    impl FakeHsm {
        fn new(device_key: Slot, reset_issuer: Slot) -> Arc<Self> {
            Arc::new(Self {
                device_key: Mutex::new(device_key),
                reset_issuer: Mutex::new(reset_issuer),
                delegation_root: Mutex::new(Slot::Absent),
                pubkey_reads: AtomicUsize::new(0),
            })
        }
        fn reads(&self) -> usize {
            self.pubkey_reads.load(Ordering::SeqCst)
        }
    }

    fn answer(slot: Slot, der: impl FnOnce() -> Vec<u8>) -> Result<Vec<u8>, HsmError> {
        match slot {
            Slot::Has => Ok(der()),
            Slot::Absent => Err(HsmError::KeyNotFound("absent".into())),
            Slot::Unreadable => Err(HsmError::CryptoError("link down".into())),
        }
    }

    impl HsmCryptoProvider for FakeHsm {
        fn sign(&self, _: KeyHandle, _: &[u8]) -> Result<Vec<u8>, HsmError> {
            Err(HsmError::NotSupported("fake".into()))
        }
        fn verify(&self, _: KeyHandle, _: &[u8], _: &[u8]) -> Result<bool, HsmError> {
            Err(HsmError::NotSupported("fake".into()))
        }
        fn encrypt(&self, _: KeyHandle, _: &[u8]) -> Result<Vec<u8>, HsmError> {
            Err(HsmError::NotSupported("fake".into()))
        }
        fn decrypt(&self, _: KeyHandle, _: &[u8]) -> Result<Vec<u8>, HsmError> {
            Err(HsmError::NotSupported("fake".into()))
        }
        fn mac_generate(&self, _: KeyHandle, _: &[u8]) -> Result<Vec<u8>, HsmError> {
            Err(HsmError::NotSupported("fake".into()))
        }
        fn mac_verify(&self, _: KeyHandle, _: &[u8], _: &[u8]) -> Result<bool, HsmError> {
            Err(HsmError::NotSupported("fake".into()))
        }
        fn derive(&self, _: KeyHandle, _: &[u8], _: usize) -> Result<Vec<u8>, HsmError> {
            Err(HsmError::NotSupported("fake".into()))
        }
        fn random(&self, _: usize) -> Result<Vec<u8>, HsmError> {
            Err(HsmError::NotSupported("fake".into()))
        }
        fn get_certificate_der(&self, _: KeyHandle) -> Result<Vec<u8>, HsmError> {
            Err(HsmError::NotSupported("fake".into()))
        }
        fn get_public_key_der(&self, h: KeyHandle) -> Result<Vec<u8>, HsmError> {
            self.pubkey_reads.fetch_add(1, Ordering::SeqCst);
            if h == KeyRole::DeviceDecryption.handle() {
                answer(*self.device_key.lock().unwrap(), || spki(&device_key()))
            } else if h == KeyRole::FactoryResetIssuer.handle() {
                answer(*self.reset_issuer.lock().unwrap(), || {
                    spki(&keystore_issuer())
                })
            } else {
                answer(Slot::Absent, Vec::new)
            }
        }
        fn get_trust_anchor_der(&self, _: &str) -> Result<Vec<u8>, HsmError> {
            // Never `Has` in these tests: a root would need a real certificate.
            answer(*self.delegation_root.lock().unwrap(), Vec::new)
        }
        fn get_slot_info(&self, _: KeyHandle) -> Result<SlotInfo, HsmError> {
            Err(HsmError::NotSupported("fake".into()))
        }
    }

    fn token(sk: &SigningKey, aud: &str, scope: &str) -> String {
        let enc =
            EncodingKey::from_ec_pem(sk.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes()).unwrap();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(FRI.to_string());
        let claims = serde_json::json!({
            "sub": "operator", "iss": FRI, "aud": aud, "boot_id": "boot-1",
            "exp": 9_999_999_999u64, "scope": scope,
        });
        format!("Bearer {}", encode(&header, &claims, &enc).unwrap())
    }

    async fn accepts(authz: &dyn Authorizer, bearer: &str, capability: Capability) -> bool {
        authz
            .authorize(&AccessRequest {
                bearer: Some(bearer),
                method: &axum::http::Method::POST,
                path: "/x",
                component: None,
                capability,
            })
            .await
            .is_ok()
    }

    fn build_for(hsm: &FakeHsm, extra: Option<&ExtraAnchor>) -> Arc<dyn Authorizer> {
        build_authorizer_now(
            hsm,
            None,
            false,
            Arc::new(AtomicU64::new(0)),
            Arc::new(NoopFloorSink),
            extra,
        )
    }

    /// {keystore has the factory-reset-issuer key, has none, cannot be read}
    /// x {build with / without the recovery anchor} x {ECU id readable /
    /// unreadable}, against a factory reset. Columns: a keystore-issuer token
    /// and a recovery-anchor token, each with this ECU's id, a wrong audience,
    /// and the empty audience.
    #[tokio::test]
    async fn keystore_outcome_x_build_x_id_table() {
        use Slot::*;
        const T: bool = true;
        const F: bool = false;
        #[rustfmt::skip]
        let table: &[(Slot, bool, bool, [bool; 6])] = &[
            //                       ks:id rec:id ks:wrong rec:wrong ks:"" rec:""
            (Has,        T, T, [T, F, F, F, F, F]),
            (Has,        F, T, [T, F, F, F, F, F]),
            (Absent,     T, T, [F, T, F, F, F, F]),
            (Absent,     F, T, [F, F, F, F, F, F]),
            (Unreadable, T, T, [F, T, F, F, F, F]),
            (Unreadable, F, T, [F, F, F, F, F, F]),
            (Has,        T, F, [F, F, F, F, T, F]),
            (Has,        F, F, [F, F, F, F, F, F]),
            (Absent,     T, F, [F, F, F, F, F, T]),
            (Absent,     F, F, [F, F, F, F, F, F]),
            (Unreadable, T, F, [F, F, F, F, F, T]),
            (Unreadable, F, F, [F, F, F, F, F, F]),
        ];
        let id = ecu_id();
        let extra = recovery_extra();
        let (ks, rec) = (keystore_issuer(), recovery_issuer());
        for &(issuer_slot, with_extra, id_readable, want) in table {
            let device = if id_readable { Has } else { Unreadable };
            let hsm = FakeHsm::new(device, issuer_slot);
            let authz = build_for(&hsm, with_extra.then_some(&extra));
            let tokens = [
                token(&ks, &id, "factory-reset"),
                token(&rec, &id, "factory-reset"),
                token(&ks, "another-ecu", "factory-reset"),
                token(&rec, "another-ecu", "factory-reset"),
                token(&ks, "", "factory-reset"),
                token(&rec, "", "factory-reset"),
            ];
            for (col, (bearer, want)) in tokens.iter().zip(want).enumerate() {
                assert_eq!(
                    accepts(authz.as_ref(), bearer, Capability::FactoryReset).await,
                    want,
                    "keystore {issuer_slot:?}, extra anchor {with_extra}, \
                     id readable {id_readable}, column {col}"
                );
            }
        }
    }

    /// With no ECU id, the recovery-anchor token restarts and factory-resets
    /// the unit and does nothing else; tokenless reads stay read-open. A
    /// device key that is absent (not unreadable) gets the same rule.
    #[tokio::test]
    async fn without_an_ecu_id_the_recovery_anchor_only_restarts_and_resets() {
        let extra = recovery_extra();
        let rec = recovery_issuer();
        for device in [Slot::Unreadable, Slot::Absent] {
            let hsm = FakeHsm::new(device, Slot::Absent);
            let authz = build_authorizer_now(
                hsm.as_ref(),
                None,
                true,
                Arc::new(AtomicU64::new(0)),
                Arc::new(NoopFloorSink),
                Some(&extra),
            );
            let all = token(&rec, "", "factory-reset reset:execute data:write");
            assert!(accepts(authz.as_ref(), &all, Capability::FactoryReset).await);
            assert!(accepts(authz.as_ref(), &all, Capability::ResetExecute).await);
            assert!(!accepts(authz.as_ref(), &all, Capability::DataWrite).await);
            let read = authz
                .authorize(&AccessRequest {
                    bearer: None,
                    method: &axum::http::Method::GET,
                    path: "/x",
                    component: None,
                    capability: Capability::Read,
                })
                .await;
            assert!(read.is_ok(), "{device:?}: tokenless read stays open");
        }
    }

    fn cached(hsm: &Arc<FakeHsm>, extra: Option<ExtraAnchor>, dir: &str) -> Arc<dyn Authorizer> {
        let keystore = std::env::temp_dir().join(dir);
        let _ = std::fs::remove_dir_all(&keystore);
        std::fs::create_dir_all(&keystore).unwrap();
        std::fs::write(keystore.join("manifest"), b"x").unwrap();
        HsmAuthorizerDeps {
            keystore,
            crypto: hsm.clone(),
            time_floor_secs: Arc::new(AtomicU64::new(0)),
            floor_sink: Arc::new(NoopFloorSink),
            extra_anchor: extra,
        }
        .destructive("boot-1")
    }

    /// A complete build is cached: the keystore is not read again per request.
    #[tokio::test]
    async fn a_complete_build_is_cached() {
        let hsm = FakeHsm::new(Slot::Has, Slot::Has);
        let authz = cached(&hsm, None, "component-mgr-authz-cache-complete");
        let ok = token(&keystore_issuer(), &ecu_id(), "factory-reset");
        assert!(accepts(authz.as_ref(), &ok, Capability::FactoryReset).await);
        let reads = hsm.reads();
        assert!(reads > 0);
        assert!(accepts(authz.as_ref(), &ok, Capability::FactoryReset).await);
        assert_eq!(hsm.reads(), reads, "no rebuild for a cached build");
    }

    /// A build during an HSM outage fails closed and is not cached: the next
    /// request rebuilds, and once the HSM answers a valid token is accepted —
    /// no restart, no manifest change — and that build is cached.
    #[tokio::test]
    async fn a_build_during_an_outage_is_rebuilt_and_heals() {
        let hsm = FakeHsm::new(Slot::Unreadable, Slot::Unreadable);
        *hsm.delegation_root.lock().unwrap() = Slot::Unreadable;
        let authz = cached(&hsm, None, "component-mgr-authz-cache-outage");
        let ok = token(&keystore_issuer(), &ecu_id(), "factory-reset");
        assert!(!accepts(authz.as_ref(), &ok, Capability::FactoryReset).await);
        let reads = hsm.reads();
        assert!(!accepts(authz.as_ref(), &ok, Capability::FactoryReset).await);
        assert!(
            hsm.reads() > reads,
            "a degraded build is rebuilt per request"
        );

        *hsm.device_key.lock().unwrap() = Slot::Has;
        *hsm.reset_issuer.lock().unwrap() = Slot::Has;
        *hsm.delegation_root.lock().unwrap() = Slot::Absent;
        assert!(accepts(authz.as_ref(), &ok, Capability::FactoryReset).await);
        let reads = hsm.reads();
        assert!(accepts(authz.as_ref(), &ok, Capability::FactoryReset).await);
        assert_eq!(hsm.reads(), reads, "the healed build is cached");
    }

    /// A delegation root that cannot be read degrades the build too, though
    /// every issuer anchor and the id were read.
    #[tokio::test]
    async fn an_unreadable_delegation_root_is_not_cached() {
        let hsm = FakeHsm::new(Slot::Has, Slot::Has);
        *hsm.delegation_root.lock().unwrap() = Slot::Unreadable;
        let authz = cached(&hsm, None, "component-mgr-authz-cache-root");
        let ok = token(&keystore_issuer(), &ecu_id(), "factory-reset");
        assert!(accepts(authz.as_ref(), &ok, Capability::FactoryReset).await);
        let reads = hsm.reads();
        assert!(accepts(authz.as_ref(), &ok, Capability::FactoryReset).await);
        assert!(hsm.reads() > reads, "rebuilt: the root read failed");
    }

    /// Dev build, provisioned unit: while its own reset-issuer anchor cannot
    /// be read the recovery anchor stands in (the unit stays resettable), but
    /// that build is not cached, so once the HSM answers the unit's own anchor
    /// wins again and the recovery key no longer authorises it.
    #[tokio::test]
    async fn the_recovery_anchor_stands_in_only_while_the_keystore_is_unreadable() {
        let hsm = FakeHsm::new(Slot::Has, Slot::Unreadable);
        let authz = cached(
            &hsm,
            Some(recovery_extra()),
            "component-mgr-authz-cache-recovery",
        );
        let own = token(&keystore_issuer(), &ecu_id(), "factory-reset");
        let recovery = token(&recovery_issuer(), &ecu_id(), "factory-reset");
        assert!(accepts(authz.as_ref(), &recovery, Capability::FactoryReset).await);
        assert!(!accepts(authz.as_ref(), &own, Capability::FactoryReset).await);

        *hsm.reset_issuer.lock().unwrap() = Slot::Has;
        assert!(accepts(authz.as_ref(), &own, Capability::FactoryReset).await);
        assert!(!accepts(authz.as_ref(), &recovery, Capability::FactoryReset).await);
    }

    /// The three outcomes of a keystore read: present, absent (no such key, or
    /// an unprovisioned keystore), and unreadable (anything else).
    #[test]
    fn keystore_read_keeps_absent_and_unreadable_apart() {
        assert_eq!(keystore_read(Ok(vec![1])).unwrap(), Some(vec![1]));
        assert_eq!(
            keystore_read(Err(HsmError::KeyNotFound("x".into()))).unwrap(),
            None
        );
        assert_eq!(keystore_read(Err(HsmError::NotProvisioned)).unwrap(), None);
        assert!(keystore_read(Err(HsmError::CryptoError("down".into()))).is_err());
        assert!(keystore_read(Err(HsmError::NotRunning)).is_err());
    }
}
