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
//! # What the deployment still owns
//!
//! - **The keystore path** — one `PathBuf`, not a config type. (It was a clone of
//!   an entire deployment `Config` struct held to reach exactly this field.)
//! - **The floor sink** — making a floor advance durable needs the host's clock;
//!   injected as [`FloorSink`] (`host_clock::ClockDiscipliningFloorSink` on a real
//!   node, `NoopFloorSink` elsewhere).
//! - **`extra_anchor`** — an out-of-keystore anchor lookup, consulted only where
//!   the keystore has no key for an id. This is where a dev build puts the
//!   well-known factory recovery key so a rig with an empty keystore is still
//!   factory-resettable. Deliberately NOT here: which builds get a dev escape
//!   hatch, and which key backs it, is a deployment policy decision.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use hsm::HsmCryptoProvider;
use sovd_api::Authorizer;

use super::authz::{FloorSink, TieredAuthorizer};
use super::{identity, issuer_keys};

/// An out-of-keystore anchor lookup by key id, consulted only when the keystore
/// itself has no key for that id. See the module docs.
pub type ExtraAnchor = Arc<dyn Fn(&str) -> Option<Vec<u8>> + Send + Sync>;

/// The cache cell: the keystore-manifest mtime the cached authorizer was built
/// from (`None` = no manifest, i.e. unprovisioned), and the authorizer.
type CacheCell = Option<(Option<std::time::SystemTime>, Arc<dyn Authorizer>)>;

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
            cache: tokio::sync::Mutex::new(None),
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
            cache: tokio::sync::Mutex::new(None),
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

/// Read the HSM keystore (issuer anchors + the delegation root via
/// `get_trust_anchor_der`) and construct the tiered authorizer. Re-run whenever
/// the keystore changes. `boot_id = Some` binds accepted tokens to the current
/// boot (destructive routes); `read_open` serves tokenless reads anonymously
/// (general path).
///
/// Fails closed: a build error yields an authorizer trusting no issuer.
pub fn build_authorizer_now(
    crypto: &dyn HsmCryptoProvider,
    boot_id: Option<&str>,
    read_open: bool,
    time_floor_secs: Arc<AtomicU64>,
    floor_sink: Arc<dyn FloorSink>,
    extra_anchor: Option<&ExtraAnchor>,
) -> Arc<dyn Authorizer> {
    let from_keystore = |id: &str| -> Option<Vec<u8>> {
        let h = hsm::vhsm_proto::handle_for_key_id(id)?;
        crypto.get_public_key_der(hsm::KeyHandle::new(h)).ok()
    };
    // Both closures capture only shared references, so they are `Copy` — `der_for`
    // can be passed by value to both consumers below.
    let der_for = |id: &str| anchor_der(from_keystore, extra_anchor, id);
    // The delegation root rides the SAME keystore as the issuer anchors: when the
    // device provisioned one, `authorizer_from_anchors` pins it and the x5c
    // delegated path (a workshop delegate's reset token) is accepted for the
    // High-consequence reset / factory-reset routes. Absent = delegation stays
    // off, only the pinned issuers are trusted.
    let anchor_for = |id: &str| crypto.get_trust_anchor_der(id).ok();
    // `audience` = this ECU's own id (its device-key thumbprint), the cross-ECU
    // replay guard.
    let audience = identity::ecu_id(der_for).unwrap_or_default();
    let base = match issuer_keys::authorizer_from_anchors(der_for, anchor_for, &audience) {
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
    Arc::new(
        base.with_time_floor(time_floor_secs)
            .with_floor_sink(floor_sink),
    )
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

#[async_trait::async_trait]
impl Authorizer for CachedHsmAuthorizer {
    fn is_open(&self) -> bool {
        surface_is_open(&self.deps.keystore, self.bootstrap_open, self.force_open)
    }

    async fn authorize(
        &self,
        req: &sovd_api::AccessRequest<'_>,
    ) -> Result<sovd_api::ClientContext, String> {
        // "Did the HSM change?" = the keystore manifest's mtime; install-keystore
        // rewrites it on every (re)provision. A missing manifest (un-provisioned)
        // reads as None and rebuilds the same way.
        let manifest = self.deps.keystore.join("manifest");
        let mtime = std::fs::metadata(&manifest).and_then(|m| m.modified()).ok();
        let authz = {
            let mut guard = self.cache.lock().await;
            let fresh = matches!(&*guard, Some((m, _)) if *m == mtime);
            if !fresh {
                *guard = Some((
                    mtime,
                    build_authorizer_now(
                        self.deps.crypto.as_ref(),
                        self.boot_id.as_deref(),
                        self.read_open,
                        self.deps.time_floor_secs.clone(),
                        self.deps.floor_sink.clone(),
                        self.deps.extra_anchor.as_ref(),
                    ),
                ));
            }
            guard.as_ref().expect("cache populated above").1.clone()
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
    #[test]
    fn without_a_fallback_a_missing_anchor_stays_missing() {
        assert_eq!(anchor_der(|_| None, None, "factory-reset-issuer"), None);
        assert_eq!(
            anchor_der(|_| Some(b"k".to_vec()), None, "x").as_deref(),
            Some(&b"k"[..])
        );
    }
}
