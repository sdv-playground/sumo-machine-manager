//! Link-B provisioning round-trips against a REAL `SimHsm`.
//!
//! These exercise `hsm::link_b::serve` (the full crypto + provisioning loop the
//! `hsm-sim-service` bin runs) and `hsm::link_b::LinkBProvider` against a real
//! `SimHsm` backend over a temp keystore. They moved here from the `hsm` crate's
//! own `link_b` tests in S7b: `hsm` no longer owns a concrete backend (SimHsm
//! relocated to this crate), and `hsm` cannot depend on `hsm-sim-backend`
//! (that would be a cycle), so the real-backend integration coverage lives here.
//! The mock-backed wire-framing coverage (`serve_crypto`) stays in `hsm`.

use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};
use std::thread;

use hsm::link_b::{serve, LinkBClient, LinkBProvider};
use hsm::payload::{HsmKeystore, KeySlot, KEY_TYPE_AES_256, KEY_TYPE_EC_P256, SCHEMA_VERSION};
use hsm::{HsmError, HsmProvider, KeyRole, ProvisioningState};
use hsm_sim_backend::SimHsm;

/// A signing EC slot (has a public half → get_public_key) + the AES storage slot
/// — the suit-less `write_keystore` core that `provision` ultimately calls, the
/// same shortcut the sim's own provisioning tests use to reach a provisioned
/// state without building a signed+encrypted SUIT envelope.
fn provisioned_keystore() -> HsmKeystore {
    HsmKeystore {
        schema_version: SCHEMA_VERSION,
        security_version: 1,
        identities: Vec::new(),
        slots: vec![
            KeySlot {
                key_id: KeyRole::JwtSigning.key_id().to_string(),
                key_kind: KEY_TYPE_EC_P256,
                anchor_public_key: None,
                allowed_guests: None,
                allowed_ops: None,
            },
            KeySlot {
                key_id: KeyRole::Storage.key_id().to_string(),
                key_kind: KEY_TYPE_AES_256,
                anchor_public_key: None,
                allowed_guests: None,
                allowed_ops: None,
            },
        ],
        certificates: Vec::new(),
        trust_anchors: Vec::new(),
    }
}

/// Provisioning-half round trip — mirror of `hsm`'s crypto-op round trip for the
/// `0x20..=0x27` ops, but against a REAL `SimHsm` over a temp keystore (served
/// through the same combined [`serve`] loop `hsm-sim-service` runs), not a mock.
/// Drives a `LinkBClient` through is_provisioned → provision → get_public_key →
/// list_keys (+ provisioning_state and the enrolment trio).
///
/// `provision` over the wire is exercised against a garbage envelope (it must
/// route to `HsmProvider::provision` and the error category must round-trip); a
/// *valid* factory provision needs a signed+encrypted SUIT envelope built from
/// `sumo-offboard`, which is not a dependency here. The provisioned state the
/// read ops need is therefore established via the suit-less `write_keystore`
/// core that `provision` ultimately calls.
#[test]
fn link_b_round_trips_provisioning_ops_against_real_sim_hsm() {
    let dir = tempfile::tempdir().unwrap();
    let keystore = dir.path().to_path_buf();
    let sock = dir.path().join("hsm-sim-prov.sock");

    // Shared Arc<Mutex<…>>: the serve thread drives wire ops; the test side
    // provisions in-process. `serve` locks per op, so an idle peer never
    // holds the lock the test needs.
    let hsm = Arc::new(Mutex::new(SimHsm::new(keystore)));

    let listener = UnixListener::bind(&sock).unwrap();
    let hsm_for_server = Arc::clone(&hsm);
    let server = thread::spawn(move || {
        let (stream, _addr) = listener.accept().unwrap();
        serve(stream, &*hsm_for_server);
    });

    let client = LinkBClient::connect(&sock).unwrap();

    // 1. Unprovisioned: the state ops report it; the inventory is empty.
    assert!(!client.is_provisioned().unwrap());
    assert_eq!(
        client.provisioning_state().unwrap(),
        ProvisioningState::Unprovisioned
    );
    assert!(client.list_keys().unwrap().is_empty());

    // 2. provision routes to HsmProvider::provision — a garbage envelope is
    //    rejected and the error category survives the wire round-trip.
    let err = client.provision(b"not a suit envelope").unwrap_err();
    assert!(
        matches!(
            err,
            HsmError::EnvelopeInvalid(_) | HsmError::PayloadInvalid(_) | HsmError::DecryptionFailed(_)
        ),
        "garbage envelope must be rejected with a provisioning error, got {err:?}"
    );
    assert!(
        !client.is_provisioned().unwrap(),
        "a rejected provision must leave the keystore unprovisioned"
    );

    // Establish the real provisioned state (suit-less write_keystore core).
    hsm.lock().unwrap().write_keystore(&provisioned_keystore()).unwrap();

    // 3. Provisioned: the state ops flip over the wire.
    assert!(client.is_provisioned().unwrap());
    assert_eq!(
        client.provisioning_state().unwrap(),
        ProvisioningState::Provisioned
    );

    // 4. get_public_key over the wire == the backend's own COSE_Key. The wire
    //    carries SPKI DER; the client rebuilds the COSE_Key. For a signing
    //    role both encodings tag ES256, so the bytes match exactly.
    let wire_cose = client.get_public_key(KeyRole::JwtSigning).unwrap();
    let direct_cose = hsm.lock().unwrap().get_public_key(KeyRole::JwtSigning).unwrap();
    assert_eq!(
        wire_cose, direct_cose,
        "wire-reconstructed COSE_Key must equal the backend's get_public_key"
    );
    assert!(!wire_cose.is_empty());

    // 5. list_keys over the wire == the backend's inventory, field-by-field
    //    (KeyInfo has no PartialEq).
    let wire_keys = client.list_keys().unwrap();
    let direct_keys = hsm.lock().unwrap().list_keys().unwrap();
    assert_eq!(wire_keys.len(), 2);
    assert_eq!(wire_keys.len(), direct_keys.len());
    for (w, d) in wire_keys.iter().zip(direct_keys.iter()) {
        assert_eq!(w.handle, d.handle);
        assert_eq!(w.key_id, d.key_id);
        assert_eq!(w.key_type, d.key_type);
        assert_eq!(w.has_certificate, d.has_certificate);
    }
    assert!(wire_keys
        .iter()
        .any(|k| k.key_id == KeyRole::JwtSigning.key_id()));

    // 6. Enrolment trio over the wire (bools both directions). arm puts vm9 in
    //    `pending`, not `enrolled`, so is_enrolled is still false and
    //    clear_enrolled finds nothing to remove.
    client.arm_enrollment("vm9", Some(3600)).unwrap();
    assert!(!client.is_enrolled("vm9").unwrap());
    assert!(!client.clear_enrolled("vm9").unwrap());

    drop(client);
    server.join().unwrap();
}

/// [`LinkBProvider`] satisfies `dyn HsmProvider` and delegates each half to the
/// underlying [`LinkBClient`]: provisioning/keystore ops to the client's
/// inherent link-B methods, crypto-dup ops (`sign`/`verify`) to its
/// [`HsmCryptoProvider`], and lifecycle to no-ops. Driven against a REAL
/// `SimHsm` over the same combined [`serve`] loop `hsm-sim-service` runs.
#[test]
fn link_b_provider_satisfies_hsm_provider_and_delegates() {
    let dir = tempfile::tempdir().unwrap();
    let keystore = dir.path().to_path_buf();
    let sock = dir.path().join("hsm-sim-provider.sock");

    let hsm = Arc::new(Mutex::new(SimHsm::new(keystore)));

    let listener = UnixListener::bind(&sock).unwrap();
    let hsm_for_server = Arc::clone(&hsm);
    let server = thread::spawn(move || {
        let (stream, _addr) = listener.accept().unwrap();
        serve(stream, &*hsm_for_server);
    });

    let client = LinkBClient::connect(&sock).unwrap();
    // The provider IS the host-side `dyn HsmProvider` view of the link-B
    // client — coerce to the trait object to PROVE it satisfies the trait.
    let mut provider: Box<dyn HsmProvider> = Box::new(LinkBProvider::new(Arc::new(client)));

    // Unprovisioned: provisioning/keystore delegation reaches the real sim.
    assert!(!provider.is_provisioned().unwrap());
    assert_eq!(
        provider.provisioning_state().unwrap(),
        ProvisioningState::Unprovisioned
    );
    assert!(provider.list_keys().unwrap().is_empty());

    // provision routes to HsmProvider::provision on the backend; a garbage
    // envelope is rejected and the error category survives the wire.
    let err = provider.provision(b"not a suit envelope").unwrap_err();
    assert!(
        matches!(
            err,
            HsmError::EnvelopeInvalid(_) | HsmError::PayloadInvalid(_) | HsmError::DecryptionFailed(_)
        ),
        "garbage envelope must be a provisioning error, got {err:?}"
    );
    assert!(!provider.is_provisioned().unwrap());

    // Establish the provisioned state via the suit-less write_keystore core.
    hsm.lock().unwrap().write_keystore(&provisioned_keystore()).unwrap();

    // Provisioned: state flips through the provider; get_public_key delegates
    // (the wire-reconstructed COSE_Key equals the backend's own).
    assert!(provider.is_provisioned().unwrap());
    assert_eq!(
        provider.provisioning_state().unwrap(),
        ProvisioningState::Provisioned
    );
    let provider_cose = provider.get_public_key(KeyRole::JwtSigning).unwrap();
    let direct_cose = hsm
        .lock()
        .unwrap()
        .get_public_key(KeyRole::JwtSigning)
        .unwrap();
    assert_eq!(provider_cose, direct_cose);
    assert!(!provider_cose.is_empty());

    // list_keys delegates: the two slots are present.
    assert_eq!(provider.list_keys().unwrap().len(), 2);

    // Enrolment trio over the provider (bools both directions). arm puts vm7
    // in `pending`, not `enrolled`, so is_enrolled stays false and
    // clear_enrolled finds nothing to remove.
    provider.arm_enrollment("vm7", Some(1800)).unwrap();
    assert!(!provider.is_enrolled("vm7").unwrap());
    assert!(!provider.clear_enrolled("vm7").unwrap());

    // Drop the provider → its sole Arc<LinkBClient> drops → stream EOF →
    // serve returns.
    drop(provider);
    server.join().unwrap();
}
