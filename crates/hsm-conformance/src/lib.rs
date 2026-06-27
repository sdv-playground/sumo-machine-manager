//! Link-B HSM backend **conformance battery**.
//!
//! An HSM developer who has implemented the host↔backend op contract (link-B —
//! see `crates/hsm-link-b` for the frozen wire and `crates/hsm/src/link_b.rs`
//! for the Rust glue) runs this harness against their backend to check it
//! actually honours the contract. [`run_conformance`] drives a backend through a
//! fixed sequence of [`HsmCryptoProvider`] ops and returns a [`ConformanceReport`].
//!
//! The harness drives the backend through `&dyn HsmCryptoProvider`, so it is
//! transport-agnostic. The `hsm-conformance` bin connects a
//! [`LinkBClient`](hsm::link_b::LinkBClient) to a backend already listening on a
//! link-B socket — how that backend was launched (vendor bridge, hardware
//! service, …) is not this tool's business. The conformance *tests* use
//! [`spawn_and_connect`] to bring up a local reference backend (`hsm-sim-service`
//! or the C skeleton) first; that helper is a test/dev convenience, not the bin's
//! path.
//!
//! ## What makes a backend "conform"
//!
//! The load-bearing check is **C2**: the battery takes the signature the backend
//! produces and re-verifies it **independently** with its own RustCrypto (`p256`)
//! stack, against the public key the backend exports. A backend that *stubs* its
//! crypto — returns plausibly-framed but fake signature bytes — sails through the
//! framing/dispatch checks but **cannot** pass C2, because fake bytes are not a
//! real ECDSA-P256 signature over the message. That is the difference between
//! "speaks the wire" and "is a real HSM".
//!
//! ## On C7 (and a deviation worth stating up front)
//!
//! C7 asserts that a **private-key operation against a public-only trust anchor
//! is rejected**. It probes this with `sign(SW_AUTHORITY, …)`, NOT
//! `generate_key(SW_AUTHORITY, …)`. The reason: the reference software backend
//! (`SimHsm`) is filename-addressed and has *no notion* of public-only anchors —
//! `generate_key` on any well-known handle simply writes a fresh private key and
//! succeeds. A real HSE and the C reference skeleton both correctly refuse a
//! private-key op on a public-only anchor. Probing with a *sign* (a genuine
//! private-key use) tests the contract property that holds for every conforming
//! backend — the conforming sim (which has no private key in that anchor slot)
//! and a hardware backend (which marks it virtual) both reject it — whereas
//! probing with `generate_key` would spuriously fail the conforming sim.

mod spawn;
pub use spawn::spawn_and_connect;

use std::fmt;

use hsm::{HsmCryptoProvider, KeyHandle, KeyType};

/// The result of a single conformance check.
#[derive(Debug)]
pub enum Outcome {
    /// The check held.
    Pass,
    /// The check did not hold; the string explains why (for the report).
    Fail(String),
}

/// One conformance check and how it turned out.
#[derive(Debug)]
pub struct Check {
    /// Stable check name, prefixed with its id (`"C1 …"` … `"C9 …"`).
    pub name: &'static str,
    /// Pass, or Fail with a reason.
    pub outcome: Outcome,
    /// Informational checks (C9) are reported but do NOT affect the
    /// [`ConformanceReport::all_passed`] verdict — a backend MAY decline them.
    pub informational: bool,
}

impl Check {
    fn pass(name: &'static str) -> Self {
        Check {
            name,
            outcome: Outcome::Pass,
            informational: false,
        }
    }

    fn fail(name: &'static str, why: String) -> Self {
        Check {
            name,
            outcome: Outcome::Fail(why),
            informational: false,
        }
    }

    /// Map a `Result<(), String>` to a Pass/Fail check (the common shape — an
    /// `Err` carries the failure reason). Errors are *caught*, never panicked.
    fn from_result(name: &'static str, r: Result<(), String>) -> Self {
        match r {
            Ok(()) => Self::pass(name),
            Err(why) => Self::fail(name, why),
        }
    }

    /// As [`Check::from_result`] but flagged informational (C9).
    fn info_from_result(name: &'static str, r: Result<(), String>) -> Self {
        let mut c = Self::from_result(name, r);
        c.informational = true;
        c
    }

    fn passed(&self) -> bool {
        matches!(self.outcome, Outcome::Pass)
    }
}

/// The full result of a conformance run.
pub struct ConformanceReport {
    /// Every check, in id order (C1 … C9).
    pub checks: Vec<Check>,
    /// Number of checks that passed (informational included, for transparency).
    pub passed: usize,
    /// Number of checks that failed (informational included).
    pub failed: usize,
}

impl ConformanceReport {
    fn new(checks: Vec<Check>) -> Self {
        let passed = checks.iter().filter(|c| c.passed()).count();
        let failed = checks.len() - passed;
        Self {
            checks,
            passed,
            failed,
        }
    }

    /// The verdict: did the backend conform? True iff every **non-informational**
    /// check passed. C9 (random) is informational — a backend MAY decline it
    /// without forfeiting conformance.
    pub fn all_passed(&self) -> bool {
        self.checks
            .iter()
            .all(|c| c.informational || c.passed())
    }

    /// Look up a check's outcome by its id prefix (e.g. `"C2"`). Handy in tests
    /// and callers that want a specific verdict rather than the whole table.
    pub fn outcome(&self, id_prefix: &str) -> Option<&Outcome> {
        self.checks
            .iter()
            .find(|c| c.name.starts_with(id_prefix))
            .map(|c| &c.outcome)
    }
}

impl fmt::Display for ConformanceReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "link-B HSM conformance report")?;
        writeln!(f, "─────────────────────────────")?;
        for c in &self.checks {
            let tag = match (&c.outcome, c.informational) {
                (Outcome::Pass, false) => "PASS",
                (Outcome::Pass, true) => "INFO",
                (Outcome::Fail(_), false) => "FAIL",
                (Outcome::Fail(_), true) => "INFO",
            };
            write!(f, "  [{tag}] {}", c.name)?;
            if let Outcome::Fail(why) = &c.outcome {
                write!(f, " — {why}")?;
            }
            writeln!(f)?;
        }
        writeln!(
            f,
            "─────────────────────────────\n{} passed, {} failed (C9 is informational and excluded from the verdict)",
            self.passed, self.failed
        )?;
        writeln!(
            f,
            "RESULT: {}",
            if self.all_passed() {
                "CONFORMS"
            } else {
                "DOES NOT CONFORM"
            }
        )
    }
}

/// Run the link-B conformance battery against `c`.
///
/// The checks run in order on one provider/keystore and share state: C1 creates
/// the JWT-signing key that C2–C6 exercise; C7/C8 probe a public-only anchor and
/// an unknown handle; C9 is informational.
///
/// Every check catches its own errors into [`Outcome::Fail`] — this never panics
/// on a misbehaving backend.
pub fn run_conformance(c: &dyn HsmCryptoProvider) -> ConformanceReport {
    // A fixed, non-empty message to sign + verify throughout.
    const MSG: &[u8] = b"hsm-conformance link-B KAT message";

    let jwt = KeyHandle(vhsm_proto::HANDLE_JWT_SIGNING);
    let anchor = KeyHandle(vhsm_proto::HANDLE_SW_AUTHORITY);
    let unknown = KeyHandle(0xFFFF);

    let mut checks: Vec<Check> = Vec::with_capacity(9);

    // ── C1: keygen returns a non-empty key blob (framing / dispatch). ─────────
    // We check ONLY non-emptiness here; the structural validity of that blob (it
    // is a real P-256 SubjectPublicKeyInfo whose point is on the curve) is proven
    // in C2/C3, where the independent verify parses it. That split is deliberate:
    // a framing-correct stub answers keygen with bytes and passes C1, then fails
    // the real-crypto C2 — exactly the "prove the example is only an example" line.
    let spki1: Option<Vec<u8>> = match c.generate_key(jwt, vhsm_proto::ALG_ECC_P256) {
        Ok(der) if !der.is_empty() => {
            checks.push(Check::pass(
                "C1 keygen — generate_key(JWT_SIGNING, ECC-P256) returns a non-empty key",
            ));
            Some(der)
        }
        Ok(_) => {
            checks.push(Check::fail(
                "C1 keygen — generate_key(JWT_SIGNING, ECC-P256) returns a non-empty key",
                "generate_key returned an empty byte string".into(),
            ));
            None
        }
        Err(e) => {
            checks.push(Check::fail(
                "C1 keygen — generate_key(JWT_SIGNING, ECC-P256) returns a non-empty key",
                format!("generate_key failed: {e}"),
            ));
            None
        }
    };

    // Produce one signature over MSG, reused by C2 (independent verify) and by
    // C4/C5 (the backend's own verify). `None` ⇒ sign itself failed.
    let sig: Option<Vec<u8>> = c.sign(jwt, MSG).ok();

    // ── C2: real-crypto KAT — the load-bearing check. ─────────────────────────
    // Re-verify the backend's signature INDEPENDENTLY with p256, against the
    // public key the backend exports. Fake/stubbed crypto cannot pass this.
    let c2 = (|| -> Result<(), String> {
        let sig = sig
            .as_ref()
            .ok_or("sign(JWT_SIGNING, MSG) failed — no signature to verify")?;
        let pubkey = c
            .get_public_key_der(jwt)
            .map_err(|e| format!("get_public_key_der failed: {e}"))?;
        independent_verify(&pubkey, MSG, sig)
    })();
    checks.push(Check::from_result(
        "C2 real-crypto KAT — independent p256 verify of sign() against the exported pubkey",
        c2,
    ));

    // ── C3: exported pubkey is stable (== the key C1 returned). ───────────────
    let c3 = (|| -> Result<(), String> {
        let spki1 = spki1
            .as_ref()
            .ok_or("C1 keygen did not return a public key to compare against")?;
        let again = c
            .get_public_key_der(jwt)
            .map_err(|e| format!("get_public_key_der failed: {e}"))?;
        if &again == spki1 {
            Ok(())
        } else {
            Err("get_public_key_der did not match the key bytes generate_key returned".into())
        }
    })();
    checks.push(Check::from_result(
        "C3 pubkey stable — get_public_key_der equals the C1 keygen output",
        c3,
    ));

    // ── C4: the backend's own verify accepts a genuine signature. ─────────────
    let c4 = (|| -> Result<(), String> {
        let sig = sig
            .as_ref()
            .ok_or("no signature available (sign failed in C2)")?;
        match c.verify(jwt, MSG, sig) {
            Ok(true) => Ok(()),
            Ok(false) => {
                Err("verify() returned false for a signature the backend itself produced".into())
            }
            Err(e) => Err(format!("verify() errored: {e}")),
        }
    })();
    checks.push(Check::from_result(
        "C4 link-B verify (true) — verify() accepts the backend's own signature",
        c4,
    ));

    // ── C5: the backend's own verify rejects a signature over a different msg. ─
    let c5 = (|| -> Result<(), String> {
        let sig = sig
            .as_ref()
            .ok_or("no signature available (sign failed in C2)")?;
        match c.verify(jwt, b"tampered", sig) {
            Ok(false) => Ok(()),
            Ok(true) => Err(
                "verify() ACCEPTED a signature over a different message (a verify that always \
                 accepts is not really verifying)"
                    .into(),
            ),
            Err(e) => Err(format!("verify() errored: {e}")),
        }
    })();
    checks.push(Check::from_result(
        "C5 link-B verify (false) — verify() rejects a tampered message",
        c5,
    ));

    // ── C6: key metadata reports EC-P256. ─────────────────────────────────────
    let c6 = match c.get_key_info(jwt) {
        Ok(info) if info.key_type == KeyType::EcP256 => Ok(()),
        Ok(info) => Err(format!(
            "get_key_info reported key_type {}, expected EC-P256",
            info.key_type
        )),
        Err(e) => Err(format!("get_key_info failed: {e}")),
    };
    checks.push(Check::from_result(
        "C6 key info — get_key_info(JWT_SIGNING) reports EC-P256",
        c6,
    ));

    // ── C7: a private-key op on a public-only trust anchor is rejected. ───────
    // See the module docs: probed with `sign` (a real private-key use), not
    // `generate_key`, so the conforming sim and a hardware backend both pass.
    let c7 = match c.sign(anchor, MSG) {
        Err(_) => Ok(()),
        Ok(_) => Err(
            "sign() on the public-only SW_AUTHORITY anchor unexpectedly succeeded \
             (a public-only trust anchor holds no private key)"
                .into(),
        ),
    };
    checks.push(Check::from_result(
        "C7 virtual anchor — a private-key op on public-only SW_AUTHORITY is rejected",
        c7,
    ));

    // ── C8: an unknown handle is rejected. ────────────────────────────────────
    let c8 = match c.sign(unknown, MSG) {
        Err(_) => Ok(()),
        Ok(_) => Err("sign() on unknown handle 0xFFFF unexpectedly succeeded".into()),
    };
    checks.push(Check::from_result(
        "C8 unknown handle — sign() on an unregistered handle (0xFFFF) is rejected",
        c8,
    ));

    // ── C9: random (informational — a backend MAY decline). ───────────────────
    let c9 = match c.random(32) {
        Ok(b) if b.len() == 32 => Ok(()),
        Ok(b) => Err(format!("random(32) returned {} bytes, expected 32", b.len())),
        Err(e) => Err(format!("random(32) declined/failed: {e}")),
    };
    checks.push(Check::info_from_result(
        "C9 random — random(32) returns 32 bytes [informational]",
        c9,
    ));

    ConformanceReport::new(checks)
}

/// Independently verify an ECDSA-P256 signature with `p256`, against a public key
/// the backend exported as SubjectPublicKeyInfo DER. This is what makes C2 a real
/// KAT rather than self-attestation: the proof never touches the backend.
///
/// The SPKI's trailing 65 bytes are the SEC1 uncompressed point (`0x04 || X || Y`)
/// — the same slice `hsm`'s own crypto code uses. The signature is tried as ASN.1
/// **DER** first (what `SimHsm::sign` and the link-B `OP_SIGN` contract return),
/// then as a raw fixed 64-byte `r || s` (the COSE/JWS form) so a backend that
/// returns the raw form is not failed on encoding alone.
fn independent_verify(spki_der: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), String> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::VerifyingKey;

    if spki_der.len() < 65 {
        return Err(format!(
            "exported public key is {} bytes — too short to hold a SEC1 P-256 point \
             (backend returned non-crypto bytes?)",
            spki_der.len()
        ));
    }
    let point = &spki_der[spki_der.len() - 65..];
    let vk = VerifyingKey::from_sec1_bytes(point).map_err(|e| {
        format!("exported public key is not a valid P-256 point (stubbed crypto?): {e}")
    })?;

    // Primary: ASN.1 DER signature (the link-B `sign` contract / SimHsm form).
    if let Ok(der_sig) = ecdsa::der::Signature::<p256::NistP256>::from_bytes(sig) {
        return vk
            .verify(msg, &der_sig)
            .map_err(|e| format!("DER signature did not verify under the exported pubkey: {e}"));
    }

    // Fallback: raw fixed 64-byte r||s.
    let raw = p256::ecdsa::Signature::from_slice(sig).map_err(|e| {
        format!("signature is neither valid ASN.1 DER nor a 64-byte r||s pair: {e}")
    })?;
    vk.verify(msg, &raw)
        .map_err(|e| format!("raw 64-byte signature did not verify under the exported pubkey: {e}"))
}
