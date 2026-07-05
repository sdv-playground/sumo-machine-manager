//! Freeze test — the C mirror `vhsm_proto.h` MUST track this crate byte-exact.
//!
//! The guest `/dev/vhsm` wire (link A) is defined **authoritatively in Rust**
//! (`crates/vhsm-proto/src/lib.rs`) and mirrored in a hand-written C header,
//! `shared/include/vhsm_proto.h`, consumed by the guest C vhsm-daemon. The C
//! header lives in the sibling `guest-vm-spec` repo. Nothing forces the two to
//! agree, so they drift: a v3 Rust daemon vs a v2 C client gets the version
//! byte wrong and every connection is rejected (`ProtocolTooOld`) — or, subtler,
//! a renamed/missing handle constant silently maps the wrong slot and the daemon
//! answers `PERMISSION_DENY`.
//!
//! This test freezes the wire. It pins every wire-visible constant to a literal
//! snapshot AND, when the C header can be located, parses its `#define`s and
//! asserts they equal that same snapshot — so a change on either side that isn't
//! mirrored on the other fails here instead of at runtime on a vehicle.
//!
//! Pattern mirrors `tools/crates/hsm-conformance/tests/conformance.rs`, which
//! locates an in-repo artefact by walking `CARGO_MANIFEST_DIR` ancestors.
//!
//! IF YOU CHANGE A WIRE CONSTANT: update `src/lib.rs`, the `SNAPSHOT` below, and
//! `vhsm_proto.h` together — they are one wire contract in three files.

use std::collections::HashMap;
use std::path::PathBuf;

use vhsm_proto::*;

/// One frozen wire constant.
///
/// * `c` — the C macro name in `vhsm_proto.h`, or `None` when the C side encodes
///   it as a non-literal (e.g. `sizeof(struct …)`) the `#define` scraper can't eval.
/// * `rust` — the live value read from this crate (catches Rust-side drift).
/// * `expect` — the frozen literal (catches drift on *both* sides at once, and is
///   the value the C `#define` must equal).
struct Frozen {
    c: Option<&'static str>,
    rust: u64,
    expect: u64,
}

const fn f(c: &'static str, rust: u64, expect: u64) -> Frozen {
    Frozen {
        c: Some(c),
        rust,
        expect,
    }
}

/// The frozen vHSM v3 guest-wire snapshot. Every entry is `(C macro, Rust value,
/// literal)`. Host-only handles (`0x000A‥0x000C`) and the v3 handshake op range
/// (`0x00F0‥0x00F4`) are deliberately absent: they never cross the guest C wire,
/// so the guest C header does not (and must not) define them.
fn snapshot() -> Vec<Frozen> {
    vec![
        // ---- magic + version ------------------------------------------------
        f("VHSM_MAGIC_0", VHSM_MAGIC[0] as u64, 0x56),
        f("VHSM_MAGIC_1", VHSM_MAGIC[1] as u64, 0x48),
        f("VHSM_MAGIC_2", VHSM_MAGIC[2] as u64, 0x53),
        f("VHSM_VERSION", VHSM_VERSION as u64, 0x03),
        // ---- transport ------------------------------------------------------
        f("VHSM_PORT", VHSM_PORT as u64, 5100),
        // ---- limits ---------------------------------------------------------
        f("VHSM_MAX_PAYLOAD", MAX_PAYLOAD as u64, 65536),
        f("VHSM_MAX_RANDOM", MAX_RANDOM as u64, 1024),
        f("VHSM_MAX_HANDLES", MAX_HANDLES as u64, 64),
        f("VHSM_LABEL_LEN", LABEL_LEN as u64, 32),
        // ---- header sizes (C side is `sizeof`, so no macro to scrape) --------
        Frozen {
            c: None,
            rust: REQUEST_HEADER_SIZE as u64,
            expect: 16,
        },
        Frozen {
            c: None,
            rust: RESPONSE_HEADER_SIZE as u64,
            expect: 20,
        },
        // ---- operation codes ------------------------------------------------
        f("VHSM_OP_GET_RANDOM", Op::GetRandom as u64, 0x0001),
        f("VHSM_OP_KEY_GENERATE", Op::KeyGenerate as u64, 0x0010),
        f("VHSM_OP_KEY_IMPORT", Op::KeyImport as u64, 0x0011),
        f("VHSM_OP_KEY_DERIVE", Op::KeyDerive as u64, 0x0012),
        f("VHSM_OP_KEY_DELETE", Op::KeyDelete as u64, 0x0013),
        f("VHSM_OP_ENCRYPT", Op::Encrypt as u64, 0x0020),
        f("VHSM_OP_DECRYPT", Op::Decrypt as u64, 0x0021),
        f("VHSM_OP_MAC_GENERATE", Op::MacGenerate as u64, 0x0030),
        f("VHSM_OP_MAC_VERIFY", Op::MacVerify as u64, 0x0031),
        f("VHSM_OP_SIGN", Op::Sign as u64, 0x0040),
        f("VHSM_OP_VERIFY", Op::Verify as u64, 0x0041),
        f("VHSM_OP_GET_HANDLE_INFO", Op::GetHandleInfo as u64, 0x0050),
        f("VHSM_OP_GET_PUBKEY", Op::GetPubkey as u64, 0x0051),
        f("VHSM_OP_GET_CERT", Op::GetCert as u64, 0x0052),
        // ---- status codes ---------------------------------------------------
        f("VHSM_STATUS_OK", StatusCode::Ok as u64, 0),
        f(
            "VHSM_STATUS_INVALID_HANDLE",
            StatusCode::InvalidHandle as u64,
            1,
        ),
        f(
            "VHSM_STATUS_PERMISSION_DENY",
            StatusCode::PermissionDeny as u64,
            2,
        ),
        f(
            "VHSM_STATUS_POLICY_REJECT",
            StatusCode::PolicyReject as u64,
            3,
        ),
        f("VHSM_STATUS_HSE_ERROR", StatusCode::HseError as u64, 4),
        f(
            "VHSM_STATUS_INVALID_PARAM",
            StatusCode::InvalidParam as u64,
            5,
        ),
        f("VHSM_STATUS_NO_RESOURCE", StatusCode::NoResource as u64, 6),
        f(
            "VHSM_STATUS_STORAGE_ERROR",
            StatusCode::StorageError as u64,
            7,
        ),
        f(
            "VHSM_STATUS_CRYPTO_ERROR",
            StatusCode::CryptoError as u64,
            8,
        ),
        f("VHSM_STATUS_INTERNAL", StatusCode::Internal as u64, 9),
        // ---- algorithm identifiers ------------------------------------------
        f("VHSM_ALG_AES_128", ALG_AES_128 as u64, 0x0001),
        f("VHSM_ALG_AES_256", ALG_AES_256 as u64, 0x0002),
        f("VHSM_ALG_HMAC_SHA256", ALG_HMAC_SHA256 as u64, 0x0010),
        f("VHSM_ALG_ED25519", ALG_ED25519 as u64, 0x0020),
        f("VHSM_ALG_ECC_P256", ALG_ECC_P256 as u64, 0x0021),
        // ---- permission bitmask --------------------------------------------
        f("VHSM_PERM_ENCRYPT", PERM_ENCRYPT as u64, 1 << 0),
        f("VHSM_PERM_DECRYPT", PERM_DECRYPT as u64, 1 << 1),
        f("VHSM_PERM_MAC_GEN", PERM_MAC_GEN as u64, 1 << 2),
        f("VHSM_PERM_MAC_VFY", PERM_MAC_VFY as u64, 1 << 3),
        f("VHSM_PERM_SIGN", PERM_SIGN as u64, 1 << 4),
        f("VHSM_PERM_VERIFY", PERM_VERIFY as u64, 1 << 5),
        f("VHSM_PERM_DERIVE", PERM_DERIVE as u64, 1 << 6),
        f("VHSM_PERM_DELETE", PERM_DELETE as u64, 1 << 7),
        f("VHSM_PERM_GET_PUBKEY", PERM_GET_PUBKEY as u64, 1 << 8),
        f("VHSM_PERM_GET_CERT", PERM_GET_CERT as u64, 1 << 9),
        f("VHSM_PERM_KEY_GENERATE", PERM_KEY_GENERATE as u64, 1 << 10),
        // ---- well-known handles (guest-visible sumo-core band + boundaries) --
        f("VHSM_HANDLE_INVALID", HANDLE_INVALID as u64, 0x0000),
        f(
            "VHSM_HANDLE_SW_AUTHORITY",
            HANDLE_SW_AUTHORITY as u64,
            0x0002,
        ),
        f(
            "VHSM_HANDLE_DEVICE_DECRYPT",
            HANDLE_DEVICE_DECRYPT as u64,
            0x0003,
        ),
        f("VHSM_HANDLE_IAM_SIGNING", HANDLE_IAM_SIGNING as u64, 0x0004),
        f(
            "VHSM_HANDLE_KEY_AUTHORITY",
            HANDLE_KEY_AUTHORITY as u64,
            0x0005,
        ),
        f("VHSM_HANDLE_JWT_SIGNING", HANDLE_JWT_SIGNING as u64, 0x0006),
        f("VHSM_HANDLE_STORAGE", HANDLE_STORAGE as u64, 0x0007),
        f(
            "VHSM_HANDLE_OPERATIONAL_ISSUER",
            HANDLE_OPERATIONAL_ISSUER as u64,
            0x0008,
        ),
        f(
            "VHSM_HANDLE_FACTORY_RESET_ISSUER",
            HANDLE_FACTORY_RESET_ISSUER as u64,
            0x0009,
        ),
        f(
            "VHSM_HANDLE_PROJECT_BASE",
            HANDLE_PROJECT_BASE as u64,
            0x0080,
        ),
        f(
            "VHSM_HANDLE_DYNAMIC_BASE",
            HANDLE_DYNAMIC_BASE as u64,
            0x0100,
        ),
    ]
}

/// Candidate paths to `vhsm_proto.h`, relative to some ancestor of this crate.
/// Covers a possible future in-tree vendored copy first, then the sibling
/// `guest-vm-spec` checkout layouts (it ships as a submodule of the guest
/// superprojects beside `sumo-workspace`).
const HEADER_CANDIDATES: &[&str] = &[
    "crates/vhsm-proto/include/vhsm_proto.h",
    "shared/include/vhsm_proto.h",
    "guest-vm-spec/shared/include/vhsm_proto.h",
    "guest-vm-sdk/guest-vm-spec/shared/include/vhsm_proto.h",
    "guest-vm-kernel/guest-vm-spec/shared/include/vhsm_proto.h",
    "guest-vm-qnx/guest-vm-spec/shared/include/vhsm_proto.h",
];

/// Walk `CARGO_MANIFEST_DIR` ancestors and return the first existing candidate.
fn locate_header() -> Option<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for ancestor in manifest.ancestors() {
        for rel in HEADER_CANDIDATES {
            let p = ancestor.join(rel);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

/// Evaluate a C integer constant: decimal, `0x` hex, or a `(1u << N)` shift,
/// tolerating `u`/`l` suffixes and surrounding parens. Returns `None` for things
/// the scraper isn't meant to handle (`sizeof(...)`, brace lists, …).
fn eval_c_int(expr: &str) -> Option<u64> {
    let s = expr.trim();
    let s = s
        .strip_prefix('(')
        .and_then(|x| x.strip_suffix(')'))
        .unwrap_or(s)
        .trim();
    if let Some((lhs, rhs)) = s.split_once("<<") {
        return Some(parse_scalar(lhs)? << parse_scalar(rhs)?);
    }
    parse_scalar(s)
}

fn parse_scalar(tok: &str) -> Option<u64> {
    let t = tok.trim().trim_end_matches(['u', 'U', 'l', 'L']).trim();
    match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => t.parse::<u64>().ok(),
    }
}

/// Scrape every evaluable object-like `#define NAME VALUE` into a map.
fn parse_defines(src: &str) -> HashMap<String, u64> {
    let mut out = HashMap::new();
    for line in src.lines() {
        let Some(rest) = line.trim_start().strip_prefix("#define") else {
            continue;
        };
        let rest = rest.trim_start();
        let mut parts = rest.splitn(2, char::is_whitespace);
        let name = parts.next().unwrap_or_default().trim();
        let Some(mut value) = parts.next() else {
            continue;
        };
        // Drop a trailing `/* … */` or `// …` comment.
        if let Some(i) = value.find("/*") {
            value = &value[..i];
        }
        if let Some(i) = value.find("//") {
            value = &value[..i];
        }
        let value = value.trim();
        if name.is_empty() || value.is_empty() {
            continue;
        }
        if let Some(v) = eval_c_int(value) {
            out.insert(name.to_string(), v);
        }
    }
    out
}

/// The Rust side alone must never drift from the frozen snapshot — runs with no
/// filesystem dependency, so it is meaningful even where the C header is absent.
#[test]
fn rust_wire_constants_are_frozen() {
    for fr in snapshot() {
        let label = fr.c.unwrap_or("(rust-only)");
        assert_eq!(
            fr.rust, fr.expect,
            "Rust wire constant for {label} drifted: live {:#x} != frozen {:#x} \
             — update vhsm_proto.h + the SNAPSHOT in lockstep",
            fr.rust, fr.expect,
        );
    }
}

/// The C mirror `vhsm_proto.h` must equal the frozen snapshot define-for-define.
/// When the header can't be located (e.g. CI without the sibling `guest-vm-spec`
/// checkout) this falls back to the Rust-only freeze with a loud lockstep note,
/// exactly as the snapshot fallback is intended to behave.
#[test]
fn c_header_mirrors_rust() {
    let snap = snapshot();

    let Some(path) = locate_header() else {
        eprintln!(
            "NOTE: vhsm_proto.h not found under any ancestor of {} (looked for {:?}). \
             The C mirror lives in guest-vm-spec (shared/include/vhsm_proto.h) and MUST \
             be kept in lockstep with crates/vhsm-proto/src/lib.rs. Falling back to the \
             frozen snapshot (Rust side only).",
            env!("CARGO_MANIFEST_DIR"),
            HEADER_CANDIDATES,
        );
        for fr in &snap {
            assert_eq!(
                fr.rust, fr.expect,
                "Rust wire constant drifted from snapshot"
            );
        }
        return;
    };

    eprintln!("vhsm_proto.h located at {}", path.display());
    let src =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let defs = parse_defines(&src);

    // The header must define VHSM_VERSION at all, and it must be v3 — the headline
    // drift this test exists to catch.
    assert_eq!(
        defs.get("VHSM_VERSION").copied(),
        Some(0x03),
        "vhsm_proto.h VHSM_VERSION must be 0x03 (v3) in {}",
        path.display(),
    );

    for fr in &snap {
        let Some(name) = fr.c else { continue };
        let got = defs.get(name).unwrap_or_else(|| {
            panic!(
                "vhsm_proto.h ({}) is missing #define {name} — C mirror lags the Rust wire",
                path.display(),
            )
        });
        assert_eq!(
            *got,
            fr.expect,
            "WIRE DRIFT: {name} = {got:#x} in {} but the frozen Rust wire is {:#x}",
            path.display(),
            fr.expect,
        );
        // And the Rust constant equals the frozen value too (belt and braces).
        assert_eq!(fr.rust, fr.expect, "Rust {name} drifted from the snapshot");
    }
}
