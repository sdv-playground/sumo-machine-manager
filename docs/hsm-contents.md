# HSM contents — what the device expects

**Audience:** security reviewers and hardware-HSM implementers.

This is the contract the in-vehicle (host) machine manager and its vHSM
daemon (`vhsm-ssd`) assume the device HSM holds once provisioned. A hardware HSM
(e.g. NXP HSE) replacing the dev `SimHsm` must present exactly these slots, with
the same private-half guarantees and the same vHSM wire handles.

**Status:** updated 2026-06-19. Authoritative sources:
`hsm::KeyRole` (`crates/hsm/src/types.rs`), the keystore
schema (`crates/hsm/src/payload.rs`, CBOR schema **v4**), and the vHSM handle map
(`crates/vhsm-proto/src/lib.rs`).

---

## How it gets there

The HSM is provisioned by **Tower 1** with a **signed SUIT keystore envelope**
(CBOR `HsmKeystore`, schema v4). The very first install is verified against the
**well-known factory bootstrap key** (P-256 `scalar = 1`, public by design);
after that the Key Authority anchor takes over. Re-provisioning must raise the
keystore's `security_version` — a monotonic **anti-rollback floor**.

The envelope carries, per slot, only what the device must *not* generate itself:
the **public half** of each external trust anchor. Every **device-identity
private key is generated inside the HSM at provisioning time and never crosses
the envelope boundary** in either direction — there is no API to export it.

## The two axes

Each slot is classified by two independent properties:

1. **Private-half location**
   - **In-HSM** — the HSM generates the keypair locally; the private half never
     leaves. The keystore ships no key material for it (only, later, a signed
     leaf cert for its public half).
   - **External anchor** — the HSM stores only the public half; the private half
     lives off-device with the signing infrastructure (a Tower / OEM CA). Used
     purely to *verify*.
2. **vHSM addressability** — a *second* handle layer, not the HSM's own.
   **Every slot is a real key object in the HSM, addressed internally by its
   `key_id`** (a hardware HSM binds each to its own key slot / handle at
   provisioning). On top of that, `vhsm-ssd` re-exports a *subset* to guests:
   - **Guest handle** — a fixed vHSM wire-handle number (`0x0002`–`0x0009`) the
     daemon maps to the slot's `key_id`, so a guest VM can address it over
     `/dev/vhsm`.
   - **Host-only (`—`)** — no guest wire handle; the host (the host machine manager / `vhsm-ssd`)
     reaches it by `key_id` directly. `freshness-signing` / `tls-identity` are
     host-only *by design* — a guest must never be able to sign with them.

---

## The slot catalog (11 mandatory slots)

All slots are mandatory (`KeyRole::mandatory_roles()`) — an HSM missing any is
"not fully provisioned." **Every slot is a real key object in the HSM** (the
*Exists in HSM* column is ✓ for all). **Slot #** is the *guest* vHSM wire handle;
`—` means the slot has no guest handle (host-only, reached by `key_id`). Sorted by
handle.

| Slot # | Name (`key_id`) | Exists in HSM | Type in HSM | At interface | Guest vHSM | Usage (host) |
|---|---|---|---|---|---|---|
| `0x0002` | `sw-authority` | ✓ | EC-P256 public (anchor) | ES256 verify | ✓ | Verify firmware / software SUIT envelopes (Software Authority / Tower 2 root). |
| `0x0003` | `device-decrypt` | ✓ | EC-P256 keypair | ECDH-ES decrypt | ✓ | Unwrap the per-device content key that decrypts firmware payloads. |
| `0x0004` | `iam-signing` | ✓ | EC-P256 keypair | ES256 sign | ✗ † | Daemon-internal IAM / CWT + cert issuer (cross-node principal auth). |
| `0x0005` | `key-authority` | ✓ | EC-P256 public (anchor) | ES256 verify | ✓ | Verify key-material SUIT envelopes (Key Authority root). |
| `0x0006` | `jwt-signing` | ✓ | EC-P256 keypair | ES256 sign | ✓ | The in-vehicle operational token minter (the device's own issuer). |
| `0x0007` | `storage-key` | ✓ | AES-256 (symmetric) | AES-256-GCM enc/dec | ✓ | At-rest encryption of host secstore / key-metadata. |
| `0x0008` | `operational-issuer` | ✓ | EC-P256 public (anchor) | ES256 verify | ✓ | Verify Operational-tier operator tokens (workshop / OEM) — incl. ECU reboot (`reset:execute`). |
| `0x0009` | `factory-reset-issuer` | ✓ | EC-P256 public (anchor) | ES256 verify | ✓ | Verify **factory-reset** tokens — the lone HighConsequence capability. Clear this slot in production → factory-reset is permanently revoked. |
| — | `ivd-signing` | ✓ | EC-P256 keypair | ES256 sign | ✗ | Sign the IVD (installed-version descriptor) manifest. |
| — | `freshness-signing` | ✓ | EC-P256 keypair | ES256 sign | ✗ | Sign the §7.2 vehicle freshness assertion (safe-time-floor + epoch). |
| — | `tls-identity` | ✓ | EC-P256 keypair | mTLS client auth (ES256) | ✗ | The node's mTLS client identity (leaf chains to the fleet identity root). |

† `iam-signing` has handle `0x0004` reserved but is **not** registered on the
guest wire — CWT minting goes through a host-privileged adapter.

**Reading the columns.** *Type in HSM* is the **hardware contract**: a **keypair**
is generated inside the HSM and its private half never leaves; a **public
(anchor)** is stored verify-only (no private half on the device at all); **AES-256**
is a symmetric key generated and held inside. *At interface* is the operation a
caller invokes. *Guest vHSM* ✓ means a guest VM may address the slot over
`/dev/vhsm`; ✗ means host-only (the host machine manager / `vhsm-ssd` in-process).

**Split:** 7 device-generated keys whose private / symmetric half lives **in the
HSM** (`device-decrypt`, `iam-signing`, `jwt-signing`, `ivd-signing`,
`freshness-signing`, `tls-identity`, `storage-key`) and 4 public verify-anchors
(`key-authority`, `sw-authority`, `operational-issuer`, `factory-reset-issuer`).

---

## Trust anchors (pinned CA roots — *not* key slots)

Carried in the keystore's `trust_anchors` list (schema v4, CBOR key 5). These are
**DER X.509 CA root certificates** the device pins. Distinct from the slots
above: a slot certifies one of the device's *own* keys; a trust anchor certifies
*no* slot — it's the root a *foreign* chain must validate to.

| `anchor_id` | Form | Purpose |
|---|---|---|
| `delegation-root` | DER X.509 CA root | The CA whose `x5c` chain a **delegated operator token** (a workshop reset-grant) must validate to. Pinning it enables the delegated reset path; absent, only the pinned issuers above are trusted. |

---

## Trust roots, summarised (for the security discussion)

The device relates to several **deliberately separate** trust domains — the core
of the security model. None is a master of another; compromising one does not
grant another's authority.

| Trust root | Anchored by | Signs / authorises |
|---|---|---|
| **Key Authority** | `key-authority` slot (public) | key-material SUIT envelopes |
| **Software Authority** (Tower 2) | `sw-authority` slot (public) | firmware / software SUIT envelopes |
| **Identity root** (fleet) | `tls-identity` leaf chains to it | the node's mTLS identity |
| **Delegation root** | `delegation-root` trust anchor | delegated operator (workshop) reset grants |
| **Operational issuer** | `operational-issuer` slot (public) | routine operator tokens (OTA, reads) |
| **Factory-reset issuer** | `factory-reset-issuer` slot (public) | factory-reset operator tokens (the lone high-consequence capability) |

---

## For hardware-HSM implementers

A hardware HSM replacing `SimHsm` must:

- Provide all **11 slots** above (10 EC-P256 + the AES-256 `storage-key`) as key
  objects under their `key_id`s, each bound to its own HSM key handle / catalog
  slot. The listed vHSM handles are a *separate*, host-managed wire mapping
  (`vhsm-ssd`'s handle table) that re-exports only the guest-addressable subset —
  not the HSM's own handles.
- Generate the **7 device-generated keys** internally at provisioning (6 EC-P256
  keypairs + the AES-256 `storage-key`) and expose **no export path** for their
  private / symmetric halves. `sign` / `decrypt` / `encrypt` operate on the
  handle; the key bytes never leave the boundary.
- Store the **4 external-anchor public keys** as verify-only objects (no private
  half present).
- Support the public **CSR flow** for device-generated identity keys (e.g.
  `tls-identity`), so a CA can later return a signed leaf — stored as the slot's
  cert object and reported via `GET_CERT`.
- Honour the per-slot operation policy (`allowed_ops`): an anchor may
  VERIFY / GET_PUBKEY but never SIGN; `device-decrypt` may DECRYPT but never
  ENCRYPT; `storage-key` may ENCRYPT / DECRYPT but has no public-key op; etc.
- Enforce the keystore `security_version` anti-rollback floor on
  (re-)provisioning.

### Reserved handle ranges

(`iam-signing` 0x0004 and `storage-key` 0x0007 are now full catalog rows above.)

| Handle | Note |
|---|---|
| `0x0001` | Reserved; unused. |
| `0x0080+` | Project-extension well-known range (owned by downstream guest specs). |
| `0x0100+` | Dynamic — runtime-allocated handles, not provisioned. |

### Naming note

The slot is `factory-reset-issuer` — the `KeyRole` variant (`FactoryResetIssuer`),
the wire `key_id` / token `kid` (`factory-reset-issuer`), and the vHSM wire-handle
const (`HANDLE_FACTORY_RESET_ISSUER` 0x0009, mirrored across `vhsm-proto` ↔
`vhsm_proto.h` ↔ `vhsm-handles-ext`). The handle **number `0x0009` is unchanged** —
it is the wire contract. It was renamed across the chain
`high-consequence-issuer` → `reset-issuer` → `factory-reset-issuer` as the model
narrowed it to **factory-reset only** (ECU reboot is now Operational, gated by
minter policy rather than this slot). The only remaining tier-era name is the
`Tier::HighConsequence` authz ceiling, pending the tier→capability-set refactor
(see the workspace `docs/design/authorization.md`).
