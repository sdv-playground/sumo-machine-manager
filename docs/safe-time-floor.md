# Safe-time floor

How a clockless ECU validates token/cert freshness without a trusted clock — and
why the mechanism that makes it rollback-proof lives in the HSM as a **generic
monotonic counter**, while everything that knows the word "time" lives above it.

## Problem

The device boots with no trusted wall clock — no RTC, no GPS, and NTP is itself
unauthenticated. At power-on the clock is effectively the Unix epoch. But
authorization decisions need *some* answer to "what time is it, at least?": a
JWT's `exp`/`nbf`, a certificate's validity window, a signed manifest's freshness.

A plain persisted timestamp doesn't survive the threat model — an attacker with
filesystem or SOVD access could roll it back and replay long-expired credentials.

## The mechanism, split in two

**The HSM provides a rollback-proof monotonic counter — and nothing else.** It is
a generic `u64` that only ever ratchets upward. It has no idea it represents time.

- `read_monotonic() -> u64` — the current value (0 if never raised).
- `raise_monotonic(v) -> u64` — ratchet to `max(current, v)`; a value at or below
  the stored one is a no-op. Returns the resulting value.
- link-B ops `OP_READ_MONOTONIC` (0x28) / `OP_RAISE_MONOTONIC` (0x29).
- Stored in the HSM's secure NV — the same tamper/rollback domain as the keystore
  `security_version` anti-rollback counter. (The dev/sim backend mirrors it in a
  file; a hardware backend keeps it in HSM NV.)

The safety core is this and only this: **a caller can only *stall* the counter,
never *rewind* it.** Even a buggy or hostile caller cannot move it backward.

**The caller owns "time".** The host machine-manager reads the counter and
*interprets* it as the safe-time floor (Unix seconds); freshness checks evaluate
against `max(wall_clock_now, floor)`. The interpretation is a thin accessor:

```rust
fn read_safe_time_floor(p: &dyn HsmProvider) -> u64 { p.read_monotonic().unwrap_or(0) }
```

Nothing below that line — not the trait, not the link-B protocol, not the NV
format — contains the word "time".

## Provenance: where the trust boundary sits

The caller ratchets the floor **only from signature-verified material** — a
verified certificate's `not_before`, a signed SUIT manifest's timestamp, a
Roughtime response checked against a root the caller holds. Never from raw input.

The predicate is **"signature verified to a trusted root"**, which is *weaker* and
*earlier* than "the artifact was accepted". A SUIT manifest whose signature verifies
but which the device then **discards** for anti-rollback (`security_version` below the
floor) or device-identity mismatch still carried a truthful, trusted lower bound on
real time: `component-mgr` ratchets the floor from its `signing_time` before the
rejection propagates (`ManifestError::RollbackRejected` carries the signed
`signing_time_secs`). Monotonicity makes this safe — a stale rejected manifest's
timestamp can only be a no-op, never a rewind — and it lets an offline device advance
its floor whenever it merely *sees* trusted signed time, not only on a full install.

## Self-bootstrapping: the delegate cert's own `not_before`

The workshop minter is a **delegate**, not a pinned issuer — its key isn't in the
keystore; it presents an `x5c` chain to the pinned delegation root. This is deliberate:
delegates rotate without re-provisioning every device (a fleet-scale requirement). But
a delegate leaf's `not_before` is a real-world date, and a no-RTC device boots behind
real time — so a naive "valid at now" window check rejects a fresh delegate as *not yet
valid*, deadlocking the very first flash at `open_update` (HTTP 401). Nothing has
advanced the floor yet, because the flash IS the thing that would.

The delegated path (`sovd/delegation.rs` `verify_delegate_chain` +
`sovd/authz.rs` `authorize_delegated`) breaks that **without** trusting the delegate to
assert its own validity blindly, and **without** an operator pre-step:

1. Verify the chain **signature + path + clientAuth EKU** *window-agnostically* — call
   the webpki verifier at `now = the leaf's own not_before`, so the window is trivially
   satisfied and the call reduces to "does this chain to the pinned root?". A forged /
   mis-rooted / wrong-EKU cert still fails here (those checks don't depend on the instant).
2. Only after the signature verifies is `not_before` trusted — the pinned root signed it,
   so it's a trusted lower bound on real time. Ratchet the floor to it (the in-memory
   cell immediately, and the injected `FloorSink` disciplines the wall clock forward so
   the token's own JWT `exp`/`nbf` checks — which read the raw clock — also see it).
3. **Expiry is still enforced**: reject iff `not_after < effective_now = max(wall, floor)`.

Net rule: **accept a delegate iff its signature is valid AND we cannot PROVE it expired**
against the rollback-proof floor. The `not_before` gate is intentionally dropped for
delegates — advancing the floor can only *tighten* the expiry check, never loosen it, so
this can't resurrect a cert the device already knows is stale (`not_after < old_floor`
still rejects). This is the clockless-device model: reject what you can prove stale;
accept what you can't disprove. It is **not** circular — the accept decision rests on the
signature (independent of the floor); the floor advance is a *consequence* of an
already-trusted signature, and being monotonic + forward-only it can never create trust
it didn't already have.

Residual risk (bounded, same class as any signed-time source): a **stolen, expired**
delegate presented to a device whose floor is stuck far in the past (fresh / epoch-boot).
Mitigated by the provisioning-time floor seed (a just-provisioned device's floor ≈
provisioning time, not epoch), short delegate lifetimes, and `boot_id` + scope binding on
the token the cert vouches for. A compromised delegation root is out of scope — it can
mint currently-valid certs regardless.

This is deliberate. The HSM is *not* asked to verify provenance, because doing so
would drag SUIT-manifest parsing and Roughtime validation into the HSM's TCB — a
large attack surface for essentially no security gain (see below). Every new time
source is a caller-side plugin: verify the signature, call `raise_monotonic`. The
HSM protocol never changes to add one.

## Threat model

The adversary has **filesystem / SOVD / NV-rollback access, not host code
execution.**

| Attack | Defense |
|---|---|
| Rewind the persisted floor on disk | HSM monotonicity — the NV counter can't go backward |
| Call `raise` with a bogus far-future value (auth DoS) | The raw `raise` op is **host-only link-B**, never exposed over the guest `vhsm-ssd` channel. The only *remote* path that advances it — the `x-attest-time` SOVD op — takes NO caller-supplied number: it accepts a **SoftwareAuthority-signed SUIT manifest** and ratchets to the manifest's own signature-covered `signing_time`. An attacker cannot forge a far-future time without the sw-authority key. |
| Feed an unsigned timestamp to the floor | The caller only ratchets from signature-verified sources |
| Replay an old signed manifest to `x-attest-time` | Monotonic — an `iat` at/below the floor is a no-op. Worst case: no change. |

The host callers that advance the floor are the OTA engine (`component-mgr`, on
every trust-root-verified manifest — see Provenance) and the `x-attest-time`
operator operation (below). Both ratchet only from a SoftwareAuthority-signed
`signing_time`; neither takes a raw number.

## Operator-pushed time: the `x-attest-time` operation

Ratcheting the floor during an OTA install has a bootstrap gap: a device whose
clock lags real time rejects a freshly-minted **workshop-delegate cert**
(`not_before ≈ now`) at `open_update` ("certificate not valid yet") — before any
manifest is uploaded, so nothing has advanced the floor yet. The delegate cert's
validity window is checked against `max(wall_clock, floor)`, and the floor is
still stale.

`x-attest-time` breaks that deadlock **without widening any cert window**:

```
POST /vehicle/v1/components/<host>/operations/x-attest-time/executions
  body { "parameters": "<hex of a SoftwareAuthority-signed SUIT manifest>" }
  → device verifies the signature to its pinned SoftwareAuthority root  (clock-free)
  → ratchets the safe-time floor to the manifest's signed signing_time  (monotonic)
  → disciplines CLOCK_REALTIME forward to the floor
THEN the normal flash: open_update's delegate-cert window is now checked at a
`now` past its not_before → it validates.
```

Why this is sound and **non-circular**: the manifest is signed by the
**SoftwareAuthority** root — a *different, independent* trust anchor from the
`delegation-root` that vouches for the workshop delegate cert. So a sw-authority
`signing_time` admitting a delegate cert is not self-referential; the workshop
minter/delegate is **never** trusted to assert time. Authorization for the op is
the ordinary `operations:execute` (Operational tier), carriable by a
`boot_id`-fresh pinned-issuer token — itself clock-free. The op is verify-only
(no payload, no bank write) and idempotent. An operator (e.g. the autoloader)
pushes any recent sw-authority-signed manifest it already holds before flashing.

## Why not verify provenance inside the HSM

It is tempting to make `raise` take the signed cert/SUIT/Roughtime blob and have
the HSM verify it before ratcheting — moving the trust boundary "down". We
deliberately don't:

- It pulls SUIT and Roughtime parsers into the HSM's trusted computing base,
  multiplying its attack surface. The HSM stays a small, auditable primitive
  provider (crypto + this counter).
- It buys almost nothing: a compromised host caller can obtain a real,
  validly-signed timestamp from a live source and advance the floor within it.
- Keeping the HSM generic is what makes new time sources free — Roughtime,
  signed-NTP, a fresh cert — each is caller-side verification plus one
  `raise_monotonic` call.

## Boundaries / non-goals

- **Not a clock.** The floor is a *lower bound*, never a source of "now". Anything
  needing the actual time still needs a real clock; the floor only rejects the past.
- **Not per-component versioning.** Each updatable component's anti-rollback
  `security_version` lives in `component-mgr`, not here. This counter is one
  generic slot; if a second monotonic value is ever needed, add a slot index then
  (YAGNI now).
- **Single counter.** No slot index today — one monotonic value, interpreted by
  the caller as the floor.

## Code map

| Concern | Location |
|---|---|
| link-B op codes (`OP_READ/RAISE_MONOTONIC`, 0x28/0x29) | `crates/hsm-link-b/src/lib.rs` |
| `HsmProvider::{read,raise}_monotonic` trait + client + dispatch | `crates/hsm/src/{lib.rs,link_b.rs}` |
| Dev/sim backend (file-mirrored counter) | `tools/crates/hsm-sim-backend/src/sim.rs` |
| Safe-time-floor interpretation | the consuming host machine-manager (a `read_safe_time_floor` accessor over `read_monotonic`) |

The counter first shipped as a bespoke `OP_*_TIME_FLOOR` / `read_time_floor` pair,
then was renamed to the generic monotonic form once it was clear the HSM should
not carry time semantics.
