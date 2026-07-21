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
| Call `raise` with a bogus far-future value (auth DoS) | The raw `raise` op is **host-only link-B**, never exposed over the guest `vhsm-ssd` channel. The only *remote* path that advances it — the `x-sumo-attest-time` SOVD op — takes NO caller-supplied number: it accepts a **SoftwareAuthority-signed SUIT manifest** and ratchets to the manifest's own signature-covered `signing_time`. An attacker cannot forge a far-future time without the sw-authority key. |
| Feed an unsigned timestamp to the floor | The caller only ratchets from signature-verified sources |
| Replay an old signed manifest to `x-sumo-attest-time` | Monotonic — an `iat` at/below the floor is a no-op. Worst case: no change. |

The host callers that advance the floor are the OTA engine (`component-mgr`, on
every trust-root-verified manifest — see Provenance) and the `x-sumo-attest-time`
operator operation (below). Both ratchet only from a SoftwareAuthority-signed
`signing_time`; neither takes a raw number.

## Operator-pushed time: the `x-sumo-attest-time` operation

Ratcheting the floor during an OTA install has a bootstrap gap: a device whose
clock lags real time rejects a freshly-minted **workshop-delegate cert**
(`not_before ≈ now`) at `open_update` ("certificate not valid yet") — before any
manifest is uploaded, so nothing has advanced the floor yet. The delegate cert's
validity window is checked against `max(wall_clock, floor)`, and the floor is
still stale.

`x-sumo-attest-time` breaks that deadlock **without widening any cert window**:

```
POST /vehicle/v1/components/<host>/operations/x-sumo-attest-time/executions
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
