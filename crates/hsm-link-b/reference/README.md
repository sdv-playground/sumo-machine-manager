# Link-B HSE service skeleton (the vendor handoff)

`hse_service_skeleton.c` is the artifact you hand a hardware / HSE vendor. It is
a complete, compilable **C skeleton of the full Link-B surface** — every
handle-addressed crypto op plus the provisioning / key-management ops — with the
real crypto stubbed out.

## The contract: implement Link B and nothing else

The vendor implements **Link B and nothing else**. This process answers
handle-addressed ops over a UNIX stream socket. It never sees:

- the guest-facing vHSM wire ("link A"),
- sessions or the connect-time handshake,
- guest identity or IAM / ACLs.

The host proxy (`vhsm-ssd`) terminates all of that and forwards only the backend
op. Link A and Link B evolve independently, so what you build here does not move
when the guest wire changes.

The frozen contract is the `hsm-link-b` crate, **not** this file:

- `../src/lib.rs` — authoritative: the per-op payload table, the field codec, the
  `OP_*` / `ST_*` / `KEYTYPE_*` constants, the `KeyInfo` layout.
- `../include/hsm_link_b.h` — the C mirror of those constants (this skeleton
  `#include`s it). Rust is authoritative; if the two ever disagree, Rust wins.

The wire frame is a uniform **3-field little-endian header in both directions**
(`a | flags | len`, where `a` is the op on a request and the status on a
response). A 2-field response would desync the host reader and **deadlock** —
the skeleton always writes all three fields.

## Build & run

```sh
cc -Wall -I ../include hse_service_skeleton.c -o hse_service
./hse_service --listen <unix-socket> [--keystore <path>]
```

Compiles warning-free under `-Wall` (and `-Wall -Wextra -std=c11 -pedantic`). It
serves one connection, then exits. `--keystore` is accepted for CLI parity with
a real service but ignored here.

## What you implement: `grep 'TODO(vendor)'`

Every place a real HSE SDK call goes is marked `TODO(vendor):`:

```sh
grep -n 'TODO(vendor)' hse_service_skeleton.c
```

Until you fill them in, each crypto op returns a **clearly-fake, deterministic**
value (e.g. a signature is 70 bytes of `0xA1`), correctly framed — so the host
side can be exercised before any real crypto exists. The framing, the field
codec (the C mirror of the Rust `Writer` / `Reader`), the dispatch over every
op, and the slot-map resolution are all real and complete.

Handle handling, already wired:

- An unknown handle returns `ST_KEY_NOT_FOUND`.
- A **virtual** handle (a public-only trust anchor) on a **private-key** op
  returns `ST_VIRTUAL`. Link B has no dedicated virtual-handle status, so that
  name is a local alias for the frozen `ST_NOT_SUPPORTED` — do not add a new
  wire code. Public-half ops (`VERIFY`, `GET_PUBLIC_KEY_DER`, `GET_KEY_INFO`)
  work on virtual anchors.
- A **counter** handle (the `time-floor` monotonic slot) answers only
  `READ_MONOTONIC` / `RAISE_MONOTONIC`. Those ops on a non-counter handle — and
  the key catalogue (`LIST_KEYS` / `GET_KEY_INFO`) on the counter — return
  `ST_KEY_NOT_FOUND`, because a counter is not a key.

## What you replace: the slot map (the per-silicon part)

The `SLOT_MAP` table near the top of the file is a **hypothetical** device — a
made-up HSM with 16 NVM ECC slots, 4 NVM symmetric slots, and a monotonic-counter
bank. It binds each well-known sumo-core handle (`sw-authority` 0x0002 …
`tls-identity` 0x000C, plus the `time-floor` counter 0x000D) to a physical slot,
and marks the four public-only trust anchors
(`sw` / `key` / `operational` / `factory-reset-issuer` = 0x0002 / 0x0005 / 0x0008
/ 0x0009) as `VIRTUAL`. The `time-floor` slot (0x000D) is not a key at all: it is
a rollback-proof **monotonic counter** answering `READ_MONOTONIC` /
`RAISE_MONOTONIC`, so it never appears in the key catalogue (`LIST_KEYS` /
`GET_KEY_INFO`). Handle 0x000B is a retired gap (was `freshness-signing`).

This is the **one table a real integrator replaces** for their silicon: keep the
logical handles identical, substitute your own physical slot numbers / key
banks. Nothing above Link B (the proxy, the transport, the op contract) changes.
