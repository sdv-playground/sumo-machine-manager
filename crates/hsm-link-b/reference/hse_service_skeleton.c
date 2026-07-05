/*
 * hse_service_skeleton.c — a FULL-SURFACE Link-B HSE service skeleton.
 *
 * THE VENDOR HANDOFF ARTIFACT. A hardware/HSE vendor implements Link B and
 * NOTHING else: this process answers handle-addressed crypto + provisioning
 * ops over a stream socket. It never sees the guest-facing vHSM wire ("link A"),
 * sessions, guest identity, or IAM — the host proxy (vhsm-ssd) strips all of
 * that and forwards only the backend op. Link A and Link B evolve independently.
 *
 * This file mirrors the FROZEN contract in the `hsm-link-b` crate:
 *   - crates/hsm-link-b/src/lib.rs      (authoritative: per-op payload table)
 *   - crates/hsm-link-b/include/hsm_link_b.h  (the C mirror of the constants)
 * Rust is authoritative; if the two disagree, the Rust crate wins.
 *
 * Wire frame — a uniform 3-field little-endian header in BOTH directions:
 *   request:   op:u32     | flags:u32 | payload_len:u32 | payload[payload_len]
 *   response:  status:u32 | flags:u32 | result_len:u32  | result[result_len]
 * `flags` is reserved (FLAGS_NONE). A 2-field response would desync the host
 * reader and DEADLOCK — the response header MUST carry all three fields.
 *
 * Field encoding within a payload (mirrors the Rust Writer / Reader):
 *   u8 / u32 / u64 : fixed little-endian scalars.
 *   bytes          : a u32-length-prefixed blob  ->  len:u32 | bytes[len].
 *   tail           : the final field, rest of payload, no length prefix.
 * For handle-addressed ops the logical handle is the FIRST payload field (it is
 * NOT in the header — that is the key difference from the older 4-op skeleton).
 *
 * What is real vs. stubbed:
 *   - The framing, the field codec, the dispatch over every op, and the slot
 *     map are real and complete.
 *   - The CRYPTO is stubbed. Every place a real HSE SDK call goes is marked
 *     `TODO(vendor): ...` and returns a clearly-fake, deterministic value
 *     (framed correctly). Find them all with:  grep -n 'TODO(vendor)'
 *   - The SLOT MAP below is a HYPOTHETICAL device. It is the per-silicon part:
 *     a real integrator replaces that one table for their hardware.
 *
 * Build:  cc -Wall -I ../include hse_service_skeleton.c -o hse_service
 * Usage:  ./hse_service --listen <unix-socket> [--keystore <path>]
 *         (serves one connection, then exits — like the reference it grew from)
 */

#include "hsm_link_b.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

/* Request payload / response result are bounded by this skeleton. */
#define LINKB_BUF_CAP  65536u
/* Length-driven stub outputs (RANDOM, DERIVE, fake ciphertext) are capped so a
 * caller-supplied length can never overrun the response buffer. */
#define LINKB_STUB_MAX  4096u

/*
 * Link B has NO dedicated "virtual handle" status code — hsm_link_b.h / the
 * Rust crate are authoritative, so do not invent one on the wire. A public-only
 * trust anchor (sw / key / operational / factory-reset-issuer) carries no
 * private key on this silicon, so a PRIVATE-KEY op against one cannot be served.
 * On the wire that is the frozen ST_NOT_SUPPORTED; we name the intent
 * ST_VIRTUAL locally purely for readability.
 */
#define ST_VIRTUAL ST_NOT_SUPPORTED

/* ===================================================================== */
/* Little-endian scalars + length-framed socket I/O.                     */
/* ===================================================================== */

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void put_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[3] = (uint8_t)((v >> 24) & 0xffu);
}
static uint64_t le64(const uint8_t *p) {
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}
static void put_le64(uint8_t *p, uint64_t v) {
    int i;
    for (i = 0; i < 8; i++) p[i] = (uint8_t)((v >> (8 * i)) & 0xffu);
}
static int read_all(int fd, uint8_t *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}
static int write_all(int fd, const uint8_t *buf, size_t n) {
    size_t put = 0;
    while (put < n) {
        ssize_t w = write(fd, buf + put, n - put);
        if (w <= 0) return -1;
        put += (size_t)w;
    }
    return 0;
}

/* ===================================================================== */
/* Payload field primitives — the C mirror of the Rust Writer / Reader.  */
/*                                                                       */
/* These are non-static so the COMPLETE primitive set is part of the     */
/* reference even where this particular skeleton happens not to exercise */
/* one: no response field in the current surface is a u64, for instance, */
/* so wr_u64 is provided but unused here. u8/u32/u64 are fixed LE         */
/* scalars; `bytes` is a u32-length-prefixed blob; `tail` is the final   */
/* unprefixed field.                                                     */
/* ===================================================================== */

typedef struct {
    const uint8_t *buf;
    uint32_t       len;
    uint32_t       pos;
    int            ok;  /* cleared on underrun -> caller returns ST_PROTOCOL_ERROR */
} rdr_t;

void rdr_init(rdr_t *r, const uint8_t *buf, uint32_t len) {
    r->buf = buf;
    r->len = len;
    r->pos = 0;
    r->ok = 1;
}
static const uint8_t *rd_take(rdr_t *r, uint32_t n) {
    const uint8_t *p;
    if (!r->ok || n > r->len - r->pos) {
        r->ok = 0;
        return NULL;
    }
    p = r->buf + r->pos;
    r->pos += n;
    return p;
}
uint8_t rd_u8(rdr_t *r) {
    const uint8_t *p = rd_take(r, 1);
    return p ? p[0] : 0u;
}
uint32_t rd_u32(rdr_t *r) {
    const uint8_t *p = rd_take(r, 4);
    return p ? le32(p) : 0u;
}
uint64_t rd_u64(rdr_t *r) {
    const uint8_t *p = rd_take(r, 8);
    return p ? le64(p) : 0u;
}
/* A length-prefixed blob written by wr_bytes. */
const uint8_t *rd_bytes(rdr_t *r, uint32_t *out_len) {
    uint32_t n = rd_u32(r);
    const uint8_t *p = rd_take(r, n);
    *out_len = p ? n : 0u;
    return p;
}
/* The rest of the payload (the wr_tail field). */
const uint8_t *rd_tail(rdr_t *r, uint32_t *out_len) {
    const uint8_t *p = r->buf + r->pos;
    *out_len = r->len - r->pos;
    r->pos = r->len;
    return p;
}

typedef struct {
    uint8_t *buf;
    uint32_t cap;
    uint32_t len;  /* bytes intended; writes past `cap` are dropped (capped paths only) */
} wtr_t;

void wtr_init(wtr_t *w, uint8_t *buf, uint32_t cap) {
    w->buf = buf;
    w->cap = cap;
    w->len = 0;
}
void wr_u8(wtr_t *w, uint8_t v) {
    if (w->len + 1u <= w->cap) w->buf[w->len] = v;
    w->len += 1u;
}
void wr_u32(wtr_t *w, uint32_t v) {
    if (w->len + 4u <= w->cap) put_le32(w->buf + w->len, v);
    w->len += 4u;
}
void wr_u64(wtr_t *w, uint64_t v) {
    if (w->len + 8u <= w->cap) put_le64(w->buf + w->len, v);
    w->len += 8u;
}
/* The final field: raw bytes, no length prefix. */
void wr_tail(wtr_t *w, const uint8_t *b, uint32_t n) {
    if (w->len + n <= w->cap) memcpy(w->buf + w->len, b, n);
    w->len += n;
}
/* A length-prefixed blob: len:u32 | bytes. */
void wr_bytes(wtr_t *w, const uint8_t *b, uint32_t n) {
    wr_u32(w, n);
    wr_tail(w, b, n);
}

/* Append `n` bytes of `fill` — how every crypto STUB synthesises its fake,
 * deterministic output. A real impl emits real bytes via wr_tail / wr_bytes. */
static void wr_fill(wtr_t *w, uint8_t fill, uint32_t n) {
    static uint8_t tmp[LINKB_STUB_MAX];
    if (n > LINKB_STUB_MAX) n = LINKB_STUB_MAX;
    memset(tmp, fill, n);
    wr_tail(w, tmp, n);
}

/* ===================================================================== */
/* The HYPOTHETICAL slot map — the per-silicon binding (REPLACE THIS).    */
/*                                                                       */
/* This skeleton models a made-up HSM with two key banks plus a counter: */
/*   - 16 NVM ECC slots        (asymmetric P-256 keys)                   */
/*   -  4 NVM symmetric slots  (AES / HMAC secret keys)                  */
/*   -  a monotonic-counter bank (rollback-proof u64 counters, no keys)  */
/* deliberately more than the sumo-core inventory needs (headroom).      */
/*                                                                       */
/* It binds each well-known sumo-core handle (sw-authority 0x0002 ..     */
/* tls-identity 0x000C, plus the time-floor counter 0x000D) to a slot.   */
/* The four public-only trust anchors — sw / key / operational /         */
/* factory-reset-issuer = 0x0002 / 0x0005 / 0x0008 / 0x0009 — hold NO    */
/* private key on this device and are marked VIRTUAL; a private-key op   */
/* against one returns ST_VIRTUAL. The time-floor slot (0x000D) is NOT a */
/* key: it is a rollback-proof MONOTONIC COUNTER (read/raise only). It   */
/* DOES appear in the inventory (LIST_SLOTS / GET_SLOT_INFO), 0xFF.      */
/*                                                                       */
/* A real integrator REPLACES this whole table for their silicon: the    */
/* logical handles stay identical, the physical slot numbers / key banks */
/* become theirs. This is the slot-map reference.                        */
/* ===================================================================== */

/* Hypothetical physical slot id: (bank << 8) | index. Purely illustrative —
 * a real HSE has its own slot / key-handle encoding. */
#define HSM_ECC_BANK 0x01u  /* 16 asymmetric P-256 slots */
#define HSM_SYM_BANK 0x02u  /*  4 symmetric AES / HMAC slots */
#define HSM_ECC_SLOT(n) (((uint32_t)HSM_ECC_BANK << 8) | (uint32_t)(n)) /* n: 0..15 */
#define HSM_SYM_SLOT(n) (((uint32_t)HSM_SYM_BANK << 8) | (uint32_t)(n)) /* n: 0..3  */
#define HSM_MONOTONIC_BANK 0x03u  /* rollback-proof monotonic counters (no keys) */
#define HSM_MONOTONIC_SLOT(n) (((uint32_t)HSM_MONOTONIC_BANK << 8) | (uint32_t)(n)) /* n: 0.. */

/*
 * KEYTYPE_MONOTONIC (defined in hsm_link_b.h) is the wire `kind` for a slot that
 * holds no key material: a rollback-proof MONOTONIC COUNTER (the time-floor). It
 * now crosses the wire as SlotInfo.kind exactly like a real KEYTYPE_* — the slot
 * inventory (LIST_SLOTS / GET_SLOT_INFO) enumerates counter rows too. It stays
 * clear of the real key-type range (1..5). Mirrors the host-side ALG_MONOTONIC
 * sentinel that labels this slot in the sumo-core registry.
 */

typedef struct {
    uint32_t    handle;     /* logical sumo-core vHSM handle (the wire identity) */
    int         is_virtual; /* 1 = public-only anchor: no private slot here      */
    uint32_t    slot;       /* physical slot id (valid only when !is_virtual)    */
    uint32_t    key_type;   /* SlotInfo.kind: KEYTYPE_* or KEYTYPE_MONOTONIC     */
    int         has_cert;   /* 1 = an X.509 cert is stored alongside this key     */
    const char *key_id;     /* stable key_id (GET_SLOT_INFO / LIST_SLOTS)         */
} binding_t;

static const binding_t SLOT_MAP[] = {
    /* handle  virt  physical slot     key_type         cert  key_id */
    { 0x0002,  1, 0,               KEYTYPE_EC_P256,  0, "sw-authority"         }, /* VIRTUAL anchor */
    { 0x0003,  0, HSM_ECC_SLOT(0), KEYTYPE_EC_P256,  0, "device-decrypt"       },
    { 0x0004,  0, HSM_ECC_SLOT(1), KEYTYPE_EC_P256,  0, "iam-signing"          },
    { 0x0005,  1, 0,               KEYTYPE_EC_P256,  0, "key-authority"        }, /* VIRTUAL anchor */
    { 0x0006,  0, HSM_ECC_SLOT(2), KEYTYPE_EC_P256,  0, "jwt-signing"          },
    { 0x0007,  0, HSM_SYM_SLOT(0), KEYTYPE_AES256,   0, "storage-key"          },
    { 0x0008,  1, 0,               KEYTYPE_EC_P256,  0, "operational-issuer"   }, /* VIRTUAL anchor */
    { 0x0009,  1, 0,               KEYTYPE_EC_P256,  0, "factory-reset-issuer" }, /* VIRTUAL anchor */
    { 0x000A,  0, HSM_ECC_SLOT(3), KEYTYPE_EC_P256,  0, "ivd-signing"          },
    /* 0x000B RETIRED (was "freshness-signing") — do NOT reuse this handle. */
    { 0x000C,  0, HSM_ECC_SLOT(5), KEYTYPE_EC_P256,  1, "tls-identity"         }, /* mTLS leaf: has a cert */
    /* Not a key: a rollback-proof monotonic COUNTER (host-only time-floor). */
    { 0x000D,  0, HSM_MONOTONIC_SLOT(0), KEYTYPE_MONOTONIC, 0, "time-floor"   },
};
static const size_t SLOT_MAP_LEN = sizeof(SLOT_MAP) / sizeof(SLOT_MAP[0]);

static const binding_t *resolve(uint32_t handle) {
    size_t i;
    for (i = 0; i < SLOT_MAP_LEN; i++)
        if (SLOT_MAP[i].handle == handle) return &SLOT_MAP[i];
    return NULL;
}

static int is_symmetric(uint32_t key_type) {
    return key_type == KEYTYPE_AES128 ||
           key_type == KEYTYPE_AES256 ||
           key_type == KEYTYPE_HMAC_SHA256;
}

/* A counter row (KEYTYPE_MONOTONIC) is NOT a key: it holds no key material and
 * answers only READ/RAISE_MONOTONIC, never a crypto op or the key catalogue. */
static int is_counter(uint32_t key_type) {
    return key_type == KEYTYPE_MONOTONIC;
}

/* Skeleton state — a real HSE tracks this in silicon (secure NV). */
static int g_provisioned = 0;

/*
 * Per-handle rollback-proof monotonic counters (the time-floor lives here). A
 * tiny table keyed by logical handle; each cell reads 0 until first raised.
 * This is a REFERENCE store in process RAM so the host side can be exercised.
 * TODO(vendor): back each counter with tamper-resistant, rollback-proof
 * monotonic NV (HSE secure counters) — process RAM is neither persistent nor
 * rollback-proof, so it does NOT provide the anti-rollback guarantee.
 */
typedef struct { uint32_t handle; uint64_t value; } counter_cell_t;
static counter_cell_t g_counters[4];
static size_t g_counter_len = 0;

/* The counter cell for `handle`, lazily created (0-initialised) on first use;
 * NULL only if the fixed table is full (cannot happen for the mapped set). */
static counter_cell_t *counter_cell(uint32_t handle) {
    size_t i;
    for (i = 0; i < g_counter_len; i++)
        if (g_counters[i].handle == handle) return &g_counters[i];
    if (g_counter_len >= sizeof(g_counters) / sizeof(g_counters[0])) return NULL;
    g_counters[g_counter_len].handle = handle;
    g_counters[g_counter_len].value = 0;
    return &g_counters[g_counter_len++];
}

/*
 * Encode one SlotInfo per the frozen layout:
 *   handle:u32, kind:u32, has_certificate:u8, key_id:bytes(utf-8),
 *   allowed_guests:optlist, allowed_ops:optlist
 * where optlist = present:u8, [count:u32, item:bytes(utf-8) x count]
 * (present = 0 => None). `kind` is a KEYTYPE_* for a key slot or
 * KEYTYPE_MONOTONIC for the monotonic-counter slot. This skeleton reports both
 * optlists as None — guest ACLs are the host proxy's concern (link A), never
 * the backend's.
 */
static void wr_slot_info(wtr_t *w, const binding_t *b) {
    wr_u32(w, b->handle);
    wr_u32(w, b->key_type);
    wr_u8(w, (uint8_t)(b->has_cert ? 1 : 0));
    wr_bytes(w, (const uint8_t *)b->key_id, (uint32_t)strlen(b->key_id));
    wr_u8(w, 0u); /* allowed_guests: None */
    wr_u8(w, 0u); /* allowed_ops:    None */
}

/* ===================================================================== */
/* Link-B dispatch — every op: crypto (0x01..0x11), provisioning         */
/* (0x20..0x27), and the monotonic-counter ops (0x28..0x29).             */
/*                                                                       */
/* Pattern per handle-addressed op: decode the request fields per the     */
/* frozen table, resolve the logical handle through the slot map (unknown */
/* -> ST_KEY_NOT_FOUND), reject a virtual handle on a PRIVATE-key op with  */
/* ST_VIRTUAL, then call the HSE SDK. Each SDK call is a TODO(vendor) stub */
/* that returns a clearly-fake deterministic value, framed correctly.     */
/* ===================================================================== */
static uint32_t handle_op(uint32_t op, const uint8_t *payload, uint32_t plen,
                          uint8_t *out, uint32_t *out_len) {
    rdr_t r;
    wtr_t w;
    rdr_init(&r, payload, plen);
    wtr_init(&w, out, LINKB_BUF_CAP);
    *out_len = 0;

    switch (op) {

    /* ---- crypto: signing ---------------------------------------------- */
    case OP_SIGN: {
        uint32_t handle = rd_u32(&r);
        uint32_t dlen;  const uint8_t *data = rd_tail(&r, &dlen);
        const binding_t *b;
        if (!r.ok) return ST_PROTOCOL_ERROR;
        b = resolve(handle);
        if (!b) return ST_KEY_NOT_FOUND;
        if (b->is_virtual) return ST_VIRTUAL;
        (void)data; (void)dlen;
        /* TODO(vendor): sig = HSE ECDSA-P256 sign of SHA-256(data) on b->slot,
         * DER-encoded (SEQUENCE { INTEGER r, INTEGER s }); emit as the tail. */
        wr_fill(&w, 0xA1, 70u); /* fake ~70-byte DER ECDSA signature */
        *out_len = w.len;
        return ST_OK;
    }
    case OP_SIGN_RAW_P256: {
        uint32_t handle = rd_u32(&r);
        uint32_t dlen;  const uint8_t *data = rd_tail(&r, &dlen);
        const binding_t *b;
        if (!r.ok) return ST_PROTOCOL_ERROR;
        b = resolve(handle);
        if (!b) return ST_KEY_NOT_FOUND;
        if (b->is_virtual) return ST_VIRTUAL;
        (void)data; (void)dlen;
        /* TODO(vendor): raw P-256 ECDSA sign on b->slot; emit 64-byte r||s. */
        wr_fill(&w, 0xA2, 64u);
        *out_len = w.len;
        return ST_OK;
    }
    case OP_VERIFY: {
        uint32_t handle = rd_u32(&r);
        uint32_t mlen;  const uint8_t *msg = rd_bytes(&r, &mlen);
        uint32_t slen;  const uint8_t *sig = rd_tail(&r, &slen);
        const binding_t *b;
        if (!r.ok) return ST_PROTOCOL_ERROR;
        b = resolve(handle);
        if (!b) return ST_KEY_NOT_FOUND;
        /* VERIFY is a PUBLIC-key op: virtual trust anchors verify from their
         * public bytes — do NOT reject is_virtual here. */
        (void)msg; (void)mlen; (void)sig; (void)slen;
        /* TODO(vendor): ok = HSE ECDSA verify(public-of(b), msg, sig). */
        wr_u8(&w, 1u); /* fake: accept */
        *out_len = w.len;
        return ST_OK;
    }

    /* ---- crypto: bulk + MAC ------------------------------------------- */
    case OP_ENCRYPT: {
        uint32_t handle = rd_u32(&r);
        uint32_t ptlen;  const uint8_t *pt = rd_tail(&r, &ptlen);
        const binding_t *b;
        if (!r.ok) return ST_PROTOCOL_ERROR;
        b = resolve(handle);
        if (!b) return ST_KEY_NOT_FOUND;
        if (b->is_virtual) return ST_VIRTUAL;
        (void)pt;
        /* TODO(vendor): AES-GCM encrypt on b->slot; emit iv(12) || ct || tag(16). */
        wr_fill(&w, 0xE1, 12u);    /* fake 12-byte IV */
        wr_fill(&w, 0xE2, ptlen);  /* fake ciphertext (length capped by wr_fill) */
        wr_fill(&w, 0xE3, 16u);    /* fake 16-byte tag */
        *out_len = w.len;
        return ST_OK;
    }
    case OP_DECRYPT: {
        uint32_t handle = rd_u32(&r);
        uint32_t ctlen;  const uint8_t *ct = rd_tail(&r, &ctlen);
        const binding_t *b;
        if (!r.ok) return ST_PROTOCOL_ERROR;
        b = resolve(handle);
        if (!b) return ST_KEY_NOT_FOUND;
        if (b->is_virtual) return ST_VIRTUAL;
        (void)ct; (void)ctlen;
        /* TODO(vendor): AES-GCM (storage-key) or ECIES (device-decrypt) decrypt;
         * emit the recovered plaintext. ST_DECRYPTION_FAILED on tag mismatch. */
        wr_fill(&w, 0xD5, 16u); /* fake recovered plaintext */
        *out_len = w.len;
        return ST_OK;
    }
    case OP_MAC_GENERATE: {
        uint32_t handle = rd_u32(&r);
        uint32_t dlen;  const uint8_t *data = rd_tail(&r, &dlen);
        const binding_t *b;
        if (!r.ok) return ST_PROTOCOL_ERROR;
        b = resolve(handle);
        if (!b) return ST_KEY_NOT_FOUND;
        if (b->is_virtual) return ST_VIRTUAL;
        (void)data; (void)dlen;
        /* TODO(vendor): HMAC-SHA256 / CMAC on b->slot, truncated to 16 bytes. */
        wr_fill(&w, 0x6A, 16u);
        *out_len = w.len;
        return ST_OK;
    }
    case OP_MAC_VERIFY: {
        uint32_t handle = rd_u32(&r);
        uint32_t dlen;  const uint8_t *data = rd_bytes(&r, &dlen);
        uint32_t mlen;  const uint8_t *mac = rd_tail(&r, &mlen);
        const binding_t *b;
        if (!r.ok) return ST_PROTOCOL_ERROR;
        b = resolve(handle);
        if (!b) return ST_KEY_NOT_FOUND;
        if (b->is_virtual) return ST_VIRTUAL; /* MAC needs the secret key */
        (void)data; (void)dlen; (void)mac; (void)mlen;
        /* TODO(vendor): recompute the MAC on b->slot and constant-time compare. */
        wr_u8(&w, 1u); /* fake: accept */
        *out_len = w.len;
        return ST_OK;
    }
    case OP_DERIVE: {
        uint32_t handle = rd_u32(&r);
        uint32_t want   = rd_u32(&r);
        uint32_t clen;  const uint8_t *ctx = rd_tail(&r, &clen);
        const binding_t *b;
        if (!r.ok) return ST_PROTOCOL_ERROR;
        b = resolve(handle);
        if (!b) return ST_KEY_NOT_FOUND;
        if (b->is_virtual) return ST_VIRTUAL;
        (void)ctx; (void)clen;
        /* TODO(vendor): KDF (e.g. HKDF) from b->slot keyed by `ctx`, `want` bytes. */
        wr_fill(&w, 0x8D, want); /* length capped by wr_fill */
        *out_len = w.len;
        return ST_OK;
    }
    case OP_RANDOM: {
        uint32_t want = rd_u32(&r);
        if (!r.ok) return ST_PROTOCOL_ERROR;
        /* TODO(vendor): fill `want` bytes from the HSE TRNG.
         * (This stub emits a FIXED pattern — deliberately NOT random.) */
        wr_fill(&w, 0x99, want); /* length capped by wr_fill */
        *out_len = w.len;
        return ST_OK;
    }

    /* ---- crypto: exports + key info ----------------------------------- */
    case OP_GET_CERTIFICATE_DER: {
        uint32_t handle = rd_u32(&r);
        const binding_t *b;
        if (!r.ok) return ST_PROTOCOL_ERROR;
        b = resolve(handle);
        if (!b) return ST_KEY_NOT_FOUND;
        if (!b->has_cert) return ST_KEY_NOT_FOUND; /* no cert stored for this slot */
        /* TODO(vendor): export the stored X.509 cert (DER) for b->slot. */
        wr_fill(&w, 0xCE, 120u); /* fake DER certificate */
        *out_len = w.len;
        return ST_OK;
    }
    case OP_GET_PUBLIC_KEY_DER: {
        uint32_t handle = rd_u32(&r);
        const binding_t *b;
        if (!r.ok) return ST_PROTOCOL_ERROR;
        b = resolve(handle);
        if (!b) return ST_KEY_NOT_FOUND;
        /* Public-half read: valid for virtual anchors too. */
        /* TODO(vendor): export SubjectPublicKeyInfo (SPKI DER) for the slot. */
        wr_fill(&w, 0xB0, 91u); /* fake P-256 SPKI DER (real length is 91 bytes) */
        *out_len = w.len;
        return ST_OK;
    }
    case OP_GET_TRUST_ANCHOR_DER: {
        uint32_t idlen;  const uint8_t *anchor_id = rd_tail(&r, &idlen);
        if (!r.ok) return ST_PROTOCOL_ERROR;
        (void)anchor_id; (void)idlen;
        /* TODO(vendor): look up the pinned trust-anchor cert/pubkey (DER) by the
         * utf-8 anchor_id; ST_KEY_NOT_FOUND if unknown. */
        wr_fill(&w, 0xAC, 91u);
        *out_len = w.len;
        return ST_OK;
    }
    case OP_GET_SLOT_INFO: {
        uint32_t handle = rd_u32(&r);
        const binding_t *b;
        if (!r.ok) return ST_PROTOCOL_ERROR;
        b = resolve(handle);
        if (!b) return ST_KEY_NOT_FOUND;
        /* Metadata read — valid for EVERY slot: key slots, virtual anchors, AND
         * the monotonic counter (reported with kind KEYTYPE_MONOTONIC). */
        wr_slot_info(&w, b);
        *out_len = w.len;
        return ST_OK;
    }

    /* ---- crypto: key lifecycle + CEK unwrap --------------------------- */
    case OP_GENERATE_KEY: {
        uint32_t handle = rd_u32(&r);
        uint32_t alg    = rd_u32(&r);
        const binding_t *b;
        if (!r.ok) return ST_PROTOCOL_ERROR;
        b = resolve(handle);
        if (!b) return ST_KEY_NOT_FOUND;
        if (b->is_virtual) return ST_VIRTUAL;
        (void)alg; /* TODO(vendor): validate the requested alg matches the slot. */
        /* TODO(vendor): generate a fresh key in b->slot. Symmetric => empty
         * result; asymmetric => emit the new public key as SPKI DER. */
        if (!is_symmetric(b->key_type))
            wr_fill(&w, 0xB1, 91u); /* fake SPKI DER for the new P-256 public key */
        *out_len = w.len;           /* 0 (empty) for symmetric keys */
        return ST_OK;
    }
    case OP_GENERATE_CSR: {
        uint32_t handle = rd_u32(&r);
        uint32_t cnlen;  const uint8_t *cn = rd_tail(&r, &cnlen);
        const binding_t *b;
        if (!r.ok) return ST_PROTOCOL_ERROR;
        b = resolve(handle);
        if (!b) return ST_KEY_NOT_FOUND;
        if (b->is_virtual) return ST_VIRTUAL;
        (void)cn; (void)cnlen;
        /* TODO(vendor): build a PKCS#10 CSR for subject CN, self-sign with
         * b->slot; emit the CSR DER. */
        wr_fill(&w, 0xC5, 200u);
        *out_len = w.len;
        return ST_OK;
    }
    case OP_UNWRAP_CEK_A128KW: {
        uint32_t handle = rd_u32(&r);
        uint32_t wlen;  const uint8_t *wrapped = rd_tail(&r, &wlen);
        const binding_t *b;
        if (!r.ok) return ST_PROTOCOL_ERROR;
        b = resolve(handle);
        if (!b) return ST_KEY_NOT_FOUND;
        if (b->is_virtual) return ST_VIRTUAL;
        (void)wrapped; (void)wlen;
        /* TODO(vendor): AES-128 key-unwrap (RFC 3394) the CEK with b->slot. */
        wr_fill(&w, 0x1A, 16u); /* fake 16-byte CEK */
        *out_len = w.len;
        return ST_OK;
    }
    case OP_UNWRAP_CEK_ECDH_ES: {
        uint32_t handle = rd_u32(&r);
        uint32_t eplen;  const uint8_t *ephem   = rd_bytes(&r, &eplen);
        uint32_t wlen;   const uint8_t *wrapped = rd_bytes(&r, &wlen);
        uint32_t rplen;  const uint8_t *recip   = rd_tail(&r, &rplen);
        const binding_t *b;
        if (!r.ok) return ST_PROTOCOL_ERROR;
        b = resolve(handle);
        if (!b) return ST_KEY_NOT_FOUND;
        if (b->is_virtual) return ST_VIRTUAL;
        (void)ephem; (void)eplen; (void)wrapped; (void)wlen; (void)recip; (void)rplen;
        /* TODO(vendor): ECDH-ES(b->slot, ephem) -> KEK, then A128KW-unwrap the
         * CEK, binding `recipient_protected` per COSE. */
        wr_fill(&w, 0x1E, 16u); /* fake 16-byte CEK */
        *out_len = w.len;
        return ST_OK;
    }

    /* ---- provisioning / key management -------------------------------- */
    case OP_IS_PROVISIONED:
        /* TODO(vendor): report whether the keystore is installed. */
        wr_u8(&w, (uint8_t)(g_provisioned ? 1 : 0));
        *out_len = w.len;
        return ST_OK;

    case OP_PROVISION: {
        uint32_t elen;  const uint8_t *envelope = rd_tail(&r, &elen);
        if (!r.ok) return ST_PROTOCOL_ERROR;
        (void)envelope; (void)elen;
        /* TODO(vendor): verify the SUIT provisioning envelope and install the
         * keystore into HSE NVM. ST_ENVELOPE_INVALID / ST_ALREADY_PROVISIONED
         * as appropriate. */
        g_provisioned = 1;
        return ST_OK; /* empty result */
    }
    case OP_LIST_SLOTS: {
        size_t i;
        /* TODO(vendor): enumerate EVERY slot — the key slots AND the non-key
         * monotonic-counter slot (the time-floor, reported with kind
         * KEYTYPE_MONOTONIC). The inventory is STRUCTURE, not state: the counter
         * VALUE is never reported here (read it via READ_MONOTONIC). */
        wr_u32(&w, (uint32_t)SLOT_MAP_LEN);
        for (i = 0; i < SLOT_MAP_LEN; i++)
            wr_slot_info(&w, &SLOT_MAP[i]);
        *out_len = w.len;
        return ST_OK;
    }
    case OP_PROVISIONING_STATE:
        /* TODO(vendor): map your provisioning state machine to a u32.
         * Illustrative: 0 = unprovisioned, 1 = provisioned. */
        wr_u32(&w, g_provisioned ? 1u : 0u);
        *out_len = w.len;
        return ST_OK;

    case OP_ARM_ENROLLMENT: {
        uint8_t  ttl_present = rd_u8(&r);
        uint64_t ttl         = rd_u64(&r);
        uint32_t vlen;  const uint8_t *vm_id = rd_tail(&r, &vlen);
        if (!r.ok) return ST_PROTOCOL_ERROR;
        (void)ttl_present; (void)ttl; (void)vm_id; (void)vlen;
        /* TODO(vendor): arm the assisted-enrollment window for vm_id (optional ttl). */
        return ST_OK; /* empty result */
    }
    case OP_IS_ENROLLED: {
        uint32_t vlen;  const uint8_t *vm_id = rd_tail(&r, &vlen);
        if (!r.ok) return ST_PROTOCOL_ERROR;
        (void)vm_id; (void)vlen;
        /* TODO(vendor): report whether vm_id is enrolled. */
        wr_u8(&w, 0u); /* fake: not enrolled */
        *out_len = w.len;
        return ST_OK;
    }
    case OP_CLEAR_ENROLLED: {
        uint32_t vlen;  const uint8_t *vm_id = rd_tail(&r, &vlen);
        if (!r.ok) return ST_PROTOCOL_ERROR;
        (void)vm_id; (void)vlen;
        /* TODO(vendor): clear vm_id's enrollment; return whether anything changed. */
        wr_u8(&w, 0u); /* fake: nothing cleared */
        *out_len = w.len;
        return ST_OK;
    }
    case OP_GET_PUBLIC_KEY: {
        uint32_t role = rd_u32(&r);
        if (!r.ok) return ST_PROTOCOL_ERROR;
        (void)role;
        /* TODO(vendor): export the role's public key as a COSE_Key (CBOR map).
         * Below is a correctly-SHAPED but FAKE ES256 COSE_Key:
         *   { 1:2 (kty EC2), -1:1 (crv P-256), -2:x(32), -3:y(32) } */
        wr_u8(&w, 0xA4);                  /* map(4)  */
        wr_u8(&w, 0x01); wr_u8(&w, 0x02); /* 1 : 2   */
        wr_u8(&w, 0x20); wr_u8(&w, 0x01); /* -1 : 1  */
        wr_u8(&w, 0x21); wr_u8(&w, 0x58); wr_u8(&w, 0x20); wr_fill(&w, 0x27, 32u); /* -2 : x */
        wr_u8(&w, 0x22); wr_u8(&w, 0x58); wr_u8(&w, 0x20); wr_fill(&w, 0x27, 32u); /* -3 : y */
        *out_len = w.len;
        return ST_OK;
    }

    /* ---- monotonic counters (rollback-proof, addressed by handle) ----- */
    case OP_READ_MONOTONIC: {
        uint32_t handle = rd_u32(&r);
        const binding_t *b;
        const counter_cell_t *c;
        if (!r.ok) return ST_PROTOCOL_ERROR;
        b = resolve(handle);
        if (!b) return ST_KEY_NOT_FOUND;
        if (!is_counter(b->key_type)) return ST_KEY_NOT_FOUND; /* not a counter slot */
        /* TODO(vendor): read the tamper-resistant monotonic NV counter for
         * b->slot. Here: the per-handle RAM cell (0 if never raised). */
        c = counter_cell(handle);
        wr_u64(&w, c ? c->value : 0u);
        *out_len = w.len;
        return ST_OK;
    }
    case OP_RAISE_MONOTONIC: {
        uint32_t handle    = rd_u32(&r);
        uint64_t new_value = rd_u64(&r);
        const binding_t *b;
        counter_cell_t *c;
        if (!r.ok) return ST_PROTOCOL_ERROR;
        b = resolve(handle);
        if (!b) return ST_KEY_NOT_FOUND;
        if (!is_counter(b->key_type)) return ST_KEY_NOT_FOUND; /* not a counter slot */
        c = counter_cell(handle);
        if (!c) return ST_KEYSTORE_ERROR; /* counter table full — unreachable here */
        /* Ratchet to max(current, new_value): a lower value is a NO-OP, so the
         * counter can only move forward, never rewind. This is the safety core.
         * TODO(vendor): ratchet the tamper-resistant, rollback-proof monotonic
         * NV counter for b->slot instead of this RAM cell. */
        if (new_value > c->value) c->value = new_value;
        wr_u64(&w, c->value);
        *out_len = w.len;
        return ST_OK;
    }

    default:
        /* Op code outside the link-B surface. */
        return ST_PROTOCOL_ERROR;
    }
}

/* ===================================================================== */
/* main: bind a UNIX socket, accept one connection, run the serve loop.   */
/* ===================================================================== */
int main(int argc, char **argv) {
    const char *sock = NULL;
    const char *keystore = NULL;
    int i, srv, fd;
    size_t path_len;
    struct sockaddr_un addr;
    static uint8_t payload[LINKB_BUF_CAP];
    static uint8_t out[LINKB_BUF_CAP];
    uint8_t hdr[HSM_LINK_B_HEADER_SIZE];
    uint8_t resp[HSM_LINK_B_HEADER_SIZE];

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc) {
            sock = argv[++i];
        } else if (strcmp(argv[i], "--keystore") == 0 && i + 1 < argc) {
            keystore = argv[++i];
        } else {
            fprintf(stderr, "usage: %s --listen <unix-socket> [--keystore <path>]\n", argv[0]);
            return 2;
        }
    }
    if (!sock) {
        fprintf(stderr, "usage: %s --listen <unix-socket> [--keystore <path>]\n", argv[0]);
        return 2;
    }
    /* `--keystore` is accepted for CLI parity with a real service (which would
     * load its keystore from here); this skeleton keeps keys in the slot map. */
    (void)keystore;

    unlink(sock); /* remove a stale socket from a prior run */

    srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    path_len = strlen(sock);
    if (path_len >= sizeof(addr.sun_path)) {
        fprintf(stderr, "socket path too long: %s\n", sock);
        return 1;
    }
    memcpy(addr.sun_path, sock, path_len + 1); /* +1 copies the NUL terminator */

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(srv, 1) < 0) { perror("listen"); return 1; }

    fd = accept(srv, NULL, NULL);
    if (fd < 0) { perror("accept"); return 1; }

    for (;;) {
        uint32_t op, flags, plen, out_len, status;

        if (read_all(fd, hdr, HSM_LINK_B_HEADER_SIZE) < 0) break;
        op    = le32(hdr);
        flags = le32(hdr + 4); /* reserved (FLAGS_NONE) */
        plen  = le32(hdr + 8);
        (void)flags;
        if (plen > sizeof(payload)) break; /* oversized frame — drop the connection */
        if (plen && read_all(fd, payload, plen) < 0) break;

        out_len = 0;
        status = handle_op(op, payload, plen, out, &out_len);
        if (out_len > sizeof(out)) out_len = (uint32_t)sizeof(out); /* defensive clamp */

        /* Response uses the SAME 3-field header (status | flags | len). A
         * 2-field response would desync the host reader and DEADLOCK. */
        put_le32(resp, status);
        put_le32(resp + 4, HSM_LINK_B_FLAGS_NONE);
        put_le32(resp + 8, out_len);
        if (write_all(fd, resp, HSM_LINK_B_HEADER_SIZE) < 0) break;
        if (out_len && write_all(fd, out, out_len) < 0) break;
    }

    close(fd);
    close(srv);
    unlink(sock);
    return 0;
}
