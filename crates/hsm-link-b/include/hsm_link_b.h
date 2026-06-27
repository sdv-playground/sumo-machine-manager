/*
 * hsm_link_b.h — Link-B: the host <-> physical-HSE service protocol.
 *
 * The C mirror of the Rust `hsm-link-b` crate. A vendor's HSE service implements
 * THIS protocol and nothing else: it answers handle-addressed crypto +
 * provisioning ops over a stream socket. It never sees the guest wire (link A),
 * sessions, identity, or IAM — the host proxy strips those first. It is
 * deliberately decoupled from the guest wire so the two evolve independently.
 *
 * Keep this file byte-for-byte in step with crates/hsm-link-b/src/lib.rs
 * (Rust is authoritative; drift = wrong status/op at runtime).
 *
 * Wire frame (uniform 3-field little-endian header, both directions):
 *   request:   op:u32     | flags:u32 | payload_len:u32 | payload[payload_len]
 *   response:  status:u32 | flags:u32 | result_len:u32  | result[result_len]
 *
 * Field encoding within a payload:
 *   - u8/u32/u64 : fixed little-endian scalars.
 *   - bytes      : length-prefixed blob  ->  len:u32 | bytes[len]
 *   - tail       : the final field, rest of payload, no length prefix.
 *
 * On an error response status != ST_OK and result is a UTF-8 message.
 * The per-op payload table lives in the Rust crate docs and
 * docs/design/hsm-backend-architecture.md.
 */
#ifndef HSM_LINK_B_H
#define HSM_LINK_B_H

#include <stdint.h>

#define HSM_LINK_B_HEADER_SIZE 12u /* three u32 fields */
#define HSM_LINK_B_FLAGS_NONE  0u

/* Op codes — crypto (0x01..0x1F). */
#define OP_SIGN                 0x01u
#define OP_SIGN_RAW_P256        0x02u
#define OP_VERIFY               0x03u
#define OP_ENCRYPT              0x04u
#define OP_DECRYPT              0x05u
#define OP_MAC_GENERATE         0x06u
#define OP_MAC_VERIFY           0x07u
#define OP_DERIVE               0x08u
#define OP_RANDOM               0x09u
#define OP_GET_CERTIFICATE_DER  0x0Au
#define OP_GET_PUBLIC_KEY_DER   0x0Bu
#define OP_GET_TRUST_ANCHOR_DER 0x0Cu
#define OP_GET_KEY_INFO         0x0Du
#define OP_GENERATE_KEY         0x0Eu
#define OP_GENERATE_CSR         0x0Fu
#define OP_UNWRAP_CEK_A128KW    0x10u
#define OP_UNWRAP_CEK_ECDH_ES   0x11u

/* Op codes — provisioning / key management (0x20..0x3F). */
#define OP_IS_PROVISIONED       0x20u
#define OP_PROVISION            0x21u
#define OP_LIST_KEYS            0x22u
#define OP_PROVISIONING_STATE   0x23u
#define OP_ARM_ENROLLMENT       0x24u
#define OP_IS_ENROLLED          0x25u
#define OP_CLEAR_ENROLLED       0x26u
#define OP_GET_PUBLIC_KEY       0x27u

/* Status codes (mirror the Rust HsmError categories). */
#define ST_OK                   0u
#define ST_NOT_PROVISIONED      1u
#define ST_ALREADY_PROVISIONED  2u
#define ST_NOT_RUNNING          3u
#define ST_ALREADY_RUNNING      4u
#define ST_KEYSTORE_ERROR       5u
#define ST_PROCESS_ERROR        6u
#define ST_CONFIG_ERROR         7u
#define ST_ENVELOPE_INVALID     8u
#define ST_PAYLOAD_INVALID      9u
#define ST_DECRYPTION_FAILED    10u
#define ST_ROLLBACK_REJECTED    11u
#define ST_NOT_SUPPORTED        12u
#define ST_CRYPTO_ERROR         13u
#define ST_KEY_NOT_FOUND        14u
#define ST_PROTOCOL_ERROR       15u /* malformed frame/payload */

#endif /* HSM_LINK_B_H */
