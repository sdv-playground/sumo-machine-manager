//! Post-handshake request dispatch, shared by the two serve paths.
//!
//! By the time a request reaches here the caller's identity is already
//! established — a [`CallerId`]. The guest path (`main.rs::serve_connection`)
//! binds it via the in-band v3 CWT handshake over the private bridge; the
//! cross-node path ([`crate::crossnode`]) binds it from the verified mTLS
//! client certificate. Both then run the *same* per-request logic: dispatch
//! through [`handler::handle_request`], persist a newly-minted dynamic handle,
//! audit, and write the response. Keeping it in one place means the two
//! transports can't drift in how they authorize, persist, or audit.

use std::io::Write;
use std::sync::{Arc, Mutex};

use hsm::HsmCryptoProvider;
use secstore::{FileBackend, KeyMetadata, LinuxSimEncryptor, Secstore};

use crate::audit::AuditLogger;
use crate::codec;
use crate::handle_table::HandleTable;
use crate::handler::{self, CallerId};
use crate::iam::IamPolicy;
use crate::proto::{Op, Request, Response, StatusCode};

/// Whether the connection should keep serving after one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dispatch {
    /// Response written; keep reading.
    Continue,
    /// The response could not be written; close the connection.
    Close,
}

/// Dispatch one already-read, post-handshake request. Runs the op through
/// `handle_request`, persists a newly-created persistent dynamic handle (if
/// `store` is configured), records the audit line, and writes the response to
/// `writer`. Returns [`Dispatch::Close`] only when the response write fails —
/// op-level failures are normal responses with a non-OK status.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_request(
    req: &Request,
    caller: &CallerId,
    writer: &mut dyn Write,
    handle_table: &Arc<Mutex<HandleTable>>,
    iam: &IamPolicy,
    crypto: &dyn HsmCryptoProvider,
    store: Option<&Secstore<LinuxSimEncryptor, FileBackend>>,
    audit: &Arc<Mutex<AuditLogger>>,
) -> Dispatch {
    let (resp, authz) = {
        let mut table = handle_table.lock().unwrap();
        handler::handle_request(req, caller, &mut table, iam, crypto)
    };

    // Persist the handle a successful KEY_GENERATE minted, if it asked to be
    // persistent. The handle comes from the answer: another connection's
    // generate can land in the table between this request's two locks, so
    // neither the table's growth nor its last entry says which handle is ours,
    // and a failed generate must persist nothing.
    if let (Some(s), Some(handle)) = (store, generated_handle(req, &resp)) {
        let table = handle_table.lock().unwrap();
        if let Some(entry) = table.get(handle).filter(|e| e.persistent) {
            let label_str = std::str::from_utf8(&entry.label)
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_string();
            let meta = KeyMetadata {
                vhsm_handle: entry.handle,
                key_id: entry.key_id.clone(),
                algorithm: entry.algorithm,
                permitted_ops: entry.permitted_ops,
                owner_vm_id: entry.owner_vm_id.clone(),
                persistent: true,
                label: label_str,
            };
            if let Err(e) = s.store(&meta) {
                tracing::warn!(handle = entry.handle, error = %e, "failed to persist handle");
            }
        }
    }

    if let Err(e) = audit.lock().unwrap().record(caller, req, &resp, authz) {
        tracing::error!(vm = %caller.vm_id, error = %e, "audit log write failed");
    }

    if let Err(e) = codec::write_response(writer, &resp) {
        tracing::warn!(vm = %caller.vm_id, error = %e, "write error, closing connection");
        return Dispatch::Close;
    }
    Dispatch::Continue
}

/// The handle a successful KEY_GENERATE answered with: the first four bytes of
/// its result (`handle(4) + pubkey_len(4) + pubkey`). `None` for any other op or
/// status.
fn generated_handle(req: &Request, resp: &Response) -> Option<u32> {
    if req.op != Op::KeyGenerate as u32 || resp.status != StatusCode::Ok as u32 {
        return None;
    }
    let bytes: [u8; 4] = resp.payload.get(0..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{ALG_AES_256, LABEL_LEN, PERM_DECRYPT, PERM_ENCRYPT};
    use hsm_sim_backend::SimHsm;

    /// A KEY_GENERATE request: algorithm(4) + permitted_ops(4) + persistent(1) +
    /// pad(3) + label(32).
    fn keygen(alg: u32, persistent: bool) -> Request {
        let mut payload = Vec::with_capacity(44);
        payload.extend_from_slice(&alg.to_le_bytes());
        payload.extend_from_slice(&(PERM_ENCRYPT | PERM_DECRYPT).to_le_bytes());
        payload.push(persistent as u8);
        payload.extend_from_slice(&[0u8; 3]);
        payload.extend_from_slice(&[0u8; LABEL_LEN]);
        Request {
            op: Op::KeyGenerate as u32,
            session_id: 1,
            payload,
        }
    }

    /// Only a successful, persistent KEY_GENERATE is persisted, and under the
    /// handle its own answer names. A refused one persists nothing and leaves
    /// the table as it was.
    #[test]
    fn only_a_successful_persistent_generate_is_persisted_under_its_own_handle() {
        let keystore = tempfile::tempdir().expect("tempdir");
        let persist = tempfile::tempdir().expect("tempdir");
        let crypto = SimHsm::new(keystore.path().to_path_buf());
        let store = Secstore::new(
            LinuxSimEncryptor::default_test(),
            FileBackend::new(persist.path()),
        );
        let table = Arc::new(Mutex::new(HandleTable::new()));
        let audit = Arc::new(Mutex::new(AuditLogger::disabled()));
        let iam = IamPolicy::parse(
            "version: 1\nstatements:\n  - principals: [vm1]\n    handles: [system]\n    ops: [key-generate]\n",
        )
        .expect("policy parses");
        let caller = CallerId {
            peer_ip: "10.0.200.2".parse().expect("ip"),
            vm_id: "vm1".to_string(),
            cert_thumbprint: [0u8; 32],
        };
        let dispatch = |req: &Request| {
            let mut out = Vec::new();
            dispatch_request(
                req,
                &caller,
                &mut out,
                &table,
                &iam,
                &crypto,
                Some(&store),
                &audit,
            );
            codec::read_response(&mut out.as_slice()).expect("one response written")
        };

        // Refused: an algorithm the backend lacks. Nothing persisted, no entry.
        let refused = dispatch(&keygen(0x0099, true));
        assert_eq!(refused.status, StatusCode::InvalidParam as u32);
        assert_eq!(table.lock().unwrap().len(), 0);
        assert!(store.load_all().expect("load").is_empty());

        // A non-persistent success is not persisted.
        let volatile = dispatch(&keygen(ALG_AES_256, false));
        assert_eq!(volatile.status, StatusCode::Ok as u32);
        assert!(store.load_all().expect("load").is_empty());

        // A persistent success is persisted under the handle it answered.
        let kept = dispatch(&keygen(ALG_AES_256, true));
        assert_eq!(kept.status, StatusCode::Ok as u32);
        let handle = u32::from_le_bytes(kept.payload[0..4].try_into().unwrap());
        let saved = store.load_all().expect("load");
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].vhsm_handle, handle);
    }
}
