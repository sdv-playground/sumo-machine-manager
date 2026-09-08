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
use crate::proto::Request;

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
    let table_len_before = handle_table.lock().unwrap().len();

    let (resp, authz) = {
        let mut table = handle_table.lock().unwrap();
        handler::handle_request(req, caller, &mut table, iam, crypto)
    };

    // Persist if a dynamic handle was added (KEY_GENERATE success).
    if let Some(s) = store {
        let table = handle_table.lock().unwrap();
        if table.len() > table_len_before {
            if let Some(entry) = table.last() {
                if entry.persistent {
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
