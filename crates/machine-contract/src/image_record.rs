//! Image record — the platform's own record of an image in a bank.
//!
//! Some platforms keep their own table of *which image lives where, and which
//! one boots*: a hardware boot manager's image table, a boot ROM's slot
//! descriptor, a loader's image list. Writing that table is platform code — it
//! knows image types and device nodes, two things machine-mgr deliberately
//! never learns. What machine-mgr owns is the **order** those writes must
//! happen in, and ordering is the whole of this seam:
//!
//! - [`sealed`](ImageRecord::sealed) runs while the bank is being sealed, BEFORE
//!   the bank is signed — a record that refuses aborts the install rather than
//!   leaving a signed bank the platform disowns.
//! - [`route`](ImageRecord::route) runs BEFORE the boot selector is switched to
//!   the bank, on activate and on rollback alike — the platform always learns
//!   where to boot from before the node is told to boot there. A route error
//!   leaves the selector untouched.
//! - `commit` never routes: committing confirms the bank that already booted, it
//!   moves nothing.
//!
//! Attaching a record is opt-in per bank part ([`crate::BankProvider`] impls
//! carry the handle); a part without one is untouched by any of this.

use nv_store::types::Bank;

use crate::bank_provider::BankError;

/// The platform's own record of an image in a bank. See the module docs — the
/// ordering guarantees are the point, not the payload.
pub trait ImageRecord: Send + Sync {
    /// An image is sealed into `bank`: `size` bytes hashing to `sha256`, as read
    /// BACK off the medium (never what the wire claimed). Called before the bank
    /// is signed; an `Err` aborts the seal.
    fn sealed(&self, bank: Bank, size: u64, sha256: &[u8; 32]) -> Result<(), BankError>;

    /// Point the record at `bank` — the bank the node is about to be told to
    /// boot. Called before the boot selector is switched, on activate and on
    /// rollback; an `Err` aborts with the selector untouched.
    fn route(&self, bank: Bank) -> Result<(), BankError>;
}
