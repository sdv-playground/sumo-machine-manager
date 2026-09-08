//! vHSM wire protocol — re-exported from the shared [`vhsm_proto`] crate (the
//! authoritative definition, mirrored in `vhsm_proto.h` + `vhsm-handles-ext`).
//! The server and the client (`vhsm-client`) share one wire contract.
pub use vhsm_proto::*;
