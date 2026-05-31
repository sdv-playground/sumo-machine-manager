use std::fmt;

pub type MachineResult<T> = Result<T, MachineError>;

#[derive(Debug, Clone)]
pub enum MachineError {
    /// The component does not implement this operation.
    NotSupported(&'static str),
    /// No component with the given id is registered.
    NotFound(String),
    /// The caller passed an invalid argument (bad DID, bad chunk offset, ...).
    InvalidArgument(String),
    /// Operation rejected by policy (security version floor, anti-rollback, etc.).
    PolicyRejected(String),
    /// Resource is busy / state machine refuses the op right now (e.g. a
    /// previous OTA is still in trial mode). Distinct from PolicyRejected
    /// because the underlying condition is transient — the caller can
    /// commit/rollback and retry.
    Busy(String),
    /// Manifest validation failed (signature, hash, sequence number, ...).
    ManifestInvalid(String),
    /// Manifest is well-formed but addressed at a different target than
    /// the Component receiving it (e.g. a vm2 envelope handed to vm1's
    /// install pipeline).  The SOVD adapter maps this to HTTP 415
    /// Unsupported Media Type (BackendError::UnsupportedMediaType).
    WrongTarget(String),
    /// A flash session id is unknown or has expired.
    UnknownFlashSession(String),
    /// Backing storage / hardware error.
    Storage(String),
    /// Generic internal failure.
    Internal(String),
}

impl fmt::Display for MachineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSupported(op) => write!(f, "operation not supported: {op}"),
            Self::NotFound(id) => write!(f, "component not found: {id}"),
            Self::InvalidArgument(m) => write!(f, "invalid argument: {m}"),
            Self::PolicyRejected(m) => write!(f, "policy rejected: {m}"),
            Self::Busy(m) => write!(f, "busy: {m}"),
            Self::ManifestInvalid(m) => write!(f, "manifest invalid: {m}"),
            Self::WrongTarget(m) => write!(f, "wrong target: {m}"),
            Self::UnknownFlashSession(id) => write!(f, "unknown flash session: {id}"),
            Self::Storage(m) => write!(f, "storage error: {m}"),
            Self::Internal(m) => write!(f, "internal error: {m}"),
        }
    }
}

impl std::error::Error for MachineError {}
