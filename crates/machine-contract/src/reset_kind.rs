//! The reset class an activation demands of the node.

/// What a bank activation demands of the node afterwards. This is a SOVD wire
/// value (snake_case: "none" / "local" / "requires_ecu_reset"); the canonical
/// wire enum is `sovd_core::ResetKind` and machine-mgr converts exhaustively
/// in both directions. It is defined HERE so that an implementer of the bank
/// traits never has to depend on SOVDd to name a reset kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResetKind {
    /// Activation needs no reset (HSM keystore swap, container hot-reload).
    None,
    /// Activation cycles the component itself (qvm restart, container restart,
    /// daemon SIGHUP). **Default** — most components fall here.
    #[default]
    Local,
    /// Activation requires rebooting the parent ECU because the newly-staged
    /// image only runs after a host boot (M7 firmware via m7loader, host-OS IFS
    /// via the Dev/Partition activators).
    RequiresEcuReset,
}

#[cfg(test)]
mod tests {
    use super::ResetKind;

    #[test]
    fn wire_strings_are_snake_case() {
        // Wire-visible names — the orchestrator parses these. Lock them down.
        assert_eq!(serde_json::to_string(&ResetKind::None).unwrap(), "\"none\"");
        assert_eq!(
            serde_json::to_string(&ResetKind::Local).unwrap(),
            "\"local\""
        );
        assert_eq!(
            serde_json::to_string(&ResetKind::RequiresEcuReset).unwrap(),
            "\"requires_ecu_reset\""
        );
    }

    #[test]
    fn default_is_local() {
        // `#[serde(default)]` on the carrying structs leans on this: a payload
        // written before the field existed deserialises to Local, which is what
        // those components actually did.
        assert_eq!(ResetKind::default(), ResetKind::Local);
    }
}
