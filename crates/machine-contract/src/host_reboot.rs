//! The node-reset primitive: how THIS kind of node is asked to reset, and nothing
//! about when. A deployment decides when a reset is owed, what must happen first
//! and how long teardown may take (that is the deadman's job, in `host-reboot`);
//! an implementation only knows the mechanism — a QNX kernel-direct reset, a
//! process exit under a respawn supervisor, whatever another OS needs. Defined
//! here so the deadman can fire any of them without knowing which, and so a board
//! can bring its own without forking the deadman.

/// The mechanism that resets this node.
///
/// Same shape as [`BankActivator`](crate::BankActivator): one synchronous method
/// the platform implements and the shared code calls. `host-reboot` ships two
/// (`QnxSysmgrReboot`, `ExitRespawnReboot`) and holds callers to
/// `Arc<dyn HostReboot>`, so a board with a third mechanism writes it where its
/// other platform impls live.
pub trait HostReboot: Send + Sync {
    /// Request the reset now. On success the call may never return (the node is
    /// resetting); `Ok(())` means the reset was requested; `Err` means it could
    /// not even be requested and the caller should log and fall back.
    fn reboot(&self) -> std::io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::HostReboot;

    /// The deadman holds the implementation as `Arc<dyn HostReboot>` and fires it
    /// from a thread it spawns, so the trait must be object-safe AND the erased
    /// form must be `Send + Sync`. A compile-time assertion, because the failure
    /// mode is a build break at the caller, not a test failure here.
    #[test]
    fn an_erased_implementation_is_object_safe_and_shareable() {
        fn assert_shareable<T: Send + Sync + ?Sized>() {}
        assert_shareable::<dyn HostReboot>();
        assert_shareable::<Box<dyn HostReboot>>();
    }
}
