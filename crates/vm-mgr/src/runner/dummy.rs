/// Dummy runner — no-op backend for components without a real VM process.
use super::*;

pub struct DummyRunner;

impl Default for DummyRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl DummyRunner {
    pub fn new() -> Self {
        Self
    }
}

impl VmRunner for DummyRunner {
    fn start(&mut self, name: &str, _def: &VmDefinition) -> Result<VmHandle, RunnerError> {
        Ok(VmHandle {
            name: name.to_string(),
            pid: None,
        })
    }

    fn stop(&mut self, _handle: &VmHandle) -> Result<(), RunnerError> {
        Ok(())
    }

    fn is_running(&self, _handle: &VmHandle) -> bool {
        false
    }

    fn wait(&mut self, _handle: &VmHandle) -> Result<Option<i32>, RunnerError> {
        Ok(Some(0))
    }

    fn cleanup(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn dummy_vm_def() -> VmDefinition {
        serde_yaml::from_str(
            r#"
backend: dummy
image_dir: /nonexistent
"#,
        )
        .unwrap()
    }

    #[test]
    fn start_returns_handle_with_name_and_no_pid() {
        let mut r = DummyRunner::new();
        let h = r.start("host", &dummy_vm_def()).unwrap();
        assert_eq!(h.name, "host");
        assert!(h.pid.is_none());
    }

    #[test]
    fn is_running_always_false() {
        let r = DummyRunner::new();
        let h = VmHandle {
            name: "x".into(),
            pid: None,
        };
        assert!(!r.is_running(&h));
    }

    #[test]
    fn stop_and_wait_are_noops() {
        let mut r = DummyRunner::new();
        let h = r.start("x", &dummy_vm_def()).unwrap();
        r.stop(&h).unwrap();
        let rc = r.wait(&h).unwrap();
        assert_eq!(rc, Some(0));
    }

    #[test]
    fn cleanup_is_idempotent() {
        let mut r = DummyRunner::new();
        r.cleanup();
        r.cleanup(); // second call must not panic
    }

    #[test]
    fn default_graceful_shutdown_delegates_to_stop() {
        let mut r = DummyRunner::new();
        let h = r.start("x", &dummy_vm_def()).unwrap();
        // Default impl in trait: calls stop(). DummyRunner::stop is Ok(()).
        r.graceful_shutdown(&h, Duration::from_secs(1)).unwrap();
    }

    #[test]
    fn default_wait_ready_returns_immediately() {
        let mut r = DummyRunner::new();
        let h = r.start("x", &dummy_vm_def()).unwrap();
        // Trait default returns Ok(()).
        r.wait_ready(&h, Duration::from_secs(1)).unwrap();
    }
}
