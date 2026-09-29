//! Portable child-process runner for native integration tests.
//!
//! The process backend deliberately does not model a hypervisor. It launches a
//! test guest with the selector-resolved bank as its working directory and
//! exposes the same lifecycle to `VmManager` as the QEMU and QNX runners.

use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};

use super::*;

pub struct ProcessRunner {
    child: Option<Arc<Mutex<Child>>>,
}

impl Default for ProcessRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessRunner {
    pub fn new() -> Self {
        Self { child: None }
    }

    fn command(def: &VmDefinition) -> Result<PathBuf, RunnerError> {
        def.process_command
            .clone()
            .ok_or_else(|| RunnerError::Config("process backend requires process_command".into()))
    }
}

impl VmRunner for ProcessRunner {
    fn start(&mut self, name: &str, def: &VmDefinition) -> Result<VmHandle, RunnerError> {
        if self.child.is_some() {
            return Err(RunnerError::ProcessFailed(
                "process runner already has a child".into(),
            ));
        }

        let command = Self::command(def)?;
        let bank_dir = def.image_dir.to_string_lossy().into_owned();
        let child = Command::new(&command)
            .args(&def.process_args)
            .current_dir(&def.image_dir)
            .env("SUMO_VM_NAME", name)
            .env("SUMO_VM_BANK_DIR", &bank_dir)
            .spawn()
            .map_err(|e| RunnerError::ProcessFailed(format!("{}: {e}", command.display())))?;
        let pid = child.id();
        self.child = Some(Arc::new(Mutex::new(child)));
        Ok(VmHandle {
            name: name.to_string(),
            pid: Some(pid),
        })
    }

    fn stop(&mut self, _handle: &VmHandle) -> Result<(), RunnerError> {
        if let Some(child) = self.child.as_ref() {
            let mut child = child.lock().unwrap();
            if child.try_wait()?.is_none() {
                child.kill()?;
                child.wait()?;
            }
        }
        self.child = None;
        Ok(())
    }

    fn is_running(&self, _handle: &VmHandle) -> bool {
        self.child.as_ref().is_some_and(|child| {
            child
                .lock()
                .unwrap()
                .try_wait()
                .is_ok_and(|exit| exit.is_none())
        })
    }

    fn exit_probe(&self) -> Option<Arc<dyn Fn() -> bool + Send + Sync>> {
        let child = self.child.as_ref()?.clone();
        Some(Arc::new(move || {
            child
                .lock()
                .unwrap()
                .try_wait()
                .is_ok_and(|exit| exit.is_some())
        }))
    }

    fn wait(&mut self, _handle: &VmHandle) -> Result<Option<i32>, RunnerError> {
        let Some(child) = self.child.take() else {
            return Err(RunnerError::ProcessFailed("process child not found".into()));
        };
        let mut child = child.lock().unwrap();
        Ok(child.wait()?.code())
    }

    fn cleanup(&mut self) {
        if let Some(child) = self.child.take() {
            let mut child = child.lock().unwrap();
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

impl Drop for ProcessRunner {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BackendType;
    use std::time::Duration;

    fn definition(command: Option<PathBuf>) -> VmDefinition {
        VmDefinition {
            backend: BackendType::Process,
            image_dir: std::env::temp_dir(),
            process_command: command,
            process_args: Vec::new(),
            ..serde_yaml::from_str("backend: dummy\nimage_dir: /tmp\n").unwrap()
        }
    }

    #[test]
    fn requires_process_command() {
        let mut runner = ProcessRunner::new();
        let error = match runner.start("vm1", &definition(None)) {
            Ok(_) => panic!("process backend unexpectedly started without a command"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("process_command"));
    }

    #[cfg(unix)]
    #[test]
    fn starts_and_stops_a_process() {
        let mut runner = ProcessRunner::new();
        let mut def = definition(Some("/bin/sh".into()));
        def.process_args = vec!["-c".into(), "exec sleep 30".into()];
        let handle = runner.start("vm1", &def).unwrap();
        assert!(runner.is_running(&handle));
        runner.stop(&handle).unwrap();
        assert!(!runner.is_running(&handle));
        runner
            .graceful_shutdown(&handle, Duration::from_millis(1))
            .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn reaps_exited_child_and_allows_relaunch() {
        let mut runner = ProcessRunner::new();
        let mut def = definition(Some("/bin/sh".into()));
        def.process_args = vec!["-c".into(), "exit 0".into()];
        let handle = runner.start("vm1", &def).unwrap();
        for _ in 0..100 {
            if !runner.is_running(&handle) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!runner.is_running(&handle));
        runner.cleanup();
        let next = runner.start("vm1", &def).unwrap();
        runner.wait(&next).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn dropping_runner_kills_and_reaps_its_child() {
        let mut runner = ProcessRunner::new();
        let mut def = definition(Some("/bin/sh".into()));
        def.process_args = vec!["-c".into(), "exec sleep 30".into()];
        let handle = runner.start("vm1", &def).unwrap();
        assert!(runner.is_running(&handle));
        let pid = handle.pid.unwrap();

        drop(runner);

        assert_ne!(unsafe { libc::kill(pid as libc::pid_t, 0) }, 0);
    }

    #[cfg(unix)]
    #[test]
    fn passes_vm_context_to_the_child() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("context");
        let mut runner = ProcessRunner::new();
        let mut def = definition(Some("/bin/sh".into()));
        def.image_dir = dir.path().to_path_buf();
        def.process_args = vec![
            "-c".into(),
            format!(
                "printf '%s\\n%s' \"$SUMO_VM_NAME\" \"$SUMO_VM_BANK_DIR\" > {}",
                marker.display()
            ),
        ];
        let handle = runner.start("vm1", &def).unwrap();
        runner.wait(&handle).unwrap();
        let context = std::fs::read_to_string(marker).unwrap();
        assert_eq!(context, format!("vm1\n{}", dir.path().display()));
    }
}
