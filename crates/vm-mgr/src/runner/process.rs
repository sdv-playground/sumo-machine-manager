//! Portable child-process runner for native integration tests.
//!
//! The process backend deliberately does not model a hypervisor. It launches a
//! test guest with the selector-resolved bank as its working directory and
//! exposes the same lifecycle to `VmManager` as the QEMU and QNX runners.

use std::path::PathBuf;
use std::process::{Child, Command};

use super::*;

pub struct ProcessRunner {
    child: Option<Child>,
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
        self.child = Some(child);
        Ok(VmHandle {
            name: name.to_string(),
            pid: Some(pid),
        })
    }

    fn stop(&mut self, _handle: &VmHandle) -> Result<(), RunnerError> {
        if let Some(child) = self.child.as_mut() {
            child.kill()?;
            let _ = child.wait();
        }
        self.child = None;
        Ok(())
    }

    fn is_running(&self, handle: &VmHandle) -> bool {
        handle
            .pid
            .map(|pid| unsafe { libc::kill(pid as libc::pid_t, 0) == 0 })
            .unwrap_or(false)
    }

    fn wait(&mut self, _handle: &VmHandle) -> Result<Option<i32>, RunnerError> {
        let Some(mut child) = self.child.take() else {
            return Err(RunnerError::ProcessFailed("process child not found".into()));
        };
        Ok(child.wait()?.code())
    }

    fn cleanup(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = None;
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
        def.process_args = vec!["-c".into(), "sleep 30".into()];
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
