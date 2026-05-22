//! QNX qvm runner — thin wrapper around the qvm hypervisor process.
//!
//! Lifecycle:
//!   1. devb-loopback maps the rootfs file to `/dev/qvmdiskN`
//!   2. `qvm @<config>` launches the guest VM
//!   3. Track the qvm PID for is_running / stop / wait
//!
//! Health monitoring (heartbeat read, shutdown command) is owned by
//! `VmManager` via `HeartbeatDevice` + `PowerCommandDevice` over the
//! configured `DeviceTransport`. The runner has nothing to do with it.

use std::path::Path;
use std::process::{Child, Command};
use std::time::Duration;

use super::*;

/// Timeout waiting for devb-loopback to create the device node.
const LOOPBACK_TIMEOUT: Duration = Duration::from_secs(5);

pub struct QnxRunner {
    /// devb-loopback spawn parents for rootfs + every extra disk. Each held
    /// `Child` is just the fork parent — devb-loopback double-forks. The
    /// real daemons land in `loopback_pids` so cleanup can libc::kill them.
    loopback_children: Vec<Child>,
    loopback_pids: Vec<u32>,
    /// VM name remembered from start() so cleanup can re-find any daemons
    /// whose pid wasn't captured (find raced ahead of devb-loopback's
    /// daemonize) — see [`Self::slay_loopbacks_for_vm`].
    vm_name: Option<String>,
    /// qvm process (the guest VM).
    qvm_child: Option<Child>,
}

impl QnxRunner {
    pub fn new() -> Self {
        Self {
            loopback_children: Vec::new(),
            loopback_pids: Vec::new(),
            vm_name: None,
            qvm_child: None,
        }
    }

    /// Kill a child process if it's still alive.
    fn kill_child(child: &mut Child) {
        let _ = child.kill();
        let _ = child.wait();
    }

    /// Prefix the rootfs devb-loopback registers under in `/dev`.
    fn rootfs_prefix(vm_name: &str) -> String {
        format!("qvmdisk-{vm_name}")
    }

    /// Prefix an extra-disk devb-loopback registers under in `/dev`. Single
    /// hyphen — matches the rootfs `qvmdisk-{vm}` pattern. Empirically, two
    /// hyphens in the prefix made the device node never appear (devb-loopback
    /// process ran but io-blk silently dropped the registration).
    fn extra_prefix(vm_name: &str, role: &str) -> String {
        format!("qvm{role}-{vm_name}")
    }

    fn extra_device(vm_name: &str, role: &str) -> String {
        format!("/dev/{}0", Self::extra_prefix(vm_name, role))
    }

    /// Walk `/proc/<pid>/cmdline` for every live process and return
    /// `(pid, argv_string)` pairs. argv tokens are NUL-separated on
    /// disk; we substitute spaces so callers can `.contains()`-match.
    ///
    /// QNX 7.1's `pidin -F "%p %a"` does NOT include argv — `%a`
    /// surfaces some other field (priority-ish). procfs is the only
    /// portable way to read argv on this platform.
    fn enumerate_pids_with_cmdline() -> Vec<(u32, String)> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return out;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Ok(pid) = name.parse::<u32>() else { continue };
            let cmdline_path = format!("/proc/{pid}/cmdline");
            let Ok(bytes) = std::fs::read(&cmdline_path) else { continue };
            if bytes.is_empty() { continue; }
            let argv = String::from_utf8_lossy(&bytes).replace('\0', " ");
            out.push((pid, argv));
        }
        out
    }

    /// Find every live devb-loopback daemon associated with this VM.
    ///
    /// `Command::spawn`'s child pid points at the (long-dead) fork parent
    /// because devb-loopback daemonizes. The actual driver shows up with
    /// the same argv vector. Match argv on the `prefix=…-{vm_name},fd=`
    /// substring so we hit both `qvmdisk-{vm}` and `qvm-{role}-{vm}`.
    fn find_loopback_pids(vm_name: &str) -> Vec<u32> {
        let needle = format!("-{vm_name},fd=");
        Self::enumerate_pids_with_cmdline()
            .into_iter()
            .filter(|(_, argv)| argv.contains("devb-loopback") && argv.contains(&needle))
            .map(|(pid, _)| pid)
            .collect()
    }

    /// SIGTERM-then-SIGKILL every devb-loopback for this VM. Used as
    /// defense-in-depth at start() to clear leftovers from a prior boot
    /// that didn't go through cleanup() (process crash, hard reset).
    fn slay_loopbacks_for_vm(vm_name: &str) {
        for pid in Self::find_loopback_pids(vm_name) {
            tracing::info!(vm = %vm_name, pid, "killing stale devb-loopback");
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM); }
            std::thread::sleep(Duration::from_millis(100));
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL); }
        }
    }

    /// Spawn a devb-loopback for a backing file with a given prefix, wait
    /// for `/dev/<prefix>0` to appear, and remember the daemon pid for
    /// cleanup. Shared by the rootfs + extra-disks paths.
    fn spawn_loopback(&mut self, prefix: &str, backing: &Path) -> Result<(), RunnerError> {
        let device = format!("/dev/{prefix}0");
        tracing::info!("starting devb-loopback: {} → {device}", backing.display());
        let child = Command::new("devb-loopback")
            .arg("loopback")
            .arg(format!("prefix={prefix},fd={}", backing.display()))
            .spawn()
            .map_err(|e| RunnerError::ProcessFailed(format!("devb-loopback: {e}")))?;
        self.loopback_children.push(child);
        wait_for_device(&device, LOOPBACK_TIMEOUT)?;
        if let Some(pid) = Self::find_loopback_pid_by_prefix(prefix) {
            self.loopback_pids.push(pid);
            tracing::info!("{device} ready (devb-loopback pid: {pid})");
        } else {
            tracing::info!("{device} ready (devb-loopback pid: unresolved)");
        }
        Ok(())
    }

    fn find_loopback_pid_by_prefix(prefix: &str) -> Option<u32> {
        let needle = format!("prefix={prefix},");
        Self::enumerate_pids_with_cmdline()
            .into_iter()
            .find(|(_, argv)| argv.contains("devb-loopback") && argv.contains(&needle))
            .map(|(pid, _)| pid)
    }

    /// Find every live qvm process started against this VM's qvm config.
    ///
    /// `Command::new("qvm").arg("@<config>")` → argv shape `qvm @<config>`.
    /// Match against the config path so we only slay qvms whose config we
    /// own — other VMs' qvms stay untouched.
    fn find_qvm_pids(qvm_config: &Path) -> Vec<u32> {
        let needle = format!("@{}", qvm_config.display());
        Self::enumerate_pids_with_cmdline()
            .into_iter()
            .filter(|(_, argv)| {
                if !argv.contains(&needle) { return false; }
                // Confirm argv[0] is `qvm` (not some other process that
                // happens to reference the config path in its argv).
                let mut tokens = argv.split_whitespace();
                let Some(cmd) = tokens.next() else { return false };
                cmd == "qvm" || cmd.rsplit('/').next() == Some("qvm")
            })
            .map(|(pid, _)| pid)
            .collect()
    }

    /// SIGTERM-then-SIGKILL every qvm running against this VM's config.
    ///
    /// Defense in depth at start() for orphan qvms that the tracked
    /// `qvm_child` handle can't reach — e.g. a previous supernova
    /// lifetime spawned qvm, then supernova got slayed; start-managed.sh
    /// kicks off the next supernova with a global `slay qvm` but that's
    /// best-effort with no exit-wait, so the new vm-service can race a
    /// dying qvm and end up with a fresh VmManager (qvm_child=None)
    /// while an orphan qvm still holds /dev/qvm/<sys>, vdevpeer
    /// endpoints, and qvm-shmem slots. Symptom: VMs keep serving the
    /// OLD rootfs from page cache after an OTA flash — only a device
    /// reboot dislodges the orphan.
    fn slay_qvm_for_vm(qvm_config: &Path) {
        for pid in Self::find_qvm_pids(qvm_config) {
            tracing::info!(qvm_config = %qvm_config.display(), pid, "killing stale qvm");
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM); }
            std::thread::sleep(Duration::from_millis(100));
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL); }
        }
    }
}

/// Poll for a device node to appear, with timeout.
fn wait_for_device(path: &str, timeout: Duration) -> Result<(), RunnerError> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if Path::new(path).exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(RunnerError::ProcessFailed(format!(
        "{path} did not appear within {}s",
        timeout.as_secs()
    )))
}

impl VmRunner for QnxRunner {
    /// Slay orphan qvm + devb-loopback for this VM. Called by
    /// VmManager BEFORE the pre-launch verify hook runs so the
    /// verifier can read `rootfs.img` directly — otherwise a
    /// leftover devb-loopback from a previous lifetime holds the
    /// file open (QNX returns EBUSY on second-opener).
    fn prepare_for_launch(&mut self, name: &str, def: &VmDefinition) {
        // Compute the same qvm_config path start() will use, so we
        // can target the orphan qvm by argv.
        let qvm_config = match def.qvm_config.as_ref() {
            Some(raw) if raw.is_relative() => def.image_dir.join(raw),
            Some(raw) => raw.clone(),
            None => return, // No config → no orphan possible to slay.
        };

        // Order: qvm first (so it stops reading from the loopback),
        // then loopback (so it stops holding rootfs.img open).
        Self::slay_qvm_for_vm(&qvm_config);
        std::thread::sleep(Duration::from_millis(100));
        Self::slay_loopbacks_for_vm(name);
        std::thread::sleep(Duration::from_millis(100));
        self.vm_name = Some(name.to_string());
    }

    fn start(&mut self, name: &str, def: &VmDefinition) -> Result<VmHandle, RunnerError> {
        let raw_path = def.qvm_config.as_ref().ok_or_else(|| {
            RunnerError::Config(format!("VM {name}: qvm_config not set"))
        })?;

        // Relative paths resolve against image_dir (follows active bank symlink)
        let qvm_config = if raw_path.is_relative() {
            def.image_dir.join(raw_path)
        } else {
            raw_path.clone()
        };

        if !qvm_config.exists() {
            return Err(RunnerError::Config(format!(
                "VM {name}: qvm config not found: {}",
                qvm_config.display()
            )));
        }

        // The slay dance moved to `prepare_for_launch` (called by
        // VmManager before the pre-launch verify so EBUSY doesn't
        // fire on `rootfs.img`). vm_name is set there too; we keep
        // this as belt-and-suspenders in case `start` is invoked
        // outside the VmManager path (e.g. direct tests).
        if self.vm_name.is_none() {
            self.vm_name = Some(name.to_string());
        }

        // Rootfs: per-VM prefix lets multiple VMs run concurrently with
        // distinct /dev/qvmdisk-vmX0 nodes.
        if let Some(rootfs) = def.rootfs_path() {
            if rootfs.exists() {
                let prefix = Self::rootfs_prefix(name);
                self.spawn_loopback(&prefix, &rootfs)?;
            } else {
                tracing::warn!("VM {name}: rootfs not found: {} — skipping loopback", rootfs.display());
            }
        }

        // Extra disks (data, swap, …) from def.disks. Uses a distinct
        // `qvm-{role}-{vm}` prefix so io-blk doesn't see name-prefix
        // collisions with the rootfs's `qvmdisk-{vm}` namespace.
        for disk in &def.disks {
            if !disk.path.exists() {
                tracing::warn!("VM {name}: extra disk {role} not found: {path} — skipping",
                    role = disk.role, path = disk.path.display());
                continue;
            }
            let prefix = Self::extra_prefix(name, &disk.role);
            self.spawn_loopback(&prefix, &disk.path)?;
            let device = Self::extra_device(name, &disk.role);
            tracing::info!(vm = %name, role = %disk.role, device, path = %disk.path.display(), "extra disk attached");
        }

        // Materialise a per-launch qvm.conf that carries the VM's
        // vm_id on the kernel cmdline. Source config lives in the bank
        // (operator-shipped); we copy + inject so the bank stays
        // immutable and the rootfs init script can read VHSM_VM_ID
        // from procnto's env. Per the QNX mkifs env-var convention,
        // KEY=value tokens on cmdline become env vars for user-mode
        // children. See guest-vm-spec spec §11.4-bis / Phase 12c.
        let launch_config = match build_launch_qvm_config(&qvm_config, name) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    vm = %name,
                    error = %e,
                    "qvm.conf vm_id injection failed; launching with template as-is (vhsm-daemon will skip)"
                );
                qvm_config.clone()
            }
        };

        // Launch qvm with the (possibly injected) config file
        tracing::info!("starting qvm for {name}: @{}", launch_config.display());
        let child = Command::new("qvm")
            .arg(format!("@{}", launch_config.display()))
            .spawn()
            .map_err(|e| RunnerError::ProcessFailed(format!("qvm: {e}")))?;

        let pid = child.id();
        self.qvm_child = Some(child);

        tracing::info!("VM {name} started (qvm pid: {pid})");
        Ok(VmHandle {
            name: name.to_string(),
            pid: Some(pid),
        })
    }

    fn stop(&mut self, _handle: &VmHandle) -> Result<(), RunnerError> {
        if let Some(ref mut child) = self.qvm_child {
            Self::kill_child(child);
        }
        Ok(())
    }

    fn is_running(&self, handle: &VmHandle) -> bool {
        if let Some(pid) = handle.pid {
            unsafe { libc::kill(pid as i32, 0) == 0 }
        } else {
            false
        }
    }

    fn wait(&mut self, _handle: &VmHandle) -> Result<Option<i32>, RunnerError> {
        if let Some(ref mut child) = self.qvm_child {
            let status = child.wait()?;
            return Ok(status.code());
        }
        Err(RunnerError::ProcessFailed("qvm process not found".into()))
    }

    fn cleanup(&mut self) {
        // Kill qvm first so it stops accessing /dev/<prefix>N before we
        // tear down devb-loopback under it.
        if let Some(ref mut child) = self.qvm_child {
            Self::kill_child(child);
        }
        self.qvm_child = None;

        // Held Children point at the spawn-parents (daemons double-fork);
        // kill_child on them is a no-op but reaps the zombie. The real
        // daemons live in loopback_pids.
        for mut child in self.loopback_children.drain(..) {
            Self::kill_child(&mut child);
        }

        // Resolve any daemons we missed at start() (find raced with
        // daemonize) by re-scanning by VM name.
        let mut pids = std::mem::take(&mut self.loopback_pids);
        if let Some(ref vm) = self.vm_name {
            for pid in Self::find_loopback_pids(vm) {
                if !pids.contains(&pid) {
                    pids.push(pid);
                }
            }
        }
        for pid in pids {
            tracing::info!(vm = ?self.vm_name, pid, "killing devb-loopback daemon");
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM); }
            std::thread::sleep(Duration::from_millis(100));
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL); }
        }
        self.vm_name = None;
    }
}

impl Drop for QnxRunner {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Read `template` qvm.conf, inject `VHSM_VM_ID=<vm_name>` into its
/// cmdline if not already present, write to a /tmp file, return the
/// path. The bank's qvm.conf stays untouched so subsequent installs
/// see it as the operator delivered it.
///
/// If the cmdline already contains `VHSM_VM_ID=`, the template is
/// returned as-is (operator override; we don't second-guess).
fn build_launch_qvm_config(template: &std::path::Path, vm_name: &str) -> std::io::Result<std::path::PathBuf> {
    let content = std::fs::read_to_string(template)?;
    if content.contains("VHSM_VM_ID=") {
        return Ok(template.to_path_buf());
    }
    let injected = inject_vhsm_vm_id(&content, vm_name);
    let out = std::env::temp_dir().join(format!("qvm-{vm_name}-launch.conf"));
    std::fs::write(&out, injected)?;
    Ok(out)
}

/// Append ` VHSM_VM_ID=<vm_name>` to the `cmdline "..."` line of a
/// qvm.conf-shaped text. If there's no `cmdline` line we leave the
/// content as-is (the rootfs init will then skip vhsm-daemon — same
/// safe default as the no-qvm.conf-write path).
fn inject_vhsm_vm_id(content: &str, vm_name: &str) -> String {
    let mut out = String::with_capacity(content.len() + 32);
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("cmdline ") || trimmed.starts_with("cmdline\t") {
            // Inject before the closing quote of the cmdline string.
            if let Some(close) = line.rfind('"') {
                if let Some(open) = line.find('"') {
                    if open < close {
                        out.push_str(&line[..close]);
                        out.push(' ');
                        out.push_str("VHSM_VM_ID=");
                        out.push_str(vm_name);
                        out.push_str(&line[close..]);
                        out.push('\n');
                        continue;
                    }
                }
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_appends_before_closing_quote() {
        let src = r#"# preamble
memory 256M
cmdline "console=ttyAMA0,115200 root=/dev/vda"
rootfs "/path/to/rootfs"
"#;
        let out = inject_vhsm_vm_id(src, "vm1");
        assert!(out.contains(r#"cmdline "console=ttyAMA0,115200 root=/dev/vda VHSM_VM_ID=vm1""#));
        // Other lines untouched.
        assert!(out.contains("memory 256M"));
        assert!(out.contains(r#"rootfs "/path/to/rootfs""#));
    }

    #[test]
    fn inject_leaves_non_cmdline_lines_alone() {
        let src = "memory 256M\nrootfs \"/x\"\n";
        let out = inject_vhsm_vm_id(src, "vm2");
        assert_eq!(out, "memory 256M\nrootfs \"/x\"\n");
    }

    #[test]
    fn inject_preserves_existing_cmdline_tokens() {
        // Existing args like console=ttyAMA0 should still be there.
        let src = "cmdline \"a=1 b=2 c=3\"\n";
        let out = inject_vhsm_vm_id(src, "vm9");
        assert!(out.contains("a=1 b=2 c=3 VHSM_VM_ID=vm9"));
    }

    #[test]
    fn inject_handles_indented_cmdline() {
        let src = "    cmdline \"foo=bar\"\n";
        let out = inject_vhsm_vm_id(src, "vm1");
        assert!(out.contains("foo=bar VHSM_VM_ID=vm1"));
    }

    #[test]
    fn build_launch_skips_when_vhsm_vm_id_already_present() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("qvm.conf");
        std::fs::write(&path, "cmdline \"foo=bar VHSM_VM_ID=preset\"\n").unwrap();
        let out = build_launch_qvm_config(&path, "vm9").unwrap();
        // Should return the template path unchanged, not a /tmp copy.
        assert_eq!(out, path);
    }
}
