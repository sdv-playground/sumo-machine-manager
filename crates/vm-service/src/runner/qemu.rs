/// QEMU runner — translates VM definitions into QEMU command lines
/// and manages host-side processes (ivshmem-server, simulators).

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use crate::config::*;
use crate::ivshmem::{self, HostProcess, IvshmemSockets};
use super::*;

pub struct QemuRunner {
    /// Override QEMU binary path. If None, resolved from arch.
    qemu_bin: Option<PathBuf>,
    /// Path to ivshmem-server binary.
    ivshmem_bin: PathBuf,
    /// Use KVM if available.
    try_kvm: bool,
    /// Running host-side processes.
    host_processes: Vec<HostProcess>,
    /// Socket paths to clean up.
    sockets: Vec<PathBuf>,
    /// Cancel flags for Rust simulator threads (time, CAN bridge).
    /// Health used to be in this list — now `VmManager` reads heartbeat
    /// directly via `HeartbeatDevice` over the configured `DeviceTransport`.
    sim_cancellers: Vec<Arc<AtomicBool>>,
}

impl QemuRunner {
    pub fn new() -> Self {
        Self {
            qemu_bin: None,
            ivshmem_bin: PathBuf::from("ivshmem-server"),
            try_kvm: true,
            host_processes: Vec::new(),
            sockets: Vec::new(),
            sim_cancellers: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn qemu_bin(mut self, path: impl Into<PathBuf>) -> Self {
        self.qemu_bin = Some(path.into());
        self
    }

    pub fn ivshmem_bin(mut self, path: impl Into<PathBuf>) -> Self {
        self.ivshmem_bin = path.into();
        self
    }

    #[allow(dead_code)]
    pub fn try_kvm(mut self, enable: bool) -> Self {
        self.try_kvm = enable;
        self
    }

    fn resolve_qemu_bin(&self, arch: Arch) -> String {
        self.qemu_bin.as_ref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| arch.qemu_binary().to_string())
    }

    /// Start the Rust time simulator on a background thread.
    fn start_time_sim(&mut self, vm_name: &str) -> Result<(), RunnerError> {
        use vm_devices::transport::ivshmem::{IvshmemSharedMemory, NullDoorbell};
        use vm_devices::clock::system::SystemClock;
        use vm_devices::time::TimeSim;

        let shm = IvshmemSharedMemory::open_by_name(vm_name, "time")
            .map_err(|e| RunnerError::ProcessFailed(format!("time shm: {e}")))?;
        let clock = Arc::new(SystemClock::new());
        let mut sim = TimeSim::new(shm, NullDoorbell, clock)
            .with_sync_guest_id(1)
            .with_min_adjust_interval(std::time::Duration::from_secs(2));

        // Init header immediately
        sim.init();

        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_clone = cancel.clone();
        std::thread::Builder::new()
            .name("time-sim".into())
            .spawn(move || sim.run(&cancel_clone))
            .map_err(|e| RunnerError::ProcessFailed(format!("time-sim thread: {e}")))?;
        self.sim_cancellers.push(cancel);
        tracing::info!("started Rust time-sim for {vm_name}");
        Ok(())
    }

    /// Start the Rust CAN bridge on a background thread.
    fn start_can_bridge(&mut self, vm_name: &str, index: u8, ifname: &str) -> Result<(), RunnerError> {
        use vm_devices::transport::ivshmem::{IvshmemSharedMemory, connect_ivshmem_server, NullDoorbell};
        use vm_devices::transport::Doorbell;
        use vm_devices::can::{CanBridge, socketcan::SocketCanBackend};

        let label = format!("can{index}");
        let shm = IvshmemSharedMemory::open_by_name(vm_name, &label)
            .map_err(|e| RunnerError::ProcessFailed(format!("CAN shm: {e}")))?;
        let backend = SocketCanBackend::open(ifname)
            .map_err(|e| RunnerError::ProcessFailed(format!("CAN socket {ifname}: {e}")))?;

        // Connect to ivshmem-server to get the guest's eventfd for doorbell.
        // This wakes guest NAPI when we write frames to the RX ring.
        let sock_path = crate::ivshmem::socket_path(vm_name, &label);
        let doorbell: Box<dyn Doorbell> = match connect_ivshmem_server(&sock_path) {
            Ok(db) => {
                tracing::info!("CAN bridge can{index}: got guest doorbell from ivshmem-server");
                Box::new(db)
            }
            Err(e) => {
                tracing::warn!("CAN bridge can{index}: no doorbell ({e}), RX may be delayed");
                Box::new(NullDoorbell)
            }
        };

        let mut bridge = CanBridge::new(shm, doorbell, backend);
        bridge.init();

        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_clone = cancel.clone();
        std::thread::Builder::new()
            .name(format!("can-bridge-{index}"))
            .spawn(move || bridge.run(&cancel_clone))
            .map_err(|e| RunnerError::ProcessFailed(format!("can-bridge thread: {e}")))?;
        self.sim_cancellers.push(cancel);
        tracing::info!("started Rust CAN bridge for {vm_name} can{index} <-> {ifname}");
        Ok(())
    }

    /// Build the QEMU command line from a VM definition.
    fn build_qemu_args(
        &self,
        name: &str,
        def: &VmDefinition,
        ivshmem_sockets: &IvshmemSockets,
    ) -> Result<Vec<String>, RunnerError> {
        let arch = def.arch();
        let mut args: Vec<String> = Vec::new();
        let use_kvm = self.try_kvm && arch.kvm_available();

        let cpu = if use_kvm {
            "host".to_string()
        } else {
            def.cpu_model.clone()
                .unwrap_or_else(|| arch.default_cpu().to_string())
        };

        args.extend_from_slice(&[
            self.resolve_qemu_bin(arch),
            "-machine".into(), arch.machine_type().into(),
            "-cpu".into(), cpu,
        ]);

        if use_kvm {
            args.push("-enable-kvm".into());
        }

        args.extend_from_slice(&[
            "-m".into(), format!("{}M", def.ram_mb),
            "-smp".into(), def.cpus.to_string(),
            "-nographic".into(),
            "-no-reboot".into(),
        ]);

        // QMP socket for vCPU pause/resume (simulation stepping)
        let qmp_sock = format!("/tmp/vm-svc-{name}-qmp.sock");
        args.extend_from_slice(&[
            "-qmp".into(),
            format!("unix:{qmp_sock},server,nowait"),
        ]);

        // Boot mode depends on OS type
        let is_qnx = def.os_type == crate::config::OsType::Qnx;

        if is_qnx {
            // QNX: IFS boot disk + QNX6 root filesystem as separate drives.
            // Boot disk (IFS): loaded by BIOS/IPL into RAM.
            // Root filesystem: mounted at / by IFS startup script.
            if let Some(boot) = def.kernel_path() {
                args.extend_from_slice(&[
                    "-drive".into(),
                    format!("file={},format=raw", boot.display()),
                ]);
            }
            if let Some(rootfs) = def.rootfs_path() {
                args.extend_from_slice(&[
                    "-drive".into(),
                    format!("file={},format=raw", rootfs.display()),
                ]);
            }

            // Policy partition (AUTH-ARCH-001 §4) — read-only image
            // mounted at /etc/sumo/policy by the guest's startup.
            if let Some(policy) = def.policy_path() {
                args.extend_from_slice(&[
                    "-drive".into(),
                    format!("file={},format=raw,readonly=on", policy.display()),
                ]);
            }

            // Extra disks (data partition, etc.)
            for disk in &def.disks {
                args.extend_from_slice(&[
                    "-drive".into(),
                    format!("file={},format=raw", disk.path.display()),
                ]);
            }

        } else {
            // Linux: kernel + rootfs + cmdline

            if let Some(kernel_path) = def.kernel_path() {
                args.extend_from_slice(&[
                    "-kernel".into(),
                    kernel_path.to_string_lossy().into_owned(),
                ]);
            }

            let mut cmdline_parts: Vec<String> = vec![
                "root=/dev/vda".into(),
                "rw".into(),
                format!("console={}", arch.console_device()),
                "earlycon".into(),
                "no_console_suspend".into(),
                "pm_debug_messages".into(),
            ];

            let can_count = def.can_count();
            if can_count > 0 {
                cmdline_parts.push("vcan_shm.backend=ivshmem".into());
                cmdline_parts.push(format!("vcan_shm.num_devices={can_count}"));
            }

            if let Some(ref extra) = def.extra_cmdline {
                cmdline_parts.push(extra.clone());
            }
            // Extra disks (data, swap — from def.disks, not banked)
            let blk_device = arch.virtio_device("blk");
            let mut disk_args: Vec<Vec<String>> = Vec::new();

            for disk in &def.disks {
                let drive_id = format!("hd_{}", disk.role);
                let ro = if disk.readonly { ",readonly=on" } else { "" };
                disk_args.push(vec![
                    "-drive".into(),
                    format!("file={},format=raw,if=none,id={drive_id}{ro}", disk.path.display()),
                    "-device".into(),
                    format!("{blk_device},drive={drive_id}"),
                ]);

                if disk.role == "swap" {
                    cmdline_parts.push("resume=/dev/vdc".into());
                }
            }

            // Policy partition (AUTH-ARCH-001 §4) — read-only image.
            // Appended to disk_args so it shares the same ordering
            // logic as data/swap disks. The guest's init mounts it
            // at /etc/sumo/policy/ from whichever virtio-blk node it
            // enumerates as.
            if let Some(policy) = def.policy_path() {
                disk_args.push(vec![
                    "-drive".into(),
                    format!(
                        "file={},format=raw,if=none,id=hd_policy,readonly=on",
                        policy.display()
                    ),
                    "-device".into(),
                    format!("{blk_device},drive=hd_policy"),
                ]);
            }

            let rootfs = def.rootfs_path()
                .ok_or_else(|| RunnerError::Config(format!(
                    "{name}: no rootfs image configured (set images.rootfs in config)"
                )))?;
            let rootfs_args = vec![
                "-drive".into(),
                format!("file={},format=raw,if=none,id=hd_rootfs", rootfs.display()),
                "-device".into(),
                format!("{blk_device},drive=hd_rootfs"),
            ];

            if arch.reverse_disk_order() {
                for disk in &disk_args {
                    args.extend_from_slice(disk);
                }
                args.push("-device".into());
                args.push(arch.virtio_device("rng"));
                args.extend_from_slice(&rootfs_args);
            } else {
                args.extend_from_slice(&rootfs_args);
                args.push("-device".into());
                args.push(arch.virtio_device("rng"));
                for disk in &disk_args {
                    args.extend_from_slice(disk);
                }
            }

            // Append kernel cmdline
            let cmdline = cmdline_parts.join(" ");
            args.extend_from_slice(&["-append".into(), cmdline]);
        } // end Linux boot

        // Network devices (shared for both OS types — spec mandates virtio-net)
        let networks: Vec<_> = def.devices.iter()
            .filter(|d| matches!(d, DeviceConfig::Network { .. }))
            .collect();
        let net_device = arch.virtio_device("net");

        let net_iter: Box<dyn Iterator<Item = (usize, &&DeviceConfig)>> = if arch.reverse_disk_order() {
            Box::new(networks.iter().enumerate().rev())
        } else {
            Box::new(networks.iter().enumerate())
        };

        let mut net_idx = 0;
        for (i, dev) in net_iter {
            if let DeviceConfig::Network { mac, ssh_port } = dev {
                let id = format!("net{net_idx}");
                let mut netdev = format!("user,id={id}");
                if let Some(port) = ssh_port {
                    netdev.push_str(&format!(",hostfwd=tcp::{port}-:22"));
                }
                if i > 0 {
                    let subnet = i + 2;
                    netdev.push_str(&format!(",net=10.0.{subnet}.0/24,dhcpstart=10.0.{subnet}.15"));
                }
                args.extend_from_slice(&["-netdev".into(), netdev]);
                let mut dev_str = format!("{net_device},netdev={id}");
                if let Some(m) = mac {
                    dev_str.push_str(&format!(",mac={m}"));
                }
                args.extend_from_slice(&["-device".into(), dev_str]);
                net_idx += 1;
            }
        }

        // Bridge NICs (private vHSM network). Each guest's IP on the
        // bridge is the host vHSM daemon's identity for that guest, so
        // the MAC is mandatory: dnsmasq pins MAC → IP via static lease.
        for dev in &def.devices {
            if let DeviceConfig::Bridge { bridge, mac } = dev {
                let id = format!("net{net_idx}");
                args.extend_from_slice(&[
                    "-netdev".into(),
                    format!("bridge,id={id},br={bridge}"),
                    "-device".into(),
                    format!("{net_device},netdev={id},mac={mac}"),
                ]);
                net_idx += 1;
            }
        }

        // ivshmem devices (time, health, CAN)
        for dev in &def.devices {
            if !dev.needs_ivshmem() { continue; }
            match dev {
                DeviceConfig::Time { .. } => {
                    if let Some(sock) = &ivshmem_sockets.time {
                        args.extend_from_slice(&[
                            "-chardev".into(),
                            format!("socket,path={},id=ivshmem_time", sock.display()),
                            "-device".into(),
                            "ivshmem-doorbell,chardev=ivshmem_time,vectors=2".into(),
                        ]);
                    }
                }
                DeviceConfig::Health { .. } => {
                    if let Some(sock) = &ivshmem_sockets.health {
                        args.extend_from_slice(&[
                            "-chardev".into(),
                            format!("socket,path={},id=ivshmem_health", sock.display()),
                            "-device".into(),
                            "ivshmem-doorbell,chardev=ivshmem_health,vectors=2".into(),
                        ]);
                    }
                }
                _ => {}
            }
        }

        // CAN interfaces in reverse order (so can0 gets lowest PCI address)
        let mut can_devs: Vec<(u8, &Option<String>)> = Vec::new();
        for dev in &def.devices {
            if let DeviceConfig::Can { index, interface, .. } = dev {
                if dev.needs_ivshmem() {
                    can_devs.push((*index, interface));
                }
            }
        }
        can_devs.sort_by(|a, b| b.0.cmp(&a.0));
        for (idx, _) in &can_devs {
            if let Some(sock) = ivshmem_sockets.can.get(idx) {
                args.extend_from_slice(&[
                    "-chardev".into(),
                    format!("socket,path={},id=ivshmem_can{idx}", sock.display()),
                    "-device".into(),
                    format!("ivshmem-doorbell,chardev=ivshmem_can{idx},vectors=2"),
                ]);
            }
        }

        Ok(args)
    }
}

impl VmRunner for QemuRunner {
    fn start(&mut self, name: &str, def: &VmDefinition) -> Result<VmHandle, RunnerError> {
        let _sim_dir = def.sim_dir.as_deref();
        let mut ivshmem = IvshmemSockets::default();

        // Start ivshmem servers for devices that need shared memory
        for dev in &def.devices {
            if !dev.needs_ivshmem() { continue; }
            match dev {
                DeviceConfig::Can { index, .. } => {
                    let sock = ivshmem::start_ivshmem(
                        name, &format!("can{index}"), "1M",
                        &self.ivshmem_bin, &mut self.host_processes, &mut self.sockets,
                    )?;
                    ivshmem.can.insert(*index, sock);
                }
                DeviceConfig::Health { .. } => {
                    let sock = ivshmem::start_ivshmem(
                        name, "health", "4K",
                        &self.ivshmem_bin, &mut self.host_processes, &mut self.sockets,
                    )?;
                    ivshmem.health = Some(sock);
                }
                DeviceConfig::Time { .. } => {
                    let sock = ivshmem::start_ivshmem(
                        name, "time", "4K",
                        &self.ivshmem_bin, &mut self.host_processes, &mut self.sockets,
                    )?;
                    ivshmem.time = Some(sock);
                }
                _ => {}
            }
        }

        // Start Rust device simulators (health, time) or write magic headers
        for dev in &def.devices {
            if !dev.needs_ivshmem() { continue; }
            match dev {
                DeviceConfig::Health { .. } => {
                    // Heartbeat / power channels are owned by VmManager via
                    // the DeviceTransport — nothing to start here. The
                    // ivshmem region's host-side mmap is created by
                    // `IvshmemTransport::open_channel` before QEMU launches,
                    // so QEMU's `-device ivshmem-plain,memdev=...` finds the
                    // file ready when it tries to mmap it.
                }
                DeviceConfig::Time { .. } => {
                    self.start_time_sim(name)?;
                }
                DeviceConfig::Can { .. } => {
                    // CAN bridges start after QEMU launches (need guest peer for doorbell)
                }
                _ => {}
            }
        }

        // The HSM service (vhsm-ssd) is managed by the orchestrator;
        // each guest reaches it over the private vbr-vhsm bridge — see
        // the Bridge device branch in build_qemu_args().

        // Small delay for processes to initialize
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Build and launch QEMU
        let args = self.build_qemu_args(name, def, &ivshmem)?;

        let child = Command::new(&args[0])
            .args(&args[1..])
            .spawn()
            .map_err(|e| RunnerError::ProcessFailed(format!("QEMU: {e}")))?;

        let pid = child.id();
        self.host_processes.push(HostProcess {
            name: "qemu".to_string(),
            child,
        });

        // Start CAN bridges now that QEMU is connected to ivshmem-server
        // (we need the guest peer's eventfd for the doorbell)
        std::thread::sleep(std::time::Duration::from_millis(500));
        for dev in &def.devices {
            if let DeviceConfig::Can { index, interface, .. } = dev {
                let ifname = interface.as_deref().unwrap_or("vcan1");
                self.start_can_bridge(name, *index, ifname)?;
            }
        }

        Ok(VmHandle { name: name.to_string(), pid: Some(pid) })
    }

    fn wait(&mut self, handle: &VmHandle) -> Result<Option<i32>, RunnerError> {
        if let Some(pid) = handle.pid {
            for proc in &mut self.host_processes {
                if proc.name == "qemu" && proc.pid() == pid {
                    let status = proc.child.wait()?;
                    return Ok(status.code());
                }
            }
        }
        Err(RunnerError::ProcessFailed("QEMU process not found".into()))
    }

    fn stop(&mut self, handle: &VmHandle) -> Result<(), RunnerError> {
        if let Some(pid) = handle.pid {
            for proc in &mut self.host_processes {
                if proc.name == "qemu" && proc.pid() == pid {
                    let _ = proc.child.kill();
                    let _ = proc.child.wait();
                    break;
                }
            }
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

    fn cleanup(&mut self) {
        // Signal Rust simulator threads to stop
        for cancel in &self.sim_cancellers {
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        self.sim_cancellers.clear();

        for proc in self.host_processes.iter_mut().rev() {
            let _ = proc.child.kill();
            let _ = proc.child.wait();
        }
        self.host_processes.clear();

        for sock in &self.sockets {
            let _ = std::fs::remove_file(sock);
        }
        self.sockets.clear();
    }

    fn graceful_shutdown(&mut self, handle: &VmHandle, _timeout: Duration) -> Result<(), RunnerError> {
        // Heartbeat-driven graceful shutdown is now `VmManager`'s job —
        // it sends `PowerCommand::Shutdown` over the device transport before
        // calling stop(). The runner just force-kills if VmManager arrives here.
        self.stop(handle)
    }
}

impl Drop for QemuRunner {
    fn drop(&mut self) {
        self.cleanup();
    }
}
