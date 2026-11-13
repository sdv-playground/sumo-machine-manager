/// QEMU runner — translates VM definitions into QEMU command lines
/// and manages host-side processes (ivshmem-server, simulators).
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::config::*;
use crate::ivshmem::{self, HostProcess, IvshmemSockets};

// QNX 7.1's devnp-virtio driver does not reliably handle all optional
// virtio-net features advertised by QEMU (PCI on x86_64, mmio on aarch64; the
// properties are the device's, not the transport's).  In
// particular, leaving these at their QEMU defaults can wedge the control
// queue while the guest is programming its MAC filter, leaving the guest
// NIC up but unusable.  Keep the control virtqueue enabled: QNX needs it for
// the driver to start correctly.
const QNX_VIRTIO_NET_FEATURES: &str =
    ",event_idx=off,mrg_rxbuf=off,indirect_desc=off,rx_queue_size=1024,ctrl_rx=off,ctrl_rx_extra=off,ctrl_vlan=off,ctrl_mac_addr=off,ctrl_guest_offloads=off";

fn virtio_net_compat_features(os_type: OsType) -> &'static str {
    if matches!(os_type, OsType::Qnx) {
        QNX_VIRTIO_NET_FEATURES
    } else {
        ""
    }
}

/// The `,prop=…` suffix for every NIC: the VM's `virtio_net_features`
/// override when set, otherwise the guest profile's built-in set.
fn virtio_net_features(def: &VmDefinition) -> String {
    match def.virtio_net_features.as_deref().map(str::trim) {
        Some("") => String::new(),
        Some(features) => format!(",{}", features.trim_matches(',')),
        None => virtio_net_compat_features(def.os_type).to_string(),
    }
}

/// Whether to run with KVM: `auto` follows the runner's `try_kvm` and the
/// host; `kvm` insists (a config error when the host cannot); `tcg` never.
/// An explicit per-VM `accel: kvm` wins over the runner's `try_kvm(false)`:
/// the VM's config is the more specific choice.
fn resolve_kvm(
    vm: &str,
    accel: Accel,
    try_kvm: bool,
    kvm_available: bool,
) -> Result<bool, RunnerError> {
    match accel {
        Accel::Auto => Ok(try_kvm && kvm_available),
        Accel::Tcg => Ok(false),
        Accel::Kvm if kvm_available => Ok(true),
        Accel::Kvm => Err(RunnerError::Config(format!(
            "{vm}: accel: kvm, but KVM is not available for this guest arch on this host"
        ))),
    }
}

/// QEMU's `virt` machine has 32 virtio-mmio transports (buses 0–31).
const VIRT_MMIO_SLOTS: u8 = 32;

/// Fixed virtio-mmio placement for QNX aarch64 guests: every device names its
/// bus, and a missing, out-of-range or doubly used slot is a config error. A
/// device on the wrong slot is not an error the guest reports — it just never
/// finds that disk (e.g. no sumo-config, so no network config).
struct MmioSlots<'a> {
    vm: &'a str,
    used: Vec<(u8, String)>,
}

impl<'a> MmioSlots<'a> {
    fn new(vm: &'a str) -> Self {
        Self {
            vm,
            used: Vec::new(),
        }
    }

    fn claim(&mut self, slot: Option<u8>, what: &str) -> Result<u8, RunnerError> {
        let vm = self.vm;
        let slot = slot.ok_or_else(|| {
            RunnerError::Config(format!(
                "{vm}: {what} needs a `slot` (virtio-mmio bus) on a QNX aarch64 guest"
            ))
        })?;
        if slot >= VIRT_MMIO_SLOTS {
            return Err(RunnerError::Config(format!(
                "{vm}: {what} slot {slot} is out of range (0-{})",
                VIRT_MMIO_SLOTS - 1
            )));
        }
        if let Some((_, owner)) = self.used.iter().find(|(used, _)| *used == slot) {
            return Err(RunnerError::Config(format!(
                "{vm}: {what} and {owner} both use virtio-mmio slot {slot}"
            )));
        }
        self.used.push((slot, what.to_string()));
        Ok(slot)
    }
}

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

impl Default for QemuRunner {
    fn default() -> Self {
        Self::new()
    }
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
        self.qemu_bin
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| arch.qemu_binary().to_string())
    }

    /// Start the Rust time simulator on a background thread.
    fn start_time_sim(&mut self, vm_name: &str) -> Result<(), RunnerError> {
        use vm_devices::clock::system::SystemClock;
        use vm_devices::time::TimeSim;
        use vm_devices::transport::ivshmem::{IvshmemSharedMemory, NullDoorbell};

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
    fn start_can_bridge(
        &mut self,
        vm_name: &str,
        index: u8,
        ifname: &str,
    ) -> Result<(), RunnerError> {
        use vm_devices::can::{socketcan::SocketCanBackend, CanBridge};
        use vm_devices::transport::ivshmem::{
            connect_ivshmem_server, IvshmemSharedMemory, NullDoorbell,
        };
        use vm_devices::transport::Doorbell;

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
        let use_kvm = resolve_kvm(name, def.accel, self.try_kvm, arch.kvm_available())?;
        self.build_qemu_args_with_kvm(name, def, ivshmem_sockets, use_kvm)
    }

    fn build_qemu_args_with_kvm(
        &self,
        name: &str,
        def: &VmDefinition,
        ivshmem_sockets: &IvshmemSockets,
        use_kvm: bool,
    ) -> Result<Vec<String>, RunnerError> {
        let arch = def.arch();
        let is_qnx = def.os_type == crate::config::OsType::Qnx;
        // guest-vm-qnx's arm64 image: an ELF IFS loaded with -kernel, every
        // device on the fixed virtio-mmio slot its device tree expects.
        let qnx_mmio = is_qnx && arch == Arch::Aarch64;
        let mut mmio_slots = MmioSlots::new(name);
        let mut args: Vec<String> = Vec::new();

        // A configured model is an explicit compatibility choice and applies
        // with KVM as well as TCG. Keep host passthrough as the default when
        // KVM is available; otherwise use the architecture default (for a QNX
        // aarch64 guest under TCG, the cortex-a57 its IFS is qualified on).
        let cpu = def.cpu_model.clone().unwrap_or_else(|| {
            if use_kvm {
                "host".to_string()
            } else if qnx_mmio {
                "cortex-a57".to_string()
            } else {
                arch.default_cpu().to_string()
            }
        });
        let machine = def
            .machine
            .clone()
            .unwrap_or_else(|| arch.machine_type().to_string());

        args.extend_from_slice(&[
            self.resolve_qemu_bin(arch),
            "-machine".into(),
            machine,
            "-cpu".into(),
            cpu,
        ]);

        if use_kvm {
            args.push("-enable-kvm".into());
        }

        // QNX 7.1's GICv3 init traps as NISV MMIO under arm64 KVM; the
        // patched QEMU that relays it to the in-kernel vGIC only works while
        // sibling vCPUs are quiesced, so an unfixed guest hangs with more than
        // one vCPU. The count stays the config's: a guest or QEMU with the GIC
        // fix runs SMP, and `accel: tcg` keeps several vCPUs on any host.
        if qnx_mmio && use_kvm && def.cpus > 1 {
            tracing::warn!(
                vm = name,
                cpus = def.cpus,
                "QNX aarch64 under KVM with more than 1 vCPU: needs a guest or QEMU \
                 with the GICv3 NISV fix, else set cpus: 1 or accel: tcg"
            );
        }
        args.extend_from_slice(&[
            "-m".into(),
            format!("{}M", def.ram_mb),
            "-smp".into(),
            def.cpus.to_string(),
        ]);
        if let Some(serial_log_path) = &def.serial_log {
            let serial_log = serial_log_path.to_string_lossy();
            if !serial_log_path.is_absolute()
                || serial_log.is_empty()
                || serial_log
                    .chars()
                    .any(|character| matches!(character, ',' | '\n' | '\r'))
            {
                return Err(RunnerError::Config(
                    "serial_log must be an absolute non-empty path without commas or newlines"
                        .into(),
                ));
            }
            args.extend_from_slice(&[
                "-display".into(),
                "none".into(),
                "-monitor".into(),
                "none".into(),
                "-serial".into(),
                format!("file:{serial_log}"),
            ]);
        } else {
            args.push("-nographic".into());
        }
        args.push("-no-reboot".into());

        // QMP socket for vCPU pause/resume (simulation stepping)
        let qmp_sock = format!("/tmp/vm-svc-{name}-qmp.sock");
        args.extend_from_slice(&["-qmp".into(), format!("unix:{qmp_sock},server,nowait")]);

        // Boot mode depends on OS type
        if is_qnx && arch == Arch::X86_64 {
            // QNX x86_64 (QEMU) boots a BIOS+IPL-wrapped disk (boot.img) and
            // mounts its QNX6 rootfs (+ per-bank partitions + extra disks) as
            // additional disks, laid out in order: boot(0), rootfs(1),
            // partitions, disks.
            //
            // Every disk is a `virtio-blk-pci` — the guest IFS runs
            // `devb-virtio` (the same block stack as the rig), which has no port
            // ceiling, so all bank partitions + persistent disks fit. SeaBIOS
            // boots boot.img via `bootindex=0`; the guest enumerates the disks
            // /dev/hd0.. in attach order (boot=hd0, rootfs=hd1, partitions hd2..).
            //
            // (path, read_only). Boot + rootfs are IVD-signed, immutable firmware,
            // so they are attached READ-ONLY — mirroring the rig, where the QNX6
            // rootfs mounts read-only. A writable rootfs lets the guest mutate the
            // host image, so it drifts from the signed manifest and fail-closed
            // pre-launch verify refuses it on the next boot. Per-bank partitions and
            // extra disks carry their own `readonly` flag, honoured here exactly
            // like the Linux path (writable data disks stay rw).
            let mut qnx_disks: Vec<(PathBuf, bool)> = Vec::new();
            if let Some(boot) = def.kernel_path() {
                qnx_disks.push((boot, true));
            }
            if let Some(rootfs) = def.rootfs_path() {
                qnx_disks.push((rootfs, true));
            }
            for part in &def.partitions {
                let path = def.partition_path(part);
                if path.exists() {
                    qnx_disks.push((path, part.readonly));
                }
            }
            for disk in &def.disks {
                qnx_disks.push((disk.path.clone(), disk.readonly));
            }
            for (i, (path, read_only)) in qnx_disks.iter().enumerate() {
                let id = format!("qnxd{i}");
                let bootidx = if i == 0 { ",bootindex=0" } else { "" };
                let ro = if *read_only { ",readonly=on" } else { "" };
                args.extend_from_slice(&[
                    "-drive".into(),
                    format!("file={},format=raw,if=none,id={id}{ro}", path.display()),
                    "-device".into(),
                    format!("virtio-blk-pci,drive={id}{bootidx}"),
                ]);
            }
        } else if qnx_mmio {
            // QNX aarch64 (QEMU, guest-vm-qnx's arm64 image): boot.img is an
            // ELF IFS loaded with -kernel, not a disk. Every block device sits
            // on the virtio-mmio slot the image's device tree and layers.conf
            // expect (rootfs 31 by default; partitions and disks name theirs).
            // Boot + rootfs are read-only as on x86_64; partitions and disks
            // carry their own flag. A partition whose image is absent is not
            // attached, leaving its slot empty, exactly like x86_64.
            let boot = def.kernel_path().ok_or_else(|| {
                RunnerError::Config(format!(
                    "{name}: QNX aarch64 boots its IFS with -kernel; set images.kernel"
                ))
            })?;
            args.extend_from_slice(&["-kernel".into(), boot.to_string_lossy().into_owned()]);

            let mut qnx_disks: Vec<(PathBuf, bool, u8)> = Vec::new();
            if let Some(rootfs) = def.rootfs_path() {
                let slot = mmio_slots.claim(
                    Some(
                        def.images
                            .rootfs_slot
                            .unwrap_or(crate::config::QNX_AARCH64_ROOTFS_SLOT),
                    ),
                    "rootfs",
                )?;
                qnx_disks.push((rootfs, true, slot));
            }
            // Every partition claims its slot, flashed or not, so a bad slot
            // fails on the first start rather than when the layer arrives.
            for part in &def.partitions {
                let slot = mmio_slots.claim(part.slot, &format!("partition '{}'", part.role))?;
                let path = def.partition_path(part);
                if path.exists() {
                    qnx_disks.push((path, part.readonly, slot));
                }
            }
            for disk in &def.disks {
                let slot = mmio_slots.claim(disk.slot, &format!("disk '{}'", disk.role))?;
                qnx_disks.push((disk.path.clone(), disk.readonly, slot));
            }
            for (i, (path, read_only, slot)) in qnx_disks.iter().enumerate() {
                let id = format!("qnxd{i}");
                let ro = if *read_only { ",readonly=on" } else { "" };
                args.extend_from_slice(&[
                    "-drive".into(),
                    format!("file={},format=raw,if=none,id={id}{ro}", path.display()),
                    "-device".into(),
                    format!("virtio-blk-device,drive={id},bus=virtio-mmio-bus.{slot}"),
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

            // `ro`, not `rw`: an immutable (dm-verity) guest must not remount /
            // read-write, and a mutable ext4 guest is unaffected — its fstab
            // `/ defaults` still upgrades to rw during boot (today's behavior).
            // A dm-verity guest supplies `dm-mod.create=… root=/dev/dm-0 ro` from
            // its `verity-cmdline` bank part (read + appended below); the kernel's
            // last-wins root=/ro handling then boots the verity device, not this
            // /dev/vda default.
            let mut cmdline_parts: Vec<String> = vec![
                "root=/dev/vda".into(),
                "ro".into(),
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
            // dm-verity guests ship a `verity-cmdline` bank part — the
            // `dm-mod.create=… root=/dev/dm-0 ro` root-hash fragment — flashed +
            // IVD-signed in the same bank as rootfs.img, so the hash always matches
            // the image (no stale baked-in hash to drift). Read it from the bank and
            // append; the trailing `root=/dev/dm-0` wins the last-root= race. Absent
            // for a non-verity guest → skipped.
            let verity_cmdline = def.image_dir.join("verity-cmdline");
            if let Ok(frag) = std::fs::read_to_string(&verity_cmdline) {
                let frag = frag.trim();
                if !frag.is_empty() {
                    cmdline_parts.push(frag.to_string());
                }
            }
            // Extra disks (data, swap — from def.disks, not banked)
            let blk_device = arch.virtio_device("blk");
            let mut disk_args: Vec<Vec<String>> = Vec::new();

            for disk in &def.disks {
                let drive_id = format!("hd_{}", disk.role);
                let ro = if disk.readonly { ",readonly=on" } else { "" };
                disk_args.push(vec![
                    "-drive".into(),
                    format!(
                        "file={},format=raw,if=none,id={drive_id}{ro}",
                        disk.path.display()
                    ),
                    "-device".into(),
                    format!("{blk_device},drive={drive_id}"),
                ]);

                if disk.role == "swap" {
                    cmdline_parts.push("resume=/dev/vdc".into());
                }
            }

            // Per-bank read-only partitions (policy, ca-bundle, sumo-config,
            // app images …) from the OTA-delivered vm-config.yaml. Appended
            // to disk_args so they share the data/swap ordering logic; the
            // guest mounts each from whichever virtio-blk node it enumerates
            // as. A missing source is skipped.
            for part in &def.partitions {
                let path = def.partition_path(part);
                if !path.exists() {
                    continue;
                }
                let drive_id = format!("hd_{}", part.role);
                let ro = if part.readonly { ",readonly=on" } else { "" };
                disk_args.push(vec![
                    "-drive".into(),
                    format!(
                        "file={},format=raw,if=none,id={drive_id}{ro}",
                        path.display()
                    ),
                    "-device".into(),
                    format!("{blk_device},drive={drive_id}"),
                ]);
            }

            let rootfs = def.rootfs_path().ok_or_else(|| {
                RunnerError::Config(format!(
                    "{name}: no rootfs image configured (set images.rootfs in config)"
                ))
            })?;
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
        let networks: Vec<_> = def
            .devices
            .iter()
            .filter(|d| matches!(d, DeviceConfig::Network { .. }))
            .collect();
        let net_device = arch.virtio_device("net");
        let virtio_net_features = virtio_net_features(def);
        let mut mmio_bus = |slot: Option<u8>, what: String| -> Result<String, RunnerError> {
            if qnx_mmio {
                Ok(format!(
                    ",bus=virtio-mmio-bus.{}",
                    mmio_slots.claim(slot, &what)?
                ))
            } else {
                Ok(String::new())
            }
        };

        let net_iter: Box<dyn Iterator<Item = (usize, &&DeviceConfig)>> =
            if arch.reverse_disk_order() {
                Box::new(networks.iter().enumerate().rev())
            } else {
                Box::new(networks.iter().enumerate())
            };

        let mut net_idx = 0;
        for (i, dev) in net_iter {
            if let DeviceConfig::Network {
                mac,
                ssh_port,
                slot,
            } = dev
            {
                let id = format!("net{net_idx}");
                let mut netdev = format!("user,id={id}");
                if let Some(port) = ssh_port {
                    netdev.push_str(&format!(",hostfwd=tcp::{port}-:22"));
                }
                if i > 0 {
                    let subnet = i + 2;
                    netdev.push_str(&format!(
                        ",net=10.0.{subnet}.0/24,dhcpstart=10.0.{subnet}.15"
                    ));
                }
                args.extend_from_slice(&["-netdev".into(), netdev]);
                let mut dev_str = format!("{net_device},netdev={id}{virtio_net_features}");
                if let Some(m) = mac {
                    dev_str.push_str(&format!(",mac={m}"));
                }
                dev_str.push_str(&mmio_bus(*slot, format!("network NIC {i}"))?);
                args.extend_from_slice(&["-device".into(), dev_str]);
                net_idx += 1;
            }
        }

        // Bridge NICs (private vHSM network). Each guest's IP on the
        // bridge is the host vHSM daemon's identity for that guest, so
        // the MAC is mandatory: dnsmasq pins MAC → IP via static lease.
        for dev in &def.devices {
            if let DeviceConfig::Bridge { bridge, mac, slot } = dev {
                let bus = mmio_bus(*slot, format!("bridge NIC '{bridge}'"))?;
                let id = format!("net{net_idx}");
                args.extend_from_slice(&[
                    "-netdev".into(),
                    format!("bridge,id={id},br={bridge}"),
                    "-device".into(),
                    format!("{net_device},netdev={id},mac={mac}{virtio_net_features}{bus}"),
                ]);
                net_idx += 1;
            }
        }

        // ivshmem devices (time, health, CAN)
        for dev in &def.devices {
            if !dev.needs_ivshmem() {
                continue;
            }
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
            if let DeviceConfig::Can {
                index, interface, ..
            } = dev
            {
                if dev.needs_ivshmem() {
                    can_devs.push((*index, interface));
                }
            }
        }
        can_devs.sort_by_key(|d| std::cmp::Reverse(d.0));
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
            if !dev.needs_ivshmem() {
                continue;
            }
            match dev {
                DeviceConfig::Can { index, .. } => {
                    let sock = ivshmem::start_ivshmem(
                        name,
                        &format!("can{index}"),
                        "1M",
                        &self.ivshmem_bin,
                        &mut self.host_processes,
                        &mut self.sockets,
                    )?;
                    ivshmem.can.insert(*index, sock);
                }
                DeviceConfig::Health { .. } => {
                    let sock = ivshmem::start_ivshmem(
                        name,
                        "health",
                        "4K",
                        &self.ivshmem_bin,
                        &mut self.host_processes,
                        &mut self.sockets,
                    )?;
                    ivshmem.health = Some(sock);
                }
                DeviceConfig::Time { .. } => {
                    let sock = ivshmem::start_ivshmem(
                        name,
                        "time",
                        "4K",
                        &self.ivshmem_bin,
                        &mut self.host_processes,
                        &mut self.sockets,
                    )?;
                    ivshmem.time = Some(sock);
                }
                _ => {}
            }
        }

        // Start Rust device simulators (health, time) or write magic headers
        for dev in &def.devices {
            if !dev.needs_ivshmem() {
                continue;
            }
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
        tracing::info!("QEMU command: {}", args.join(" "));

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
            if let DeviceConfig::Can {
                index, interface, ..
            } = dev
            {
                let ifname = interface.as_deref().unwrap_or("vcan1");
                self.start_can_bridge(name, *index, ifname)?;
            }
        }

        Ok(VmHandle {
            name: name.to_string(),
            pid: Some(pid),
        })
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

    fn graceful_shutdown(
        &mut self,
        handle: &VmHandle,
        _timeout: Duration,
    ) -> Result<(), RunnerError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn qnx_x86_definition() -> VmDefinition {
        VmDefinition {
            display_name: Some("VM1".into()),
            backend: BackendType::Qemu,
            os_type: OsType::Qnx,
            arch: Some("x86_64".into()),
            machine: None,
            cpus: 2,
            accel: Accel::Auto,
            ram_mb: 2048,
            cpu_model: None,
            serial_log: None,
            image_dir: PathBuf::from("/tmp/vm1"),
            bank: None,
            images: ImagePaths {
                kernel: Some("kernel".into()),
                rootfs: Some("rootfs.img".into()),
                rootfs_slot: None,
            },
            devices: Vec::new(),
            disks: Vec::new(),
            partitions: Vec::new(),
            health: None,
            shutdown: None,
            extra_cmdline: None,
            virtio_net_features: None,
            sim_dir: None,
            process_command: None,
            process_args: Vec::new(),
            qvm_config: None,
            auto_start: false,
        }
    }

    fn option_value<'a>(args: &'a [String], option: &str) -> Option<&'a str> {
        args.iter()
            .position(|arg| arg == option)
            .and_then(|index| args.get(index + 1))
            .map(String::as_str)
    }

    #[test]
    fn qnx_gets_virtio_net_compatibility_features() {
        assert_eq!(
            virtio_net_compat_features(OsType::Qnx),
            QNX_VIRTIO_NET_FEATURES
        );
    }

    #[test]
    fn other_guest_profiles_keep_default_virtio_net_features() {
        assert_eq!(virtio_net_compat_features(OsType::Linux), "");
    }

    #[test]
    fn virtio_net_features_override_replaces_the_profile_set() {
        let mut def = qnx_x86_definition();
        def.virtio_net_features = Some("event_idx=off,guest_tso4=off".into());
        assert_eq!(virtio_net_features(&def), ",event_idx=off,guest_tso4=off");
        def.virtio_net_features = Some(",guest_tso4=off,".into());
        assert_eq!(virtio_net_features(&def), ",guest_tso4=off");
        def.virtio_net_features = Some(String::new());
        assert_eq!(virtio_net_features(&def), "");
    }

    #[test]
    fn linux_aarch64_keeps_kernel_boot_and_plain_virtio_devices() {
        let def: VmDefinition = serde_yaml::from_str(
            r#"
backend: qemu
os_type: linux
arch: aarch64
cpus: 2
image_dir: /var/lib/vm2
images: { kernel: arm64-Image, rootfs: rootfs.img }
devices:
  - { type: network, mac: "52:54:00:00:02:01" }
"#,
        )
        .unwrap();

        let args = QemuRunner::new()
            .build_qemu_args_with_kvm("vm2", &def, &IvshmemSockets::default(), false)
            .unwrap();

        assert_eq!(
            option_value(&args, "-kernel"),
            Some("/var/lib/vm2/arm64-Image")
        );
        assert_eq!(option_value(&args, "-cpu"), Some("cortex-a76"));
        assert!(args.contains(&"virtio-blk-device,drive=hd_rootfs".to_string()));
        assert!(args.contains(&"virtio-net-device,netdev=net0,mac=52:54:00:00:02:01".to_string()));
        assert!(!args.iter().any(|arg| arg.contains("virtio-mmio-bus")));
        assert!(
            option_value(&args, "-append").is_some_and(|cmdline| cmdline.contains("root=/dev/vda"))
        );
    }

    #[test]
    fn qnx_x86_keeps_bios_boot_disk_on_pci() {
        let def = qnx_x86_definition();

        let args = QemuRunner::new()
            .build_qemu_args_with_kvm("vm1", &def, &IvshmemSockets::default(), true)
            .unwrap();

        assert!(args.contains(&"virtio-blk-pci,drive=qnxd0,bootindex=0".to_string()));
        assert!(args.contains(&"virtio-blk-pci,drive=qnxd1".to_string()));
        assert!(!args.iter().any(|arg| arg == "-kernel"));
        assert!(!args.iter().any(|arg| arg.contains("virtio-mmio-bus")));
    }

    /// guest-vm-qnx arm64 layout: rootfs 31, data 30, NICs 29/28, opt 27,
    /// sumo-config 20.
    fn qnx_aarch64_definition(bank: &std::path::Path) -> VmDefinition {
        std::fs::write(bank.join("sumo-config.qnx6"), b"").unwrap();
        serde_yaml::from_str(&format!(
            r#"
backend: qemu
os_type: qnx
arch: aarch64
image_dir: {bank}
images: {{ kernel: boot.img, rootfs: rootfs.img }}
partitions:
  - {{ role: cfg, source: sumo-config.qnx6, slot: 20 }}
  - {{ role: rtl, source: absent-layer.qnx6, slot: 19 }}
disks:
  - {{ role: data, path: /var/lib/vm1/data.img, slot: 30 }}
  - {{ role: opt, path: /var/lib/vm1/opt.img, slot: 27 }}
devices:
  - {{ type: bridge, bridge: br0, mac: "52:54:00:00:01:02", slot: 29 }}
"#,
            bank = bank.display()
        ))
        .unwrap()
    }

    #[test]
    fn qnx_aarch64_boots_ifs_with_devices_on_fixed_mmio_slots() {
        let bank = tempfile::tempdir().unwrap();
        let def = qnx_aarch64_definition(bank.path());

        let args = QemuRunner::new()
            .build_qemu_args_with_kvm("vm1", &def, &IvshmemSockets::default(), false)
            .unwrap();

        let boot = bank.path().join("boot.img");
        assert_eq!(option_value(&args, "-kernel"), boot.to_str());
        assert_eq!(option_value(&args, "-machine"), Some("virt,gic-version=3"));
        assert_eq!(option_value(&args, "-cpu"), Some("cortex-a57"));
        assert_eq!(option_value(&args, "-smp"), Some("4"));
        assert!(!args
            .iter()
            .any(|arg| arg == "-enable-kvm" || arg == "-append"));

        let devices: Vec<&str> = args
            .iter()
            .zip(args.iter().skip(1))
            .filter(|(option, _)| *option == "-device")
            .map(|(_, value)| value.as_str())
            .collect();
        assert_eq!(
            devices[..4],
            [
                "virtio-blk-device,drive=qnxd0,bus=virtio-mmio-bus.31",
                "virtio-blk-device,drive=qnxd1,bus=virtio-mmio-bus.20",
                "virtio-blk-device,drive=qnxd2,bus=virtio-mmio-bus.30",
                "virtio-blk-device,drive=qnxd3,bus=virtio-mmio-bus.27",
            ]
        );
        assert_eq!(
            devices[4],
            format!(
                "virtio-net-device,netdev=net0,mac=52:54:00:00:01:02{QNX_VIRTIO_NET_FEATURES},bus=virtio-mmio-bus.29"
            )
        );
        let rootfs = bank.path().join("rootfs.img");
        assert!(args.contains(&format!(
            "file={},format=raw,if=none,id=qnxd0,readonly=on",
            rootfs.display()
        )));
        assert!(
            args.contains(&"file=/var/lib/vm1/data.img,format=raw,if=none,id=qnxd2".to_string())
        );
    }

    #[test]
    fn qnx_aarch64_keeps_the_configured_vcpus_under_kvm() {
        let bank = tempfile::tempdir().unwrap();
        let def = qnx_aarch64_definition(bank.path());

        let args = QemuRunner::new()
            .build_qemu_args_with_kvm("vm1", &def, &IvshmemSockets::default(), true)
            .unwrap();

        assert_eq!(option_value(&args, "-smp"), Some("4"));
        assert_eq!(option_value(&args, "-cpu"), Some("host"));
        assert!(args.iter().any(|arg| arg == "-enable-kvm"));
    }

    #[test]
    fn accel_selects_kvm_or_tcg() {
        assert!(resolve_kvm("vm1", Accel::Auto, true, true).unwrap());
        assert!(!resolve_kvm("vm1", Accel::Auto, false, true).unwrap());
        assert!(!resolve_kvm("vm1", Accel::Auto, true, false).unwrap());
        assert!(!resolve_kvm("vm1", Accel::Tcg, true, true).unwrap());
        assert!(resolve_kvm("vm1", Accel::Kvm, false, true).unwrap());
        let error = resolve_kvm("vm1", Accel::Kvm, true, false).unwrap_err();
        assert!(error.to_string().contains("KVM is not available"));
    }

    #[test]
    fn qnx_aarch64_rejects_a_device_without_a_slot() {
        let bank = tempfile::tempdir().unwrap();
        let mut def = qnx_aarch64_definition(bank.path());
        def.disks[1].slot = None;

        let error = QemuRunner::new()
            .build_qemu_args_with_kvm("vm1", &def, &IvshmemSockets::default(), false)
            .unwrap_err();

        assert!(error.to_string().contains("disk 'opt' needs a `slot`"));
    }

    #[test]
    fn qnx_aarch64_rejects_a_slot_used_twice_or_out_of_range() {
        let bank = tempfile::tempdir().unwrap();
        let mut def = qnx_aarch64_definition(bank.path());
        def.partitions[0].slot = Some(31);

        let error = QemuRunner::new()
            .build_qemu_args_with_kvm("vm1", &def, &IvshmemSockets::default(), false)
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("partition 'cfg' and rootfs both use virtio-mmio slot 31"));

        def.partitions[0].slot = Some(32);
        let error = QemuRunner::new()
            .build_qemu_args_with_kvm("vm1", &def, &IvshmemSockets::default(), false)
            .unwrap_err();
        assert!(error.to_string().contains("slot 32 is out of range"));
    }

    #[test]
    fn qnx_aarch64_checks_the_slot_of_a_partition_not_flashed_yet() {
        let bank = tempfile::tempdir().unwrap();
        let mut def = qnx_aarch64_definition(bank.path());
        def.partitions[1].slot = None; // absent-layer.qnx6 is not on disk

        let error = QemuRunner::new()
            .build_qemu_args_with_kvm("vm1", &def, &IvshmemSockets::default(), false)
            .unwrap_err();

        assert!(error.to_string().contains("partition 'rtl' needs a `slot`"));
    }

    #[test]
    fn configured_qemu_options_apply_with_kvm() {
        let mut def = qnx_x86_definition();
        def.machine = Some("q35".into());
        def.cpu_model = Some("qemu64".into());
        def.serial_log = Some(PathBuf::from("/tmp/vm1-serial.log"));

        let args = QemuRunner::new()
            .build_qemu_args_with_kvm("vm1", &def, &IvshmemSockets::default(), true)
            .unwrap();

        assert_eq!(option_value(&args, "-machine"), Some("q35"));
        assert_eq!(option_value(&args, "-cpu"), Some("qemu64"));
        assert_eq!(option_value(&args, "-m"), Some("2048M"));
        assert_eq!(
            option_value(&args, "-serial"),
            Some("file:/tmp/vm1-serial.log")
        );
        assert!(args.iter().any(|arg| arg == "-enable-kvm"));
        assert!(!args.iter().any(|arg| arg == "-nographic"));
    }

    #[test]
    fn qemu_defaults_remain_host_cpu_and_nographic_with_kvm() {
        let def = qnx_x86_definition();

        let args = QemuRunner::new()
            .build_qemu_args_with_kvm("vm1", &def, &IvshmemSockets::default(), true)
            .unwrap();

        assert_eq!(option_value(&args, "-machine"), Some("q35"));
        assert_eq!(option_value(&args, "-cpu"), Some("host"));
        assert!(args.iter().any(|arg| arg == "-nographic"));
        assert!(!args.iter().any(|arg| arg == "-serial"));
    }

    #[test]
    fn serial_log_rejects_qemu_option_delimiters() {
        let mut def = qnx_x86_definition();
        def.serial_log = Some(PathBuf::from("/tmp/vm1,serial.log"));

        let error = QemuRunner::new()
            .build_qemu_args_with_kvm("vm1", &def, &IvshmemSockets::default(), false)
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("serial_log must be an absolute non-empty path"));
    }

    #[test]
    fn serial_log_rejects_relative_paths() {
        let mut def = qnx_x86_definition();
        def.serial_log = Some(PathBuf::from("vm1-serial.log"));

        let error = QemuRunner::new()
            .build_qemu_args_with_kvm("vm1", &def, &IvshmemSockets::default(), false)
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("serial_log must be an absolute non-empty path"));
    }
}
