use serde::Deserialize;
/// Static YAML configuration for vm-service.
///
/// Loaded once at startup. Declares which VMs can exist and their hardware
/// setup. Lifecycle control (start/stop/restart) comes via the HTTP API.
/// Bank selection is invisible — `image_dir` is typically a symlink that
/// the diagnostic stack flips before calling restart.
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Top-level service configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct VmServiceConfig {
    /// TCP bind address for the control API (e.g. "127.0.0.1:9101").
    /// Localhost-only by default — clients (vm-mgr inside supernova,
    /// CLI tools on the host) reach it over loopback.
    ///
    /// Originally a Unix socket path (`socket: ...`); switched to TCP
    /// after `tokio::net::UnixListener::accept()` was found not to wake
    /// up reliably on QNX 7.1. Real-fs AF_UNIX paths still create the
    /// socket file but no async events ever fire. TCP on loopback
    /// avoids the issue entirely on the same locality boundary.
    #[serde(default = "default_bind")]
    pub bind: String,
    /// Host↔guest device-transport configuration. When set, vm-service
    /// constructs the named transport at startup and `VmManager` opens
    /// `HeartbeatDevice` + `PowerCommandDevice` channels through it for
    /// every VM that declares a `health` device. When unset, VMs with
    /// health devices warn at startup and have no liveness signal.
    ///
    /// Production qvm hosts: `kind: http, bind: 10.0.100.1:9200`.
    /// Linux/QEMU dev: `kind: ivshmem, base_dir: /dev/shm`.
    #[serde(default)]
    pub device_transport: Option<DeviceTransportConfig>,
    /// VM definitions, keyed by name (e.g., "vm1", "vm2").
    pub vms: HashMap<String, VmDefinition>,
}

/// Which device-transport substrate to use for host↔guest channels.
///
/// One transport per vm-service instance. All VMs share it; channels are
/// keyed by `(vm, device, channel)` so namespace collisions can't happen.
//
// dead_code: `QvmShmem` is constructed by supernova-mm (which links
// libhyp), not by vm-service's own build path. The vm-service binary's
// dead-code pass doesn't see those fields read; supernova-mm does.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
#[allow(dead_code)]
pub enum DeviceTransportConfig {
    /// Files at `<base_dir>/ivshmem-{vm}-{device}-{channel}`. Each is
    /// `mmap`'d on the host by `IvshmemTransport` and exposed to the guest
    /// via QEMU's `-device ivshmem-plain,memdev=...` (the QemuRunner adds
    /// the `-object memory-backend-file` + `-device ivshmem-plain` pair).
    /// Linux only.
    Ivshmem {
        #[serde(default = "default_ivshmem_dir")]
        base_dir: PathBuf,
    },
    /// HTTP server on `bind` (e.g. `10.0.100.1:9200`). Guests reach it via
    /// virtio-net + their host-route (typically the vp0 IP). Universal —
    /// works under any hypervisor with a usable guest network.
    Http { bind: String },
    /// QNX hypervisor `vdev shmem` — zero-copy cross-VM transport via
    /// libhyp on the host side and qvm-shmem.ko (Linux guest) or
    /// vm-guest-pci (QNX guest). Construction lives in supernova-mm
    /// because it links the proprietary `libhyp.a`; vm-service's
    /// `build_device_transport` returns `None` for this variant and
    /// expects the embedding binary to construct the transport itself
    /// via `VmManager::with_device_transport`.
    QvmShmem {
        /// Pages per region (one slot per peer, 4 KiB each). Default
        /// 16 — full GUEST_SHM_MAX_CLIENTS capacity.
        #[serde(default = "default_qvm_region_pages")]
        region_pages: u32,
        /// Per-VM strict slot assignment. Both peers' slot indices are
        /// pinned per VM and applied to ALL regions for that VM.
        /// Missing entries default to `{ host_slot: 0, peer_slot: 1 }`.
        ///
        /// On Region::open, if libhyp gives the host a slot index that
        /// doesn't match `host_slot`, the channel construction fails
        /// loud — typically caused by a leaked slot from a previously-
        /// crashed peer in the same region; reboot to clear libhyp
        /// factory state and redeploy.
        #[serde(default)]
        vm_slots: HashMap<String, VmSlots>,
        /// Channel triples that should be read-only on the host side
        /// (host doesn't write — e.g. heartbeat is guest-published).
        /// Format: `"{vm}-{device}-{channel}"`.
        #[serde(default)]
        read_only_channels: Vec<String>,
    },
}

/// Per-VM slot pair for qvm-shmem regions. Mirrors
/// `qnx_devices::qvm_transport::VmSlots` shape so the supernova-mm
/// translation is field-for-field.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub struct VmSlots {
    /// Slot index the host pins itself to (own slot for paired
    /// channels). Verified against `region.idx()` after libhyp
    /// allocation; mismatch errors loud.
    #[serde(default = "default_host_slot")]
    pub host_slot: u32,
    /// Slot index the guest is pinned to (host's read target).
    #[serde(default = "default_peer_slot")]
    pub peer_slot: u32,
}

impl Default for VmSlots {
    fn default() -> Self {
        // host=0, peer=2 because qvm reserves slot 1 for itself (the
        // creator/factory). Empirically the guest's first attach lands
        // on slot 2 every time, on both fresh boot and after deploys.
        // Override per VM only if you actually know better.
        Self {
            host_slot: 0,
            peer_slot: 2,
        }
    }
}

fn default_host_slot() -> u32 {
    0
}
fn default_peer_slot() -> u32 {
    2
}

fn default_ivshmem_dir() -> PathBuf {
    PathBuf::from("/dev/shm")
}

fn default_qvm_region_pages() -> u32 {
    16
}

fn default_bind() -> String {
    "127.0.0.1:9101".to_string()
}

/// Everything needed to run a single VM.
#[derive(Debug, Clone, Deserialize)]
pub struct VmDefinition {
    /// Human-readable display name (e.g., "VM1 — Debian Linux").
    /// Used in SOVD component listing if available.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Backend type: qemu, qnx, or dummy.
    pub backend: BackendType,
    /// Guest operating system type. Affects boot method, disk layout, device setup.
    #[serde(default)]
    pub os_type: OsType,
    /// Target architecture (default: aarch64).
    #[serde(default)]
    pub arch: Option<String>,
    /// Number of virtual CPUs (default: 4).
    #[serde(default = "default_cpus")]
    pub cpus: u32,
    /// RAM in MB (default: 2048).
    #[serde(default = "default_ram")]
    pub ram_mb: u32,
    /// CPU model override. If unset, uses arch default.
    #[serde(default)]
    pub cpu_model: Option<String>,
    /// Directory containing kernel + rootfs. Typically a symlink
    /// (e.g., /var/lib/vms/vm1/current → bank_a/).
    pub image_dir: PathBuf,
    /// Image filenames relative to image_dir.
    #[serde(default)]
    pub images: ImagePaths,
    /// Devices attached to this VM.
    #[serde(default)]
    pub devices: Vec<DeviceConfig>,
    /// Extra disks (data, swap) — not part of the banked image set.
    #[serde(default)]
    pub disks: Vec<DiskConfig>,
    /// Per-bank read-only partitions (policy, ca-bundle, sumo-config,
    /// app images …) the host loopbacks for the guest. Sourced from the
    /// OTA-delivered `vm-config.yaml`; see [`Partition`].
    #[serde(default)]
    pub partitions: Vec<Partition>,
    /// Health monitoring configuration.
    #[serde(default)]
    #[allow(dead_code)]
    pub health: Option<HealthConfig>,
    /// Shutdown configuration.
    #[serde(default)]
    pub shutdown: Option<ShutdownConfig>,
    /// Extra kernel command-line arguments.
    #[serde(default)]
    pub extra_cmdline: Option<String>,
    /// Directory for host simulator binaries.
    #[serde(default)]
    pub sim_dir: Option<PathBuf>,
    /// Path to qvm config file (QNX backend only).
    #[serde(default)]
    pub qvm_config: Option<PathBuf>,
    /// Auto-start this VM when vm-service starts (default: false).
    #[serde(default)]
    pub auto_start: bool,
}

fn default_cpus() -> u32 {
    4
}
fn default_ram() -> u32 {
    2048
}

/// Guest OS type — affects boot method, disk layout, and device setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OsType {
    /// Linux guest: boots with -kernel + -append + rootfs as virtio-blk.
    /// Supports vcan-shm, vtime, vhealth kernel modules.
    #[default]
    Linux,
    /// QNX guest: boots from disk image (IFS + QNX6 filesystem).
    /// No separate kernel — bootloader in the disk image.
    Qnx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendType {
    Qemu,
    Qnx,
    Dummy,
}

/// Paths to boot images, relative to image_dir.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ImagePaths {
    /// Kernel image filename (e.g., "kernel", "Image").
    #[serde(default)]
    pub kernel: Option<String>,
    /// Root filesystem filename (e.g., "rootfs.qcow2").
    #[serde(default)]
    pub rootfs: Option<String>,
}

/// One extra read-only image the host exposes to the guest as a block
/// device (devb-loopback → `/dev/qvm{role}-{vm}0`, wired to the guest's
/// `qvm.conf` hostdev). Declared per-bank in the OTA-delivered
/// `vm-config.yaml`, so adding a partition — policy, ca-bundle,
/// sumo-config, an app image — never needs a host-binary change; only a
/// genuinely new *kind* of host operation would. `role` is the short
/// device token (keep ≤4 chars — io-blk on QNX 7.1 silently drops longer
/// prefixes); `source` is the bank-relative filename backing the loopback.
#[derive(Debug, Clone, Deserialize)]
pub struct Partition {
    pub role: String,
    pub source: String,
    /// Attach read-only (default true — these are RO partitions).
    #[serde(default = "default_true")]
    pub readonly: bool,
}

fn default_true() -> bool {
    true
}

/// Extra disk not managed by the banking system.
#[derive(Debug, Clone, Deserialize)]
pub struct DiskConfig {
    /// Role name: "data", "swap", etc.
    pub role: String,
    /// Absolute path to disk image.
    pub path: PathBuf,
    /// Mount read-only.
    #[serde(default)]
    pub readonly: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct HealthConfig {
    /// Seconds before declaring VM unhealthy.
    #[serde(default = "default_health_timeout")]
    pub timeout_secs: u64,
}

fn default_health_timeout() -> u64 {
    10
}

#[derive(Debug, Clone, Deserialize)]
pub struct ShutdownConfig {
    /// Seconds to wait for graceful shutdown before force-kill.
    #[serde(default = "default_shutdown_timeout")]
    pub timeout_secs: u64,
}

// 60s — Linux (autosd / debian) systemd shutdown takes 5-30s on
// managed-cvc; QNX is faster but the orchestrator amortises the
// extra ceiling. Was 10s, which always force-killed before linux
// finished, leaving fsck-on-next-mount as the cleanup path.
fn default_shutdown_timeout() -> u64 {
    60
}

impl VmServiceConfig {
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        serde_yaml::from_str(&content)
            .map_err(|e| format!("failed to parse {}: {e}", path.display()))
    }
}

impl VmDefinition {
    /// Resolve target architecture (defaults to Aarch64).
    pub fn arch(&self) -> Arch {
        self.arch
            .as_deref()
            .and_then(Arch::from_str)
            .unwrap_or(Arch::Aarch64)
    }

    /// Count CAN interfaces.
    pub fn can_count(&self) -> u8 {
        self.devices
            .iter()
            .filter(|d| matches!(d, DeviceConfig::Can { .. }))
            .count() as u8
    }

    /// Get SSH port if any network device has one.
    #[allow(dead_code)]
    pub fn ssh_port(&self) -> Option<u16> {
        self.devices.iter().find_map(|d| match d {
            DeviceConfig::Network { ssh_port, .. } => *ssh_port,
            _ => None,
        })
    }

    /// Resolve the kernel path (image_dir + images.kernel).
    pub fn kernel_path(&self) -> Option<PathBuf> {
        self.images.kernel.as_ref().map(|k| {
            if Path::new(k).is_absolute() {
                PathBuf::from(k)
            } else {
                self.image_dir.join(k)
            }
        })
    }

    /// Resolve the rootfs path (image_dir + images.rootfs).
    pub fn rootfs_path(&self) -> Option<PathBuf> {
        self.images.rootfs.as_ref().map(|r| {
            if Path::new(r).is_absolute() {
                PathBuf::from(r)
            } else {
                self.image_dir.join(r)
            }
        })
    }

    /// Resolve a partition's backing path: bank-relative `source` against
    /// `image_dir`, or an absolute `source` verbatim. Used by the runners
    /// to back each partition's devb-loopback / -drive.
    pub fn partition_path(&self, p: &Partition) -> PathBuf {
        if Path::new(&p.source).is_absolute() {
            PathBuf::from(&p.source)
        } else {
            self.image_dir.join(&p.source)
        }
    }

    /// Shutdown timeout in seconds (default 10).
    pub fn shutdown_timeout_secs(&self) -> u64 {
        // Default kept in sync with `default_shutdown_timeout` above.
        self.shutdown.as_ref().map(|s| s.timeout_secs).unwrap_or(60)
    }

    /// Merge per-bank overrides into this definition. Only present fields are overridden.
    pub fn with_bank_overrides(&self, overrides: &VmBankConfig) -> Self {
        let mut merged = self.clone();
        if let Some(ref name) = overrides.display_name {
            merged.display_name = Some(name.clone());
        }
        if let Some(cpus) = overrides.cpus {
            merged.cpus = cpus;
        }
        if let Some(ram) = overrides.ram_mb {
            merged.ram_mb = ram;
        }
        if let Some(ref model) = overrides.cpu_model {
            merged.cpu_model = Some(model.clone());
        }
        if let Some(ref cmd) = overrides.extra_cmdline {
            merged.extra_cmdline = Some(cmd.clone());
        }
        if let Some(ref imgs) = overrides.images {
            if imgs.kernel.is_some() {
                merged.images.kernel = imgs.kernel.clone();
            }
            if imgs.rootfs.is_some() {
                merged.images.rootfs = imgs.rootfs.clone();
            }
        }
        // Partitions are declared wholesale per-bank (vm-config.yaml),
        // not field-merged: a present list replaces the base entirely.
        if let Some(ref parts) = overrides.partitions {
            merged.partitions = parts.clone();
        }
        merged
    }
}

// =============================================================================
// Architecture abstraction (copied from boot crate — pure data, no nv-store dep)
// =============================================================================

/// Target architecture for a VM. Drives QEMU binary selection, machine type,
/// console device, virtio transport, and disk enumeration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    Aarch64,
    X86_64,
}

impl Arch {
    /// Parse an architecture token from config strings.  Not the
    /// `std::str::FromStr` trait method — returns `Option`, not
    /// `Result`, because unknown tokens are legitimately absent
    /// rather than malformed.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "aarch64" | "arm64" => Some(Arch::Aarch64),
            "x86_64" | "amd64" => Some(Arch::X86_64),
            _ => None,
        }
    }

    pub fn qemu_binary(&self) -> &'static str {
        match self {
            Arch::Aarch64 => "qemu-system-aarch64",
            Arch::X86_64 => "qemu-system-x86_64",
        }
    }

    pub fn machine_type(&self) -> &'static str {
        match self {
            Arch::Aarch64 => "virt,gic-version=3",
            Arch::X86_64 => "q35",
        }
    }

    pub fn console_device(&self) -> &'static str {
        match self {
            Arch::Aarch64 => "ttyAMA0",
            Arch::X86_64 => "ttyS0",
        }
    }

    pub fn default_cpu(&self) -> &'static str {
        match self {
            Arch::Aarch64 => "cortex-a76",
            Arch::X86_64 => "max",
        }
    }

    pub fn virtio_device(&self, kind: &str) -> String {
        match self {
            Arch::Aarch64 => format!("virtio-{kind}-device"),
            Arch::X86_64 => format!("virtio-{kind}-pci"),
        }
    }

    pub fn reverse_disk_order(&self) -> bool {
        match self {
            Arch::Aarch64 => true,
            Arch::X86_64 => false,
        }
    }

    pub fn kvm_available(&self) -> bool {
        if !Path::new("/dev/kvm").exists() {
            return false;
        }
        match self {
            Arch::Aarch64 => cfg!(target_arch = "aarch64"),
            Arch::X86_64 => cfg!(target_arch = "x86_64"),
        }
    }
}

// =============================================================================
// Device configuration (adapted from boot crate)
// =============================================================================

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum DeviceConfig {
    #[serde(rename = "can")]
    Can {
        #[serde(default)]
        index: u8,
        transport: String,
        #[serde(default)]
        interface: Option<String>,
    },
    #[serde(rename = "health")]
    Health { transport: String },
    #[serde(rename = "time")]
    Time { transport: String },
    #[serde(rename = "hsm")]
    Hsm {
        // Deserialized from config for compatibility but not consumed
        // by the bin path today — keep the fields in the enum so config
        // files don't fail to parse, and silence the unused warning.
        #[serde(default)]
        #[allow(dead_code)]
        keystore: Option<String>,
        #[serde(default)]
        #[allow(dead_code)]
        keygen_bin: Option<String>,
        #[serde(default = "default_hsm_port")]
        #[allow(dead_code)]
        port: u16,
    },
    #[serde(rename = "network")]
    Network {
        #[serde(default)]
        mac: Option<String>,
        #[serde(default)]
        ssh_port: Option<u16>,
    },
    #[serde(rename = "bridge")]
    Bridge { bridge: String, mac: String },
    #[serde(rename = "console")]
    Console,
}

fn default_hsm_port() -> u16 {
    5100
}

impl DeviceConfig {
    pub fn needs_ivshmem(&self) -> bool {
        match self {
            DeviceConfig::Health { transport }
            | DeviceConfig::Time { transport }
            | DeviceConfig::Can { transport, .. } => transport == "ivshmem",
            _ => false,
        }
    }
}

// =============================================================================
// Per-bank VM config (delivered alongside firmware during OTA)
// =============================================================================

/// Per-bank VM config — lives in bank directories, overrides base VmDefinition fields.
/// Delivered alongside firmware during OTA updates. All fields Optional — only present
/// fields override the base VmDefinition.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct VmBankConfig {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub cpus: Option<u32>,
    #[serde(default)]
    pub ram_mb: Option<u32>,
    #[serde(default)]
    pub cpu_model: Option<String>,
    #[serde(default)]
    pub extra_cmdline: Option<String>,
    #[serde(default)]
    pub images: Option<ImagePaths>,
    #[serde(default)]
    pub partitions: Option<Vec<Partition>>,
}

impl VmBankConfig {
    /// Load per-bank config from image directory. Returns None if the file
    /// doesn't exist or can't be parsed (backward-compatible default).
    pub fn from_dir(image_dir: &Path) -> Option<Self> {
        let path = image_dir.join("vm-config.yaml");
        let content = std::fs::read_to_string(&path).ok()?;
        match serde_yaml::from_str(&content) {
            Ok(config) => Some(config),
            Err(e) => {
                tracing::warn!("failed to parse {}: {e}", path.display());
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn base_def() -> VmDefinition {
        VmDefinition {
            display_name: Some("Base VM".into()),
            backend: BackendType::Dummy,
            os_type: OsType::Linux,
            arch: None,
            cpus: 4,
            ram_mb: 2048,
            cpu_model: None,
            image_dir: PathBuf::from("/tmp/test"),
            images: ImagePaths {
                kernel: Some("bzImage".into()),
                rootfs: Some("rootfs.img".into()),
            },
            devices: vec![],
            disks: vec![],
            partitions: vec![],
            health: None,
            shutdown: None,
            extra_cmdline: Some("console=ttyS0".into()),
            sim_dir: None,
            qvm_config: None,
            auto_start: false,
        }
    }

    #[test]
    fn bank_config_partial_override() {
        let base = base_def();
        let overrides = VmBankConfig {
            cpus: Some(2),
            ram_mb: Some(4096),
            ..Default::default()
        };

        let merged = base.with_bank_overrides(&overrides);
        assert_eq!(merged.cpus, 2);
        assert_eq!(merged.ram_mb, 4096);
        // Unchanged fields
        assert_eq!(merged.display_name.as_deref(), Some("Base VM"));
        assert_eq!(merged.extra_cmdline.as_deref(), Some("console=ttyS0"));
        assert_eq!(merged.images.kernel.as_deref(), Some("bzImage"));
    }

    #[test]
    fn bank_config_full_override() {
        let base = base_def();
        let overrides = VmBankConfig {
            display_name: Some("VM1 — Debian v2.0".into()),
            cpus: Some(8),
            ram_mb: Some(8192),
            cpu_model: Some("max".into()),
            extra_cmdline: Some("console=ttyS0 debug".into()),
            images: Some(ImagePaths {
                kernel: Some("vmlinuz".into()),
                rootfs: Some("root.ext4".into()),
            }),
            partitions: None,
        };

        let merged = base.with_bank_overrides(&overrides);
        assert_eq!(merged.display_name.as_deref(), Some("VM1 — Debian v2.0"));
        assert_eq!(merged.cpus, 8);
        assert_eq!(merged.ram_mb, 8192);
        assert_eq!(merged.cpu_model.as_deref(), Some("max"));
        assert_eq!(merged.extra_cmdline.as_deref(), Some("console=ttyS0 debug"));
        assert_eq!(merged.images.kernel.as_deref(), Some("vmlinuz"));
        assert_eq!(merged.images.rootfs.as_deref(), Some("root.ext4"));
    }

    #[test]
    fn bank_config_empty_override_is_noop() {
        let base = base_def();
        let overrides = VmBankConfig::default();

        let merged = base.with_bank_overrides(&overrides);
        assert_eq!(merged.cpus, 4);
        assert_eq!(merged.ram_mb, 2048);
        assert_eq!(merged.display_name.as_deref(), Some("Base VM"));
    }

    #[test]
    fn bank_config_deserialize_yaml() {
        let yaml = r#"
cpus: 2
ram_mb: 1024
display_name: "Test VM v1.0"
extra_cmdline: "debug"
"#;
        let config: VmBankConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.cpus, Some(2));
        assert_eq!(config.ram_mb, Some(1024));
        assert_eq!(config.display_name.as_deref(), Some("Test VM v1.0"));
        assert_eq!(config.extra_cmdline.as_deref(), Some("debug"));
        assert!(config.cpu_model.is_none());
        assert!(config.images.is_none());
    }

    #[test]
    fn bank_config_from_dir_missing_file() {
        let dir = std::env::temp_dir().join("vm-bank-config-test-missing");
        let _ = std::fs::create_dir_all(&dir);
        assert!(VmBankConfig::from_dir(&dir).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bank_config_from_dir_valid_file() {
        let dir = std::env::temp_dir().join("vm-bank-config-test-valid");
        let _ = std::fs::create_dir_all(&dir);

        let mut f = std::fs::File::create(dir.join("vm-config.yaml")).unwrap();
        writeln!(f, "cpus: 6\nram_mb: 3072").unwrap();

        let config = VmBankConfig::from_dir(&dir).unwrap();
        assert_eq!(config.cpus, Some(6));
        assert_eq!(config.ram_mb, Some(3072));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bank_config_images_partial_override() {
        let base = base_def();
        // Override only kernel, keep rootfs from base
        let overrides = VmBankConfig {
            images: Some(ImagePaths {
                kernel: Some("vmlinuz-new".into()),
                rootfs: None,
            }),
            ..Default::default()
        };

        let merged = base.with_bank_overrides(&overrides);
        assert_eq!(merged.images.kernel.as_deref(), Some("vmlinuz-new"));
        assert_eq!(merged.images.rootfs.as_deref(), Some("rootfs.img")); // unchanged
    }

    #[test]
    fn bank_config_partitions_override() {
        let base = base_def();
        assert!(base.partitions.is_empty());
        let overrides = VmBankConfig {
            partitions: Some(vec![
                Partition {
                    role: "cfg".into(),
                    source: "sumo-config".into(),
                    readonly: true,
                },
                Partition {
                    role: "cab".into(),
                    source: "ca-bundle".into(),
                    readonly: true,
                },
            ]),
            ..Default::default()
        };
        let merged = base.with_bank_overrides(&overrides);
        assert_eq!(merged.partitions.len(), 2);
        assert_eq!(merged.partitions[0].role, "cfg");
        assert_eq!(merged.partitions[0].source, "sumo-config");
    }

    #[test]
    fn bank_config_deserialize_partitions() {
        let yaml = r#"
cpus: 2
partitions:
  - { role: pols, source: policy }
  - { role: cfg, source: sumo-config }
"#;
        let config: VmBankConfig = serde_yaml::from_str(yaml).unwrap();
        let parts = config.partitions.expect("partitions present");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].role, "pols");
        assert_eq!(parts[1].source, "sumo-config");
        assert!(parts[0].readonly); // defaults true
    }

    // -----------------------------------------------------------------
    // Top-level VmServiceConfig parsing
    // -----------------------------------------------------------------

    #[test]
    fn vm_service_config_parses_minimal_yaml() {
        let yaml = r#"
bind: 127.0.0.1:9999
vms:
  vm1:
    backend: dummy
    image_dir: /var/lib/vms/vm1
"#;
        let cfg: VmServiceConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.bind, "127.0.0.1:9999");
        assert_eq!(cfg.vms.len(), 1);
        let vm1 = cfg.vms.get("vm1").unwrap();
        assert!(matches!(vm1.backend, BackendType::Dummy));
        // Defaults
        assert_eq!(vm1.cpus, default_cpus());
        assert_eq!(vm1.ram_mb, default_ram());
        assert!(!vm1.auto_start);
    }

    #[test]
    fn vm_definition_honors_explicit_fields() {
        let yaml = r#"
socket: /tmp/s.sock
vms:
  hostvm:
    backend: qemu
    os_type: linux
    arch: amd64
    cpus: 2
    ram_mb: 1024
    image_dir: /data/images/host
    auto_start: true
"#;
        let cfg: VmServiceConfig = serde_yaml::from_str(yaml).unwrap();
        let v = cfg.vms.get("hostvm").unwrap();
        assert!(matches!(v.backend, BackendType::Qemu));
        assert_eq!(v.cpus, 2);
        assert_eq!(v.ram_mb, 1024);
        assert!(v.auto_start);
    }

    #[test]
    fn vm_service_config_parses_with_defaults_when_only_vms_present() {
        // `bind` and `device_transport` are both optional. A minimal config
        // is just the vms map.
        let yaml = r#"
vms:
  vm1:
    backend: dummy
    image_dir: /x
"#;
        let cfg: VmServiceConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.bind, default_bind());
        assert!(cfg.device_transport.is_none());
        assert_eq!(cfg.vms.len(), 1);
    }

    #[test]
    fn vm_service_config_parses_http_device_transport() {
        let yaml = r#"
device_transport:
  kind: http
  bind: 10.0.100.1:9200
vms:
  vm2:
    backend: qnx
    image_dir: /var/lib/vms/vm2
"#;
        let cfg: VmServiceConfig = serde_yaml::from_str(yaml).unwrap();
        match cfg.device_transport {
            Some(DeviceTransportConfig::Http { bind }) => assert_eq!(bind, "10.0.100.1:9200"),
            other => panic!("expected http transport, got {other:?}"),
        }
    }

    #[test]
    fn vm_service_config_parses_ivshmem_device_transport_with_default_dir() {
        let yaml = r#"
device_transport:
  kind: ivshmem
vms: {}
"#;
        let cfg: VmServiceConfig = serde_yaml::from_str(yaml).unwrap();
        match cfg.device_transport {
            Some(DeviceTransportConfig::Ivshmem { base_dir }) => {
                assert_eq!(base_dir, default_ivshmem_dir());
            }
            other => panic!("expected ivshmem transport, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // VmDefinition accessor methods
    // -----------------------------------------------------------------

    fn minimal_vm(image_dir: &str) -> VmDefinition {
        let yaml = format!(
            r#"
backend: dummy
image_dir: {image_dir}
"#
        );
        serde_yaml::from_str(&yaml).unwrap()
    }

    #[test]
    fn arch_defaults_to_aarch64() {
        let v = minimal_vm("/x");
        assert_eq!(v.arch(), Arch::Aarch64);
    }

    #[test]
    fn arch_parses_from_arch_field() {
        let y = r#"backend: dummy
image_dir: /x
arch: amd64
"#;
        let v: VmDefinition = serde_yaml::from_str(y).unwrap();
        assert_eq!(v.arch(), Arch::X86_64);
    }

    #[test]
    fn shutdown_timeout_has_sensible_default() {
        let v = minimal_vm("/x");
        let t = v.shutdown_timeout_secs();
        assert!(t > 0 && t <= 120, "sane default in seconds, got {t}");
    }

    #[test]
    fn ssh_port_absent_when_no_ssh_device() {
        let v = minimal_vm("/x");
        assert_eq!(v.ssh_port(), None);
    }

    // -----------------------------------------------------------------
    // Arch methods
    // -----------------------------------------------------------------

    #[test]
    fn arch_from_str_accepts_common_aliases() {
        for s in ["amd64", "x86_64"] {
            assert_eq!(Arch::from_str(s), Some(Arch::X86_64), "{s}");
        }
        for s in ["aarch64", "arm64"] {
            assert_eq!(Arch::from_str(s), Some(Arch::Aarch64), "{s}");
        }
        assert_eq!(Arch::from_str("ppc64"), None);
    }

    #[test]
    fn arch_provides_qemu_binary_and_machine_type() {
        // Smoke: values are non-empty for both supported arches.
        for a in &[Arch::X86_64, Arch::Aarch64] {
            assert!(!a.qemu_binary().is_empty());
            assert!(!a.machine_type().is_empty());
            assert!(!a.default_cpu().is_empty());
            assert!(!a.console_device().is_empty());
        }
    }

    // -----------------------------------------------------------------
    // Backend + OsType enums
    // -----------------------------------------------------------------

    #[test]
    fn backend_type_deserializes_snake_case() {
        for (s, want) in [
            ("qemu", BackendType::Qemu),
            ("qnx", BackendType::Qnx),
            ("dummy", BackendType::Dummy),
        ] {
            let yaml = format!("backend: {s}\nimage_dir: /x\n");
            let v: VmDefinition = serde_yaml::from_str(&yaml).unwrap();
            assert!(std::mem::discriminant(&v.backend) == std::mem::discriminant(&want));
        }
    }

    #[test]
    fn os_type_defaults_to_linux() {
        let v = minimal_vm("/x");
        assert!(matches!(v.os_type, OsType::Linux));
    }

    // -----------------------------------------------------------------
    // VmBankConfig::from_dir — positive + negative
    // -----------------------------------------------------------------

    #[test]
    fn bank_config_from_dir_rejects_malformed_yaml() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("vm-config.yaml"), "this: is: broken::").unwrap();
        // Malformed yaml → from_dir returns None rather than panicking.
        assert!(VmBankConfig::from_dir(dir.path()).is_none());
    }
}
