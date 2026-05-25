/// VM profile configuration — declares what a VM needs, independent of platform.
///
/// Parsed from TOML. The boot backend translates this into platform-specific
/// actions (QEMU args, qvm config, host-side processes).
///
/// Top-level YAML config (`VmMgrConfig`) declares which components exist and
/// their backend type (qemu, dummy, qnx). Each QEMU component references
/// an existing VmProfile TOML for device-level configuration.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use serde::Deserialize;

// =============================================================================
// Architecture abstraction
// =============================================================================

/// Target architecture for a VM. Drives QEMU binary selection, machine type,
/// console device, virtio transport, and disk enumeration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    Aarch64,
    X86_64,
}

impl Arch {
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

    /// Virtio device name: ARM virt uses MMIO transport (`-device`),
    /// x86 q35 uses PCI transport (`-pci`).
    pub fn virtio_device(&self, kind: &str) -> String {
        match self {
            Arch::Aarch64 => format!("virtio-{kind}-device"),
            Arch::X86_64 => format!("virtio-{kind}-pci"),
        }
    }

    /// Whether disk enumeration is reversed (ARM virt MMIO quirk).
    /// On aarch64, the last-attached virtio-blk becomes /dev/vda.
    /// On x86_64, the first-attached virtio-blk becomes /dev/vda.
    pub fn reverse_disk_order(&self) -> bool {
        match self {
            Arch::Aarch64 => true,
            Arch::X86_64 => false,
        }
    }

    /// Whether KVM is available for this guest architecture on the current host.
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
// VM profile (TOML)
// =============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct VmProfile {
    pub vm: VmConfig,
    #[serde(default)]
    pub devices: Vec<DeviceConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VmConfig {
    pub bank_set: String, // "hypervisor", "vm1", "vm2", "hsm"
    /// Target architecture: "aarch64" (default) or "x86_64"
    #[serde(default)]
    pub arch: Option<String>,
    #[serde(default = "default_ram")]
    pub ram_mb: u32,
    #[serde(default = "default_cpus")]
    pub cpus: u32,
    /// CPU model override. If unset, uses arch default (cortex-a76 / max).
    #[serde(default)]
    pub cpu_model: Option<String>,
    /// Kernel image path (relative to output dir or absolute)
    #[serde(default)]
    pub kernel: Option<String>,
    /// Extra kernel cmdline arguments
    #[serde(default)]
    pub extra_cmdline: Option<String>,
}

fn default_ram() -> u32 { 2048 }
fn default_cpus() -> u32 { 4 }

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum DeviceConfig {
    #[serde(rename = "can")]
    Can {
        #[serde(default)]
        index: u8,
        #[serde(default = "default_backend")]
        backend: String,
        /// Host CAN interface for passthrough mode
        #[serde(default)]
        interface: Option<String>,
    },
    #[serde(rename = "health")]
    Health {
        #[serde(default = "default_backend")]
        backend: String,
    },
    #[serde(rename = "time")]
    Time {
        #[serde(default = "default_backend")]
        backend: String,
    },
    #[serde(rename = "hsm")]
    Hsm {
        /// Keystore path
        #[serde(default)]
        keystore: Option<String>,
        #[serde(default)]
        keygen_bin: Option<String>,
        #[serde(default = "default_hsm_port")]
        port: u16,
    },
    #[serde(rename = "network")]
    Network {
        #[serde(default)]
        mac: Option<String>,
        #[serde(default)]
        ssh_port: Option<u16>,
    },
    #[serde(rename = "disk")]
    Disk {
        role: String, // "rootfs", "data", "swap"
        path: String,
        #[serde(default)]
        readonly: bool,
    },
    #[serde(rename = "console")]
    Console,
}

fn default_backend() -> String { "simulated".to_string() }
fn default_hsm_port() -> u16 { 5100 }

impl DeviceConfig {
    /// Whether this device uses ivshmem shared memory for host-guest communication.
    /// Health and Time always do. CAN does unless host-passthrough.
    pub fn needs_ivshmem(&self) -> bool {
        match self {
            DeviceConfig::Health { .. } => true,
            DeviceConfig::Time { .. } => true,
            DeviceConfig::Can { backend, .. } => backend != "host-passthrough",
            _ => false,
        }
    }

    /// Whether to start a host-side simulator process for this device.
    pub fn needs_simulator(&self) -> bool {
        match self {
            DeviceConfig::Health { backend }
            | DeviceConfig::Time { backend }
            | DeviceConfig::Can { backend, .. } => backend == "simulated",
            _ => false,
        }
    }

    /// The ivshmem shared memory label (used for socket/shm naming).
    pub fn ivshmem_label(&self) -> Option<String> {
        match self {
            DeviceConfig::Health { .. } if self.needs_ivshmem() => Some("health".into()),
            DeviceConfig::Time { .. } if self.needs_ivshmem() => Some("time".into()),
            DeviceConfig::Can { index, .. } if self.needs_ivshmem() => Some(format!("can{index}")),
            _ => None,
        }
    }

    /// Magic value written at offset 0 of shared memory so guest drivers
    /// can identify which ivshmem device is which (all share PCI ID 0x1af4:0x1110).
    pub fn ivshmem_magic(&self) -> Option<u32> {
        match self {
            DeviceConfig::Health { .. } => Some(0x48544C48), // "HLTH"
            DeviceConfig::Time { .. } => Some(0x54494D45),   // "TIME"
            DeviceConfig::Can { .. } => Some(0x4E414356),    // "VCAN"
            _ => None,
        }
    }
}

impl VmProfile {
    pub fn from_toml(content: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(content)
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        Self::from_toml(&content)
            .map_err(|e| format!("failed to parse {}: {e}", path.display()))
    }

    /// Resolve target architecture (defaults to Aarch64).
    pub fn arch(&self) -> Arch {
        self.vm.arch.as_deref()
            .and_then(Arch::from_str)
            .unwrap_or(Arch::Aarch64)
    }

    /// Count CAN interfaces
    pub fn can_count(&self) -> u8 {
        self.devices.iter().filter(|d| matches!(d, DeviceConfig::Can { .. })).count() as u8
    }

    /// Get SSH port if any network device has one
    pub fn ssh_port(&self) -> Option<u16> {
        self.devices.iter().find_map(|d| match d {
            DeviceConfig::Network { ssh_port, .. } => *ssh_port,
            _ => None,
        })
    }
}

// =============================================================================
// Top-level YAML config — declares all managed components and their backends
// =============================================================================

/// Top-level vm-mgr configuration. Declares which components exist,
/// what backend manages each, and shared paths.
#[derive(Debug, Clone, Deserialize)]
pub struct VmMgrConfig {
    /// Path to the NV store file/device.
    pub nv_store: PathBuf,
    /// Directory containing bank images ({set}-{bank}.img).
    pub images_dir: PathBuf,
    /// Per-component configuration, keyed by component ID (e.g., "vm1", "hsm").
    pub components: HashMap<String, ComponentEntry>,
}

/// Configuration for a single managed component.
#[derive(Debug, Clone, Deserialize)]
pub struct ComponentEntry {
    /// Bank set name: "hypervisor", "vm1", "vm2", "hsm".
    pub bank_set: String,
    /// Backend type: "qemu", "dummy", "qnx".
    #[serde(default = "default_component_backend")]
    pub backend: String,
    /// Path to VmProfile TOML (required for qemu backend).
    #[serde(default)]
    pub profile: Option<PathBuf>,
    /// Simulator binary directory (optional, qemu only).
    #[serde(default)]
    pub sim_dir: Option<PathBuf>,
    /// Whether this is a single-bank component (e.g., HSM).
    #[serde(default)]
    pub single_bank: bool,
    /// Graceful shutdown configuration.
    #[serde(default)]
    pub shutdown: Option<ShutdownConfig>,
    /// Readiness detection configuration.
    #[serde(default)]
    pub readiness: Option<ReadinessConfig>,
}

fn default_component_backend() -> String { "dummy".to_string() }

/// How to gracefully shut down a VM before force-killing.
#[derive(Debug, Clone, Deserialize)]
pub struct ShutdownConfig {
    /// Seconds to wait for graceful shutdown before force-kill.
    #[serde(default = "default_shutdown_timeout")]
    pub timeout_secs: u64,
    /// Shutdown signaling method: "health" (ivshmem), "none".
    #[serde(default = "default_shutdown_method")]
    pub method: String,
}

// 60s — Linux systemd shutdown takes 5-30s on managed-cvc; was 10s,
// which always force-killed before linux finished. Mirror of the
// vm-service default; both knobs read the same env-name.
fn default_shutdown_timeout() -> u64 { 60 }
fn default_shutdown_method() -> String { "health".to_string() }

/// How to detect when a VM is ready after start.
#[derive(Debug, Clone, Deserialize)]
pub struct ReadinessConfig {
    /// Readiness detection method: "health" (ivshmem), "none".
    #[serde(default = "default_readiness_method")]
    pub method: String,
    /// Seconds to wait for readiness before giving up.
    #[serde(default = "default_readiness_timeout")]
    pub timeout_secs: u64,
}

fn default_readiness_method() -> String { "health".to_string() }
fn default_readiness_timeout() -> u64 { 30 }

impl VmMgrConfig {
    pub fn from_yaml(content: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(content)
    }

    pub fn from_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        Self::from_yaml(&content)
            .map_err(|e| format!("failed to parse {}: {e}", path.display()))
    }
}
