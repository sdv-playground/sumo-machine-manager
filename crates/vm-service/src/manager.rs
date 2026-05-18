//! VM lifecycle manager — owns runners + per-VM device handles.
//!
//! `VmManager` opens `HeartbeatDevice` + `PowerCommandDevice` channels
//! when a VM starts and drops them when it stops. The lifetime is tied
//! to the VM process because the qvm-shmem transport's libhyp handles
//! belong to a specific qvm process — when qvm restarts (e.g. after an
//! ECU reset), the host must release its old handle and attach to the
//! fresh region the new qvm registers. For transports whose backing
//! state is independent of the VM process (HTTP, ivshmem files, mem),
//! `DeviceTransport::release_vm` is a no-op so this lifecycle is
//! cheap.
//!
//! Runners are thin wrappers around the VM process (qvm / qemu / dummy)
//! — they no longer construct their own shmem regions or sensor sims.
//! All host-side device I/O flows through `DeviceChannel`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use vm_devices::clock::{system::SystemClock, Clock};
use vm_devices::heartbeat::{GuestState, HeartbeatDevice, HEARTBEAT_WIRE_SIZE};
use vm_devices::power::{PowerCommand, PowerCommandDevice, POWER_WIRE_SIZE};
use vm_devices::regs::time as vtime_regs;
use vm_devices::time::{TimeDevice, TIME_DEFAULT_INTERVAL};
use vm_devices::transport::DeviceTransport;

use crate::config::{BackendType, VmBankConfig, VmDefinition, VmServiceConfig};
use crate::health_status::{HealthDetail, HealthStatus};
use crate::runner::dummy::DummyRunner;
#[cfg(target_os = "linux")]
use crate::runner::qemu::QemuRunner;
use crate::runner::qnx::QnxRunner;
use crate::runner::{RunnerError, VmHandle, VmRunner};

/// How long a stale heartbeat is tolerated before declaring `Unhealthy`.
const HEARTBEAT_STALE_AFTER: Duration = Duration::from_secs(5);

/// Information about a single VM for API responses.
pub struct VmInfo {
    pub name: String,
    pub status: HealthStatus,
    pub pid: Option<u32>,
    pub backend: BackendType,
}

/// Per-VM liveness tracker: detects the heartbeat seq counter standing still.
struct HeartbeatLiveness {
    last_seq: Option<u32>,
    last_seq_change: Option<Instant>,
}

impl HeartbeatLiveness {
    fn new() -> Self {
        Self { last_seq: None, last_seq_change: None }
    }

    /// Update tracker with a freshly read seq. Returns `true` if the
    /// heartbeat is stale (seq hasn't changed within the configured window).
    fn observe(&mut self, seq: u32, now: Instant) -> bool {
        match self.last_seq {
            Some(prev) if prev == seq => self
                .last_seq_change
                .map(|when| now.duration_since(when) > HEARTBEAT_STALE_AFTER)
                .unwrap_or(false),
            _ => {
                self.last_seq = Some(seq);
                self.last_seq_change = Some(now);
                false
            }
        }
    }
}

struct ManagedVm {
    def: VmDefinition,
    runner: Box<dyn VmRunner>,
    handle: Option<VmHandle>,
    /// Guest → host heartbeat reader. `None` when no transport is
    /// configured or VM has no `health` device.
    heartbeat: Option<HeartbeatDevice>,
    /// Host → guest power command sender (shutdown / reboot / suspend).
    /// Same condition as `heartbeat`.
    power: Option<PowerCommandDevice>,
    /// Host → guest time-register publisher. Holds a background writer
    /// thread; dropped when the VM stops. `None` when no transport is
    /// configured or VM has no `time` device.
    time: Option<TimeDevice>,
    /// Liveness state for the heartbeat seq counter.
    liveness: HeartbeatLiveness,
}

pub struct VmManager {
    vms: HashMap<String, ManagedVm>,
    /// Used by `start_vm` to (re-)open device channels and by
    /// `finalize_stop` to release per-VM state — the qvm-shmem path
    /// in particular needs the cached Region dropped before the next
    /// qvm spawn, otherwise the host reads stale memory from the
    /// previous qvm process.
    device_transport: Option<Arc<dyn DeviceTransport>>,
    /// Time source published into per-VM TimeDevice channels. Defaults to
    /// `SystemClock` (host CLOCK_MONOTONIC + CLOCK_REALTIME). Override
    /// via `with_clock` — supernova selects gPTP / simulation per its
    /// startup config.
    clock_source: Arc<dyn Clock>,
    /// Optional pre-launch verification hook. Called from `start_vm`
    /// with `(vm_name, bank_dir)` AFTER per-bank config is loaded but
    /// BEFORE the runner spawns devb-loopback / qvm. Returning `Err`
    /// fails the start; the resolved bank dir is whatever
    /// `image_dir/current` points at, so the gate sees the actual
    /// content about to boot.
    ///
    /// Owned by supernova because the verify itself needs NV +
    /// HsmProvider, which vm-service doesn't depend on. Default is
    /// `None` (no gate; same behavior as before this was added).
    pre_launch_verify: Option<PreLaunchVerify>,
}

/// Closure type for [`VmManager::with_pre_launch_verify`].
///
/// Args: `(vm_name, bank_dir)`. Returns `Ok(())` to allow the launch,
/// `Err(message)` to refuse it. The closure is expected to log its own
/// outcome (timing, sig status, gen) — `start_vm` only adds a thin
/// failure breadcrumb on its end.
pub type PreLaunchVerify =
    Arc<dyn Fn(&str, &std::path::Path) -> Result<(), String> + Send + Sync>;

/// Returned by `initiate_stop` — carries enough info to wait for exit
/// without holding the manager lock.
pub struct StopHandle {
    #[allow(dead_code)]
    pub name: String,
    pub pid: Option<u32>,
    pub timeout_secs: u64,
}

/// Wait for a process to exit, polling with a timeout. No locks held.
pub fn wait_for_exit(pid: u32, timeout_secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    while Instant::now() < deadline {
        if unsafe { libc::kill(pid as i32, 0) != 0 } {
            return; // process gone
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    tracing::warn!("pid {pid} did not exit within {timeout_secs}s — will force-kill");
}

#[derive(Debug)]
pub enum ManagerError {
    NotFound(String),
    AlreadyRunning(String),
    NotRunning(String),
    Runner(RunnerError),
}

impl std::fmt::Display for ManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManagerError::NotFound(name) => write!(f, "VM not found: {name}"),
            ManagerError::AlreadyRunning(name) => write!(f, "VM already running: {name}"),
            ManagerError::NotRunning(name) => write!(f, "VM not running: {name}"),
            ManagerError::Runner(e) => write!(f, "runner error: {e}"),
        }
    }
}

impl From<RunnerError> for ManagerError {
    fn from(e: RunnerError) -> Self {
        ManagerError::Runner(e)
    }
}

// `with_clock` and `with_pre_launch_verify` are called by supernova-mm
// at startup; vm-service's own binary doesn't invoke them, so its
// dead-code pass flags them. Suppress here rather than on each method.
#[allow(dead_code)]
impl VmManager {
    /// Construct a manager from config alone. Builds the configured
    /// `DeviceTransport` internally (via `transport_setup::build_device_transport`)
    /// so callers — vm-service's main, supernova's embedding — don't have
    /// to plumb transport details through their own argument lists.
    /// Async because the HTTP transport variant binds + spawns its server
    /// during construction.
    pub async fn new(config: VmServiceConfig) -> Self {
        let device_transport_cfg = config.device_transport.clone();
        let device_transport =
            crate::transport_setup::build_device_transport(device_transport_cfg).await;
        Self::with_device_transport(config, device_transport)
    }

    /// Construct with an explicit `DeviceTransport`. Tests use this to
    /// inject a `MemTransport`; production code should prefer `new` so
    /// the configured transport is built consistently across callers.
    pub fn with_device_transport(
        config: VmServiceConfig,
        device_transport: Option<Arc<dyn DeviceTransport>>,
    ) -> Self {
        let mut vms = HashMap::new();

        for (name, def) in config.vms {
            let runner: Box<dyn VmRunner> = match def.backend {
                #[cfg(target_os = "linux")]
                BackendType::Qemu => {
                    let mut r = QemuRunner::new();
                    if let Some(ref sim_dir) = def.sim_dir {
                        r = r.ivshmem_bin(
                            sim_dir.join("ivshmem-server")
                                .exists()
                                .then(|| sim_dir.join("ivshmem-server"))
                                .unwrap_or_else(|| "ivshmem-server".into()),
                        );
                    }
                    Box::new(r)
                }
                #[cfg(not(target_os = "linux"))]
                BackendType::Qemu => {
                    tracing::warn!("QEMU backend not available on this platform, using dummy");
                    Box::new(DummyRunner::new())
                }
                BackendType::Qnx => Box::new(QnxRunner::new()),
                BackendType::Dummy => Box::new(DummyRunner::new()),
            };

            // Channels are opened lazily in `start_vm` so their lifetime
            // matches the VM process — see module docs.
            vms.insert(name, ManagedVm {
                def,
                runner,
                handle: None,
                heartbeat: None,
                power: None,
                time: None,
                liveness: HeartbeatLiveness::new(),
            });
        }

        Self {
            vms,
            device_transport,
            clock_source: Arc::new(SystemClock::new()),
            pre_launch_verify: None,
        }
    }

    /// Override the clock source used when publishing vtime registers.
    /// Default is `SystemClock`. Supernova calls this with `GptpClock`
    /// or `SimulationClock` based on its startup `time:` config.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock_source = clock;
        self
    }

    /// Install a closure called from `start_vm` after the per-bank
    /// config is loaded but before the runner spawns anything. Lets
    /// supernova plug in IVD verify (NV + HSM live in supernova, not
    /// here) without vm-service taking a crypto dependency.
    pub fn with_pre_launch_verify(mut self, hook: PreLaunchVerify) -> Self {
        self.pre_launch_verify = Some(hook);
        self
    }

    pub fn start_vm(&mut self, name: &str) -> Result<(), ManagerError> {
        let vm = self.vms.get_mut(name)
            .ok_or_else(|| ManagerError::NotFound(name.to_string()))?;

        if vm.handle.is_some() {
            // Check if still actually running
            if let Some(ref handle) = vm.handle {
                if vm.runner.is_running(handle) {
                    return Err(ManagerError::AlreadyRunning(name.to_string()));
                }
            }
            // Was running but exited — clean up
            vm.runner.cleanup();
            vm.handle = None;
        }

        // Defense in depth: drop any device channels left from a previous
        // qvm process. finalize_stop is the canonical release path, but
        // covering this here protects against asymmetric stop paths
        // (process crashed, started without going through stop_vm).
        vm.heartbeat = None;
        vm.power = None;
        vm.time = None; // Drop signals the writer thread to exit on next tick.
        if let Some(ref tx) = self.device_transport {
            tx.release_vm(name);
        }

        // Reset liveness so a stale-from-prior-boot reading doesn't carry over.
        vm.liveness = HeartbeatLiveness::new();

        // Read per-bank config if available (image_dir resolves through current symlink)
        let effective_def = match VmBankConfig::from_dir(&vm.def.image_dir) {
            Some(bank_config) => {
                tracing::info!("loaded per-bank config for {name} from {}/vm-config.yaml",
                    vm.def.image_dir.display());
                vm.def.with_bank_overrides(&bank_config)
            }
            None => vm.def.clone(),
        };

        // Release any resources from a previous lifetime that would
        // block the pre-launch verify (devb-loopback holding rootfs.img
        // open → EBUSY on read). No-op for runners without per-VM
        // host-side state; QnxRunner slays orphan qvm + loopback here.
        vm.runner.prepare_for_launch(name, &effective_def);

        // Pre-launch verify gate — supernova installs this to run IVD
        // verify against the bank that `image_dir/current` points at.
        // The hook owns its own per-call logging (timing, gen, sig
        // status).
        //
        // CURRENT POLICY: log-only. Verify still runs and reports
        // good/bad with timing, but failure does NOT refuse to start.
        // Reason: autosd's systemd-remount-fs upgrades rootfs.img to
        // r/w during boot, so the file's bytes legitimately diverge
        // from the manifest's claim on subsequent boots. Switching
        // back to fail-closed needs read-only rootfs + overlay (or
        // dm-verity) — tracked in
        // tasks/launch-time-verify-mutable-rootfs.md.
        if let Some(ref verify) = self.pre_launch_verify {
            let started = Instant::now();
            match verify(name, &effective_def.image_dir) {
                Ok(()) => {
                    tracing::info!(
                        vm = name,
                        bank_dir = %effective_def.image_dir.display(),
                        verify_us = started.elapsed().as_micros() as u64,
                        "pre-launch verify OK",
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        vm = name,
                        bank_dir = %effective_def.image_dir.display(),
                        verify_us = started.elapsed().as_micros() as u64,
                        error = %e,
                        "pre-launch verify FAILED — continuing anyway (log-only policy; \
                         see tasks/launch-time-verify-mutable-rootfs.md)",
                    );
                }
            }
        }

        // Don't start if boot images are missing (e.g. first boot before provisioning)
        if let Some(kernel) = effective_def.kernel_path() {
            if !kernel.exists() {
                tracing::warn!("VM {name}: kernel not found: {} — deferring start", kernel.display());
                return Err(ManagerError::Runner(
                    crate::runner::RunnerError::Config(format!("kernel not found: {}", kernel.display()))
                ));
            }
        }

        // Open device channels for the new VM lifetime. This must happen
        // BEFORE runner.start spawns qvm — qvm-shmem regions are
        // host-registered (via libhyp factory) and qvm attaches to the
        // existing region by name. For ivshmem-file transports the file
        // must exist before QEMU mmaps it. Both are satisfied by opening
        // here.
        let has_health = effective_def.devices.iter()
            .any(|d| matches!(d, crate::config::DeviceConfig::Health { .. }));
        if has_health {
            if let Some(ref tx) = self.device_transport {
                match (
                    tx.open_channel(name, "heartbeat", "data", HEARTBEAT_WIRE_SIZE),
                    tx.open_channel(name, "power", "cmd", POWER_WIRE_SIZE),
                ) {
                    (Ok(hb_ch), Ok(pw_ch)) => {
                        vm.heartbeat = Some(HeartbeatDevice::new(hb_ch));
                        vm.power = Some(PowerCommandDevice::new(pw_ch));
                    }
                    (hb_res, pw_res) => {
                        if let Err(e) = hb_res { tracing::warn!("VM {name}: heartbeat channel open failed: {e}"); }
                        if let Err(e) = pw_res { tracing::warn!("VM {name}: power channel open failed: {e}"); }
                    }
                }
            } else {
                tracing::warn!(
                    "VM {name}: health device declared but no device_transport configured \
                     — heartbeat unavailable"
                );
            }
        }

        // Time device — host periodically writes vtime registers into a
        // shared region; guest's vtime driver reads them and disciplines
        // local CLOCK_REALTIME. Single 128-byte bidirectional channel:
        // host writes regs (0x00-0x3F) + status reply (0x40-0x7F),
        // guest writes TIME_ADJUST commands via the peer slot.
        let has_time = effective_def.devices.iter()
            .any(|d| matches!(d, crate::config::DeviceConfig::Time { .. }));
        if has_time {
            if let Some(ref tx) = self.device_transport {
                match tx.open_channel(name, "time", "regs", vtime_regs::REGION_SIZE) {
                    Ok(ch) => {
                        vm.time = Some(TimeDevice::new(
                            ch,
                            self.clock_source.clone(),
                            TIME_DEFAULT_INTERVAL,
                        ));
                        tracing::info!("VM {name}: vtime publisher started");
                    }
                    Err(e) => {
                        tracing::warn!("VM {name}: time channel open failed: {e}");
                    }
                }
            } else {
                tracing::warn!(
                    "VM {name}: time device declared but no device_transport configured \
                     — vtime unavailable"
                );
            }
        }

        let handle = vm.runner.start(name, &effective_def)?;
        tracing::info!("started VM {name} (pid: {:?})", handle.pid);
        vm.handle = Some(handle);
        Ok(())
    }

    /// Signal a VM to stop. Returns the PID and timeout for the caller to
    /// wait on *without* holding the manager lock. Call `finalize_stop` after.
    pub fn initiate_stop(&mut self, name: &str) -> Result<StopHandle, ManagerError> {
        let vm = self.vms.get_mut(name)
            .ok_or_else(|| ManagerError::NotFound(name.to_string()))?;

        let handle = vm.handle.as_ref()
            .ok_or_else(|| ManagerError::NotRunning(name.to_string()))?;

        if !vm.runner.is_running(handle) {
            vm.runner.cleanup();
            vm.handle = None;
            return Ok(StopHandle { name: name.to_string(), pid: None, timeout_secs: 0 });
        }

        // Send PowerCommand::Shutdown via the host→guest power channel.
        // If no power device exists (no transport configured / no health
        // device), skip the graceful wait and force-kill immediately.
        let timeout_secs = match vm.power.as_ref().map(|p| p.send(PowerCommand::Shutdown)) {
            Some(Ok(_seq)) => vm.def.shutdown_timeout_secs(),
            Some(Err(e)) => {
                tracing::warn!("VM {name}: failed to send shutdown command: {e} — force-kill");
                0
            }
            None => 0,
        };

        let pid = handle.pid;
        tracing::info!("signalled shutdown for VM {name} (pid: {pid:?}, timeout: {timeout_secs}s)");

        Ok(StopHandle { name: name.to_string(), pid, timeout_secs })
    }

    /// Finalize stop: force-kill if still running, clean up resources.
    /// Call after waiting for the process to exit (outside the lock).
    pub fn finalize_stop(&mut self, name: &str) {
        if let Some(vm) = self.vms.get_mut(name) {
            if let Some(ref handle) = vm.handle {
                if vm.runner.is_running(handle) {
                    let _ = vm.runner.stop(handle);
                }
            }
            vm.runner.cleanup();
            vm.handle = None;

            // Drop the device channels — the VM process is gone, so any
            // libhyp Region handles bound to it are stale. Order matters:
            // ManagedVm holds Arcs, so its references must drop before
            // the transport's `release_vm` for the underlying Region to
            // fully release. All three clears are needed.
            vm.heartbeat = None;
            vm.power = None;
            vm.time = None; // Drop signals the writer thread to exit on next tick.
            if let Some(ref tx) = self.device_transport {
                tx.release_vm(name);
            }

            tracing::info!("stopped VM {name}");
        }
    }

    /// Blocking stop (for daemon shutdown and restart). Holds the lock
    /// for the full duration — only use when lock contention doesn't matter.
    pub fn stop_vm(&mut self, name: &str) -> Result<(), ManagerError> {
        let sh = self.initiate_stop(name)?;
        if let Some(pid) = sh.pid {
            wait_for_exit(pid, sh.timeout_secs);
        }
        self.finalize_stop(name);
        Ok(())
    }

    #[allow(dead_code)]
    pub fn restart_vm(&mut self, name: &str) -> Result<(), ManagerError> {
        // Stop if running (ignore NotRunning)
        match self.stop_vm(name) {
            Ok(()) | Err(ManagerError::NotRunning(_)) => {}
            Err(e) => return Err(e),
        }
        self.start_vm(name)
    }

    #[allow(dead_code)]
    pub fn health(&mut self, name: &str) -> Result<HealthStatus, ManagerError> {
        Ok(self.health_detail(name)?.status)
    }

    /// Compute current health from process state + most-recent heartbeat.
    pub fn health_detail(&mut self, name: &str) -> Result<HealthDetail, ManagerError> {
        let vm = self.vms.get_mut(name)
            .ok_or_else(|| ManagerError::NotFound(name.to_string()))?;

        Ok(read_health(vm))
    }

    pub fn list(&mut self) -> Vec<VmInfo> {
        self.vms.iter_mut().map(|(name, vm)| {
            let detail = read_health(vm);
            let pid = vm.handle.as_ref().and_then(|h| h.pid);
            VmInfo {
                name: name.clone(),
                status: detail.status,
                pid: if matches!(detail.status, HealthStatus::Stopped) { None } else { pid },
                backend: vm.def.backend,
            }
        }).collect()
    }

    /// Stop all running VMs (for graceful daemon shutdown).
    pub fn stop_all(&mut self) {
        let names: Vec<String> = self.vms.keys().cloned().collect();
        for name in names {
            if let Err(e) = self.stop_vm(&name) {
                tracing::warn!("failed to stop VM {name}: {e}");
            }
        }
    }
}

/// Compute current `HealthDetail`. Pulled out so `health_detail` and `list`
/// share one mapping and the same liveness-tracker mutation rules.
fn read_health(vm: &mut ManagedVm) -> HealthDetail {
    let empty = HealthDetail { status: HealthStatus::Stopped, guest_state: None, hb_seq: None, boot_id: None };

    // Process state takes precedence — a Stopped VM has no live heartbeat.
    let handle = match &vm.handle {
        Some(h) => h,
        None => return empty,
    };
    if !vm.runner.is_running(handle) {
        return empty;
    }

    // No heartbeat device wired up — process is up, can't say more.
    let Some(ref hb_dev) = vm.heartbeat else {
        return HealthDetail { status: HealthStatus::Running, ..empty };
    };

    // Read heartbeat. None = guest hasn't written yet, or wire is bad.
    let Some(hb) = hb_dev.read() else {
        return HealthDetail { status: HealthStatus::Starting, ..empty };
    };

    let stale = vm.liveness.observe(hb.seq, Instant::now());
    let status = if stale {
        HealthStatus::Unhealthy
    } else {
        match hb.state {
            GuestState::Booting => HealthStatus::Starting,
            GuestState::Running => HealthStatus::Running,
            GuestState::Degraded => HealthStatus::Unhealthy,
            GuestState::ShuttingDown => HealthStatus::ShuttingDown,
        }
    };

    HealthDetail {
        status,
        guest_state: Some(hb.state as u32),
        hb_seq: Some(hb.seq),
        boot_id: Some(hb.boot_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn liveness_marks_stale_after_window() {
        let mut l = HeartbeatLiveness::new();
        let t0 = Instant::now();
        // First observation — establishes baseline, never stale.
        assert!(!l.observe(5, t0));
        // Same seq within window — not stale.
        assert!(!l.observe(5, t0 + Duration::from_secs(2)));
        // Same seq past window — stale.
        assert!(l.observe(5, t0 + HEARTBEAT_STALE_AFTER + Duration::from_secs(1)));
        // New seq resets the timer — not stale.
        let t1 = t0 + HEARTBEAT_STALE_AFTER + Duration::from_secs(2);
        assert!(!l.observe(6, t1));
    }
}
