//! Host-side device simulators for virtual CAN, health, and time.
//!
//! Abstracts transport (ivshmem vs QNX native shm) and clock (real-time
//! vs simulation stepping vs gPTP) so the same device code runs on both
//! Linux/QEMU development and QNX production hosts.

pub mod clock;
#[cfg(target_os = "linux")]
pub mod qmp;
pub mod regs;
pub mod transport;

// Heartbeat (guest → host liveness signal) and power-command (host → guest
// shutdown/reboot/suspend) devices, both built on top of `DeviceChannel`.
// Sensor publishing was previously here as `HealthDevice` — deleted; sensor
// data now flows via host-side OpenTelemetry, not host↔guest shmem.
#[cfg(feature = "health")]
pub mod heartbeat;
#[cfg(feature = "health")]
pub mod power;

#[cfg(feature = "time")]
pub mod time;

#[cfg(feature = "can")]
pub mod can;
