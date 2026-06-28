//! Platform-specific `SensorReader` implementations.
//!
//! Picked by `host_metrics::default_reader()` based on `target_os`.
//! Production hardware readers (board-specific, like NXP S32G3) live
//! outside this crate — in the host machine manager — and implement
//! the same trait. They typically wrap the platform default and add
//! board-specific metrics on top.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxSensorReader;

#[cfg(target_os = "nto")]
pub mod qnx;
#[cfg(target_os = "nto")]
pub use qnx::QnxSensorReader;
