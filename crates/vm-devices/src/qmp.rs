//! QEMU Machine Protocol (QMP) client for vCPU control.
//!
//! QMP is JSON over a Unix socket. We use it to pause/resume vCPUs,
//! which freezes CLOCK_MONOTONIC inside the guest — making debugger
//! stepping across RT↔HP boundaries safe (no timeout expiry).
//!
//! Protocol:
//! 1. Connect to Unix socket
//! 2. Read greeting {"QMP": ...}
//! 3. Send {"execute": "qmp_capabilities"}
//! 4. Read {"return": {}}
//! 5. Now ready — send commands, read responses
//!
//! Commands we use:
//! - {"execute": "stop"}  → pause all vCPUs
//! - {"execute": "cont"}  → resume all vCPUs
//! - {"execute": "query-status"} → check if running/paused

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

/// QMP client connected to a QEMU instance.
pub struct QmpClient {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
}

#[derive(Debug)]
pub enum QmpError {
    Io(std::io::Error),
    Protocol(String),
}

impl std::fmt::Display for QmpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QmpError::Io(e) => write!(f, "QMP I/O: {e}"),
            QmpError::Protocol(e) => write!(f, "QMP protocol: {e}"),
        }
    }
}

impl std::error::Error for QmpError {}

impl From<std::io::Error> for QmpError {
    fn from(e: std::io::Error) -> Self {
        QmpError::Io(e)
    }
}

impl QmpClient {
    /// Connect to a QEMU QMP socket and complete the handshake.
    pub fn connect(socket_path: &Path) -> Result<Self, QmpError> {
        let stream = UnixStream::connect(socket_path)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        let reader = BufReader::new(stream.try_clone()?);

        let mut client = Self { stream, reader };

        // Read greeting
        let greeting = client.read_line()?;
        if !greeting.contains("\"QMP\"") {
            return Err(QmpError::Protocol(format!(
                "expected QMP greeting, got: {greeting}"
            )));
        }

        // Send capabilities negotiation
        client.send_command("qmp_capabilities")?;

        Ok(client)
    }

    /// Pause all guest vCPUs. CLOCK_MONOTONIC stops.
    pub fn stop(&mut self) -> Result<(), QmpError> {
        self.send_command("stop")
    }

    /// Resume all guest vCPUs.
    pub fn cont(&mut self) -> Result<(), QmpError> {
        self.send_command("cont")
    }

    /// Query if the guest is running or paused.
    pub fn is_running(&mut self) -> Result<bool, QmpError> {
        self.write_json(r#"{"execute": "query-status"}"#)?;
        let resp = self.read_line()?;
        // Response: {"return": {"running": true, "status": "running", ...}}
        Ok(resp.contains("\"running\":true") || resp.contains("\"running\": true"))
    }

    fn send_command(&mut self, cmd: &str) -> Result<(), QmpError> {
        let json = format!("{{\"execute\": \"{cmd}\"}}");
        self.write_json(&json)?;

        // Read response — may get events before the return
        loop {
            let line = self.read_line()?;
            if line.contains("\"return\"") {
                return Ok(());
            }
            if line.contains("\"error\"") {
                return Err(QmpError::Protocol(line));
            }
            // Event (e.g., STOP, RESUME) — skip and keep reading
        }
    }

    fn write_json(&mut self, json: &str) -> Result<(), QmpError> {
        self.stream.write_all(json.as_bytes())?;
        self.stream.write_all(b"\n")?;
        self.stream.flush()?;
        Ok(())
    }

    fn read_line(&mut self) -> Result<String, QmpError> {
        let mut line = String::new();
        self.reader.read_line(&mut line)?;
        if line.is_empty() {
            return Err(QmpError::Protocol("connection closed".into()));
        }
        Ok(line)
    }
}
