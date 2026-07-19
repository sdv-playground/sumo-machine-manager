//! Generic vm-service-stop [`Deactivator`] — the enactment step of
//! administratively disabling a VM component.
//!
//! Built by component-factory for every bank-type component that has a
//! vm-service behind it (`vm_service_addr`), so a VM is disableable by
//! construction — no name list anywhere. Activator-backed components (RT)
//! get their deactivator injected by the deployment instead; `hsm`/`app`
//! never get one.
//!
//! `POST /vms/{name}/stop` over raw HTTP/1.1 on loopback TCP — the same wire
//! shape as `ComponentBackend::notify_vm_service`, but **blocking**
//! (`std::net`): [`Deactivator::deactivate`] is a sync trait method (mirroring
//! `BankActivator`), and the async caller runs it under
//! `tokio::task::spawn_blocking`. Unlike `/start`/`/restart` (which reply 200
//! the moment the recycle is queued), vm-service's `/stop` replies only after
//! the guest has actually exited (graceful window default 60 s, then
//! force-kill) — so the read timeout here must cover the full graceful
//! shutdown, and a 200 means the VM is genuinely down.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use machine_mgr::{DeactivateError, DeactivateOutcome, Deactivator};

/// Connect timeout — both ends are on loopback.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Response timeout — must exceed vm-service's graceful-shutdown ceiling
/// (default 60 s before force-kill) plus margin.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(90);

/// Stops a VM through vm-service. See the module docs.
pub struct VmDeactivator {
    /// vm-service control address (`host:port`, loopback).
    vm_service_addr: String,
    /// The VM's name in vm-service's `vms:` map (== the component id).
    vm_name: String,
}

impl VmDeactivator {
    pub fn new(vm_service_addr: String, vm_name: String) -> Self {
        Self {
            vm_service_addr,
            vm_name,
        }
    }
}

impl Deactivator for VmDeactivator {
    fn deactivate(&self) -> Result<DeactivateOutcome, DeactivateError> {
        let addr: std::net::SocketAddr = self
            .vm_service_addr
            .parse()
            .map_err(|e| DeactivateError::Failed(format!("bad vm-service addr: {e}")))?;
        let mut stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
            .map_err(|e| DeactivateError::Failed(format!("connect to vm-service: {e}")))?;
        stream.set_read_timeout(Some(RESPONSE_TIMEOUT))?;
        stream.set_write_timeout(Some(CONNECT_TIMEOUT))?;

        let request = format!(
            "POST /vms/{}/stop HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Length: 0\r\n\
             Connection: close\r\n\
             \r\n",
            self.vm_name
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| DeactivateError::Failed(format!("write to vm-service: {e}")))?;

        let mut buf = [0u8; 128];
        let n = stream
            .read(&mut buf)
            .map_err(|e| DeactivateError::Failed(format!("read from vm-service: {e}")))?;
        let resp = String::from_utf8_lossy(&buf[..n]);
        let status_line = resp.lines().next().unwrap_or("(empty)");

        // 200 = stopped. 409 = vm-service's NotRunning conflict — the VM is
        // already down, which IS the desired state, so deactivation has
        // converged (idempotent enact). Anything else is a real failure.
        if status_line.contains("200") || status_line.contains("409") {
            tracing::info!(
                vm = %self.vm_name,
                status = %status_line,
                "vm-service stop enacted (administrative disable)"
            );
            // A VM stop is immediate — nothing about it waits for a node
            // reset (unlike the RT erase deactivator).
            Ok(DeactivateOutcome {
                reboot_required: false,
            })
        } else {
            Err(DeactivateError::Failed(format!(
                "vm-service returned: {status_line}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serve exactly one connection with a canned status line on an
    /// ephemeral loopback port; return (addr, join-handle yielding the
    /// request bytes seen).
    fn one_shot_server(status_line: &'static str) -> (String, std::thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 512];
            let n = stream.read(&mut buf).unwrap();
            stream
                .write_all(format!("{status_line}\r\nContent-Length: 0\r\n\r\n").as_bytes())
                .unwrap();
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        (addr, handle)
    }

    #[test]
    fn posts_stop_and_succeeds_on_200() {
        let (addr, seen) = one_shot_server("HTTP/1.1 200 OK");
        let d = VmDeactivator::new(addr, "vm2".into());
        let out = d.deactivate().expect("200 = stopped");
        assert!(!out.reboot_required, "a VM stop never needs a node reset");
        let request = seen.join().unwrap();
        assert!(
            request.starts_with("POST /vms/vm2/stop HTTP/1.1"),
            "must POST the stop route, got: {request}"
        );
    }

    #[test]
    fn already_stopped_409_is_converged_success() {
        // vm-service maps NotRunning to 409 — for a deactivation that IS the
        // desired state, so it must count as success (idempotent enact).
        let (addr, _seen) = one_shot_server("HTTP/1.1 409 Conflict");
        let d = VmDeactivator::new(addr, "vm1".into());
        let out = d.deactivate().expect("409 NotRunning = already stopped");
        assert!(!out.reboot_required);
    }

    #[test]
    fn server_error_is_a_failure() {
        let (addr, _seen) = one_shot_server("HTTP/1.1 500 Internal Server Error");
        let d = VmDeactivator::new(addr, "vm1".into());
        let err = d.deactivate().expect_err("500 must fail the enact");
        assert!(err.to_string().contains("500"), "{err}");
    }

    #[test]
    fn unreachable_vm_service_is_a_failure() {
        // Bind-then-drop yields a port with nothing listening.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let d = VmDeactivator::new(format!("127.0.0.1:{port}"), "vm1".into());
        assert!(d.deactivate().is_err());
    }
}
