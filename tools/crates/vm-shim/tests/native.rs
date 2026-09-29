#![cfg(unix)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use vm_devices::transport::http::HttpTransport;
use vm_mgr::config::{Bank, VmServiceConfig};
use vm_mgr::health_status::HealthStatus;
use vm_mgr::manager::VmManager;

fn wait_for_status(manager: &mut VmManager, status: HealthStatus, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if manager.health("vm1").unwrap() == status {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "expected {status:?}, got {:?}",
        manager.health("vm1").unwrap()
    );
}

fn wait_for_new_boot(manager: &mut VmManager, previous: Option<u32>) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        let detail = manager.health_detail("vm1").unwrap();
        if detail.status == HealthStatus::Running {
            if let Some(id) = detail.boot_id.filter(|id| Some(*id) != previous) {
                return id;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("new shim never published its own healthy heartbeat");
}

#[tokio::test(flavor = "multi_thread")]
async fn shim_health_modes_and_shutdown_over_http() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("bank_a")).unwrap();
    for (mode, expected) in [
        ("healthy", HealthStatus::Running),
        ("never-ready", HealthStatus::Starting),
        ("stale-heartbeat", HealthStatus::Unhealthy),
        ("exit-immediately", HealthStatus::Failed),
    ] {
        let transport = Arc::new(HttpTransport::new(tokio::runtime::Handle::current()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = transport.router();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let config: VmServiceConfig = serde_yaml::from_str(&format!(
            "vms:\n  vm1:\n    backend: process\n    image_dir: {:?}\n    process_command: {:?}\n    process_args: [\"--host\", \"{addr}\", \"--mode\", \"{mode}\"]\n    devices:\n      - type: health\n        transport: http\n    shutdown:\n      timeout_secs: 1\n",
            root.path().display().to_string(),
            env!("CARGO_BIN_EXE_vm-shim")
        ))
        .unwrap();
        let mut manager = VmManager::with_device_transport(config, Some(transport.clone()));
        manager.set_vm_bank("vm1", Some(Bank::A)).unwrap();
        manager.start_vm("vm1").unwrap();
        wait_for_status(&mut manager, expected, Duration::from_secs(8));
        if mode == "healthy" {
            manager.initiate_stop("vm1").unwrap();
            wait_for_status(&mut manager, HealthStatus::Stopped, Duration::from_secs(3));
            manager.finalize_stop("vm1");
        } else if mode != "exit-immediately" {
            manager.stop_vm("vm1").unwrap();
        }
        server.abort();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn healthy_shim_restarts_on_the_same_transport_without_waiting_for_timeout() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("bank_a")).unwrap();
    let transport = Arc::new(HttpTransport::new(tokio::runtime::Handle::current()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = transport.router();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let config: VmServiceConfig = serde_yaml::from_str(&format!(
        "vms:\n  vm1:\n    backend: process\n    image_dir: {:?}\n    process_command: {:?}\n    process_args: [\"--host\", \"{addr}\", \"--mode\", \"healthy\"]\n    devices:\n      - type: health\n        transport: http\n    shutdown:\n      timeout_secs: 5\n",
        root.path().display().to_string(),
        env!("CARGO_BIN_EXE_vm-shim")
    ))
    .unwrap();
    let mut manager = VmManager::with_device_transport(config, Some(transport));
    manager.set_vm_bank("vm1", Some(Bank::A)).unwrap();
    let mut previous_boot_id = None;
    for _ in 0..2 {
        manager.start_vm("vm1").unwrap();
        previous_boot_id = Some(wait_for_new_boot(&mut manager, previous_boot_id));
        let started = Instant::now();
        manager.stop_vm("vm1").unwrap();
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    manager.start_vm("vm1").unwrap();
    wait_for_new_boot(&mut manager, previous_boot_id);
    let started = Instant::now();
    manager.stop_all_for_reboot(5);
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(manager.runtime_identity("vm1").is_none());
    server.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_heartbeat_waits_for_first_successful_delivery() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("bank_a")).unwrap();
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = reserved.local_addr().unwrap();
    drop(reserved);

    let transport = Arc::new(HttpTransport::new(tokio::runtime::Handle::current()));
    let config: VmServiceConfig = serde_yaml::from_str(&format!(
        "vms:\n  vm1:\n    backend: process\n    image_dir: {:?}\n    process_command: {:?}\n    process_args: [\"--host\", \"{addr}\", \"--mode\", \"stale-heartbeat\"]\n    devices:\n      - type: health\n        transport: http\n    shutdown:\n      timeout_secs: 1\n",
        root.path().display().to_string(),
        env!("CARGO_BIN_EXE_vm-shim")
    ))
    .unwrap();
    let mut manager = VmManager::with_device_transport(config, Some(transport.clone()));
    manager.set_vm_bank("vm1", Some(Bank::A)).unwrap();
    manager.start_vm("vm1").unwrap();

    tokio::time::sleep(Duration::from_millis(1500)).await;
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let router = transport.router();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    wait_for_status(&mut manager, HealthStatus::Running, Duration::from_secs(4));
    wait_for_status(
        &mut manager,
        HealthStatus::Unhealthy,
        Duration::from_secs(8),
    );
    manager.stop_vm("vm1").unwrap();
    server.abort();
}
