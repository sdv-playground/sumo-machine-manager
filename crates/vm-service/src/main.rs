/// vm-service — VM lifecycle daemon.
///
/// Reads static YAML config at startup, exposes a control API on a Unix socket.
/// Knows nothing about firmware updates, banking, or diagnostics — just runs VMs.
///
/// Usage:
///   vm-service --config /etc/vm-service/config.yaml
mod api;
mod config;
mod health_status;
#[cfg(target_os = "linux")]
mod ivshmem;
mod manager;
mod runner;
mod transport_setup;

use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

fn parse_args() -> PathBuf {
    let args: Vec<String> = std::env::args().collect();
    let mut config_path = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                i += 1;
                config_path = args.get(i).map(PathBuf::from);
            }
            "--help" | "-h" => {
                eprintln!("Usage: vm-service --config <path.yaml>");
                std::process::exit(0);
            }
            other => {
                eprintln!("Unknown argument: {other}");
                eprintln!("Usage: vm-service --config <path.yaml>");
                std::process::exit(1);
            }
        }
        i += 1;
    }
    config_path.unwrap_or_else(|| {
        eprintln!("Usage: vm-service --config <path.yaml>");
        std::process::exit(1);
    })
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let config_path = parse_args();

    let config = match config::VmServiceConfig::from_file(&config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("failed to load config: {e}");
            std::process::exit(1);
        }
    };

    let bind_addr = config.bind.clone();
    let vm_count = config.vms.len();

    // Collect auto-start VM names before config is consumed
    let auto_start_vms: Vec<String> = config
        .vms
        .iter()
        .filter(|(_, def)| def.auto_start)
        .map(|(name, _)| name.clone())
        .collect();

    tracing::info!("loaded config: {} VMs, bind: {}", vm_count, bind_addr,);

    // VmManager builds the device-transport from `config.device_transport`
    // internally. supernova-machine-manager (which embeds VmManager
    // in-process) goes through the same constructor, so transport setup
    // is consistent across both binaries.
    let manager = Arc::new(Mutex::new(manager::VmManager::new(config).await));

    // Auto-start VMs that have auto_start: true
    if !auto_start_vms.is_empty() {
        let mut mgr = manager.lock().await;
        for name in &auto_start_vms {
            tracing::info!("auto-starting VM {name}");
            if let Err(e) = mgr.start_vm(name) {
                tracing::warn!("auto-start {name} failed: {e}");
            }
        }
    }

    let manager_shutdown = manager.clone();

    let app = api::router(manager);

    let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("failed to bind {bind_addr}: {e}");
            std::process::exit(1);
        }
    };

    tracing::info!("listening on {bind_addr}");

    // Graceful shutdown on SIGTERM/SIGINT
    let shutdown = async move {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM");

        tokio::select! {
            _ = sigterm.recv() => {
                tracing::info!("received SIGTERM");
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received SIGINT");
            }
        }

        tracing::info!("shutting down, stopping all VMs...");
        manager_shutdown.lock().await.stop_all();
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .unwrap();
}
