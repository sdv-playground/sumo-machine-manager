//! Standalone `host-metrics` binary — serves Prometheus `/metrics`.
//!
//! For dev / standalone deployments. In production, the host machine manager
//! embeds the same library and serves on its own bind with its
//! board-specific reader. Either way the wire format on `/metrics` is
//! identical — Prometheus / OTel collectors don't see a difference.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let bind_addr = parse_bind_arg();

    let reader = host_metrics::default_reader();
    let app = host_metrics::router(reader);

    let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to bind {bind_addr}: {e}");
            return ExitCode::from(1);
        }
    };

    tracing::info!("host-metrics listening on {bind_addr}, GET /metrics");

    let shutdown = async {
        let mut sigterm =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("failed to register SIGTERM: {e}");
                    return;
                }
            };
        tokio::select! {
            _ = sigterm.recv() => tracing::info!("SIGTERM"),
            _ = tokio::signal::ctrl_c() => tracing::info!("SIGINT"),
        }
    };

    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
    {
        tracing::error!("server error: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// Tiny CLI: `host-metrics --bind <addr>` (default `0.0.0.0:9300`).
fn parse_bind_arg() -> String {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 {
        return "0.0.0.0:9300".to_string();
    }
    match args[1].as_str() {
        "--bind" if args.len() >= 3 => args[2].clone(),
        "--help" | "-h" => {
            eprintln!("Usage: host-metrics [--bind <ip:port>]");
            eprintln!("  default bind: 0.0.0.0:9300");
            std::process::exit(0);
        }
        other => {
            eprintln!("unknown argument: {other}");
            eprintln!("Usage: host-metrics [--bind <ip:port>]");
            std::process::exit(1);
        }
    }
}
