//! Serving: the transport (HTTPS from the HSM-held tls-identity leaf, else
//! HTTP), the mDNS advertisement, the bind, and the graceful shutdown the
//! binary's signal, restart or reset paths trigger.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;

use crate::ShellConfig;

/// How long [`SovdListener::serve`] lets in-flight connections drain after the
/// shutdown notify before it closes them, so a client holding one open cannot
/// hold back the mDNS goodbye or the binary's cleanup.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Advertise the host SOVD endpoint over mDNS / DNS-SD (ISO 17978-3 §5.11) when
/// `sovd_mdns` is on. The `configured` identification (see
/// [`crate::configured_identification`]), if any, is prepended to `identities` (see
/// `sovd_mdns::SovdAdvertiser::new` for how they resolve). A failure is logged
/// and the server carries on undiscoverable; hold the returned guard for the
/// server's lifetime.
fn start_mdns(
    cfg: &ShellConfig,
    configured: Option<&str>,
    identities: &[sovd_mdns::Identity<'_>],
    scheme: sovd_mdns::Scheme,
) -> Option<sovd_mdns::AdvertiserGuard> {
    if !cfg.sovd_mdns {
        return None;
    }
    let ids: Vec<sovd_mdns::Identity<'_>> = configured
        .map(sovd_mdns::Identity::Configured)
        .into_iter()
        .chain(identities.iter().cloned())
        .collect();
    let Some(adv) = sovd_mdns::SovdAdvertiser::new(&ids, scheme, &cfg.bind) else {
        tracing::warn!(scheme = %scheme, "SOVD mDNS: no identity or bind port — not advertising");
        return None;
    };
    match adv.start() {
        Ok(g) => Some(g),
        Err(e) => {
            tracing::warn!(error = %e, "SOVD mDNS advertise failed");
            None
        }
    }
}

/// SIGTERM/SIGINT → notify the `shutdown` channel. This lets the server
/// drain, then the binary's `main` falls through to its cleanup. Without this
/// the default tokio signal disposition exits the process immediately and any
/// child processes are orphaned, taking their listening sockets with them.
pub fn shutdown_on_signals(shutdown: Arc<Notify>) {
    use tokio::signal::unix::{signal, SignalKind};
    let shutdown_for_signal = shutdown.clone();
    tokio::spawn(async move {
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "could not install SIGTERM handler");
                return;
            }
        };
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "could not install SIGINT handler");
                return;
            }
        };
        tokio::select! {
            _ = sigterm.recv() => tracing::info!("received SIGTERM — initiating graceful shutdown"),
            _ = sigint.recv()  => tracing::info!("received SIGINT — initiating graceful shutdown"),
        }
        shutdown_for_signal.notify_one();
    });
}

/// The SOVD server's transport, chosen and bound by [`SovdListener::bind`],
/// with the mDNS advertisement for it.
pub struct SovdListener {
    transport: Transport,
    bind: String,
    mdns: Option<sovd_mdns::AdvertiserGuard>,
}

enum Transport {
    Http(tokio::net::TcpListener),
    Https(axum_server::tls_rustls::RustlsConfig),
}

impl SovdListener {
    /// Server-only SOVD-over-TLS using the HSM-held tls-identity leaf — the
    /// client authenticates with an operator token, not a client cert; the
    /// link-B backend signs the handshake (through `crypto`) and the private key
    /// never leaves the HSM. Best-effort: HTTPS only once the tls-identity leaf
    /// is provisioned. Until then (first-boot provisioning) HTTP — the very flow
    /// that installs the leaf (CSR enrollment + keystore install) runs over this
    /// SOVD path, so it can't require the cert it's about to deliver. The server
    /// never restarts itself: the transport switch is an activation effect of
    /// the hsm keystore update (`ResetKind::RequiresEcuReset`), and the tester
    /// issues the node restart that lights up HTTPS.
    ///
    /// Every server advertises over mDNS (when `sovd_mdns`): HTTPS with the leaf
    /// identity, or HTTP with the configured `identification` / OS hostname.
    /// `Err` is the bind failure, worded for the operator.
    pub async fn bind(
        cfg: &ShellConfig,
        crypto: &Arc<dyn hsm::HsmCryptoProvider>,
        identification: Option<&str>,
    ) -> Result<Self, String> {
        // mDNS/DNS-SD advertiser guard — held for the server's lifetime,
        // unregisters on drop.
        let mut mdns: Option<sovd_mdns::AdvertiserGuard> = None;
        let tls_config: Option<axum_server::tls_rustls::RustlsConfig> = if cfg.sovd_tls {
            match crypto.get_certificate_der(hsm::KeyRole::TlsIdentity.handle()) {
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "sovd_tls set but the tls-identity leaf isn't provisioned yet — serving HTTP \
                         (provisioning runs over the SOVD path)"
                    );
                    None
                }
                Ok(leaf) => {
                    // Advertise the SOVD endpoint over mDNS (ISO 17978-3 §5.11):
                    // instance/hostname come from this leaf's `<id>.local` SAN, so a
                    // discovery client dialing `<id>.local` verifies this cert.
                    mdns = start_mdns(
                        cfg,
                        identification,
                        &[
                            sovd_mdns::Identity::Leaf(&leaf),
                            sovd_mdns::Identity::Hostname,
                        ],
                        sovd_mdns::Scheme::Https,
                    );
                    let signer = crypto.clone();
                    let sign_fn = move |msg: &[u8]| {
                        signer
                            .sign(hsm::KeyRole::TlsIdentity.handle(), msg)
                            .map_err(|e| e.to_string())
                    };
                    let tls_cfg = hsm_rustls::server_config_no_client_auth(leaf, sign_fn);
                    Some(axum_server::tls_rustls::RustlsConfig::from_config(
                        Arc::new(tls_cfg),
                    ))
                }
            }
        } else {
            None
        };
        if tls_config.is_none() {
            mdns = start_mdns(
                cfg,
                identification,
                &[sovd_mdns::Identity::Hostname],
                sovd_mdns::Scheme::Http,
            );
        }

        // Plain-HTTP listener only when TLS is off — axum_server binds the TLS
        // socket itself, so a pre-bound TcpListener would collide on the port.
        let transport = match tls_config {
            Some(tls_config) => Transport::Https(tls_config),
            None => Transport::Http(
                tokio::net::TcpListener::bind(&cfg.bind)
                    .await
                    .map_err(|e| format!("failed to bind to {}: {e}", cfg.bind))?,
            ),
        };
        Ok(Self {
            transport,
            bind: cfg.bind.clone(),
            mdns,
        })
    }

    /// Serving HTTPS (the tls-identity leaf is provisioned and `sovd_tls` on).
    pub fn is_tls(&self) -> bool {
        matches!(self.transport, Transport::Https(_))
    }

    /// Serve `router` until `shutdown` is notified, then drain in-flight
    /// requests for at most 5 s (`SHUTDOWN_GRACE`) and withdraw the mDNS
    /// advertisement (the DNS-SD goodbye is on the wire when this returns).
    /// `Err` is a TLS bind that is not `ip:port`; a server failure panics.
    pub async fn serve(self, router: axum::Router, shutdown: Arc<Notify>) -> Result<(), String> {
        match self.transport {
            Transport::Http(listener) => {
                // One task turns the notify into a watch, so both the graceful
                // shutdown and its cap see it (a Notify wakes one waiter).
                let (stop_tx, stop_rx) = tokio::sync::watch::channel(());
                tokio::spawn(async move {
                    shutdown.notified().await;
                    let _ = stop_tx.send(());
                });
                let mut graceful_rx = stop_rx.clone();
                let mut cap_rx = stop_rx;
                let serve = axum::serve(listener, router).with_graceful_shutdown(async move {
                    let _ = graceful_rx.changed().await;
                });
                tokio::select! {
                    result = serve => result.unwrap(),
                    _ = async {
                        let _ = cap_rx.changed().await;
                        tokio::time::sleep(SHUTDOWN_GRACE).await;
                    } => tracing::warn!("graceful shutdown timed out after 5 s; closing"),
                }
            }
            Transport::Https(tls_config) => {
                let addr: std::net::SocketAddr = self
                    .bind
                    .parse()
                    .map_err(|e| format!("sovd_tls: bind {} must be ip:port: {e}", self.bind))?;
                // axum_server has no `.with_graceful_shutdown(future)`; drive its
                // Handle from the same shutdown Notify so the binary's post-serve
                // cleanup still runs on SIGTERM / SIGINT / its own shutdowns.
                let handle = axum_server::Handle::new();
                let shutdown_handle = handle.clone();
                tokio::spawn(async move {
                    shutdown.notified().await;
                    shutdown_handle.graceful_shutdown(Some(SHUTDOWN_GRACE));
                });
                axum_server::bind_rustls(addr, tls_config)
                    .handle(handle)
                    .serve(router.into_make_service())
                    .await
                    .unwrap();
            }
        }
        // The goodbye: the guard's drop multicasts the TTL-0 records and blocks
        // (bounded) until they are sent, so a process exiting right after this
        // returns — `std::process::exit` runs no Drop — still withdraws it.
        drop(self.mdns);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hsm::{HsmError, KeyHandle, SlotInfo};
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// An HSM whose tls-identity leaf is not provisioned yet.
    struct NoLeaf;

    impl hsm::HsmCryptoProvider for NoLeaf {
        fn sign(&self, _: KeyHandle, _: &[u8]) -> Result<Vec<u8>, HsmError> {
            Err(HsmError::NotProvisioned)
        }
        fn verify(&self, _: KeyHandle, _: &[u8], _: &[u8]) -> Result<bool, HsmError> {
            Err(HsmError::NotProvisioned)
        }
        fn encrypt(&self, _: KeyHandle, _: &[u8]) -> Result<Vec<u8>, HsmError> {
            Err(HsmError::NotProvisioned)
        }
        fn decrypt(&self, _: KeyHandle, _: &[u8]) -> Result<Vec<u8>, HsmError> {
            Err(HsmError::NotProvisioned)
        }
        fn mac_generate(&self, _: KeyHandle, _: &[u8]) -> Result<Vec<u8>, HsmError> {
            Err(HsmError::NotProvisioned)
        }
        fn mac_verify(&self, _: KeyHandle, _: &[u8], _: &[u8]) -> Result<bool, HsmError> {
            Err(HsmError::NotProvisioned)
        }
        fn derive(&self, _: KeyHandle, _: &[u8], _: usize) -> Result<Vec<u8>, HsmError> {
            Err(HsmError::NotProvisioned)
        }
        fn random(&self, _: usize) -> Result<Vec<u8>, HsmError> {
            Err(HsmError::NotProvisioned)
        }
        fn get_certificate_der(&self, _: KeyHandle) -> Result<Vec<u8>, HsmError> {
            Err(HsmError::NotProvisioned)
        }
        fn get_public_key_der(&self, _: KeyHandle) -> Result<Vec<u8>, HsmError> {
            Err(HsmError::NotProvisioned)
        }
        fn get_slot_info(&self, _: KeyHandle) -> Result<SlotInfo, HsmError> {
            Err(HsmError::NotProvisioned)
        }
    }

    fn cfg(bind: &str) -> ShellConfig {
        serde_yaml::from_str(&format!("bind: \"{bind}\"\nsovd_mdns: false\n")).unwrap()
    }

    /// `sovd_tls` is on by default; without a leaf the server is HTTP, and
    /// a notified shutdown with no open connection ends `serve` promptly.
    #[tokio::test]
    async fn no_leaf_serves_http_until_shutdown() {
        let crypto: Arc<dyn hsm::HsmCryptoProvider> = Arc::new(NoLeaf);
        let listener = SovdListener::bind(&cfg("127.0.0.1:0"), &crypto, None)
            .await
            .unwrap();
        assert!(!listener.is_tls());
        let shutdown = Arc::new(Notify::new());
        shutdown.notify_one();
        let start = Instant::now();
        listener.serve(axum::Router::new(), shutdown).await.unwrap();
        let took = start.elapsed();
        assert!(took < Duration::from_secs(1), "{took:?}");
    }

    /// Serve `router` over HTTP on a free port: its address, the shutdown
    /// notify and the `serve` task.
    async fn serve_http(
        router: axum::Router,
    ) -> (
        std::net::SocketAddr,
        Arc<Notify>,
        tokio::task::JoinHandle<Result<(), String>>,
    ) {
        let crypto: Arc<dyn hsm::HsmCryptoProvider> = Arc::new(NoLeaf);
        let listener = SovdListener::bind(&cfg("127.0.0.1:0"), &crypto, None)
            .await
            .unwrap();
        let Transport::Http(l) = &listener.transport else {
            panic!("no leaf, so HTTP");
        };
        let addr = l.local_addr().unwrap();
        let shutdown = Arc::new(Notify::new());
        let task = tokio::spawn(listener.serve(router, shutdown.clone()));
        (addr, shutdown, task)
    }

    /// Notify `shutdown` and time how long `serve` takes to return.
    async fn shutdown_time(
        shutdown: &Notify,
        task: tokio::task::JoinHandle<Result<(), String>>,
    ) -> Duration {
        shutdown.notify_one();
        let start = Instant::now();
        tokio::time::timeout(SHUTDOWN_GRACE * 3, task)
            .await
            .expect("serve did not return")
            .unwrap()
            .unwrap();
        start.elapsed()
    }

    /// A client idling on a keep-alive connection after its response does not
    /// hold `serve` open.
    #[tokio::test]
    async fn an_idle_keep_alive_connection_does_not_hold_shutdown() {
        let router = axum::Router::new().route("/", axum::routing::get(|| async { "ok" }));
        let (addr, shutdown, task) = serve_http(router).await;
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        conn.write_all(b"GET / HTTP/1.1\r\nhost: t\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let n = conn.read(&mut buf).await.unwrap();
        assert!(buf[..n].starts_with(b"HTTP/1.1 200"), "{:?}", &buf[..n]);
        let took = shutdown_time(&shutdown, task).await;
        assert!(took < SHUTDOWN_GRACE + Duration::from_secs(1), "{took:?}");
        drop(conn);
    }

    /// A request that never completes holds the HTTP drain for 5 s, no longer.
    #[tokio::test]
    async fn a_held_http_request_is_cut_after_the_grace() {
        let entered = Arc::new(Notify::new());
        let router = axum::Router::new().route(
            "/hang",
            axum::routing::get({
                let entered = entered.clone();
                || async move {
                    entered.notify_one();
                    std::future::pending::<&str>().await
                }
            }),
        );
        let (addr, shutdown, task) = serve_http(router).await;
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        conn.write_all(b"GET /hang HTTP/1.1\r\nhost: t\r\n\r\n")
            .await
            .unwrap();
        entered.notified().await;
        let took = shutdown_time(&shutdown, task).await;
        assert!(took >= SHUTDOWN_GRACE, "{took:?}");
        assert!(took < SHUTDOWN_GRACE + Duration::from_secs(1), "{took:?}");
        drop(conn);
    }

    /// A TLS client that connected but never finishes its handshake (axum_server
    /// would wait out its 10 s handshake timeout) holds the drain for 5 s, no
    /// longer. The leaf is never read: no handshake gets that far.
    #[tokio::test]
    async fn a_held_tls_connection_is_cut_after_the_grace() {
        let addr = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let tls_cfg =
            hsm_rustls::server_config_no_client_auth(Vec::new(), |_| Err("no key".to_string()));
        let listener = SovdListener {
            transport: Transport::Https(axum_server::tls_rustls::RustlsConfig::from_config(
                Arc::new(tls_cfg),
            )),
            bind: addr.to_string(),
            mdns: None,
        };
        let shutdown = Arc::new(Notify::new());
        let task = tokio::spawn(listener.serve(axum::Router::new(), shutdown.clone()));
        let conn = loop {
            match tokio::net::TcpStream::connect(addr).await {
                Ok(c) => break c,
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        };
        // Let the accept loop take the connection and park again: axum_server's
        // graceful shutdown only wakes a loop that is waiting.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let took = shutdown_time(&shutdown, task).await;
        assert!(took >= SHUTDOWN_GRACE, "{took:?}");
        assert!(took < SHUTDOWN_GRACE + Duration::from_secs(1), "{took:?}");
        drop(conn);
    }

    #[tokio::test]
    async fn a_bind_failure_names_the_address() {
        let crypto: Arc<dyn hsm::HsmCryptoProvider> = Arc::new(NoLeaf);
        let Err(e) = SovdListener::bind(&cfg("not-an-address"), &crypto, None).await else {
            panic!("bound to nothing");
        };
        assert!(e.starts_with("failed to bind to not-an-address: "), "{e}");
    }
}
