//! Serving: the transport (HTTPS from the HSM-held tls-identity leaf, else
//! HTTP), the mDNS advertisement, the bind, and the graceful shutdown the
//! binary's signal, restart or reset paths trigger.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::sync::Notify;

use crate::ShellConfig;

/// How long [`SovdListener::serve`] lets in-flight connections drain after the
/// shutdown notify before it closes them, so a client holding one open cannot
/// hold back the mDNS goodbye or the binary's cleanup. The switch from HTTP to
/// HTTPS drains the HTTP connections for as long.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// How often a server on HTTP with `sovd_tls` on looks whether it may switch to
/// HTTPS: the tls-identity leaf is provisioned and the binary's gate
/// ([`SovdListener::switch_when`]) allows it (see [`SovdListener::serve`]).
const SWITCH_POLL: Duration = Duration::from_secs(2);

/// When a server may switch to HTTPS once the leaf is there; see
/// [`SovdListener::switch_when`].
pub type SwitchGate = Arc<dyn Fn() -> bool + Send + Sync>;

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
    mdns: Advertisement,
    /// For a server on HTTP with `sovd_tls` on: what it needs to switch to
    /// HTTPS once the tls-identity leaf is provisioned.
    upgrade: Option<Upgrade>,
    /// Whether HTTPS is being served; see [`SovdListener::tls_live`].
    tls_live: Arc<std::sync::atomic::AtomicBool>,
}

/// What a [`SovdListener`] on HTTP switches to HTTPS with.
struct Upgrade {
    cfg: ShellConfig,
    crypto: Arc<dyn hsm::HsmCryptoProvider>,
    identification: Option<String>,
    poll: Duration,
    gate: SwitchGate,
}

/// The HTTPS transport for the tls-identity leaf, or `None` while it is not
/// provisioned. The link-B backend signs the handshake (through `crypto`); the
/// private key never leaves the HSM.
fn tls_config(
    crypto: &Arc<dyn hsm::HsmCryptoProvider>,
) -> Option<(Vec<u8>, axum_server::tls_rustls::RustlsConfig)> {
    let leaf = crypto
        .get_certificate_der(hsm::KeyRole::TlsIdentity.handle())
        .ok()?;
    let signer = crypto.clone();
    let sign_fn = move |msg: &[u8]| {
        signer
            .sign(hsm::KeyRole::TlsIdentity.handle(), msg)
            .map_err(|e| e.to_string())
    };
    let tls_cfg = hsm_rustls::server_config_no_client_auth(leaf.clone(), sign_fn);
    Some((
        leaf,
        axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls_cfg)),
    ))
}

/// The HTTPS advertisement: instance and hostname from the leaf's `<id>.local`
/// SAN, so a discovery client dialing `<id>.local` verifies this cert.
fn https_mdns(
    cfg: &ShellConfig,
    identification: Option<&str>,
    leaf: &[u8],
) -> Option<sovd_mdns::AdvertiserGuard> {
    start_mdns(
        cfg,
        identification,
        &[
            sovd_mdns::Identity::Leaf(leaf),
            sovd_mdns::Identity::Hostname,
        ],
        sovd_mdns::Scheme::Https,
    )
}

/// How the HTTP phase of [`SovdListener::serve`] ended.
enum HttpEnd {
    Shutdown,
    /// The leaf appeared: serve HTTPS with it on the same address.
    Upgrade(
        Vec<u8>,
        axum_server::tls_rustls::RustlsConfig,
        std::net::SocketAddr,
    ),
}

/// A [`SovdListener`]'s mDNS advertisement, shared between its `serve` and the
/// binary (see [`SovdListener::advertisement`]): whichever withdraws it first
/// sends the DNS-SD goodbye.
#[derive(Clone)]
pub struct Advertisement(Arc<Mutex<Option<sovd_mdns::AdvertiserGuard>>>);

impl Advertisement {
    /// Withdraw the advertisement now: the guard's drop multicasts the TTL-0
    /// records and blocks (bounded, about 1 s) until they are sent. Idempotent;
    /// a no-op when mDNS is off. The guard is dropped under the lock, so a
    /// concurrent call returns only once the goodbye is on the wire.
    pub fn withdraw(&self) {
        let mut guard = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        *guard = None;
    }
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
    /// SOVD path, so it can't require the cert it's about to deliver. Once the
    /// keystore install brings the leaf and the binary's gate allows it
    /// ([`switch_when`](Self::switch_when): the update that brought it is over),
    /// [`serve`](Self::serve) switches to HTTPS on the same port by itself,
    /// without a restart: the hsm keystore update needs no reset (`ResetKind::None`).
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
            match tls_config(crypto) {
                None => {
                    tracing::warn!(
                        "sovd_tls set but the tls-identity leaf isn't provisioned yet — serving HTTP \
                         until it is (provisioning runs over the SOVD path)"
                    );
                    None
                }
                Some((leaf, config)) => {
                    // Advertise the SOVD endpoint over mDNS (ISO 17978-3 §5.11).
                    mdns = https_mdns(cfg, identification, &leaf);
                    Some(config)
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
        let upgrade = (cfg.sovd_tls && tls_config.is_none()).then(|| Upgrade {
            cfg: cfg.clone(),
            crypto: crypto.clone(),
            identification: identification.map(str::to_owned),
            poll: SWITCH_POLL,
            gate: Arc::new(|| true),
        });
        let tls_live = Arc::new(std::sync::atomic::AtomicBool::new(tls_config.is_some()));
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
            mdns: Advertisement(Arc::new(Mutex::new(mdns))),
            upgrade,
            tls_live,
        })
    }

    /// Switch to HTTPS only while `gate` says so, besides the leaf being there:
    /// the binary's say on when the switch may come. A keystore install brings
    /// the leaf in the middle of its update, and a client whose server changes
    /// transport mid-session loses it, so a node gates the switch on that
    /// update being over (its DELETE, the last call of an x-update). Without a
    /// gate the switch comes as soon as the leaf is there.
    pub fn switch_when(mut self, gate: SwitchGate) -> Self {
        if let Some(upgrade) = self.upgrade.as_mut() {
            upgrade.gate = gate;
        }
        self
    }

    /// Set while HTTPS is served: from the bind, or from the switch. A binary
    /// that keeps its authorization open for the run that provisions the device
    /// (no token can come over plain HTTP) closes it with this, so token checks
    /// and TLS come together.
    pub fn tls_live(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.tls_live.clone()
    }

    /// The handle that withdraws this server's mDNS advertisement — for a
    /// reset path that ends the process without the shutdown notify, so
    /// `serve` never returns: call [`Advertisement::withdraw`] just before it.
    pub fn advertisement(&self) -> Advertisement {
        self.mdns.clone()
    }

    /// Serving HTTPS (the tls-identity leaf is provisioned and `sovd_tls` on).
    pub fn is_tls(&self) -> bool {
        matches!(self.transport, Transport::Https(_))
    }

    /// Serve `router` until `shutdown` is notified, then drain in-flight
    /// requests for at most 5 s (`SHUTDOWN_GRACE`) and withdraw the mDNS
    /// advertisement (the DNS-SD goodbye is on the wire when this returns,
    /// unless an [`Advertisement::withdraw`] already sent it).
    ///
    /// A server on HTTP with `sovd_tls` on looks every 2 s (`SWITCH_POLL`)
    /// whether the tls-identity leaf is provisioned and the gate
    /// ([`switch_when`](Self::switch_when)) allows the switch. Then it drains its
    /// HTTP connections as for a shutdown, withdraws the HTTP advertisement,
    /// announces HTTPS, serves it on the same port and sets
    /// [`tls_live`](Self::tls_live): the process, and every update session it
    /// holds, carries on.
    /// `Err` is a TLS bind that is not `ip:port`, or a failed rebind for HTTPS;
    /// a server failure panics.
    pub async fn serve(self, router: axum::Router, shutdown: Arc<Notify>) -> Result<(), String> {
        // One task turns the notify into a watch, so every phase, its graceful
        // shutdown and its cap see it (a Notify wakes one waiter).
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            shutdown.notified().await;
            let _ = stop_tx.send(true);
        });
        let result = match self.transport {
            Transport::Http(listener) => {
                match serve_http(
                    listener,
                    router.clone(),
                    stop_rx.clone(),
                    self.upgrade.as_ref(),
                )
                .await
                {
                    HttpEnd::Shutdown => Ok(()),
                    HttpEnd::Upgrade(leaf, config, addr) => {
                        let upgrade = self
                            .upgrade
                            .as_ref()
                            .expect("an upgrade comes from its settings");
                        // The HTTP goodbye first, then the HTTPS announcement.
                        self.mdns.withdraw();
                        let guard =
                            https_mdns(&upgrade.cfg, upgrade.identification.as_deref(), &leaf);
                        *self.mdns.0.lock().unwrap_or_else(PoisonError::into_inner) = guard;
                        tracing::info!(%addr, "the tls-identity leaf is provisioned — serving HTTPS");
                        let listener = rebind(addr)?;
                        self.tls_live
                            .store(true, std::sync::atomic::Ordering::SeqCst);
                        serve_https(
                            axum_server::from_tcp_rustls(listener, config),
                            router,
                            stop_rx,
                        )
                        .await;
                        Ok(())
                    }
                }
            }
            Transport::Https(tls_config) => {
                let addr: std::net::SocketAddr = self
                    .bind
                    .parse()
                    .map_err(|e| format!("sovd_tls: bind {} must be ip:port: {e}", self.bind))?;
                serve_https(axum_server::bind_rustls(addr, tls_config), router, stop_rx).await;
                Ok(())
            }
        };
        // The goodbye: sent (bounded) before this returns, so a process exiting
        // right after — `std::process::exit` runs no Drop — still withdraws it.
        self.mdns.withdraw();
        result
    }
}

/// Serve HTTP on `listener` until the shutdown, or, with an `upgrade`, until the
/// tls-identity leaf is provisioned; then drain for at most `SHUTDOWN_GRACE`.
async fn serve_http(
    listener: tokio::net::TcpListener,
    router: axum::Router,
    stop_rx: tokio::sync::watch::Receiver<bool>,
    upgrade: Option<&Upgrade>,
) -> HttpEnd {
    let addr = listener.local_addr().ok();
    let (switch_tx, switch_rx) = tokio::sync::watch::channel(None);
    if let (Some(upgrade), Some(addr)) = (upgrade, addr) {
        let crypto = upgrade.crypto.clone();
        let poll = upgrade.poll;
        let gate = upgrade.gate.clone();
        let mut stopped = stop_rx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stopped.changed() => return,
                    _ = tokio::time::sleep(poll) => {}
                }
                // The gate first: while it holds the switch back the leaf is not
                // read, so a gated node asks its HSM nothing.
                if !gate() {
                    continue;
                }
                if let Some((leaf, config)) = tls_config(&crypto) {
                    let _ = switch_tx.send(Some((leaf, config, addr)));
                    return;
                }
            }
        });
    }
    // Ends the HTTP phase: the shutdown, or the leaf.
    let ended = |mut stop: tokio::sync::watch::Receiver<bool>,
                 mut switch: tokio::sync::watch::Receiver<Option<_>>| async move {
        tokio::select! {
            _ = stop.wait_for(|stopped| *stopped) => {}
            _ = switch.wait_for(|leaf: &Option<_>| leaf.is_some()) => {}
        }
    };
    let serve = axum::serve(listener, router)
        .with_graceful_shutdown(ended(stop_rx.clone(), switch_rx.clone()));
    tokio::select! {
        result = serve => result.unwrap(),
        _ = async {
            ended(stop_rx.clone(), switch_rx.clone()).await;
            tokio::time::sleep(SHUTDOWN_GRACE).await;
        } => tracing::warn!("HTTP drain timed out after 5 s; closing"),
    }
    if *stop_rx.borrow() {
        return HttpEnd::Shutdown;
    }
    let leaf = switch_rx.borrow().clone();
    match leaf {
        Some((leaf, config, addr)) => HttpEnd::Upgrade(leaf, config, addr),
        None => HttpEnd::Shutdown,
    }
}

/// The HTTPS socket on the address the HTTP server just released, with
/// `SO_REUSEADDR`, as tokio binds the HTTP one.
fn rebind(addr: std::net::SocketAddr) -> Result<std::net::TcpListener, String> {
    let socket = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()
    } else {
        tokio::net::TcpSocket::new_v6()
    }
    .map_err(|e| format!("HTTPS socket for {addr}: {e}"))?;
    socket
        .set_reuseaddr(true)
        .map_err(|e| format!("HTTPS socket for {addr}: {e}"))?;
    socket
        .bind(addr)
        .map_err(|e| format!("failed to bind HTTPS to {addr}: {e}"))?;
    let listener = socket
        .listen(1024)
        .map_err(|e| format!("failed to listen for HTTPS on {addr}: {e}"))?;
    listener
        .into_std()
        .map_err(|e| format!("HTTPS listener on {addr}: {e}"))
}

/// Serve HTTPS with `server` until the shutdown, then drain for at most
/// `SHUTDOWN_GRACE`. axum_server has no `.with_graceful_shutdown(future)`;
/// its Handle is driven from the shutdown watch, so the binary's post-serve
/// cleanup still runs on SIGTERM / SIGINT / its own shutdowns.
async fn serve_https(
    server: axum_server::Server<axum_server::tls_rustls::RustlsAcceptor>,
    router: axum::Router,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
) {
    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        let _ = stop_rx.wait_for(|stopped| *stopped).await;
        shutdown_handle.graceful_shutdown(Some(SHUTDOWN_GRACE));
    });
    server
        .handle(handle)
        .serve(router.into_make_service())
        .await
        .unwrap();
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
            mdns: Advertisement(Arc::new(Mutex::new(None))),
            upgrade: None,
            tls_live: Arc::new(std::sync::atomic::AtomicBool::new(true)),
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

    /// An explicit withdraw — twice, from another thread while `serve` runs,
    /// with mDNS off — is a no-op for `serve`: its shutdown still returns
    /// promptly, and withdrawing after it is harmless.
    #[tokio::test]
    async fn withdrawing_while_serving_leaves_the_shutdown_intact() {
        let crypto: Arc<dyn hsm::HsmCryptoProvider> = Arc::new(NoLeaf);
        let listener = SovdListener::bind(&cfg("127.0.0.1:0"), &crypto, None)
            .await
            .unwrap();
        let advertisement = listener.advertisement();
        let shutdown = Arc::new(Notify::new());
        let task = tokio::spawn(listener.serve(axum::Router::new(), shutdown.clone()));
        let other = advertisement.clone();
        std::thread::spawn(move || {
            other.withdraw();
            other.withdraw();
        })
        .join()
        .unwrap();
        let took = shutdown_time(&shutdown, task).await;
        assert!(took < Duration::from_secs(1), "{took:?}");
        advertisement.withdraw();
    }

    /// An HSM whose tls-identity leaf appears when `provisioned` is set, as a
    /// keystore install brings it. The leaf is empty: no handshake gets far
    /// enough to need it.
    struct LeafLater(Arc<std::sync::atomic::AtomicBool>);

    impl hsm::HsmCryptoProvider for LeafLater {
        fn sign(&self, h: KeyHandle, m: &[u8]) -> Result<Vec<u8>, HsmError> {
            NoLeaf.sign(h, m)
        }
        fn verify(&self, h: KeyHandle, m: &[u8], s: &[u8]) -> Result<bool, HsmError> {
            NoLeaf.verify(h, m, s)
        }
        fn encrypt(&self, h: KeyHandle, m: &[u8]) -> Result<Vec<u8>, HsmError> {
            NoLeaf.encrypt(h, m)
        }
        fn decrypt(&self, h: KeyHandle, m: &[u8]) -> Result<Vec<u8>, HsmError> {
            NoLeaf.decrypt(h, m)
        }
        fn mac_generate(&self, h: KeyHandle, m: &[u8]) -> Result<Vec<u8>, HsmError> {
            NoLeaf.mac_generate(h, m)
        }
        fn mac_verify(&self, h: KeyHandle, m: &[u8], t: &[u8]) -> Result<bool, HsmError> {
            NoLeaf.mac_verify(h, m, t)
        }
        fn derive(&self, h: KeyHandle, c: &[u8], n: usize) -> Result<Vec<u8>, HsmError> {
            NoLeaf.derive(h, c, n)
        }
        fn random(&self, n: usize) -> Result<Vec<u8>, HsmError> {
            NoLeaf.random(n)
        }
        fn get_certificate_der(&self, h: KeyHandle) -> Result<Vec<u8>, HsmError> {
            if self.0.load(std::sync::atomic::Ordering::SeqCst) {
                Ok(Vec::new())
            } else {
                NoLeaf.get_certificate_der(h)
            }
        }
        fn get_public_key_der(&self, h: KeyHandle) -> Result<Vec<u8>, HsmError> {
            NoLeaf.get_public_key_der(h)
        }
        fn get_slot_info(&self, h: KeyHandle) -> Result<SlotInfo, HsmError> {
            NoLeaf.get_slot_info(h)
        }
    }

    /// What a plain HTTP `GET /` on a fresh connection to `addr` gets back,
    /// empty when the server closes it without an HTTP answer.
    async fn plain_get(addr: std::net::SocketAddr) -> Vec<u8> {
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        conn.write_all(b"GET / HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), conn.read_to_end(&mut buf)).await;
        buf
    }

    /// Without the leaf the server is HTTP, and with it too while the gate holds
    /// the switch back; once the gate allows it the server stops answering plain
    /// HTTP on that port, serves TLS there instead and reports HTTPS live,
    /// without `serve` returning; the shutdown still ends it.
    #[tokio::test]
    async fn switches_to_https_on_the_same_port_once_the_leaf_is_provisioned() {
        let provisioned = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let crypto: Arc<dyn hsm::HsmCryptoProvider> = Arc::new(LeafLater(provisioned.clone()));
        let open = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let gate = open.clone();
        let mut listener = SovdListener::bind(&cfg("127.0.0.1:0"), &crypto, None)
            .await
            .unwrap()
            .switch_when(Arc::new(move || {
                gate.load(std::sync::atomic::Ordering::SeqCst)
            }));
        assert!(!listener.is_tls());
        listener
            .upgrade
            .as_mut()
            .expect("sovd_tls on, so it may switch")
            .poll = Duration::from_millis(50);
        let tls_live = listener.tls_live();
        let Transport::Http(l) = &listener.transport else {
            panic!("no leaf, so HTTP");
        };
        let addr = l.local_addr().unwrap();
        let router = axum::Router::new().route("/", axum::routing::get(|| async { "ok" }));
        let shutdown = Arc::new(Notify::new());
        let task = tokio::spawn(listener.serve(router, shutdown.clone()));

        assert!(plain_get(addr).await.starts_with(b"HTTP/1.1 200"));

        // The leaf alone does not switch while the gate holds it back (its
        // update is still open).
        provisioned.store(true, std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            plain_get(addr).await.starts_with(b"HTTP/1.1 200"),
            "gated: still HTTP"
        );
        assert!(!tls_live.load(std::sync::atomic::Ordering::SeqCst));

        open.store(true, std::sync::atomic::Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let answer = match tokio::net::TcpStream::connect(addr).await {
                Ok(_) => plain_get(addr).await,
                Err(_) => b"HTTP/1.1 200".to_vec(), // between the two binds
            };
            if !answer.starts_with(b"HTTP/1.1 200") {
                break;
            }
            assert!(Instant::now() < deadline, "still plain HTTP after the leaf");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // A TLS ClientHello gets a TLS record back: the HTTPS server is there.
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        conn.write_all(&tls_client_hello()).await.unwrap();
        let mut head = [0u8; 1];
        tokio::time::timeout(Duration::from_secs(2), conn.read_exact(&mut head))
            .await
            .expect("an answer to the ClientHello")
            .unwrap();
        assert!(
            head[0] == 0x16 || head[0] == 0x15,
            "TLS handshake or alert record, got {head:?}"
        );
        assert!(!task.is_finished(), "the switch does not end serve");
        assert!(
            tls_live.load(std::sync::atomic::Ordering::SeqCst),
            "HTTPS is live"
        );

        let took = shutdown_time(&shutdown, task).await;
        assert!(took < SHUTDOWN_GRACE + Duration::from_secs(1), "{took:?}");
    }

    /// A minimal TLS 1.2 ClientHello record (no extensions, two suites).
    fn tls_client_hello() -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session id
        body.extend_from_slice(&[0x00, 0x04, 0xc0, 0x2b, 0xc0, 0x2f]); // suites
        body.extend_from_slice(&[0x01, 0x00]); // compression: null
        let mut handshake = vec![0x01];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    /// With `sovd_tls` off the server stays HTTP whatever the HSM holds.
    #[tokio::test]
    async fn with_sovd_tls_off_it_never_switches() {
        let crypto: Arc<dyn hsm::HsmCryptoProvider> = Arc::new(LeafLater(Arc::new(
            std::sync::atomic::AtomicBool::new(true),
        )));
        let off: ShellConfig =
            serde_yaml::from_str("bind: \"127.0.0.1:0\"\nsovd_mdns: false\nsovd_tls: false\n")
                .unwrap();
        let listener = SovdListener::bind(&off, &crypto, None).await.unwrap();
        assert!(!listener.is_tls());
        assert!(listener.upgrade.is_none());
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
