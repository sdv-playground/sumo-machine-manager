//! HTTP transport — universal fallback for cells where shmem isn't viable.
//!
//! Covers the qvm + Linux/Android matrix cell where there's no usable shared
//! memory mechanism without per-guest kernel work. Also a useful CI / dev
//! transport because it has zero hypervisor coupling.
//!
//! ## Architecture
//!
//! Host runs an axum server that exposes per-`(vm, device, channel)` HTTP
//! endpoints over the existing `vp0` virtio-net link. Guest is an HTTP
//! client (lives in `vm-guest-lib`, not in this crate).
//!
//! Endpoints (all under the host's bind addr, e.g. `10.0.100.1:9200`):
//!
//! - `PUT  /vm/{vm}/dev/{device}/ch/{channel}` — write a snapshot. Body
//!   bytes become the channel's current value. Always increments
//!   `notify_seq` (write implies the data changed; long-pollers wake).
//! - `GET  /vm/{vm}/dev/{device}/ch/{channel}` — read the most recent
//!   snapshot. Returns `404` if the channel hasn't been opened yet.
//! - `POST /vm/{vm}/dev/{device}/ch/{channel}/notify` — ring the doorbell
//!   without changing data (host-→guest "wake up" without a payload).
//! - `GET  /vm/{vm}/dev/{device}/ch/{channel}/wait?timeout=ms` — long-poll.
//!   Returns `200` + body when notified, `204` on timeout.
//!
//! ## Host-side `DeviceChannel` impl
//!
//! `HttpTransport::open_channel` returns an `HttpChannel` whose
//! `read`/`write`/`notify` go **directly** to the in-memory state — not via
//! the loopback HTTP server. The HTTP layer exists for the *guest* to talk
//! in; making the host loopback through HTTP would just burn CPU.
//!
//! The guest-side `DeviceChannel` impl lives in `vm-guest-lib` and uses an
//! HTTP client. Both impls share this file's wire format and `Notify`
//! semantics.
//!
//! ## Wait/notify semantics
//!
//! Backed by `tokio::sync::Notify`. `notify_waiters()` wakes all currently
//! parked waiters; a notify that fires before any `wait()` call does **not**
//! latch (matches `MemChannel` behaviour, documented there). Sync `wait()`
//! uses `Handle::block_on` — the channel must be called from a non-runtime
//! thread, otherwise the runtime deadlocks.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use tokio::sync::Notify;

use crate::transport::{DeviceChannel, DeviceTransport, TransportError};

/// `(vm, device, channel)` triple keying the channel registry.
type ChannelKey = (String, String, String);

/// Per-channel state — shared between the in-process `HttpChannel` handles
/// and the axum HTTP handlers serving the same channel to remote clients.
struct ChannelState {
    /// Last snapshot written (by either side). `Mutex` rather than
    /// `RwLock` because writes are short and we never read concurrently.
    data: Mutex<Vec<u8>>,
    /// Notify-on-write primitive. `notify_waiters` is called whenever
    /// `data` is replaced or `notify()` is explicitly invoked.
    notify: Notify,
}

impl ChannelState {
    fn new() -> Self {
        Self {
            data: Mutex::new(Vec::new()),
            notify: Notify::new(),
        }
    }
}

/// Shared registry of all channels under one `HttpTransport`. Lives in an
/// `Arc` so the axum handlers and the `HttpChannel` handles see the same map.
#[derive(Default)]
struct TransportState {
    channels: Mutex<HashMap<ChannelKey, Arc<ChannelState>>>,
}

impl TransportState {
    fn open(&self, key: ChannelKey) -> Arc<ChannelState> {
        let mut map = self
            .channels
            .lock()
            .expect("HttpTransport channels mutex poisoned");
        map.entry(key)
            .or_insert_with(|| Arc::new(ChannelState::new()))
            .clone()
    }

    fn get(&self, key: &ChannelKey) -> Option<Arc<ChannelState>> {
        self.channels
            .lock()
            .expect("HttpTransport channels mutex poisoned")
            .get(key)
            .cloned()
    }
}

/// Host-side `DeviceTransport` exposing channels over HTTP.
///
/// Construct with `HttpTransport::new(rt_handle)` so we can drive the
/// `tokio::sync::Notify` primitive from the sync `DeviceChannel::wait`
/// implementation. The runtime handle is also used by `bind_and_serve`
/// to spawn the axum server.
pub struct HttpTransport {
    state: Arc<TransportState>,
    rt: tokio::runtime::Handle,
}

impl HttpTransport {
    /// Construct an empty transport. No HTTP server is bound until
    /// `bind_and_serve` is called or the `router()` is mounted into an
    /// existing axum app.
    pub fn new(rt: tokio::runtime::Handle) -> Self {
        Self {
            state: Arc::new(TransportState::default()),
            rt,
        }
    }

    /// Returns an axum `Router` serving this transport's channels at the
    /// paths documented at the module level. Mount under a base path of
    /// your choice in vm-service's main router. Tests use this directly
    /// to bind on an ephemeral port.
    pub fn router(&self) -> Router {
        Router::new()
            .route(
                "/vm/{vm}/dev/{device}/ch/{channel}",
                get(handle_get).put(handle_put),
            )
            .route(
                "/vm/{vm}/dev/{device}/ch/{channel}/notify",
                post(handle_notify),
            )
            .route("/vm/{vm}/dev/{device}/ch/{channel}/wait", get(handle_wait))
            .with_state(self.state.clone())
    }
}

impl DeviceTransport for HttpTransport {
    fn open_channel(
        &self,
        vm: &str,
        device: &str,
        channel: &str,
        _size_hint: usize,
    ) -> Result<Arc<dyn DeviceChannel>, TransportError> {
        let key = (vm.to_string(), device.to_string(), channel.to_string());
        let ch_state = self.state.open(key);
        let http_channel = Arc::new(HttpChannel {
            state: ch_state,
            rt: self.rt.clone(),
        });
        Ok(http_channel as Arc<dyn DeviceChannel>)
    }
}

/// In-process `DeviceChannel` handle. Goes directly to `ChannelState`,
/// not via HTTP — see module docs for why.
pub struct HttpChannel {
    state: Arc<ChannelState>,
    rt: tokio::runtime::Handle,
}

impl DeviceChannel for HttpChannel {
    fn read(&self) -> Result<Vec<u8>, TransportError> {
        let data = self
            .state
            .data
            .lock()
            .expect("HttpChannel data mutex poisoned");
        Ok(data.clone())
    }

    fn write(&self, data: &[u8]) -> Result<(), TransportError> {
        {
            let mut buf = self
                .state
                .data
                .lock()
                .expect("HttpChannel data mutex poisoned");
            buf.clear();
            buf.extend_from_slice(data);
        }
        // PUT-by-host always wakes long-pollers — they're out there waiting
        // for new data and there *is* new data now.
        self.state.notify.notify_waiters();
        Ok(())
    }

    fn notify(&self) -> Result<(), TransportError> {
        self.state.notify.notify_waiters();
        Ok(())
    }

    fn wait(&self, timeout: Option<Duration>) -> Result<bool, TransportError> {
        let state = self.state.clone();
        match timeout {
            None => {
                self.rt.block_on(async move {
                    state.notify.notified().await;
                });
                Ok(true)
            }
            Some(dur) => {
                let result = self.rt.block_on(async move {
                    tokio::time::timeout(dur, state.notify.notified()).await
                });
                Ok(result.is_ok())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP handlers — drive the same TransportState the trait impls use.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ChannelPath {
    vm: String,
    device: String,
    channel: String,
}

impl ChannelPath {
    fn to_key(&self) -> ChannelKey {
        (self.vm.clone(), self.device.clone(), self.channel.clone())
    }
}

async fn handle_get(
    State(state): State<Arc<TransportState>>,
    Path(p): Path<ChannelPath>,
) -> Result<Vec<u8>, StatusCode> {
    match state.get(&p.to_key()) {
        Some(ch) => {
            let data = ch.data.lock().expect("data mutex poisoned");
            Ok(data.clone())
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn handle_put(
    State(state): State<Arc<TransportState>>,
    Path(p): Path<ChannelPath>,
    body: Bytes,
) -> StatusCode {
    let ch = state.open(p.to_key());
    {
        let mut data = ch.data.lock().expect("data mutex poisoned");
        data.clear();
        data.extend_from_slice(&body);
    }
    ch.notify.notify_waiters();
    StatusCode::NO_CONTENT
}

async fn handle_notify(
    State(state): State<Arc<TransportState>>,
    Path(p): Path<ChannelPath>,
) -> StatusCode {
    match state.get(&p.to_key()) {
        Some(ch) => {
            ch.notify.notify_waiters();
            StatusCode::NO_CONTENT
        }
        None => StatusCode::NOT_FOUND,
    }
}

#[derive(Deserialize)]
struct WaitQuery {
    /// Timeout in milliseconds. `0` means non-blocking poll. Capped at
    /// 60_000 (1 minute) to keep clients from holding sockets indefinitely.
    timeout: Option<u64>,
}

async fn handle_wait(
    State(state): State<Arc<TransportState>>,
    Path(p): Path<ChannelPath>,
    Query(q): Query<WaitQuery>,
) -> impl IntoResponse {
    let timeout_ms = q.timeout.unwrap_or(30_000).min(60_000);
    let timeout = Duration::from_millis(timeout_ms);
    let Some(ch) = state.get(&p.to_key()) else {
        return (StatusCode::NOT_FOUND, Vec::new());
    };

    let notified = tokio::time::timeout(timeout, ch.notify.notified()).await;
    if notified.is_ok() {
        let data = ch.data.lock().expect("data mutex poisoned");
        (StatusCode::OK, data.clone())
    } else {
        (StatusCode::NO_CONTENT, Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heartbeat::{GuestState, Heartbeat, HeartbeatDevice, HEARTBEAT_WIRE_SIZE};
    use crate::power::{PowerCommand, PowerCommandDevice, POWER_WIRE_SIZE};

    /// Build a transport on the current Tokio runtime. Must be called
    /// from a `#[tokio::test]` function (or with an explicit runtime).
    fn make_transport() -> HttpTransport {
        HttpTransport::new(tokio::runtime::Handle::current())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn open_channel_returns_same_handle_for_same_triple() {
        let t = make_transport();
        let a = t.open_channel("vm2", "hb", "data", 32).unwrap();
        let b = t.open_channel("vm2", "hb", "data", 32).unwrap();

        // Doing the actual write from a blocking context to avoid the
        // "block_on inside async" deadlock — write is sync but doesn't
        // block on the runtime. Same for read.
        a.write(&[42u8; 32]).unwrap();
        assert_eq!(b.read().unwrap(), vec![42u8; 32]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fresh_channel_read_returns_empty() {
        let t = make_transport();
        let ch = t.open_channel("vm2", "hb", "data", 32).unwrap();
        assert!(ch.read().unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_channel_drives_heartbeat_device() {
        let t = make_transport();
        let ch = t
            .open_channel("vm2", "heartbeat", "data", HEARTBEAT_WIRE_SIZE)
            .unwrap();
        let host = HeartbeatDevice::new(ch.clone());
        let guest = HeartbeatDevice::new(ch);

        let hb = Heartbeat {
            seq: 99,
            state: GuestState::Running,
            mono_ns: 555_000_000,
            flags: crate::heartbeat::HB_FLAG_SERVICES_READY,
            boot_id: 0xFEEDFACE,
        };
        guest.write(&hb).unwrap();
        assert_eq!(host.read().unwrap(), hb);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_channel_drives_power_command_device() {
        let t = make_transport();
        let ch = t
            .open_channel("vm2", "power", "cmd", POWER_WIRE_SIZE)
            .unwrap();
        let host = PowerCommandDevice::new(ch.clone());
        let guest = PowerCommandDevice::new(ch);

        let seq = host.send(PowerCommand::Reboot).unwrap();
        let frame = guest.read().unwrap();
        assert_eq!(frame.seq, seq);
        assert_eq!(frame.cmd, PowerCommand::Reboot);
    }

    // ---- HTTP-routing integration tests ----
    //
    // Bind axum on an ephemeral port, exercise the actual wire endpoints
    // with a hyper client. These tests prove the routes match the spec
    // and that the in-process state is the same state the HTTP handlers
    // see. Without this, we'd be testing the trait but not the wire
    // contract guests will speak.

    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes as HyperBytes;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    async fn bind_test_server(transport: &HttpTransport) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = transport.router();
        tokio::spawn(async move {
            // Server lifetime ties to the test — when the test ends and
            // the runtime drops, this task is cancelled.
            let _ = axum::serve(listener, router).await;
        });
        // Brief settle so the listener is accepting before clients connect.
        tokio::time::sleep(Duration::from_millis(10)).await;
        addr
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_put_then_get_roundtrip() {
        let t = make_transport();
        let addr = bind_test_server(&t).await;

        let client: Client<_, Full<HyperBytes>> =
            Client::builder(TokioExecutor::new()).build_http();
        let url = format!("http://{addr}/vm/vm2/dev/heartbeat/ch/data");

        // PUT
        let put_req = hyper::Request::builder()
            .method("PUT")
            .uri(&url)
            .body(Full::new(HyperBytes::from_static(&[1, 2, 3, 4])))
            .unwrap();
        let put_resp = client.request(put_req).await.unwrap();
        assert_eq!(put_resp.status(), StatusCode::NO_CONTENT);

        // GET
        let get_req = hyper::Request::builder()
            .method("GET")
            .uri(&url)
            .body(Full::new(HyperBytes::new()))
            .unwrap();
        let get_resp = client.request(get_req).await.unwrap();
        assert_eq!(get_resp.status(), StatusCode::OK);
        let body = get_resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), &[1, 2, 3, 4]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_get_unknown_channel_returns_404() {
        let t = make_transport();
        let addr = bind_test_server(&t).await;

        let client: Client<_, Full<HyperBytes>> =
            Client::builder(TokioExecutor::new()).build_http();
        let url = format!("http://{addr}/vm/nope/dev/nope/ch/nope");
        let get_req = hyper::Request::builder()
            .method("GET")
            .uri(&url)
            .body(Full::new(HyperBytes::new()))
            .unwrap();
        let resp = client.request(get_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_wait_returns_204_on_timeout() {
        let t = make_transport();
        // Pre-create the channel so wait gets past the 404 check.
        let _ch = t.open_channel("vm2", "hb", "data", 32).unwrap();
        let addr = bind_test_server(&t).await;

        let client: Client<_, Full<HyperBytes>> =
            Client::builder(TokioExecutor::new()).build_http();
        let url = format!("http://{addr}/vm/vm2/dev/hb/ch/data/wait?timeout=50");
        let req = hyper::Request::builder()
            .method("GET")
            .uri(&url)
            .body(Full::new(HyperBytes::new()))
            .unwrap();
        let resp = client.request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn http_wait_returns_data_on_notify() {
        let t = make_transport();
        let ch = t.open_channel("vm2", "hb", "data", 32).unwrap();
        let addr = bind_test_server(&t).await;

        // Spawn the long-poll first.
        let url = format!("http://{addr}/vm/vm2/dev/hb/ch/data/wait?timeout=5000");
        let waiter = tokio::spawn(async move {
            let client: Client<_, Full<HyperBytes>> =
                Client::builder(TokioExecutor::new()).build_http();
            let req = hyper::Request::builder()
                .method("GET")
                .uri(&url)
                .body(Full::new(HyperBytes::new()))
                .unwrap();
            let resp = client.request(req).await.unwrap();
            let status = resp.status();
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            (status, body)
        });

        // Give the waiter time to register before we trigger.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Trigger: PUT new data — should wake the long-poll with the body.
        // Use a blocking write on the in-process channel rather than
        // another HTTP PUT, just to exercise that direction works too.
        ch.write(&[7, 8, 9]).unwrap();

        let (status, body) = waiter.await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_ref(), &[7, 8, 9]);
    }
}
