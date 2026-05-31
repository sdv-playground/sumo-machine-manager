//! TCP-stream `DeviceTransport` — host side of the stream channel.
//!
//! Used for high-rate or strictly-ordered frame traffic (CAN, audio, log
//! streaming) where HTTP request/response is the wrong shape and shmem
//! rings aren't available across the host/guest boundary (qvm + Linux).
//!
//! ## Wire protocol
//!
//! A new TCP connection per `(vm, device, channel)` triple. The guest sends
//! a one-line handshake, the host validates against its registry, then both
//! sides exchange length-prefixed frames:
//!
//! ```text
//!   guest → host:  "STREAM /vm/{vm}/dev/{device}/ch/{channel}\n"
//!   host  → guest: "OK\n"          (channel registered, attached)
//!                  "ERR <msg>\n"   (channel not registered, malformed handshake)
//!   then both sides:
//!                  4-byte LE length (u32, max 4 MiB)
//!                  N bytes payload
//!                  ... repeat
//! ```
//!
//! See `guest-vm-spec/specs/transport/tcp-stream.md` for the protocol spec.
//!
//! ## Threading model
//!
//! `TcpStreamTransport::bind` spawns one accept-loop thread. Each accepted
//! connection (after a successful handshake) gets one reader thread that
//! decodes frames into the channel's `rx_queue`; writes go directly to the
//! `TcpStream` from `send_frame`'s caller thread.
//!
//! Cloning `TcpStream` produces a second handle for the same socket — read
//! and write halves use independent clones so they don't contend on a
//! mutex. EOF on read closes the channel's RX side; the next `send_frame`
//! that hits a closed socket will surface the error.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use super::{DeviceTransport, StreamChannel, TransportError};

/// Maximum frame size in bytes. Transport rejects send/recv beyond this.
/// 4 MiB is generous for any plausible stream payload (CAN frames are 72
/// bytes; audio buffers ≤ 16 KiB; bulk video ≤ 1 MiB).
const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024;

/// Per-channel mutable state — shared between the accept-loop reader thread
/// (which pushes into `rx_queue` + sets `tx_stream`) and `send_frame` /
/// `recv_frame` callers.
struct ChannelState {
    /// Frame queue from peer → us, populated by the reader thread.
    rx_queue: Mutex<VecDeque<Vec<u8>>>,
    /// Wakes `recv_frame` when `rx_queue` gains a frame or `tx_stream`
    /// becomes None (peer disconnected mid-wait).
    rx_cv: Condvar,
    /// Write-side of the TCP socket. `None` until a guest connects with the
    /// matching handshake; reset to `None` when the reader thread sees EOF.
    /// `send_frame` errors with `NotConnected` while this is `None`.
    tx_stream: Mutex<Option<TcpStream>>,
}

impl ChannelState {
    fn new() -> Self {
        Self {
            rx_queue: Mutex::new(VecDeque::new()),
            rx_cv: Condvar::new(),
            tx_stream: Mutex::new(None),
        }
    }

    fn detach(&self) {
        *self.tx_stream.lock().expect("tx_stream poisoned") = None;
        // Wake any thread parked in recv_frame so it can see the disconnect.
        self.rx_cv.notify_all();
    }
}

type ChannelKey = (String, String, String);

/// Internal registry shared between the accept loop and `open_stream`.
#[derive(Default)]
struct Registry {
    channels: Mutex<HashMap<ChannelKey, Arc<ChannelState>>>,
}

impl Registry {
    fn open(&self, key: ChannelKey) -> Arc<ChannelState> {
        let mut map = self.channels.lock().expect("registry poisoned");
        map.entry(key)
            .or_insert_with(|| Arc::new(ChannelState::new()))
            .clone()
    }

    fn lookup(&self, key: &ChannelKey) -> Option<Arc<ChannelState>> {
        self.channels
            .lock()
            .expect("registry poisoned")
            .get(key)
            .cloned()
    }
}

/// Host-side TCP stream transport. Bind once, then hand to `VmManager` so
/// runners can request stream channels for their VMs.
pub struct TcpStreamTransport {
    registry: Arc<Registry>,
}

impl TcpStreamTransport {
    /// Construct an empty transport. No socket is opened until `bind` is
    /// called or the registry is otherwise served.
    pub fn new() -> Self {
        Self {
            registry: Arc::new(Registry::default()),
        }
    }

    /// Bind a TCP listener on `addr` and spawn the accept loop. Returns the
    /// resolved local address (so callers using `:0` for ephemeral ports
    /// can find out which port they got).
    ///
    /// The accept loop runs on a dedicated thread for the lifetime of this
    /// transport. Currently no graceful shutdown — drop the transport and
    /// the OS reaps the listener when the process exits. (vm-service runs
    /// long-lived, so this is fine.)
    pub fn bind(&self, addr: &str) -> std::io::Result<SocketAddr> {
        let listener = TcpListener::bind(addr)?;
        let local_addr = listener.local_addr()?;
        let registry = self.registry.clone();
        std::thread::Builder::new()
            .name("tcp-stream-accept".into())
            .spawn(move || accept_loop(listener, registry))?;
        Ok(local_addr)
    }
}

impl Default for TcpStreamTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceTransport for TcpStreamTransport {
    fn open_stream(
        &self,
        vm: &str,
        device: &str,
        channel: &str,
    ) -> Result<Arc<dyn StreamChannel>, TransportError> {
        let key = (vm.to_string(), device.to_string(), channel.to_string());
        let state = self.registry.open(key);
        Ok(Arc::new(TcpStreamChannelHandle { state }) as Arc<dyn StreamChannel>)
    }
}

/// Host-side channel handle returned by `open_stream`. Idempotent — multiple
/// handles to the same `(vm, device, channel)` share state, so a host writer
/// and a host monitor see each other's view of the connection.
struct TcpStreamChannelHandle {
    state: Arc<ChannelState>,
}

impl StreamChannel for TcpStreamChannelHandle {
    fn send_frame(&self, data: &[u8]) -> Result<(), TransportError> {
        if data.len() > MAX_FRAME_SIZE {
            return Err(TransportError::OutOfBounds {
                offset: 0,
                len: data.len(),
                size: MAX_FRAME_SIZE,
            });
        }
        let mut guard = self.state.tx_stream.lock().expect("tx_stream poisoned");
        let stream = guard.as_mut().ok_or_else(|| {
            TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "no peer connected to this channel yet",
            ))
        })?;
        write_frame(stream, data).map_err(TransportError::Io)
    }

    fn recv_frame(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, TransportError> {
        let queue = self.state.rx_queue.lock().expect("rx_queue poisoned");
        match timeout {
            None => {
                let mut q = self
                    .state
                    .rx_cv
                    .wait_while(queue, |q| q.is_empty())
                    .expect("rx_cv poisoned");
                Ok(q.pop_front())
            }
            Some(dur) => {
                let (mut q, result) = self
                    .state
                    .rx_cv
                    .wait_timeout_while(queue, dur, |q| q.is_empty())
                    .expect("rx_cv poisoned");
                if result.timed_out() {
                    Ok(None)
                } else {
                    Ok(q.pop_front())
                }
            }
        }
    }

    fn try_recv_frame(&self) -> Result<Option<Vec<u8>>, TransportError> {
        let mut q = self.state.rx_queue.lock().expect("rx_queue poisoned");
        Ok(q.pop_front())
    }
}

// ---------------------------------------------------------------------------
// Accept loop + per-connection reader
// ---------------------------------------------------------------------------

fn accept_loop(listener: TcpListener, registry: Arc<Registry>) {
    loop {
        let (stream, peer_addr) = match listener.accept() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("tcp-stream accept failed: {e}");
                continue;
            }
        };
        let registry = registry.clone();
        std::thread::Builder::new()
            .name(format!("tcp-stream-conn-{peer_addr}"))
            .spawn(move || {
                if let Err(e) = handle_connection(stream, peer_addr, registry) {
                    tracing::warn!("tcp-stream connection from {peer_addr} ended: {e}");
                }
            })
            .ok(); // if we can't spawn the thread, drop the connection
    }
}

fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    registry: Arc<Registry>,
) -> std::io::Result<()> {
    // Handshake: read one line "STREAM /vm/{vm}/dev/{device}/ch/{channel}\n"
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut handshake = String::new();
    reader.read_line(&mut handshake)?;
    let handshake = handshake.trim_end_matches(['\r', '\n']);

    let key = match parse_handshake(handshake) {
        Some(k) => k,
        None => {
            let mut tx = stream;
            let _ = tx.write_all(format!("ERR malformed handshake: {handshake}\n").as_bytes());
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad handshake",
            ));
        }
    };

    let state = match registry.lookup(&key) {
        Some(s) => s,
        None => {
            let mut tx = stream;
            let _ = tx.write_all(b"ERR no such channel registered\n");
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "channel not registered",
            ));
        }
    };

    // Reject second connection to the same channel — single peer per stream
    // for now. Reconnection requires the previous peer to have disconnected
    // (reader thread sets tx_stream=None on EOF).
    {
        let mut tx_guard = state.tx_stream.lock().expect("tx_stream poisoned");
        if tx_guard.is_some() {
            let mut tx = stream;
            let _ = tx.write_all(b"ERR channel already in use\n");
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "channel already attached",
            ));
        }
        // Plug write half in.
        let write_half = stream.try_clone()?;
        *tx_guard = Some(write_half);
    }

    // Acknowledge.
    {
        let mut tx_guard = state.tx_stream.lock().expect("tx_stream poisoned");
        if let Some(s) = tx_guard.as_mut() {
            s.write_all(b"OK\n")?;
        }
    }

    tracing::info!(target: "vm_devices::tcp_stream",
        path = handshake, peer = %peer_addr, "tcp-stream channel attached");

    // Read frames forever, push into rx_queue, signal cv. Loop exits on EOF
    // / IO error, after which we detach so the channel is reusable by a
    // future reconnection.
    let inner = reader.into_inner();
    let result = read_loop(inner, state.clone());
    state.detach();
    result
}

fn read_loop(mut stream: TcpStream, state: Arc<ChannelState>) -> std::io::Result<()> {
    loop {
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > MAX_FRAME_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("frame size {len} exceeds max {MAX_FRAME_SIZE}"),
            ));
        }
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload)?;

        let mut q = state.rx_queue.lock().expect("rx_queue poisoned");
        q.push_back(payload);
        state.rx_cv.notify_one();
    }
}

fn write_frame(stream: &mut TcpStream, data: &[u8]) -> std::io::Result<()> {
    let len = (data.len() as u32).to_le_bytes();
    stream.write_all(&len)?;
    stream.write_all(data)?;
    stream.flush()
}

/// Parse `"STREAM /vm/{vm}/dev/{device}/ch/{channel}"` into a `ChannelKey`.
/// Returns `None` if the format doesn't match exactly.
fn parse_handshake(line: &str) -> Option<ChannelKey> {
    let path = line.strip_prefix("STREAM ")?;
    // Path: /vm/{vm}/dev/{device}/ch/{channel}
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if segments.len() != 6 {
        return None;
    }
    if segments[0] != "vm" || segments[2] != "dev" || segments[4] != "ch" {
        return None;
    }
    Some((
        segments[1].to_string(),
        segments[3].to_string(),
        segments[5].to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn open_handle(
        t: &TcpStreamTransport,
        vm: &str,
        dev: &str,
        ch: &str,
    ) -> Arc<dyn StreamChannel> {
        t.open_stream(vm, dev, ch).expect("open_stream")
    }

    fn connect_with_handshake(addr: SocketAddr, path: &str) -> std::io::Result<TcpStream> {
        let mut s = TcpStream::connect(addr)?;
        s.write_all(format!("STREAM {path}\n").as_bytes())?;
        let mut reader = BufReader::new(s.try_clone()?);
        let mut response = String::new();
        reader.read_line(&mut response)?;
        if !response.starts_with("OK") {
            return Err(std::io::Error::other(format!(
                "handshake rejected: {}",
                response.trim()
            )));
        }
        Ok(s)
    }

    #[test]
    fn parse_handshake_well_formed() {
        let key = parse_handshake("STREAM /vm/vm2/dev/can/ch/tx").unwrap();
        assert_eq!(key, ("vm2".into(), "can".into(), "tx".into()));
    }

    #[test]
    fn parse_handshake_rejects_missing_prefix() {
        assert!(parse_handshake("/vm/vm2/dev/can/ch/tx").is_none());
        assert!(parse_handshake("GET /vm/vm2/dev/can/ch/tx").is_none());
    }

    #[test]
    fn parse_handshake_rejects_wrong_segment_count() {
        assert!(parse_handshake("STREAM /vm/vm2/dev/can").is_none());
        assert!(parse_handshake("STREAM /vm/vm2/dev/can/ch/tx/extra").is_none());
    }

    #[test]
    fn parse_handshake_rejects_wrong_keywords() {
        assert!(parse_handshake("STREAM /VM/vm2/dev/can/ch/tx").is_none());
        assert!(parse_handshake("STREAM /vm/vm2/device/can/ch/tx").is_none());
    }

    #[test]
    fn open_stream_returns_unsupported_for_open_channel() {
        let t = TcpStreamTransport::new();
        let r = t.open_channel("vm2", "heartbeat", "data", 32);
        assert!(matches!(r, Err(TransportError::Unsupported(_))));
    }

    #[test]
    fn send_frame_before_peer_connects_returns_not_connected() {
        let t = TcpStreamTransport::new();
        let ch = open_handle(&t, "vm2", "can", "tx");
        let r = ch.send_frame(&[1, 2, 3]);
        match r {
            Err(TransportError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotConnected),
            other => panic!("expected NotConnected, got {other:?}"),
        }
    }

    #[test]
    fn send_frame_rejects_oversized() {
        let t = TcpStreamTransport::new();
        let ch = open_handle(&t, "vm2", "can", "tx");
        let huge = vec![0u8; MAX_FRAME_SIZE + 1];
        let r = ch.send_frame(&huge);
        assert!(matches!(r, Err(TransportError::OutOfBounds { .. })));
    }

    #[test]
    fn try_recv_frame_returns_none_when_empty() {
        let t = TcpStreamTransport::new();
        let ch = open_handle(&t, "vm2", "can", "tx");
        assert!(matches!(ch.try_recv_frame(), Ok(None)));
    }

    #[test]
    fn recv_frame_with_short_timeout_returns_none() {
        let t = TcpStreamTransport::new();
        let ch = open_handle(&t, "vm2", "can", "tx");
        let r = ch.recv_frame(Some(Duration::from_millis(15))).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn handshake_unknown_channel_returns_err_and_disconnects() {
        let t = TcpStreamTransport::new();
        let addr = t.bind("127.0.0.1:0").unwrap();
        // Don't open the channel — server should reply ERR.
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(b"STREAM /vm/vm2/dev/nothing/ch/here\n")
            .unwrap();
        let mut response = String::new();
        BufReader::new(s).read_to_string(&mut response).unwrap();
        assert!(response.starts_with("ERR"), "got: {response:?}");
    }

    #[test]
    fn handshake_malformed_returns_err() {
        let t = TcpStreamTransport::new();
        let addr = t.bind("127.0.0.1:0").unwrap();
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(b"PUT /vm/vm2/dev/can/ch/tx\n").unwrap();
        let mut response = String::new();
        BufReader::new(s).read_to_string(&mut response).unwrap();
        assert!(response.starts_with("ERR"));
    }

    #[test]
    fn end_to_end_frame_roundtrip() {
        let t = TcpStreamTransport::new();
        let host_ch = open_handle(&t, "vm2", "can", "tx");
        let addr = t.bind("127.0.0.1:0").unwrap();

        let mut client = connect_with_handshake(addr, "/vm/vm2/dev/can/ch/tx").unwrap();
        // Brief settle so the handshake-accepting thread has plumbed
        // the write half into ChannelState.tx_stream before we send.
        std::thread::sleep(Duration::from_millis(20));

        // Host → guest direction.
        host_ch.send_frame(&[10, 20, 30]).unwrap();
        let mut len_buf = [0u8; 4];
        client.read_exact(&mut len_buf).unwrap();
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut payload = vec![0u8; len];
        client.read_exact(&mut payload).unwrap();
        assert_eq!(payload, vec![10, 20, 30]);

        // Guest → host direction.
        write_frame(&mut client, &[40, 50]).unwrap();
        let frame = host_ch
            .recv_frame(Some(Duration::from_secs(1)))
            .unwrap()
            .expect("recv_frame should yield the guest's send");
        assert_eq!(frame, vec![40, 50]);
    }

    #[test]
    fn second_connection_to_same_channel_rejected() {
        let t = TcpStreamTransport::new();
        let _host_ch = open_handle(&t, "vm2", "can", "tx");
        let addr = t.bind("127.0.0.1:0").unwrap();

        let _first = connect_with_handshake(addr, "/vm/vm2/dev/can/ch/tx").unwrap();
        std::thread::sleep(Duration::from_millis(20));

        let second = connect_with_handshake(addr, "/vm/vm2/dev/can/ch/tx");
        assert!(second.is_err(), "second connection must be rejected");
    }

    #[test]
    fn open_stream_returns_same_state_for_same_triple() {
        let t = TcpStreamTransport::new();
        let _ch1 = t.open_stream("vm2", "can", "tx").unwrap();
        let ch2 = t.open_stream("vm2", "can", "tx").unwrap();

        // Both must reflect the same not-connected state.
        let r = ch2.send_frame(&[0]);
        match r {
            Err(TransportError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotConnected),
            other => panic!("expected NotConnected, got {other:?}"),
        }
    }
}
