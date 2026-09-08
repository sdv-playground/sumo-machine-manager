//! TCP transport for vHSM. Each accepted connection carries the peer's
//! source IP, which the policy module resolves to a `vm_id`.
//!
//! The expectation is that the listener binds an interface that is only
//! reachable from authorised guests (e.g. the host side of a private
//! `vbr-vhsm` bridge) — the IP allow-list is meaningless on a public NIC.

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener as StdTcpListener, TcpStream};

/// A single accepted client connection.
pub struct Connection {
    stream: TcpStream,
    peer_ip: IpAddr,
}

impl Connection {
    pub fn reader(&mut self) -> &mut dyn Read {
        &mut self.stream
    }

    pub fn writer(&mut self) -> &mut dyn Write {
        &mut self.stream
    }

    /// Source IP the connection arrived from. The policy module maps this
    /// to a `vm_id`; without an entry, the connection is rejected.
    pub fn peer_ip(&self) -> IpAddr {
        self.peer_ip
    }
}

pub struct TcpListener {
    inner: StdTcpListener,
    addr: SocketAddr,
}

impl TcpListener {
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let inner = StdTcpListener::bind(addr)?;
        let addr = inner.local_addr()?;
        Ok(Self { inner, addr })
    }

    pub fn accept(&self) -> io::Result<Connection> {
        let (stream, peer) = self.inner.accept()?;
        // TCP_NODELAY: small request/response, latency matters more than
        // throughput. Best-effort — ignore failure.
        let _ = stream.set_nodelay(true);
        let peer_ip = peer.ip();

        tracing::info!(peer = %peer_ip, port = self.addr.port(), "vhsm connection accepted");

        Ok(Connection { stream, peer_ip })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }
}
