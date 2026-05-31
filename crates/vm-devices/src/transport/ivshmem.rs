//! ivshmem shared memory transport for Linux/QEMU.
//!
//! Maps `/dev/shm/ivshmem-{vm}-{label}` into the process address space
//! using mmap. All reads/writes use volatile semantics to match the
//! seqcount protocol expected by guest kernel drivers.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use super::shmem::ShmemChannel;
use super::{DeviceChannel, DeviceTransport, Doorbell, SharedMemory, TransportError};

/// Shared memory backed by an mmap'd file in `/dev/shm/`.
///
/// Created by ivshmem-server during VM startup. The file persists
/// for the lifetime of the ivshmem-server process.
pub struct IvshmemSharedMemory {
    ptr: *mut u8,
    size: usize,
    _path: PathBuf,
}

// SAFETY: The shared memory region is accessed via volatile operations
// and explicit fences. The mmap'd region is valid for the process lifetime.
unsafe impl Send for IvshmemSharedMemory {}
unsafe impl Sync for IvshmemSharedMemory {}

impl IvshmemSharedMemory {
    /// Open an existing ivshmem shared memory region.
    ///
    /// The file at `path` must already exist (created by ivshmem-server).
    pub fn open(path: &Path) -> Result<Self, TransportError> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(TransportError::Io)?;

        let size = file.metadata().map_err(TransportError::Io)?.len() as usize;
        if size == 0 {
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "shared memory file is empty",
            )));
        }

        let fd = {
            use std::os::unix::io::AsRawFd;
            file.as_raw_fd()
        };

        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(TransportError::Io(std::io::Error::last_os_error()));
        }

        // Keep the file open by leaking it — the mmap holds a reference
        // to the underlying inode, so the fd can be closed. But we keep
        // the File alive for safety.
        std::mem::forget(file);

        Ok(Self {
            ptr: ptr as *mut u8,
            size,
            _path: path.to_path_buf(),
        })
    }

    /// Open by VM name and label (standard naming convention).
    pub fn open_by_name(vm_name: &str, label: &str) -> Result<Self, TransportError> {
        let path = PathBuf::from(format!("/dev/shm/ivshmem-{vm_name}-{label}"));
        Self::open(&path)
    }

    /// Open or create a shmem file at `path`, sized to exactly `size` bytes.
    ///
    /// Used by `IvshmemTransport::open_channel` so a host process that comes
    /// up before QEMU can preallocate the file. QEMU later opens the same
    /// path via `-device ivshmem-plain,memdev=...`. The file is `ftruncate`d
    /// to `size`; existing content is preserved if the file already had the
    /// right size, zero-extended if it was shorter.
    pub fn create_or_open(path: &Path, size: usize) -> Result<Self, TransportError> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(TransportError::Io)?;

        // Size the file to `size`. ftruncate is idempotent if the file is
        // already the right length. Zero-extends shorter files.
        let cur_len = file.metadata().map_err(TransportError::Io)?.len() as usize;
        if cur_len < size {
            file.set_len(size as u64).map_err(TransportError::Io)?;
        }

        let fd = {
            use std::os::unix::io::AsRawFd;
            file.as_raw_fd()
        };

        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(TransportError::Io(std::io::Error::last_os_error()));
        }

        // mmap holds a reference to the inode; closing the fd is safe but
        // we keep the file handle alive for symmetry with `open()`.
        std::mem::forget(file);

        Ok(Self {
            ptr: ptr as *mut u8,
            size,
            _path: path.to_path_buf(),
        })
    }
}

impl Drop for IvshmemSharedMemory {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.size);
        }
    }
}

impl SharedMemory for IvshmemSharedMemory {
    fn len(&self) -> usize {
        self.size
    }

    fn read_u16(&self, offset: usize) -> u16 {
        assert!(offset + 2 <= self.size);
        unsafe {
            let p = self.ptr.add(offset) as *const u16;
            core::ptr::read_volatile(p).to_le()
        }
    }

    fn write_u16(&self, offset: usize, value: u16) {
        assert!(offset + 2 <= self.size);
        unsafe {
            let p = self.ptr.add(offset) as *mut u16;
            core::ptr::write_volatile(p, value.to_le());
        }
    }

    fn read_u32(&self, offset: usize) -> u32 {
        assert!(offset + 4 <= self.size);
        unsafe {
            let p = self.ptr.add(offset) as *const u32;
            core::ptr::read_volatile(p).to_le()
        }
    }

    fn write_u32(&self, offset: usize, value: u32) {
        assert!(offset + 4 <= self.size);
        unsafe {
            let p = self.ptr.add(offset) as *mut u32;
            core::ptr::write_volatile(p, value.to_le());
        }
    }

    fn read_u64(&self, offset: usize) -> u64 {
        assert!(offset + 8 <= self.size);
        unsafe {
            let p = self.ptr.add(offset) as *const u64;
            core::ptr::read_volatile(p).to_le()
        }
    }

    fn write_u64(&self, offset: usize, value: u64) {
        assert!(offset + 8 <= self.size);
        unsafe {
            let p = self.ptr.add(offset) as *mut u64;
            core::ptr::write_volatile(p, value.to_le());
        }
    }

    fn read_bytes(&self, offset: usize, buf: &mut [u8]) {
        assert!(offset + buf.len() <= self.size);
        unsafe {
            core::ptr::copy_nonoverlapping(self.ptr.add(offset), buf.as_mut_ptr(), buf.len());
        }
    }

    fn write_bytes(&self, offset: usize, data: &[u8]) {
        assert!(offset + data.len() <= self.size);
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.add(offset), data.len());
        }
    }

    fn fence(&self, ordering: Ordering) {
        std::sync::atomic::fence(ordering);
    }
}

/// Eventfd-based doorbell.
///
/// The eventfd is obtained from the ivshmem-server socket protocol.
/// For now, this is a simple wrapper around a raw fd.
pub struct EventfdDoorbell {
    fd: i32,
}

impl EventfdDoorbell {
    /// Create from a raw eventfd file descriptor.
    ///
    /// # Safety
    /// The fd must be a valid eventfd descriptor.
    pub unsafe fn from_raw_fd(fd: i32) -> Self {
        Self { fd }
    }
}

impl Drop for EventfdDoorbell {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}

impl Doorbell for EventfdDoorbell {
    fn notify(&self) -> Result<(), TransportError> {
        let val: u64 = 1;
        let ret = unsafe { libc::write(self.fd, &val as *const u64 as *const libc::c_void, 8) };
        if ret != 8 {
            return Err(TransportError::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    fn wait(&self) -> Result<(), TransportError> {
        let mut val: u64 = 0;
        let ret = unsafe { libc::read(self.fd, &mut val as *mut u64 as *mut libc::c_void, 8) };
        if ret != 8 {
            return Err(TransportError::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    fn try_wait(&self) -> Result<bool, TransportError> {
        // Non-blocking check via poll
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, 0) };
        if ret < 0 {
            return Err(TransportError::Io(std::io::Error::last_os_error()));
        }
        if ret > 0 && (pfd.revents & libc::POLLIN) != 0 {
            // Consume the event
            let _ = self.wait();
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Null doorbell — does nothing. Used when the ivshmem-server socket
/// protocol isn't available or not needed (health/time use polling).
pub struct NullDoorbell;

impl Doorbell for NullDoorbell {
    fn notify(&self) -> Result<(), TransportError> {
        Ok(())
    }
    fn wait(&self) -> Result<(), TransportError> {
        Ok(())
    }
    fn try_wait(&self) -> Result<bool, TransportError> {
        Ok(false)
    }
}

/// Connect to an ivshmem-server Unix socket and receive the peer's eventfd.
///
/// ivshmem-server protocol:
///   1. Server sends: version (i64 LE) via SCM_RIGHTS
///   2. Server sends: our peer_id (i64 LE) via SCM_RIGHTS
///   3. Server sends: shm_fd via SCM_RIGHTS
///   4. For each existing peer: peer_id (i64 LE) + eventfd per vector via SCM_RIGHTS
///
/// We connect, receive our own eventfds, then wait for the guest peer's
/// eventfd which we use as the doorbell to wake NAPI.
///
/// Returns (our_eventfds, guest_eventfd_for_vector_0) or None if no guest connected yet.
pub fn connect_ivshmem_server(socket_path: &Path) -> Result<EventfdDoorbell, TransportError> {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(TransportError::Io(std::io::Error::last_os_error()));
    }

    // Connect to ivshmem-server
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as u16;
    let path_bytes = socket_path.to_string_lossy();
    let path_bytes = path_bytes.as_bytes();
    if path_bytes.len() >= addr.sun_path.len() {
        unsafe { libc::close(fd) };
        return Err(TransportError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "socket path too long",
        )));
    }
    for (i, b) in path_bytes.iter().enumerate() {
        addr.sun_path[i] = *b as libc::c_char;
    }

    let ret = unsafe {
        libc::connect(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(TransportError::Io(err));
    }

    // Receive messages from ivshmem-server until we get the guest's eventfd.
    // Message 1: version (i64), no fd
    // Message 2: our peer_id (i64), no fd
    // Message 3: -1 (i64), shm_fd via SCM_RIGHTS
    // Message 4+: for each existing peer, we get their eventfds
    // We also get our own eventfds (2 vectors)
    //
    // We need to collect our own eventfds (to give the guest a way to notify us)
    // and the guest's eventfd vector 0 (so we can notify the guest).

    let mut our_notify_fd: i32 = -1;
    let mut msg_count = 0;
    let mut our_peer_id: i64 = -1;

    loop {
        let (val, recv_fd) = recv_ivshmem_msg(fd)?;
        msg_count += 1;

        match msg_count {
            1 => {
                // Version — ignore
            }
            2 => {
                // Our peer ID
                our_peer_id = val;
                tracing::debug!("ivshmem: our peer_id = {our_peer_id}");
            }
            3 => {
                // shm_fd — we don't need it (already mmap'd), close it
                if let Some(f) = recv_fd {
                    unsafe { libc::close(f) };
                }
            }
            _ => {
                // Peer messages: val = peer_id, fd = their eventfd for a vector
                // We receive 2 eventfds per peer (2 vectors)
                // For our own peer: these are eventfds the guest writes to notify us
                // For the guest peer: these are eventfds we write to notify the guest
                if let Some(f) = recv_fd {
                    if val != our_peer_id {
                        // This is the guest's eventfd — use vector 0 to notify NAPI
                        if our_notify_fd < 0 {
                            our_notify_fd = f;
                            tracing::debug!("ivshmem: got guest eventfd (peer {val}, vector 0)");
                        } else {
                            // Vector 1 — close, we only need vector 0
                            unsafe { libc::close(f) };
                        }
                        // Got what we need
                        break;
                    } else {
                        // Our own eventfd — close (we don't need to notify ourselves)
                        unsafe { libc::close(f) };
                    }
                }
            }
        }

        // Safety: don't loop forever if server sends unexpected data
        if msg_count > 20 {
            break;
        }
    }

    // Keep the server connection alive (closing disconnects us as a peer)
    // Keep the server connection fd alive (closing disconnects us as a peer).
    // Leak the fd intentionally — it lives for the process lifetime.
    // (Don't close it or we lose our peer registration with ivshmem-server.)

    if our_notify_fd >= 0 {
        Ok(unsafe { EventfdDoorbell::from_raw_fd(our_notify_fd) })
    } else {
        // No guest connected yet — return a doorbell that will work once
        // QEMU connects (the eventfd is created by ivshmem-server when
        // QEMU starts, which happens after us). We need to retry or
        // use a fallback approach.
        //
        // For now, create our own eventfd as placeholder — the guest won't
        // receive interrupts until it connects, but QEMU hasn't started yet.
        // The real eventfd arrives when QEMU connects.
        tracing::warn!("ivshmem: no guest peer yet, doorbell won't work until QEMU starts");
        Err(TransportError::Io(std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "no guest peer connected to ivshmem-server yet",
        )))
    }
}

/// Receive one ivshmem-server message: i64 value + optional fd via SCM_RIGHTS.
fn recv_ivshmem_msg(sock_fd: i32) -> Result<(i64, Option<i32>), TransportError> {
    let mut val: i64 = 0;
    let mut iov = libc::iovec {
        iov_base: &mut val as *mut _ as *mut libc::c_void,
        iov_len: 8,
    };

    let mut cmsg_buf = [0u8; 64]; // enough for one fd

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len();

    let n = unsafe { libc::recvmsg(sock_fd, &mut msg, 0) };
    if n <= 0 {
        return Err(TransportError::Io(std::io::Error::last_os_error()));
    }

    // Extract fd from SCM_RIGHTS if present
    let mut recv_fd: Option<i32> = None;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let fd_ptr = libc::CMSG_DATA(cmsg) as *const i32;
                recv_fd = Some(*fd_ptr);
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    Ok((val, recv_fd))
}

// ---------------------------------------------------------------------------
// IvshmemTransport — DeviceTransport factory backed by /dev/shm/ivshmem-*
// ---------------------------------------------------------------------------

/// `DeviceTransport` for QEMU+ivshmem. Each channel is a file at
/// `<base_dir>/ivshmem-{vm}-{device}-{channel}` mmap'd into the host
/// process. QEMU is configured separately to attach the same file as an
/// ivshmem PCI BAR for the guest:
///
/// ```text
///   -object memory-backend-file,id=hostmem,mem-path=<file>,size=<bytes>,share=on \
///   -device ivshmem-plain,memdev=hostmem
/// ```
///
/// Doorbell support is **not yet wired up** — channels get `NullDoorbell`.
/// To get eventfd-driven notify/wait, ivshmem-server has to be running and
/// IvshmemTransport needs to call `connect_ivshmem_server` per peer (TODO).
/// In the meantime, devices that need to react to peer writes must poll
/// (matches what `HeartbeatDevice::wait_for_state` already does).
///
/// Channels are cached by `(vm, device, channel)` — repeated `open_channel`
/// calls with the same triple return the same `Arc<ShmemChannel>` and the
/// underlying mmap is shared.
pub struct IvshmemTransport {
    base_dir: PathBuf,
    channels: Mutex<HashMap<(String, String, String), Arc<ShmemChannel>>>,
}

impl IvshmemTransport {
    /// Use the default `/dev/shm` directory.
    pub fn new() -> Self {
        Self::with_base_dir(PathBuf::from("/dev/shm"))
    }

    /// Use a custom base directory. Tests pass a `tempfile::TempDir` so
    /// they don't pollute the real `/dev/shm` namespace and so two test
    /// runs in parallel don't collide.
    pub fn with_base_dir(base_dir: PathBuf) -> Self {
        Self {
            base_dir,
            channels: Mutex::new(HashMap::new()),
        }
    }

    fn channel_path(&self, vm: &str, device: &str, channel: &str) -> PathBuf {
        self.base_dir
            .join(format!("ivshmem-{vm}-{device}-{channel}"))
    }
}

impl Default for IvshmemTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceTransport for IvshmemTransport {
    fn open_channel(
        &self,
        vm: &str,
        device: &str,
        channel: &str,
        size_hint: usize,
    ) -> Result<Arc<dyn DeviceChannel>, TransportError> {
        let key = (vm.to_string(), device.to_string(), channel.to_string());

        let mut map = self
            .channels
            .lock()
            .expect("IvshmemTransport mutex poisoned");
        if let Some(existing) = map.get(&key) {
            let cloned: Arc<ShmemChannel> = existing.clone();
            return Ok(cloned as Arc<dyn DeviceChannel>);
        }

        let path = self.channel_path(vm, device, channel);
        let region: Arc<dyn SharedMemory> =
            Arc::new(IvshmemSharedMemory::create_or_open(&path, size_hint)?);
        // TODO(step 4 / production): attach to ivshmem-server and use
        // EventfdDoorbell so notify() / wait() are interrupt-driven instead
        // of polling.
        let doorbell: Arc<dyn Doorbell> = Arc::new(NullDoorbell);
        let shmem_channel = Arc::new(ShmemChannel::new(region, doorbell, size_hint)?);

        map.insert(key, shmem_channel.clone());
        Ok(shmem_channel as Arc<dyn DeviceChannel>)
    }
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    use crate::heartbeat::{GuestState, Heartbeat, HeartbeatDevice, HEARTBEAT_WIRE_SIZE};
    use crate::power::{PowerCommand, PowerCommandDevice, POWER_WIRE_SIZE};

    /// Test scratch dir under /tmp instead of /dev/shm to keep CI clean.
    /// Each test makes its own subdir so parallel runs don't collide.
    fn tmp_dir(tag: &str) -> PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("ivshmem-tx-{tag}-{pid}-{nanos}"));
        std::fs::create_dir_all(&dir).expect("create tmp dir");
        dir
    }

    fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn open_channel_creates_file_with_requested_size() {
        let dir = tmp_dir("create-size");
        let transport = IvshmemTransport::with_base_dir(dir.clone());

        let _ch = transport
            .open_channel("vm2", "heartbeat", "data", 4096)
            .unwrap();

        let path = dir.join("ivshmem-vm2-heartbeat-data");
        assert!(path.exists());
        let len = std::fs::metadata(&path).unwrap().len();
        assert_eq!(len, 4096);

        cleanup(&dir);
    }

    #[test]
    fn open_channel_returns_same_handle_for_same_triple() {
        let dir = tmp_dir("same-triple");
        let transport = IvshmemTransport::with_base_dir(dir.clone());

        let a = transport.open_channel("vm2", "hb", "data", 64).unwrap();
        let b = transport.open_channel("vm2", "hb", "data", 64).unwrap();
        a.write(&[42u8; 64]).unwrap();
        assert_eq!(b.read().unwrap(), vec![42u8; 64]);

        cleanup(&dir);
    }

    #[test]
    fn open_channel_returns_distinct_handles_for_distinct_triples() {
        let dir = tmp_dir("distinct");
        let transport = IvshmemTransport::with_base_dir(dir.clone());

        let a = transport.open_channel("vm2", "hb", "data", 32).unwrap();
        let b = transport.open_channel("vm2", "power", "cmd", 32).unwrap();
        a.write(&[1u8; 32]).unwrap();
        b.write(&[2u8; 32]).unwrap();
        assert_eq!(a.read().unwrap()[0], 1);
        assert_eq!(b.read().unwrap()[0], 2);

        cleanup(&dir);
    }

    #[test]
    fn ivshmem_transport_drives_heartbeat_device() {
        // End-to-end through the real /dev/shm-style file.
        let dir = tmp_dir("hb-e2e");
        let transport = IvshmemTransport::with_base_dir(dir.clone());

        let host_ch = transport
            .open_channel("vm2", "heartbeat", "data", HEARTBEAT_WIRE_SIZE)
            .unwrap();
        let guest_ch = transport
            .open_channel("vm2", "heartbeat", "data", HEARTBEAT_WIRE_SIZE)
            .unwrap();
        let host = HeartbeatDevice::new(host_ch);
        let guest = HeartbeatDevice::new(guest_ch);

        let hb = Heartbeat {
            seq: 11,
            state: GuestState::Running,
            mono_ns: 999_888_777,
            flags: crate::heartbeat::HB_FLAG_SERVICES_READY,
            boot_id: 0x12345678,
        };
        guest.write(&hb).unwrap();
        let got = host.read().expect("host read");
        assert_eq!(got, hb);

        cleanup(&dir);
    }

    #[test]
    fn ivshmem_transport_drives_power_command_device() {
        let dir = tmp_dir("pwr-e2e");
        let transport = IvshmemTransport::with_base_dir(dir.clone());

        let host_ch = transport
            .open_channel("vm2", "power", "cmd", POWER_WIRE_SIZE)
            .unwrap();
        let guest_ch = transport
            .open_channel("vm2", "power", "cmd", POWER_WIRE_SIZE)
            .unwrap();
        let host = PowerCommandDevice::new(host_ch);
        let guest = PowerCommandDevice::new(guest_ch);

        let seq = host.send(PowerCommand::Hibernate).unwrap();
        let frame = guest.read().expect("guest read");
        assert_eq!(frame.seq, seq);
        assert_eq!(frame.cmd, PowerCommand::Hibernate);

        cleanup(&dir);
    }

    #[test]
    fn ivshmem_transport_persists_data_across_open_channel_calls() {
        // Different IvshmemTransport instances pointing at the same dir
        // both see the same file. Mirrors the production case where host
        // and guest are different processes (via QEMU) sharing the file.
        let dir = tmp_dir("persist");

        {
            let t = IvshmemTransport::with_base_dir(dir.clone());
            let ch = t.open_channel("vm2", "hb", "data", 16).unwrap();
            ch.write(&[0xAB; 16]).unwrap();
        }
        // First transport drops; mmap still backs the file via fd kept
        // alive by `mem::forget(file)`. New transport opens the same file.
        {
            let t = IvshmemTransport::with_base_dir(dir.clone());
            let ch = t.open_channel("vm2", "hb", "data", 16).unwrap();
            assert_eq!(ch.read().unwrap(), vec![0xAB; 16]);
        }

        cleanup(&dir);
    }
}
