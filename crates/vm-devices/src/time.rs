//! Time device — host writes vtime registers to a shared region; guests
//! read them and discipline their local CLOCK_REALTIME.
//!
//! Two flavors live in this file:
//!
//! - [`TimeSim`] — uses the low-level [`SharedMemory`] + [`Doorbell`]
//!   abstractions for direct register access. Requires a transport that
//!   exposes raw memory (ivshmem on Linux). Includes full TIME_ADJUST
//!   command handling (auth, rate limit, anti-rollback, etc.) and is
//!   well unit-tested.
//!
//! - [`TimeDevice`] — uses the higher-level byte-stream [`DeviceChannel`]
//!   API. Periodic writer task; each tick assembles the full 128-byte
//!   region and writes it through the channel. No TIME_ADJUST handling
//!   yet — the guest is read-only in this iteration. Used on QNX with
//!   the qvm-shmem transport, where channels are byte-level not
//!   register-level.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use std::sync::Arc;
use std::thread;

use crate::clock::Clock;
use crate::regs::time as r;
use crate::transport::{seqcount_write, DeviceChannel, Doorbell, SharedMemory};

/// Time device simulator.
pub struct TimeSim<S: SharedMemory, D: Doorbell, C: Clock> {
    shm: S,
    doorbell: D,
    clock: Arc<C>,
    interval: Duration,
    /// Only this guest ID may issue TIME_ADJUST (0 = allow all).
    sync_guest_id: u32,
    /// Minimum interval between adjustments.
    min_adjust_interval: Duration,
    /// Maximum correction magnitude (ns).
    max_correction_ns: i64,
    /// Current wall offset correction (accumulated from TIME_ADJUST commands).
    wall_correction_ns: i64,
    /// Last adjustment time.
    last_adjust: Option<Instant>,
    /// Last seen guest command sequence number.
    last_cmd_seq: u32,
}

impl<S: SharedMemory, D: Doorbell, C: Clock> TimeSim<S, D, C> {
    pub fn new(shm: S, doorbell: D, clock: Arc<C>) -> Self {
        Self {
            shm,
            doorbell,
            clock,
            interval: Duration::from_millis(100), // 10 Hz
            sync_guest_id: 1,
            min_adjust_interval: Duration::from_secs(10),
            max_correction_ns: 3_600_000_000_000, // 1 hour
            wall_correction_ns: 0,
            last_adjust: None,
            last_cmd_seq: 0,
        }
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    pub fn with_sync_guest_id(mut self, id: u32) -> Self {
        self.sync_guest_id = id;
        self
    }

    pub fn with_min_adjust_interval(mut self, d: Duration) -> Self {
        self.min_adjust_interval = d;
        self
    }

    /// Initialize shared memory header.
    pub fn init(&self) {
        self.shm.write_u32(r::OFF_MAGIC, r::MAGIC);
        self.shm.write_u32(r::OFF_VERSION, r::VERSION);
        self.shm.write_u32(r::OFF_UPDATE_SEQ, 0);
        self.shm.write_u32(r::OFF_FLAGS, 0);
        self.shm.write_u32(r::OFF_SYNC_SOURCE, r::SRC_NONE);
        self.shm.write_u32(r::OFF_SYNC_QUALITY, r::QUALITY_UNKNOWN);
    }

    /// Run the simulator loop. Blocks until `cancel` is set.
    pub fn run(&mut self, cancel: &AtomicBool) {
        self.init();

        while !cancel.load(Ordering::Relaxed) {
            self.update_time();
            self.check_adjust();
            let _ = self.doorbell.notify();
            std::thread::sleep(self.interval);
        }
    }

    /// Write current time registers using seqcount protocol.
    pub fn update_time(&self) {
        let mono_ns = self.clock.now_mono_ns();
        let wall_offset = self.clock.wall_offset_ns() + self.wall_correction_ns;

        seqcount_write(&self.shm, r::OFF_UPDATE_SEQ, || {
            self.shm.write_u64(r::OFF_MONO_NS, mono_ns);
            self.shm.write_i64(r::OFF_WALL_OFFSET_NS, wall_offset);
        });
    }

    /// Check for and process TIME_ADJUST commands from the guest.
    pub fn check_adjust(&mut self) {
        let cmd_seq = self.shm.read_u32(r::CMD_OFF_SEQ);
        if cmd_seq == self.last_cmd_seq {
            return;
        }
        self.last_cmd_seq = cmd_seq;

        let op = self.shm.read_u32(r::CMD_OFF_OP) as u8;
        if op != r::CMD_ADJUST {
            return;
        }

        let guest_id = self.shm.read_u32(r::CMD_OFF_GUEST_ID);
        let correction = self.shm.read_i64(r::CMD_OFF_CORRECTION_NS);

        // Authorization check
        if self.sync_guest_id != 0 && guest_id != self.sync_guest_id {
            self.shm
                .write_u32(r::CMD_OFF_STATUS, r::STATUS_UNAUTHORIZED);
            let _ = self.doorbell.notify();
            return;
        }

        // Rate limit check
        if let Some(last) = self.last_adjust {
            if last.elapsed() < self.min_adjust_interval {
                self.shm
                    .write_u32(r::CMD_OFF_STATUS, r::STATUS_RATE_LIMITED);
                let _ = self.doorbell.notify();
                return;
            }
        }

        // Magnitude check
        if correction.abs() > self.max_correction_ns {
            self.shm.write_u32(r::CMD_OFF_STATUS, r::STATUS_REJECTED);
            let _ = self.doorbell.notify();
            return;
        }

        // Apply correction
        self.wall_correction_ns += correction;

        // Anti-rollback floor check
        let min_wall = self.shm.read_u64(r::OFF_MIN_WALL_NS);
        if min_wall > 0 {
            let mono = self.clock.now_mono_ns();
            let new_wall = mono as i64 + self.clock.wall_offset_ns() + self.wall_correction_ns;
            if (new_wall as u64) < min_wall {
                self.wall_correction_ns -= correction; // undo
                self.shm.write_u32(r::CMD_OFF_STATUS, r::STATUS_REJECTED);
                let _ = self.doorbell.notify();
                return;
            }
        }

        // Update sync metadata
        let source = self.shm.read_u32(r::CMD_OFF_SYNC_SOURCE);
        let quality = self.shm.read_u32(r::CMD_OFF_SYNC_QUALITY);
        self.shm.write_u32(r::OFF_SYNC_SOURCE, source);
        self.shm.write_u32(r::OFF_SYNC_QUALITY, quality);
        self.shm
            .write_u64(r::OFF_LAST_SYNC_MONO_NS, self.clock.now_mono_ns());
        self.shm.write_u32(r::OFF_FLAGS, r::FLAG_SYNC_VALID);

        self.last_adjust = Some(Instant::now());
        self.shm.write_u32(r::CMD_OFF_STATUS, r::STATUS_APPLIED);

        // Write updated time immediately
        self.update_time();
        let _ = self.doorbell.notify();
    }
}

// =============================================================================
// TimeDevice — DeviceChannel-based variant for byte-stream transports
// =============================================================================

/// Default writer interval (10 Hz). Most guest discipline loops sample at
/// 1–10 Hz, so this gives them a fresh value every poll.
pub const TIME_DEFAULT_INTERVAL: Duration = Duration::from_millis(100);

/// Default sync-guest identity allowed to issue TIME_ADJUST. Matches
/// the convention used by the vtime spec; configurable per-deployment
/// once policy lands. `0` means "any guest".
pub const TIME_DEFAULT_SYNC_GUEST_ID: u32 = 1;

/// Default minimum interval between accepted TIME_ADJUST commands.
pub const TIME_DEFAULT_MIN_ADJUST_INTERVAL: Duration = Duration::from_secs(1);

/// Default maximum magnitude of a single TIME_ADJUST correction (1 hour).
pub const TIME_DEFAULT_MAX_CORRECTION_NS: i64 = 3_600_000_000_000;

/// Host-side TimeDevice for byte-stream transports (qvm-shmem, http, etc.).
///
/// On construction, spawns a background thread that periodically:
///   1. Reads `mono_ns` and `wall_offset_ns` from the configured [`Clock`].
///   2. Assembles a full 128-byte vtime region buffer.
///   3. Writes it through the [`DeviceChannel`].
///
/// `update_seq` advances by 2 each tick (always even). The writer never
/// publishes an odd value, so a guest reader that samples seq before and
/// after reading data fields will only see a "torn" read if the underlying
/// transport delivers a mid-flight buffer — which the qvm-shmem channel
/// API does not (each `write()` lands as a unit). When/if a SharedMemory-
/// capable transport lands, the proper odd/even seqcount protocol can be
/// reinstated via `TimeSim` instead.
///
/// Drop aborts the writer thread on the next tick (cooperative cancel).
pub struct TimeDevice {
    cancel: Arc<AtomicBool>,
    writer: Option<thread::JoinHandle<()>>,
}

impl TimeDevice {
    /// Construct and start the periodic writer. `interval` is wall time
    /// between writes; `TIME_DEFAULT_INTERVAL` is a sensible default.
    ///
    /// Single-channel constructor — bidirectional vtime over ONE channel
    /// using offset-based directional split (regs at 0x00-0x3F, cmd at
    /// 0x40-0x7F). Suits qvm-shmem where each peer writes its own slot.
    pub fn new(channel: Arc<dyn DeviceChannel>, clock: Arc<dyn Clock>, interval: Duration) -> Self {
        // Pass same Arc twice; writer_loop_inner uses Arc::ptr_eq to
        // detect aliasing and emits a single combined write.
        Self::with_split_channels(channel.clone(), channel, clock, interval)
    }

    /// Two-channel constructor — host→guest regs on one channel,
    /// bidirectional adjust on a second. Used by transports that don't
    /// natively split direction (HTTP today). The two channels each
    /// carry a 128-byte payload; regs-channel writes leave the cmd
    /// half zero, adjust-channel writes leave the regs half zero.
    pub fn with_split_channels(
        regs_channel: Arc<dyn DeviceChannel>,
        adjust_channel: Arc<dyn DeviceChannel>,
        clock: Arc<dyn Clock>,
        interval: Duration,
    ) -> Self {
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_clone = cancel.clone();
        let writer = thread::Builder::new()
            .name("vtime-writer".into())
            .spawn(move || writer_loop(regs_channel, adjust_channel, clock, interval, cancel_clone))
            .expect("spawn vtime-writer thread");

        Self {
            cancel,
            writer: Some(writer),
        }
    }
}

impl Drop for TimeDevice {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        if let Some(handle) = self.writer.take() {
            let _ = handle.join();
        }
    }
}

/// Per-tick state of the TimeDevice writer. Tracks accumulated wall
/// offset corrections from TIME_ADJUST commands, plus the seqcount of
/// the last cmd we processed (for ack reply + dedup).
struct WriterState {
    update_seq: u32,
    /// Accumulated correction from TIME_ADJUST commands. Added on top
    /// of `clock.wall_offset_ns()` when publishing regs.
    wall_correction_ns: i64,
    /// Most-recent cmd seq we processed (0 = none yet). The reply
    /// status echoes this seq so the guest can correlate.
    last_cmd_seq: u32,
    /// Status code for the last processed cmd. Published in the cmd
    /// region of host's slot so the guest can read it back.
    last_cmd_status: u32,
    /// Sync source / quality from the last APPLIED cmd. Persists across
    /// regs writes so the guest's --query consistently reports them.
    sync_source: vm_wire::SyncSource,
    sync_quality: vm_wire::SyncQuality,
    last_sync_mono_ns: u64,
    flags: u32,
    /// Wall-time of the last accepted adjust. Drives the rate-limit gate.
    last_adjust: Option<Instant>,
}

impl WriterState {
    fn new() -> Self {
        Self {
            update_seq: 0,
            wall_correction_ns: 0,
            last_cmd_seq: 0,
            last_cmd_status: vm_wire::VTIME_STATUS_PENDING,
            sync_source: vm_wire::SyncSource::None,
            sync_quality: vm_wire::SyncQuality::Unknown,
            last_sync_mono_ns: 0,
            flags: 0,
            last_adjust: None,
        }
    }
}

fn writer_loop(
    regs_channel: Arc<dyn DeviceChannel>,
    adjust_channel: Arc<dyn DeviceChannel>,
    clock: Arc<dyn Clock>,
    interval: Duration,
    cancel: Arc<AtomicBool>,
) {
    // Wrap the iteration loop in catch_unwind so a panic inside the
    // body (channel.write, clock.now_mono_ns, …) doesn't silently
    // kill the writer with no diagnostic. On the CVC we hit a freeze
    // where mono_ns stopped advancing with zero supernova-side
    // evidence; this surfaces the cause next time. Thread still
    // exits on panic — vm-service has to rebuild the TimeDevice
    // (stop_vm + start_vm) to recover. We deliberately don't
    // auto-restart the loop until we know what's panicking.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        writer_loop_inner(regs_channel, adjust_channel, clock, interval, cancel);
    }));
    if let Err(payload) = result {
        let msg = payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<non-string panic payload>".to_string());
        tracing::error!(
            target: "vtime",
            "vtime-writer thread panicked, exiting: {msg}\n\
             host will stop publishing VtimeRegs; guest /dev/vtime snapshot \
             will freeze at the last good values. Recover by restarting the \
             VM (vm-service stop_vm + start_vm rebuilds the TimeDevice)."
        );
    }
}

fn writer_loop_inner(
    regs_channel: Arc<dyn DeviceChannel>,
    adjust_channel: Arc<dyn DeviceChannel>,
    clock: Arc<dyn Clock>,
    interval: Duration,
    cancel: Arc<AtomicBool>,
) {
    use vm_wire::{VtimeCmd, VtimeRegs, VTIME_FLAG_SYNC_VALID, VTIME_REGS_SIZE, VTIME_WIRE_SIZE};

    // Single-channel mode (qvm-shmem): regs and adjust are the same Arc;
    // direction is split via offsets within the host's slot. The combined
    // 128-byte buffer goes out as one write.
    //
    // Two-channel mode (HTTP): separate channels for regs and adjust.
    // The regs channel is host→guest only — regs in first 64 bytes,
    // cmd half zero. The adjust channel is bidirectional — guest writes
    // cmd (regs half zero, cmd half = cmd + status=PENDING), host writes
    // back the same buffer with status updated (regs half stays zero).
    // Detect by Arc::ptr_eq to avoid an explicit transport-kind argument.
    let single_channel_mode = Arc::ptr_eq(&regs_channel, &adjust_channel);

    // Threshold for the host self-election step below. Any wall_ns
    // beyond 2024-01-01 UTC is "obviously not the systemd built-in
    // epoch / RTC-default 1970"; the host is willing to claim its
    // own clock as authoritative once it crosses this. Future
    // refinement: replace the constant with a persisted Roughtime
    // floor that survives reboots — see "monotonic time floor"
    // discussion in tasks/time-broker-in-guest.md.
    const EPOCH_2024_NS: i64 = 1_704_067_200_000_000_000;

    let mut st = WriterState::new();

    while !cancel.load(Ordering::Relaxed) {
        // 1. Poll for a new TIME_ADJUST cmd.
        //    - Single-channel (qvm-shmem): read peer's slot (the guest's
        //      writes); cmd at offsets 0x40..0x80.
        //    - Two-channel (HTTP): read the adjust channel; cmd at the
        //      same offsets. Guest writes leave the regs half zero;
        //      our own ack-writes also leave regs zero so the seq-dedup
        //      check below correctly skips reads that are echoes of
        //      our previous ack.
        if let Ok(peer_buf) = adjust_channel.read() {
            if peer_buf.len() >= VTIME_WIRE_SIZE {
                if let Some(cmd) = VtimeCmd::from_cmd_bytes(&peer_buf[VTIME_REGS_SIZE..]) {
                    if cmd.seq != 0 && cmd.seq != st.last_cmd_seq {
                        process_adjust(&cmd, &mut st, &clock);
                    }
                }
            }
        }

        // 1b. Host self-election. Without this step the publisher
        //     refuses to advertise SYNC_VALID until a guest issues a
        //     TIME_ADJUST — but on managed-cvc the host already gets
        //     its wall time from sntp at boot and is the most natural
        //     authority. The QNX guest gets the host clock via qvm's
        //     kernel pass-through and ignores the regs flag entirely;
        //     Linux guests have no equivalent shortcut and correctly
        //     refuse to step the clock based on data flagged invalid.
        //     Self-electing closes that gap.
        //
        //     A subsequent TIME_ADJUST from an authorised guest (the
        //     eventual time-broker daemon in vm1, with Roughtime +
        //     sntp validation) will overwrite source/quality with
        //     something more accurate. See tasks/time-broker-in-guest.md.
        //
        //     Timing note: guests may not be up yet when we flip this.
        //     The writer runs every `interval`, so the flag stays
        //     latched on subsequent iterations — any guest booting
        //     later reads the already-set state. seqcount_write
        //     handles read-side atomicity for guests that connect
        //     mid-write.
        let now_mono = clock.now_mono_ns();
        let now_wall_off = clock.wall_offset_ns().saturating_add(st.wall_correction_ns);
        let now_wall_ns = (now_mono as i64).saturating_add(now_wall_off);
        if (st.flags & VTIME_FLAG_SYNC_VALID) == 0 && now_wall_ns > EPOCH_2024_NS {
            st.flags |= VTIME_FLAG_SYNC_VALID;
            st.sync_source = vm_wire::SyncSource::Sntp;
            st.sync_quality = vm_wire::SyncQuality::Coarse;
            st.last_sync_mono_ns = now_mono;
            tracing::info!(
                target: "vtime",
                wall_ns = now_wall_ns,
                "host clock crossed plausibility threshold — self-electing as SNTP source"
            );
        }

        // 2. Build host's slot: regs in the top 64 bytes, status reply
        //    in the bottom 64 bytes. The bottom-64 layout matches
        //    VtimeCmd so the guest can decode it as a status reply
        //    (status field at the same offset as in a request).
        st.update_seq = st.update_seq.wrapping_add(2);

        let regs = VtimeRegs {
            mono_ns: now_mono,
            wall_offset_ns: now_wall_off,
            last_sync_mono_ns: st.last_sync_mono_ns,
            sync_source: st.sync_source,
            sync_quality: st.sync_quality,
            min_wall_ns: 0,
            flags: st.flags,
            update_seq: st.update_seq,
        };
        let reply = VtimeCmd {
            seq: st.last_cmd_seq,
            op: 0,
            correction_ns: 0,
            sync_source: st.sync_source,
            sync_quality: st.sync_quality,
            status: st.last_cmd_status,
            guest_id: 0,
        };

        // notify() pokes the guest's vdev slot to wake it for a re-read.
        // Its success also serves as a liveness signal: when the guest
        // isn't attached, the qvm vdev layer logs "remote side not ready"
        // on every poke. We use the result to drive an adaptive cadence
        // (see the sleep below) rather than poking an absent peer at the
        // full rate.
        let peer_reachable = if single_channel_mode {
            // qvm-shmem path: regs + reply combined in one 128-byte
            // buffer, written to the single channel (host's own slot).
            let mut buf = [0u8; VTIME_WIRE_SIZE];
            buf[..VTIME_REGS_SIZE].copy_from_slice(&regs.to_regs_bytes());
            buf[VTIME_REGS_SIZE..].copy_from_slice(&reply.to_cmd_bytes());
            if let Err(e) = regs_channel.write(&buf) {
                tracing::warn!("vtime write failed: {e}");
            }
            regs_channel.notify().is_ok()
        } else {
            // HTTP path: regs to regs channel (cmd half zero), reply
            // to adjust channel (regs half zero). The adjust write is
            // idempotent — it always carries the latest ack, regardless
            // of whether a new cmd was processed this tick. Same shape
            // makes the guest's poll-for-ack code transport-agnostic.
            let mut regs_buf = [0u8; VTIME_WIRE_SIZE];
            regs_buf[..VTIME_REGS_SIZE].copy_from_slice(&regs.to_regs_bytes());
            if let Err(e) = regs_channel.write(&regs_buf) {
                tracing::warn!("vtime regs write failed: {e}");
            }
            let regs_ok = regs_channel.notify().is_ok();

            let mut adj_buf = [0u8; VTIME_WIRE_SIZE];
            adj_buf[VTIME_REGS_SIZE..].copy_from_slice(&reply.to_cmd_bytes());
            if let Err(e) = adjust_channel.write(&adj_buf) {
                tracing::warn!("vtime adjust write failed: {e}");
            }
            let adj_ok = adjust_channel.notify().is_ok();
            // HTTP notify has no peer-attach concept — treat success as
            // reachable so HTTP transports keep the base cadence.
            regs_ok && adj_ok
        };

        // Adaptive cadence: run at the base `interval` while the guest is
        // reachable; back off while it isn't, so an unattached guest (vm1
        // still booting, or a VM that never came up) isn't poked at the
        // base rate — every such poke makes qvm log "remote side not
        // ready". Snaps straight back to the base rate the moment the
        // guest attaches and the poke succeeds again.
        const PEER_ABSENT_BACKOFF: Duration = Duration::from_secs(2);
        let sleep_for = if peer_reachable {
            interval
        } else {
            interval.max(PEER_ABSENT_BACKOFF)
        };
        thread::sleep(sleep_for);
    }
}

/// Validate + apply a TIME_ADJUST cmd. Updates `st` with the new
/// status code so the next regs write publishes the ack.
fn process_adjust(cmd: &vm_wire::VtimeCmd, st: &mut WriterState, clock: &Arc<dyn Clock>) {
    use vm_wire::{
        VTIME_CMD_ADJUST, VTIME_FLAG_SYNC_VALID, VTIME_STATUS_APPLIED, VTIME_STATUS_RATE_LIMITED,
        VTIME_STATUS_REJECTED, VTIME_STATUS_UNAUTHORIZED,
    };

    // Always claim ownership of this seq so we never re-process it on
    // the next tick — even on rejection. Guest must bump seq for retry.
    st.last_cmd_seq = cmd.seq;

    if cmd.op != VTIME_CMD_ADJUST {
        // Unknown op — silently mark applied=false. Treat as rejected.
        st.last_cmd_status = VTIME_STATUS_REJECTED;
        return;
    }

    if TIME_DEFAULT_SYNC_GUEST_ID != 0 && cmd.guest_id != TIME_DEFAULT_SYNC_GUEST_ID {
        tracing::warn!(
            guest_id = cmd.guest_id,
            "TIME_ADJUST rejected: unauthorized guest"
        );
        st.last_cmd_status = VTIME_STATUS_UNAUTHORIZED;
        return;
    }

    if let Some(prev) = st.last_adjust {
        if prev.elapsed() < TIME_DEFAULT_MIN_ADJUST_INTERVAL {
            tracing::debug!("TIME_ADJUST rate-limited");
            st.last_cmd_status = VTIME_STATUS_RATE_LIMITED;
            return;
        }
    }

    if cmd.correction_ns.abs() > TIME_DEFAULT_MAX_CORRECTION_NS {
        tracing::warn!(
            correction_ns = cmd.correction_ns,
            max = TIME_DEFAULT_MAX_CORRECTION_NS,
            "TIME_ADJUST rejected: correction exceeds magnitude bound"
        );
        st.last_cmd_status = VTIME_STATUS_REJECTED;
        return;
    }

    // Accept.
    st.wall_correction_ns = st.wall_correction_ns.saturating_add(cmd.correction_ns);
    st.sync_source = cmd.sync_source;
    st.sync_quality = cmd.sync_quality;
    st.last_sync_mono_ns = clock.now_mono_ns();
    st.flags |= VTIME_FLAG_SYNC_VALID;
    st.last_adjust = Some(Instant::now());
    st.last_cmd_status = VTIME_STATUS_APPLIED;

    tracing::info!(
        correction_ns = cmd.correction_ns,
        new_wall_correction_ns = st.wall_correction_ns,
        source = ?cmd.sync_source,
        quality = ?cmd.sync_quality,
        "TIME_ADJUST applied"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mem::{MemDoorbell, MemSharedMemory};

    struct FixedClock {
        mono: u64,
        wall_off: i64,
    }
    impl Clock for FixedClock {
        fn now_mono_ns(&self) -> u64 {
            self.mono
        }
        fn wall_offset_ns(&self) -> i64 {
            self.wall_off
        }
    }

    fn make_sim() -> TimeSim<MemSharedMemory, MemDoorbell, FixedClock> {
        let shm = MemSharedMemory::new(r::REGION_SIZE);
        let clock = Arc::new(FixedClock {
            mono: 5_000_000_000,
            wall_off: 1_700_000_000_000_000_000, // ~2023 epoch offset
        });
        TimeSim::new(shm, MemDoorbell, clock).with_min_adjust_interval(Duration::ZERO)
    }

    #[test]
    fn init_writes_header() {
        let sim = make_sim();
        sim.init();

        assert_eq!(sim.shm.read_u32(r::OFF_MAGIC), r::MAGIC);
        assert_eq!(sim.shm.read_u32(r::OFF_VERSION), r::VERSION);
    }

    #[test]
    fn update_time_writes_registers() {
        let sim = make_sim();
        sim.init();
        sim.update_time();

        assert_eq!(sim.shm.read_u64(r::OFF_MONO_NS), 5_000_000_000);
        let wall_off = sim.shm.read_i64(r::OFF_WALL_OFFSET_NS);
        assert_eq!(wall_off, 1_700_000_000_000_000_000);
    }

    #[test]
    fn update_time_increments_seqcount() {
        let sim = make_sim();
        sim.init();

        let seq_before = sim.shm.read_u32(r::OFF_UPDATE_SEQ);
        sim.update_time();
        let seq_after = sim.shm.read_u32(r::OFF_UPDATE_SEQ);

        assert_eq!(seq_after, seq_before + 2);
        assert_eq!(seq_after % 2, 0);
    }

    #[test]
    fn adjust_applies_correction() {
        let mut sim = make_sim();
        sim.init();
        sim.update_time();

        // Simulate guest writing TIME_ADJUST command
        sim.shm.write_u32(r::CMD_OFF_SEQ, 1);
        sim.shm.write_u32(r::CMD_OFF_OP, r::CMD_ADJUST as u32);
        sim.shm.write_i64(r::CMD_OFF_CORRECTION_NS, 1_000_000); // +1ms
        sim.shm.write_u32(r::CMD_OFF_SYNC_SOURCE, r::SRC_NTP);
        sim.shm
            .write_u32(r::CMD_OFF_SYNC_QUALITY, r::QUALITY_MEDIUM);
        sim.shm.write_u32(r::CMD_OFF_GUEST_ID, 1);

        sim.check_adjust();

        assert_eq!(sim.shm.read_u32(r::CMD_OFF_STATUS), r::STATUS_APPLIED);
        assert_eq!(sim.shm.read_u32(r::OFF_SYNC_SOURCE), r::SRC_NTP);
        assert_eq!(sim.shm.read_u32(r::OFF_FLAGS), r::FLAG_SYNC_VALID);

        // Wall offset should include correction
        let wall_off = sim.shm.read_i64(r::OFF_WALL_OFFSET_NS);
        assert_eq!(wall_off, 1_700_000_000_000_000_000 + 1_000_000);
    }

    #[test]
    fn adjust_rejects_unauthorized_guest() {
        let mut sim = make_sim();
        sim.init();

        sim.shm.write_u32(r::CMD_OFF_SEQ, 1);
        sim.shm.write_u32(r::CMD_OFF_OP, r::CMD_ADJUST as u32);
        sim.shm.write_i64(r::CMD_OFF_CORRECTION_NS, 1_000_000);
        sim.shm.write_u32(r::CMD_OFF_GUEST_ID, 99); // wrong guest

        sim.check_adjust();

        assert_eq!(sim.shm.read_u32(r::CMD_OFF_STATUS), r::STATUS_UNAUTHORIZED);
    }

    #[test]
    fn adjust_rejects_excessive_correction() {
        let mut sim = make_sim();
        sim.init();

        // More than 1 hour correction
        sim.shm.write_u32(r::CMD_OFF_SEQ, 1);
        sim.shm.write_u32(r::CMD_OFF_OP, r::CMD_ADJUST as u32);
        sim.shm
            .write_i64(r::CMD_OFF_CORRECTION_NS, 4_000_000_000_000); // 4 hours
        sim.shm.write_u32(r::CMD_OFF_GUEST_ID, 1);

        sim.check_adjust();

        assert_eq!(sim.shm.read_u32(r::CMD_OFF_STATUS), r::STATUS_REJECTED);
    }
}
