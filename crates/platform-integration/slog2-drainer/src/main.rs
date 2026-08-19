//! `slog2-drainer` — persist the QNX slog2 ring to sealed disk segments.
//!
//! A Tier-2 host daemon. It live-follows the kernel slog2 ring
//! ([`platform_log::drain_live`], DYNAMIC parse) and appends each packet as a
//! stamped line to a RAM live file `<segdir_live>/<stem>.log`. At a size ceiling
//! it SEALS the live file to a flash segment `<segdir_sealed>/<stem>.<seq>.log`
//! (immutable, append-only) and reopens the live file fresh, culling the oldest
//! sealed segments to a total byte budget. The monotonic `seq` (derived from the
//! highest existing segment, never reused) is the reboot-safe cursor spine that
//! `platform_log::read_segments` pages over.
//!
//! This mirrors the guest `svclog` C writer exactly, so the SAME segment reader
//! serves both. The ring stays volatile + tail-able (`LogSource::Slog2`); this
//! adds the durable, cursor-pageable history plane (`LogSource::Slog2Segments`).
//!
//! Persist policy (what's WORTH keeping on flash — live appends are free in RAM):
//! a severity FLOOR (default `info`+, so supernova's operational trail persists —
//! it emits at `info`, never `notice`) and an emitter DENYLIST (default
//! `devb_,CAM` — the eMMC/CAM driver firehose). Both env-tunable. Everything is
//! still live-tailable via the ring regardless; the policy only bounds what
//! PERSISTS.
//!
//! Segment line format: `<20-char ISO stamp> <priority> <message>` — the priority
//! token preserves severity so the durable timeline isn't severity-blind (the
//! reader's `seg_record` recovers it).
//!
//! QNX-only in effect: off-nto `drain_live` is a no-op, so `main` exits cleanly
//! (the crate builds + tests everywhere; the segmenter logic is target-agnostic).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use platform_log::{rfc3339_utc, DrainRecord};

const DEFAULT_MAX_BYTES: u64 = 256 * 1024; // rotate threshold (live file ceiling)
const DEFAULT_KEEP_BYTES: u64 = 1024 * 1024; // total budget (live + sealed)
const DEFAULT_STEM: &str = "slog2";
// The RAM live file lives DIRECTLY in /dev/shmem — NOT a subdir. On QNX
// /dev/shmem is a flat shmem-object namespace that does not support mkdir
// (subdir creation → ENOSYS), so the live file is `/dev/shmem/<stem>.log`,
// mirroring svclog's flat `/dev/shmem/<svc>.log` convention.
const DEFAULT_LIVE_DIR: &str = "/dev/shmem";
const DEFAULT_SEALED_DIR: &str = "/mnt/common-rw/log/segments";
/// slog2 severity below which a packet isn't persisted (still ring-tailable).
/// Names→rank via [`severity_rank`]; default keeps `info` and more-severe.
///
/// `info`, NOT `notice`: supernova (via score-log-slog2) maps its `Info` level to
/// SLOG2_INFO and NEVER emits at `notice` (score-log-slog2: "SLOG2_NOTICE exists
/// but nothing maps to it"). A `notice+` floor therefore dropped supernova's ENTIRE
/// operational trail (ivd-route, vhsm handshakes, bank serving) — the durable
/// `slog2` timeline captured only boot-time OS lines + the rare WARNING, so it read
/// nearly empty on a healthy device while all real content lived only in the
/// volatile ring. `info` makes the persisted timeline actually mirror supernova.
/// Flash wear stays bounded by the emitter denylist (kills the `devb_`/CAM driver
/// firehose — the real volume) + the cull budget (SVCLOG_KEEP_BYTES); info-level
/// supernova traffic itself is light. Override with SLOG2_DRAINER_SEVERITY_FLOOR.
const DEFAULT_SEVERITY_FLOOR: &str = "info";
/// Emitter prefixes never persisted (comma-separated, prefix-matched).
const DEFAULT_EMITTER_DENYLIST: &str = "devb_,CAM";

/// The persist policy: which packets are worth keeping on flash.
struct Policy {
    /// Keep a packet iff its severity rank ≤ this (lower rank = more severe).
    floor_rank: u8,
    /// Drop a packet whose emitter starts with any of these prefixes.
    deny_prefixes: Vec<String>,
}

impl Policy {
    fn keeps(&self, rec: &DrainRecord) -> bool {
        if severity_rank(rec.priority) > self.floor_rank {
            return false;
        }
        !self
            .deny_prefixes
            .iter()
            .any(|p| !p.is_empty() && rec.emitter.starts_with(p.as_str()))
    }
}

/// SOVD priority name → syslog-style rank (0 = most severe). Mirrors the reader's
/// severity mapping so "floor = notice" means notice + warning + error + … kept.
fn severity_rank(name: &str) -> u8 {
    match name {
        "emergency" => 0,
        "alert" => 1,
        "critical" => 2,
        "error" => 3,
        "warning" => 4,
        "notice" => 5,
        "info" => 6,
        "debug" => 7,
        _ => 6,
    }
}

/// The segment writer — the Rust mirror of svclog's write path. All filesystem
/// state lives here so it's unit-testable against a tempdir.
struct Segmenter {
    live_dir: PathBuf,
    sealed_dir: PathBuf,
    stem: String,
    max_bytes: u64,
    keep_bytes: u64,
    /// Bytes currently in the live file.
    written: u64,
    /// The seq to assign the NEXT sealed segment (derive-from-max + 1; monotonic,
    /// never reused even across culls or reboots).
    next_seq: u64,
}

impl Segmenter {
    fn new(
        live_dir: PathBuf,
        sealed_dir: PathBuf,
        stem: String,
        max_bytes: u64,
        keep_bytes: u64,
    ) -> std::io::Result<Self> {
        // The live dir is typically /dev/shmem — a pre-existing flat shmem
        // namespace that rejects mkdir (ENOSYS). Only create it if absent, and
        // tolerate an ENOSYS/EEXIST when it's already there (don't hard-fail init
        // over a dir that exists). The SEALED dir is a normal fs dir → must exist.
        if !live_dir.exists() {
            if let Err(e) = fs::create_dir_all(&live_dir) {
                if !live_dir.exists() {
                    return Err(e);
                }
            }
        }
        fs::create_dir_all(&sealed_dir)?;
        let next_seq = max_existing_seq(&sealed_dir, &stem) + 1;
        let live_path = live_dir.join(format!("{stem}.log"));
        // Seed `written` from any existing live file (a warm restart keeps
        // appending; svclog's open_live does the same via ftell).
        let written = fs::metadata(&live_path).map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            live_dir,
            sealed_dir,
            stem,
            // keep_bytes floored to ≥ max_bytes (a budget below one segment is
            // meaningless); mirrors svclog's startup floor.
            max_bytes,
            keep_bytes: keep_bytes.max(max_bytes),
            written,
            next_seq,
        })
    }

    fn live_path(&self) -> PathBuf {
        self.live_dir.join(format!("{}.log", self.stem))
    }

    fn seg_path(&self, seq: u64) -> PathBuf {
        self.sealed_dir.join(format!("{}.{seq}.log", self.stem))
    }

    /// Format one record as a sealed-segment line:
    /// `<20-char ISO stamp> <uptime-secs> <priority> <message>\n`.
    ///
    /// Two metadata tokens sit between the stamp and the message so the durable
    /// timeline preserves BOTH the monotonic runtime (the jump-proof
    /// `x-sumo-runtime` window axis) AND the severity. The reader's
    /// `split_leading_stamp` parses the leading 20-char wall stamp; `seg_record`
    /// then peels the uptime (a bare integer) and the priority token in order.
    fn format_line(rec: &DrainRecord) -> String {
        // rfc3339_utc yields `YYYY-MM-DDThh:mm:ssZ` (20 chars); + a space = the
        // 21-char prefix the reader's split_leading_stamp requires, then
        // `<uptime> <priority> ` before the message.
        let msg = rec.message.trim_end_matches('\n');
        format!(
            "{} {} {} {}\n",
            rfc3339_utc(rec.epoch_secs),
            rec.uptime_secs,
            rec.priority,
            msg
        )
    }

    /// Apply policy, then append the record — rotating FIRST if this line would
    /// exceed the live ceiling (svclog's rotate-before-write). A dropped-by-policy
    /// record is a no-op.
    fn write(&mut self, rec: &DrainRecord, policy: &Policy) -> std::io::Result<()> {
        if !policy.keeps(rec) {
            return Ok(());
        }
        let line = Self::format_line(rec);
        let rec_len = line.len() as u64;
        if self.written > 0 && self.written + rec_len > self.max_bytes {
            self.seal_and_rotate()?;
        }
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.live_path())?;
        f.write_all(line.as_bytes())?;
        f.flush()?; // crash-readable live file (svclog fflushes per line)
        self.written += rec_len;
        Ok(())
    }

    /// Seal the live file → `<sealed_dir>/<stem>.<seq>.log`, reopen live fresh,
    /// cull to budget. RAM→flash is cross-device, so this is always copy+truncate
    /// (rename would EXDEV); we do the copy directly.
    fn seal_and_rotate(&mut self) -> std::io::Result<()> {
        let seq = self.next_seq;
        self.next_seq += 1;
        let live = self.live_path();
        let seg = self.seg_path(seq);
        // Copy live → sealed segment (immutable henceforth), then truncate live.
        if live.exists() {
            fs::copy(&live, &seg)?;
        }
        // Truncate the live file (bound RAM even if it didn't exist).
        fs::File::create(&live)?;
        self.written = 0;
        // Segment budget reserves headroom for the live file to refill to the
        // rotate threshold, so (live + sealed) ≤ keep_bytes worst case.
        let seg_budget = self.keep_bytes.saturating_sub(self.max_bytes);
        self.cull(seg_budget);
        Ok(())
    }

    /// Delete oldest-seq sealed segments until their total ≤ `seg_budget`. seq
    /// never resets, so the cursor stays monotonic across culls.
    fn cull(&self, seg_budget: u64) {
        loop {
            let mut segs = list_segments(&self.sealed_dir, &self.stem);
            let total: u64 = segs.iter().map(|(_, sz, _)| *sz).sum();
            if total <= seg_budget || segs.is_empty() {
                return;
            }
            segs.sort_by_key(|(seq, _, _)| *seq); // oldest first
            let (_, _, path) = &segs[0];
            if fs::remove_file(path).is_err() {
                return; // can't remove — avoid a spin
            }
        }
    }
}

/// The seq of a sealed segment name `<stem>.<seq>.log`, else `None` (live file /
/// non-match). Mirrors svclog `seg_seq_of` + `platform_log::seg_seq_of`.
fn seg_seq_of(name: &str, stem: &str) -> Option<u64> {
    let rest = name.strip_prefix(stem)?.strip_prefix('.')?;
    let seq = rest.strip_suffix(".log")?;
    if seq.is_empty() || !seq.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    seq.parse::<u64>().ok()
}

/// Highest existing sealed seq for `stem` in `dir` (0 if none). Next assigned =
/// this + 1 — derive-from-max, no persisted counter.
fn max_existing_seq(dir: &Path, stem: &str) -> u64 {
    list_segments(dir, stem)
        .iter()
        .map(|(seq, _, _)| *seq)
        .max()
        .unwrap_or(0)
}

/// All sealed segments for `stem` in `dir`: (seq, size_bytes, path).
fn list_segments(dir: &Path, stem: &str) -> Vec<(u64, u64, PathBuf)> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if let Some(seq) = seg_seq_of(&name, stem) {
                let sz = e.metadata().map(|m| m.len()).unwrap_or(0);
                out.push((seq, sz, e.path()));
            }
        }
    }
    out
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_str(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn main() {
    let live_dir = PathBuf::from(env_str("SLOG2_DRAINER_LIVE_DIR", DEFAULT_LIVE_DIR));
    let sealed_dir = PathBuf::from(env_str("SLOG2_DRAINER_SEALED_DIR", DEFAULT_SEALED_DIR));
    let stem = env_str("SLOG2_DRAINER_STEM", DEFAULT_STEM);
    let max_bytes = env_u64("SVCLOG_MAX_BYTES", DEFAULT_MAX_BYTES);
    let keep_bytes = env_u64("SVCLOG_KEEP_BYTES", DEFAULT_KEEP_BYTES);
    let policy = Policy {
        floor_rank: severity_rank(&env_str(
            "SLOG2_DRAINER_SEVERITY_FLOOR",
            DEFAULT_SEVERITY_FLOOR,
        )),
        deny_prefixes: env_str("SLOG2_DRAINER_EMITTER_DENY", DEFAULT_EMITTER_DENYLIST)
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    };

    let seg = match Segmenter::new(
        live_dir.clone(),
        sealed_dir.clone(),
        stem.clone(),
        max_bytes,
        keep_bytes,
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("slog2-drainer: cannot init (live={live_dir:?} sealed={sealed_dir:?}): {e}");
            std::process::exit(1);
        }
    };

    eprintln!(
        "slog2-drainer: stem={stem} live={live_dir:?} sealed={sealed_dir:?} \
         max={max_bytes} keep={keep_bytes} next_seq={} floor={} deny={:?}",
        seg.next_seq, policy.floor_rank, policy.deny_prefixes
    );

    // SEAL-ON-SHUTDOWN. The live file lives in /dev/shmem (RAM) — a reboot wipes it,
    // and hop-2 sealing only fires at the size ceiling, so a small pre-reboot burst
    // (e.g. an OTA flash's finalize/`boot-vector write` lines) is normally LOST on
    // reboot. supernova's reboot path SIGTERMs us (with a bounded grace) BEFORE the
    // kernel reset so we can flush the live file to a durable disk segment first.
    //
    // Pattern (mirrors vhsm-ssd's signal path): BLOCK SIGTERM/SIGINT in the main
    // thread, then a dedicated waiter thread `sigwait`s them. `sigwait` returns in
    // NORMAL thread context (NOT a signal handler), so the seal — which does file
    // I/O — runs directly, with no async-signal-safety constraints and no atomic
    // dance. The FFI drain runs on this (main) thread; the waiter seals + exits the
    // process on the signal.
    let seg = std::sync::Arc::new(std::sync::Mutex::new(seg));

    #[cfg(unix)]
    {
        block_term_int_in_main_thread();
        let seg = std::sync::Arc::clone(&seg);
        std::thread::Builder::new()
            .name("drain-seal-on-term".into())
            .spawn(move || {
                let sig = wait_for_term_int();
                // Flush the RAM live file → a durable disk segment before exit, so
                // the pre-reboot window survives (the reboot wipes /dev/shmem).
                match seg.lock().map(|mut s| s.seal_and_rotate()) {
                    Ok(Ok(())) => {
                        eprintln!("slog2-drainer: sealed live file on signal {sig} — exiting")
                    }
                    Ok(Err(e)) => eprintln!("slog2-drainer: shutdown seal failed: {e}"),
                    Err(_) => eprintln!("slog2-drainer: segmenter lock poisoned at shutdown"),
                }
                std::process::exit(0);
            })
            .ok();
    }

    // BLOCKS forever on QNX (the DYNAMIC ring stream never ends); the seal-on-term
    // thread exits the process on SIGTERM. A no-op that returns immediately off-nto
    // (so the bin builds + exits cleanly on Linux).
    platform_log::drain_live(move |rec| {
        if let Ok(mut s) = seg.lock() {
            if let Err(e) = s.write(&rec, &policy) {
                eprintln!("slog2-drainer: write failed: {e}");
            }
        }
    });
}

/// The SIGTERM+SIGINT set — one place so block + wait use a byte-identical set.
#[cfg(unix)]
fn term_int_set() -> libc::sigset_t {
    // SAFETY: a zeroed sigset_t is a valid (empty) set on Linux/QNX; sigemptyset +
    // sigaddset then populate it per the libc contract.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGINT);
        set
    }
}

/// Block SIGTERM/SIGINT in the current (main) thread so the waiter thread can
/// `sigwait` them (the block is inherited by later-spawned threads). Mirrors
/// vhsm-ssd's proven-on-QNX signal path.
#[cfg(unix)]
fn block_term_int_in_main_thread() {
    let set = term_int_set();
    // SAFETY: a standard POSIX sigmask call with a valid set pointer.
    unsafe {
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
}

/// Block until SIGTERM/SIGINT, returning the signal number. `sigwait` returns
/// OUTSIDE handler context, so the caller may run arbitrary code (the seal) after.
/// A nonzero return (e.g. EINTR) → wait again rather than return spuriously.
#[cfg(unix)]
fn wait_for_term_int() -> libc::c_int {
    let set = term_int_set();
    let mut sig: libc::c_int = 0;
    // SAFETY: `set` and `sig` are valid, suitably-aligned locals.
    while unsafe { libc::sigwait(&set, &mut sig) } != 0 {}
    sig
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("drainer-{}-{}", std::process::id(), tag));
        let live = base.join("live");
        let sealed = base.join("sealed");
        let _ = fs::remove_dir_all(&base);
        (live, sealed)
    }

    fn rec(secs: u64, prio: &'static str, emitter: &str, msg: &str) -> DrainRecord {
        DrainRecord {
            epoch_secs: secs,
            // A stand-in monotonic value for tests: use the wall secs so the
            // uptime column is present + round-trips. Real drains read
            // CLOCK_MONOTONIC (slog2_reader::monotonic_secs).
            uptime_secs: secs,
            priority: prio,
            emitter: emitter.to_string(),
            message: msg.to_string(),
        }
    }

    fn all_kept() -> Policy {
        Policy {
            floor_rank: 7,
            deny_prefixes: vec![],
        }
    }

    #[test]
    fn new_tolerates_preexisting_live_dir() {
        // Regression: on QNX the live dir is /dev/shmem — a pre-existing flat
        // namespace that rejects mkdir (ENOSYS). Init must NOT fail when the live
        // dir already exists (the earlier bug: create_dir_all on a /dev/shmem
        // SUBDIR returned ENOSYS and killed the drainer at startup).
        let (live, sealed) = tmp("preexist");
        fs::create_dir_all(&live).unwrap(); // simulate /dev/shmem already present
        let s = Segmenter::new(live.clone(), sealed, "slog2".into(), 256, 1024)
            .unwrap_or_else(|e| panic!("init must succeed with a pre-existing live dir: {e}"));
        assert_eq!(s.live_path(), live.join("slog2.log"), "flat live file");
    }

    #[test]
    fn format_line_matches_split_leading_stamp_contract() {
        let line = Segmenter::format_line(&rec(1_784_562_613, "error", "snova", "hello"));
        // `<stamp> <uptime> <priority> <message>` — uptime + severity preserved.
        // (rec() sets uptime_secs = the wall secs as a stand-in.)
        assert_eq!(line, "2026-07-20T15:50:13Z 1784562613 error hello\n");
        // Reader parses the stamp back off it; the uptime + priority tokens follow.
        let (stamp, rest) = platform_log::split_leading_stamp(line.trim_end_matches('\n'));
        assert_eq!(stamp, Some("2026-07-20T15:50:13Z"));
        assert_eq!(rest, "1784562613 error hello");
    }

    #[test]
    fn seq_derives_from_max_existing() {
        let (live, sealed) = tmp("seqderive");
        fs::create_dir_all(&sealed).unwrap();
        fs::write(sealed.join("slog2.7.log"), b"x").unwrap();
        fs::write(sealed.join("slog2.42.log"), b"x").unwrap();
        fs::write(sealed.join("slog2.9.log"), b"x").unwrap();
        let s = Segmenter::new(live, sealed, "slog2".into(), 256, 1024).unwrap();
        assert_eq!(s.next_seq, 43, "next = max(7,42,9)+1");
    }

    #[test]
    fn rotates_and_seals_at_ceiling() {
        let (live, sealed) = tmp("rotate");
        // Tiny ceiling so a couple lines rotate; big budget so nothing culls.
        let mut s =
            Segmenter::new(live.clone(), sealed.clone(), "slog2".into(), 40, 100_000).unwrap();
        let p = all_kept();
        // Each formatted line is ~30 bytes; the 2nd should trip the 40-byte ceiling.
        s.write(&rec(1_784_562_613, "info", "e", "line-one"), &p)
            .unwrap();
        s.write(&rec(1_784_562_614, "info", "e", "line-two"), &p)
            .unwrap();
        s.write(&rec(1_784_562_615, "info", "e", "line-three"), &p)
            .unwrap();
        let segs = list_segments(&sealed, "slog2");
        assert!(
            !segs.is_empty(),
            "at least one sealed segment after rotates"
        );
        // Sealed segments read back through the real reader, in order.
        let q = platform_log::LogQuery {
            tail: Some(100),
            ..Default::default()
        };
        let page = platform_log::read_segments(&sealed, "slog2", None, &q);
        // The live file (not in `sealed` dir) isn't read here; sealed history is.
        let msgs: Vec<_> = page.items.iter().map(|r| r.message.clone()).collect();
        assert!(msgs.contains(&"line-one".to_string()), "got {msgs:?}");
        // Severity round-trips: the written priority is recovered on read-back
        // (not fabricated as `info`). "line-one" was written at `info`; verify a
        // non-info line too via the priority-preservation test below.
        let one = page.items.iter().find(|r| r.message == "line-one").unwrap();
        assert_eq!(
            one.priority, "info",
            "priority recovered from the segment line"
        );
    }

    #[test]
    fn severity_round_trips_through_segments() {
        let (live, sealed) = tmp("severity");
        let mut s =
            Segmenter::new(live, sealed.clone(), "slog2".into(), 100_000, 1_000_000).unwrap();
        let p = all_kept();
        s.write(&rec(1_784_562_613, "error", "snova", "boom"), &p)
            .unwrap();
        s.write(&rec(1_784_562_614, "warning", "snova", "careful"), &p)
            .unwrap();
        // Force a seal so the reader walks a sealed segment.
        s.seal_and_rotate().unwrap();
        let page = platform_log::read_segments(
            &sealed,
            "slog2",
            None,
            &platform_log::LogQuery {
                tail: Some(100),
                ..Default::default()
            },
        );
        let by_msg = |m: &str| {
            page.items
                .iter()
                .find(|r| r.message == m)
                .unwrap_or_else(|| panic!("missing {m}: {:?}", page.items))
                .priority
                .clone()
        };
        assert_eq!(by_msg("boom"), "error", "error severity preserved");
        assert_eq!(by_msg("careful"), "warning", "warning severity preserved");
    }

    #[test]
    fn culls_oldest_to_budget() {
        let (live, sealed) = tmp("cull");
        // max=40, keep=80 → seg_budget = 40: only ~one segment's worth survives.
        let mut s = Segmenter::new(live, sealed.clone(), "slog2".into(), 40, 80).unwrap();
        let p = all_kept();
        for i in 0..8 {
            s.write(
                &rec(1_784_562_613 + i, "info", "e", &format!("msg{i:02}")),
                &p,
            )
            .unwrap();
        }
        let segs = list_segments(&sealed, "slog2");
        let total: u64 = segs.iter().map(|(_, sz, _)| *sz).sum();
        assert!(
            total <= 40,
            "sealed total {total} must be within seg_budget 40"
        );
        // seq kept climbing across culls (monotonic): the surviving seg's seq > 0.
        assert!(segs.iter().all(|(seq, _, _)| *seq >= 1));
    }

    #[test]
    fn policy_severity_floor_and_emitter_denylist() {
        let (live, sealed) = tmp("policy");
        let mut s =
            Segmenter::new(live, sealed.clone(), "slog2".into(), 100_000, 1_000_000).unwrap();
        let p = Policy {
            floor_rank: severity_rank("notice"), // keep notice+; drop info/debug
            deny_prefixes: vec!["devb_".into(), "CAM".into()],
        };
        s.write(&rec(1, "info", "snova", "info-dropped"), &p)
            .unwrap();
        s.write(&rec(2, "debug", "snova", "debug-dropped"), &p)
            .unwrap();
        s.write(&rec(3, "warning", "snova", "warn-kept"), &p)
            .unwrap();
        s.write(&rec(4, "error", "devb_sdmmc_mx8x", "driver-dropped"), &p)
            .unwrap();
        s.write(&rec(5, "error", "snova", "err-kept"), &p).unwrap();
        // Read the LIVE file directly (nothing sealed — huge ceiling).
        let live_body = fs::read_to_string(s.live_path()).unwrap();
        assert!(live_body.contains("warn-kept"));
        assert!(live_body.contains("err-kept"));
        assert!(
            !live_body.contains("dropped"),
            "policy must drop: {live_body}"
        );
    }
}
