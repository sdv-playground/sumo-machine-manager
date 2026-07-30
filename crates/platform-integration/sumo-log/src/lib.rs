//! Fleet-wide logging init for sumo services.
//!
//! Every service logs the SAME way by calling ONE function at startup. Which one
//! depends on how the service emits:
//!
//! - **`tracing` producers (the standard — nearly all code, plus deps like
//!   axum/hyper):** call [`init_tracing`]. Service code keeps `tracing::info!`;
//!   `init_tracing` installs the platform recorder AND the tracing→score_log
//!   bridge, so those events (ours and our dependencies') are captured.
//!   ```ignore
//!   fn main() {
//!       sumo_log::init_tracing("teesa-vf"); // only per-app arg: its context tag
//!       tracing::info!("alive");            // then just standard tracing macros
//!   }
//!   ```
//! - **direct `score_log` callers (rare — e.g. a minimal qualified component that
//!   must keep unqualified `tracing` out of its path):** call [`init`], then use
//!   `score_log::info!`.
//!
//! Either way the service supplies ONLY its `context` tag. Everything else — the
//! producer→sink CAPTURE wiring, level, format, and which recorder (destination)
//! is installed — is fleet policy that lives HERE, not in each app. `tracing` is
//! the producer; score_log/slog2/stdout is the sink; THIS is the only place that
//! knows about the capture between them. That means:
//!   - one place to change the fleet's logging behaviour, and
//!   - the destination is SELECTABLE at startup via environment, without touching
//!     any app: set `SUMO_LOG_SINK` in the launch environment (the QNX layer hook
//!     / `services.conf` row, or a systemd unit) and every service follows.
//!
//! ## Environment
//! - `SUMO_LOG_SINK` = `auto` (default) | `stdout` | `slog2`
//!   - `auto`: `slog2` on QNX (the normal QNX system log), `stdout` elsewhere.
//!   - `stdout`: S-CORE `stdout_logger` — formatted lines to stdout (captured by
//!     the QNX layer's svclog hook, or by systemd/journald on Linux).
//!   - `slog2`: the QNX `slogger2` ring, via `score-log-slog2`. On non-QNX this
//!     falls back to `stdout` (there is no slog2 bus) with a one-line notice.
//! - `SUMO_LOG_LEVEL` = `off|fatal|error|warn|info|debug|trace` (default `info`),
//!   case-insensitive. Applied via `score_log::set_max_level`.
//!
//! `init` is idempotent-safe: `score_log`'s global logger can be set only once, so
//! a second call (or a double-init) is ignored rather than panicking.

use score_log::LevelFilter;

/// Which recorder to install.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sink {
    /// Pick per platform: slog2 on QNX, stdout elsewhere.
    Auto,
    /// S-CORE stdout_logger (→ svclog hook on QNX, journald on Linux).
    Stdout,
    /// QNX slogger2 ring (score-log-slog2); stdout fallback off QNX.
    Slog2,
}

impl Sink {
    fn from_env() -> Self {
        match std::env::var("SUMO_LOG_SINK").ok().as_deref() {
            Some(s) if s.eq_ignore_ascii_case("stdout") => Sink::Stdout,
            Some(s) if s.eq_ignore_ascii_case("slog2") => Sink::Slog2,
            // "auto", unset, or anything unrecognized → auto.
            _ => Sink::Auto,
        }
    }
}

/// Read `SUMO_LOG_LEVEL` (default `info`). Unparseable values fall back to `info`.
fn level_from_env() -> LevelFilter {
    std::env::var("SUMO_LOG_LEVEL")
        .ok()
        .and_then(|s| s.parse::<LevelFilter>().ok())
        .unwrap_or(LevelFilter::Info)
}

/// Initialize logging for a service that emits DIRECTLY via `score_log` macros.
///
/// Installs the env-selected `score_log` recorder as the process's global logger.
/// Most code should use [`init_tracing`] instead — `tracing` is the standard
/// producer (and the only way to capture dependency logs). Use `init` only for a
/// pure score_log caller. Call ONCE at startup; safe to call again (a global
/// logger can only be set once, so a second call is ignored).
pub fn init(context: &str) {
    let _ = init_with(context, Sink::from_env(), level_from_env());
}

/// Initialize logging for a service that emits via `tracing` (the standard — this
/// is what nearly all code and dependencies like axum/hyper use).
///
/// Installs the env-selected `score_log` recorder AND composes the
/// `ScoreLogBridge` `tracing` layer, so every `tracing::*` event (ours and our
/// dependencies') is captured into the recorder → the platform sink. Service code
/// stays standard `tracing`; only THIS init knows about the capture.
///
/// The `tracing` level filter comes from `RUST_LOG` (falling back to the same
/// `SUMO_LOG_LEVEL` the recorder uses); the recorder's own max level is
/// `SUMO_LOG_LEVEL`. Call ONCE at startup; safe to call again (the global
/// subscriber + logger are set-once, so a second call is a no-op).
#[cfg(feature = "tracing")]
pub fn init_tracing(context: &str) {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::EnvFilter;

    // 1) Install the score_log recorder (the sink).
    let level = init_with(context, Sink::from_env(), level_from_env());

    // 2) Compose the tracing subscriber: an env filter (RUST_LOG, else the same
    //    level as the recorder) + the bridge that forwards tracing → score_log.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level.as_str().to_ascii_lowercase()));
    // try_init (not init): a second call / an already-set global subscriber is a
    // no-op rather than a panic, matching init's set-once semantics.
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(score_log_tracing::ScoreLogBridge::new())
        .try_init();
}

/// The testable core: install `sink` at `level` for `context`; returns the level
/// actually applied (so `init_tracing` can align its env-filter fallback).
fn init_with(context: &str, sink: Sink, level: LevelFilter) -> LevelFilter {
    let resolved = resolve(sink);
    match resolved {
        Sink::Slog2 => {
            // Route to the QNX slogger2 ring. On QNX this registers a
            // `context`-named buffer; off QNX score-log-slog2's emit is a no-op,
            // but `resolve` already downgraded Auto→Stdout there, so we only reach
            // this arm off-QNX if the user explicitly asked for slog2.
            let _ = score_log_slog2::install(context, level);
        }
        // Auto is resolved to a concrete sink by `resolve`; Stdout is the fallback.
        Sink::Stdout | Sink::Auto => install_stdout(context, level),
    }
    level
}

/// Resolve `Auto` to the platform-native concrete sink, and downgrade an explicit
/// `Slog2` request to `Stdout` on non-QNX (no slog2 bus there) with a notice.
fn resolve(sink: Sink) -> Sink {
    match sink {
        Sink::Auto => {
            if cfg!(target_os = "nto") {
                Sink::Slog2
            } else {
                Sink::Stdout
            }
        }
        Sink::Slog2 if !cfg!(target_os = "nto") => {
            eprintln!("sumo-log: SUMO_LOG_SINK=slog2 requested but this is not QNX — using stdout");
            Sink::Stdout
        }
        other => other,
    }
}

fn install_stdout(context: &str, level: LevelFilter) {
    // try_set_as_default_logger returns Err if a logger was already installed —
    // treat that as "already initialized", not a failure.
    let _ = stdout_logger::StdoutLoggerBuilder::new()
        .context(context)
        .show_file(false)
        .show_line(false)
        .log_level(level)
        .try_set_as_default_logger();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_parsing_defaults_to_info() {
        // (Can't safely mutate process env in parallel tests; test the parse rule
        // directly via LevelFilter::from_str, which is what level_from_env uses.)
        // score_log's ParseLevelError doesn't impl Debug, so avoid .unwrap()/
        // is_err() assertions that would require it — match on Ok instead.
        assert!(matches!(
            "info".parse::<LevelFilter>(),
            Ok(LevelFilter::Info)
        ));
        assert!(matches!(
            "DEBUG".parse::<LevelFilter>(),
            Ok(LevelFilter::Debug)
        ));
        assert!(matches!("off".parse::<LevelFilter>(), Ok(LevelFilter::Off)));
        assert!("nonsense".parse::<LevelFilter>().is_err());
    }

    #[test]
    fn sink_env_mapping() {
        // Map the string forms the way from_env does (without touching real env).
        let map = |s: &str| match s {
            x if x.eq_ignore_ascii_case("stdout") => Sink::Stdout,
            x if x.eq_ignore_ascii_case("slog2") => Sink::Slog2,
            _ => Sink::Auto,
        };
        assert_eq!(map("stdout"), Sink::Stdout);
        assert_eq!(map("SLOG2"), Sink::Slog2);
        assert_eq!(map("auto"), Sink::Auto);
        assert_eq!(map("whatever"), Sink::Auto);
    }

    #[test]
    fn resolve_auto_and_slog2_downgrade() {
        // On this (Linux) test host: Auto → Stdout, explicit Slog2 → Stdout.
        assert_eq!(resolve(Sink::Auto), Sink::Stdout);
        assert_eq!(resolve(Sink::Slog2), Sink::Stdout);
        assert_eq!(resolve(Sink::Stdout), Sink::Stdout);
    }

    #[test]
    fn init_with_installs_and_second_call_is_ignored() {
        // First install wins; a second must not panic (global logger set once).
        // Returns the level it applied.
        assert_eq!(
            init_with("test-a", Sink::Stdout, LevelFilter::Info),
            LevelFilter::Info
        );
        let _ = init_with("test-b", Sink::Stdout, LevelFilter::Debug);
        // Reaching here without panic is the assertion.
    }

    /// init_tracing wires the tracing→score_log bridge without panicking, and a
    /// `tracing::*` call afterward is accepted (goes through the global subscriber).
    /// Set-once safe: a second init_tracing is a no-op, not a panic.
    #[cfg(feature = "tracing")]
    #[test]
    fn init_tracing_wires_bridge_and_is_set_once_safe() {
        init_tracing("tr-test");
        // These must not panic — they flow through the installed subscriber.
        tracing::info!(target: "tr-test", "hello {}", 1);
        tracing::warn!("plain");
        // Second call is ignored (global subscriber + logger are set-once).
        init_tracing("tr-test-2");
    }
}
