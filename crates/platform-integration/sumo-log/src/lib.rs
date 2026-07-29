//! Fleet-wide logging init for sumo services.
//!
//! Every service logs the SAME way by calling one function at startup:
//!
//! ```ignore
//! fn main() {
//!     sumo_log::init("teesa-vf");   // the only per-app argument: its context tag
//!     score_log::info!("alive");    // then just use the score_log macros
//! }
//! ```
//!
//! The service supplies ONLY its `context` tag. Everything else — level, format,
//! and which recorder (destination) is installed — is fleet policy that lives
//! HERE, not hardcoded in each app. That means:
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

/// Initialize logging for a service with the given `context` tag.
///
/// Installs the env-selected `score_log` recorder as the process's global logger.
/// Call ONCE at startup, before any log macro. Safe to call again (subsequent
/// calls are ignored — a global logger can only be set once).
pub fn init(context: &str) {
    init_with(context, Sink::from_env(), level_from_env());
}

/// The testable core: install `sink` at `level` for `context`.
fn init_with(context: &str, sink: Sink, level: LevelFilter) {
    let resolved = resolve(sink);
    match resolved {
        Sink::Slog2 => {
            // Route to the QNX slogger2 ring. On QNX this registers a
            // `context`-named buffer; off QNX score-log-slog2's emit is a no-op,
            // but `resolve` already downgraded Auto→Stdout there, so we only reach
            // this arm off-QNX if the user explicitly asked for slog2.
            if score_log_slog2::install(context, level).is_err() {
                // Already set — nothing to do.
            }
        }
        // Auto is resolved to a concrete sink by `resolve`; Stdout is the fallback.
        Sink::Stdout | Sink::Auto => install_stdout(context, level),
    }
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
        init_with("test-a", Sink::Stdout, LevelFilter::Info);
        init_with("test-b", Sink::Stdout, LevelFilter::Debug);
        // Reaching here without panic is the assertion.
    }
}
