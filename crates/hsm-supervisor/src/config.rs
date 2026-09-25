//! What this crate needs to know to stand the daemons up, and the path
//! resolution rules that fill in what a node leaves unset.
//!
//! [`HsmSupervisorConfig`] is deliberately **not** a serde type. The node's
//! deployment config (supernova's `HsmConfig`, and whatever the CM5 and DDU
//! managers grow) owns the YAML surface and the defaults, because the useful
//! defaults are board-specific: supernova's `bind` defaults to the vp2
//! vdevpeer address and its `policy_dir` to a bank-relative path under
//! `/mnt/common-rw`. Neither is a fact about HSM supervision. So the node maps
//! its own config into this struct, and this crate holds only the rules that
//! genuinely generalise — which is all three `resolve_*` functions below.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

/// The daemon-facing half of a node's HSM configuration: everything the two
/// spawns need, and nothing about how the node stores or defaults it.
///
/// Every `Option` here means "not configured — resolve it", not "disabled",
/// except `audit_log` and `cross_node_listen`, which are genuinely optional
/// daemon features.
#[derive(Debug, Clone)]
pub struct HsmSupervisorConfig {
    /// Keystore directory. Also the parent of the default backend socket and of
    /// the `bootstrap.yaml` the standup pre-creates.
    pub keystore: PathBuf,

    /// Address the vhsm-ssd proxy listens on for guests. Formatted with
    /// [`Self::port`] into the daemon's `--listen bind:port`.
    pub bind: IpAddr,

    /// Port half of the proxy's listen address.
    pub port: u16,

    /// The vhsm-ssd executable. `None` → the bare name `vhsm-ssd`, PATH-resolved.
    pub daemon: Option<PathBuf>,

    /// The link-B backend executable the node spawns and OWNS. `None` → a
    /// sibling `hsm-sim-service` beside [`Self::daemon`] (the dev software
    /// backend); point it at a vendor bridge to select hardware. The wire is
    /// backend-agnostic — neither vhsm-ssd nor the node can tell them apart.
    pub backend_cmd: Option<PathBuf>,

    /// The link-B Unix socket the backend serves and the proxy connects to.
    /// `None` → `<keystore>/hsm-backend.sock`.
    pub backend_socket: Option<PathBuf>,

    /// Per-guest identity map, one `--ip-map <ip>=<vm>` per entry. Empty leaves
    /// the daemon on its own single-VM heuristic.
    pub ip_map: Vec<(IpAddr, String)>,

    /// When set, the daemon is spawned with `--audit-log <path>` and emits one
    /// fsync'd JSON line per dispatched op.
    pub audit_log: Option<PathBuf>,

    /// IAM policy directory, passed as `--policy-dir`. Must contain
    /// `policy.yaml`. This is the HOST-side policy — what each guest principal
    /// may ask the daemon for — not the guest-side policy mount that services
    /// inside a VM read.
    pub policy_dir: PathBuf,

    /// Optional second bind for node-to-node mTLS, passed as
    /// `--cross-node-listen <ip:port>`. mTLS-gated, so a `0.0.0.0` address here
    /// is intentional rather than an open hole.
    pub cross_node_listen: Option<SocketAddr>,
}

impl Default for HsmSupervisorConfig {
    /// Inert placeholders, **not** policy. `bind` is loopback and the two
    /// directories are empty on purpose: a node that forgets to fill a field
    /// should fail on a dev loopback or an obviously-wrong path, never silently
    /// bind a real vehicle interface or read a real policy directory. Every
    /// deployment overwrites all of these from its own config.
    fn default() -> Self {
        Self {
            keystore: PathBuf::new(),
            bind: IpAddr::from([127, 0, 0, 1]),
            port: 5100,
            daemon: None,
            backend_cmd: None,
            backend_socket: None,
            ip_map: Vec::new(),
            audit_log: None,
            policy_dir: PathBuf::new(),
            cross_node_listen: None,
        }
    }
}

impl HsmSupervisorConfig {
    /// The proxy's `bind:port` listen string — the same value that goes into
    /// `--listen` and that the stale-orphan probe binds against.
    pub fn listen(&self) -> String {
        format!("{}:{}", self.bind, self.port)
    }
}

/// The vhsm-ssd executable: `cfg.daemon` when set, else the bare name
/// (PATH-resolved).
pub fn resolve_daemon_bin(cfg: &HsmSupervisorConfig) -> PathBuf {
    cfg.daemon
        .clone()
        .unwrap_or_else(|| PathBuf::from("vhsm-ssd"))
}

/// The link-B backend executable: `cfg.backend_cmd` when set, else a sibling
/// `hsm-sim-service` next to the configured vhsm-ssd `daemon`.
pub fn resolve_backend_cmd(cfg: &HsmSupervisorConfig) -> PathBuf {
    cfg.backend_cmd
        .clone()
        .unwrap_or_else(|| sibling_bin(cfg.daemon.as_deref(), "hsm-sim-service"))
}

/// The link-B Unix socket: `cfg.backend_socket` when set, else
/// `<keystore>/hsm-backend.sock` (the same default vhsm-ssd uses in its own
/// spawn mode).
pub fn resolve_backend_socket(cfg: &HsmSupervisorConfig) -> PathBuf {
    cfg.backend_socket
        .clone()
        .unwrap_or_else(|| cfg.keystore.join("hsm-backend.sock"))
}

/// `name` resolved beside `base` (same directory). When `base` is `None` or is a
/// bare PATH-resolved name (no parent directory), returns a bare `name` (also
/// PATH-resolved). Keeps the backend + proxy co-located by default — they ship
/// in the same directory.
///
/// ```
/// use hsm_supervisor::sibling_bin;
/// use std::path::{Path, PathBuf};
///
/// // Beside an absolute base.
/// assert_eq!(
///     sibling_bin(Some(Path::new("/opt/bin/vhsm-ssd")), "hsm-sim-service"),
///     PathBuf::from("/opt/bin/hsm-sim-service"),
/// );
/// // A bare PATH-resolved base yields a bare PATH-resolved name, NOT "./name".
/// assert_eq!(
///     sibling_bin(Some(Path::new("vhsm-ssd")), "hsm-sim-service"),
///     PathBuf::from("hsm-sim-service"),
/// );
/// assert_eq!(sibling_bin(None, "hsm-sim-service"), PathBuf::from("hsm-sim-service"));
/// ```
pub fn sibling_bin(base: Option<&Path>, name: &str) -> PathBuf {
    match base.and_then(|b| b.parent()) {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(name),
        _ => PathBuf::from(name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sibling_bin_resolves_beside_base_or_falls_back_to_bare() {
        assert_eq!(
            sibling_bin(Some(Path::new("/opt/bin/vhsm-ssd")), "hsm-sim-service"),
            PathBuf::from("/opt/bin/hsm-sim-service"),
        );
        // Bare PATH-resolved daemon name → bare backend name (parent is "").
        assert_eq!(
            sibling_bin(Some(Path::new("vhsm-ssd")), "hsm-sim-service"),
            PathBuf::from("hsm-sim-service"),
        );
        assert_eq!(
            sibling_bin(None, "hsm-sim-service"),
            PathBuf::from("hsm-sim-service"),
        );
    }

    #[test]
    fn resolve_backend_cmd_defaults_to_sibling_else_override() {
        // Default: sibling hsm-sim-service next to the configured daemon.
        let cfg = HsmSupervisorConfig {
            daemon: Some(PathBuf::from("/d/vhsm-ssd")),
            backend_cmd: None,
            ..HsmSupervisorConfig::default()
        };
        assert_eq!(
            resolve_backend_cmd(&cfg),
            PathBuf::from("/d/hsm-sim-service")
        );

        // Explicit override (e.g. a vendor HSE bridge) wins.
        let cfg = HsmSupervisorConfig {
            daemon: Some(PathBuf::from("/d/vhsm-ssd")),
            backend_cmd: Some(PathBuf::from("/vendor/hse-bridge")),
            ..HsmSupervisorConfig::default()
        };
        assert_eq!(
            resolve_backend_cmd(&cfg),
            PathBuf::from("/vendor/hse-bridge")
        );

        // No daemon configured → bare hsm-sim-service (PATH-resolved).
        let cfg = HsmSupervisorConfig {
            daemon: None,
            backend_cmd: None,
            ..HsmSupervisorConfig::default()
        };
        assert_eq!(resolve_backend_cmd(&cfg), PathBuf::from("hsm-sim-service"));
    }

    #[test]
    fn resolve_backend_socket_defaults_under_keystore_else_override() {
        let cfg = HsmSupervisorConfig {
            keystore: PathBuf::from("/ks"),
            backend_socket: None,
            ..HsmSupervisorConfig::default()
        };
        assert_eq!(
            resolve_backend_socket(&cfg),
            PathBuf::from("/ks/hsm-backend.sock")
        );

        let cfg = HsmSupervisorConfig {
            keystore: PathBuf::from("/ks"),
            backend_socket: Some(PathBuf::from("/run/hsm.sock")),
            ..HsmSupervisorConfig::default()
        };
        assert_eq!(resolve_backend_socket(&cfg), PathBuf::from("/run/hsm.sock"));
    }

    /// `resolve_daemon_bin` was untested in supernova — the arg-mapping tests
    /// covered it only incidentally, through `vhsm_spawn_spec`'s `daemon_bin`
    /// assertion on the `None` case.
    #[test]
    fn resolve_daemon_bin_defaults_to_bare_name_else_override() {
        assert_eq!(
            resolve_daemon_bin(&HsmSupervisorConfig::default()),
            PathBuf::from("vhsm-ssd")
        );
        let cfg = HsmSupervisorConfig {
            daemon: Some(PathBuf::from("/opt/bin/vhsm-ssd")),
            ..HsmSupervisorConfig::default()
        };
        assert_eq!(resolve_daemon_bin(&cfg), PathBuf::from("/opt/bin/vhsm-ssd"));
    }

    /// The `Default` is placeholders, not policy: loopback and empty paths, so a
    /// node that forgets a field fails visibly instead of binding a real
    /// interface. Pinned because the whole argument for keeping the serde
    /// defaults up in the node rests on it.
    #[test]
    fn default_is_inert_not_a_deployment() {
        let d = HsmSupervisorConfig::default();
        assert_eq!(d.listen(), "127.0.0.1:5100");
        assert_eq!(d.keystore, PathBuf::new());
        assert_eq!(d.policy_dir, PathBuf::new());
        assert!(d.ip_map.is_empty());
        assert!(d.audit_log.is_none());
        assert!(d.cross_node_listen.is_none());
    }
}
