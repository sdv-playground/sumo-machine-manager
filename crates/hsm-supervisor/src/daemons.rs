//! Spawn, own, respawn and reap the two HSM daemons.
//!
//! The daemon lifecycle belongs to the node's machine manager, not to a
//! provider trait: `standup` spawns the link-B backend, connects to it (the
//! connect is what proves it bound), then spawns the vhsm-ssd proxy in
//! connect-only mode against the same socket. The returned [`HsmDaemons`] is
//! held for the process lifetime and torn down explicitly — `std::process::exit`
//! skips `Drop`, so a `Drop` impl would be a lie on the path that matters.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hsm::HsmProvider;

use crate::config::{
    resolve_backend_cmd, resolve_backend_socket, resolve_daemon_bin, HsmSupervisorConfig,
};

/// The two HSM daemons the node spawns and owns. Held for the process lifetime
/// and killed explicitly at shutdown. The vhsm-ssd child is behind a `Mutex` so
/// the post-provision reload can kill + respawn it WITHOUT disturbing the
/// backend (which keeps serving the keystore).
pub struct HsmDaemons {
    /// The link-B crypto backend. Owned for lifetime; serves the keystore.
    pub backend_child: Child,
    /// The node's own shared link-B crypto client — the SAME connection the
    /// `LinkBProvider` wraps. Hand it to in-process readers (authorizer pubkeys)
    /// as an `Arc<dyn HsmCryptoProvider>`, so PROD code holds no in-process
    /// `SimHsm` crypto.
    pub crypto_client: Arc<hsm::link_b::LinkBClient>,
    /// The vhsm-ssd A→B proxy (connect-only). Re-spawnable on provision.
    pub vhsm_child: Arc<Mutex<Child>>,
    /// Captured vhsm-ssd spawn spec, shared with the reload hook so a respawn is
    /// byte-for-byte the same argv.
    pub vhsm_spec: Arc<VhsmSpawnSpec>,
}

impl HsmDaemons {
    /// Tear both daemons down in order — proxy first, then the backend it talks
    /// to — SIGTERM with a ~2s grace each, then SIGKILL, reaping both.
    ///
    /// A method rather than two open-coded `terminate_child` calls because this
    /// sequence was duplicated at every call site, and the copies disagreed
    /// about lock poisoning: one recovered a poisoned vhsm lock, the other
    /// `unwrap`ed it. The poison-recovering version is the correct one — a panic
    /// elsewhere must not turn shutdown into a second panic that leaves both
    /// daemons orphaned with the port and socket still bound.
    pub fn shutdown(&mut self) {
        {
            let mut vhsm = self.vhsm_child.lock().unwrap_or_else(|p| p.into_inner());
            terminate_child(&mut vhsm, "vhsm-ssd");
        }
        terminate_child(&mut self.backend_child, "hsm-backend");
    }

    /// The `post_provision_reload` hook: kill + respawn the proxy so it re-reads
    /// its startup-cached `ecu_signing_pub` after a keystore provision. Captures
    /// only the two `Arc`s, so it does not borrow the daemons.
    pub fn respawn_hook(&self) -> impl Fn() + Send + Sync + 'static {
        let child = self.vhsm_child.clone();
        let spec = self.vhsm_spec.clone();
        move || respawn_vhsm(&child, &spec)
    }
}

/// A captured vhsm-ssd spawn spec so the initial standup and the post-provision
/// reload spawn it identically. Owning the argv (not just a closure) keeps the
/// respawn provably the same command.
pub struct VhsmSpawnSpec {
    pub daemon_bin: PathBuf,
    pub args: Vec<OsString>,
    /// `bind:port` listen address — probed for a stale orphan before each spawn.
    pub listen: String,
}

impl VhsmSpawnSpec {
    /// Reclaim the listen port from any stale orphan (a prior manager lifetime
    /// killed by SIGKILL reparents vhsm-ssd to init with the port still bound),
    /// then spawn vhsm-ssd.
    pub fn spawn(&self) -> std::io::Result<Child> {
        kill_stale_daemon_if_port_busy(&self.listen, &self.daemon_bin);
        Command::new(&self.daemon_bin).args(&self.args).spawn()
    }
}

/// Build the vhsm-ssd connect-only spawn spec from `cfg`: the link-A args
/// (`--keystore`, `--listen <bind:port>`, `--policy-dir`, `--bootstrap-state`,
/// one `--ip-map <ip>=<vm>` per entry, optional `--audit-log`, optional
/// `--cross-node-listen`), PLUS `--backend-connect-only --backend-socket <S>` —
/// because the node, not vhsm-ssd, owns the link-B backend.
pub fn vhsm_spawn_spec(
    cfg: &HsmSupervisorConfig,
    backend_socket: &Path,
    bootstrap_state: &Path,
) -> VhsmSpawnSpec {
    let listen = cfg.listen();
    let daemon_bin = resolve_daemon_bin(cfg);

    // Mandatory link-A args; optional flags and the connect-only backend flags
    // are pushed below.
    let mut args: Vec<OsString> = vec![
        "--keystore".into(),
        cfg.keystore.clone().into_os_string(),
        "--listen".into(),
        OsString::from(listen.clone()),
        "--policy-dir".into(),
        cfg.policy_dir.clone().into_os_string(),
        "--bootstrap-state".into(),
        bootstrap_state.as_os_str().to_os_string(),
    ];
    // One --ip-map per entry — the (ip, vm_id) pairs the daemon's ENROLL_ASSISTED
    // resolver keys guest identity on.
    for (ip, vm) in &cfg.ip_map {
        args.push("--ip-map".into());
        args.push(OsString::from(format!("{ip}={vm}")));
    }
    if let Some(ref audit) = cfg.audit_log {
        args.push("--audit-log".into());
        args.push(audit.clone().into_os_string());
    }
    if let Some(addr) = cfg.cross_node_listen {
        args.push("--cross-node-listen".into());
        args.push(OsString::from(addr.to_string()));
    }
    // Backend ownership: connect to the pre-spawned backend the node owns,
    // instead of vhsm-ssd spawning + reaping its own.
    args.push("--backend-connect-only".into());
    args.push("--backend-socket".into());
    args.push(backend_socket.as_os_str().to_os_string());

    VhsmSpawnSpec {
        daemon_bin,
        args,
        listen,
    }
}

/// Stand up the node's owned HSM daemons: spawn the link-B backend + connect a
/// `LinkBProvider` to it, ensure the bootstrap-state file exists, then spawn
/// vhsm-ssd in connect-only mode against the backend socket. Returns the
/// provider (the node's HSM handle, for factory deps and the startup checks, all
/// over link-B) and the owned daemon handles (for the reload hook + shutdown).
///
/// The single `spawn_and_connect` client is the node's HSM handle; vhsm-ssd opens
/// its OWN connection to the same backend socket (the backend accepts multiple
/// link-B connections). If vhsm-ssd can't be spawned, the just-spawned backend is
/// reaped rather than orphaned.
pub fn standup(
    cfg: &HsmSupervisorConfig,
) -> std::io::Result<(Arc<Mutex<dyn HsmProvider>>, HsmDaemons)> {
    let backend_cmd = resolve_backend_cmd(cfg);
    let backend_socket = resolve_backend_socket(cfg);

    // Reclaim the backend socket from any stale orphan first — a SIGKILL'd prior
    // lifetime leaves the backend reparented to init with its socket still bound
    // (the Unix-socket analog of the vhsm-ssd port reclaim below).
    kill_stale_backend_if_socket_live(&backend_socket, &backend_cmd);

    // 1. Spawn the link-B backend and connect (the connect proves it bound).
    let (client, backend_child) = hsm::link_b::spawn_and_connect(
        &backend_cmd,
        Some(cfg.keystore.as_path()),
        &backend_socket,
    )?;
    tracing::info!(
        backend_cmd = %backend_cmd.display(),
        socket = %backend_socket.display(),
        "link-B HSM backend spawned + connected"
    );

    // 2. Ensure the bootstrap-state file exists. vhsm-ssd tolerates a missing
    //    file, but pre-create an empty one (no ENROLL tokens yet) to match the
    //    behaviour the in-process orchestration had.
    let bootstrap_state = cfg.keystore.join("bootstrap.yaml");
    if !bootstrap_state.exists() {
        if let Err(e) = std::fs::write(&bootstrap_state, "tokens: {}\n") {
            tracing::warn!(
                path = %bootstrap_state.display(),
                error = %e,
                "failed to write empty bootstrap state"
            );
        }
    }

    // 3. Spawn the vhsm-ssd proxy in connect-only mode against the backend socket.
    let spec = Arc::new(vhsm_spawn_spec(cfg, &backend_socket, &bootstrap_state));
    let vhsm = match spec.spawn() {
        Ok(c) => c,
        Err(e) => {
            // Don't orphan the backend we just brought up.
            let mut bc = backend_child;
            let _ = bc.kill();
            let _ = bc.wait();
            return Err(std::io::Error::new(
                e.kind(),
                format!("spawn vhsm-ssd ({}): {e}", spec.daemon_bin.display()),
            ));
        }
    };
    tracing::info!(pid = vhsm.id(), listen = %spec.listen, "vhsm-ssd proxy spawned (connect-only)");

    // 4. The LinkBProvider IS the node's HsmProvider now; its lifecycle methods
    //    are no-ops (the daemon lifecycle is owned here, not over the wire). The
    //    single link-B client is shared: the provider wraps a clone, and a clone
    //    rides in HsmDaemons so in-process readers reach the SAME connection.
    let client = Arc::new(client);
    let provider: Arc<Mutex<dyn HsmProvider>> =
        Arc::new(Mutex::new(hsm::LinkBProvider::new(client.clone())));

    Ok((
        provider,
        HsmDaemons {
            backend_child,
            crypto_client: client,
            vhsm_child: Arc::new(Mutex::new(vhsm)),
            vhsm_spec: spec,
        },
    ))
}

/// Probe-bind `listen`; if busy, assume a stale vhsm-ssd orphan from a prior
/// manager lifetime (a SIGKILL reparents children to init, port still bound) and
/// pkill/slay it by basename, polling for the port to free.
pub fn kill_stale_daemon_if_port_busy(listen: &str, daemon_bin: &Path) {
    match std::net::TcpListener::bind(listen) {
        Ok(l) => {
            drop(l);
            return;
        }
        Err(e) => tracing::warn!(
            addr = listen, error = %e,
            "vhsm-ssd listen port busy — assuming stale orphan"
        ),
    }

    let bin_name = basename_or(daemon_bin, "vhsm-ssd");
    reclaim_by_name(bin_name, "stale vhsm-ssd killed; port free", || {
        std::net::TcpListener::bind(listen).is_ok()
    });

    if std::net::TcpListener::bind(listen).is_err() {
        tracing::warn!(
            addr = listen,
            "could not reclaim vhsm-ssd listen port — spawn will likely fail"
        );
    }
}

/// The Unix-socket analog of [`kill_stale_daemon_if_port_busy`] for the link-B
/// backend: if something still accepts on `socket`, assume a stale orphan from a
/// SIGKILL'd prior lifetime and pkill/slay it by basename, polling for the
/// socket to go dead. `spawn_and_connect` then removes the now-dead socket file
/// and binds a fresh one.
pub fn kill_stale_backend_if_socket_live(socket: &Path, backend_cmd: &Path) {
    use std::os::unix::net::UnixStream;

    // Nothing accepting (no socket file, or a dead leftover file) → no orphan.
    if UnixStream::connect(socket).is_err() {
        return;
    }
    tracing::warn!(
        socket = %socket.display(),
        "link-B backend socket still live — assuming stale orphan"
    );

    let bin_name = basename_or(backend_cmd, "hsm-sim-service");
    reclaim_by_name(
        bin_name,
        "stale hsm-sim-service killed; socket free",
        || UnixStream::connect(socket).is_err(),
    );

    if UnixStream::connect(socket).is_ok() {
        tracing::warn!(
            socket = %socket.display(),
            "could not reclaim link-B backend socket — spawn will likely fail"
        );
    }
}

/// `path`'s file name as a `&str`, or `fallback` when it has none or isn't UTF-8.
fn basename_or<'a>(path: &'a Path, fallback: &'a str) -> &'a str {
    path.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(fallback)
}

/// Escalate SIGTERM → SIGKILL against every process named `bin_name`, via
/// whichever of `pkill` / `slay` the host has (QNX ships `slay`, Linux `pkill`),
/// polling `freed` for up to ~500ms after each attempt.
///
/// Shared by the two reclaim paths above, which differ only in what "freed"
/// means — a bindable TCP port vs. a dead Unix socket. Both escalate through the
/// same four attempts, and both previously open-coded this loop.
fn reclaim_by_name(bin_name: &str, success_msg: &str, mut freed: impl FnMut() -> bool) {
    use std::process::Stdio;

    let attempts: &[(&str, &[&str])] = &[
        ("pkill", &["-TERM", "-x", bin_name]),
        ("slay", &["-T1", bin_name]),
        // Final fallback if the running process ignored SIGTERM.
        ("pkill", &["-KILL", "-x", bin_name]),
        ("slay", &["-9", bin_name]),
    ];
    for (cmd, args) in attempts {
        let _ = Command::new(cmd)
            .args(*args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        for _ in 0..5 {
            std::thread::sleep(Duration::from_millis(100));
            if freed() {
                tracing::info!(via = %cmd, "{}", success_msg);
                return;
            }
        }
    }
}

/// SIGTERM a manager-owned daemon child, wait up to ~2s, then SIGKILL. Used for
/// both HSM daemons at shutdown and for the vhsm-ssd respawn. SIGTERM lets the
/// vhsm-ssd connect-only signal path exit cleanly (and the backend terminate on
/// its default disposition); `Child::wait` reaps the process so it never orphans.
pub fn terminate_child(child: &mut Child, name: &str) {
    let pid = child.id();
    #[cfg(unix)]
    // SAFETY: `pid` is this process's direct child; SIGTERM is a valid signal.
    // A failed kill (already-exited) is harmless — we wait() next regardless.
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                tracing::info!(pid, name, "HSM daemon stopped");
                return;
            }
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
            }
            _ => break,
        }
    }

    tracing::warn!(
        pid,
        name,
        "HSM daemon did not exit on SIGTERM, sending SIGKILL"
    );
    let _ = child.kill();
    let _ = child.wait();
}

/// Kill + respawn the vhsm-ssd proxy so it re-reads its startup-cached
/// `ecu_signing_pub` (the iam-signing pubkey) after a keystore provision. The
/// link-B backend keeps running — it serves the freshly-written keystore from
/// disk — so ONLY the proxy's cache is stale. Wired as
/// `FactoryDeps.post_provision_reload`: component-mgr calls it INSTEAD of the
/// provider's (no-op) stop/start after an HSM keystore install.
pub fn respawn_vhsm(child: &Arc<Mutex<Child>>, spec: &VhsmSpawnSpec) {
    // Recover a poisoned lock — we overwrite the child below regardless.
    let mut guard = child.lock().unwrap_or_else(|p| p.into_inner());
    terminate_child(&mut guard, "vhsm-ssd");
    match spec.spawn() {
        Ok(c) => {
            tracing::info!(
                pid = c.id(),
                "vhsm-ssd respawned post-provision (re-reading iam-signing pubkey)"
            );
            *guard = c;
        }
        Err(e) => tracing::error!(
            error = %e,
            "failed to respawn vhsm-ssd post-provision — guest AUTH may reject until restart"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    /// A fully-specified config for arg-construction tests (no defaults leaking
    /// in), with the knobs the spec maps from.
    fn cfg_with(
        keystore: &str,
        bind: &str,
        port: u16,
        policy_dir: &str,
        ip_map: Vec<(&str, &str)>,
        audit_log: Option<&str>,
        cross_node_listen: Option<&str>,
    ) -> HsmSupervisorConfig {
        HsmSupervisorConfig {
            keystore: PathBuf::from(keystore),
            bind: bind.parse().unwrap(),
            port,
            policy_dir: PathBuf::from(policy_dir),
            ip_map: ip_map
                .into_iter()
                .map(|(ip, vm)| (ip.parse::<IpAddr>().unwrap(), vm.to_string()))
                .collect(),
            audit_log: audit_log.map(PathBuf::from),
            cross_node_listen: cross_node_listen.map(|a| a.parse().unwrap()),
            ..HsmSupervisorConfig::default()
        }
    }

    fn args_of(spec: &VhsmSpawnSpec) -> Vec<String> {
        spec.args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    /// The vhsm-ssd argv maps every configured field
    /// (keystore/listen/policy-dir/bootstrap-state, one --ip-map per entry,
    /// optional --audit-log + --cross-node-listen), PLUS the connect-only backend
    /// flags appended.
    #[test]
    fn vhsm_spawn_spec_maps_every_field_plus_connect_only() {
        let cfg = cfg_with(
            "/ks",
            "0.0.0.0",
            6000,
            "/pol",
            vec![("10.0.0.2", "vm1"), ("10.0.0.3", "vm2")],
            Some("/var/audit.log"),
            Some("0.0.0.0:7000"),
        );
        let spec = vhsm_spawn_spec(
            &cfg,
            Path::new("/run/hsm.sock"),
            Path::new("/ks/bootstrap.yaml"),
        );

        assert_eq!(spec.listen, "0.0.0.0:6000");
        assert_eq!(spec.daemon_bin, PathBuf::from("vhsm-ssd")); // cfg.daemon == None
        assert_eq!(
            args_of(&spec),
            vec![
                "--keystore",
                "/ks",
                "--listen",
                "0.0.0.0:6000",
                "--policy-dir",
                "/pol",
                "--bootstrap-state",
                "/ks/bootstrap.yaml",
                "--ip-map",
                "10.0.0.2=vm1",
                "--ip-map",
                "10.0.0.3=vm2",
                "--audit-log",
                "/var/audit.log",
                "--cross-node-listen",
                "0.0.0.0:7000",
                "--backend-connect-only",
                "--backend-socket",
                "/run/hsm.sock",
            ],
        );
    }

    /// Minimal config: no ip-map, no audit, no cross-node — only the required
    /// link-A args + the connect-only backend flags.
    #[test]
    fn vhsm_spawn_spec_minimal_has_no_optional_flags() {
        let cfg = cfg_with("/k", "127.0.0.1", 5100, "/p", Vec::new(), None, None);
        let spec = vhsm_spawn_spec(&cfg, Path::new("/s"), Path::new("/b"));
        let args = args_of(&spec);
        assert_eq!(
            args,
            vec![
                "--keystore",
                "/k",
                "--listen",
                "127.0.0.1:5100",
                "--policy-dir",
                "/p",
                "--bootstrap-state",
                "/b",
                "--backend-connect-only",
                "--backend-socket",
                "/s",
            ],
        );
        assert!(!args
            .iter()
            .any(|a| a == "--ip-map" || a == "--audit-log" || a == "--cross-node-listen"));
    }

    /// `basename_or` backs both reclaim paths' pkill/slay target. A configured
    /// absolute path must reduce to the bare process name — `pkill -x` matches on
    /// the name, so passing a path would silently match nothing and the reclaim
    /// would appear to run while killing no orphan.
    #[test]
    fn basename_or_reduces_a_path_to_the_process_name() {
        assert_eq!(
            basename_or(Path::new("/opt/bin/vhsm-ssd"), "fb"),
            "vhsm-ssd"
        );
        assert_eq!(basename_or(Path::new("vhsm-ssd"), "fb"), "vhsm-ssd");
        // No file name at all → the caller's fallback.
        assert_eq!(basename_or(Path::new("/"), "vhsm-ssd"), "vhsm-ssd");
    }
}
