//! Real mDNS / DNS-SD advertiser, backed by the pure-Rust `mdns-sd` crate.
//!
//! Compiled and selected on every target except QNX (`target_os = "nto"`),
//! where the hand-rolled [`responder`](crate::responder) takes over (`mdns-sd`'s
//! deps have no `nto` support). See the crate-level docs for the rationale.

use crate::{AdvertiseError, SovdAdvertiser, SERVICE_TYPE};
use mdns_sd::{ServiceDaemon, ServiceInfo};

/// Guard returned by [`SovdAdvertiser::start`](crate::SovdAdvertiser::start).
///
/// On drop it unregisters the service (DNS-SD goodbye / TTL-0 records) and
/// stops the background daemon thread. Hold it for the SOVD server's lifetime.
pub struct AdvertiserGuard {
    daemon: ServiceDaemon,
    fullname: String,
}

impl Drop for AdvertiserGuard {
    fn drop(&mut self) {
        // Best-effort graceful teardown: `unregister` queues the goodbye
        // (TTL-0) announcements, then `shutdown` stops the daemon thread. The
        // daemon drains its command queue in order, so the goodbye is emitted
        // before the thread exits.
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}

pub(crate) fn start(adv: SovdAdvertiser) -> Result<AdvertiserGuard, AdvertiseError> {
    let daemon = ServiceDaemon::new().map_err(|e| AdvertiseError(e.to_string()))?;

    // mdns-sd requires the hostname to end with `.local.` (trailing dot).
    let hostname = format!("{}.local.", adv.instance);
    let txt = [
        ("identification", adv.identification.as_str()),
        ("accessurl", adv.accessurl.as_str()),
    ];

    let info = ServiceInfo::new(
        SERVICE_TYPE,
        &adv.instance, // instance name -> fullname `<instance>._sovd._tcp.local.`
        &hostname,
        (),       // no explicit addresses; auto-detected below
        adv.port, // SRV port = the SOVD server's actual bind port
        &txt[..],
    )
    .map_err(|e| AdvertiseError(e.to_string()))?
    // Let the daemon fill in (and keep tracking) this host's addresses on all
    // interfaces, so the A/AAAA records follow the live network config.
    .enable_addr_auto();

    let fullname = info.get_fullname().to_string();
    daemon
        .register(info)
        .map_err(|e| AdvertiseError(e.to_string()))?;

    tracing::info!(
        service = %fullname,
        hostname = %hostname,
        port = adv.port,
        accessurl = %adv.accessurl,
        "SOVD mDNS/DNS-SD advertiser registered"
    );

    Ok(AdvertiserGuard { daemon, fullname })
}
