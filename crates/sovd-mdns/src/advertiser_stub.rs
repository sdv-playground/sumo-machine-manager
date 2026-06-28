//! Inert advertiser for QNX (`target_os = "nto"`).
//!
//! `mdns-sd`'s event loop (`mio`) + interface enumeration (`if-addrs`) +
//! `socket-pktinfo` have no `nto` support, and the supernova QNX cross-build
//! only patches `libc`/`socket2`/`tokio`/`ring`. Rather than break that build,
//! this stub provides the identical API to `advertiser_real.rs`: registration
//! logs a warning and is a no-op, and the guard does nothing on drop.
//!
//! Real QNX advertising is a follow-up — either upstream `nto` support in the
//! `mdns-sd` dep tree, or a hand-rolled UDP-multicast advertiser built directly
//! on the patched `socket2`/`libc`. The cert parse in `lib.rs` already works on
//! this target, so only the wire backend is missing.

use crate::{AdvertiseError, SovdAdvertiser};

/// No-op guard mirroring the real backend's
/// [`AdvertiserGuard`](crate::AdvertiserGuard).
pub struct AdvertiserGuard;

pub(crate) fn start(adv: SovdAdvertiser) -> Result<AdvertiserGuard, AdvertiseError> {
    tracing::warn!(
        instance = %adv.instance,
        port = adv.port,
        accessurl = %adv.accessurl,
        "SOVD mDNS advertising is not available on this target (QNX/nto); the \
         SOVD endpoint will not be discoverable via DNS-SD"
    );
    Ok(AdvertiserGuard)
}
