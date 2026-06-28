//! Drive the hand-rolled pure-Rust DNS-SD responder so an external browser
//! (`avahi-browse`, `dns-sd`) can discover the SOVD service. This deliberately
//! exercises the `responder` backend (the one used on QNX) on the host.
//!
//! ```text
//! cargo run -p sovd-mdns --example advertise -- [instance] [port] [seconds]
//! # then, from another shell:
//! avahi-browse -rpt _sovd._tcp
//! ```

fn main() {
    let mut args = std::env::args().skip(1);
    let instance = args
        .next()
        .unwrap_or_else(|| "cvc-host-deadbeef".to_string());
    let port: u16 = args.next().and_then(|s| s.parse().ok()).unwrap_or(4000);
    let secs: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(30);

    let host = format!("{instance}.local");
    let adv = sovd_mdns::SovdAdvertiser {
        identification: instance.clone(),
        accessurl: format!("https://{host}:{port}/vehicle"),
        instance: instance.clone(),
        port,
    };

    let _guard = sovd_mdns::responder::start(adv).expect("start mDNS responder");
    eprintln!(
        "advertising {instance}._sovd._tcp.local (host {host}, port {port}) for {secs}s; \
         drops a goodbye on exit"
    );
    std::thread::sleep(std::time::Duration::from_secs(secs));
}
