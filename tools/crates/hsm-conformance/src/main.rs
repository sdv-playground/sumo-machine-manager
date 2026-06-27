//! `hsm-conformance` — run the link-B conformance battery against a running backend.
//!
//! Point it at a backend already listening on a link-B Unix socket:
//!
//!     hsm-conformance <socket-path>
//!
//! It prints the [`ConformanceReport`](hsm_conformance::ConformanceReport) table
//! and exits `0` iff the backend conforms (every non-informational check passed),
//! else `1`. A connect failure exits `2`.
//!
//! How the backend got started — a vendor HSE bridge, a hardware service, a
//! locally-launched `hsm-sim-service` — is the operator's concern, NOT this
//! tool's. Every backend has its own launch story (args, env, privileges,
//! silicon), so the harness tests the CONTRACT over the socket and nothing else.
//! (The conformance *tests* spawn the reference sim / C skeleton themselves via
//! `hsm_conformance::spawn_and_connect`; that helper exists to bring up a local
//! test double, not as a CLI mode for launching arbitrary vendor backends.)

use std::io::Write;
use std::path::Path;

use hsm::link_b::LinkBClient;
use hsm_conformance::run_conformance;

const USAGE: &str = "\
usage: hsm-conformance <socket-path>

  <socket-path>   a link-B backend already listening on this Unix socket
                  (equivalently: --backend-socket <socket-path>)

Exit: 0 = conforms, 1 = does not conform, 2 = bad usage / connect failure.";

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let socket = match &args[1..] {
        [a] if a == "-h" || a == "--help" => {
            let _ = writeln!(std::io::stdout(), "{USAGE}");
            std::process::exit(0);
        }
        // The backend socket as a positional path …
        [sock] if !sock.starts_with('-') => sock.clone(),
        // … or via the explicit flag form.
        [flag, sock] if flag == "--backend-socket" => sock.clone(),
        _ => {
            let _ = writeln!(std::io::stderr(), "{USAGE}");
            std::process::exit(2);
        }
    };

    let client = LinkBClient::connect(Path::new(&socket)).unwrap_or_else(|e| {
        let _ = writeln!(
            std::io::stderr(),
            "error: could not connect to link-B backend at {socket}: {e}"
        );
        std::process::exit(2);
    });

    let report = run_conformance(&client);

    // Write the report, then exit with the verdict. Through a locked handle with
    // I/O errors ignored, so a broken stdout pipe (e.g. `hsm-conformance … | head`)
    // can't turn this tool's machine-readable verdict exit code into a panic (101).
    let mut out = std::io::stdout().lock();
    let _ = write!(out, "{report}");
    let _ = out.flush();

    std::process::exit(if report.all_passed() { 0 } else { 1 });
}
