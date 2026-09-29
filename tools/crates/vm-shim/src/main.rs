use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::{Duration, Instant};

use vm_wire::{GuestState, Heartbeat, PowerCommand, PowerCommandFrame, POWER_WIRE_SIZE};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Healthy,
    NeverReady,
    StaleHeartbeat,
    ExitImmediately,
}

fn main() {
    let mut host = "127.0.0.1:9200".to_string();
    let mut mode = Mode::Healthy;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--host" => host = args.next().expect("--host requires host:port"),
            "--mode" => {
                mode = match args.next().as_deref() {
                    Some("healthy") => Mode::Healthy,
                    Some("never-ready") => Mode::NeverReady,
                    Some("stale-heartbeat") => Mode::StaleHeartbeat,
                    Some("exit-immediately") => Mode::ExitImmediately,
                    Some(value) => panic!("unknown mode: {value}"),
                    None => panic!("--mode requires a value"),
                };
            }
            value => panic!("unknown argument: {value}"),
        }
    }

    let vm = std::env::var("SUMO_VM_NAME").expect("SUMO_VM_NAME is required");
    if mode == Mode::ExitImmediately {
        return;
    }

    let boot_id = boot_id();
    let started = Instant::now();
    let mut seq = 0u32;
    let mut last_power_seq = 0u32;
    let mut sent_stale = false;

    loop {
        if let Some(frame) = read_power(&host, &vm) {
            if frame.seq != last_power_seq {
                last_power_seq = frame.seq;
                if matches!(frame.cmd, PowerCommand::Shutdown | PowerCommand::Reboot) {
                    return;
                }
            }
        }

        let state = if mode == Mode::NeverReady {
            GuestState::Booting
        } else {
            GuestState::Running
        };
        if mode != Mode::StaleHeartbeat || !sent_stale {
            seq = seq.wrapping_add(1);
            let heartbeat = Heartbeat {
                seq,
                state,
                mono_ns: started.elapsed().as_nanos() as u64,
                flags: if state == GuestState::Running {
                    vm_wire::HB_FLAG_SERVICES_READY
                } else {
                    0
                },
                boot_id,
            };
            let _ = put_channel(&host, &vm, "heartbeat", "data", &heartbeat.to_bytes());
            sent_stale = true;
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn boot_id() -> u32 {
    let nanos = Instant::now().elapsed().as_nanos() as u64;
    (nanos as u32) ^ (std::process::id() as u32).rotate_left(13)
}

fn channel_path(host: &str, vm: &str, device: &str, channel: &str) -> String {
    format!("http://{host}/vm/{vm}/dev/{device}/ch/{channel}")
}

fn endpoint(path: &str) -> (String, String) {
    let without_scheme = path.strip_prefix("http://").expect("HTTP only");
    let (host, path) = without_scheme.split_once('/').expect("host and path");
    (host.to_string(), format!("/{path}"))
}

fn request(method: &str, path: &str, body: &[u8]) -> Option<Vec<u8>> {
    let (host, path) = endpoint(path);
    let mut stream = TcpStream::connect(host).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .ok()?;
    stream.write_all(body).ok()?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).ok()?;
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?;
    let status = std::str::from_utf8(response.get(9..12)?)
        .ok()?
        .parse::<u16>()
        .ok()?;
    if !(200..300).contains(&status) && status != 404 {
        return None;
    }
    Some(response[separator + 4..].to_vec())
}

fn put_channel(host: &str, vm: &str, device: &str, channel: &str, body: &[u8]) -> Option<Vec<u8>> {
    request("PUT", &channel_path(host, vm, device, channel), body)
}

fn read_power(host: &str, vm: &str) -> Option<PowerCommandFrame> {
    let body = request("GET", &channel_path(host, vm, "power", "cmd"), &[])?;
    if body.len() < POWER_WIRE_SIZE {
        return None;
    }
    PowerCommandFrame::from_bytes(&body)
}
