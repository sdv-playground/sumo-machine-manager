use nv_store::block::FileBlockDevice;
use nv_store::store::{NvStore, MIN_NV_DEVICE_SIZE};
use nv_store::types::*;

use component_mgr::did;
use component_mgr::manifest::{FactoryManifest, FirmwareManifest};
use component_mgr::ota;

use std::path::PathBuf;

fn usage() -> ! {
    eprintln!("Usage: vm-diagserver <nv-store-path> <command> [args...]");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  status <set>                     Show bank status (hypervisor|vm1|vm2|hsm)");
    eprintln!("  install <set> <image-path> <ver> <secver>  Install OTA image");
    eprintln!("  commit <set>                     Commit trial bank");
    eprintln!("  rollback <set>                   Rollback to previous bank");
    eprintln!("  read-did <set> <did-hex>         Read a DID (e.g. F189)");
    eprintln!("  write-did <set> <did-hex> <val>  Write a runtime DID");
    eprintln!("  provision <serial> <vin>         Write factory data (once)");
    eprintln!("  factory-init <dir> [--runner-path <path>]  Initialize from manifests");
    std::process::exit(1);
}

fn parse_set(s: &str) -> BankSet {
    BankSet::from_str(s).unwrap_or_else(|| {
        eprintln!("Invalid bank set '{s}'. Use: hypervisor, vm1, vm2, hsm");
        std::process::exit(1);
    })
}

fn parse_did(s: &str) -> u16 {
    u16::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap_or_else(
        |_| {
            eprintln!("Invalid DID '{s}'. Use hex, e.g. F189 or 0xFD10");
            std::process::exit(1);
        },
    )
}

fn bank_letter(b: Bank) -> &'static str {
    match b {
        Bank::A => "A",
        Bank::B => "B",
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        usage();
    }

    let nv_path = PathBuf::from(&args[1]);
    let cmd = &args[2];

    let dev = if nv_path.exists() {
        FileBlockDevice::open(&nv_path)
    } else {
        eprintln!("[diag] creating NV store: {}", nv_path.display());
        FileBlockDevice::create(&nv_path, MIN_NV_DEVICE_SIZE)
    };

    let dev = match dev {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[diag] failed to open NV store: {e}");
            std::process::exit(1);
        }
    };

    let mut nv = NvStore::new(dev);

    // Ensure boot state exists
    if nv.read_boot_state().is_none() {
        let mut state = NvBootState::default();
        nv.write_boot_state(&mut state).unwrap();
    }

    match cmd.as_str() {
        "status" => {
            let set = parse_set(args.get(3).map(|s| s.as_str()).unwrap_or_else(|| usage()));
            match ota::status(&nv, set) {
                Some(s) => {
                    println!("Bank set: {:?}", set);
                    println!("Active bank: {}", bank_letter(s.active_bank));
                    println!("Committed: {}", s.committed);
                    println!("Boot count: {}", s.boot_count);
                    // FW version string lives in the bank's signed IVD
                    // manifest now, not NvFwMeta — not shown by this
                    // NV-only status command.
                    if let Some(v) = s.fw_secver {
                        println!("Security version: {v}");
                    }
                    if let Some(v) = s.min_security_ver {
                        println!("Min security version: {v}");
                    }
                }
                None => eprintln!("[diag] no boot state"),
            }
        }

        "install" => {
            if args.len() < 7 {
                eprintln!("Usage: install <set> <image-path> <version> <secver>");
                std::process::exit(1);
            }
            let set = parse_set(&args[3]);
            let image_path = PathBuf::from(&args[4]);
            let version = &args[5];
            let secver: u32 = args[6].parse().unwrap_or_else(|_| {
                eprintln!("Invalid security version");
                std::process::exit(1);
            });

            let image_data = std::fs::read(&image_path).unwrap_or_else(|e| {
                eprintln!("[diag] failed to read image: {e}");
                std::process::exit(1);
            });

            let mut meta = ota::ImageMeta::default();
            let vlen = version.len().min(32);
            meta.fw_version[..vlen].copy_from_slice(&version.as_bytes()[..vlen]);
            meta.fw_secver = secver;
            meta.fw_seq = secver;

            match ota::install(&mut nv, set, &image_data, &meta, false) {
                Ok(result) => {
                    println!(
                        "[diag] installed to bank {}",
                        bank_letter(result.target_bank)
                    );
                    println!("[diag] SHA-256: {}", hex(&result.image_sha256));
                    println!("[diag] reboot to activate (trial mode)");
                }
                Err(e) => {
                    eprintln!("[diag] install failed: {e}");
                    std::process::exit(1);
                }
            }
        }

        "commit" => {
            let set = parse_set(args.get(3).map(|s| s.as_str()).unwrap_or_else(|| usage()));
            match ota::commit(&mut nv, set) {
                Ok(()) => println!("[diag] committed {:?}", set),
                Err(e) => {
                    eprintln!("[diag] commit failed: {e}");
                    std::process::exit(1);
                }
            }
        }

        "rollback" => {
            let set = parse_set(args.get(3).map(|s| s.as_str()).unwrap_or_else(|| usage()));
            match ota::rollback(&mut nv, set) {
                Ok(bank) => println!("[diag] rolled back to bank {}", bank_letter(bank)),
                Err(e) => {
                    eprintln!("[diag] rollback failed: {e}");
                    std::process::exit(1);
                }
            }
        }

        "read-did" => {
            if args.len() < 5 {
                eprintln!("Usage: read-did <set> <did-hex>");
                std::process::exit(1);
            }
            let set = parse_set(&args[3]);
            let did_num = parse_did(&args[4]);
            let val = did::read_did(&nv, set, did_num, None);
            match val {
                did::DidValue::Bytes(b) => {
                    // Try as string first
                    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
                    if let Ok(s) = std::str::from_utf8(&b[..end]) {
                        if s.chars().all(|c| c.is_ascii_graphic() || c == ' ') && !s.is_empty() {
                            println!("{s}");
                        } else {
                            println!("{}", hex(&b));
                        }
                    } else {
                        println!("{}", hex(&b));
                    }
                }
                did::DidValue::NotFound => {
                    eprintln!("DID 0x{did_num:04X} not found");
                    std::process::exit(1);
                }
            }
        }

        "write-did" => {
            if args.len() < 6 {
                eprintln!("Usage: write-did <set> <did-hex> <value>");
                std::process::exit(1);
            }
            let set = parse_set(&args[3]);
            let did_num = parse_did(&args[4]);
            let value = args[5].as_bytes();
            match did::write_did(&mut nv, set, did_num, value) {
                Ok(true) => println!("[diag] wrote DID 0x{did_num:04X}"),
                Ok(false) => {
                    eprintln!("[diag] runtime DID store full");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("[diag] write failed: {e}");
                    std::process::exit(1);
                }
            }
        }

        "provision" => {
            if args.len() < 5 {
                eprintln!("Usage: provision <serial> <vin>");
                std::process::exit(1);
            }
            if nv.read_factory().is_some() {
                eprintln!("[diag] factory data already provisioned");
                std::process::exit(1);
            }
            let serial = &args[3];
            let vin = &args[4];

            let mut factory = NvFactory::default();
            let slen = serial.len().min(32);
            factory.serial_number[..slen].copy_from_slice(&serial.as_bytes()[..slen]);
            let vlen = vin.len().min(17);
            factory.vin[..vlen].copy_from_slice(&vin.as_bytes()[..vlen]);

            nv.write_factory(&mut factory).unwrap();
            println!("[diag] factory provisioned: serial={serial} vin={vin}");
        }

        "factory-init" => {
            if args.len() < 4 {
                eprintln!(
                    "Usage: factory-init <manifest-dir> [--runner-path <path>] \
                     [--images-dir <dir>] [--hsm-keystore <dir>]"
                );
                std::process::exit(1);
            }
            let dir = PathBuf::from(&args[3]);
            let mut runner_path: Option<PathBuf> = None;
            let mut images_dir: Option<PathBuf> = None;
            let mut hsm_keystore: Option<PathBuf> = None;
            let mut i = 4;
            while i < args.len() {
                if args[i] == "--runner-path" && i + 1 < args.len() {
                    runner_path = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else if args[i] == "--images-dir" && i + 1 < args.len() {
                    images_dir = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else if args[i] == "--hsm-keystore" && i + 1 < args.len() {
                    hsm_keystore = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else {
                    i += 1;
                }
            }

            // When both an images dir (for bank dirs) and an HSM keystore
            // are supplied, factory-init seals the factory SW identity into
            // each bank's signed IVD manifest — the single source for the
            // F187-F19E identification DIDs (they no longer live in NV).
            // Mirror the server's HSM bring-up: a SimHsm with device keys
            // ensured (creates the `ivd-signing` slot). Without these
            // flags, identity isn't sealed anywhere (the bank gets its
            // signed manifest at the first OTA flash instead).
            let factory_hsm = match (&images_dir, &hsm_keystore) {
                (Some(_), Some(ks)) => {
                    let hsm = hsm_sim_backend::SimHsm::new(ks.clone());
                    if let Err(e) = hsm.ensure_device_keys() {
                        eprintln!("[factory] failed to ensure HSM device keys: {e}");
                        std::process::exit(1);
                    }
                    Some(hsm)
                }
                _ => None,
            };

            // Provision factory data
            let factory_yaml = dir.join("factory.yaml");
            if factory_yaml.exists() {
                if nv.read_factory().is_some() {
                    eprintln!("[factory] factory data already provisioned, skipping");
                } else {
                    let fm = FactoryManifest::from_file(&factory_yaml).unwrap_or_else(|e| {
                        eprintln!("[factory] {e}");
                        std::process::exit(1);
                    });
                    let mut nv_factory = fm.to_nv_factory();
                    nv.write_factory(&mut nv_factory).unwrap();
                    println!(
                        "[factory] provisioned: serial={} vin={}",
                        fm.serial_number, fm.vin
                    );
                }
            }

            // Write FW meta for each bank set with a manifest
            for name in ["host-os", "vm1", "vm2", "hsm"] {
                let manifest_file = dir.join(format!("{name}.yaml"));
                if !manifest_file.exists() {
                    continue;
                }
                let manifest = FirmwareManifest::from_file(&manifest_file).unwrap_or_else(|e| {
                    eprintln!("[factory] {e}");
                    std::process::exit(1);
                });
                let set = manifest.resolve_bank_set().unwrap_or_else(|| {
                    eprintln!("[factory] cannot resolve bank set from {name}.yaml");
                    std::process::exit(1);
                });

                // Get image data for hashing
                let image_sha256: [u8; 32];
                let fw_crc: u32;

                if name == "hypervisor" {
                    if let Some(ref rp) = runner_path {
                        let data = std::fs::read(rp).unwrap_or_else(|e| {
                            eprintln!("[factory] failed to read runner binary: {e}");
                            std::process::exit(1);
                        });
                        use sha2::{Digest, Sha256};
                        image_sha256 = Sha256::digest(&data).into();
                        fw_crc = crc32fast::hash(&data);
                        println!(
                            "[factory] {name}: hashed runner binary ({} bytes)",
                            data.len()
                        );
                    } else {
                        // No runner binary — use zero hash
                        image_sha256 = [0; 32];
                        fw_crc = 0;
                        println!("[factory] {name}: no --runner-path, skipping image hash");
                    }
                } else {
                    // Look for {name}.img in the manifest dir
                    let img_path = dir.join(format!("{name}.img"));
                    if img_path.exists() {
                        let data = std::fs::read(&img_path).unwrap_or_else(|e| {
                            eprintln!("[factory] failed to read {}: {e}", img_path.display());
                            std::process::exit(1);
                        });
                        use sha2::{Digest, Sha256};
                        image_sha256 = Sha256::digest(&data).into();
                        fw_crc = crc32fast::hash(&data);
                        println!("[factory] {name}: hashed image ({} bytes)", data.len());
                    } else {
                        image_sha256 = [0; 32];
                        fw_crc = 0;
                        println!("[factory] {name}: no image file, skipping hash");
                    }
                }

                let meta = manifest.to_image_meta();
                // NvFwMeta carries boot/install state only — SW identity
                // goes into the signed IVD manifest below.
                let mut fw_meta = NvFwMeta {
                    write_seq: 0,
                    fw_seq: meta.fw_seq,
                    fw_secver: meta.fw_secver,
                    fw_crc,
                    image_sha256,
                    min_security_ver: 0,
                    // Factory baseline; first OTA install ratchets to 1.
                    gen: 0,
                };
                // Write directly to bank A (factory state, no trial mode)
                nv.write_fw_meta(set, Bank::A, &mut fw_meta).unwrap();
                println!(
                    "[factory] {name}: wrote FW meta bank A (version: {})",
                    manifest.version
                );

                // Seal the factory SW identity into bank A's signed IVD
                // manifest — the single source for the identification DIDs.
                // gen=0 matches the factory NvFwMeta baseline above.
                if let (Some(ref hsm), Some(ref images)) = (&factory_hsm, &images_dir) {
                    let bank_dir = images.join(name).join("bank_a");
                    if let Err(e) = std::fs::create_dir_all(&bank_dir) {
                        eprintln!(
                            "[factory] {name}: create bank dir {}: {e}",
                            bank_dir.display()
                        );
                        std::process::exit(1);
                    }
                    let identity = meta.to_ivd_identity();
                    match hsm::ivd::sign_bank_crypto(hsm, &bank_dir, 0, identity) {
                        Ok(_) => println!(
                            "[factory] {name}: signed IVD identity manifest in {}",
                            bank_dir.display()
                        ),
                        Err(e) => {
                            eprintln!("[factory] {name}: IVD identity sign failed: {e}");
                            std::process::exit(1);
                        }
                    }
                }
            }

            println!("[factory] initialization complete");
        }

        _ => {
            eprintln!("Unknown command: {cmd}");
            usage();
        }
    }
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}
