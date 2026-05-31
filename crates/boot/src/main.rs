use nv_store::block::FileBlockDevice;
use nv_store::store::MIN_NV_DEVICE_SIZE;
use nv_store::types::BankSet;
use std::path::PathBuf;
use vm_boot::{BootAction, BootManager, HashCheck};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let nv_path = match args.get(1) {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("Usage: vm-boot <nv-store-path> [--init]");
            eprintln!();
            eprintln!("  <nv-store-path>  Path to the NV store file/device");
            eprintln!("  --init           Create a new NV store file if it doesn't exist");
            std::process::exit(1);
        }
    };

    let init = args.get(2).is_some_and(|a| a == "--init");

    let dev = if init && !nv_path.exists() {
        eprintln!("[bootmgr] creating NV store: {}", nv_path.display());
        FileBlockDevice::create(&nv_path, MIN_NV_DEVICE_SIZE)
    } else {
        FileBlockDevice::open(&nv_path)
    };

    let dev = match dev {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[bootmgr] failed to open NV store: {e}");
            std::process::exit(1);
        }
    };

    let mut mgr = BootManager::new(dev);

    let actions = match mgr.process_boot() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[bootmgr] failed to process boot: {e}");
            std::process::exit(1);
        }
    };

    let output_sets: &[(&str, usize, BankSet)] = &[
        ("host-os", 0, BankSet::HostOs),
        ("vm1", 1, BankSet::Vm1),
        ("vm2", 2, BankSet::Vm2),
    ];

    for &(name, idx, set) in output_sets {
        let action = &actions[idx];
        match action {
            BootAction::FirstBoot => {
                println!("[bootmgr] {name}: first boot, initialized to bank A");
            }
            BootAction::Boot { bank } => {
                println!("[bootmgr] {name}: boot bank {bank:?} (committed)");
            }
            BootAction::TrialBoot { bank, boot_count } => {
                println!(
                    "[bootmgr] {name}: trial boot bank {bank:?} ({boot_count}/{})",
                    nv_store::types::MAX_TRIAL_BOOTS
                );
            }
            BootAction::AutoRollback { from, to } => {
                eprintln!(
                    "[bootmgr] {name}: AUTO-ROLLBACK from bank {from:?} to {to:?} \
                     (exceeded {} trial boots)",
                    nv_store::types::MAX_TRIAL_BOOTS
                );
            }
            BootAction::HashRollback { from, to } => {
                eprintln!("[bootmgr] {name}: HASH ROLLBACK from bank {from:?} to {to:?}");
            }
            BootAction::HashFatal { bank } => {
                eprintln!(
                    "[bootmgr] {name}: FATAL — committed bank {bank:?} hash verification failed!"
                );
            }
        }

        // Verify image hash if we have a bank to boot
        let bank = match action {
            BootAction::Boot { bank } | BootAction::TrialBoot { bank, .. } => Some(*bank),
            _ => None,
        };
        if let Some(bank) = bank {
            let check = mgr.verify_image(set, bank, &[]); // placeholder: no image data in CLI mode
            match check {
                HashCheck::NoMeta => {} // no hash stored, skip
                HashCheck::Ok => println!("[bootmgr] {name}: image hash verified"),
                HashCheck::Mismatch { .. } => {
                    eprintln!("[bootmgr] {name}: IMAGE HASH MISMATCH");
                    match mgr.handle_hash_failure(set) {
                        Ok(recovery) => {
                            eprintln!("[bootmgr] {name}: recovery action: {recovery:?}")
                        }
                        Err(e) => eprintln!("[bootmgr] {name}: recovery failed: {e}"),
                    }
                }
            }
        }
    }

    // Output active banks as machine-readable line for scripts
    println!();
    for &(name, _, set) in output_sets {
        if let Some(bank) = mgr.active_bank(set) {
            let letter = match bank {
                nv_store::types::Bank::A => "A",
                nv_store::types::Bank::B => "B",
            };
            println!("ACTIVE_{}={}", name.to_uppercase(), letter);
        }
    }
}
