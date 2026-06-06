use nv_store::block::FileBlockDevice;
use nv_store::selector::FileSelectorStore;
use nv_store::store::MIN_NV_DEVICE_SIZE;
use nv_store::types::BankSet;
use std::path::PathBuf;
use vm_boot::{BootAction, BootManager, HashCheck};

fn usage() -> ! {
    eprintln!("Usage: vm-boot <nv-store-path> [--selector <dir>] [--init]");
    eprintln!();
    eprintln!("  <nv-store-path>   Path to the NV store file/device");
    eprintln!("  --selector <dir>  Boot-selector dir (PRIMARY/SECONDARY slot files).");
    eprintln!("                    When present and seeded, drives the bank decision;");
    eprintln!("                    otherwise the NV boot state is used.");
    eprintln!("  --init            Create a new NV store file if it doesn't exist");
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Parse: the NV path is the first non-flag arg; `--selector <dir>` and
    // `--init` may appear anywhere after it.
    let mut nv_path: Option<PathBuf> = None;
    let mut selector_dir: Option<PathBuf> = None;
    let mut init = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--init" => init = true,
            "--selector" => {
                i += 1;
                match args.get(i) {
                    Some(dir) => selector_dir = Some(PathBuf::from(dir)),
                    None => {
                        eprintln!("[bootmgr] --selector requires a directory argument");
                        usage();
                    }
                }
            }
            "-h" | "--help" => usage(),
            other if other.starts_with("--") => {
                eprintln!("[bootmgr] unknown option: {other}");
                usage();
            }
            _ if nv_path.is_none() => nv_path = Some(PathBuf::from(&args[i])),
            other => {
                eprintln!("[bootmgr] unexpected argument: {other}");
                usage();
            }
        }
        i += 1;
    }

    let nv_path = match nv_path {
        Some(p) => p,
        None => usage(),
    };

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
    if let Some(dir) = &selector_dir {
        eprintln!("[bootmgr] using boot selector: {}", dir.display());
        mgr = mgr.with_selector(Box::new(FileSelectorStore::new(dir.clone())));
    }

    let actions = match mgr.process_boot() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[bootmgr] failed to process boot: {e}");
            std::process::exit(1);
        }
    };

    // (name, NV slot index, BankSet). `idx` selects this set's entry
    // in the `actions` array (indexed by `BankSet::as_index()`), so it
    // tracks the fixed semantic slot layout. `name` is the boot-script
    // contract (`ACTIVE_HOST-OS=`/`ACTIVE_VM1=`/`ACTIVE_VM2=`) and is
    // kept stable across the slot renumber.
    let output_sets: &[(&str, usize, BankSet)] = &[
        ("host-os", BankSet::Os.as_index(), BankSet::Os),
        ("vm1", BankSet::Vm1.as_index(), BankSet::Vm1),
        ("vm2", BankSet::Vm2.as_index(), BankSet::Vm2),
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
