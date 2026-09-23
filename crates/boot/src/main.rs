use nv_store::block::{BlockDevice, FileBlockDevice};
use nv_store::selector::FileSelectorStore;
use nv_store::store::nv_device_size;
use nv_store::types::{BankSet, DEFAULT_SLOTS};
use std::path::PathBuf;
use vm_boot::{BootAction, BootManager};

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
        FileBlockDevice::create(&nv_path, nv_device_size(DEFAULT_SLOTS))
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
    // The addressable slot count comes from the file's size, so print what this
    // store actually is — an existing file may be smaller than a fresh one.
    eprintln!(
        "[bootmgr] NV store {}: {} bytes = {} slots",
        nv_path.display(),
        mgr.nv().device().size(),
        mgr.nv().slot_count()
    );
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

    // A slot is a number: a component's slot comes from the platform
    // profile, so this tool has no name to print for one. `actions` is
    // one entry per ADDRESSABLE slot, indexed by `BankSet::as_index()`,
    // so the index IS the slot.
    for (idx, action) in actions.iter().enumerate() {
        match action {
            BootAction::FirstBoot => {
                println!("[bootmgr] slot {idx}: first boot, initialized to bank A");
            }
            BootAction::Boot { bank } => {
                println!("[bootmgr] slot {idx}: boot bank {bank:?} (committed)");
            }
            BootAction::TrialBoot { bank, boot_count } => {
                println!(
                    "[bootmgr] slot {idx}: trial boot bank {bank:?} ({boot_count}/{})",
                    nv_store::types::MAX_TRIAL_BOOTS
                );
            }
            BootAction::AutoRollback { from, to } => {
                eprintln!(
                    "[bootmgr] slot {idx}: AUTO-ROLLBACK from bank {from:?} to {to:?} \
                     (exceeded {} trial boots)",
                    nv_store::types::MAX_TRIAL_BOOTS
                );
            }
            BootAction::HashRollback { from, to } => {
                eprintln!("[bootmgr] slot {idx}: HASH ROLLBACK from bank {from:?} to {to:?}");
            }
            BootAction::HashFatal { bank } => {
                eprintln!(
                    "[bootmgr] slot {idx}: FATAL — committed bank {bank:?} hash verification failed!"
                );
            }
        }

        // No image verification here. This CLI holds no image bytes, so the
        // former "placeholder" check hashed EMPTY data: for any slot whose FW
        // meta carries a real hash it could only ever mismatch — and a
        // mismatch writes NV (rollback, or FATAL on a committed bank). With
        // every addressable slot in this loop that latent hazard would have
        // covered the whole store. Verification belongs to the process that
        // has the image: the host's pre-launch verify.
    }

    // Output active banks as machine-readable lines for scripts. Numeric,
    // one per slot: no consumer parses these (host-boot.sh reads the boot
    // selector by numeric slot), and the `ACTIVE_HOST-OS=`/`ACTIVE_VM1=`/
    // `ACTIVE_VM2=` triple they replace was platform vocabulary leaking
    // out of a slot-generic tool.
    println!();
    for idx in 0..actions.len() {
        if let Some(bank) = mgr.active_bank(BankSet(idx as u8)) {
            let letter = match bank {
                nv_store::types::Bank::A => "A",
                nv_store::types::Bank::B => "B",
            };
            println!("ACTIVE_SLOT_{idx}={letter}");
        }
    }
}
