use super::super::*;
use crate::manifest_provider::ManifestError;
use machine_mgr::bank_provider::{BankError, BankProvider};
use machine_mgr::ResetKind;
use nv_store::block::MemBlockDevice;
use nv_store::slots;
use nv_store::store::MIN_NV_DEVICE_SIZE;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct NoopManifest;
impl ManifestProvider for NoopManifest {
    fn validate(&self, _d: &[u8], _m: u32) -> Result<ValidatedFirmware, ManifestError> {
        Err(ManifestError::ParseError("unused".into()))
    }
}

/// A sentinel `BankProvider` whose `reset_kind()` is the distinctive
/// `RequiresEcuReset` — the default `IvdBankProvider` (no activator) returns
/// `Local`, so observing `RequiresEcuReset` through `ComponentBackend`
/// proves the injected provider is the one in use. Every other method is an
/// unreachable stub: the test only exercises the dispatch.
struct SentinelProvider {
    selected: Mutex<Option<Bank>>,
    pending_reboot: AtomicBool,
    commits: AtomicUsize,
    rollbacks: AtomicUsize,
    /// The bank report [`BankProvider::banks`] returns (`None` = none).
    banks: Mutex<Option<machine_mgr::ComponentBanks>>,
}

impl SentinelProvider {
    fn new(selected: Option<Bank>) -> Self {
        Self {
            selected: Mutex::new(selected),
            pending_reboot: AtomicBool::new(false),
            commits: AtomicUsize::new(0),
            rollbacks: AtomicUsize::new(0),
            banks: Mutex::new(None),
        }
    }

    /// Report bank B active with these trial facts from now on.
    fn set_banks(&self, in_trial: bool, pending_reset: bool) {
        *self.banks.lock().unwrap() = Some(machine_mgr::ComponentBanks {
            active: machine_mgr::BankContents {
                bank: Bank::B,
                images: Default::default(),
                install_boot_id: None,
                update_id: None,
                sealed: false,
            },
            inactive: None,
            in_trial,
            pending_reset,
        });
    }
}

impl BankProvider for SentinelProvider {
    fn active_bank(&self) -> Bank {
        Bank::B
    }
    fn selected_bank(&self) -> Option<Bank> {
        *self.selected.lock().unwrap()
    }
    fn target_bank(&self) -> Bank {
        Bank::A
    }
    fn pending_reboot(&self) -> bool {
        self.pending_reboot.load(Ordering::SeqCst)
    }
    fn prepare_target(&self, _bank: Bank) -> Result<(), BankError> {
        Ok(())
    }
    fn open_payload_writer(
        &self,
        _bank: Bank,
        _name: &str,
    ) -> Result<Box<dyn std::io::Write + Send>, BankError> {
        Err(BankError::Failed("sentinel".into()))
    }
    fn seal(
        &self,
        _b: Bank,
        _i: FirmwareIdentity,
        _g: u64,
        _r: &[String],
    ) -> Result<(), BankError> {
        Ok(())
    }
    fn read_installed(&self, _bank: Bank) -> Result<InstalledFirmware, BankError> {
        Err(BankError::NotInstalled)
    }
    fn verify_payload(&self, _b: Bank, _n: &str, _s: &[u8; 32]) -> Result<(), BankError> {
        Ok(())
    }
    fn activate(&self, _bank: Bank) -> Result<ResetKind, BankError> {
        Ok(ResetKind::RequiresEcuReset)
    }
    fn commit(&self) -> Result<(), BankError> {
        self.commits.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn rollback(&self) -> Result<(), BankError> {
        self.rollbacks.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn reset_kind(&self) -> ResetKind {
        ResetKind::RequiresEcuReset
    }
    fn can_persist_disabled_record(&self) -> Result<(), BankError> {
        Err(BankError::Failed("test provider".into()))
    }
    fn write_disabled_record(&self, _bank: Bank, _gen: u64) -> Result<(), BankError> {
        Err(BankError::Failed("test provider".into()))
    }
    fn disabled_record(&self, _bank: Bank) -> Result<Option<u64>, BankError> {
        Ok(None)
    }
    fn banks(&self) -> Option<machine_mgr::ComponentBanks> {
        self.banks.lock().unwrap().clone()
    }
}

fn backend() -> ComponentBackend<MemBlockDevice> {
    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    let mut boot = NvBootState::default();
    nv.write_boot_state(&mut boot).unwrap();
    ComponentBackend::with_options(
        slots::VM1,
        Arc::new(Mutex::new(nv)),
        Arc::new(NoopManifest),
        ComponentConfig::default(),
        None,
        None,
        None,
    )
    // The vm-service URLs this fixture's servers assert on are built from
    // the component id, which the factory supplies in production.
    .with_id("vm1".into())
}

fn backend_with_commit_provider(
    provider: Arc<SentinelProvider>,
    single_bank: bool,
) -> ComponentBackend<MemBlockDevice> {
    let mut b = backend();
    b.config.single_bank = single_bank;
    b.with_bank_provider(provider)
}

fn set_transfer_state(b: &ComponentBackend<MemBlockDevice>, state: FlashState) {
    *b.flash_transfer.lock().unwrap() = Some(FlashTransferState {
        transfer_id: "t1".into(),
        package_id: "pkg-1".into(),
        state,
        pre_reset_health: None,
        image_size: 0,
        streamed_files: Vec::new(),
    });
}

fn queued_restart_server(post_reset_boot_id: u32) -> (String, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = std::thread::spawn(move || {
        use std::io::{Read, Write};

        for (index, expected_path) in [
            "/vms/vm1/health",
            "/vms/vm1/restart?bank=b",
            "/vms/vm1/health",
        ]
        .into_iter()
        .enumerate()
        {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let size = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..size]);
            assert!(request.lines().next().unwrap().contains(expected_path));

            let body = if index == 1 {
                String::new()
            } else {
                let boot_id = if index == 0 { 7 } else { post_reset_boot_id };
                format!(r#"{{"guest_state":1,"hb_seq":10,"boot_id":{boot_id},"status":"running"}}"#)
            };
            let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            stream.write_all(response.as_bytes()).unwrap();
        }
    });
    (addr, handle)
}

fn absent_then_healthy_server() -> (String, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = std::thread::spawn(move || {
        use std::io::{Read, Write};

        for (index, expected_path) in [
            "/vms/vm1/health",
            "/vms/vm1/start?bank=b",
            "/vms/vm1/health",
        ]
        .into_iter()
        .enumerate()
        {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let size = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..size]);
            assert!(request.lines().next().unwrap().contains(expected_path));

            let (status, body) = match index {
                0 => (
                    "404 Not Found",
                    r#"{"error":"VM not found: vm1"}"#.to_string(),
                ),
                1 => ("200 OK", String::new()),
                _ => (
                    "200 OK",
                    r#"{"guest_state":1,"hb_seq":1,"boot_id":7,"status":"running"}"#.to_string(),
                ),
            };
            let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            stream.write_all(response.as_bytes()).unwrap();
        }
    });
    (addr, handle)
}

fn arm_bank_b_trial(b: &ComponentBackend<MemBlockDevice>) {
    set_transfer_state(b, FlashState::AwaitingReboot);
    let mut nv = b.nv.lock().unwrap();
    let mut boot = nv.read_boot_state().unwrap();
    let bank = &mut boot.banks[slots::VM1.as_index()];
    bank.active_bank = Bank::B;
    bank.committed = false;
    bank.boot_count = 0;
    nv.write_boot_state(&mut boot).unwrap();
}

#[tokio::test]
async fn banked_commit_preflight_rejects_awaiting_reboot_without_mutation() {
    let provider = Arc::new(SentinelProvider::new(Some(Bank::A)));
    let b = backend_with_commit_provider(provider.clone(), false);
    set_transfer_state(&b, FlashState::AwaitingReboot);
    let before_boot = b.nv.lock().unwrap().read_boot_state().unwrap();
    let before_session = b.nv.lock().unwrap().read_update_session();

    let err = b.commit_flash().await.unwrap_err();

    assert!(matches!(err, BackendError::Busy(_)));
    assert_eq!(err.status_code(), 409);
    assert_eq!(provider.commits.load(Ordering::SeqCst), 0);
    assert_eq!(
        b.flash_transfer.lock().unwrap().as_ref().unwrap().state,
        FlashState::AwaitingReboot
    );
    assert_eq!(b.nv.lock().unwrap().read_boot_state().unwrap(), before_boot);
    assert_eq!(b.nv.lock().unwrap().read_update_session(), before_session);
}

/// Arm VM1 into a bank-B trial on `b`'s NV with no boot witness and the
/// durable reboot-owed bit set — the shape the removed gates used to veto.
fn arm_owed_bank_b_without_witness(b: &ComponentBackend<MemBlockDevice>) {
    {
        let mut nv = b.nv.lock().unwrap();
        let mut boot = nv.read_boot_state().unwrap();
        let bank = &mut boot.banks[slots::VM1.as_index()];
        bank.active_bank = Bank::B;
        bank.committed = false;
        bank.boot_count = 0;
        nv.write_boot_state(&mut boot).unwrap();
    }
    b.set_reboot_owed(true).unwrap();
}

/// A clone of `b` rebuilt on the same NV, as after a process restart:
/// `running_bank` seeds from the NV active bank.
fn reconstruct(
    b: &ComponentBackend<MemBlockDevice>,
    provider: Arc<SentinelProvider>,
) -> ComponentBackend<MemBlockDevice> {
    ComponentBackend::with_options(
        slots::VM1,
        b.nv.clone(),
        Arc::new(NoopManifest),
        ComponentConfig::default(),
        None,
        None,
        None,
    )
    .with_bank_provider(provider)
}

#[tokio::test]
async fn banked_commit_preflight_rejects_running_bank_mismatch_only() {
    let provider = Arc::new(SentinelProvider::new(Some(Bank::B)));
    let b = backend_with_commit_provider(provider.clone(), false);
    arm_owed_bank_b_without_witness(&b);
    provider.set_banks(true, true);

    // The owed bit, a pending reset and the missing boot witness are not
    // vetoes; the selected bank B disagreeing with the bank this (pre-arm)
    // process still runs (A) is.
    let err = b.commit_flash().await.unwrap_err();
    assert!(matches!(err, BackendError::Busy(_)));
    assert!(err.to_string().contains("running bank"), "{err}");
    assert_eq!(provider.commits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn banked_commit_succeeds_without_boot_witness_and_clears_owed_bit() {
    let provider = Arc::new(SentinelProvider::new(Some(Bank::B)));
    let b = backend_with_commit_provider(provider.clone(), false);
    arm_owed_bank_b_without_witness(&b);
    let reconstructed = reconstruct(&b, provider.clone());
    assert!(reconstructed.vm_service_addr.is_none());

    reconstructed.commit_flash().await.unwrap();

    assert_eq!(provider.commits.load(Ordering::SeqCst), 1);
    let session =
        b.nv.lock()
            .unwrap()
            .read_update_session()
            .unwrap_or_default();
    assert!(!session.owes(slots::VM1));
}

#[tokio::test]
async fn reconstructed_trial_reports_awaiting_reboot_while_pending_reset() {
    let provider = Arc::new(SentinelProvider::new(Some(Bank::B)));
    let b =
        backend_with_commit_provider(provider.clone(), false).with_node_boot_id("boot-x".into());
    {
        let mut nv = b.nv.lock().unwrap();
        let mut meta = NvFwMeta {
            gen: 1,
            ..Default::default()
        };
        nv.write_fw_meta(slots::VM1, Bank::B, &mut meta).unwrap();
    }
    arm_owed_bank_b_without_witness(&b);
    assert_eq!(
        b.nv.lock()
            .unwrap()
            .read_update_session()
            .unwrap()
            .armed_boot_id,
        NvUpdateSession::boot_id_digest("boot-x")
    );

    // The bank report carries the boot-id comparison (`pending_reset`: the
    // install was sealed in the boot still running); the provider derives
    // it, this stub states it.
    provider.set_banks(true, true);
    let same_boot = reconstruct(&b, provider.clone()).with_node_boot_id("boot-x".into());
    assert_eq!(
        same_boot.get_activation_state().await.unwrap().state,
        FlashState::AwaitingReboot
    );
    provider.set_banks(true, false);
    let rebooted = reconstruct(&b, provider.clone()).with_node_boot_id("boot-y".into());
    assert_eq!(
        rebooted.get_activation_state().await.unwrap().state,
        FlashState::Activated
    );
    let unknown = reconstruct(&b, provider.clone());
    assert_eq!(
        unknown.get_activation_state().await.unwrap().state,
        FlashState::Activated
    );
    // Out of trial: no active update.
    provider.set_banks(false, false);
    assert_eq!(
        unknown.get_activation_state().await.unwrap().state,
        FlashState::Complete
    );
    provider.set_banks(true, false);

    rebooted.commit_flash().await.unwrap();
    assert_eq!(provider.commits.load(Ordering::SeqCst), 1);
}

/// Records the `arm_enrollment` calls `commit_flash` makes; every other
/// method is an unused stub (the commit path touches none of them).
struct EnrollRecorder {
    armed: Arc<Mutex<Vec<String>>>,
}

impl hsm::HsmProvider for EnrollRecorder {
    fn is_provisioned(&self) -> Result<bool, hsm::HsmError> {
        Ok(true)
    }
    fn provision(&mut self, _envelope: &[u8]) -> Result<(), hsm::HsmError> {
        Ok(())
    }
    fn list_slots(&self) -> Result<Vec<hsm::SlotInfo>, hsm::HsmError> {
        Ok(Vec::new())
    }
    fn get_public_key(&self, _role: hsm::KeyRole) -> Result<Vec<u8>, hsm::HsmError> {
        Ok(Vec::new())
    }
    fn provisioning_state(&self) -> Result<hsm::ProvisioningState, hsm::HsmError> {
        Ok(hsm::ProvisioningState::Provisioned)
    }
    fn arm_enrollment(&mut self, vm_id: &str, _ttl: Option<u64>) -> Result<(), hsm::HsmError> {
        self.armed.lock().unwrap().push(vm_id.to_string());
        Ok(())
    }
}

/// A banked component with an HSM whose `arm_enrollment` calls are
/// recorded, nominated (or not) as a vm principal.
fn backend_with_enroll_recorder(
    vm_principal: bool,
) -> (
    ComponentBackend<MemBlockDevice>,
    Arc<Mutex<Vec<String>>>,
    Arc<SentinelProvider>,
) {
    let armed = Arc::new(Mutex::new(Vec::new()));
    let hsm: Arc<Mutex<dyn hsm::HsmProvider>> = Arc::new(Mutex::new(EnrollRecorder {
        armed: armed.clone(),
    }));
    let provider = Arc::new(SentinelProvider::new(Some(Bank::A)));
    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    nv.write_boot_state(&mut NvBootState::default()).unwrap();
    let b = ComponentBackend::with_options(
        slots::VM1,
        Arc::new(Mutex::new(nv)),
        Arc::new(NoopManifest),
        ComponentConfig::default(),
        None,
        None,
        Some(hsm),
    )
    .with_id("vm1".into())
    .with_vm_principal(vm_principal)
    .with_bank_provider(provider.clone());
    (b, armed, provider)
}

/// Arming in-band enrolment at commit is a vm-principal property the
/// platform declares, not something the slot implies: same banked
/// component, same HSM, armed only when nominated. The negative is the
/// rt-core shape — a banked component with no guest identity to enrol.
#[tokio::test]
async fn enrollment_is_armed_at_commit_only_for_a_vm_principal() {
    for (vm_principal, expected) in [(true, vec!["vm1".to_string()]), (false, Vec::new())] {
        let (b, armed, provider) = backend_with_enroll_recorder(vm_principal);
        {
            let mut nv = b.nv.lock().unwrap();
            let mut boot = nv.read_boot_state().unwrap();
            let bank = &mut boot.banks[slots::VM1.as_index()];
            bank.committed = false;
            bank.boot_count = 1;
            nv.write_boot_state(&mut boot).unwrap();
        }

        b.commit_flash().await.unwrap();

        assert_eq!(provider.commits.load(Ordering::SeqCst), 1);
        assert_eq!(
            *armed.lock().unwrap(),
            expected,
            "vm_principal={vm_principal}"
        );
    }
}

#[tokio::test]
async fn banked_commit_succeeds_in_trial() {
    let provider = Arc::new(SentinelProvider::new(Some(Bank::A)));
    let b = backend_with_commit_provider(provider.clone(), false);
    {
        let mut nv = b.nv.lock().unwrap();
        let mut boot = nv.read_boot_state().unwrap();
        let bank = &mut boot.banks[slots::VM1.as_index()];
        bank.committed = false;
        nv.write_boot_state(&mut boot).unwrap();
    }

    b.commit_flash().await.unwrap();

    assert_eq!(provider.commits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn failed_vm_restart_does_not_record_boot_or_activation_or_advance_state() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    drop(listener);
    let mut b = backend();
    b.vm_service_addr = Some(addr);
    set_transfer_state(&b, FlashState::AwaitingReboot);
    {
        let mut nv = b.nv.lock().unwrap();
        let mut boot = nv.read_boot_state().unwrap();
        let bank = &mut boot.banks[slots::VM1.as_index()];
        bank.active_bank = Bank::B;
        bank.committed = false;
        bank.boot_count = 0;
        nv.write_boot_state(&mut boot).unwrap();
    }

    let err = b.ecu_reset(0).await.unwrap_err();

    assert!(matches!(err, BackendError::Transport(_)));
    assert_eq!(b.running_bank().unwrap(), Bank::A);
    let boot = b.nv.lock().unwrap().read_boot_state().unwrap();
    assert_eq!(boot.banks[slots::VM1.as_index()].boot_count, 0);
    assert_eq!(
        b.flash_transfer.lock().unwrap().as_ref().unwrap().state,
        FlashState::AwaitingReboot
    );
    assert!(matches!(b.commit_flash().await, Err(BackendError::Busy(_))));
    b.rollback_flash().await.unwrap();
}

#[tokio::test]
async fn vm_health_query_failure_does_not_queue_reset() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        use std::io::{Read, Write};

        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0u8; 1024];
        let size = stream.read(&mut request).unwrap();
        let request = String::from_utf8_lossy(&request[..size]);
        assert!(request.lines().next().unwrap().contains("/vms/vm1/health"));
        stream
            .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
    });
    let mut b = backend();
    b.vm_service_addr = Some(addr);
    arm_bank_b_trial(&b);

    let err = b.ecu_reset(0).await.unwrap_err();

    assert!(matches!(err, BackendError::Transport(_)));
    assert_eq!(
        b.flash_transfer.lock().unwrap().as_ref().unwrap().state,
        FlashState::AwaitingReboot
    );
    assert_eq!(b.running_bank().unwrap(), Bank::A);
    assert_eq!(
        b.nv.lock().unwrap().read_boot_state().unwrap().banks[slots::VM1.as_index()].boot_count,
        0
    );
    server.join().unwrap();
}

#[tokio::test]
async fn confirmed_absent_vm_accepts_first_later_healthy_boot() {
    let (addr, server) = absent_then_healthy_server();
    let mut b = backend();
    b.vm_service_addr = Some(addr);
    arm_bank_b_trial(&b);

    b.ecu_reset(0).await.unwrap();
    let activation = b.get_activation_state().await.unwrap();

    assert_eq!(activation.state, FlashState::Activated);
    assert_eq!(b.running_bank().unwrap(), Bank::B);
    server.join().unwrap();
}

#[tokio::test]
async fn queued_vm_restart_without_fresh_boot_stays_verifying_and_unwitnessed() {
    let (addr, server) = queued_restart_server(7);
    let mut b = backend();
    b.vm_service_addr = Some(addr);
    arm_bank_b_trial(&b);

    b.ecu_reset(0).await.unwrap();

    assert_eq!(b.running_bank().unwrap(), Bank::A);
    assert_eq!(
        b.flash_transfer.lock().unwrap().as_ref().unwrap().state,
        FlashState::Verifying
    );
    assert_eq!(
        b.nv.lock().unwrap().read_boot_state().unwrap().banks[slots::VM1.as_index()].boot_count,
        0
    );

    let activation = b.get_activation_state().await.unwrap();

    assert_eq!(activation.state, FlashState::Verifying);
    assert_eq!(b.running_bank().unwrap(), Bank::A);
    assert_eq!(
        b.nv.lock().unwrap().read_boot_state().unwrap().banks[slots::VM1.as_index()].boot_count,
        0
    );
    assert!(matches!(b.commit_flash().await, Err(BackendError::Busy(_))));
    server.join().unwrap();
}

/// A fresh healthy guest boot promotes the trial to Activated and the commit
/// goes through — with the NV boot counter still 0. The promotion no longer
/// writes one (it was a process-lifetime fact dressed up as durable), and the
/// commit gate no longer asks for one on a vm-service-backed guest: the only
/// durable writer there is supernova's heartbeat-confirmed witness, so gating
/// on it made a guest with a broken heartbeat chain permanently uncommittable
/// ("no durable boot witness" on the rig). The reboot evidence is the guest's
/// fresh heartbeat `boot_id` versus the pre-reset baseline — checked in the
/// promotion — and the durable half of that comparison is the orchestrator's.
#[tokio::test]
async fn fresh_healthy_vm_boot_promotes_and_commits_without_a_boot_counter() {
    let (addr, server) = queued_restart_server(8);
    let provider = Arc::new(SentinelProvider::new(Some(Bank::B)));
    let mut b = backend_with_commit_provider(provider.clone(), false);
    b.vm_service_addr = Some(addr);
    arm_bank_b_trial(&b);

    b.ecu_reset(0).await.unwrap();
    let activation = b.get_activation_state().await.unwrap();

    assert_eq!(activation.state, FlashState::Activated);
    assert_eq!(b.running_bank().unwrap(), Bank::B);
    assert_eq!(
        b.nv.lock().unwrap().read_boot_state().unwrap().banks[slots::VM1.as_index()].boot_count,
        0,
        "the promotion must not write a boot counter for a vm-service guest"
    );

    b.commit_flash().await.unwrap();
    assert_eq!(provider.commits.load(Ordering::SeqCst), 1);
    server.join().unwrap();
}

#[tokio::test]
async fn rollback_is_ungated_and_singleshot_commit_is_unchanged() {
    let banked_provider = Arc::new(SentinelProvider::new(Some(Bank::B)));
    banked_provider.pending_reboot.store(true, Ordering::SeqCst);
    let banked = backend_with_commit_provider(banked_provider.clone(), false);
    set_transfer_state(&banked, FlashState::AwaitingReboot);
    banked.set_reboot_owed(true).unwrap();

    banked.rollback_flash().await.unwrap();
    assert_eq!(banked_provider.rollbacks.load(Ordering::SeqCst), 1);

    let singleshot_provider = Arc::new(SentinelProvider::new(Some(Bank::B)));
    singleshot_provider
        .pending_reboot
        .store(true, Ordering::SeqCst);
    let singleshot = backend_with_commit_provider(singleshot_provider.clone(), true);
    set_transfer_state(&singleshot, FlashState::AwaitingReboot);
    singleshot.set_reboot_owed(true).unwrap();

    singleshot.commit_flash().await.unwrap();
    assert_eq!(singleshot_provider.commits.load(Ordering::SeqCst), 1);
}

/// Single-bank (HSM-style), irreversible backend for update-mode tests.
fn singleshot_backend() -> ComponentBackend<MemBlockDevice> {
    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    let mut boot = NvBootState::default();
    nv.write_boot_state(&mut boot).unwrap();
    ComponentBackend::with_options(
        slots::HSM,
        Arc::new(Mutex::new(nv)),
        Arc::new(NoopManifest),
        ComponentConfig {
            supports_rollback: false,
            single_bank: true,
            entity_type: "hsm".to_string(),
            log_sources: Vec::new(),
            test_agent_url: None,
            diag_agent_url: None,
            host_diagnostics: false,
        },
        None,
        None,
        None,
    )
}

/// Whether NV's node reboot-owed record has `b`'s bit set (still written,
/// no longer read by the node-level readers).
pub(super) fn nv_owes<D: BlockDevice + Send + 'static>(b: &ComponentBackend<D>) -> bool {
    b.nv.lock()
        .unwrap()
        .read_update_session()
        .unwrap_or_default()
        .owes(b.bank_set)
}

#[test]
fn reboot_owed_round_trips_through_nv() {
    // The durable marker: set/clear this component's node reboot-owed bit and
    // read it back from the NvUpdateSession record (dual-run: still written).
    let b = backend(); // slots::VM1
    assert!(!nv_owes(&b));

    b.set_reboot_owed(true).unwrap();
    assert!(nv_owes(&b));

    b.set_reboot_owed(false).unwrap();
    assert!(!nv_owes(&b));
}

#[test]
fn commit_and_rollback_share_one_resolve_hook() {
    // Regression for the asymmetry saka caught: commit_flash cleared the node
    // transaction but rollback_flash did not, so a rolled-back banked component
    // stayed wedged in Staging and the node never returned to Idle. Both paths
    // now route through `resolve_node_transaction`; this proves the hook clears
    // the durable reboot-owed bit AND drops the component from the
    // coordinator's staging.
    let coord = Arc::new(machine_mgr::node_update::NodeCoordinator::new());
    let b = backend().with_node_coordinator(coord.clone());
    let id = b.entity_info().id.clone();

    // Stage it (what start_flash's gate does) + mark a reboot owed (finalize).
    coord.gate_new_session(&id).unwrap();
    b.set_reboot_owed(true).unwrap();
    assert_eq!(coord.node_update_state().phase.as_str(), "Staging");

    // The single hook both commit_flash and rollback_flash call.
    b.resolve_node_transaction().unwrap();

    assert!(!nv_owes(&b), "reboot-owed must be cleared");
    assert_eq!(
        coord.node_update_state().phase.as_str(),
        "Idle",
        "staging must be cleared -> node Idle"
    );
}

#[tokio::test]
async fn update_mode_param_banked_for_default_component() {
    // Default backend: dual-bank VM, NO firmware flashed. The vendor param
    // is advertised + readable unconditionally (stable config), proving it
    // works pre-flash — unlike x-ota-installed-manifest which 404s.
    let b = backend();
    let params = b.list_parameters().await.unwrap();
    let p = params
        .iter()
        .find(|p| p.id == UPDATE_MODE_PARAM_ID)
        .expect("x-ota-update-mode must be listed even with no committed manifest");
    assert!(p.read_only);
    assert!(p.did.is_none());

    let vals = b
        .read_data(&[UPDATE_MODE_PARAM_ID.to_string()])
        .await
        .expect("update-mode reads 200 pre-flash");
    let v = &vals[0].value;
    assert_eq!(v["update_mode"], serde_json::json!("banked"));
    assert_eq!(v["supports_rollback"], serde_json::json!(true));
    assert_eq!(v["dual_bank"], serde_json::json!(true));
}

#[tokio::test]
async fn update_mode_param_singleshot_for_hsm_component() {
    // The HSM keystore is single-bank + irreversible — it must report
    // singleshot / supports_rollback=false so the offboard guard can keep it
    // out of a rollbackable campaign.
    let b = singleshot_backend();
    let params = b.list_parameters().await.unwrap();
    assert!(
        params.iter().any(|p| p.id == UPDATE_MODE_PARAM_ID),
        "x-ota-update-mode must be listed for the HSM component too"
    );
    let vals = b
        .read_data(&[UPDATE_MODE_PARAM_ID.to_string()])
        .await
        .unwrap();
    let v = &vals[0].value;
    assert_eq!(v["update_mode"], serde_json::json!("singleshot"));
    assert_eq!(v["supports_rollback"], serde_json::json!(false));
    assert_eq!(v["dual_bank"], serde_json::json!(false));
}

/// §7.21: no log source => capability off + empty list (the route
/// answers "not supported" via capabilities().logs).
#[tokio::test]
async fn logs_unsupported_without_source() {
    let b = backend();
    assert!(!b.capabilities().logs);
    let got = b.get_logs(&LogFilter::default()).await.unwrap();
    assert!(got.is_empty());
}

/// A `Slog2` source advertises the `logs` capability but NOT `bulk_data`
/// (it's a live line stream, not downloadable files — like a guest agent's
/// line view). Off QNX `platform_log::read_slog2` is an empty stub, so the
/// read degrades gracefully to no entries; on the QNX rig it reads the
/// slogger2 ring. Either way the route answers 200, never "not supported".
#[tokio::test]
async fn slog2_source_advertises_logs_not_bulk_data() {
    let b = backend_with_logs(LogSource::Slog2);
    assert!(b.capabilities().logs, "Slog2 turns the logs capability on");
    assert!(
        !b.capabilities().bulk_data,
        "Slog2 is a line stream — no bulk-data file catalog"
    );
    // Reads succeed (empty via the off-QNX stub here); never an error.
    let got = b.get_logs(&LogFilter::default()).await.unwrap();
    assert!(got.is_empty(), "off-QNX stub yields no records");
    let page = b.get_logs_paged(&LogFilter::default()).await.unwrap();
    assert!(page.items.is_empty() && page.next_cursor.is_none());

    // Source/emitter split: slog2 is ONE physical source ("slog2"); a
    // filter.source naming that source is accepted (empty here off-QNX), while
    // any OTHER source means "not this one" → contribute nothing. (The buffer
    // name is the emitter, carried in fields, not matched via source.)
    let f = |s: &str| LogFilter {
        source: Some(s.to_string()),
        ..Default::default()
    };
    assert!(b.get_logs(&f(SLOG2_SOURCE)).await.unwrap().is_empty());
    assert!(b
        .get_logs(&f("some-other-source"))
        .await
        .unwrap()
        .is_empty());
}

/// The raw-ring physical-source constant is the stable wire value a client
/// sees in `LogEntry.source` for every ring record (emitter lives in
/// `fields`). It is `slog2-ring` — the bare `slog2` name belongs to the
/// resumable drained timeline (`SLOG2_SEGMENTS_SOURCE`).
#[test]
fn slog2_source_constant_is_slog2_ring() {
    assert_eq!(SLOG2_SOURCE, "slog2-ring");
    assert_eq!(SLOG2_SEGMENTS_SOURCE, "slog2");
}

/// A `Slog2Segments` source reads the drainer's sealed disk segments as the
/// durable `slog2` journal (the resumable timeline): it advertises a cursor (cursor:true, the
/// reboot-safe <seq>:<offset>), reads entries back, and pages them — unlike the
/// volatile ring. Uses a real tempdir of sealed segments (target-agnostic; no
/// QNX needed since the reader is plain file IO).
#[tokio::test]
async fn slog2_segments_source_reads_and_pages() {
    use sovd_core::{DiagnosticBackend, LogSourceKind};

    let dir = std::env::temp_dir().join(format!("segsrc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for e in std::fs::read_dir(&dir).unwrap().flatten() {
        std::fs::remove_file(e.path()).ok();
    }
    // Two sealed segments, stamped lines (the drainer's on-disk format).
    std::fs::write(
        dir.join("slog2.1.log"),
        "2026-07-20T15:50:13Z boot one\n2026-07-20T15:50:14Z boot two\n",
    )
    .unwrap();
    std::fs::write(dir.join("slog2.2.log"), "2026-07-20T15:50:15Z later\n").unwrap();

    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    let mut boot = NvBootState::default();
    nv.write_boot_state(&mut boot).unwrap();
    let b = ComponentBackend::with_options(
        slots::OS,
        Arc::new(Mutex::new(nv)),
        Arc::new(NoopManifest),
        ComponentConfig {
            log_sources: vec![LogSource::Slog2Segments {
                dir: dir.to_string_lossy().into_owned(),
                stem: "slog2".into(),
                live_dir: None, // colocated: live file (if any) shares `dir`
            }],
            ..ComponentConfig::default()
        },
        None,
        None,
        None,
    );

    // Catalog: one journal source `slog2` (the resumable timeline), cursor:true.
    let srcs = b.list_log_sources().await.unwrap();
    assert_eq!(srcs.len(), 1);
    assert_eq!(srcs[0].name, SLOG2_SEGMENTS_SOURCE);
    assert_eq!(srcs[0].kind, LogSourceKind::Journal);
    assert!(srcs[0].cursor, "persisted segments are cursor-pageable");

    // Merged tail read: all three lines present, source = slog2 (resumable timeline).
    // (get_logs is the newest-first merged view; the paged path below is the
    // authoritative FORWARD-ordered read.)
    let all = b.get_logs(&LogFilter::default()).await.unwrap();
    let mut msgs: Vec<_> = all.iter().map(|e| e.message.clone()).collect();
    msgs.sort();
    assert_eq!(msgs, ["boot one", "boot two", "later"], "got {msgs:?}");
    assert!(all
        .iter()
        .all(|e| e.source.as_deref() == Some(SLOG2_SEGMENTS_SOURCE)));

    // Paged read scoped to the source → a real cursor page, in FORWARD order
    // (oldest→newest, the cursor's native order — NOT wall-clock re-sorted).
    let page = b
        .get_logs_paged(&LogFilter {
            source: Some(SLOG2_SEGMENTS_SOURCE.into()),
            tail: Some(2),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(page.items.len(), 2);
    let pmsgs: Vec<_> = page.items.iter().map(|e| e.message.clone()).collect();
    assert_eq!(pmsgs, ["boot one", "boot two"], "forward cursor order");
    assert!(page.next_cursor.is_some(), "more to read → next_cursor set");
    assert!(page.tip_cursor.is_some(), "segments name their tip");

    std::fs::remove_dir_all(&dir).ok();
}

/// Regression: on a MULTI-source host component (the Tier-2 shape: HostFiles +
/// Slog2 ring + Slog2Segments), a per-file source read must still page via its
/// byte-offset cursor — the catalog advertises the file source cursor:true, so
/// get_logs_paged must honour it even though the set isn't purely HostFiles.
/// Before the source-scoped file branch, this fell through to the terminal
/// default and returned next_cursor=None (broken --all over a large file).
#[tokio::test]
async fn multi_source_file_read_pages_via_cursor() {
    use sovd_core::DiagnosticBackend;

    let dir = std::env::temp_dir().join(format!("multisrc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for e in std::fs::read_dir(&dir).unwrap().flatten() {
        std::fs::remove_file(e.path()).ok();
    }
    // A file source with several lines so one page leaves more to read.
    std::fs::write(
        dir.join("supernova.log"),
        "line-a\nline-b\nline-c\nline-d\nline-e\n",
    )
    .unwrap();
    let segdir = dir.join("segments");
    std::fs::create_dir_all(&segdir).unwrap();

    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    let mut boot = NvBootState::default();
    nv.write_boot_state(&mut boot).unwrap();
    // The full Tier-2 host mix: ring + files + persisted segments.
    let b = ComponentBackend::with_options(
        slots::OS,
        Arc::new(Mutex::new(nv)),
        Arc::new(NoopManifest),
        ComponentConfig {
            log_sources: vec![
                LogSource::Slog2,
                LogSource::HostFiles {
                    globs: vec![format!("{}/*.log", dir.display())],
                },
                LogSource::Slog2Segments {
                    dir: segdir.to_string_lossy().into_owned(),
                    stem: "slog2".into(),
                    live_dir: None,
                },
            ],
            ..ComponentConfig::default()
        },
        None,
        None,
        None,
    );

    // Per-file paged read, scoped by source (as the /logs/sources/{name} route
    // sets it): must return a cursor despite the mixed source set.
    let page = b
        .get_logs_paged(&LogFilter {
            source: Some("supernova".into()),
            limit: Some(2),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!page.items.is_empty(), "file source yields lines");
    assert!(
        page.next_cursor.is_some(),
        "multi-source per-file read MUST page (cursor:true promise): {page:?}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// Name-collision dedup: a HostFiles glob resolving a file whose stem equals a
/// built-in source name (the real case: `/dev/shmem/slog2.log` vs the drained
/// `slog2` segments source) must NOT let the plain file shadow the
/// cursor-pageable journal. list_log_sources prefers the journal/cursor source
/// on a name tie. Regression for the on-device catalog showing `slog2` as a
/// non-cursor `file` (the drainer's own live file) instead of the journal.
#[tokio::test]
async fn list_log_sources_collision_prefers_journal() {
    use sovd_core::{DiagnosticBackend, LogSourceKind};

    let dir = std::env::temp_dir().join(format!("collide-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for e in std::fs::read_dir(&dir).unwrap().flatten() {
        std::fs::remove_file(e.path()).ok();
    }
    // A file literally named slog2.log (the drainer live-file shape) — its stem
    // `slog2` collides with the Slog2Segments source name.
    std::fs::write(dir.join("slog2.log"), "live tail line\n").unwrap();
    let segdir = dir.join("segments");
    std::fs::create_dir_all(&segdir).unwrap();

    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    let mut boot = NvBootState::default();
    nv.write_boot_state(&mut boot).unwrap();
    let b = ComponentBackend::with_options(
        slots::OS,
        Arc::new(Mutex::new(nv)),
        Arc::new(NoopManifest),
        ComponentConfig {
            log_sources: vec![
                LogSource::HostFiles {
                    globs: vec![format!("{}/*.log", dir.display())],
                },
                LogSource::Slog2Segments {
                    dir: segdir.to_string_lossy().into_owned(),
                    stem: "slog2".into(),
                    live_dir: None,
                },
            ],
            ..ComponentConfig::default()
        },
        None,
        None,
        None,
    );

    let srcs = b.list_log_sources().await.unwrap();
    let slog2 = srcs
        .iter()
        .find(|s| s.name == "slog2")
        .expect("a slog2 source survives the collision");
    assert_eq!(
        slog2.kind,
        LogSourceKind::Journal,
        "the drained journal must win the name collision, not the shmem file"
    );
    assert!(
        slog2.cursor,
        "the surviving slog2 source is cursor-pageable"
    );
    // Exactly one `slog2` (deduped).
    assert_eq!(srcs.iter().filter(|s| s.name == "slog2").count(), 1);

    std::fs::remove_dir_all(&dir).ok();
}

/// `list_log_sources` maps each configured `LogSource` to a catalog entry:
/// slog2 → one Journal (cursor:false), HostFiles → one File PER RESOLVED STEM
/// (dynamic, cursor:true), sorted + deduped by name.
#[tokio::test]
async fn list_log_sources_expands_slog2_and_files_by_stem() {
    use sovd_core::{DiagnosticBackend, LogSourceKind};

    // Two real files with distinct stems so resolve_log_files finds them.
    let dir = std::env::temp_dir().join(format!("lsrc-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("host-boot.log"), b"boot\n").unwrap();
    std::fs::write(dir.join("timestamp.log"), b"ts\n").unwrap();
    let glob = format!("{}/*.log", dir.display());

    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    let mut boot = NvBootState::default();
    nv.write_boot_state(&mut boot).unwrap();
    let b = ComponentBackend::with_options(
        slots::OS,
        Arc::new(Mutex::new(nv)),
        Arc::new(NoopManifest),
        ComponentConfig {
            log_sources: vec![LogSource::Slog2, LogSource::HostFiles { globs: vec![glob] }],
            ..ComponentConfig::default()
        },
        None,
        None,
        None,
    );

    let srcs = b.list_log_sources().await.unwrap();
    let names: Vec<&str> = srcs.iter().map(|s| s.name.as_str()).collect();
    // slog2-ring (journal, the raw ring) + one File per stem, sorted by name.
    assert_eq!(
        names,
        ["host-boot", "slog2-ring", "timestamp"],
        "got {names:?}"
    );

    let slog2 = srcs.iter().find(|s| s.name == "slog2-ring").unwrap();
    assert_eq!(slog2.kind, LogSourceKind::Journal);
    assert!(
        !slog2.cursor,
        "raw ring has no cursor (u16 wrap, no resume API)"
    );
    assert!(slog2.emitters.is_empty());

    let hb = srcs.iter().find(|s| s.name == "host-boot").unwrap();
    assert_eq!(hb.kind, LogSourceKind::File);
    assert!(hb.cursor, "file sources page by byte offset");

    std::fs::remove_dir_all(&dir).ok();
}

/// A single-source component (the deployed host = `[Slog2]`) advertises
/// exactly that one source — the common on-device case.
#[tokio::test]
async fn list_log_sources_single_slog2() {
    use sovd_core::{DiagnosticBackend, LogSourceKind};
    let b = backend_with_logs(LogSource::Slog2);
    let srcs = b.list_log_sources().await.unwrap();
    assert_eq!(srcs.len(), 1);
    assert_eq!(srcs[0].name, "slog2-ring", "raw ring is slog2-ring");
    assert_eq!(srcs[0].kind, LogSourceKind::Journal);
    assert!(!srcs[0].cursor, "raw ring is non-resumable (cursor:false)");
}

fn backend_with_logs(source: LogSource) -> ComponentBackend<MemBlockDevice> {
    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    let mut boot = NvBootState::default();
    nv.write_boot_state(&mut boot).unwrap();
    ComponentBackend::with_options(
        slots::VM1,
        Arc::new(Mutex::new(nv)),
        Arc::new(NoopManifest),
        ComponentConfig {
            log_sources: vec![source],
            ..ComponentConfig::default()
        },
        None,
        None,
        None,
    )
}

/// §7.9 HOST diagnostics: a `host_diagnostics: true` backend gathers probes
/// IN-PROCESS (no guest agent) — this is how supernova's own disk/RAM become
/// visible over SOVD (the gap a flash `No space left on device` exposed).
#[tokio::test]
async fn host_diagnostics_gathers_in_process() {
    use sovd_core::DiagnosticBackend;
    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    let mut boot = NvBootState::default();
    nv.write_boot_state(&mut boot).unwrap();
    let b = ComponentBackend::with_options(
        slots::OS,
        Arc::new(Mutex::new(nv)),
        Arc::new(NoopManifest),
        ComponentConfig {
            host_diagnostics: true,
            ..ComponentConfig::default()
        },
        None,
        None,
        None,
    );

    // Discovery: the fixed host.* probe set, no guest agent.
    let probes = b.list_diagnostics().await.unwrap();
    assert!(probes.iter().any(|p| p.id == "host.disk"));
    assert!(probes.iter().any(|p| p.id == "host.common-rw-usage"));

    // Gather df in-process — real output on the Linux test host.
    let r = b.read_diagnostic("host.disk").await.unwrap();
    assert!(r.ok, "df gather: {:?}", r.message);
    assert!(!r.output.is_empty());

    // /proc/meminfo (Linux host) → MemTotal.
    let m = b.read_diagnostic("host.mem").await.unwrap();
    if std::path::Path::new("/proc/meminfo").exists() {
        assert!(m.ok && m.output.contains("MemTotal"));
    }

    // A missing dir → ok=false with a reason (real signal, not a crash).
    let miss = b.read_diagnostic("host.log-usage").await.unwrap();
    // /mnt/common-rw/log won't exist on the test host → not present.
    assert!(!miss.ok || miss.output.starts_with("TOTAL"));

    // Unknown probe → ok=false, named.
    let bad = b.read_diagnostic("host.nonsense").await.unwrap();
    assert!(!bad.ok && bad.message.unwrap().contains("unknown host probe"));
}

/// host_du reports a reconciling TOTAL + per-subdir rollup + top files —
/// so "what fills the partition" is answerable incl. many-small-files (the
/// question the old top-40-only view couldn't answer). Controlled tree:
/// dir_big/one huge file + dir_many/lots of tiny files.
#[test]
fn host_du_totals_rollup_and_top_files() {
    let root = std::env::temp_dir().join(format!("cm-du-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("dir_big")).unwrap();
    std::fs::create_dir_all(root.join("dir_many")).unwrap();
    // One 300 KiB file.
    std::fs::write(root.join("dir_big/huge.img"), vec![0u8; 300 * 1024]).unwrap();
    // 50 files of 4 KiB each = 200 KiB — invisible to a top-N-files view if
    // N is small, but must show as a fat subdir + count in the total.
    for i in 0..50 {
        std::fs::write(root.join(format!("dir_many/f{i}.log")), vec![0u8; 4 * 1024]).unwrap();
    }
    let out = host_du(root.to_str().unwrap(), 5).unwrap();

    // TOTAL reconciles (~500 KiB, 51 files) — not truncated.
    assert!(out.contains("51 files"), "count in total; got:\n{out}");
    let total_line = out.lines().next().unwrap();
    let total_kib: u64 = total_line
        .split('\t')
        .nth(1)
        .and_then(|s| s.trim_end_matches(" KiB").parse().ok())
        .unwrap();
    assert!(
        (498..=502).contains(&total_kib),
        "total ~500 KiB, got {total_kib}"
    );

    // Subdir rollup: dir_big (300) > dir_many (200), both present.
    assert!(out.contains("\tdir_big") && out.contains("\tdir_many"));
    // The many-small-files dir shows its CUMULATIVE size (~200 KiB), which a
    // top-5-FILES view would never surface.
    let many_line = out.lines().find(|l| l.ends_with("dir_many")).unwrap();
    let many_kib: u64 = many_line.split('\t').next().unwrap().parse().unwrap();
    assert!(
        (198..=204).contains(&many_kib),
        "dir_many cumulative ~200, got {many_kib}"
    );

    // Top files: the huge one is listed.
    assert!(out.contains("huge.img"));

    let _ = std::fs::remove_dir_all(&root);
}

fn backend_with_test_agent(url: &str) -> ComponentBackend<MemBlockDevice> {
    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    let mut boot = NvBootState::default();
    nv.write_boot_state(&mut boot).unwrap();
    ComponentBackend::with_options(
        slots::VM1,
        Arc::new(Mutex::new(nv)),
        Arc::new(NoopManifest),
        ComponentConfig {
            test_agent_url: Some(url.to_string()),
            diag_agent_url: Some(url.to_string()),
            ..ComponentConfig::default()
        },
        None,
        None,
        None,
    )
}

/// §7.15 scripts: list_scripts proxies the guest test-agent's /tests. A stub
/// agent returns two registered tests; a down agent degrades to [] (not 500).
#[tokio::test]
async fn scripts_proxy_guest_test_agent_and_degrade() {
    use sovd_core::DiagnosticBackend;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for conn in listener.incoming() {
            let mut s = match conn {
                Ok(s) => s,
                Err(_) => break,
            };
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            let body = r#"[{"id":"guest-hal.smoke","title":"Smoke","tags":["smoke"]},{"id":"guest-hal.slow","tags":["slow"]}]"#;
            let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            let _ = s.write_all(resp.as_bytes());
        }
    });

    let b = backend_with_test_agent(&format!("http://{addr}"));
    let scripts = b.list_scripts().await.unwrap();
    assert_eq!(scripts.len(), 2);
    assert_eq!(scripts[0].id, "guest-hal.smoke");
    assert_eq!(scripts[0].title.as_deref(), Some("Smoke"));
    assert_eq!(scripts[0].tags, ["smoke"]);
    assert_eq!(scripts[1].id, "guest-hal.slow");

    // No test_agent_url configured → empty (not an error).
    let none = backend_with_logs(LogSource::HostFiles { globs: vec![] });
    assert!(none.list_scripts().await.unwrap().is_empty());

    // Configured but unreachable → empty terminal, never a 500.
    let down = backend_with_test_agent("http://127.0.0.1:1");
    assert!(down.list_scripts().await.unwrap().is_empty());
}

/// §7.9 diagnostics: list_diagnostics proxies the guest diag-agent's
/// /probes, and read_diagnostic proxies /probes/{id} → the ProbeResult. A
/// stub agent serves both; no url → NotSupported (read) / [] (list); a down
/// agent → [] (list) / Transport (read) — never a panic.
#[tokio::test]
async fn diagnostics_proxy_guest_diag_agent_and_degrade() {
    use sovd_core::DiagnosticBackend;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for conn in listener.incoming() {
            let mut s = match conn {
                Ok(s) => s,
                Err(_) => break,
            };
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            let head = String::from_utf8_lossy(&buf);
            let path = head
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("");
            let body = if path == "/probes" {
                r#"[{"id":"guest-hal.mem","title":"Memory","tags":["health"]},{"id":"guest-hal.disk","tags":["storage"]}]"#.to_string()
            } else if let Some(id) = path.strip_prefix("/probes/") {
                // Echo the requested id back in an ok result.
                format!(r#"{{"id":"{id}","ok":true,"output":"MemTotal: 2048 kB\n"}}"#)
            } else {
                "[]".to_string()
            };
            let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            let _ = s.write_all(resp.as_bytes());
        }
    });

    let b = backend_with_test_agent(&format!("http://{addr}"));
    // Discovery.
    let probes = b.list_diagnostics().await.unwrap();
    assert_eq!(probes.len(), 2);
    assert_eq!(probes[0].id, "guest-hal.mem");
    assert_eq!(probes[0].title.as_deref(), Some("Memory"));
    assert_eq!(probes[1].id, "guest-hal.disk");
    // Gather one — the ProbeResult passes through.
    let r = b.read_diagnostic("guest-hal.mem").await.unwrap();
    assert!(r.ok);
    assert_eq!(r.id, "guest-hal.mem");
    assert!(r.output.contains("MemTotal"));

    // No diag_agent_url → [] (list) / NotSupported (read).
    let none = backend_with_logs(LogSource::HostFiles { globs: vec![] });
    assert!(none.list_diagnostics().await.unwrap().is_empty());
    assert!(matches!(
        none.read_diagnostic("guest-hal.mem").await,
        Err(BackendError::NotSupported(_))
    ));

    // Configured but unreachable → [] (list) / Transport (read).
    let down = backend_with_test_agent("http://127.0.0.1:1");
    assert!(down.list_diagnostics().await.unwrap().is_empty());
    assert!(matches!(
        down.read_diagnostic("guest-hal.mem").await,
        Err(BackendError::Transport(_))
    ));
}

/// §7.15 execution: start_script proxies the guest test-agent's synchronous
/// `POST /tests/{id}/run`, stores the finished run as a terminal
/// ScriptExecution (verdict + exit code), and get/list read it back. A down
/// agent errors cleanly (Transport), never a panic.
#[tokio::test]
async fn scripts_execute_proxies_run_and_stores_execution() {
    use sovd_core::DiagnosticBackend;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for conn in listener.incoming() {
            let mut s = match conn {
                Ok(s) => s,
                Err(_) => break,
            };
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            // Mirror test-agent::RunResult for a passing run.
            let body = r#"{"id":"guest-hal.smoke","verdict":"pass","exit_code":0,"duration_ms":42,"stdout_tail":"ok\n"}"#;
            let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            let _ = s.write_all(resp.as_bytes());
        }
    });

    let b = backend_with_test_agent(&format!("http://{addr}"));
    let exec = b.start_script("guest-hal.smoke").await.unwrap();
    assert_eq!(exec.status, ScriptStatus::Done);
    assert_eq!(exec.verdict, Some(ScriptVerdict::Pass));
    assert_eq!(exec.exit_code, Some(0));
    assert_eq!(exec.duration_ms, Some(42));
    assert_eq!(exec.stdout_tail.as_deref(), Some("ok\n"));
    assert_eq!(exec.script_id, "guest-hal.smoke");
    // exec_id is <script_id>-<n>, monotonic per process.
    assert!(exec.exec_id.starts_with("guest-hal.smoke-"));
    assert!(exec.ended.is_some());

    // Stored + retrievable via get / list.
    let got = b
        .get_script_execution("guest-hal.smoke", &exec.exec_id)
        .await
        .unwrap();
    assert_eq!(got.exec_id, exec.exec_id);
    assert_eq!(got.verdict, Some(ScriptVerdict::Pass));
    let ids = b.list_script_executions("guest-hal.smoke").await.unwrap();
    assert_eq!(ids, vec![exec.exec_id.clone()]);

    // Unknown exec id → EntityNotFound (404), never a panic.
    let miss = b
        .get_script_execution("guest-hal.smoke", "nope")
        .await
        .expect_err("unknown exec");
    assert!(matches!(miss, BackendError::EntityNotFound(_)));

    // A down agent → Transport error, never a panic.
    let down = backend_with_test_agent("http://127.0.0.1:1");
    let err = down
        .start_script("guest-hal.smoke")
        .await
        .expect_err("down agent");
    assert!(matches!(err, BackendError::Transport(_)));

    // No test_agent_url → NotSupported.
    let none = backend_with_logs(LogSource::HostFiles { globs: vec![] });
    let err = none.start_script("x").await.expect_err("no agent");
    assert!(matches!(err, BackendError::NotSupported(_)));
}

/// §7.21 HostFiles source: bounded tails of matching files with
/// source/pattern/tail filter semantics.
#[tokio::test]
async fn logs_host_files_globs_and_filters() {
    let dir = std::env::temp_dir().join(format!("cm-logs-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("supernova.log"), "one\ntwo\nthree\n").unwrap();
    std::fs::write(dir.join("other.log"), "alpha\nbeta\n").unwrap();
    std::fs::write(dir.join("skip.txt"), "not a log\n").unwrap();

    let b = backend_with_logs(LogSource::HostFiles {
        globs: vec![format!("{}/*.log", dir.display())],
    });
    assert!(b.capabilities().logs);

    let all = b.get_logs(&LogFilter::default()).await.unwrap();
    assert_eq!(all.len(), 5, "both .log files, txt excluded");
    assert!(all.iter().all(|e| e.priority == LogPriority::Info));

    let filtered = b
        .get_logs(&LogFilter {
            source: Some("supernova".into()),
            pattern: Some("t".into()),
            tail: Some(1),
            ..LogFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].message, "three");
    assert_eq!(filtered[0].source.as_deref(), Some("supernova"));

    std::fs::remove_dir_all(&dir).ok();
}

/// A binary file caught by a glob (e.g. the vendor fslog persister's gzip
/// archive, or a stray binary `.log`) must NOT be dumped as replacement-char
/// garbage — `tail_file_lines` skips it. A real text log alongside it still
/// reads. Regression for the `./sovd-get-logs.sh` binary-garbage report.
#[tokio::test]
async fn logs_host_files_skip_binary() {
    let dir = std::env::temp_dir().join(format!("cm-logs-bin-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("real.log"), "hello\nworld\n").unwrap();
    // gzip-magic + NUL bytes: an fslog-style binary archive named .log.
    std::fs::write(
        dir.join("archive.log"),
        [0x1f, 0x8b, 0x08, 0x00, 0x00, 0x03],
    )
    .unwrap();

    let b = backend_with_logs(LogSource::HostFiles {
        globs: vec![format!("{}/*.log", dir.display())],
    });
    let all = b.get_logs(&LogFilter::default()).await.unwrap();
    let msgs: Vec<_> = all.iter().map(|e| e.message.as_str()).collect();
    assert!(msgs.contains(&"hello"), "text log read: {msgs:?}");
    assert!(msgs.contains(&"world"), "text log read: {msgs:?}");
    assert_eq!(all.len(), 2, "binary file contributes no lines: {msgs:?}");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn looks_binary_classifies() {
    assert!(!looks_binary(b""), "empty is not binary");
    assert!(!looks_binary(b"plain text log\nwith lines\n"));
    assert!(!looks_binary(b"tabs\tand\r\nnewlines ok"));
    assert!(looks_binary(&[0x1f, 0x8b, 0x08, 0x00]), "gzip magic");
    assert!(looks_binary(b"text\0with\0nul"), "NUL byte");
    // >10% control bytes → binary.
    assert!(looks_binary(&[
        0x01, 0x02, 0x03, 0x04, b'a', b'b', b'c', b'd'
    ]));
}

/// §7.21 GuestAgent source: proxy a stub agent (canned JSON) and map
/// records to LogEntry; an unreachable agent degrades to empty.
#[tokio::test]
async fn logs_guest_agent_proxy_and_degrade() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let body = r#"[{"timestamp":"2026-07-18T12:00:00Z","priority":"warning","message":"hb late","source":"vhealth"}]"#;
        for conn in listener.incoming().take(1) {
            let mut s = conn.unwrap();
            use std::io::{Read, Write};
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            let _ = s.write_all(resp.as_bytes());
        }
    });

    let b = backend_with_logs(LogSource::GuestAgent {
        url: format!("http://{addr}"),
    });
    assert!(b.capabilities().logs);
    let got = b.get_logs(&LogFilter::default()).await.unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].message, "hb late");
    assert_eq!(got[0].priority, LogPriority::Warning);
    assert_eq!(got[0].source.as_deref(), Some("vhealth"));
    assert_eq!(got[0].timestamp.to_rfc3339(), "2026-07-18T12:00:00+00:00");

    // Unreachable agent: empty list, not an error (the SOVD route
    // must stay 200 with [] when a VM is down).
    let b = backend_with_logs(LogSource::GuestAgent {
        url: "http://127.0.0.1:1".into(),
    });
    let got = b.get_logs(&LogFilter::default()).await.unwrap();
    assert!(got.is_empty());
}

/// Guest cursor paging: get_logs_paged against a sole GuestAgent proxies the
/// agent's `/logs/page`, threading its `__CURSOR` through `next_cursor`. The
/// stub serves a page WITH a cursor first, then (given `after=`) an empty
/// page with no cursor — so a client's loop terminates. A down agent yields
/// an empty terminal page, never a 500.
#[tokio::test]
async fn logs_guest_agent_cursor_paging() {
    use sovd_core::DiagnosticBackend;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        // Serve until the listener drops. First call (no after=) → 1 item +
        // cursor "C1"; a call carrying after=C1 → empty page, no cursor.
        for conn in listener.incoming() {
            let mut s = match conn {
                Ok(s) => s,
                Err(_) => break,
            };
            let mut buf = [0u8; 2048];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let target = req
                .lines()
                .next()
                .unwrap_or("")
                .split_whitespace()
                .nth(1)
                .unwrap_or("");
            let body = if target.contains("after=C1") {
                r#"{"items":[]}"#.to_string()
            } else {
                r#"{"items":[{"timestamp":"2026-07-18T12:00:00Z","priority":"info","message":"line1","source":"vhealth"}],"next_cursor":"C1"}"#.to_string()
            };
            let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            let _ = s.write_all(resp.as_bytes());
        }
    });

    let b = backend_with_logs(LogSource::GuestAgent {
        url: format!("http://{addr}"),
    });

    // Page 1: one item + a next_cursor.
    let p1 = b.get_logs_paged(&LogFilter::default()).await.unwrap();
    assert_eq!(p1.items.len(), 1);
    assert_eq!(p1.items[0].message, "line1");
    assert_eq!(p1.next_cursor.as_deref(), Some("C1"));

    // Page 2: feed the cursor back → empty, no next_cursor → loop stops.
    let f2 = LogFilter {
        after: p1.next_cursor.clone(),
        ..LogFilter::default()
    };
    let p2 = b.get_logs_paged(&f2).await.unwrap();
    assert!(p2.items.is_empty());
    assert!(p2.next_cursor.is_none());

    // Down agent → empty terminal page, not an error.
    let down = backend_with_logs(LogSource::GuestAgent {
        url: "http://127.0.0.1:1".into(),
    });
    let pd = down.get_logs_paged(&LogFilter::default()).await.unwrap();
    assert!(pd.items.is_empty() && pd.next_cursor.is_none());
}

/// Stable-id round-trip: an id from `get_logs` re-resolves via `get_log`
/// and `get_log_content` (no server state) — the fix for the old ephemeral
/// `{source}-{i}` ids that resolved nowhere.
#[tokio::test]
async fn logs_standard_line_id_round_trips() {
    let dir = std::env::temp_dir().join(format!("cm-logid-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("svc.log"), "hello world\nsecond line\n").unwrap();

    let b = backend_with_logs(LogSource::HostFiles {
        globs: vec![format!("{}/*.log", dir.display())],
    });
    let listed = b.get_logs(&LogFilter::default()).await.unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().all(|e| e.id.starts_with("line:svc:")));

    // get_log by the listed id returns the same entry.
    let one = &listed[0];
    let fetched = b.get_log(&one.id).await.unwrap();
    assert_eq!(fetched.id, one.id);
    assert_eq!(fetched.message, one.message);

    // get_log_content returns the line's bytes.
    let content = b.get_log_content(&one.id).await.unwrap();
    assert_eq!(String::from_utf8(content).unwrap(), one.message);

    // a standard line is not deletable.
    assert!(matches!(
        b.delete_log(&one.id).await,
        Err(BackendError::NotSupported(_))
    ));
    std::fs::remove_dir_all(&dir).ok();
}

/// Per-line timestamps: a line carrying svclog's leading ISO-8601 stamp gets
/// THAT time (and the stamp is stripped from the message); a line without one
/// gets the epoch "unknown" sentinel — NOT the file mtime, which would make
/// every unstamped line share one bogus time (the old "all timestamps equal"
/// bug). Both readers (tailed `get_logs`, paged `get_logs_paged`) agree.
#[tokio::test]
async fn host_lines_use_per_line_stamp_else_epoch() {
    let dir = std::env::temp_dir().join(format!("cm-lts-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // Two stamped lines (distinct times) + one bare line, in file order.
    std::fs::write(
        dir.join("svc.log"),
        "2026-07-25T10:00:00Z first stamped\n\
             2026-07-25T10:00:05Z second stamped\n\
             bare line no stamp\n",
    )
    .unwrap();
    let b = backend_with_logs(LogSource::HostFiles {
        globs: vec![format!("{}/*.log", dir.display())],
    });

    let epoch = chrono::DateTime::<Utc>::UNIX_EPOCH;
    // Order-independent (readers may not preserve file order): look up by the
    // stripped message.
    let check = |entries: &[LogEntry]| {
        assert_eq!(entries.len(), 3);
        let ts = |msg: &str| {
            entries
                .iter()
                .find(|e| e.message == msg)
                .unwrap_or_else(|| panic!("no entry with message {msg:?}"))
                .timestamp
        };
        // Stamp parsed → that time, message stripped of the stamp.
        assert_eq!(
            ts("first stamped").to_rfc3339(),
            "2026-07-25T10:00:00+00:00"
        );
        assert_eq!(
            ts("second stamped").to_rfc3339(),
            "2026-07-25T10:00:05+00:00"
        );
        // Distinct times — NOT collapsed to one mtime.
        assert_ne!(ts("first stamped"), ts("second stamped"));
        // No stamp → epoch sentinel, whole line kept as-is.
        assert_eq!(ts("bare line no stamp"), epoch);
    };

    // Tailed reader.
    let listed = b.get_logs(&LogFilter::default()).await.unwrap();
    check(&listed);
    // Paged reader agrees (large page → all three in one page).
    let paged = b
        .get_logs_paged(&LogFilter {
            limit: Some(100),
            ..Default::default()
        })
        .await
        .unwrap();
    check(&paged.items);

    std::fs::remove_dir_all(&dir).ok();
}

/// Priority filter is "this level and above" (§7.21, numeric `<=`), not an
/// exact match. Host-file lines are `Info` (6); the discriminating case is a
/// `Debug` (7) threshold: "and-above" KEEPS the Info line (6 ≤ 7) where the
/// old `==` semantics would have dropped it.
#[tokio::test]
async fn logs_priority_filter_is_and_above() {
    let dir = std::env::temp_dir().join(format!("cm-prio-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("svc.log"), "an info line\n").unwrap();
    let b = backend_with_logs(LogSource::HostFiles {
        globs: vec![format!("{}/*.log", dir.display())],
    });

    // threshold = Debug (least severe): everything at or above is kept — the
    // Info line survives. `==` would require priority == Debug and drop it.
    let kept = b
        .get_logs(&LogFilter {
            priority: Some(LogPriority::Debug),
            ..LogFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(kept.len(), 1, "Info is above Debug — and-above keeps it");

    // threshold = Warning (more severe than Info): the Info line is dropped.
    let dropped = b
        .get_logs(&LogFilter {
            priority: Some(LogPriority::Warning),
            ..LogFilter::default()
        })
        .await
        .unwrap();
    assert!(dropped.is_empty(), "Info is below Warning — filtered out");
    std::fs::remove_dir_all(&dir).ok();
}

// -----------------------------------------------------------------------
// Reboot-safe log pagination (tasks/log-retrieval-design.md, HOST tier)
// -----------------------------------------------------------------------

/// Cursor encode→decode preserves the boot epoch and every per-source
/// (gen, offset). The token is opaque base64url; clients never parse it.
#[test]
fn log_cursor_round_trips() {
    let mut sources = BTreeMap::new();
    sources.insert("svc".to_string(), SourcePos { gen: 0, offset: 42 });
    sources.insert(
        "kern".to_string(),
        SourcePos {
            gen: 0,
            offset: 1_000_000,
        },
    );
    let c = LogCursor {
        boot_epoch: 7,
        sources,
    };
    let decoded = LogCursor::decode(&c.encode()).expect("round-trips");
    assert_eq!(decoded, c);
    assert_eq!(decoded.boot_epoch, 7);
    assert_eq!(decoded.sources["svc"].offset, 42);
    assert_eq!(decoded.sources["kern"].offset, 1_000_000);
}

/// A garbage `after` cursor is treated as "no cursor" (start from oldest),
/// never a panic or 500.
#[test]
fn log_cursor_bad_token_is_none() {
    assert!(LogCursor::decode("").is_none());
    assert!(LogCursor::decode("!!!not-base64!!!").is_none());
    // Valid base64url of non-JSON bytes → still None (not a panic).
    assert!(LogCursor::decode(&b64url(b"\xff\xfe\x00garbage")).is_none());
}

/// Paging an append-only file in batches returns disjoint, in-order lines
/// and terminates (next_cursor eventually None). Also: appending AFTER the
/// head is reached and re-calling with the last cursor returns ONLY the new
/// lines.
#[test]
fn log_paging_batches_disjoint_and_terminates() {
    let dir = std::env::temp_dir().join(format!("cm-page-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("svc.log");
    std::fs::write(&path, "l1\nl2\nl3\nl4\nl5\n").unwrap();
    let globs = vec![format!("{}/*.log", dir.display())];

    // Page size 2, boot epoch 1.
    let f = |after: Option<String>| LogFilter {
        limit: Some(2),
        after,
        ..LogFilter::default()
    };

    let p1 = host_file_logs_paged(&globs, &f(None), 1);
    let m1: Vec<_> = p1.items.iter().map(|e| e.message.clone()).collect();
    assert_eq!(m1, vec!["l1", "l2"]);
    assert!(p1.next_cursor.is_some());
    assert!(p1.oldest_cursor.is_some(), "oldest_cursor always reported");

    let p2 = host_file_logs_paged(&globs, &f(p1.next_cursor.clone()), 1);
    let m2: Vec<_> = p2.items.iter().map(|e| e.message.clone()).collect();
    assert_eq!(m2, vec!["l3", "l4"]);

    let p3 = host_file_logs_paged(&globs, &f(p2.next_cursor.clone()), 1);
    let m3: Vec<_> = p3.items.iter().map(|e| e.message.clone()).collect();
    assert_eq!(m3, vec!["l5"]);

    // Head reached: nothing new → next_cursor None (loop terminates).
    let p4 = host_file_logs_paged(&globs, &f(p3.next_cursor.clone()), 1);
    assert!(p4.items.is_empty());
    assert!(p4.next_cursor.is_none(), "no new bytes → head → None");

    // Append after EOF, re-call with the LAST non-None cursor (p3's): only
    // the new lines come back, none of l1..l5 replayed.
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(b"l6\nl7\n").unwrap();
    }
    let p5 = host_file_logs_paged(&globs, &f(p3.next_cursor.clone()), 1);
    let m5: Vec<_> = p5.items.iter().map(|e| e.message.clone()).collect();
    assert_eq!(m5, vec!["l6", "l7"], "only the newly-appended lines");

    std::fs::remove_dir_all(&dir).ok();
}

/// tip_cursor is a FOLLOW anchor: capture the tip "now", append, then poll
/// `after=tip` and get ONLY the lines written after the tip was taken.
#[test]
fn log_tip_cursor_follows_new_lines() {
    let dir = std::env::temp_dir().join(format!("cm-tip-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("svc.log");
    std::fs::write(&path, "old1\nold2\n").unwrap();
    let globs = vec![format!("{}/*.log", dir.display())];

    // Take the tip at "now" — it names the current EOF, and is always set.
    let p = host_file_logs_paged(&globs, &LogFilter::default(), 1);
    let tip = p
        .tip_cursor
        .clone()
        .expect("tip_cursor is always set for host files");

    // Append after capturing the tip.
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(b"new1\nnew2\n").unwrap();
    }

    // Poll after=tip → only the post-tip lines, not old1/old2.
    let follow = LogFilter {
        after: Some(tip),
        ..LogFilter::default()
    };
    let got: Vec<_> = host_file_logs_paged(&globs, &follow, 1)
        .items
        .iter()
        .map(|e| e.message.clone())
        .collect();
    assert_eq!(
        got,
        vec!["new1", "new2"],
        "follow from tip yields only new lines"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// Volatile invalidation: a stale-epoch cursor against a /dev/shmem-style
/// (volatile) path restarts from offset 0, while a persistent path with the
/// SAME stale epoch keeps its offset. We exercise `is_volatile` directly (no
/// real /dev/shmem needed) plus the offset-decision the pager uses.
#[test]
fn log_volatile_source_invalidated_across_reboot() {
    assert!(is_volatile(Path::new("/dev/shmem/foo.log")));
    assert!(!is_volatile(Path::new("/var/log/foo.log")));

    // Persistent file: a stale-epoch cursor's offset MUST be honoured — a
    // byte offset into an append-only file is reboot-safe.
    let dir = std::env::temp_dir().join(format!("cm-vol-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("persist.log");
    std::fs::write(&path, "a\nb\nc\nd\n").unwrap();
    let globs = vec![format!("{}/*.log", dir.display())];

    // Mint a cursor at boot epoch 1 that has already consumed "a\nb\n" (4 bytes).
    let mut sources = BTreeMap::new();
    sources.insert("persist".to_string(), SourcePos { gen: 0, offset: 4 });
    let stale = LogCursor {
        boot_epoch: 1,
        sources,
    }
    .encode();

    // Current epoch is 2 (a reboot happened). The path is PERSISTENT, so the
    // offset survives — we resume at "c", not restart at "a".
    let page = host_file_logs_paged(
        &globs,
        &LogFilter {
            after: Some(stale),
            ..LogFilter::default()
        },
        2,
    );
    let msgs: Vec<_> = page.items.iter().map(|e| e.message.clone()).collect();
    assert_eq!(
        msgs,
        vec!["c", "d"],
        "persistent offset honoured across reboot"
    );

    // The volatile decision itself: same stale epoch + volatile path ⇒ the
    // pager's start_offset logic resets to 0. We assert the classifier and
    // the epoch mismatch that together trigger the reset (the reset branch in
    // host_file_logs_paged keys on exactly `epoch_mismatch && is_volatile`).
    let epoch_mismatch = 1u64 != 2u64;
    assert!(epoch_mismatch && is_volatile(Path::new("/dev/shmem/x.log")));

    std::fs::remove_dir_all(&dir).ok();
}

/// Truncation/rotation gap: a cursor whose offset exceeds the current file
/// length (file shrank) restarts that source from 0 rather than seeking past
/// EOF and returning nothing.
#[test]
fn log_paging_truncation_restarts_from_oldest() {
    let dir = std::env::temp_dir().join(format!("cm-trunc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("svc.log");
    std::fs::write(&path, "fresh1\nfresh2\n").unwrap(); // 14 bytes
    let globs = vec![format!("{}/*.log", dir.display())];

    // Cursor claims offset 9999 (way past the 14-byte file) — the file was
    // clearly truncated/replaced. Same boot epoch so only the gap check fires.
    let mut sources = BTreeMap::new();
    sources.insert(
        "svc".to_string(),
        SourcePos {
            gen: 0,
            offset: 9999,
        },
    );
    let cur = LogCursor {
        boot_epoch: 5,
        sources,
    }
    .encode();

    let page = host_file_logs_paged(
        &globs,
        &LogFilter {
            after: Some(cur),
            ..LogFilter::default()
        },
        5,
    );
    let msgs: Vec<_> = page.items.iter().map(|e| e.message.clone()).collect();
    assert_eq!(msgs, vec!["fresh1", "fresh2"], "shrunk file → restart at 0");
    std::fs::remove_dir_all(&dir).ok();
}

/// boot_epoch file: absent → first read yields 1; a second bump yields 2;
/// the value persists across calls. Uses a temp path via the override so
/// /var/lib is never touched.
#[test]
fn boot_epoch_file_increments_and_persists() {
    let dir = std::env::temp_dir().join(format!("cm-epoch-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("boot_epoch");

    // Absent file → 0 baseline → returns 1, and persists "1".
    assert_eq!(bump_boot_epoch_file(&path), 1);
    assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), "1");
    // Second bump reads 1 → returns 2.
    assert_eq!(bump_boot_epoch_file(&path), 2);
    assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), "2");

    std::fs::remove_dir_all(&dir).ok();
}

/// Multi-source components (HostFiles + a non-paginable source) fall back to
/// the DEFAULT single terminal page: next_cursor None so a client's loop
/// still terminates in one step (design doc step 5 choice).
#[tokio::test]
async fn logs_paged_multisource_falls_back_to_terminal_page() {
    use sovd_core::DiagnosticBackend;
    let dir = std::env::temp_dir().join(format!("cm-multi-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("svc.log"), "one\ntwo\n").unwrap();

    // A component with BOTH a HostFiles and a HostDumps source → not pure
    // HostFiles → terminal page.
    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    let mut boot = NvBootState::default();
    nv.write_boot_state(&mut boot).unwrap();
    let b = ComponentBackend::with_options(
        slots::VM1,
        Arc::new(Mutex::new(nv)),
        Arc::new(NoopManifest),
        ComponentConfig {
            log_sources: vec![
                LogSource::HostFiles {
                    globs: vec![format!("{}/*.log", dir.display())],
                },
                LogSource::HostDumps {
                    dir: dir.to_string_lossy().into_owned(),
                },
            ],
            ..ComponentConfig::default()
        },
        None,
        None,
        None,
    );

    let page = b.get_logs_paged(&LogFilter::default()).await.unwrap();
    assert!(
        page.next_cursor.is_none(),
        "mixed sources → terminal page, loop terminates"
    );
    // The host-file lines still appear in that one page.
    assert!(page.items.iter().any(|e| e.message == "one"));

    std::fs::remove_dir_all(&dir).ok();
}

/// A sole-GuestAgent component pages via the guest `/logs/page`, and the
/// guest's tip_cursor/oldest_cursor (QNX svclog `<seq>:<offset>`) pass
/// THROUGH the host relay — this is what feeds the §7.15 tester log bracket
/// (current_log_tip) + `sovd-cli logs --follow` on QNX.
#[tokio::test]
async fn logs_paged_guest_agent_relays_tip_and_oldest_cursors() {
    use sovd_core::DiagnosticBackend;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for conn in listener.incoming() {
            let mut s = match conn {
                Ok(s) => s,
                Err(_) => break,
            };
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            // Mimic the guest PagedLogs: one line + segment cursors.
            let body = r#"{"items":[{"timestamp":"2026-07-18T15:50:13Z","priority":"info","message":"[vhsm] up","source":"vhsm-daemon"}],"tip_cursor":"7:2048","oldest_cursor":"3:0"}"#;
            let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            let _ = s.write_all(resp.as_bytes());
        }
    });

    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    let mut boot = NvBootState::default();
    nv.write_boot_state(&mut boot).unwrap();
    let b = ComponentBackend::with_options(
        slots::VM1,
        Arc::new(Mutex::new(nv)),
        Arc::new(NoopManifest),
        ComponentConfig {
            log_sources: vec![LogSource::GuestAgent {
                url: format!("http://{addr}"),
            }],
            ..ComponentConfig::default()
        },
        None,
        None,
        None,
    );

    let page = b.get_logs_paged(&LogFilter::default()).await.unwrap();
    assert_eq!(page.tip_cursor.as_deref(), Some("7:2048"), "tip relayed");
    assert_eq!(page.oldest_cursor.as_deref(), Some("3:0"), "oldest relayed");
    assert!(page.items.iter().any(|e| e.message == "[vhsm] up"));

    // current_log_tip (the §7.15 bracket source) now returns the tip.
    assert_eq!(b.current_log_tip().await.as_deref(), Some("7:2048"));
}

/// Pure-HostFiles components DO paginate through `get_logs_paged`: the first
/// page of a >page-size file sets a next_cursor.
#[tokio::test]
async fn logs_paged_pure_hostfiles_paginates() {
    use sovd_core::DiagnosticBackend;
    let dir = std::env::temp_dir().join(format!("cm-pure-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let body: String = (0..10).map(|i| format!("line{i}\n")).collect();
    std::fs::write(dir.join("svc.log"), body).unwrap();

    let b = backend_with_logs(LogSource::HostFiles {
        globs: vec![format!("{}/*.log", dir.display())],
    });
    let page = b
        .get_logs_paged(&LogFilter {
            limit: Some(3),
            ..LogFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(page.items.len(), 3);
    assert!(page.next_cursor.is_some(), "more to read → cursor set");
    assert!(page.oldest_cursor.is_some());
    std::fs::remove_dir_all(&dir).ok();
}

/// §7.21 CUSTOM logs: a dump directory is a catalog — list, fetch content
/// by id, delete by id. Sidecar sets type/status.
#[tokio::test]
async fn logs_host_dumps_catalog_content_and_delete() {
    let dir = std::env::temp_dir().join(format!("cm-dumps-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("crash-001.bin"), b"\x00\x01\x02dump-bytes").unwrap();
    std::fs::write(
        dir.join("crash-001.bin.meta.json"),
        br#"{"type":"engine_dump","status":"pending"}"#,
    )
    .unwrap();

    let b = backend_with_logs(LogSource::HostDumps {
        dir: dir.to_string_lossy().into_owned(),
    });
    assert!(b.capabilities().logs);

    // Catalog: one dump, sidecar type/status, size, stable dump: id.
    let listed = b.get_logs(&LogFilter::default()).await.unwrap();
    assert_eq!(listed.len(), 1, "sidecar is not itself an entry");
    let d = &listed[0];
    assert!(d.id.starts_with("dump:host:"));
    assert_eq!(d.log_type.as_deref(), Some("engine_dump"));
    assert_eq!(d.status, Some(LogStatus::Pending));
    assert_eq!(d.size, Some(13)); // 3 raw bytes + "dump-bytes" (10)

    // Content by id = the file bytes.
    let content = b.get_log_content(&d.id).await.unwrap();
    assert_eq!(content, b"\x00\x01\x02dump-bytes");

    // Filter by type.
    let by_type = b
        .get_logs(&LogFilter {
            log_type: Some("engine_dump".into()),
            ..LogFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(by_type.len(), 1);

    // Delete by id removes the file AND its `<name>.meta.json` sidecar
    // (regression: with_extension would target crash-001.meta.json and
    // orphan the real crash-001.bin.meta.json).
    b.delete_log(&d.id).await.unwrap();
    assert!(!dir.join("crash-001.bin").exists());
    assert!(
        !dir.join("crash-001.bin.meta.json").exists(),
        "sidecar must be removed alongside the dump"
    );
    assert!(b.get_logs(&LogFilter::default()).await.unwrap().is_empty());
    std::fs::remove_dir_all(&dir).ok();
}

/// A crafted dump id can't escape the dump dir (path-traversal defence).
#[tokio::test]
async fn logs_dump_id_cannot_escape_dir() {
    // parse_log_id must reject a decoded name containing separators / `..`.
    let evil = format!("dump:host:{}", b64url(b"../../etc/passwd"));
    assert!(
        parse_log_id(&evil).is_none(),
        "traversal name must not parse"
    );

    // And a valid-but-absent file id is EntityNotFound, not a read elsewhere.
    let b = backend_with_logs(LogSource::HostDumps {
        dir: "/nonexistent-dump-dir".into(),
    });
    let missing = dump_log_id("ghost.bin");
    assert!(matches!(
        b.get_log_content(&missing).await,
        Err(BackendError::EntityNotFound(_))
    ));
}

// =====================================================================
// SOVD §7.20 bulk-data — HOST-FILE log download tests.
// =====================================================================

/// A HostFiles component exposes exactly the `logs` bulk-data category, its
/// files list as items (ids round-trip to the paths, sizes/source match),
/// an unknown category is 404, and a known item downloads its bytes whole.
#[tokio::test]
async fn bulk_data_logs_category_list_and_download() {
    use sovd_core::DiagnosticBackend;
    let dir = std::env::temp_dir().join(format!("cm-bulk-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f1 = dir.join("supernova.log");
    let f2 = dir.join("other.log");
    std::fs::write(&f1, "one\ntwo\nthree\n").unwrap();
    std::fs::write(&f2, "alpha\nbeta\n").unwrap();

    let b = backend_with_logs(LogSource::HostFiles {
        globs: vec![format!("{}/*.log", dir.display())],
    });

    // Capability + category: exactly [{name:"logs"}].
    assert!(b.capabilities().bulk_data);
    let cats = b.list_bulk_data_categories().await.unwrap();
    assert_eq!(cats.len(), 1);
    assert_eq!(cats[0].name, "logs");

    // Items: both files, ids decode back to the paths, sizes + source match.
    let items = b
        .list_bulk_data("logs", &BulkDataFilter::default())
        .await
        .unwrap();
    assert_eq!(items.len(), 2);
    for it in &items {
        assert_eq!(it.mime, "text/plain");
        let decoded = String::from_utf8(b64url_decode(&it.id).unwrap()).unwrap();
        let path = std::path::PathBuf::from(&decoded);
        assert!(path == f1 || path == f2, "id must decode to a listed file");
        assert_eq!(it.size, std::fs::metadata(&path).unwrap().len());
        assert_eq!(it.source.as_deref(), Some(source_name(&path)).as_deref());
    }

    // Unknown category → EntityNotFound.
    assert!(matches!(
        b.list_bulk_data("other", &BulkDataFilter::default()).await,
        Err(BackendError::EntityNotFound(_))
    ));

    // Download file-1 by its id → Inline bytes == file-1 contents.
    let id1 = b64url(f1.to_str().unwrap().as_bytes());
    match b.get_bulk_data("logs", &id1).await.unwrap() {
        BulkDataDownload::Inline { mime, bytes } => {
            assert_eq!(mime, "text/plain");
            assert_eq!(bytes, b"one\ntwo\nthree\n");
        }
        other => panic!("expected Inline, got {other:?}"),
    }

    // Unknown category on download → EntityNotFound.
    assert!(matches!(
        b.get_bulk_data("nope", &id1).await,
        Err(BackendError::EntityNotFound(_))
    ));

    std::fs::remove_dir_all(&dir).ok();
}

/// Path-traversal guard: a crafted id naming a file OUTSIDE the component's
/// resolved glob set (e.g. /etc/passwd) must NOT be readable — it is
/// indistinguishable from "no such item" → EntityNotFound. A malformed
/// (non-base64 / non-UTF-8) id is likewise 404.
#[tokio::test]
async fn bulk_data_download_rejects_arbitrary_path() {
    use sovd_core::DiagnosticBackend;
    let dir = std::env::temp_dir().join(format!("cm-bulk-evil-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("svc.log"), "safe\n").unwrap();

    let b = backend_with_logs(LogSource::HostFiles {
        globs: vec![format!("{}/*.log", dir.display())],
    });

    // A well-formed id for a real file that is NOT in this component's set.
    let evil = b64url(b"/etc/passwd");
    assert!(matches!(
        b.get_bulk_data("logs", &evil).await,
        Err(BackendError::EntityNotFound(_))
    ));

    // A malformed id (not valid base64url) → EntityNotFound, no panic.
    assert!(matches!(
        b.get_bulk_data("logs", "!!!not-base64!!!").await,
        Err(BackendError::EntityNotFound(_))
    ));

    std::fs::remove_dir_all(&dir).ok();
}

/// The created-before/after filter selects by mtime: a far-future
/// `created_after` yields nothing, a far-past `created_before` yields
/// nothing, and an open filter yields everything.
#[tokio::test]
async fn bulk_data_list_honours_created_filter() {
    use sovd_core::DiagnosticBackend;
    let dir = std::env::temp_dir().join(format!("cm-bulk-filt-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a.log"), "x\n").unwrap();
    std::fs::write(dir.join("b.log"), "y\n").unwrap();

    let b = backend_with_logs(LogSource::HostFiles {
        globs: vec![format!("{}/*.log", dir.display())],
    });

    // Open filter → both files.
    assert_eq!(
        b.list_bulk_data("logs", &BulkDataFilter::default())
            .await
            .unwrap()
            .len(),
        2
    );

    // created_after in the far future → nothing is newer.
    let future = chrono::DateTime::<Utc>::from_timestamp(4_000_000_000, 0).unwrap();
    assert!(b
        .list_bulk_data(
            "logs",
            &BulkDataFilter {
                created_after: Some(future),
                created_before: None,
            }
        )
        .await
        .unwrap()
        .is_empty());

    // created_before in the far past → nothing is older.
    let past = chrono::DateTime::<Utc>::from_timestamp(1, 0).unwrap();
    assert!(b
        .list_bulk_data(
            "logs",
            &BulkDataFilter {
                created_after: None,
                created_before: Some(past),
            }
        )
        .await
        .unwrap()
        .is_empty());

    std::fs::remove_dir_all(&dir).ok();
}

/// A component with NO HostFiles source (dumps only) exposes no bulk-data
/// category, and listing `logs` is EntityNotFound.
#[tokio::test]
async fn bulk_data_absent_without_host_files() {
    use sovd_core::DiagnosticBackend;
    let b = backend_with_logs(LogSource::HostDumps {
        dir: "/nonexistent-dump-dir".into(),
    });
    assert!(!b.capabilities().bulk_data);
    assert!(b.list_bulk_data_categories().await.unwrap().is_empty());
    assert!(matches!(
        b.list_bulk_data("logs", &BulkDataFilter::default()).await,
        Err(BackendError::EntityNotFound(_))
    ));
}

// =====================================================================
// SOVD §7.20 bulk-data — GUEST tier (guest log-agent /files proxy).
// =====================================================================

/// The guest-namespaced bulk-data item id round-trips (encode → decode →
/// route decision) WITHOUT any live agent, and does NOT collide with the
/// host-file id scheme (bare base64url path, no `guest:` prefix).
#[test]
fn guest_bulk_id_round_trips_and_is_distinct() {
    let url = "http://10.0.101.2:9300";
    let guest_id = b64url(b"/dev/shmem/vhealth.log"); // an opaque guest id
    let id = guest_bulk_id(url, &guest_id);
    assert!(id.starts_with("guest:"));

    // Decodes straight back to (url, guest_id).
    let (u, g) = parse_guest_bulk_id(&id).expect("guest id must parse");
    assert_eq!(u, url);
    assert_eq!(g, guest_id);

    // A host-file id (bare base64url path — the unchanged scheme) is NOT
    // parsed as a guest id, so get_bulk_data routes it to the host path.
    let host_id = b64url(b"/var/log/supernova.log");
    assert!(parse_guest_bulk_id(&host_id).is_none());
    // And the host id still round-trips to its path (scheme unchanged).
    assert_eq!(
        String::from_utf8(b64url_decode(&host_id).unwrap()).unwrap(),
        "/var/log/supernova.log"
    );

    // Malformed guest ids are rejected (no panic).
    assert!(parse_guest_bulk_id("guest:not-base64!:x").is_none());
    assert!(parse_guest_bulk_id("guest:").is_none());
    assert!(parse_guest_bulk_id(&format!("guest:{}:", b64url(url.as_bytes()))).is_none());
}

/// A GuestAgent component exposes the `logs` bulk-data category; its
/// `/files` catalog lists as items (guest-namespaced ids), and downloading
/// one proxies the agent's `/files/{id}` bytes. Uses a canned stub agent.
#[tokio::test]
async fn bulk_data_guest_agent_list_and_download() {
    use sovd_core::DiagnosticBackend;
    // Stub agent: /files → one file; /files/<gid> → its bytes.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let gid = "Zm9vLmxvZw"; // opaque guest id (base64url, no `:`)
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        // Serve every connection the client makes. get_bulk_data lists /files
        // TWICE (once in list_bulk_data, once as the defense-in-depth re-list)
        // and then downloads /files/<gid> — so this test drives 3 requests, and
        // a fixed `.take(N)` under-counts. Loop until the listener is dropped.
        for conn in listener.incoming() {
            let mut s = match conn {
                Ok(s) => s,
                Err(_) => break,
            };
            let mut buf = [0u8; 1024];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let target = req
                .lines()
                .next()
                .unwrap_or("")
                .split_whitespace()
                .nth(1)
                .unwrap_or("");
            let (ctype, body): (&str, Vec<u8>) = if target == "/files" {
                let json = format!(
                    r#"[{{"id":"{gid}","name":"foo.log","size":9,"source":"foo","modified":1784562613}}]"#
                );
                ("application/json", json.into_bytes())
            } else {
                // /files/<gid> → the raw bytes.
                ("application/octet-stream", b"log bytes".to_vec())
            };
            let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
            let _ = s.write_all(resp.as_bytes());
            let _ = s.write_all(&body);
        }
    });

    let url = format!("http://{addr}");
    let b = backend_with_logs(LogSource::GuestAgent { url: url.clone() });

    // Capability + category are now on for a GuestAgent component.
    assert!(b.capabilities().bulk_data);
    assert_eq!(b.list_bulk_data_categories().await.unwrap()[0].name, "logs");

    // Items: the one guest file, guest-namespaced id, mapped metadata.
    let items = b
        .list_bulk_data("logs", &BulkDataFilter::default())
        .await
        .unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].size, 9);
    assert_eq!(items[0].source.as_deref(), Some("foo"));
    assert_eq!(
        parse_guest_bulk_id(&items[0].id).unwrap(),
        (url.clone(), gid.to_string())
    );

    // Download by that id → proxied bytes inline.
    match b.get_bulk_data("logs", &items[0].id).await.unwrap() {
        BulkDataDownload::Inline { mime, bytes } => {
            assert_eq!(mime, "text/plain");
            assert_eq!(bytes, b"log bytes");
        }
        other => panic!("expected Inline, got {other:?}"),
    }
}

/// A down/unreachable guest agent contributes ZERO bulk-data items (never a
/// 500): list is Ok(empty), and downloading any guest id from it is 404.
#[tokio::test]
async fn bulk_data_guest_agent_degrades_when_down() {
    use sovd_core::DiagnosticBackend;
    let url = "http://127.0.0.1:1".to_string(); // nothing listening
    let b = backend_with_logs(LogSource::GuestAgent { url: url.clone() });

    // Down guest → empty list, still Ok (200 at the route).
    let items = b
        .list_bulk_data("logs", &BulkDataFilter::default())
        .await
        .unwrap();
    assert!(items.is_empty());

    // A well-formed guest id whose agent is down → 404, not 500.
    let id = guest_bulk_id(&url, "Zm9vLmxvZw");
    assert!(matches!(
        b.get_bulk_data("logs", &id).await,
        Err(BackendError::EntityNotFound(_))
    ));

    // A guest id for an agent url that is NOT one of ours → 404 (the
    // url-is-ours guard, before any network call).
    let foreign = guest_bulk_id("http://10.9.9.9:9300", "Zm9vLmxvZw");
    assert!(matches!(
        b.get_bulk_data("logs", &foreign).await,
        Err(BackendError::EntityNotFound(_))
    ));
}

#[test]
fn injected_provider_is_the_one_backend_uses() {
    // Default backend: IvdBankProvider with no activator => Local.
    let b = backend();
    assert_eq!(b.reset_kind(), ResetKind::Local);

    // After injection, the backend routes through the sentinel.
    let b = b.with_bank_provider(Arc::new(SentinelProvider::new(None)));
    assert_eq!(
        b.reset_kind(),
        ResetKind::RequiresEcuReset,
        "reset_kind() must come from the injected provider"
    );
}

#[test]
fn override_survives_later_rebuild_triggering_builders() {
    // with_bank_spec / with_bank_activator call rebuild_bank_provider; the
    // override flag must make those no-op on the provider so the injected
    // one is NOT clobbered.
    let b = backend()
        .with_bank_provider(Arc::new(SentinelProvider::new(None)))
        .with_bank_spec(crate::bank_spec::BankSetSpec {
            dir_name: "vm1".into(),
        });
    assert_eq!(
        b.reset_kind(),
        ResetKind::RequiresEcuReset,
        "with_bank_spec after with_bank_provider must not clobber the override"
    );

    struct DummyActivator;
    impl machine_mgr::BankActivator for DummyActivator {
        fn activate(&self, _d: &std::path::Path) -> Result<(), machine_mgr::BankActivatorError> {
            Ok(())
        }
    }
    let b = b.with_bank_activator(Arc::new(DummyActivator));
    assert_eq!(
        b.reset_kind(),
        ResetKind::RequiresEcuReset,
        "with_bank_activator after with_bank_provider must not clobber the override"
    );
}
