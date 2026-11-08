// ===========================================================================
// Copy-forward (manifest-only / partial push reconciliation)
// ===========================================================================
use super::super::*;
use crate::manifest_provider::ManifestError;
use nv_store::block::MemBlockDevice;
use nv_store::slots;
use nv_store::store::MIN_NV_DEVICE_SIZE;
use sha2::{Digest, Sha256};
use sumo_offboard::{keygen, ImageManifestBuilder};

struct NoopManifest;
impl ManifestProvider for NoopManifest {
    fn validate(&self, _d: &[u8], _m: u32) -> Result<ValidatedFirmware, ManifestError> {
        Err(ManifestError::ParseError(
            "unused in copy-forward tests".into(),
        ))
    }
}
/// A detached (no integrated payload) single-component SUIT manifest whose
/// declared image digest is `digest` — mimics the offboard "manifest-only,
/// you already have this" push. `component_id = ["vm1", part]` — the part
/// segment is the on-disk bank filename, verbatim. The payload uri stays
/// `#firmware` on purpose: naming must key off the id, never the uri.
fn detached_manifest(part: &str, digest: &[u8], size: u64) -> Vec<u8> {
    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    ImageManifestBuilder::new()
        .signing_time(1_700_000_000)
        .component_id(vec!["vm1".into(), part.into()])
        .sequence_number(2)
        .payload_digest(digest, size)
        .payload_uri("#firmware".into())
        .build(&key)
        .unwrap()
}

fn vm1_backend(images_dir: PathBuf) -> ComponentBackend<MemBlockDevice> {
    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    let mut boot = NvBootState::default();
    boot.banks[slots::VM1.as_index()].active_bank = Bank::A;
    nv.write_boot_state(&mut boot).unwrap();
    ComponentBackend::with_options(
        slots::VM1,
        Arc::new(Mutex::new(nv)),
        Arc::new(NoopManifest),
        ComponentConfig::default(),
        None,
        Some(images_dir),
        None,
    )
    .with_bank_spec(crate::bank_spec::BankSetSpec {
        dir_name: "vm1".into(),
    })
}

/// Digest-match: the active bank's content hashes to what the manifest
/// declares → copy it forward into the target bank + report the inventory.
#[tokio::test]
async fn reconcile_unpushed_copies_matching_component() {
    let tmp = tempfile::tempdir().unwrap();
    let images_dir = tmp.path().to_path_buf();
    let content = b"vm1 rootfs the vehicle already has";
    let active = images_dir.join("vm1/bank_a");
    std::fs::create_dir_all(&active).unwrap();
    std::fs::write(active.join("rootfs.img"), content).unwrap();
    let digest: [u8; 32] = Sha256::digest(content).into();

    let manifest = detached_manifest("rootfs.img", &digest, content.len() as u64);
    let backend = vm1_backend(images_dir.clone());

    let copied = backend
        .reconcile_unpushed(&manifest, &[0], Bank::B)
        .await
        .expect("digest matches → copy-forward");
    assert_eq!(copied.len(), 1);
    assert_eq!(copied[0].relative_path, "rootfs.img");
    assert_eq!(copied[0].sha256, digest.to_vec());
    assert_eq!(copied[0].size, content.len() as u64);
    assert_eq!(
        std::fs::read(images_dir.join("vm1/bank_b/rootfs.img")).unwrap(),
        content,
        "target bank_b gets the active bank's verified rootfs"
    );
}

/// Digest-mismatch with no fetch source: the active bank holds a different
/// version than the manifest declares → the install must FAIL and stage
/// nothing (never ship stale content).
#[tokio::test]
async fn reconcile_unpushed_fails_on_stale_active() {
    let tmp = tempfile::tempdir().unwrap();
    let images_dir = tmp.path().to_path_buf();
    let active = images_dir.join("vm1/bank_a");
    std::fs::create_dir_all(&active).unwrap();
    std::fs::write(active.join("rootfs.img"), b"STALE local rootfs").unwrap();

    let declared: [u8; 32] = Sha256::digest(b"the version offboard expects").into();
    let manifest = detached_manifest("rootfs.img", &declared, 42);
    let backend = vm1_backend(images_dir.clone());

    let err = backend
        .reconcile_unpushed(&manifest, &[0], Bank::B)
        .await
        .expect_err("digest mismatch → install must fail");
    assert!(matches!(err, BackendError::Internal(_)), "got {err:?}");
    assert!(
        !images_dir.join("vm1/bank_b/rootfs.img").exists(),
        "stale content must not be staged into the target bank"
    );
}

/// No un-pushed components (`next_component == total`) → no-op, empty result.
#[tokio::test]
async fn reconcile_unpushed_noop_when_all_pushed() {
    let tmp = tempfile::tempdir().unwrap();
    let images_dir = tmp.path().to_path_buf();
    let manifest = detached_manifest("rootfs.img", &[0u8; 32], 0);
    let backend = vm1_backend(images_dir);
    let copied = backend
        .reconcile_unpushed(&manifest, &[], Bank::B)
        .await
        .expect("no un-pushed components");
    assert!(copied.is_empty());
}

/// Like `detached_manifest`, with an explicit payload uri — the pull shape
/// puts the CONTENT-ADDRESS there.
fn detached_manifest_with_uri(part: &str, digest: &[u8], size: u64, uri: &str) -> Vec<u8> {
    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    ImageManifestBuilder::new()
        .signing_time(1_700_000_000)
        .component_id(vec!["vm1".into(), part.into()])
        .sequence_number(2)
        .payload_digest(digest, size)
        .payload_uri(uri.into())
        .build(&key)
        .unwrap()
}

/// A session [`machine_mgr::InstallSource`] over `base` (anchor unused by
/// blob fetches — blobs verify by content-address, not signature).
fn test_source(base: String) -> machine_mgr::InstallSource {
    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    machine_mgr::InstallSource {
        cas_base_url: base,
        trust_anchor: key.public_key_bytes(),
    }
}

/// Minimal raw-HTTP/1.1 CAS for the reconcile fetch tests: serves `blobs`
/// by exact path, honours HEAD (headers only) and `Range: bytes=N-` (206),
/// logs every `"<METHOD> <path>"`, and optionally truncates the FIRST GET
/// body after `early_close_once` bytes (then serves fully — the resume
/// scenario).
///
/// Teardown is deliberately graceful (drain the full request, then FIN via
/// `shutdown`): an abrupt drop can turn into a TCP RST, and an RST discards
/// data the client kernel has buffered but not yet read — which made the
/// truncated-body bytes vanish under load (empty `.part`, flaky
/// `reconcile_fetch_failure_is_retry_safe_and_resumes`). With a clean FIN
/// plus a delivery gap after a truncated body (see below), the client
/// reliably sees exactly the bytes written, then EOF.
async fn serve_cas(
    blobs: std::collections::HashMap<String, Vec<u8>>,
    early_close_once: Option<usize>,
) -> (String, Arc<Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let log: Arc<Mutex<Vec<String>>> = Arc::default();
    let log_srv = log.clone();
    let cut = Arc::new(Mutex::new(early_close_once));
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(c) => c,
                Err(_) => return,
            };
            let blobs = blobs.clone();
            let log = log_srv.clone();
            let cut = cut.clone();
            tokio::spawn(async move {
                // Drain the whole request (headers end at the blank line;
                // these requests carry no body). Unread request bytes at
                // close would turn the close into an RST.
                let mut buf = Vec::with_capacity(4096);
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let req = String::from_utf8_lossy(&buf).into_owned();
                let mut first = req.lines().next().unwrap_or("").split_whitespace();
                let method = first.next().unwrap_or("").to_string();
                let path = first.next().unwrap_or("").to_string();
                log.lock().unwrap().push(format!("{method} {path}"));
                let Some(blob) = blobs.get(&path) else {
                    let _ = sock
                            .write_all(
                                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await;
                    let _ = sock.shutdown().await;
                    return;
                };
                let start = req
                    .lines()
                    .find_map(|l| l.strip_prefix("Range: bytes="))
                    .and_then(|r| r.split('-').next())
                    .and_then(|s| s.trim().parse::<usize>().ok())
                    .filter(|s| *s <= blob.len());
                let (line, mut body): (&str, &[u8]) = match start {
                    Some(s) => ("206 Partial Content", &blob[s..]),
                    None => ("200 OK", &blob[..]),
                };
                let full_len = body.len();
                let mut truncated = false;
                if method == "HEAD" {
                    body = &[];
                } else if let Some(limit) = cut.lock().unwrap().take() {
                    if body.len() > limit {
                        body = &body[..limit];
                        truncated = true;
                    }
                }
                let head = format!(
                        "HTTP/1.1 {line}\r\nContent-Length: {full_len}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                    );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body).await;
                let _ = sock.flush().await;
                if truncated {
                    // Separate the short body from the EOF in time. When
                    // the truncated bytes and the FIN reach the client as
                    // one read event, hyper races its buffered body chunk
                    // against the premature-EOF error and sometimes
                    // surfaces ONLY the error — the client then persists a
                    // 0-byte partial and the resume test loses its Range
                    // leg. With the gap, the client must consume the
                    // prefix as its own event before the EOF arrives.
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                // FIN, not RST: guarantees delivery of everything written
                // (the truncated-GET case relies on the client seeing all
                // `early_close_once` bytes, then clean EOF).
                let _ = sock.shutdown().await;
            });
        }
    });
    (format!("http://{addr}/"), log)
}

/// Copy-forward misses (empty active bank) → the part is FETCHED by the
/// content-address in the (signed) manifest uri: the `sha256:` scheme is
/// mapped onto the repo blob path for both the size probe and the fetch,
/// the outer sha is verified while streaming, the inner digest at install,
/// and the CAS temp is cleaned on success.
#[tokio::test]
async fn reconcile_fetches_missing_part_by_content_address() {
    let tmp = tempfile::tempdir().unwrap();
    let images_dir = tmp.path().to_path_buf();
    std::fs::create_dir_all(images_dir.join("vm1/bank_a")).unwrap(); // empty active

    let content = b"vm1 rootfs fetched from the CAS".to_vec();
    // Unencrypted + uncompressed: outer (ciphertext) == inner (plaintext).
    let digest: [u8; 32] = Sha256::digest(&content).into();
    let outer_hex = hex::encode(digest);
    let (base, log) = serve_cas(
        std::collections::HashMap::from([(format!("/blobs/{outer_hex}"), content.clone())]),
        None,
    )
    .await;

    let manifest = detached_manifest_with_uri(
        "rootfs.img",
        &digest,
        content.len() as u64,
        &format!("sha256:{outer_hex}"),
    );
    let backend = vm1_backend(images_dir.clone());
    backend.set_install_source(test_source(base));

    let done = backend
        .reconcile_unpushed(&manifest, &[0], Bank::B)
        .await
        .expect("missing active + content-addressed uri → fetch");
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].relative_path, "rootfs.img");
    assert_eq!(done[0].sha256, digest.to_vec());
    assert_eq!(
        std::fs::read(images_dir.join("vm1/bank_b/rootfs.img")).unwrap(),
        content,
    );
    let log = log.lock().unwrap();
    assert!(
        log.iter().any(|l| l == &format!("HEAD /blobs/{outer_hex}")),
        "{log:?}"
    );
    assert!(
        log.iter().any(|l| l == &format!("GET /blobs/{outer_hex}")),
        "{log:?}"
    );
    let leftovers: Vec<_> = std::fs::read_dir(images_dir.join("vm1/cas"))
        .unwrap()
        .collect();
    assert!(leftovers.is_empty(), "CAS temp not cleaned: {leftovers:?}");
}

/// Per-part copy-vs-fetch: parts whose active-bank content matches the
/// manifest digest are copied locally; ONLY the changed part is fetched —
/// the metered-link litmus (a config-only change never re-downloads the
/// rootfs).
#[tokio::test]
async fn reconcile_copies_matching_parts_and_fetches_only_the_changed_one() {
    use sumo_offboard::image_builder::{ComponentSpec as SuitComponentSpec, MultiComponentBuilder};

    let tmp = tempfile::tempdir().unwrap();
    let images_dir = tmp.path().to_path_buf();
    let active = images_dir.join("vm1/bank_a");
    std::fs::create_dir_all(&active).unwrap();

    let kernel = b"kernel bytes the vehicle has".to_vec();
    let rootfs = b"rootfs bytes the vehicle has".to_vec();
    let config_new = b"NEW vm config".to_vec();
    std::fs::write(active.join("kernel"), &kernel).unwrap();
    std::fs::write(active.join("rootfs.img"), &rootfs).unwrap();
    std::fs::write(active.join("vm-config.yaml"), b"OLD vm config").unwrap();

    let d_kernel: [u8; 32] = Sha256::digest(&kernel).into();
    let d_rootfs: [u8; 32] = Sha256::digest(&rootfs).into();
    let d_config: [u8; 32] = Sha256::digest(&config_new).into();
    let config_hex = hex::encode(d_config);
    // Only the changed part exists on the CAS — a request for anything
    // else would 404 and fail the test via the digest/size checks.
    let (base, log) = serve_cas(
        std::collections::HashMap::from([(format!("/blobs/{config_hex}"), config_new.clone())]),
        None,
    )
    .await;

    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let spec = |part: &str, d: &[u8; 32], len: usize| SuitComponentSpec {
        id: vec!["vm1".into(), part.into()],
        digest: d.to_vec(),
        size: len as u64,
        uri: format!("sha256:{}", hex::encode(d)),
        encryption_info: None,
    };
    let manifest = MultiComponentBuilder::new()
        .signing_time(1_700_000_000)
        .sequence_number(2)
        .add_component(spec("kernel", &d_kernel, kernel.len()))
        .add_component(spec("rootfs.img", &d_rootfs, rootfs.len()))
        .add_component(spec("vm-config.yaml", &d_config, config_new.len()))
        .build(&key)
        .unwrap();

    let backend = vm1_backend(images_dir.clone());
    backend.set_install_source(test_source(base));

    let done = backend
        .reconcile_unpushed(&manifest, &[0, 1, 2], Bank::B)
        .await
        .expect("2 copies + 1 fetch");
    assert_eq!(done.len(), 3);
    let target = images_dir.join("vm1/bank_b");
    assert_eq!(std::fs::read(target.join("kernel")).unwrap(), kernel);
    assert_eq!(std::fs::read(target.join("rootfs.img")).unwrap(), rootfs);
    assert_eq!(
        std::fs::read(target.join("vm-config.yaml")).unwrap(),
        config_new
    );
    // Exactly ONE part hit the network (HEAD + GET on the config blob).
    let log = log.lock().unwrap();
    assert_eq!(log.len(), 2, "{log:?}");
    assert!(log.iter().all(|l| l.ends_with(&config_hex)), "{log:?}");
}

/// A CDN serving different bytes behind the content-address is rejected
/// while streaming (outer sha mismatch) — nothing lands in the target bank.
#[tokio::test]
async fn reconcile_rejects_tampered_cdn_content() {
    let tmp = tempfile::tempdir().unwrap();
    let images_dir = tmp.path().to_path_buf();
    std::fs::create_dir_all(images_dir.join("vm1/bank_a")).unwrap();

    let content = b"the bytes T2 signed for".to_vec();
    let digest: [u8; 32] = Sha256::digest(&content).into();
    let outer_hex = hex::encode(digest);
    let (base, _log) = serve_cas(
        std::collections::HashMap::from([(
            format!("/blobs/{outer_hex}"),
            b"SWAPPED cdn object".to_vec(),
        )]),
        None,
    )
    .await;

    let manifest = detached_manifest_with_uri(
        "rootfs.img",
        &digest,
        content.len() as u64,
        &format!("sha256:{outer_hex}"),
    );
    let backend = vm1_backend(images_dir.clone());
    backend.set_install_source(test_source(base));

    let err = backend
        .reconcile_unpushed(&manifest, &[0], Bank::B)
        .await
        .expect_err("tampered CDN content must be rejected");
    assert!(matches!(err, BackendError::Internal(_)), "got {err:?}");
    assert!(
        !images_dir.join("vm1/bank_b/rootfs.img").exists(),
        "tampered content must never land in the target bank"
    );
}

/// A transport failure mid-blob keeps the resumable `.part` (outside the
/// bank dirs, so the bank's prune at the next manifest can't destroy it); the
/// retry resumes with a Range request and completes.
#[tokio::test]
async fn reconcile_fetch_failure_is_retry_safe_and_resumes() {
    let tmp = tempfile::tempdir().unwrap();
    let images_dir = tmp.path().to_path_buf();
    std::fs::create_dir_all(images_dir.join("vm1/bank_a")).unwrap();

    let content: Vec<u8> = (0..4096u32).flat_map(|i| i.to_le_bytes()).collect();
    let digest: [u8; 32] = Sha256::digest(&content).into();
    let outer_hex = hex::encode(digest);
    let (base, log) = serve_cas(
        std::collections::HashMap::from([(format!("/blobs/{outer_hex}"), content.clone())]),
        Some(1000), // first GET truncates after 1000 bytes
    )
    .await;

    let manifest = detached_manifest_with_uri(
        "rootfs.img",
        &digest,
        content.len() as u64,
        &format!("sha256:{outer_hex}"),
    );
    let backend = vm1_backend(images_dir.clone());
    backend.set_install_source(test_source(base));

    backend
        .reconcile_unpushed(&manifest, &[0], Bank::B)
        .await
        .expect_err("truncated transfer must fail the first attempt");
    let part = images_dir.join(format!("vm1/cas/cas-{outer_hex}.part"));
    assert!(part.exists(), "resumable partial must persist");
    // Exactly the delivered prefix — serve_cas's post-truncation gap makes
    // the 1000 delivered-then-EOF bytes deterministic.
    assert_eq!(std::fs::metadata(&part).unwrap().len(), 1000);

    let done = backend
        .reconcile_unpushed(&manifest, &[0], Bank::B)
        .await
        .expect("retry resumes the partial and completes");
    assert_eq!(done[0].sha256, digest.to_vec());
    assert_eq!(
        std::fs::read(images_dir.join("vm1/bank_b/rootfs.img")).unwrap(),
        content,
    );
    // The retry's GET carried a Range (206 path) — visible as a second GET.
    let log = log.lock().unwrap();
    assert_eq!(
        log.iter().filter(|l| l.starts_with("GET ")).count(),
        2,
        "{log:?}"
    );
}

/// Siblings Join ONE node update transaction; `abort_install` through the
/// adapter resolves the staging so the node returns to Idle.
#[tokio::test]
async fn siblings_join_one_node_transaction_and_abort_resolves_it() {
    let tmp = tempfile::tempdir().unwrap();
    let images_dir = tmp.path().to_path_buf();
    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    let mut boot = NvBootState::default();
    for set in [slots::VM1, slots::VM2] {
        boot.banks[set.as_index()].active_bank = Bank::A;
        boot.banks[set.as_index()].committed = true;
    }
    nv.write_boot_state(&mut boot).unwrap();
    let nv = Arc::new(Mutex::new(nv));
    let coord = Arc::new(machine_mgr::node_update::NodeCoordinator::new());
    let mk = |set: BankSet| {
        ComponentBackend::with_options(
            set,
            nv.clone(),
            Arc::new(NoopManifest),
            ComponentConfig::default(),
            None,
            Some(images_dir.clone()),
            None,
        )
        .with_node_coordinator(coord.clone())
    };
    let vm1 = mk(slots::VM1);
    let vm2 = mk(slots::VM2);

    vm1.ensure_flash_can_start()
        .expect("first campaign member stages");
    vm2.ensure_flash_can_start()
        .expect("sibling joins the same node transaction");
    assert_eq!(
        coord.node_update_state().phase,
        machine_mgr::node_update::NodePhase::Staging
    );

    // Adapter-level abort resolves the staging membership (not just the
    // backend session) — the node returns to Idle once both leave.
    use machine_mgr::Component as _;
    let a1 = crate::component_adapter::ComponentAdapter::new(Arc::new(vm1));
    let a2 = crate::component_adapter::ComponentAdapter::new(Arc::new(vm2));
    a1.abort_install(&machine_mgr::FlashId::new("x"))
        .await
        .unwrap();
    a2.abort_install(&machine_mgr::FlashId::new("x"))
        .await
        .unwrap();
    let st = coord.node_update_state();
    assert_eq!(st.phase, machine_mgr::node_update::NodePhase::Idle);
}

/// The in-trial verdict gate: while a sibling is in trial and the node has
/// rebooted since arming (a Local-reset VM is never pending a node reset,
/// so the node phase is Trial, not RebootPending), a NEW flash of a
/// DIFFERENT component is refused with `Refused::Trial` — the node owes a
/// commit/rollback verdict first. Committing the in-trial component clears
/// it. The same-component case is caught one layer earlier by the
/// component's own in-trial check ("in trial mode"), never the node gate.
#[tokio::test]
async fn in_trial_component_refuses_a_new_flash_of_a_sibling() {
    let tmp = tempfile::tempdir().unwrap();
    let images_dir = tmp.path().to_path_buf();

    // vm1 in trial: active bank B, uncommitted. vm2 fully committed, so it
    // clears its own in-trial check and reaches the node gate.
    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    let mut boot = NvBootState::default();
    boot.banks[slots::VM1.as_index()].active_bank = Bank::B;
    boot.banks[slots::VM1.as_index()].committed = false;
    boot.banks[slots::VM2.as_index()].active_bank = Bank::A;
    boot.banks[slots::VM2.as_index()].committed = true;
    nv.write_boot_state(&mut boot).unwrap();
    let nv = Arc::new(Mutex::new(nv));

    // The node has rebooted since vm1 was armed: its trial awaits a verdict.
    let coord = Arc::new(
        machine_mgr::node_update::NodeCoordinator::new()
            .with_rebooted_probe(Arc::new(|_| Some(true))),
    );
    let mk = |set: BankSet, id: &str| {
        let backend = Arc::new(
            ComponentBackend::with_options(
                set,
                nv.clone(),
                Arc::new(NoopManifest),
                ComponentConfig::default(),
                None,
                Some(images_dir.clone()),
                None,
            )
            .with_id(id.to_string())
            .with_node_coordinator(coord.clone()),
        );
        // The adapter registers the component's bank report with the node.
        crate::component_adapter::ComponentAdapter::new(backend.clone());
        backend
    };
    let vm1 = mk(slots::VM1, "vm1");
    let vm2 = mk(slots::VM2, "vm2");

    // A DIFFERENT component is refused by the node gate: the node owes a
    // verdict for the in-trial vm1.
    let err = vm2
        .ensure_flash_can_start()
        .expect_err("a new flash must be refused while vm1 is in trial");
    let msg = match &err {
        BackendError::Busy(m) => m.clone(),
        other => panic!("expected Busy(Trial), got {other:?}"),
    };
    assert!(
        msg.contains("owes a verdict for in-trial") && msg.contains("vm1"),
        "expected the node-gate Trial refusal naming vm1, got: {msg}"
    );

    // The SAME component (vm1) is refused one layer earlier — its own
    // in-trial check ("in trial mode"), never the node gate. That layer must
    // stay intact.
    let err = vm1
        .ensure_flash_can_start()
        .expect_err("vm1 itself is in trial → refused by its own check");
    let msg = match &err {
        BackendError::Busy(m) => m.clone(),
        other => panic!("expected Busy(bank-set trial mode), got {other:?}"),
    };
    assert!(
        msg.contains("is in trial mode"),
        "expected the component's in-trial refusal, got: {msg}"
    );

    // Commit vm1 — without a boot selector its bank report derives
    // `in_trial` from the NV committed flag, so flipping it to committed is
    // exactly what a commit verdict does here. The node returns to Idle and a
    // new flash of vm2 is admitted.
    {
        let mut guard = nv.lock().unwrap();
        let mut boot = guard.read_boot_state().unwrap();
        boot.banks[slots::VM1.as_index()].committed = true;
        guard.write_boot_state(&mut boot).unwrap();
    }
    vm2.ensure_flash_can_start()
        .expect("with vm1 committed, the node is Idle and vm2 may flash");
}

/// Build a fully-provisioned SimHsm (keystore + device `ivd-signing` keypair)
/// so `finalize_flash`'s seal step can sign. Mirrors `identity_tests`.
fn provisioned_hsm(
    tag: &str,
) -> (
    Arc<Mutex<dyn hsm::HsmProvider>>,
    Arc<dyn hsm::HsmCryptoProvider>,
    PathBuf,
) {
    use hsm::payload::*;
    use hsm::HsmProvider;
    use hsm_sim_backend::SimHsm;
    let keystore = std::env::temp_dir().join(format!("component-mgr-copyfwd-ks-{tag}"));
    let _ = std::fs::remove_dir_all(&keystore);
    std::fs::create_dir_all(&keystore).unwrap();
    let hsm = SimHsm::new(keystore.clone());
    let ks = HsmKeystore {
        schema_version: SCHEMA_VERSION,
        security_version: 1,
        identities: vec![],
        slots: vec![KeySlot {
            key_id: hsm::ivd::IVD_KEY_ID.to_string(),
            key_kind: KEY_TYPE_EC_P256,
            anchor_public_key: None,
            allowed_guests: None,
            allowed_ops: Some(vec![OP_SIGN, OP_VERIFY, OP_GET_PUBKEY]),
        }],
        certificates: Vec::new(),
        trust_anchors: Vec::new(),
    };
    hsm.write_keystore(&ks).unwrap();
    hsm.ensure_device_keys().unwrap();
    std::fs::write(keystore.join("provision_state"), b"1\n").unwrap();
    assert!(hsm.is_provisioned().unwrap());
    let crypto: Arc<dyn hsm::HsmCryptoProvider> = Arc::new(SimHsm::new(keystore.clone()));
    (Arc::new(Mutex::new(hsm)), crypto, keystore)
}

/// End-to-end brick fix: a 0-payload (manifest-only) push must NOT activate
/// an empty bank. `finalize_flash` copies the un-pushed component forward from
/// the active bank, IVD-seals the target, flips NV — so the bank is bootable
/// (no auto-rollback), not empty.
#[tokio::test]
async fn finalize_manifest_only_copies_forward_seals_and_flips_nv() {
    let tmp = tempfile::tempdir().unwrap();
    let images_dir = tmp.path().to_path_buf();

    // Active bank (A) holds the rootfs the manifest-only push declares.
    let content = b"vm1 rootfs already on the vehicle";
    let active = images_dir.join("vm1/bank_a");
    std::fs::create_dir_all(&active).unwrap();
    std::fs::write(active.join("rootfs.img"), content).unwrap();
    let digest: [u8; 32] = Sha256::digest(content).into();

    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    let mut boot = NvBootState::default();
    boot.banks[slots::VM1.as_index()].active_bank = Bank::A;
    boot.banks[slots::VM1.as_index()].committed = true;
    nv.write_boot_state(&mut boot).unwrap();
    let nv = Arc::new(Mutex::new(nv));

    let (hsm, crypto, keystore) = provisioned_hsm("finalize");
    let backend = ComponentBackend::with_options(
        slots::VM1,
        nv.clone(),
        Arc::new(NoopManifest),
        ComponentConfig::default(),
        None,
        Some(images_dir.clone()),
        Some(hsm),
    )
    .with_bank_spec(crate::bank_spec::BankSetSpec {
        dir_name: "vm1".into(),
    })
    .with_hsm_crypto(crypto);

    // Park a manifest-only session (0 of 1 components pushed) + the Firmware
    // package finalize reads image_meta from (image_sha256 = None, exactly
    // the header-only shape the real manifest-only path produces).
    let manifest = detached_manifest("rootfs.img", &digest, content.len() as u64);
    let validated = ValidatedFirmware {
        component_name: "vm1".into(),
        manifest_type: ManifestType::Firmware,
        image_meta: crate::ota::ImageMeta::default(),
        image_data: Vec::new(),
        version_display: "1.0.0".into(),
        image_sha256: None,
        image_size: None,
        raw_envelope: None,
        streamed_files: Vec::new(),
        signing_time_secs: None,
        disable_target: None,
    };
    backend.packages.lock().unwrap().insert(
        "m1".into(),
        StoredPackage {
            id: "m1".into(),
            validated: validated.clone(),
            status: PackageStatus::Verified,
        },
    );
    *backend.flash_transfer.lock().unwrap() = Some(FlashTransferState {
        transfer_id: "t1".into(),
        package_id: "m1".into(),
        state: FlashState::AwaitingActivation,
        pre_reset_health: None,
        image_size: 0,
        streamed_files: Vec::new(),
    });
    *backend.flash_session.lock().unwrap() = Some(FlashSessionState::AwaitingPayload {
        manifest_bytes: manifest,
        validated,
        parts: vec![0],
        present: BTreeSet::new(),
    });

    // Precondition: target bank is empty (would brick if activated as-is).
    assert!(!images_dir.join("vm1/bank_b/rootfs.img").exists());

    DiagnosticBackend::finalize_flash(&backend)
        .await
        .expect("finalize reconciles the manifest-only push");

    // Target bank now carries the copied rootfs AND a signed IVD manifest.
    assert_eq!(
        std::fs::read(images_dir.join("vm1/bank_b/rootfs.img")).unwrap(),
        content,
        "un-pushed component copied forward from the active bank"
    );
    assert!(
        images_dir.join("vm1/bank_b/ivd-manifest.cbor").exists(),
        "target bank must be IVD-sealed so secure boot / commit accept it"
    );
    assert!(images_dir.join("vm1/bank_b/ivd-signature.bin").exists());
    // Session advanced; NV flipped to the sealed bank in trial mode.
    assert!(matches!(
        *backend.flash_session.lock().unwrap(),
        Some(FlashSessionState::Complete)
    ));
    let s = crate::ota::status(&nv.lock().unwrap(), slots::VM1).unwrap();
    assert_eq!(
        s.active_bank,
        Bank::B,
        "install_precomputed flipped NV to the sealed bank"
    );
    assert!(!s.committed, "banked install enters trial mode");

    let _ = std::fs::remove_dir_all(&keystore);
}

/// A banked (dual-bank, rollbackable) activator that still needs a full node
/// ECU reset to run its armed bank — host-os's shape. Injected via
/// `with_bank_activator` so the default file provider's `reset_kind` folds in
/// `RequiresEcuReset`.
struct EcuResetActivator;
impl machine_mgr::BankActivator for EcuResetActivator {
    fn activate(&self, _dir: &std::path::Path) -> Result<(), machine_mgr::BankActivatorError> {
        Ok(())
    }
    fn reset_kind(&self) -> machine_mgr::ResetKind {
        machine_mgr::ResetKind::RequiresEcuReset
    }
}

/// The banked blind-spot fix: a BANKED `RequiresEcuReset` component (host-os)
/// must now mark the durable node reboot-owed bit at finalize/arm — it did
/// not before (only write-through singleshots did), so a banked trial that
/// fell back to recovery read as `Trial` (commit-allowed). Reuses the
/// manifest-only finalize harness with a `RequiresEcuReset` activator.
#[tokio::test]
async fn banked_requires_ecu_reset_finalize_marks_reboot_owed() {
    let (backend, _nv, keystore, _tmp) = finalize_banked_requires_ecu_reset(None).await;

    // The fix: arming a banked RequiresEcuReset component now owes a node
    // reboot (the NV record is still written; dual-run).
    assert!(super::bank_provider_injection_tests::nv_owes(&backend));

    let _ = std::fs::remove_dir_all(&keystore);
}

/// Arming records the node boot id it armed under into the NV record (still
/// written; dual-run).
#[tokio::test]
async fn finalize_records_armed_boot_id() {
    let (_backend, nv, keystore, _tmp) = finalize_banked_requires_ecu_reset(Some("boot-x")).await;

    let session = nv.lock().unwrap().read_update_session().unwrap();
    assert_eq!(
        session.armed_boot_id,
        NvUpdateSession::boot_id_digest("boot-x")
    );
    assert_eq!(session.rebooted_since_arming(Some("boot-x")), Some(false));
    assert_eq!(session.rebooted_since_arming(Some("boot-y")), Some(true));
    assert_eq!(session.rebooted_since_arming(None), None);

    let _ = std::fs::remove_dir_all(&keystore);
}

/// Finalize a manifest-only push for a banked `RequiresEcuReset` VM1
/// (optionally under a node boot id). Returns the backend, its NV, the HSM
/// keystore to clean up and the images tempdir guard.
async fn finalize_banked_requires_ecu_reset(
    node_boot_id: Option<&str>,
) -> (
    ComponentBackend<MemBlockDevice>,
    Arc<Mutex<NvStore<MemBlockDevice>>>,
    std::path::PathBuf,
    tempfile::TempDir,
) {
    let tmp = tempfile::tempdir().unwrap();
    let images_dir = tmp.path().to_path_buf();

    let content = b"vm1 rootfs already on the vehicle";
    let active = images_dir.join("vm1/bank_a");
    std::fs::create_dir_all(&active).unwrap();
    std::fs::write(active.join("rootfs.img"), content).unwrap();
    let digest: [u8; 32] = Sha256::digest(content).into();

    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    let mut boot = NvBootState::default();
    boot.banks[slots::VM1.as_index()].active_bank = Bank::A;
    boot.banks[slots::VM1.as_index()].committed = true;
    nv.write_boot_state(&mut boot).unwrap();
    let nv = Arc::new(Mutex::new(nv));

    // One keystore dir per caller: the two tests that share this helper run
    // in parallel, and a shared path lets one test's setup or cleanup delete
    // the other's keys mid-write.
    let tag = match node_boot_id {
        Some(_) => "banked-owed-armed",
        None => "banked-owed",
    };
    let (hsm, crypto, keystore) = provisioned_hsm(tag);
    let backend = ComponentBackend::with_options(
        slots::VM1,
        nv.clone(),
        Arc::new(NoopManifest),
        ComponentConfig::default(), // banked: supports_rollback, dual-bank
        None,
        Some(images_dir.clone()),
        Some(hsm),
    )
    .with_bank_spec(crate::bank_spec::BankSetSpec {
        dir_name: "vm1".into(),
    })
    .with_hsm_crypto(crypto)
    .with_bank_activator(Arc::new(EcuResetActivator));
    let backend = match node_boot_id {
        Some(id) => backend.with_node_boot_id(id.into()),
        None => backend,
    };

    // Precondition: banked + RequiresEcuReset, and nothing owed yet.
    assert_eq!(
        backend.reset_kind(),
        machine_mgr::ResetKind::RequiresEcuReset
    );
    assert!(!super::bank_provider_injection_tests::nv_owes(&backend));

    let manifest = detached_manifest("rootfs.img", &digest, content.len() as u64);
    let validated = ValidatedFirmware {
        component_name: "vm1".into(),
        manifest_type: ManifestType::Firmware,
        image_meta: crate::ota::ImageMeta::default(),
        image_data: Vec::new(),
        version_display: "1.0.0".into(),
        image_sha256: None,
        image_size: None,
        raw_envelope: None,
        streamed_files: Vec::new(),
        signing_time_secs: None,
        disable_target: None,
    };
    backend.packages.lock().unwrap().insert(
        "m1".into(),
        StoredPackage {
            id: "m1".into(),
            validated: validated.clone(),
            status: PackageStatus::Verified,
        },
    );
    *backend.flash_transfer.lock().unwrap() = Some(FlashTransferState {
        transfer_id: "t1".into(),
        package_id: "m1".into(),
        state: FlashState::AwaitingActivation,
        pre_reset_health: None,
        image_size: 0,
        streamed_files: Vec::new(),
    });
    *backend.flash_session.lock().unwrap() = Some(FlashSessionState::AwaitingPayload {
        manifest_bytes: manifest,
        validated,
        parts: vec![0],
        present: BTreeSet::new(),
    });

    DiagnosticBackend::finalize_flash(&backend)
        .await
        .expect("banked RequiresEcuReset finalize");
    (backend, nv, keystore, tmp)
}

/// Pull-path finalize end-to-end: the un-pushed component is FETCHED by
/// its content-address (the vehicle does NOT have the bytes), the bank
/// IVD-sealed, NV flipped into trial — the device-side fetch executor
/// completes the install exactly like the push path would, and the
/// session-scoped install source is consumed.
#[tokio::test]
async fn finalize_manifest_only_fetches_seals_and_flips_nv() {
    let tmp = tempfile::tempdir().unwrap();
    let images_dir = tmp.path().to_path_buf();

    // Active bank exists but does NOT carry the declared content.
    std::fs::create_dir_all(images_dir.join("vm1/bank_a")).unwrap();
    let content = b"vm1 rootfs only the CAS has".to_vec();
    let digest: [u8; 32] = Sha256::digest(&content).into();
    let outer_hex = hex::encode(digest);
    let (base, _log) = serve_cas(
        std::collections::HashMap::from([(format!("/blobs/{outer_hex}"), content.clone())]),
        None,
    )
    .await;

    let mut nv = NvStore::new(MemBlockDevice::new(MIN_NV_DEVICE_SIZE as usize));
    let mut boot = NvBootState::default();
    boot.banks[slots::VM1.as_index()].active_bank = Bank::A;
    boot.banks[slots::VM1.as_index()].committed = true;
    nv.write_boot_state(&mut boot).unwrap();
    let nv = Arc::new(Mutex::new(nv));

    let (hsm, crypto, keystore) = provisioned_hsm("finalize-fetch");
    let backend = ComponentBackend::with_options(
        slots::VM1,
        nv.clone(),
        Arc::new(NoopManifest),
        ComponentConfig::default(),
        None,
        Some(images_dir.clone()),
        Some(hsm),
    )
    .with_bank_spec(crate::bank_spec::BankSetSpec {
        dir_name: "vm1".into(),
    })
    .with_hsm_crypto(crypto);
    backend.set_install_source(test_source(base));

    let manifest = detached_manifest_with_uri(
        "rootfs.img",
        &digest,
        content.len() as u64,
        &format!("sha256:{outer_hex}"),
    );
    let validated = ValidatedFirmware {
        component_name: "vm1".into(),
        manifest_type: ManifestType::Firmware,
        image_meta: crate::ota::ImageMeta::default(),
        image_data: Vec::new(),
        version_display: "1.0.0".into(),
        image_sha256: None,
        image_size: None,
        raw_envelope: None,
        streamed_files: Vec::new(),
        signing_time_secs: None,
        disable_target: None,
    };
    backend.packages.lock().unwrap().insert(
        "m1".into(),
        StoredPackage {
            id: "m1".into(),
            validated: validated.clone(),
            status: PackageStatus::Verified,
        },
    );
    *backend.flash_transfer.lock().unwrap() = Some(FlashTransferState {
        transfer_id: "t1".into(),
        package_id: "m1".into(),
        state: FlashState::AwaitingActivation,
        pre_reset_health: None,
        image_size: 0,
        streamed_files: Vec::new(),
    });
    *backend.flash_session.lock().unwrap() = Some(FlashSessionState::AwaitingPayload {
        manifest_bytes: manifest,
        validated,
        parts: vec![0],
        present: BTreeSet::new(),
    });

    DiagnosticBackend::finalize_flash(&backend)
        .await
        .expect("finalize fetches the un-pushed component and seals");

    assert_eq!(
        std::fs::read(images_dir.join("vm1/bank_b/rootfs.img")).unwrap(),
        content,
        "un-pushed component fetched from the CAS into the target bank"
    );
    assert!(images_dir.join("vm1/bank_b/ivd-manifest.cbor").exists());
    assert!(images_dir.join("vm1/bank_b/ivd-signature.bin").exists());
    let s = crate::ota::status(&nv.lock().unwrap(), slots::VM1).unwrap();
    assert_eq!(s.active_bank, Bank::B);
    assert!(!s.committed, "banked install enters trial mode");
    assert!(
        backend.install_source.lock().unwrap().is_none(),
        "the session-scoped pull source is consumed by a successful finalize"
    );

    let _ = std::fs::remove_dir_all(&keystore);
}
