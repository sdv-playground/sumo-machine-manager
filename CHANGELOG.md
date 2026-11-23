# Changelog

Every tag on this repository is annotated with the notes below, and the matching GitHub release
carries the same text. A change that will be tagged adds its entry under **Unreleased** in the same
pull request; cutting the tag renames the heading. Tags are immutable: a mistake gets a new tag,
never a moved one. Consumers pin crates by `tag = "vX.Y.Z"`; the host-facing lines of each entry are
what a consumer has to touch when it moves its pin.

## Unreleased

- component-mgr: `SuitProvider::with_first_provision_gate(gate)` asks the host before an HSM-keys
  envelope is checked against the factory authority, which happens only while no key authority
  is installed. While the gate answers `false` such an envelope is refused (`SignatureInvalid`),
  so an empty keystore cannot be first-provisioned with the factory key outside the host's
  provisioning window. An installed key authority is never gated; without a gate nothing
  changes. **Host-facing:** none; a host with a provisioning window (a lifecycle read, say)
  passes it as the gate.

- hsm-sim-backend: `SimHsm`'s PROVISION checks a re-provision against the installed key authority
  alone. One that is installed but cannot be read, or whose presence cannot be checked (an I/O
  or permission error), refuses the envelope; it used to fall back to the factory key. A keystore provisioned without a key authority keeps the factory key, as
  before. **Host-facing:** none.
- **Bank activation pre-flights the boot-vector seal.** `activate` ran the bank's activator (the
  physical switch: a raw-partition write, a firmware load, record routing) and then sealed the boot
  vector; a seal that failed — a signer that is unavailable — left the new content physically in
  place while NV and the boot vector said old. The boot vector now proves first that its seal can
  run: `IvdBankProvider::activate` checks before the activator, `PartitionBankProvider::activate`
  before routing its records, and a vector that cannot seal fails the activation with
  `boot-vector activate cannot run — nothing activated: …`, nothing physical done. The engine still
  rolls NV back after a failed activation, as before. Not covered: a signer that answers the
  pre-flight and fails at the seal, and record writes that fail for other reasons; the activation
  then fails after the physical step as before. With a healthy signer every file written and every
  decision are unchanged (one extra, discarded signature per activation).

  Host-facing: `SelectorStore::check_activate(entries, header)`, a default method returning `Ok`
  (a store with nothing to check ahead needs no change; `RecordSelectorStore` implements it), and
  `SystemBankManager::check_activate(component_id, bank, images, armed_boot_id)`.
- **Software HSM (`hsm-sim-backend`): a delivered leaf certificate must certify the device's key.**
  A leaf was installed as long as it named an EC-P256 slot of the envelope; its public key was never
  compared with the device's key, so a leaf for another key installed and every verifying TLS client
  then failed. `provision` now refuses the whole envelope with `PayloadInvalid`, before anything is
  written (first provision and re-provision), when a leaf does not parse as an X.509 certificate,
  names a slot with no key on the device, or certifies a key other than the slot's on-disk public
  key — as the hardware backends do. A leaf for the device's own key installs as before.

  Host-facing: none required. A tower that delivered a leaf for a key the device does not hold now
  gets an error instead of an unusable TLS identity.
- **A trial has no boot limit.** A trial ends only by the tester's verdict, or by the boot stage's own
  rollback when the node cannot start (still recorded at the next start as `rolled_back` /
  `boot_stage`). The host-set trial boot limit and the node rollback it triggered are removed. Trial
  boots are still counted per distinct boot id and reported (`trial_boots` in the update state);
  the count decides nothing. A header an older build resolved at its limit still verifies, loads and
  reports `reason: "trial_boot_limit"`; nothing writes that reason any more.

  Host-facing: `NodeCoordinator::with_trial_boot_limit` and `trial_boot_limit()` are gone, and
  `NodeBootOutcome` keeps only `trial_boots` (`limit`, `bailed_out` and `errors` are gone). An
  embedder deletes its `with_trial_boot_limit(..)` call, its own config key for the limit (a config
  file that still carries the key keeps loading as long as the config struct does not deny unknown
  fields), and any use of the removed `NodeBootOutcome` fields. The update-state body on `/v1`
  (`x-ota-update-state`, `x-update-state`) no longer carries `trial_boot_limit`; the frozen legacy
  `/vehicle/v1` tree keeps it, always `null`, and its `/docs` are unchanged.

- **vhsm-ssd guest enrolment: an HSM sign error no longer burns the enrolment token.** The
  enrolment signer returned an empty signature when the HSM could not sign; the CWT minted from it
  was handed to the guest and the one-shot bootstrap token (or the ENROLL_ASSISTED pending flag) was
  consumed and saved, so a guest that enrolled during an HSM outage held a certificate that never
  validates and had to be re-armed. Now the signer reports the error and ENROLL / ENROLL_ASSISTED
  fail before anything is consumed or saved; the guest gets status `Internal` with no
  `AuthFailReason` payload (a server fault, not a verdict) and retries the same enrolment once the
  HSM answers. No wire format change.
  Host-facing: `vhsm_server::cert::EcuSigner::sign` now returns `Result<Vec<u8>, SignError>` (new
  `vhsm_server::cert::SignError`; `MintError` gains `Sign`). An out-of-tree `EcuSigner` returns
  `Err(SignError(..))` where it cannot sign, never a placeholder signature. Hosts that run the
  `vhsm-ssd` binary change nothing.
- **component-mgr HSM authorizer: an HSM read error is no longer "no key", and a degraded authorizer
  is no longer cached.** `build_authorizer_now` read the issuer anchors and the delegation root with
  `.ok()` and the ECU id with `unwrap_or_default()`, and `CachedHsmAuthorizer` cached the result
  keyed only on the keystore manifest mtime. An HSM read error therefore fell through to the build's
  `extra_anchor` (the development recovery key) as if the keystore had no key, made the expected
  audience `""` (accepted from every trusted issuer and on the delegated path), and was cached: a
  build made during an outage kept restart and factory reset locked until a keystore push or a
  process restart. Now a keystore read is present, absent (`KeyNotFound` / `NotProvisioned`, and
  `NotSupported` for a provider without a trust-anchor store) or unreadable, and:
  - an unreadable anchor is not trusted; on a build with an `extra_anchor` that anchor still stands
    in for the ids it answers, now as a logged decision, so a development unit with an unreadable
    HSM stays factory-resettable;
  - a build that saw any read error serves that request only and is never cached: the next request
    rebuilds, so the unit heals by itself once the HSM answers. Degraded states are logged at error
    when they start or change and at info when they end, not per request;
  - no ECU id (device key absent or unreadable): no keystore issuer and no delegate is trusted. On a
    build with an `extra_anchor`, the issuer ids it answers (resolved keystore first, as everywhere)
    are trusted with audience `""` for the factory reset only (such a unit is badly provisioned and
    the factory reset clears it); any other request that carries a token, an ECU restart included,
    is refused. Before, every trusted issuer was accepted with `aud: ""` for every
    capability.

  A healthy unit accepts and rejects the same tokens as before and caches as before.
  Host-facing: no API change (`HsmAuthorizerDeps`, `ExtraAnchor`, `build_authorizer_now` keep their
  signatures). To reset a development unit whose ECU id cannot be read, mint the recovery token with
  `aud` = `""` (`x-ecu-id` cannot answer in that state).
- **Software HSM (`hsm-sim-backend`): a re-provision keeps the device's own keys and state.** A
  second keystore envelope on a provisioned unit (a keystore update, a certificate renewal) built the
  new keystore in an empty directory, so every device-generated key was created anew — a new
  `device-decrypt` key (new ECU id), a new `ivd-signing` key (existing bank IVD manifests and the boot
  selector stopped verifying), a new `tls-identity` (the leaf delivered in that envelope certified the
  old key), new `iam-signing` / `jwt-signing` keys and a new `storage-key` — and the monotonic
  counters (the time floor among them), `bootstrap.yaml` and every other file the envelope does not
  write were dropped. Now the new keystore starts as a copy of everything the envelope does not own,
  modes kept, and the envelope is applied on top: the manifest, identities, security version,
  trust-anchor and guest-identity public keys and pinned roots are rewritten (one the new envelope no
  longer carries is gone); device keys are never regenerated when they exist; a leaf for a kept key
  stays until a new one is delivered. The keystore swap is still two renames; a start now resolves
  whatever an interrupted swap left (`SimHsm::recover_interrupted_reprovision`, run first by
  `ensure_device_keys`), to the complete old or the complete new keystore, instead of generating a
  new identity into the gap.
  The monotonic counters, `provision_state`, the manifest, the identities file, every key and
  certificate file and `bootstrap.yaml` are written atomically (temp file, fsync, rename, directory
  fsync), so a crash can no longer leave a torn counter that reads as corrupt. A device key created
  in a keystore that is already provisioned or holds other device keys is logged at ERROR, naming the
  role and what stops verifying; a fresh keystore keeps its first-boot info line.

  No on-disk format change: an existing keystore reads as before, and a first provision on a fresh
  keystore writes the same files with the same modes. Host-facing: none required.
- **node-shell `reset`** (feature `factory-reset`, on by default): the factory-reset engine, moved from
  a node manager unchanged in behaviour — `WipeTargets`, `component_dirs`,
  `write_provisioned_banks`, `ensure_under_root`, `execute_wipe` (same order, log dir last),
  `ShutdownKind`, `FactoryResetState`, `handle` (precheck, authorize, clear flash sessions, resolve,
  before-wipe, stop guests, synchronous wipe, schedule shutdown; `{ok, wiped, errors}` with 200/500;
  403 `factory-reset denied: …`) and `route` for `sovd_router`'s slot. The node supplies `ResetHooks`
  (`resolve`, `precheck`, `before_wipe`, `stop_guests`, `schedule_shutdown`).

  Host-facing: delete your engine copy, implement the hooks, mount `route(..)`. The moved lines now log
  with the `node_shell::reset` target (texts unchanged).
- **component-mgr** feature `dev-recovery-anchor` (off by default):
  `sovd::hsm_authorizer::dev_recovery_anchor()`, the factory-key SPKI for a deployment's development
  `extra_anchor`. Host-facing: delete your copy; enable the feature only where that anchor is meant to
  be compiled in.

  Verified: the node manager's served API (540 probes) and a real wipe of a fixture tree are identical before
  and after the move.
- **Boot vector: a signer that could not decide is an error, never a verdict.** Before, an HSM error
  while signing wrote an empty signature and reported success, and an HSM error while verifying read the
  copy as absent: `commit` returned `Ok` without committing the boot vector (after NV had already
  committed and raised the security floor), `activate` overwrote the primary at generation 1, and a
  start with the HSM not answering reseeded a good boot vector from NV (generation, sealed images,
  transaction header and trial count lost). Now `Ok(false)` (invalid) and `Err` (could not decide)
  stay apart everywhere: an invalid copy still reads as absent and is reseeded, as before; one that
  could not be verified fails the read and every verb that reads it; every write verb signs before its
  first write and fails with nothing written; `IvdBankProvider::commit` checks the boot vector can
  commit (`SystemBankManager::check_commit`) before the NV commit, so an HSM that is down fails the
  verdict with NV untouched. If the HSM goes away between the NV commit and the boot-vector commit the
  error says NV is committed and the vector still in trial; a retry completes it, and so does
  `seed_selector` at the next start (it commits a vector whose every trial row NV has committed at that
  bank, with nothing in trial in NV), so a trial boot limit cannot roll a committed update back. A trial
  boot count or boot-stage rollback record that cannot be written is logged at error level and leaves
  the previous header. With a working signer every file written and every decision is unchanged.

  A copy that could not be verified is `SelectorError::Unreadable`; one that could not be signed is
  the new `SelectorError::Unsignable`. A node binary can tell both from a filesystem error.

  Host-facing: `Signer::sign` returns `Result<Vec<u8>, SignerError>` and `Signer::verify`
  `Result<bool, SignerError>` (`SignerError::new` / `with_source`, exported next to `Signer`): an
  implementor returns `Ok(false)` only for a signature that does not verify and `Err` whenever it could
  not decide or sign — never an empty signature or `false` for an error. `HsmSelectorSigner` does this
  (an empty or non-DER signature is `Ok(false)` without asking the HSM; every HSM error is `Err`); a
  node carrying its own copy of it must make the same change or switch to
  `component_mgr::boot_selector_signer`. `SelectorBlob::signed` / `is_valid` return `Result`.
  `SelectorStore::read_transaction` and `BootRecord::legacy_transaction` return
  `Result<Option<_>, SelectorError>`; `SelectorStore::check_commit` is new (default `Ok`). Test seams:
  `SwitchableSigner` / `SignerMode`. `SystemBankManager::load` (and `MachineRegistryBuilder::build`)
  now also fails while the signer cannot verify: a node binary must fail closed — retry with
  `SystemBankManager::load_retrying(make_store, LoadRetry { attempts, delay })` (default 5 x 1 s, blocks
  the thread) for every store, not only a record store, then exit non-zero; never seed or serve over a
  vector it could not load. The boot stage has already chosen the bank, so a manager that does not
  start changes nothing on disk.

  Verified: a scripted sequence (seed, activate, trial boots, commit, activate, rollback, reseed after
  deleting the primary) with the deterministic test signer writes byte-identical files and returns
  identical values before and after.

## v0.1.29 — SOVDd v0.1.12: /v1 execute is orchestrated without x-ota-control

Tag on `b6d65fb` (2026-11-23), PR #68.

- deps: SOVDd v0.1.12 (every pin) — on `/v1`, `PUT …/updates/{id}/execute` without `x-ota-control` runs
  orchestrated (was 400 `incomplete-request`); `x-ota-control=orchestrated` stays accepted, any other
  value still answers 400 before anything runs; the component capabilities drop `x-update.control`,
  `/v1/docs` lists execute without parameters, `/.well-known/sovd-extensions` marks `x-ota-control`
  `implied_on: ["/v1"]`. `/vehicle/v1` unchanged. Host-facing: move SOVDd pins together; a `/v1` client
  may omit `x-ota-control`; a test pinning the 400 on a missing parameter, or reading
  `x-update.control`, must change.

## v0.1.28 — node-shell: mDNS goodbye on shutdown and before a reset

Tag on `bbccd45` (2026-11-23), PR #67.

- node-shell: `SovdListener::serve` caps the graceful drain at 5 s on both transports (HTTP warns
  `graceful shutdown timed out after 5 s; closing`) and sends the mDNS/DNS-SD goodbye before it returns
  — as vm-sovd does. Host-facing: `serve` now returns `Result<(), String>` (it no longer hands back the
  advertiser guard); drop the `_mdns` binding. `SovdListener::advertisement()` hands out an
  `Advertisement` whose `withdraw()` sends the goodbye now (idempotent, blocking ~1 s, shared with
  `serve`), for a reset path that ends the process without the shutdown notify.

## v0.1.27 — node-shell: the SOVD node application shell; SOVDd v0.1.11

Tag on `b532cb7` (2026-11-23), PR #66.

- deps: SOVDd v0.1.11 (every pin) — the whole status family of a node server is node-level (an embedder's
  `/v1/status/x-boot-id` is served at `/v1/components/{node}/status/x-boot-id`; its root form is 404),
  node-level data/operations collections, `CapabilityExtensions::with_v1_paths`. Host-facing: move SOVDd
  pins together; a test reading root-form status paths on a node server must use the node form.
- **node-shell** (new crate): the SOVD node application shell, moved from a node manager
  unchanged in behaviour — `ShellConfig` (the `bind`, `sovd_tls`, `sovd_mdns`, `identification`,
  `identification_prefix`, `node` keys, for `#[serde(flatten)]`), `read_ecu_id` /
  `configured_identification` / `node_topology` / `sovd_state`, `sovd_router` (SOVDd's router + vendor
  routes + `status/x-boot-id`, node status, `status/restart`, legacy restart stub, factory-reset route,
  node topology outermost), `restart_route` / `restart_response`, `SovdListener` (HTTPS from the HSM
  tls-identity leaf else HTTP, mDNS on both, graceful serve), `shutdown_on_signals`, and
  `capability_extensions` (`/v1`-only docs rows for the node status and boot id).

  Host-facing: a node binary flattens `ShellConfig` into its config (keys unchanged), deletes its
  copies, and supplies its backends, vendor routes, boot id, HSM, restart authorizer + reset action and
  factory-reset handler (verified: the node manager's served API identical before/after the move, 504
  probes on both trees).

## v0.1.26 — app leaf items from the node manager

Tag on `e1c84e3` (2026-11-23), PR #65.

- **app leaf items** moved from a node manager, unchanged in behaviour (sumo is the pattern: a
  device manager wires these, it does not carry its own copy):
  - component-factory: `HsmKeystoreActivator` (the `hsm-keystore` marker: no-op activate,
    `RequiresEcuReset`) and `builtin_activator(marker)` for the markers sumo implements;
    `partition_parts(&ComponentSpec)` (the `parts:` list as `PartitionPart`s).
  - component-mgr: `sovd::ident_data` (read-only `identData` entities over KEY=VALUE version records; the
    `IdentDataSpec` serde shape is the `ident_data:` config entry) and `boot_selector_signer`
    (`HsmSelectorSigner` / `make_selector_signer`).
  - machine-mgr: `node_update::read_or_create_boot_id(path)` (the file-backed per-boot nonce that
    survives a process re-exec); machine-mgr now depends on `uuid`.

  Host-facing: none required. A node binary deletes its copies and calls these; activator markers,
  config keys and wire responses are unchanged (verified on target hardware: the served API of the node manager
  built on this is identical to the build before the move, 408 requests on both trees).

## v0.1.25 — SOVDd v0.1.10: node topology, part read-back, orchestrated execute on /v1

Tag on `852a261` (2026-11-22), PR #61, #62, #63, #64.

- vm-sovd: SOVDd v0.1.7 — the SOVD server is advertised over mDNS / DNS-SD on both transports
  (`accessurl` scheme `http` before enrolment, `https` once the tls-identity leaf is live), using the
  sovd-mdns v0.1.6 identity rule: hostname from the TLS leaf, else `--identification`, else the OS
  hostname; TXT `identification` is `--identification` verbatim when set. New
  `--identification <id>` option; `--no-mdns` still opts out. SIGTERM / ctrl-c now shut the server
  down gracefully (5 s cap) on both transports, so the DNS-SD goodbye is sent before exit.
  Host-facing: none (all SOVDd pins move to v0.1.6; no API change consumed).
- deps: SOVDd v0.1.8 (every pin: machine-mgr, component-mgr, component-factory, vm-sovd) — opt-in
  node topology on /v1, `DiagnosticBackend::read_part` behind `GET /v1/…/updates/{id}/bulk-data/{part}`,
  sovd-mdns leaf instance only from a plain `<label>.local` SAN. Host-facing: none by the bump itself.
- deps: SOVDd v0.1.10 (every pin) — on /v1, `PUT …/updates/{id}/execute` requires
  `?x-ota-control=orchestrated` (400 `incomplete-request` without it; `automated` answers 409), and
  component capabilities carry `x-update.control`; node-level data is served under the node
  (`/v1/components/{node}/data/x-update-state`). Hierarchical-only on /v1 for a node server:
  `/v1/components` lists the node alone, and the flat member and root node-level forms answer 404
  naming the node form (no more Deprecation/Link headers); node-less servers and the legacy tree
  unchanged. vm-sovd: with `--node-id`, the node document carries the unit's identification
  (`--identification`, else the `--identification-prefix` result) as `x-identification`.
  Host-facing: /v1 clients send `x-ota-control=orchestrated` on execute, and address a node
  server's members and node-level resources by the node form only.
- component-mgr: `read_part` streams a part back exactly as received. The manifest is kept as
  received and reads back while its update lasts. A payload reads back only when the bank holds it as
  received (no decryption, no decompression ran, or a re-sent part whose bytes hash to the staged
  digest); one kept decoded answers 501 (NotSupported: the part exists, its received form is not
  kept). In practice fleet payloads are encrypted and compressed, so only the manifest reads back —
  the intended use: a client checks that its manifest upload landed before uploading the payloads.
  404 for an unknown file_id and once the part is no longer kept (update aborted / deleted, target
  bank wiped, next update started, bank file gone). New `BankProvider::open_payload_reader` (default
  Unsupported; file banks implement it); `InstallRouterDiag` forwards `read_part`. Host-facing: hosts
  that wrap the backend by hand forward `read_part`; a custom `BankProvider` may implement
  `open_payload_reader`.
- component-mgr: no vendor route renders a URL in a JSON body, so node-form requests get the root/flat
  form's body unchanged (pinned by a test); pull-update's root-form 202 `Location` is rewritten by
  SOVDd. New `gateway::gateway_router_with_state(machine, state, authorizer, trust_anchor)` — the
  gateway over a caller-built `AppState` (taken as is), so the same state can be handed to
  `sovd_api::with_node_topology`; `gateway_router` is unchanged for its callers.
- vm-sovd: `--node-id <id>` / `--node-name <name>` (default the id) serve /v1 as SOVDd node `<id>`
  in both modes (the final router wrapped in `with_node_topology`; a bad or colliding id fails
  startup). `--identification-prefix <prefix>`: identification `<prefix>-<first 16 hex of the ECU
  id>` (the hsm device id `x-ecu-id` serves), warning and falling through when there is none;
  `--identification` wins.

## v0.1.24 — SOVDd v0.1.5: restart outcome hooks; host ecu_reset refused as NotSupported

Tag on `108b6e1` (2026-11-21), PR #59, #60.

- component-mgr: a host component whose reset is the node's (`RequiresEcuReset`, no vm-service, not
  single-bank) refuses `ecu_reset` with NotSupported (501, message pointing to the node-level
  status/restart) instead of pretending; `restart_supported()` predicate (PR #59).
- deps: SOVDd v0.1.5 — /v1 `status/restart` answers 202 with no body and `Location: {entity}/status`
  (ISO 17978-3 §7.19.4); 405 precondition-not-fulfilled and no `restart` href when
  `supports_restart()` is false; 501 → `vendor-specific`/`not-supported` on both trees.
  component-mgr implements `supports_restart()` (= `restart_supported()`) and
  `ecu_reset_outcome()` (`Initiated` for vm-service guests, `Completed` otherwise);
  `InstallRouterDiag` delegates both. Host-facing: hosts that wrap the backend by hand must forward
  the two new methods.

## v0.1.23 — SOVDd v0.1.4: /v1 tree on the node, node-level verdict_scope; vendor routes on both trees

Tag on `d0f9740` (2026-11-17), PR #49, #50, #51, #52.

- vm-sovd: the plain (non-gateway) server mounts `node_verdict_router`, so `x-update-commit` /
  `x-update-rollback` (and the `x-ota-*-trials` aliases) are served there too, not only by `--gateway`.
- deps: SOVDd v0.1.4 — entity API under /v1 beside /vehicle/v1, node-level /updates, root
  capability document, x-update.verdict_scope. component-mgr authorizers return
  `sovd_api::AuthError`; a valid token without rights for the entity answers 403
  insufficient-access-rights on /v1 (401 on /vehicle/v1 as before).
- component-mgr: components whose bank provider requires an ECU reset report
  `VerdictScope::Node`; SOVDd refuses per-update verdicts on them under /v1 (409 naming the node
  operations) and serves verdict_scope "node"; /vehicle/v1 unchanged.
- component-mgr: every vendor route (`update_state_router`, `hsm_router`, `node_verdict_router`,
  `pull_update_router`, `device_id_router`) is served under /v1 as well as /vehicle/v1, so the
  node operations SOVDd's /v1 409 names (`POST /v1/operations/x-update-commit/executions`, …)
  resolve. A /v1 pull-update POST answers with a /v1 `Location`; /vehicle/v1 unchanged.
  `pull_update::PULL_OP_PATH` is replaced by `pull_update::pull_op_path(tree)`, and
  `execute_pull_update` takes the request's op path (used as the authz `path`).

## v0.1.22 — QNX: loopback only for wired hostdevs, console follows serial_log

Tag on `bb2ad95` (2026-11-04), PR #36, #37.

- vm-mgr: `QnxRunner::start()` spawns a `devb-loopback` for the rootfs, a `partitions:` entry or a
  `disks:` entry only when a non-comment `hostdev` line in the bank's `qvm.conf` names that `/dev`
  node (a leading `<`/`>` is ignored). An image the conf backs directly with `hostdev <file`
  (relative to the bank dir) gets no loopback and logs `… not wired as /dev/… in qvm.conf —
  file-backed, no loopback`, so it stays openable by the pre-launch verify and the bank seeder
  instead of `EBUSY`. A conf that wires `/dev` nodes, and an unreadable conf, keep the old behaviour
  (PR #36).
- vm-mgr (QNX runner): the per-VM qvm console file follows the VM's `serial_log` in
  vm-service.yaml when it is an absolute path; a relative one is ignored with a warning; without
  one it stays `/mnt/common-rw/log/<name>-console.log` (PR #37).

Host-facing: no config change needed on a host that has `/mnt/common-rw`. A host without it (e.g.
a secure-boot host) sets `serial_log: /var/log/mmgr/<vm>-console.log` per VM. A
bank whose `qvm.conf` uses `hostdev <file` for its rootfs and declares `partitions: []` needs a host
with this version; an older host still holds the file behind its loopback and qvm fails with
`EBUSY`.

## v0.1.21 — SOVDd v0.1.3, held updates served

Tag on `03aeb27` (2026-10-26), PR #34.

- deps: SOVDd v0.1.3 — the embedded server lists, describes and reports the updates this executor
  holds (`held_updates`) and marks parts `present`; no wire change for clients that do not use the
  listing.

Host-facing: pin bump only.

## v0.1.20 — the SOVDd hooks implemented; the staging record outlives the seal; wipe_staging

Tag on `524cfa3` (2026-10-26), PR #32.

- The three SOVDd hooks, implemented: `note_update_id` records the client's registration id (into
  the staging record when a session is open); `receive_package_part` takes a part named by its
  payload `uri`, on-medium name or `#name` as that part, in any order, under its declared digest
  (a present part is accepted with nothing written; an unresolved id keeps the unnamed intake);
  `held_updates` reports `PREPARING` / `PREPARED` from the staging record with an id and
  `EXECUTING` / `EXECUTED` from the armed bank's sealed id while its reset is pending / in trial.
  `InstallRouterDiag` forwards `note_update_id` and `held_updates` to its engine.
- `StagingRecord` gains `sealed` (serde default `false`, version unchanged): the seal marks the
  record sealed over the sealed parts and keeps it; `activate` removes it.

Host-facing:

- A host's factory reset calls `wipe_staging(set_dir)` (`component_mgr::bank_provider`) for every
  file-bank set, so the staging record and temporary payloads are forgotten with the banks.
- Partition-bank hosts' intake is addressed (order-free) when the client names its parts; a client
  that does not keeps manifest order.
- The staging record's `update_id` comes from the client's registration (`note_update_id`); the
  record now outlives the seal and is removed at activate.

## v0.1.19 — verdict operations, SOVDd v0.1.2, a half-staged update survives a restart

Tag on `35967a2` (2026-10-26), PRs #28, #29, #30.

- x-update: node verdict as `x-update-commit` / `x-update-rollback` operations (body: optional
  `nonce`); `x-update-verdict` stays as an alias until the x-ota names retire; OpenAPI and discovery
  list all three; the per-update path carriers follow SOVDd's `x-update-commit` /
  `x-update-rollback`.
- deps: SOVDd v0.1.2 (x-update contract: explicit verbs, client-owned ids; backend hooks
  `note_update_id`, `receive_package_part`, `held_updates`, implemented in v0.1.20).

A half-staged update survives a restart and a reboot as facts the node can prove: the inactive
bank's verified parts are kept and reported with their digests, a staging record beside the bank
names the update and the parts present, and the sealed bank carries the update id. The boot vector
still seals only from a complete manifest.

- Staging record: `machine-contract` gains `StagingRecord` (`version`, `update_id`,
  `node_boot_id`, `started_unix`, `parts`) and `StagedPart` (`name`, `size`, `sha256` hex), with
  `BankProvider::staging_record` / `write_staging_record` (defaulted: no record). Every part is
  noted in it before its upload is acknowledged; a seal removes it. An unreadable record reads as
  absent.
- Keep by digest, no wipe at start: `start_flash` no longer clears the target bank. At the manifest,
  each part the record names is kept when it is the on-medium part of a manifest component, its
  recorded digest is that component's `image_digest`, and the bytes still hash to it;
  `BankProvider::prune_target(bank, keep)` (defaulted to `prepare_target`) removes the rest and
  torn staging leftovers. The session tracks the components present; finalize reconciles exactly
  the absent ones. When the kept parts are every part, the bank seals at the manifest.
- An abort (DELETE) keeps the parts and the record and clears the record's `update_id`: a record
  without one is a part cache, not a held update.
- Content-addressed intake on file banks: a payload stages through
  `BankProvider::open_staging_writer`, its inner digest names the first absent component it is,
  and `commit_staged` renames it into the bank as that part, so parts arrive in any order. A
  payload matching no component is discarded and refused; one matching a present part is accepted
  and discarded. A provider that answers the new `BankError::Unsupported` keeps the sequential
  intake. Encrypted payloads still decrypt with the next absent component's context.
- IVD manifest key 7, `update_id` (optional, `IVD_MANIFEST_VERSION` unchanged; a manifest without
  it encodes byte-identically). `sign_bank_crypto_at` / `sign_bank_with_files_crypto_at` take
  `update_id: Option<&str>`; both sealers pass the staging record's id.
- `banks[]`: each bank carries `sealed` and, when known, `update_id` (`BankContents` gains both).
  An inactive bank with no manifest but a staging record reports the record's parts with
  `sealed: false` instead of `null`.

Host-facing:

- Verdict operations: hosts inherit the routes through `node_verdict_router`; no host change beyond the pin.
- SOVDd v0.1.2 refuses a registration without `id` (400): every client that registers an update sends
  one (the sumo-sovd engine already does).
- File-bank hosts gain `<set>/staging-<bank>.cbor` and `<set>/staging/<bank>/` beside the bank
  dirs; a payload is renamed from the latter into the bank, so both must sit on the bank's
  filesystem.
- Partition-bank hosts gain the record beside the metadata dir.
- Out-of-tree code that builds `BankContents` adds `update_id` and `sealed`; an exhaustive match on
  `BankError` adds `Unsupported`. Direct callers of the two `_at` signers add the `update_id`
  argument.

## v0.1.18 — the seed anchors only its own baseline; the vector rolls back before NV

Tag on `048820d` (2026-10-26), PR #26.

A vector with no committed copy is anchored only when it is the seed's own baseline, and a rollback
verdict rolls the boot vector back before NV, so neither path can settle or split a standing trial.

- `MachineRegistry::seed_selector` anchors a vector with no committed copy only when every row it has
  an NV view of stands at the floor the seed would itself stage (`active_bank` where NV is
  committed, `active_bank.other()` where NV is in trial): the seed's own stopped anchor, or a
  committed baseline whose committed copy was lost. Any row not at that floor it leaves alone: it
  writes nothing and logs one ERROR line naming each such id, its row's bank and the floor. A row at
  NV's `active_bank` while NV is in trial is a standing trial whose committed copy is gone;
  committing there would settle the trial before any verdict and raise the floor for good, and a
  later rollback verdict would find no trial in the vector. After the anchor, every id NV holds in
  trial whose row is at the floor is re-armed, not only the ids that were missing.
- `IvdBankProvider::rollback` checks the NV precondition first (`rollback_target`, refusing a
  committed set with the error `ota::rollback` gives), then rolls the boot vector back, then NV. The
  vector is the authority: a vector rollback that fails (`NoTrial`, e.g. a torn committed copy)
  leaves NV untouched and in trial, and the caller sees the error.

Host-facing:

- Call `seed_selector` at every start and keep no gate of your own: the seed is idempotent and
  decides which case holds. This supersedes the v0.1.16 line asking hosts to gate the seed on
  `is_empty() || !missing_entries(ids).is_empty()`; that gate hid the same hole whenever an id was
  missing.
- No wire or API change.

## v0.1.17 — reads carry an error channel; the committed copy is the copy at the floor

Tag on `969fba2` (2026-10-25), PR #24.

An unreadable boot record is no longer mistaken for an absent one, and the committed copy is defined
by the floor, not by which copy of the record holds it.

- Reads carry an error channel: `BootRecord::read(copy)` and `SelectorStore::read_primary` /
  `read_secondary` return `Result<Option<BootVector>, SelectorError>`. `Ok(None)` is absent (erased,
  never written, or a failed authenticity check); `Err` is a record that could not be read (I/O,
  allocation, a check that could not run). `SelectorError::Unreadable(String)` is new, for a backend
  that reports a check could not run.
- `RecordSelectorStore` propagates the record's `Err` from every verb that reads a copy, and an I/O
  error on its own side files (`rows`, `committed`, `transaction`) likewise; `commit` over an
  unreadable primary is `Err`, never `Ok`. A side file that is missing, does not parse or fails
  verification is still absent; `read_transaction` logs an unreadable header and reads none.
  `FileBootRecord::read`: a missing file is `Ok(None)`, one that exists and cannot be read is
  `Err(Io)`; a parse or verification failure is still absent.
- `SystemBankManager::load` and `MachineRegistryBuilder::build` return `Result`: an unreadable record
  no longer loads as an empty vector, is never seeded, never commits and is never read as a
  boot-stage rollback. `try_build` returns `BuildError` (duplicate id or unreadable store);
  `BootManager::process_boot` returns `BootError::Selector` instead of falling through to NV.
  `SystemBankManager::committed_generation()` is new.
- `RecordCopy::Secondary` is the committed copy: the rows at the floor, whichever copy of the record
  holds them; absent when no copy is at the floor. A vector with no committed copy is not a trial
  the node can resolve by rollback: `seed_selector` anchors it by committing what stands, adding any
  missing ids first through the ordinary seed sequence (an NV trial among them is re-armed over the
  new floor) — even when every id is present and matches NV. A committed vector in trial is still
  left alone.
- Executable contracts (feature `test-seams`): `contract::exercise_with_ids(&store, ids)` and
  `contract::exercise_record_with_ids(&record, ids)` write the ids the record already holds plus
  `ids`, compare generations and banks only (never images), and `exercise_record` reads the committed
  copy between activate and commit. `exercise` / `exercise_record` keep their signatures (over `os`,
  `vm1`). `InMemoryBootRecord` gains `set_fail_reads` and `tear_committed`.

Host-facing: three signature changes. `BootRecord::read` returns
`Result<Option<BootVector>, SelectorError>` (a record maps "could not determine" to `Err`, never to
`None`); `SelectorStore::read_primary` / `read_secondary` likewise; `SystemBankManager::load` and
`MachineRegistryBuilder::build` return `Result<_, SelectorError>` — retry or fail the boot-vector
subsystem on `Err`, never serve a fabricated empty vector. A host record runs
`exercise_record_with_ids` with the ids it routes. The file store's bytes and layout are unchanged.

## v0.1.16 — boot record seam: the record holds what boots, sumo holds the rest, tied by generation

Tag on `f694bf3` (2026-10-25), PR #22.

A boot stage's record carries only the rows it routes and must stay minimal. The manager rows
(components whose bank the machine manager selects after boot) and the transaction header live in
sumo's own side files, tied to the record by generation, through one mechanism for every port.

- `BootRecord` is the host seam, the only hardware-dependent surface a port implements:
  `routes(id)`, `read(copy)`, `activate(rows) -> generation` (the record issues it), `commit`,
  `rollback`, and a migration hook `legacy_transaction`.
- `RecordSelectorStore<R: BootRecord>` implements the unchanged `SelectorStore` over any record plus
  three signed side files: `rows` (manager rows at the primary generation), `committed` (at the
  floor), `transaction` (header only, byte-identical to v0.1.15). Record first throughout; manager
  rows are never written empty as a fallback; a header with no rows at its generation is never read
  as a boot-stage rollback. After a boot-stage rollback the manager rows follow the committed copy, so
  the whole node rolls back and `SystemBankManager::load` records `rolled_back / boot_stage` with the
  trial-boot count kept.
- `FileSelectorStore` is the same adapter over a `FileBootRecord` that routes every component: same
  API, same bytes in `primary` / `secondary` / `transaction`; `rows` and `committed` appear with
  empty entries.
- `MachineRegistry::seed_selector` adds only the ids a non-empty vector lacks, at their NV floor,
  and writes nothing while a trial stands. `SystemBankManager::missing_entries(ids)` gates it.
- Executable contracts (feature `test-seams`): `nv_store::selector::contract::exercise(&store)`,
  now also run over a record that routes part of the vector, and `contract::exercise_record(&record)`.

Host-facing: a file-store host changes nothing. A host with its own boot-stage record implements
`BootRecord`, builds `RecordSelectorStore::over(record, dir, signer)`, gates the seed on
`is_empty() || !missing_entries(ids).is_empty()` (superseded in v0.1.18: call the seed at every
start), and removes file-era `primary` / `secondary` from
the directory at the switch. Every seal, VM-only updates included, is one record activate (one step
of the record's generation counter). SOVDd pin stays v0.1.1.

## v0.1.15 — store contract v2: the store issues the generation, keeps the header apart, speaks in verbs

Tag on `53edca2` (2026-10-25), PR #21.

- `SelectorStore` is one contract for every store: `read_primary` / `read_secondary -> BootVector`,
  `activate(entries, header) -> generation`, `commit()`, `rollback(header) -> generation`,
  `read_transaction` / `write_transaction`. The store issues the generation and authenticates its
  contents; the manager adopts what the store returns and never computes a generation or signs.
- The transaction header is its own slot, tied to the primary generation (two durability classes:
  what boots, under anti-rollback, and what the node observed). Reference file store: `primary`,
  `secondary`, `transaction`.
- Who decides what: the orchestrator decides, the node executes and observes, the boot stage restores
  the committed copy and nothing else. Two counters by design: the boot stage's boot counter is the
  safeguard against bricking; the header's `trial_boots` is information, with the host limit an
  optional policy strictly below the boot stage's bound. No failed write verb leaves a header above
  the primary, so a header above the primary on a committed vector is the boot stage's rollback and
  is recorded at load as `rolled_back / boot_stage`, count kept.
- x-update-state `resolution.reason` gains `boot_stage`.

Host-facing: `FileSelectorStore::new(dir, signer)` (the signer that used to go to
`SystemBankManager::load`); `SystemBankManager::load(store)`;
`MachineRegistryBuilder::with_selector_store(store)`; `with_legacy_slot_map` unchanged. No device
migration: a v0.1.14 `primary` with the embedded header is read as the header until the next header
write creates `transaction`. SOVDd pin stays v0.1.1.

## v0.1.14 — boot vector carries the node transaction; the node reports facts, the orchestrator converges

Tag on `e0325c4` (2026-10-23), PRs #12–#20.

- Boot vector: fallible store with persist-then-mutate (#14); manifest-shaped entries keyed by
  host-owned component id with sealed images, opt-in legacy slot map (#15); transaction header in the
  primary copy (armed boot id, trial boot count, resolution) inside the signed digest (#17, #19).
- One bounded autonomous act: node trial-boot bail-out at a host-set limit, rollback-all through the
  vector, reason recorded; the node never commits by itself (#17).
- x-update-state: `banks[]` per component (active/inactive bank contents, `in_trial`,
  `pending_reset`, `install_boot_id`), `trial_boots`, `trial_boot_limit`, `resolution` (#16, #17, #18).
- Installed manifest records its install boot id (key 6, version unchanged) (#18).
- Readers derive from component facts; the session id is gone; two derived gates (#20). NV boot
  state and update session are still written (dual-run); they leave in a later tag.
- Per-VM QEMU options in the bank's `vm-config.yaml` (#12, #13).

Host-facing: `NodeCoordinator::new()` (no slot map) + `with_system_bank` + `with_trial_boot_limit`;
`update_state_router(coord, machine)`; `SystemBankManager::seal(armed_boot_id)` / `rollback(reason)`;
`MachineRegistry::observe_node_boot(&coord)` once after the store is loaded, before serving;
`FileSelectorStore::with_legacy_slot_map` for hosts whose boot stage reads the legacy slot map.
SOVDd pin stays v0.1.1.

## v0.1.13 — x-update aliases on the node routers

Tag on `063c2b5` (2026-10-23), PRs #10, #11.

- `POST /vehicle/v1/operations/x-update-verdict/executions` and
  `GET /vehicle/v1/data/x-update-state` (with `node_boot_id`) as aliases on the node routers.
- SOVDd pinned to v0.1.1.

## v0.1.12 — drop the on-device commit veto

Tag on `fc7ff7d` (2026-10-22).

- The node reports `reboot_owed` and `rebooted_since_arming`; the orchestrator decides commit or
  rollback. No boot witness is required to commit.

Host-facing (breaking): `node_verdict_router(machine)` and `gateway_router` drop the `NvStore` and
`NodeCoordinator` parameters; pass the node boot id via `NodeCoordinator::with_node_boot_id`.
`NvStore::confirm_running_bank` is legacy.
