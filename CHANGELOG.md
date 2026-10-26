# Changelog

Every tag on this repository is annotated with the notes below, and the matching GitHub release
carries the same text. A change that will be tagged adds its entry under **Unreleased** in the same
pull request; cutting the tag renames the heading. Tags are immutable: a mistake gets a new tag,
never a moved one. Consumers pin crates by `tag = "vX.Y.Z"`; the host-facing lines of each entry are
what a consumer has to touch when it moves its pin.

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
