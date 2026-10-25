# Changelog

Every tag on this repository is annotated with the notes below, and the matching GitHub release
carries the same text. A change that will be tagged adds its entry under **Unreleased** in the same
pull request; cutting the tag renames the heading. Tags are immutable: a mistake gets a new tag,
never a moved one. Consumers pin crates by `tag = "vX.Y.Z"`; the host-facing lines of each entry are
what a consumer has to touch when it moves its pin.

## Unreleased

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
`is_empty() || !missing_entries(ids).is_empty()`, and removes file-era `primary` / `secondary` from
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
