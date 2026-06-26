# sumo-machine-manager Index

Rust workspace for platform-agnostic A/B bank management, VM lifecycle, SUIT OTA, SOVD diagnostics, HSM, and NV storage.

## Where to look

- `README.md` — quick start, crate map, concepts, target maturity.
- `ARCHITECTURE.md` — detailed architecture and current design decisions.
- `CLAUDE.md` — contributor map and command summary.
- `Cargo.toml` — workspace members and dependency shape.
- `crates/machine-mgr/` — `Component` trait and registry abstraction.
- `crates/component-mgr/` — SUIT validation, OTA engine, SOVD adapter.
- `crates/vm-service/` — QEMU/qvm lifecycle and VM config.
- `crates/nv-store/`, `crates/hsm/`, `crates/vhsm-ssd/` — persistence and crypto/HSM layers.
- `example/` — local generated firmware/server smoke flow.
- `specs/` — bank state, disk layout, nv-store and app-installation specs.

## Essential commands

No component-local `mise` file is present; use Cargo and scripts from this submodule root.

```bash
cargo build
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo run --example build
./example/run.sh --fresh
```

Finding commands:

```bash
rg --files -g 'Cargo.toml' -g 'README*' -g 'ARCHITECTURE.md' -g 'CLAUDE.md' -g 'specs/**'
rg -n "Component trait|BankSet|SecurityProvider|SystemBankManager|ComponentBackend|OTA|SUIT|HSM|NV" crates example specs README.md ARCHITECTURE.md CLAUDE.md
```

## Stack

- Rust 2021 workspace; SOVD server crates, SUIT crates, QEMU/qvm service, HSM/vHSM, NV store.
- YAML/TOML example configuration and generated SUIT artifacts.

## Guardrails

- `machine-mgr::Component` is the update abstraction; do not treat `component-mgr` as the base layer.
- Use `sovd-core` enums and typed models; do not hand-build JSON responses.
- NV committed flags and bank selectors are source-of-truth after power cycle.
- Keep platform-specific concrete implementations behind traits.

## Gotchas

- Example fresh runs wipe local NV store state.
- Flash requires programming session plus security unlock before upload/commit paths.
- QNX support is via traits/stubs unless using supernova platform crates.

## Missing docs/specs to watch

- Compile-time Banked/Singleshot type split is deferred in architecture notes.
- Production bootloader/raw boot-vector contract is outside this repo.
