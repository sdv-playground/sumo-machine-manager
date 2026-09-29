# Native Process Integration

The `vm-mgr` crate has an opt-in `process` backend for native integration
tests. It launches a real child process from the selector-resolved bank and
passes this context to it:

- `SUMO_VM_NAME`
- `SUMO_VM_BANK_DIR`

The backend does not replace QEMU or QNX. It preserves VM lifecycle behavior
while avoiding a hypervisor for fast tests.

Run the focused coverage with:

```bash
cargo test -p vm-mgr --features process
cargo test -p vm-shim
```

`vm-shim` is a portable guest process for the next integration layer. It uses
the existing HTTP device-transport wire format and supports deterministic
health modes:

```text
healthy
never-ready
stale-heartbeat
exit-immediately
```

The Supernova process-level test can consume this backend after the host
composition bumps its pinned `vm-mgr` dependency to a revision containing
the `process` feature. Until then, do not add a local Cargo path override to a
committed lockfile; the native test should consume the same published revision
used by the Docker image.
