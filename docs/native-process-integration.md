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

`cargo test -p vm-shim` starts the real child with `VmManager` and an HTTP
device transport, and checks all four health modes. The host composition's
opt-in test runs from `supernova-machine-manager` with:

```bash
cargo test --features native-process-tests --test native_process
```
