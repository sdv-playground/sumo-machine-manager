# Example: SUIT Firmware Envelopes

Generate demo artifacts (signing keys + signed SUIT envelopes with 1MB dummy firmware):

```bash
cargo run -p component-mgr --example build_hsm_keys
```

This creates (names reflect the current `cargo run -p component-mgr --example build_hsm_keys` output —
check `output/` if the versioning scheme drifts):

| File | Component | Use case |
|------|-----------|----------|
| `output/vm1-v1.0.0.suit` | vm1 | Initial flash |
| `output/vm1-v1.1.0.suit` | vm1 | Upgrade (same secver, fleet test) |
| `output/vm1-v1.2.0.suit` | vm1 | Upgrade with secver=2 |
| `output/vm1-crl-secver2.suit` | vm1 | CRL (raises anti-rollback floor) |
| `output/vm2-v1.0.0.suit` | vm2 (QNX) | Initial flash |

## Quick start

```bash
# Start SOVD server (generates keys on first run):
./example/run.sh

# Or fresh start:
./example/run.sh --fresh
```

Then open SOVD Explorer and connect to `http://localhost:4000`.

## Simulate upgrade flow

1. Upload `vm1-v1.0.0.suit` via the Software tab → finalize → activate → commit
2. Upload `vm1-v1.2.0.suit` → finalize → activate → commit (upgrade, secver 2)
3. Try uploading `vm1-v1.0.0.suit` again → should be rejected (anti-rollback)

Same flow works for vm2 independently.
