#!/usr/bin/env bash
#
# Feature matrix — the combinations CI has to keep green.
#
#     bash scripts/feature-matrix.sh                 # fixed runs + powerset
#     bash scripts/feature-matrix.sh --fixed-only    # fixed runs only
#
# Every feature combination is clippy-with-`-D warnings` (not a bare build): a
# feature that is off must not leave dead code, unused imports or unreachable
# arms behind; one default-features `cargo test` run executes the tests those
# clippy passes only compile. The policy these combinations enforce is in
# docs/features.md.
#
# The fixed runs are cheap enough for every push; the powerset multiplies the
# build by ~10, so CI runs it on a schedule instead (.github/workflows/
# feature-matrix.yml). `--fixed-only` is that split — not a way to skip a
# failure.
set -uo pipefail

cd "$(dirname "$0")/.."

fixed_only=0
case "${1:-}" in
    --fixed-only) fixed_only=1 ;;
    "") ;;
    *) echo "usage: $0 [--fixed-only]" >&2; exit 2 ;;
esac

failed=0

run() {
    local label="$1"
    shift
    echo
    echo "=== ${label} ==="
    echo "\$ $*"
    if "$@"; then
        echo "PASS: ${label}"
    else
        echo "FAIL: ${label}"
        failed=1
    fi
}

run "no default features" \
    cargo clippy --workspace --all-targets --no-default-features -- -D warnings
run "default features" \
    cargo clippy --workspace --all-targets -- -D warnings
run "all features" \
    cargo clippy --workspace --all-targets --all-features -- -D warnings
# The tests themselves. Clippy `--all-targets` above COMPILES every test but
# never runs one — until 2026-09-23 no CI job executed `#[test]` functions at
# all, so a test could fail on main for weeks unnoticed. One run, default
# features (the shape every deployment ships); the feature corners above stay
# clippy-only to bound the wall clock.
run "tests (default features)" \
    cargo test --workspace

# Slot-vocabulary guard (v0.1.2). A bank slot is a number a component is
# constructed with; which slot means what lives in the platform profile
# (supernova), never here. The named constants, the name parser and the
# id/name/dir tables were retired in v0.1.2 — this keeps them from creeping
# back. The `nv_store::slots` test fixtures (HSM/OS/…, `test-seams` only) are
# deliberately outside the pattern.
run "no slot vocabulary in the library" \
    bash -c '! git grep -n -E "BankSet::(Hsm|Bootloader|Os|Rt|Vm1|Vm2)\b|pub const (Hsm|Bootloader|Os|Rt|Vm1|Vm2): BankSet|BankSet::from_str|bank_set_for_id|for_well_known|component_aliases" -- crates services tools'

# machine-contract must stay thin: the contract every out-of-tree implementer
# builds against may depend on nv-store and serde and nothing else — no
# sovd-core, tracing, async-trait, tokio, serde_json, bytes, futures.
# `--depth 1` is load-bearing: nv-store's OWN closure legitimately contains
# tracing / serde_json / sha2 / hex, and an implementer takes nv-store anyway
# (that is where `Bank` / `BankSet` come from). What this guards is what
# machine-contract itself declares, as an ALLOWLIST: the crate itself,
# nv-store and serde. Any other direct dependency — whatever its name — is
# printed and fails the run; a failing `cargo tree` fails it too.
run "machine-contract stays dep-light" \
    bash -c 'out=$(cargo tree -p machine-contract -e normal --depth 1 --prefix none) && ! printf "%s\n" "$out" | grep -v -E "^(machine-contract|nv-store|serde) "'

# Same allowlist discipline for hsm-supervisor, for the same reason: a node that
# only needs to PARENT the two HSM daemons must not have to link a SOVD server to
# do it. Allowlist: the crate itself, hsm, libc, tracing. Anything else printed
# fails the run — in particular sovd-core / tokio / axum creeping in would mean
# the extraction from supernova's main.rs had quietly re-coupled.
run "hsm-supervisor stays dep-light" \
    bash -c 'out=$(cargo tree -p hsm-supervisor -e normal --depth 1 --prefix none) && ! printf "%s\n" "$out" | grep -v -E "^(hsm-supervisor|hsm|libc|tracing) "'

# Same for host-reboot: resetting the node this process runs on is libc + a log
# line, and a node that needs it must not link an OTA engine to get it. Allowlist:
# the crate itself, machine-contract (the `HostReboot` seam it fires and a board
# implements out of tree — dep-light by its own guard above), libc, tracing.
#
# NOTE what this does NOT cover: the substance of that crate is behind
# `cfg(target_os = "nto")`, which no run in this file compiles. Holding that arm
# needs the SDP plus nightly + `-Zbuild-std`; it is verified by
# `cargo +nightly clippy -p host-reboot --target aarch64-unknown-nto-qnx710
# -Zbuild-std --all-targets -- -D warnings` and is not wired into CI yet. It is
# not theoretical: the QNX-only `catch_unwind` needed `AssertUnwindSafe` for a
# non-`RefUnwindSafe` `Arc<dyn Fn()>`, and the host build could not see it.
run "host-reboot stays dep-light" \
    bash -c 'out=$(cargo tree -p host-reboot -e normal --depth 1 --prefix none) && ! printf "%s\n" "$out" | grep -v -E "^(host-reboot|machine-contract|libc|tracing) "'

# host-clock implements two machine-contract seams over POSIX clock calls. The
# allowlist adds machine-contract and nothing else — in particular NOT
# component-mgr, which is where those two traits used to live and is exactly the
# coupling the seam move was for. `--depth 1` again: machine-contract's own
# closure (nv-store, serde) is legitimate and an implementer takes it anyway.
run "host-clock stays dep-light" \
    bash -c 'out=$(cargo tree -p host-clock -e normal --depth 1 --prefix none) && ! printf "%s\n" "$out" | grep -v -E "^(host-clock|machine-contract|libc|tracing) "'

# The other direction of the same seam, and the one a careless wiring change would
# actually take: component-mgr must NOT depend on the platform impls. Its
# `sovd::hsm_authorizer` needs a floor advance to reach the host's clock, and takes
# it as an injected `dyn FloorSink` precisely so that need does not become an edge —
# a `host-clock` dependency here would make every consumer of the OTA engine link
# `clock_settime`, and `host-reboot` would do the same for `sysmgr_reboot`. This is a
# DENYLIST, not an allowlist: component-mgr legitimately has ~30 direct deps, and
# enumerating them would fail on every unrelated addition and get deleted.
run "component-mgr does not depend on the platform impls" \
    bash -c 'out=$(cargo tree -p component-mgr -e normal --depth 1 --prefix none) && ! printf "%s\n" "$out" | grep -E "^(host-clock|host-reboot) "'

# `hsm` with `suit` ON and `crypto` OFF — a corner NO run above can reach. The
# three workspace-wide runs unify `crypto` on (component-mgr turns it on), and
# `--no-default-features` turns `suit` off as well, so the combination had never
# been compiled until hsm-supervisor took a default-features dep on hsm: two
# `crypto`-only imports in `hsm/src/ivd.rs` had been sitting unused-in-this-corner
# the whole time. `--lib` is load-bearing — hsm-supervisor's dev-dependencies ask
# for `crypto`, so `--all-targets` would unify it back on and lose the corner.
run "hsm with suit but no crypto" \
    cargo clippy -p hsm-supervisor --lib -- -D warnings

# The opt-in container/OCI server build — the one deployments with a container
# runtime ship. Proves the forwarding chain vm-sovd -> component-factory ->
# component-mgr -> app-mgr actually resolves.
run "vm-sovd with container" \
    cargo build -p vm-sovd --features container

# container ON with sovd-docs-hook OFF — the combination the three runs above
# CANNOT reach. They cover (hook off, container off), (hook on, container off)
# and (hook on, container on); this is the fourth corner. It is also a real
# deployment shape: a headless container node (no hypervisor, no banks, soft
# HSM) wants the container routes and has no use for the vendor docs surface.
# See docs/componentization.md, "The rp5 case".
run "vm-sovd with container, no docs hook" \
    cargo clippy --package vm-sovd --all-targets \
    --no-default-features --features container -- -D warnings

# `cargo hack` (install with `cargo install cargo-hack`) walks EVERY feature
# combination of the crates that own or forward `container`, which the three
# workspace-wide runs above can't reach on their own — Cargo unifies features
# across a build graph, so a workspace-wide run cannot compile a crate with a
# feature OFF once any member turns it on. Skipped with a note when it isn't
# installed, so the matrix still runs on a bare toolchain.
#
# 10 combinations today (app-mgr 2, component-mgr 6, component-factory 2).
# cargo-hack enumerates `default` as a feature of its own, which is why
# component-mgr's 2 features yield 6 runs and not 2^2.
if [ "${fixed_only}" -eq 1 ]; then
    echo
    echo "SKIP: cargo-hack feature powerset — --fixed-only requested."
elif cargo hack --version >/dev/null 2>&1; then
    for crate in app-mgr component-mgr component-factory; do
        # `--all-targets` belongs AFTER the subcommand: cargo-hack forwards only
        # what follows `clippy` to clippy, and treats anything before it as its
        # own flag — so `--all-targets clippy` built the invalid
        # `cargo --all-targets clippy` and every powerset run died on the first
        # combination. Latent until cargo-hack was actually installed.
        run "cargo hack powerset: ${crate}" \
            cargo hack --package "${crate}" --feature-powerset clippy --all-targets -- -D warnings
    done
else
    echo
    echo "SKIP: cargo-hack feature powerset (app-mgr, component-mgr, component-factory)"
    echo "      — cargo-hack is not installed (\`cargo install cargo-hack\`)."
fi

echo
if [ "${failed}" -ne 0 ]; then
    echo "feature matrix: FAIL"
    exit 1
fi
echo "feature matrix: PASS"
