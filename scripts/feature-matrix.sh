#!/usr/bin/env bash
#
# Feature matrix — the combinations CI has to keep green.
#
#     bash scripts/feature-matrix.sh                 # fixed runs + powerset
#     bash scripts/feature-matrix.sh --fixed-only    # fixed runs only
#
# Every combination is clippy-with-`-D warnings` (not a bare build): a feature
# that is off must not leave dead code, unused imports or unreachable arms
# behind. The policy these combinations enforce is in docs/features.md.
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
