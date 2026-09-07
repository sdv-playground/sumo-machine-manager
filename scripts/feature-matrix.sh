#!/usr/bin/env bash
#
# Feature matrix — the combinations CI has to keep green.
#
#     bash scripts/feature-matrix.sh
#
# Every combination is clippy-with-`-D warnings` (not a bare build): a feature
# that is off must not leave dead code, unused imports or unreachable arms
# behind. The policy these combinations enforce is in docs/features.md.
set -uo pipefail

cd "$(dirname "$0")/.."

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

# `cargo hack` (install with `cargo install cargo-hack`) walks EVERY feature
# combination of the crates that own or forward `container`, which the three
# workspace-wide runs above can't reach on their own. Skipped with a note when
# it isn't installed, so the matrix still runs on a bare toolchain.
if cargo hack --version >/dev/null 2>&1; then
    for crate in app-mgr component-mgr component-factory; do
        run "cargo hack powerset: ${crate}" \
            cargo hack --package "${crate}" --feature-powerset --all-targets clippy -- -D warnings
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
