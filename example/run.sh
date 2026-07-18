#!/bin/bash
# vm-mgr boot loop — simulated bootloader
#
# Syncs sumo-rs dependencies, generates SUIT signing keys and demo firmware,
# factory-inits the NV store, starts the SOVD server.
#
# The SOVD REST API defaults to http://0.0.0.0:4000 (SOVD Explorer default).
# Writes are authorized by the JWT bearer token at the SOVD layer — there is
# no seed/key security helper (that surface is retired).
#
# Usage:
#   ./example/run.sh                        # factory-init + SOVD server only
#   ./example/run.sh --fresh                # wipe NV store first
#   ./example/run.sh --profile <p> --images <dir>  # full boot loop + SOVD
#
# Examples:
#   Terminal 1: ./example/run.sh
#   Terminal 2: open SOVD Explorer -> connect to http://localhost:4000

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FIRMWARE_DIR="$ROOT_DIR/example/factory"
NV_PATH="${VM_MGR_NV:-/tmp/vm-mgr-nv.bin}"
KEYS_DIR="$ROOT_DIR/example/keys"
TRUST_ANCHOR="$KEYS_DIR/signing.pub"

# Defaults
SOVD_ADDR="${VM_MGR_SOVD_ADDR:-0.0.0.0:4000}"
PROFILE=""
NO_INIT=false
FRESH=false
EXTRA_ARGS=()

# HSM (out-of-process link-B backend) defaults. The backend (hsm-sim-service) is
# the single source of HSM crypto + provisioning; vhsm-ssd (guest-facing) and
# vm-sovd (host-facing) both CONNECT to its link-B Unix socket. Decision B: the
# connectors own no backend lifecycle — the backend is spawned FIRST, separately.
HSM_KEYSTORE="${VM_MGR_HSM_KEYSTORE:-/tmp/vm-mgr-vhsm-keys}"
HSM_SOCK="${VM_MGR_HSM_SOCK:-$HSM_KEYSTORE/hsm-backend.sock}"
HSM_PORT="${VM_MGR_HSM_PORT:-5100}"
VHSM_RUNTIME="$ROOT_DIR/target/vhsm-runtime"
VHSM_POLICY_DIR="$VHSM_RUNTIME/policy"
VHSM_BOOTSTRAP="$VHSM_RUNTIME/bootstrap.yaml"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-init)
            NO_INIT=true
            shift
            ;;
        --fresh)
            FRESH=true
            shift
            ;;
        --profile)
            PROFILE="$2"
            EXTRA_ARGS+=("$1" "$2")
            shift 2
            ;;
        --nv)
            NV_PATH="$2"
            shift 2
            ;;
        --addr)
            SOVD_ADDR="$2"
            shift 2
            ;;
        --firmware-dir)
            FIRMWARE_DIR="$2"
            shift 2
            ;;
        *)
            EXTRA_ARGS+=("$1")
            shift
            ;;
    esac
done

# Fresh start — remove NV store
if [ "$FRESH" = true ] && [ -f "$NV_PATH" ]; then
    echo "[vm-mgr] removing old NV store: $NV_PATH"
    rm -f "$NV_PATH"
fi

# 1. Sync sumo-rs dependencies
echo "[vm-mgr] syncing sumo-rs dependencies..."
cargo update --manifest-path "$ROOT_DIR/Cargo.toml" \
    -p sumo-onboard -p sumo-crypto -p sumo-codec --quiet 2>/dev/null || true

# 2. Build workspace + examples
echo "[vm-mgr] building workspace..."
cargo build --manifest-path "$ROOT_DIR/Cargo.toml" --quiet
# hsm-sim-service (the link-B backend) has required-features = ["crypto"], so a
# plain workspace build skips it — build it explicitly.
echo "[vm-mgr] building link-B HSM backend (hsm-sim-service)..."
cargo build --manifest-path "$ROOT_DIR/Cargo.toml" --quiet \
    -p hsm-sim-backend --bin hsm-sim-service

# 3. Generate SUIT keys and demo firmware (if keys don't exist)
if [ ! -f "$TRUST_ANCHOR" ]; then
    echo "[vm-mgr] generating SUIT signing keys and demo firmware..."
    bash "$SCRIPT_DIR/build.sh"
else
    echo "[vm-mgr] using existing keys in $KEYS_DIR"
fi

RUNNER="$ROOT_DIR/target/debug/vm-runner"
DIAGSERVER="$ROOT_DIR/target/debug/vm-diagserver"
SOVD="$ROOT_DIR/target/debug/vm-sovd"
BACKEND="$ROOT_DIR/target/debug/hsm-sim-service"
VHSM_SSD="$ROOT_DIR/target/debug/vhsm-ssd"

# 4. Factory init (unless --no-init or NV already exists with data)
if [ "$NO_INIT" = false ]; then
    echo "[vm-mgr] factory init from $FIRMWARE_DIR"
    "$DIAGSERVER" "$NV_PATH" factory-init "$FIRMWARE_DIR" --runner-path "$RUNNER"
    echo ""
fi

# 5. Cleanup handler — reaps every process this script owns, including the
#    externally-spawned link-B backend (the connectors never reap it themselves).
SOVD_PID=""
BACKEND_PID=""
VHSM_PID=""
cleanup() {
    [ -n "$SOVD_PID" ] && kill "$SOVD_PID" 2>/dev/null && wait "$SOVD_PID" 2>/dev/null
    [ -n "$VHSM_PID" ] && kill "$VHSM_PID" 2>/dev/null && wait "$VHSM_PID" 2>/dev/null
    [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null && wait "$BACKEND_PID" 2>/dev/null
}
trap cleanup EXIT

echo ""
echo "[vm-mgr] NV store:         $NV_PATH"
echo "[vm-mgr] Trust anchor:     $TRUST_ANCHOR"
echo "[vm-mgr] HSM backend:      link-B @ $HSM_SOCK (hsm-sim-service)"
echo "[vm-mgr] vHSM daemon:      127.0.0.1:$HSM_PORT (vhsm-ssd, connect-only)"
echo "[vm-mgr] SOVD:             http://${SOVD_ADDR/0.0.0.0/localhost}"
echo ""
echo "[vm-mgr] SOVD Explorer settings:"
echo "  Server URL:   http://${SOVD_ADDR/0.0.0.0/localhost}"
echo ""
echo "[vm-mgr] Flash flow: upload → prepare → execute → commit (no unlock dance)"
echo ""

# 6. Start the link-B HSM backend FIRST (the single source of HSM crypto +
#    provisioning), then the connectors. Both vhsm-ssd and vm-sovd CONNECT to its
#    socket; neither spawns nor reaps it (this script does, via cleanup()).
echo "[vm-mgr] starting link-B HSM backend (hsm-sim-service) on $HSM_SOCK..."
mkdir -p "$HSM_KEYSTORE"
"$BACKEND" --keystore "$HSM_KEYSTORE" --listen "$HSM_SOCK" \
    > /tmp/vm-mgr-hsm-backend.log 2>&1 &
BACKEND_PID=$!
# Wait for the backend to bind its link-B socket before starting any connector.
for _ in $(seq 1 50); do [ -S "$HSM_SOCK" ] && break; sleep 0.1; done
if [ ! -S "$HSM_SOCK" ]; then
    echo "[vm-mgr] ERROR: link-B HSM backend never bound $HSM_SOCK — see /tmp/vm-mgr-hsm-backend.log" >&2
    exit 1
fi

# 7. Start vhsm-ssd (guest-facing v3 vHSM daemon) in connect-only mode — it
#    attaches to the pre-spawned backend over link-B and serves guests on loopback
#    TCP. Its "link-A" inputs are a policy dir (guest IAM) + a bootstrap-state; a
#    minimal policy is generated here for the dev rig (no guests run by default).
mkdir -p "$VHSM_POLICY_DIR/roots"
cat > "$VHSM_POLICY_DIR/policy.yaml" <<'YAML'
version: 1
statements:
  - principals: [vm1]
    handles: [system, jwt-signing]
    ops: [get-random, key-generate, sign, verify, get-pubkey]
YAML
if [ -x "$VHSM_SSD" ]; then
    echo "[vm-mgr] starting vhsm-ssd (connect-only) on 127.0.0.1:$HSM_PORT..."
    "$VHSM_SSD" \
        --keystore "$HSM_KEYSTORE" \
        --policy-dir "$VHSM_POLICY_DIR" \
        --bootstrap-state "$VHSM_BOOTSTRAP" \
        --listen "127.0.0.1:$HSM_PORT" \
        --backend-connect-only \
        --backend-socket "$HSM_SOCK" \
        > /tmp/vm-mgr-vhsm-ssd.log 2>&1 &
    VHSM_PID=$!
    sleep 0.5
    if ! kill -0 "$VHSM_PID" 2>/dev/null; then
        echo "[vm-mgr] WARNING: vhsm-ssd exited early — see /tmp/vm-mgr-vhsm-ssd.log (guests get no vHSM)" >&2
        VHSM_PID=""
    fi
else
    echo "[vm-mgr] WARNING: vhsm-ssd binary not found at $VHSM_SSD (guests get no vHSM)" >&2
fi

# 8. Start vm-sovd (host SOVD/OTA) — CONNECT-ONLY to the SAME link-B backend.
#    Run it in the foreground (not exec) so the EXIT trap reaps the backend +
#    vhsm-ssd when it stops.
SOVD_ARGS=("$NV_PATH" --backend-socket "$HSM_SOCK" --hsm-keystore "$HSM_KEYSTORE" --hsm-port "$HSM_PORT" --bind "$SOVD_ADDR")
if [ -z "$PROFILE" ]; then
    "$SOVD" "${SOVD_ARGS[@]}" &
    SOVD_PID=$!
    wait "$SOVD_PID"
else
    "$SOVD" "${SOVD_ARGS[@]}" &
    SOVD_PID=$!
    "$RUNNER" "${EXTRA_ARGS[@]}" --nv "$NV_PATH" --init
    wait "$SOVD_PID"
fi
