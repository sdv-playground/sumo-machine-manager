#!/bin/bash
# run-vm.sh — build and start vm-service with dummy backend, clean up on Ctrl-C.
#
# Usage:
#   ./example/dummy-vm/run-vm.sh              # dummy backend (no QEMU needed)
#   ./example/dummy-vm/run-vm.sh --config /path/to/custom.yaml
#
# The vm-service unix socket defaults to /tmp/vm-service-example.sock.
# Use health-check.sh in another terminal to monitor the VM.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG="${1:+}"
VM_NAME="linux1"

# Allow overriding config via --config flag
if [[ "${1:-}" == "--config" ]] && [[ -n "${2:-}" ]]; then
    CONFIG="$2"
    shift 2
else
    CONFIG="$SCRIPT_DIR/vm-service.yaml"
fi

SOCKET=$(grep '^socket:' "$CONFIG" | awk '{print $2}')
SERVICE_BIN="$ROOT_DIR/target/debug/vm-service"
SERVICE_PID=""

# --- Cleanup ---
cleanup() {
    echo ""
    echo "[run-vm] cleaning up..."

    # Stop the VM via API (best-effort)
    if [[ -S "$SOCKET" ]]; then
        curl -sf --unix-socket "$SOCKET" \
            -X POST "http://localhost/vms/$VM_NAME/stop" \
            2>/dev/null && echo "[run-vm] stopped $VM_NAME" || true
    fi

    # Stop vm-service daemon
    if [[ -n "$SERVICE_PID" ]]; then
        kill "$SERVICE_PID" 2>/dev/null
        wait "$SERVICE_PID" 2>/dev/null || true
        echo "[run-vm] vm-service stopped"
    fi

    # Remove stale socket
    rm -f "$SOCKET"

    echo "[run-vm] done."
}
trap cleanup EXIT INT TERM

# --- Build ---
echo "[run-vm] building vm-service..."
cargo build --manifest-path "$ROOT_DIR/Cargo.toml" -p vm-service --quiet

# --- Create dummy image dir (so config is valid) ---
IMAGE_DIR=$(grep 'image_dir:' "$CONFIG" | head -1 | awk '{print $2}')
if [[ -n "$IMAGE_DIR" ]] && [[ ! -d "$IMAGE_DIR" ]]; then
    mkdir -p "$IMAGE_DIR"
    touch "$IMAGE_DIR/bzImage" "$IMAGE_DIR/rootfs.qcow2"
    echo "[run-vm] created placeholder image dir: $IMAGE_DIR"
fi

# --- Start vm-service ---
echo "[run-vm] starting vm-service (config: $CONFIG)..."
"$SERVICE_BIN" --config "$CONFIG" &
SERVICE_PID=$!
sleep 0.5

# Verify it's alive
if ! kill -0 "$SERVICE_PID" 2>/dev/null; then
    echo "[run-vm] ERROR: vm-service failed to start"
    exit 1
fi
echo "[run-vm] vm-service running (pid: $SERVICE_PID, socket: $SOCKET)"

# --- Start VM ---
echo "[run-vm] starting VM '$VM_NAME'..."
RESPONSE=$(curl -sf --unix-socket "$SOCKET" \
    -X POST "http://localhost/vms/$VM_NAME/start" 2>&1) || {
    echo "[run-vm] ERROR: failed to start VM: $RESPONSE"
    exit 1
}
echo "[run-vm] $VM_NAME started: $RESPONSE"

# --- Show status ---
echo ""
echo "[run-vm] VM list:"
curl -sf --unix-socket "$SOCKET" "http://localhost/vms" | python3 -m json.tool 2>/dev/null || \
    curl -sf --unix-socket "$SOCKET" "http://localhost/vms"
echo ""
echo "[run-vm] VM running. Press Ctrl-C to stop."
echo "[run-vm] In another terminal, run: ./example/dummy-vm/health-check.sh"
echo ""

# --- Wait ---
wait "$SERVICE_PID"
