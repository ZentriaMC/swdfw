#!/usr/bin/env bash
# E2E test: boot a FCOS VM, apply swdfw rules via nftables and iptables backends.
# Uses QEMU savevm/loadvm to cache a booted VM snapshot for fast restarts.
#
# Env vars:
#   FCOS_HARNESS_SSH_PORT   SSH port forward (default: 2223)
#   FCOS_HARNESS_SSH_KEY    SSH key (set below)
#   REBUILD_SNAPSHOT        Set to 1 to force snapshot recreation
#   KEEP_VM                 Set to 1 to keep VM running after tests
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
export FCOS_HARNESS_WORK_DIR="${root}/tmp/vm"
export FCOS_HARNESS_SSH_KEY="${root}/hack/dev/dev_ed25519"
export FCOS_HARNESS_SSH_PORT="${FCOS_HARNESS_SSH_PORT:-2223}"

chmod 600 "${FCOS_HARNESS_SSH_KEY}"

fh() { fcos-harness "$@"; }

# ---------------------------------------------------------------------------
# Detect target arch for Go cross-compile
# ---------------------------------------------------------------------------
case "$(uname -s).$(uname -m)" in
    Linux.x86_64)   goarch="amd64"   ;;
    Darwin.arm64)   goarch="arm64"   ;;
    Linux.aarch64)  goarch="arm64"   ;;
    Darwin.x86_64)  goarch="amd64"   ;;
    *) echo >&2 "Unsupported platform"; exit 1 ;;
esac

# ---------------------------------------------------------------------------
# Build Ignition config
# ---------------------------------------------------------------------------
make -C "${root}/hack/init" config.ign

ign="${root}/hack/init/config.ign"

# ---------------------------------------------------------------------------
# Cross-compile swdfw for Linux
# ---------------------------------------------------------------------------
echo ">>> Building swdfw for linux/${goarch}..."
GOOS=linux GOARCH="${goarch}" CGO_ENABLED=0 go build -o "${root}/tmp/swdfw" ./cmd/swdfw/

swdfw_bin="${root}/tmp/swdfw"
if ! [ -f "${swdfw_bin}" ]; then
    echo >&2 ">>> Build failed: swdfw binary not found"
    exit 1
fi

# ---------------------------------------------------------------------------
# Boot VM (with snapshot caching for SSH-ready state)
# ---------------------------------------------------------------------------
rebuild_flag=()
if [ "${REBUILD_SNAPSHOT:-}" = "1" ]; then
    rebuild_flag=(--rebuild-snapshot)
fi

echo ">>> Bringing up VM..."
fh up \
    --ignition "${ign}" \
    --hostname swdfw-test \
    --snapshot ssh-ready \
    --snapshot-goss "${root}/hack/goss.yaml" \
    "${rebuild_flag[@]}"

trap 'fh down' EXIT

echo ">>> Waiting for SSH..."
fh ssh --wait 30 -- true

# ---------------------------------------------------------------------------
# Deploy swdfw binary
# ---------------------------------------------------------------------------
echo ">>> Deploying swdfw binary..."

scp_opts=(
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o LogLevel=ERROR
    -P "${FCOS_HARNESS_SSH_PORT}"
    -i "${FCOS_HARNESS_SSH_KEY}"
)
scp "${scp_opts[@]}" "${swdfw_bin}" core@127.0.0.1:/tmp/swdfw
fh ssh -- "chmod +x /tmp/swdfw"

# ---------------------------------------------------------------------------
# Test 1: nftables backend
# ---------------------------------------------------------------------------
echo ">>> Test 1: nftables backend"

scp "${scp_opts[@]}" "${root}/hack/e2e/nftables.yaml" core@127.0.0.1:/tmp/nftables.yaml
fh ssh -- "sudo /tmp/swdfw -c /tmp/nftables.yaml"

# Verify table exists
fh ssh -- "sudo nft list table inet swdfw-e2e" | grep -q "chain e2e-input"
fh ssh -- "sudo nft list table inet swdfw-e2e" | grep -q "chain allow-ssh"
fh ssh -- "sudo nft list table inet swdfw-e2e" | grep -q "chain allow-icmp"
fh ssh -- "sudo nft list table inet swdfw-e2e" | grep -q "chain block-rest"
echo "    nftables chains created OK"

# Verify rules contain expected elements
nft_output="$(fh ssh -- "sudo nft list table inet swdfw-e2e")"
echo "${nft_output}" | grep -q "dport 22"
echo "${nft_output}" | grep -q "accept"
echo "${nft_output}" | grep -q "reject\|drop"
# Parent chain should use jump (not goto) so all children are reachable
echo "${nft_output}" | grep -q "jump allow-ssh"
echo "${nft_output}" | grep -q "jump block-rest"
echo "    nftables rules verified OK"

# Idempotency: run again, should succeed
fh ssh -- "sudo /tmp/swdfw -c /tmp/nftables.yaml"
echo "    nftables idempotency OK"

# Clean up nftables table
fh ssh -- "sudo nft delete table inet swdfw-e2e"

# ---------------------------------------------------------------------------
# Test 2: iptables backend
# ---------------------------------------------------------------------------
echo ">>> Test 2: iptables backend"

scp "${scp_opts[@]}" "${root}/hack/e2e/iptables.yaml" core@127.0.0.1:/tmp/iptables.yaml

# Apply and verify in a single SSH session (iptables rules may block
# new SSH connections during the atomic swap transition)
ipt_output="$(fh ssh -- "sudo /tmp/swdfw -c /tmp/iptables.yaml && sudo iptables -L e2e-input -n && sudo iptables -L allow-ssh -n")"
echo "${ipt_output}" | grep -q "allow-ssh"
echo "${ipt_output}" | grep -q "dpt:22"
echo "    iptables chains and rules verified OK"

# Idempotency: apply again, should succeed
fh ssh -- "sudo /tmp/swdfw -c /tmp/iptables.yaml" > /dev/null
echo "    iptables idempotency OK"

# ---------------------------------------------------------------------------
# Test 3: dry-run mode
# ---------------------------------------------------------------------------
echo ">>> Test 3: dry-run mode"

dry_output="$(fh ssh -- "/tmp/swdfw -c /tmp/nftables.yaml --dry-run")"
echo "${dry_output}" | grep -q "Backend: nftables"
echo "${dry_output}" | grep -q "e2e-input"
echo "    dry-run OK"

echo ""
echo ">>> All E2E tests passed!"

# ---------------------------------------------------------------------------
# Keep VM running if requested
# ---------------------------------------------------------------------------
if [ "${KEEP_VM:-}" = "1" ]; then
    echo ">>> VM is still running (ssh -p ${FCOS_HARNESS_SSH_PORT} core@127.0.0.1)"
    echo ">>> Press Ctrl-C to stop..."
    trap 'fh down; exit 0' INT
    while kill -0 "$(cat "${FCOS_HARNESS_WORK_DIR}/qemu.pid")" 2>/dev/null; do
        sleep 1
    done
fi
