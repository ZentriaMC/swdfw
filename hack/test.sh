#!/usr/bin/env bash
# E2E test: boot a FCOS VM, apply swdfw rules via nftables and iptables backends.
# Uses QEMU savevm/loadvm to cache a booted VM snapshot for fast restarts.
#
# Env vars:
#   TEST_SSH_PORT      SSH port forward (default: 2223)
#   REBUILD_SNAPSHOT   Set to 1 to force snapshot recreation
#   KEEP_VM            Set to 1 to keep VM running after tests
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
work_dir="${root}/tmp/vm"
ssh_port="${TEST_SSH_PORT:-2223}"
ssh_key="${root}/hack/dev/dev_ed25519"

snapshot_disk="${work_dir}/fcos-snapshot.qcow2"
snapshot_name="ssh-ready"
snapshot_hash_file="${work_dir}/snapshot.hash"
monitor_sock="${work_dir}/qemu-monitor.sock"
pid_file="${work_dir}/qemu.pid"

chmod 600 "${ssh_key}"

fh() {
    fcos-harness --work-dir "${work_dir}" "$@"
}
fh_ssh() {
    fh ssh --ssh-key "${ssh_key}" --ssh-port "${ssh_port}" "$@"
}

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
# Ensure FCOS base image
# ---------------------------------------------------------------------------
fh image

# ---------------------------------------------------------------------------
# Check if a valid VM snapshot exists
# ---------------------------------------------------------------------------
sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

current_hash="$(sha256 "${ign}")"
use_snapshot=false

if [ "${REBUILD_SNAPSHOT:-}" != "1" ] \
    && [ -f "${snapshot_disk}" ] \
    && [ -f "${snapshot_hash_file}" ] \
    && [ "$(cat "${snapshot_hash_file}")" = "${current_hash}" ] \
    && qemu-img snapshot -l "${snapshot_disk}" 2>/dev/null | grep -q "${snapshot_name}"; then
    use_snapshot=true
    echo ">>> Valid VM snapshot found, skipping boot+goss"
fi

# ---------------------------------------------------------------------------
# Create snapshot if needed: boot fresh, wait for SSH, goss, savevm, quit
# ---------------------------------------------------------------------------
if [ "${use_snapshot}" = false ]; then
    echo ">>> Creating VM snapshot (first run or config changed)..."
    rm -f "${snapshot_disk}" "${snapshot_hash_file}"
    fh disk --base "${work_dir}/fcos.qcow2" --overlay "${snapshot_disk}"

    fh start \
        --disk "${snapshot_disk}" \
        --ignition "${ign}" \
        --ssh-port "${ssh_port}" \
        --hostname swdfw-test \
        --serial-log "${work_dir}/serial-test.log" \
        --qmp "${monitor_sock}" \
        --pid-file "${pid_file}"

    cleanup_snapshot() {
        fh stop --pid-file "${pid_file}" 2>/dev/null || true
        rm -f "${monitor_sock}"
    }
    trap cleanup_snapshot EXIT

    echo ">>> Waiting for SSH..."
    fh_ssh --wait 180 -- true

    echo ">>> Running goss validation..."
    fh goss "${root}/hack/goss.yaml" \
        --ssh-key "${ssh_key}" \
        --ssh-port "${ssh_port}" \
        --retry-timeout-secs 30

    echo ">>> Saving VM snapshot '${snapshot_name}'..."
    fh qmp --socket "${monitor_sock}" savevm "${snapshot_name}"

    echo ">>> Stopping snapshot VM..."
    fh qmp --socket "${monitor_sock}" quit
    sleep 1
    fh stop --pid-file "${pid_file}" 2>/dev/null || true
    rm -f "${monitor_sock}"
    trap - EXIT

    echo "${current_hash}" > "${snapshot_hash_file}"
    echo ">>> Snapshot created"
fi

# ---------------------------------------------------------------------------
# Boot VM from snapshot (instant restore, ephemeral writes)
# ---------------------------------------------------------------------------
echo ">>> Booting test VM from snapshot..."
fh start \
    --disk "${snapshot_disk}" \
    --ignition "${ign}" \
    --ssh-port "${ssh_port}" \
    --hostname swdfw-test \
    --serial-log "${work_dir}/serial-test.log" \
    --loadvm "${snapshot_name}" \
    --pid-file "${pid_file}"

cleanup() {
    echo ">>> Shutting down test VM..."
    fh stop --pid-file "${pid_file}" 2>/dev/null || true
}
trap cleanup EXIT

echo ">>> Waiting for SSH (should be instant from snapshot)..."
fh_ssh --wait 30 -- true

# ---------------------------------------------------------------------------
# Deploy swdfw binary
# ---------------------------------------------------------------------------
echo ">>> Deploying swdfw binary..."

scp_opts=(
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o LogLevel=ERROR
    -P "${ssh_port}"
    -i "${ssh_key}"
)
scp "${scp_opts[@]}" "${swdfw_bin}" core@127.0.0.1:/tmp/swdfw
fh_ssh -- "chmod +x /tmp/swdfw"

# ---------------------------------------------------------------------------
# Test 1: nftables backend
# ---------------------------------------------------------------------------
echo ">>> Test 1: nftables backend"

scp "${scp_opts[@]}" "${root}/hack/e2e/nftables.yaml" core@127.0.0.1:/tmp/nftables.yaml
fh_ssh -- "sudo /tmp/swdfw -c /tmp/nftables.yaml"

# Verify table exists
fh_ssh -- "sudo nft list table inet swdfw-e2e" | grep -q "chain e2e-input"
fh_ssh -- "sudo nft list table inet swdfw-e2e" | grep -q "chain allow-ssh"
fh_ssh -- "sudo nft list table inet swdfw-e2e" | grep -q "chain allow-icmp"
fh_ssh -- "sudo nft list table inet swdfw-e2e" | grep -q "chain block-rest"
echo "    nftables chains created OK"

# Verify rules contain expected elements
nft_output="$(fh_ssh -- "sudo nft list table inet swdfw-e2e")"
echo "${nft_output}" | grep -q "dport 22"
echo "${nft_output}" | grep -q "accept"
echo "${nft_output}" | grep -q "reject\|drop"
# Parent chain should use jump (not goto) so all children are reachable
echo "${nft_output}" | grep -q "jump allow-ssh"
echo "${nft_output}" | grep -q "jump block-rest"
echo "    nftables rules verified OK"

# Idempotency: run again, should succeed
fh_ssh -- "sudo /tmp/swdfw -c /tmp/nftables.yaml"
echo "    nftables idempotency OK"

# Clean up nftables table
fh_ssh -- "sudo nft delete table inet swdfw-e2e"

# ---------------------------------------------------------------------------
# Test 2: iptables backend
# ---------------------------------------------------------------------------
echo ">>> Test 2: iptables backend"

scp "${scp_opts[@]}" "${root}/hack/e2e/iptables.yaml" core@127.0.0.1:/tmp/iptables.yaml

# Apply and verify in a single SSH session (iptables rules may block
# new SSH connections during the atomic swap transition)
ipt_output="$(fh_ssh -- "sudo /tmp/swdfw -c /tmp/iptables.yaml && sudo iptables -L e2e-input -n && sudo iptables -L allow-ssh -n")"
echo "${ipt_output}" | grep -q "allow-ssh"
echo "${ipt_output}" | grep -q "dpt:22"
echo "    iptables chains and rules verified OK"

# Idempotency: apply again, should succeed
fh_ssh -- "sudo /tmp/swdfw -c /tmp/iptables.yaml" > /dev/null
echo "    iptables idempotency OK"

# ---------------------------------------------------------------------------
# Test 3: dry-run mode
# ---------------------------------------------------------------------------
echo ">>> Test 3: dry-run mode"

dry_output="$(fh_ssh -- "/tmp/swdfw -c /tmp/nftables.yaml --dry-run")"
echo "${dry_output}" | grep -q "Backend: nftables"
echo "${dry_output}" | grep -q "e2e-input"
echo "    dry-run OK"

echo ""
echo ">>> All E2E tests passed!"

# ---------------------------------------------------------------------------
# Keep VM running if requested
# ---------------------------------------------------------------------------
if [ "${KEEP_VM:-}" = "1" ]; then
    echo ">>> VM is still running (ssh -p ${ssh_port} core@127.0.0.1)"
    echo ">>> Press Ctrl-C to stop..."
    trap cleanup INT
    wait "$(cat "${pid_file}")"
fi
