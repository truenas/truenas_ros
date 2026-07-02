#!/usr/bin/env bash

######################################################################
# Provision ZFS ACL datasets and run the Rust test suite in the VM
######################################################################

set -eu

echo "Running cargo tests..."

# Load VM info
source /tmp/vm-info.sh

# Run tests in VM as root (ZFS pool creation + privileged syscalls need it)
ssh debian@$VM_IP 'sudo bash -s' <<'REMOTE_SCRIPT'
set -eu

echo "=========================================="
echo "Loading ZFS kernel module"
echo "=========================================="
sudo modprobe zfs || {
  echo "ERROR: Failed to load ZFS kernel module"
  sudo dmesg | tail -20
  exit 1
}
lsmod | grep zfs || { echo "ERROR: ZFS module not loaded"; exit 1; }
echo "ZFS kernel module loaded successfully"

cd /home/debian/truenas_ros

echo ""
echo "=========================================="
echo "Provisioning ZFS ACL datasets"
echo "=========================================="
# Creates a POSIX-ACL dataset at /POSIXACL and an NFSv4-ACL dataset at /NFSV4ACL,
# and writes the dataset paths/names to /tmp/truenas-ros-test-env.sh.
bash .github/workflows/scripts/setup-test-zfs.sh
# shellcheck disable=SC1091
source /tmp/truenas-ros-test-env.sh

echo ""
echo "=========================================="
echo "Running cargo test --all-features"
echo "=========================================="
export CARGO_TERM_COLOR=never
# The privileged + ZFS-backed tests (ACLs, mount/idmap, open_by_handle_at,
# fsiter mountpoints) now execute instead of skipping.
cargo test --all-features 2>&1 | tee /home/debian/test-output.txt
TEST_EXIT_CODE=${PIPESTATUS[0]}

echo ""
echo "=========================================="
echo "Tearing down ZFS test datasets"
echo "=========================================="
bash .github/workflows/scripts/teardown-test-zfs.sh || true

echo "$TEST_EXIT_CODE" > /home/debian/test-exitcode.txt

echo "=========================================="
echo "Test run complete (exit code: $TEST_EXIT_CODE)"
echo "=========================================="

exit $TEST_EXIT_CODE
REMOTE_SCRIPT

TEST_RESULT=$?

scp debian@$VM_IP:~/test-output.txt /tmp/ || true
scp debian@$VM_IP:~/test-exitcode.txt /tmp/ || true

if [ $TEST_RESULT -ne 0 ]; then
    echo "Tests failed with exit code $TEST_RESULT"
    exit $TEST_RESULT
fi

echo "All tests passed!"
