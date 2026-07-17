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

echo ""
echo "=========================================="
echo "Loading kernel TLS (kTLS) module"
echo "=========================================="
# The net stack's kTLS tests need the tls ULP. Load it and confirm it actually
# registered (so setsockopt(TCP_ULP, "tls") works); the tests are then forced
# to run below rather than skip. A missing tls module is a real failure here.
sudo modprobe tls || {
  echo "ERROR: Failed to load the kernel TLS (tls) module"
  sudo dmesg | tail -20
  exit 1
}
grep -qw tls /proc/sys/net/ipv4/tcp_available_ulp || {
  ulp=$(cat /proc/sys/net/ipv4/tcp_available_ulp 2>/dev/null)
  echo "ERROR: tls ULP unavailable after modprobe (tcp_available_ulp='$ulp')"
  exit 1
}
echo "kernel TLS ULP available"

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
# This VM has a real kernel and runs as root, so an io_uring ring is always
# creatable, the tls ULP is loaded (probe above), and Trixie's OpenSSL (3.2+,
# built with enable-ktls) can engage kTLS — unlike the unprivileged Ubuntu
# runner, whose OpenSSL 3.0 cannot and lets the kTLS data-path tests skip.
# Force the net tests — including kTLS — to RUN rather than skip to green. A
# ring that fails to create, or kTLS that fails to engage end to end, is a
# real failure that must turn CI red.
export TRUENAS_ROS_REQUIRE_IO_URING=1
export TRUENAS_ROS_REQUIRE_KTLS=1
# unix_peercred needs the AF_UNIX io_uring getsockopt fix (kernel >= 6.18.16).
# The pinned VM kernel (see qemu-test.yml) is currently 6.18.15 — the last
# 6.18 trixie-backports ever shipped — so this stays pending until the pin
# moves to a 6.18.16+ kernel (e.g. a TrueNAS-built 6.18); the gate below then
# enforces automatically. Read the running kernel's exact Debian package
# version: uname -r omits the stable point release, and /proc/version's first
# "Debian x.y.z" is the compiler, not the kernel. Enforce when new enough;
# else print a visible pending line, not a silent skip.
kver=$(dpkg-query -W -f='${Version}' "linux-image-$(uname -r)" 2>/dev/null \
  | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+')
if [ -n "$kver" ] && [ "$(printf '%s\n6.18.16\n' "$kver" | sort -V | head -n1)" = "6.18.16" ]; then
  echo "kernel $kver >= 6.18.16: enforcing unix_peercred"
  export TRUENAS_ROS_REQUIRE_PEERCRED=1
else
  echo "kernel ${kver:-unknown} < 6.18.16: unix_peercred pending (pinned kernel predates the fix)"
fi
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
