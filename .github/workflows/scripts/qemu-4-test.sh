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
echo "Verifying the booted kernel"
echo "=========================================="
# qemu-3-build.sh installed exactly one kernel and recorded its release; assert
# the reboot actually landed on it. Booting anything else silently changes what
# the suite covers (statmount 6.14/6.15 fields, io_uring opcode floors, the
# peercred gate below) and would otherwise only surface as a confusing modprobe
# failure — or not at all.
EXPECTED_RELEASE=$(cat /home/debian/tn-kernel-release)
if [ "$(uname -r)" != "$EXPECTED_RELEASE" ]; then
  echo "ERROR: expected to boot the TrueNAS kernel $EXPECTED_RELEASE,"
  echo "but the VM is running $(uname -r)"
  exit 1
fi
echo "Booted the TrueNAS kernel $EXPECTED_RELEASE as expected"

echo ""
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
# qemu-3-build.sh installed current stable under a system-wide RUSTUP_HOME
# (Trixie's packaged rustc is older than the crate's rust-version) and
# symlinked rustup's cargo/rustc proxies into /usr/local/bin. The proxies need
# RUSTUP_HOME to find that toolchain, and this `sudo bash` is not a login
# shell, so read the drop-in that records it explicitly.
# shellcheck disable=SC1091
. /etc/profile.d/rust.sh
cargo --version
export CARGO_TERM_COLOR=never
# Frames for any panic in here too. The workflow-level env cannot reach this
# far — the suite runs over ssh inside the VM — so export it alongside the
# other test knobs.
export RUST_BACKTRACE=1
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
# memfd_secret (CONFIG_SECRETMEM, default-on) backs the `secrets` module's
# protected memory. `secretmem_init` mounts the backing fs only when
# `secretmem_enable && can_set_direct_map()` (mm/secretmem.c:280), and on
# x86_64 the second is unconditionally true, so the appliance kernel always
# has it: force the secrets tests to RUN, including the VM_LOCKED/VM_DONTDUMP
# assertion. A skip means secretmem regressed or was disabled off and must
# turn CI red.
export TRUENAS_ROS_REQUIRE_SECRETMEM=1
# The ZFS-ACL suites (test/zfs.rs and the live-fixture ACL checks in
# test/test.rs) skip when their datasets are absent. Those datasets were
# provisioned above, so force the suites to RUN: a skip now means provisioning
# silently degraded (wrong acltype, unmounted) and must turn CI red rather than
# pass green having tested nothing.
export TRUENAS_ROS_REQUIRE_ZFS=1
# Every scratch filesystem in this VM takes xattrs - the ZFS datasets above,
# and tmpfs registers a user.* handler (shmem_user_xattr_handler, mm/shmem.c)
# - and the run is root, so the trusted.* probe in the privileged-policy
# fixture must also stick. Force the xattr fixtures to RUN; a refusal means
# the fixture landed somewhere degraded and must turn CI red.
export TRUENAS_ROS_REQUIRE_XATTRS=1
# `setup-test-zfs.sh` mounted /POSIXACL and /NFSV4ACL, so this VM has a REAL
# mount boundary for the RESOLVE_NO_XDEV tests to cross. That is what this
# demands: every Linux host has /proc, /sys, /dev and /run as top-level mounts,
# so "some boundary exists" is never false and would gate nothing. Crossing
# into procfs also proves nothing about the platform the product ships - the
# rule these tests pin (the kernel refusing to walk off a filesystem, rather
# than the caller conventionally not doing it) has to be pinned against ZFS.
export TRUENAS_ROS_REQUIRE_MOUNT_BOUNDARY=1
# This job runs as root over ssh, which is the only place the credential
# broker can actually become another uid (CAP_SETUID). Force the multi-reactor
# broker test to RUN: unprivileged ci.yml can only skip it, so without this the
# headline multi-ring feature is gated by a test that never executes.
export TRUENAS_ROS_REQUIRE_CRED_BROKER=1
# Root-only tests - broker impersonation, DAC_READ_SEARCH traversal, the
# trusted.* namespace, capability-bounding-set sheds - return early when the
# run is unprivileged, and libtest reports that as a pass. This job is the
# only place they execute, so demand they execute: a skip here means the run
# stopped being root and the privileged half of the suite tested nothing.
export TRUENAS_ROS_REQUIRE_ROOT=1
# `open_by_handle_at` needs CAP_DAC_READ_SEARCH (`may_decode_fh`,
# fs/fhandle.c) and `name_to_handle_at` needs a filesystem that encodes
# handles - ZFS registers `zpl_export_operations` with `.encode_fh`
# (module/os/linux/zfs/zpl_export.c), and this job is root, so both hold.
# One test in the whole tree drives that round trip; force it to run.
export TRUENAS_ROS_REQUIRE_FHANDLE=1
# STATX_CHANGE_COOKIE reaches userspace only on this fork: upstream strips
# it in `cp_statx` and clears it from the request mask ("kernel-only for
# now", fs/stat.c), and the TrueNAS patch exposes it under CONFIG_TRUENAS
# for samba. This VM boots that kernel, so the cookie test must run rather
# than skip - it is the only place in CI where it can.
export TRUENAS_ROS_REQUIRE_CHANGE_COOKIE=1
# The audit suite sends REAL records over NETLINK_AUDIT. It tolerates three
# environments - no socket, a socket without CAP_AUDIT_WRITE, and the real
# thing - and only the third tests anything. This VM is the only place that
# holds: the appliance kernel carries CONFIG_AUDIT and the job runs as root,
# so records are actually accepted. Unprivileged ci.yml can only reach the
# EPERM tolerance, which is why the gate is armed here and not there.
export TRUENAS_ROS_REQUIRE_AUDIT=1
# The fsiter birth-time cutoff is skipped wholesale on a filesystem that
# reports no btime. ZFS records one (crtime) and so does tmpfs, so both
# scratch filesystems in this VM report it: force the cutoff assertion to
# RUN rather than let a degraded fixture pass green.
export TRUENAS_ROS_REQUIRE_BTIME=1
# unix_peercred needs the AF_UNIX io_uring getsockopt fix (kernel >= 6.18.16).
# We boot the TrueNAS <train>-nightly kernel (truenas/linux), whose uname -r
# carries the full point release (e.g. 6.18.16-production+truenas), so read it
# straight from there. Enforce once the booted kernel is new enough; else print
# a visible pending line, not a silent skip (a still-behind TrueNAS kernel
# self-heals when it picks up the fix).
kver=$(uname -r | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+')
if [ -n "$kver" ] && [ "$(printf '%s\n6.18.16\n' "$kver" | sort -V | head -n1)" = "6.18.16" ]; then
  echo "kernel $kver >= 6.18.16: enforcing unix_peercred"
  export TRUENAS_ROS_REQUIRE_PEERCRED=1
else
  echo "kernel ${kver:-unknown} < 6.18.16: unix_peercred pending (kernel predates the fix)"
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
