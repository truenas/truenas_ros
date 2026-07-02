#!/usr/bin/env bash
#
# Provision a ZFS pool with a POSIX-ACL and an NFSv4-ACL dataset for the
# truenas_ros `zfs` integration-test target. Requires root and `zfs`/`zpool`.
#
# It prints `export` lines and, when running under GitHub Actions, appends the
# corresponding `KEY=value` lines to $GITHUB_ENV so the `cargo test` step can
# locate the datasets:
#
#   TRUENAS_ROS_POSIX_DATASET / TRUENAS_ROS_NFS4_DATASET  -> mountpoints
#   TRUENAS_ROS_POSIX_DS      / TRUENAS_ROS_NFS4_DS        -> dataset names
#   TRUENAS_ROS_TEST_POOL     / TRUENAS_ROS_TEST_VDEV      -> for teardown
#
# Mirrors the ZFS setup in truenas_pyos's tests/conftest.py, but provisions two
# persistent datasets at the /POSIXACL and /NFSV4ACL convention paths instead of
# per-test datasets (Rust integration tests have no session-scoped fixtures).
set -euo pipefail

POOL="${TRUENAS_ROS_TEST_POOL:-rostest}"
VDEV="$(mktemp -u /tmp/rostest-vdev.XXXXXX.img)"
POSIX_MP="${TRUENAS_ROS_POSIX_DATASET:-/POSIXACL}"
NFS4_MP="${TRUENAS_ROS_NFS4_DATASET:-/NFSV4ACL}"

echo "Creating 512 MiB file vdev at $VDEV"
truncate -s 512M "$VDEV"

echo "Creating pool '$POOL'"
zpool create -f "$POOL" "$VDEV"

echo "Creating POSIX-ACL dataset at $POSIX_MP"
zfs create -o "mountpoint=$POSIX_MP" -o acltype=posixacl "$POOL/posix"

echo "Creating NFSv4-ACL dataset at $NFS4_MP"
zfs create -o "mountpoint=$NFS4_MP" -o acltype=nfsv4 \
    -o aclmode=passthrough -o aclinherit=passthrough "$POOL/nfs4"

# Also record the exports in a sourceable file so a non-GitHub caller (the QEMU
# test script) can `source` them before `cargo test`.
ENV_FILE="${TRUENAS_ROS_ENV_FILE:-/tmp/truenas-ros-test-env.sh}"
: >"$ENV_FILE"
emit() {
    echo "export $1"
    echo "export $1" >>"$ENV_FILE"
    if [ -n "${GITHUB_ENV:-}" ]; then
        echo "$1" >>"$GITHUB_ENV"
    fi
}
emit "TRUENAS_ROS_TEST_POOL=$POOL"
emit "TRUENAS_ROS_TEST_VDEV=$VDEV"
emit "TRUENAS_ROS_POSIX_DATASET=$POSIX_MP"
emit "TRUENAS_ROS_NFS4_DATASET=$NFS4_MP"
emit "TRUENAS_ROS_POSIX_DS=$POOL/posix"
emit "TRUENAS_ROS_NFS4_DS=$POOL/nfs4"

echo "ZFS test datasets ready."
