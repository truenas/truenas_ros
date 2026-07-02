#!/usr/bin/env bash
#
# Tear down the ZFS pool created by setup-test-zfs.sh. Best-effort: never fails
# the job. Reads TRUENAS_ROS_TEST_POOL / TRUENAS_ROS_TEST_VDEV from the
# environment (exported into $GITHUB_ENV by the setup script).
set -uo pipefail

POOL="${TRUENAS_ROS_TEST_POOL:-rostest}"

# Retry destroy briefly: a just-closed dataset can report EBUSY.
for _ in $(seq 1 15); do
    if zpool destroy -f "$POOL" 2>/dev/null; then
        break
    fi
    sleep 1
done

if [ -n "${TRUENAS_ROS_TEST_VDEV:-}" ]; then
    rm -f "$TRUENAS_ROS_TEST_VDEV"
fi

echo "ZFS test datasets torn down."
