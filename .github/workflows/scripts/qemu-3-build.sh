#!/usr/bin/env bash

######################################################################
# Build/install OpenZFS and stage truenas_ros in the VM
######################################################################

set -eu

echo "Building OpenZFS and staging truenas_ros..."

# Load VM info
source /tmp/vm-info.sh

# Wait for cloud-init to finish
echo "Waiting for cloud-init to complete..."
ssh debian@$VM_IP "cloud-init status --wait" || true

# Install rsync in VM first
echo "Installing rsync in VM..."
ssh debian@$VM_IP "sudo apt-get update && sudo apt-get install -y rsync"

# Check if we have cached ZFS packages
if [ "$ZFS_CACHE_HIT" = "true" ] && [ -d "/tmp/zfs-debs" ]; then
  echo "Found cached OpenZFS packages, copying to VM..."
  ssh debian@$VM_IP "mkdir -p /tmp/zfs-debs"
  rsync -az /tmp/zfs-debs/ debian@$VM_IP:/tmp/zfs-debs/
  CACHED_ZFS="true"
else
  echo "No cached OpenZFS packages found, will build from source"
  CACHED_ZFS="false"
fi

# Copy source code to VM
echo "Copying source code to VM..."
ssh debian@$VM_IP "mkdir -p ~/truenas_ros"
rsync -az --exclude='.git' --exclude='target/' \
  "$GITHUB_WORKSPACE/" debian@$VM_IP:~/truenas_ros/

# Install dependencies (OpenZFS build deps + the Rust toolchain)
echo "Installing dependencies in VM..."
ssh debian@$VM_IP bash -s <<'REMOTE_DEPS'
set -eu

sudo apt-get update

sudo apt-get install -y \
  build-essential \
  devscripts \
  debhelper \
  dh-autoreconf \
  dh-python \
  autoconf \
  automake \
  libtool \
  pkg-config \
  uuid-dev \
  libssl-dev \
  libaio-dev \
  libblkid-dev \
  libelf-dev \
  libpam0g-dev \
  libtirpc-dev \
  libudev-dev \
  lsb-release \
  po-debconf \
  zlib1g-dev \
  python3-dev \
  python3-all-dev \
  python3-cffi \
  python3-setuptools \
  python3-sphinx \
  linux-headers-amd64 \
  dkms \
  git \
  gdb \
  cargo
REMOTE_DEPS

# Reboot VM to boot into the newly installed kernel
echo "Rebooting VM to load new kernel..."
ssh debian@$VM_IP 'sudo poweroff' &

# Wait for VM to shut down
echo "Waiting for VM to shut down..."
for i in {1..60}; do
  if sudo virsh list --all | grep "$VM_NAME" | grep -q "shut off"; then
    echo "VM has shut down"
    break
  fi
  echo "Waiting for shutdown... ($i/60)"
  sleep 2
done

# Verify it's actually shut off
if ! sudo virsh list --all | grep "$VM_NAME" | grep -q "shut off"; then
  echo "VM did not shut down gracefully, forcing shutdown..."
  sudo virsh destroy "$VM_NAME" || true
  sleep 3
fi

# Start the VM
echo "Starting VM with new kernel..."
sudo virsh start "$VM_NAME"

# Give it time to start booting
sleep 5

# Wait for VM to be accessible via SSH again
echo "Waiting for VM to come back up..."
for i in {1..60}; do
  if ssh -o ConnectTimeout=2 debian@$VM_IP "echo 'VM ready'" 2>/dev/null; then
    echo "VM is accessible via SSH"
    break
  fi
  echo "Waiting for VM... ($i/60)"
  sleep 5
done

# Verify VM is accessible and check kernel version
echo "Verifying new kernel is running..."
ssh debian@$VM_IP "uname -r"

# Now build/install OpenZFS
echo "Building OpenZFS..."
ssh debian@$VM_IP bash -s "$CACHED_ZFS" <<'REMOTE_SCRIPT'
CACHED_ZFS="$1"
set -eu

# Install or build OpenZFS
if [ -d "/tmp/zfs-debs" ] && [ "$(ls -A /tmp/zfs-debs/*.deb 2>/dev/null)" ]; then
  echo "Using cached OpenZFS packages..."
  sudo apt-get -y install $(find /tmp/zfs-debs -name '*.deb' | grep -Ev 'dkms|dracut')
  echo "Updating module dependencies..."
  sudo depmod -a
else
  echo "Building OpenZFS from source..."
  cd /tmp
  git clone --depth 1 --branch truenas/zfs-2.4-release https://github.com/truenas/zfs.git
  cd zfs
  ./autogen.sh
  ./configure --prefix=/usr --enable-debuginfo
  # Build the native-deb targets sequentially. Run concurrently (with a
  # multi-core -j) they each invoke dpkg-source in this shared tree and clobber
  # one another's generated files (e.g. zfs_gitrev.h), which breaks the kmod
  # module build; the failure is sensitive to the runner's core count.
  make -j$(nproc) native-deb-utils
  make -j$(nproc) native-deb-kmod

  echo "Saving built packages for caching..."
  mkdir -p /tmp/zfs-debs
  find /tmp -maxdepth 1 -name '*.deb' | grep -Ev 'dkms|dracut' | while read deb; do
    cp "$deb" /tmp/zfs-debs/
  done

  sudo apt-get -y install $(find /tmp -maxdepth 1 -name '*.deb' | grep -Ev 'dkms|dracut')
  echo "Updating module dependencies..."
  sudo depmod -a
fi

# Sanity-check the Rust toolchain; the tests are built in the test step (as root,
# which is required for the ZFS/privileged cases).
echo "Rust toolchain:"
cargo --version

echo "OpenZFS installed and truenas_ros staged."
REMOTE_SCRIPT

# Copy ZFS packages back from VM for caching (if we built them)
# Do this BEFORE powering off the VM
if [ "$CACHED_ZFS" = "false" ]; then
  echo "Copying built OpenZFS packages from VM for caching..."
  mkdir -p /tmp/zfs-debs
  rsync -az debian@$VM_IP:/tmp/zfs-debs/ /tmp/zfs-debs/ || echo "Note: No packages to cache"
fi

# Clean cloud-init and poweroff VM
echo "Cleaning cloud-init and powering off VM..."
ssh debian@$VM_IP 'sudo cloud-init clean --logs && sync && sleep 2 && sudo poweroff' &

echo "Build complete, VM shutting down for final restart"
