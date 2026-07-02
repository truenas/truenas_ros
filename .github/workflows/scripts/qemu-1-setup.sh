#!/usr/bin/env bash

######################################################################
# Setup QEMU environment on GitHub Actions runner
######################################################################

set -eu

echo "Setting up QEMU environment..."

# Install needed packages (without GUI/manager components to reduce dependencies)
export DEBIAN_FRONTEND="noninteractive"
sudo apt-get -y update

# Install core packages with optimizations
sudo apt-get install -y --no-install-recommends \
  cloud-image-utils \
  guestfs-tools \
  virtinst \
  qemu-system-x86 \
  qemu-utils \
  libvirt-daemon-system \
  libvirt-clients \
  ovmf \
  dnsmasq \
  rsync \
  wget

# Note: Using virtinst instead of virt-manager to avoid heavy GUI dependencies
# Using --no-install-recommends to minimize package count

# Generate ssh keys for VM access
rm -f ~/.ssh/id_ed25519
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -q -N ""

# Stop unnecessary services to free up resources
sudo systemctl stop docker.socket || true
sudo systemctl stop multipathd.socket || true

# Disable dnsmasq service (libvirt will manage its own dnsmasq instance)
sudo systemctl stop dnsmasq || true
sudo systemctl disable dnsmasq || true
sudo systemctl mask dnsmasq || true

# Configure SSH client
mkdir -p "$HOME/.ssh"
cat <<EOF >> "$HOME/.ssh/config"
# No questions please
StrictHostKeyChecking no

# Small timeout for connection attempts
ConnectTimeout 10
EOF

# Ensure libvirt is running
sudo systemctl start libvirtd
sudo systemctl enable libvirtd

# Add current user to libvirt group
sudo usermod -a -G libvirt "$USER"

echo "QEMU setup complete"
