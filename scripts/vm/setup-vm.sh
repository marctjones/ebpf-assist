#!/bin/bash
# Set up everything needed for ebpf-assist MicroVM isolation.
#
# This script:
# 1. Downloads Firecracker binary
# 2. Downloads a kernel
# 3. Builds the guest rootfs with agent
#
# Usage:
#   ./scripts/vm/setup-vm.sh
#
# Requirements:
# - Docker (for rootfs build)
# - curl
# - Rust toolchain with musl target

set -euo pipefail

# Configuration
DATA_DIR="${EBPF_ASSIST_DATA:-$HOME/.local/share/ebpf-assist}"
FIRECRACKER_VERSION="v1.7.0"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[!]${NC} $*" >&2; exit 1; }

# Ensure we're in the project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

log "Setting up ebpf-assist MicroVM environment"
log "Data directory: $DATA_DIR"
echo ""

# Create data directory
mkdir -p "$DATA_DIR"

# Step 1: Download Firecracker
log "Step 1/3: Downloading Firecracker ${FIRECRACKER_VERSION}..."

FIRECRACKER_PATH="$DATA_DIR/firecracker"
if [[ -x "$FIRECRACKER_PATH" ]]; then
    log "Firecracker already installed at $FIRECRACKER_PATH"
else
    ARCH=$(uname -m)
    FC_URL="https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/firecracker-${FIRECRACKER_VERSION}-${ARCH}.tgz"

    TMPDIR=$(mktemp -d)
    trap "rm -rf $TMPDIR" EXIT

    curl -fsSL "$FC_URL" -o "$TMPDIR/firecracker.tgz"
    tar -xzf "$TMPDIR/firecracker.tgz" -C "$TMPDIR"

    # Find and copy the firecracker binary
    FC_BIN=$(find "$TMPDIR" -name "firecracker-*-${ARCH}" -type f | head -1)
    if [[ -z "$FC_BIN" ]]; then
        error "Could not find firecracker binary in archive"
    fi

    cp "$FC_BIN" "$FIRECRACKER_PATH"
    chmod +x "$FIRECRACKER_PATH"

    log "Firecracker installed: $FIRECRACKER_PATH"
fi

echo ""

# Step 2: Download kernel
log "Step 2/3: Downloading kernel..."
"$SCRIPT_DIR/download-kernel.sh" "$DATA_DIR/vmlinux"

echo ""

# Step 3: Build rootfs
log "Step 3/3: Building rootfs..."
"$SCRIPT_DIR/build-rootfs.sh" "$DATA_DIR/rootfs.ext4"

echo ""
log "Setup complete!"
echo ""
echo "MicroVM files:"
echo "  Firecracker: $FIRECRACKER_PATH"
echo "  Kernel:      $DATA_DIR/vmlinux"
echo "  Rootfs:      $DATA_DIR/rootfs.ext4"
echo ""
echo "To test manually:"
echo "  # Check KVM access"
echo "  ls -la /dev/kvm"
echo ""
echo "  # Start a VM (requires sudo for KVM)"
echo "  sudo $FIRECRACKER_PATH --api-sock /tmp/fc.sock &"
echo ""
echo "Or use ebpf-assist with --isolate flag (once implemented)"
