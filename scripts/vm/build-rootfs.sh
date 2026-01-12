#!/bin/bash
# Build a minimal rootfs for ebpf-assist MicroVM guest agent.
#
# This creates an ext4 filesystem image with:
# - Alpine Linux minimal root (musl-based, small footprint)
# - The ebpf-assist-agent binary
# - Minimal required tools (busybox)
#
# Requirements:
# - Docker (for building in isolated environment)
# - 500MB free disk space
# - sudo access (for loop mount)
#
# Usage:
#   ./scripts/vm/build-rootfs.sh [output-path]
#
# Output:
#   ~/.local/share/ebpf-assist/rootfs.ext4 (or specified path)

set -euo pipefail

# Configuration
ROOTFS_SIZE_MB=128
ALPINE_VERSION="3.19"
OUTPUT_PATH="${1:-$HOME/.local/share/ebpf-assist/rootfs.ext4}"

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

log "Building ebpf-assist MicroVM rootfs"
log "Output: $OUTPUT_PATH"

# Check prerequisites
command -v docker &>/dev/null || error "Docker is required but not found"

# Create output directory
mkdir -p "$(dirname "$OUTPUT_PATH")"

# Build the guest agent for musl target
log "Building guest agent for x86_64-unknown-linux-musl..."

# Check if musl target is installed
if ! rustup target list --installed | grep -q x86_64-unknown-linux-musl; then
    warn "Installing musl target..."
    rustup target add x86_64-unknown-linux-musl
fi

# Build in release mode with musl
cargo build --release --target x86_64-unknown-linux-musl -p ebpf-assist-agent 2>&1 || {
    warn "Musl build failed, trying with cross..."
    # Fall back to cross if native musl build fails
    if ! command -v cross &>/dev/null; then
        cargo install cross
    fi
    cross build --release --target x86_64-unknown-linux-musl -p ebpf-assist-agent
}

AGENT_BINARY="target/x86_64-unknown-linux-musl/release/ebpf-assist-agent"
if [[ ! -f "$AGENT_BINARY" ]]; then
    error "Agent binary not found at $AGENT_BINARY"
fi

log "Agent binary size: $(du -h "$AGENT_BINARY" | cut -f1)"

# Create temporary directory for rootfs in project dir (Docker can access it)
# Using project dir ensures Docker bind mounts work correctly
TMPDIR="$PROJECT_ROOT/.rootfs-build"
rm -rf "$TMPDIR"
mkdir -p "$TMPDIR"
trap "rm -rf $TMPDIR" EXIT

log "Creating rootfs in $TMPDIR..."

# Create rootfs structure using Docker
cat > "$TMPDIR/Dockerfile" <<'EOF'
FROM alpine:3.19

# Install minimal packages - no init system needed
RUN apk add --no-cache \
    busybox \
    && rm -rf /var/cache/apk/* \
    && rm -rf /etc/init.d /etc/runlevels

# Create necessary directories
RUN mkdir -p /sys/fs/bpf /sys/kernel/debug /sys/kernel/tracing /dev /proc /sys

# Add ebpf-assist-agent
COPY ebpf-assist-agent /usr/bin/ebpf-assist-agent
RUN chmod +x /usr/bin/ebpf-assist-agent

# Replace init with our custom script
# This runs as PID 1 and starts the guest agent
RUN rm -f /sbin/init && \
    echo '#!/bin/sh' > /sbin/init && \
    echo 'mount -t proc proc /proc' >> /sbin/init && \
    echo 'mount -t sysfs sys /sys' >> /sbin/init && \
    echo 'mount -t devtmpfs dev /dev 2>/dev/null || true' >> /sbin/init && \
    echo 'mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true' >> /sbin/init && \
    echo 'mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true' >> /sbin/init && \
    echo 'mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true' >> /sbin/init && \
    echo 'exec /usr/bin/ebpf-assist-agent' >> /sbin/init && \
    chmod +x /sbin/init

# Also create /init symlink as fallback
RUN ln -sf /sbin/init /init
EOF

# Copy agent binary to temp dir
cp "$AGENT_BINARY" "$TMPDIR/ebpf-assist-agent"

# Build the Docker image
log "Building Docker image for rootfs..."
docker build -t ebpf-assist-rootfs "$TMPDIR"

# Export the rootfs
log "Exporting rootfs..."
CONTAINER_ID=$(docker create ebpf-assist-rootfs)
docker export "$CONTAINER_ID" > "$TMPDIR/rootfs.tar"
docker rm "$CONTAINER_ID" >/dev/null

# Create ext4 image with contents from tarball
# Using mke2fs -d which can populate directly from a tarball (no sudo needed!)
log "Creating ext4 filesystem image (${ROOTFS_SIZE_MB}MB)..."

# Create empty image file first
dd if=/dev/zero of="$OUTPUT_PATH" bs=1M count=$ROOTFS_SIZE_MB status=none

# Create ext4 filesystem and populate from tarball in one step
# The -d option accepts a directory OR a tarball
mke2fs -F -t ext4 -L rootfs -d "$TMPDIR/rootfs.tar" "$OUTPUT_PATH" >/dev/null 2>&1

# Clean up Docker image
docker rmi ebpf-assist-rootfs >/dev/null 2>&1 || true

# Print results
log "Rootfs created successfully!"
log "Size: $(du -h "$OUTPUT_PATH" | cut -f1)"
log "Path: $OUTPUT_PATH"

echo ""
echo "To use with Firecracker:"
echo "  rootfs_path: $OUTPUT_PATH"
