#!/bin/bash
# Download a prebuilt kernel for Firecracker MicroVM.
#
# This downloads a minimal kernel configured for Firecracker from the
# official Firecracker releases or builds one locally.
#
# Usage:
#   ./scripts/vm/download-kernel.sh [output-path]
#
# Output:
#   ~/.local/share/ebpf-assist/vmlinux (or specified path)

set -euo pipefail

# Configuration
OUTPUT_PATH="${1:-$HOME/.local/share/ebpf-assist/vmlinux}"

# Kernel 5.10 - chosen for maximum compatibility with target platforms:
# - RHEL 8.2+ (kernel 4.18+), RHEL 9 (5.14+)
# - Ubuntu 22.04 (5.15+), Ubuntu 24.04 (6.8)
# - Debian 11 (5.10), Debian 12 (6.1)
# - Yocto (configurable)
#
# 5.10 has full BTF/CO-RE support for modern eBPF programs.
# Programs that work on 5.10 will work on all newer kernels.
KERNEL_VERSION="5.10"

# Primary: Fireactions prebuilt kernel (includes BTF support)
# https://hostinger.github.io/fireactions/user-guide/kernels/
KERNEL_URL="https://storage.googleapis.com/fireactions/kernels/amd64/${KERNEL_VERSION}/vmlinux"

# Fallback: AWS quickstart kernel (older, may lack BTF)
AWS_KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[!]${NC} $*" >&2; exit 1; }

log "Downloading Firecracker-compatible kernel"
log "Output: $OUTPUT_PATH"

# Create output directory
mkdir -p "$(dirname "$OUTPUT_PATH")"

# Check if kernel already exists
if [[ -f "$OUTPUT_PATH" ]]; then
    log "Kernel already exists at $OUTPUT_PATH"
    log "Size: $(du -h "$OUTPUT_PATH" | cut -f1)"
    read -p "Re-download? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
fi

# Try downloading from Fireactions (has BTF support)
log "Downloading kernel ${KERNEL_VERSION} from Fireactions..."

if curl -fsSL "$KERNEL_URL" -o "$OUTPUT_PATH.tmp"; then
    mv "$OUTPUT_PATH.tmp" "$OUTPUT_PATH"
elif curl -fsSL "$AWS_KERNEL_URL" -o "$OUTPUT_PATH.tmp"; then
    warn "Fireactions URL failed, using AWS kernel (may lack BTF support)"
    mv "$OUTPUT_PATH.tmp" "$OUTPUT_PATH"
else
    rm -f "$OUTPUT_PATH.tmp"
    error "Failed to download kernel. You may need to build one locally."
fi

# Verify the kernel
log "Verifying kernel..."
if file "$OUTPUT_PATH" | grep -q "ELF"; then
    log "Kernel downloaded successfully!"
    log "Size: $(du -h "$OUTPUT_PATH" | cut -f1)"
    log "Path: $OUTPUT_PATH"
else
    rm -f "$OUTPUT_PATH"
    error "Downloaded file is not a valid ELF kernel"
fi

echo ""
echo "To use with Firecracker:"
echo "  kernel_path: $OUTPUT_PATH"
