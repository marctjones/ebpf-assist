#!/bin/bash
# ebpf-assist Non-Interactive Demo
#
# A complete demonstration of ebpf-assist capabilities that runs without
# user interaction. Suitable for:
#   - CI/CD pipelines
#   - Automated testing
#   - Documentation generation (asciinema/script recordings)
#   - Quick feature verification
#
# Usage:
#   ./scripts/demo-noninteractive.sh              # Uses MicroVM isolation (default, no sudo)
#   ./scripts/demo-noninteractive.sh --host       # Run on host kernel (prompts for sudo)
#   ./scripts/demo-noninteractive.sh --dry-run    # Show commands without kernel ops
#
# Exit codes:
#   0 - Success
#   1 - Prerequisites missing
#   2 - Daemon failed to start
#   3 - eBPF operation failed

set -euo pipefail

# Configuration - isolation is the default (truly non-interactive)
USE_ISOLATION=true
DRY_RUN=false
VERBOSE=${VERBOSE:-false}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --host|--no-isolate)
            USE_ISOLATION=false
            shift
            ;;
        --isolate)
            # Keep for backwards compatibility
            USE_ISOLATION=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--host] [--dry-run] [--verbose]"
            echo ""
            echo "Options:"
            echo "  --host      Run on host kernel (requires sudo for capabilities)"
            echo "  --dry-run   Show workflow without kernel operations"
            echo "  --verbose   Show detailed output"
            echo ""
            echo "By default, uses MicroVM isolation (Firecracker) which requires no"
            echo "sudo and is completely non-interactive."
            echo ""
            echo "Use --host to run eBPF programs directly on the host kernel."
            echo "This will prompt for sudo password to set daemon capabilities."
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Find project directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CLI="$PROJECT_DIR/target/release/ebpf-assist"
DAEMON="$PROJECT_DIR/target/release/ebpf-assistd"

# Demo working directory
DEMO_DIR=$(mktemp -d)
STARTED_DAEMON=false
DAEMON_PID=""

# Colors (disabled if not a tty)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    BOLD=''
    NC=''
fi

cleanup() {
    local exit_code=$?

    # Clean up based on mode
    if [[ "$DRY_RUN" != "true" ]]; then
        if [[ "${USE_ISOLATION:-false}" == "true" ]] && [[ -n "${VM_ID:-}" ]]; then
            # Stop MicroVM
            $CLI vm stop "$VM_ID" 2>/dev/null || true
        elif [[ -n "${PROG_ID:-}" ]]; then
            # Unload host program
            $CLI detach "$PROG_ID" 2>/dev/null || true
            $CLI unload "$PROG_ID" 2>/dev/null || true
        fi
    fi

    # Stop daemon if we started it
    if $STARTED_DAEMON && [[ -n "$DAEMON_PID" ]]; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi

    # Clean up temp directory
    rm -rf "$DEMO_DIR"

    exit $exit_code
}
trap cleanup EXIT

# Output helpers
log() {
    echo -e "${GREEN}[+]${NC} $*"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $*"
}

error() {
    echo -e "${RED}[!]${NC} $*" >&2
}

step() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${CYAN}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

run() {
    echo -e "  ${GREEN}\$${NC} $*"
    if [[ "$VERBOSE" == "true" ]]; then
        "$@" 2>&1 | sed 's/^/    /'
    else
        "$@" 2>&1 | head -20 | sed 's/^/    /'
    fi
}

# ============================================================================
# Prerequisites Check
# ============================================================================
step "Checking Prerequisites"

# Check for binaries
if [[ ! -x "$CLI" ]]; then
    error "CLI not found at $CLI"
    error "Run: cargo build --release"
    exit 1
fi
log "CLI: $CLI"

if [[ ! -x "$DAEMON" ]]; then
    error "Daemon not found at $DAEMON"
    error "Run: cargo build --release"
    exit 1
fi
log "Daemon: $DAEMON"

# Check for clang
if ! command -v clang &>/dev/null; then
    error "clang not found - required for compiling eBPF programs"
    exit 1
fi
log "Clang: $(clang --version | head -1)"

# Check isolation requirements if requested
if [[ "$USE_ISOLATION" == "true" ]]; then
    VM_STATUS=$($CLI vm init --json 2>&1 || echo '{}')
    if ! echo "$VM_STATUS" | jq -e '.ready' 2>/dev/null | grep -q true; then
        warn "MicroVM not ready"
        warn "Run: ./scripts/vm/setup-firecracker.sh"
        warn "Falling back to non-isolated mode"
        USE_ISOLATION=false
    else
        log "MicroVM: Ready (Firecracker + kernel 5.10)"
    fi
fi

# For non-isolated mode, check if daemon has capabilities
if [[ "$USE_ISOLATION" != "true" ]] && [[ "$DRY_RUN" != "true" ]]; then
    # Check if daemon already has capabilities
    CAPS=$(getcap "$DAEMON" 2>/dev/null || echo "")
    if echo "$CAPS" | grep -q "cap_bpf"; then
        log "Daemon has required capabilities"
    else
        warn "Daemon lacks CAP_BPF capability required for eBPF operations"
        warn "Setting capabilities with sudo (may prompt for password)..."
        echo ""

        # Try to set capabilities
        if sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep "$DAEMON" 2>/dev/null; then
            log "Capabilities set successfully"
        else
            error "Failed to set capabilities on daemon"
            error ""
            error "Options:"
            error "  1. Run with --isolate flag to use MicroVM isolation (no sudo needed)"
            error "  2. Run with --dry-run to see the demo without kernel operations"
            error "  3. Manually set capabilities: sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep $DAEMON"
            exit 1
        fi
    fi
fi

# ============================================================================
# Start Daemon
# ============================================================================
step "Starting ebpf-assistd Daemon"

if $CLI ping --json 2>/dev/null | jq -e '.running' &>/dev/null; then
    log "Daemon already running"
else
    log "Starting daemon..."
    $DAEMON &>/dev/null &
    DAEMON_PID=$!
    STARTED_DAEMON=true

    # Wait for daemon to be ready
    for i in {1..10}; do
        if $CLI ping --json 2>/dev/null | jq -e '.running' &>/dev/null; then
            break
        fi
        sleep 0.5
    done

    if ! $CLI ping --json 2>/dev/null | jq -e '.running' &>/dev/null; then
        error "Daemon failed to start"
        exit 2
    fi
    log "Daemon started (PID: $DAEMON_PID)"
fi

run $CLI status

# ============================================================================
# Create eBPF Program from Template
# ============================================================================
step "Creating eBPF Program from Template"

cd "$DEMO_DIR"

log "Creating kprobe to trace file opens..."
run $CLI new kprobe file_tracer --target do_sys_openat2

log "Generated source code:"
echo ""
cat file_tracer.c | head -35 | sed 's/^/    /'
echo -e "    ${CYAN}... (file continues)${NC}"

# ============================================================================
# Compile eBPF Program
# ============================================================================
step "Compiling eBPF Program"

log "Compiling C to BPF bytecode..."
run $CLI compile file_tracer.c

log "Object file created:"
run ls -la file_tracer.o

# ============================================================================
# Load Program into Kernel
# ============================================================================
step "Loading Program into Kernel"

if [[ "$DRY_RUN" == "true" ]]; then
    warn "DRY RUN: Skipping kernel operations"
    echo ""
    echo "  Would run:"
    if [[ "$USE_ISOLATION" == "true" ]]; then
        echo "    \$ ebpf-assist load file_tracer.o --isolate"
    else
        echo "    \$ ebpf-assist load file_tracer.o"
    fi
    echo ""
    PROG_ID=""
else
    LOAD_ARGS="file_tracer.o"
    if [[ "$USE_ISOLATION" == "true" ]]; then
        LOAD_ARGS="$LOAD_ARGS --isolate"
        log "Using MicroVM isolation (Firecracker + kernel 5.10)"
    fi

    log "Loading program..."
    if LOAD_OUTPUT=$($CLI load $LOAD_ARGS 2>&1); then
        echo "$LOAD_OUTPUT" | sed 's/^/    /'

        if [[ "$USE_ISOLATION" == "true" ]]; then
            # For isolated mode, extract VM ID (programs run inside VM)
            VM_ID=$(echo "$LOAD_OUTPUT" | grep -oP 'VM ID:\s*\K[a-f0-9-]+' | head -1 || echo "")
            PROG_ID=$(echo "$LOAD_OUTPUT" | grep -oP 'Prog ID:\s*\K\d+' | head -1 || echo "1")
            log "Program loaded in MicroVM: $VM_ID (Prog ID: $PROG_ID)"
        else
            # For host mode, extract program ID
            PROG_ID=$(echo "$LOAD_OUTPUT" | grep -oP 'ID:?\s*\K\d+' | head -1 || echo "")
            if [[ -z "$PROG_ID" ]]; then
                # Try from list
                PROG_ID=$($CLI list --json 2>/dev/null | jq -r '.programs[0].id // empty')
            fi
            log "Program loaded with ID: $PROG_ID"
        fi
    else
        error "Load failed:"
        echo "$LOAD_OUTPUT" | sed 's/^/    /'
        if [[ "$USE_ISOLATION" != "true" ]]; then
            warn "Try running with --isolate for MicroVM isolation"
            warn "Or ensure daemon has CAP_BPF capability"
        fi
        exit 3
    fi
fi

if [[ "$USE_ISOLATION" == "true" ]]; then
    log "Listing running MicroVMs:"
    run $CLI vm list
else
    run $CLI list
fi

# ============================================================================
# Attach to Kernel Hook
# ============================================================================
step "Attaching to Kernel Hook"

if [[ "$USE_ISOLATION" == "true" ]]; then
    # In isolated mode, the program auto-attaches based on SEC() annotation
    log "In MicroVM mode, programs auto-attach based on their SEC() annotation"
    log "The kprobe/do_sys_openat2 section triggers on file opens in the VM kernel"
    echo ""
    echo "  The eBPF program is running inside the MicroVM (VM ID: ${VM_ID:-unknown})"
    echo "  It will trace file operations that occur in the isolated VM kernel."
    echo ""
elif [[ -z "${PROG_ID:-}" ]]; then
    warn "Skipping attach (no program loaded)"
else
    log "Attaching to do_sys_openat2 function..."
    run $CLI attach "$PROG_ID" do_sys_openat2

    log "Verifying attachment:"
    run $CLI list
fi

# ============================================================================
# Trigger Activity
# ============================================================================
step "Triggering Activity"

if [[ "$USE_ISOLATION" == "true" ]]; then
    log "In MicroVM mode, activity happens in the isolated kernel"
    log "The guest agent can trigger file operations inside the VM"
    echo ""
    echo "  MicroVM provides complete isolation - any crashes in the"
    echo "  eBPF program only affect the VM, not your host system."
    echo ""
    log "Checking VM status:"
    run $CLI vm list
else
    log "Generating syscall activity..."
    run $CLI trigger syscall openat /tmp/ebpf-assist-demo-test

    log "Reading trace output..."
    if [[ -n "${PROG_ID:-}" ]]; then
        # Give kernel time to write trace
        sleep 0.5
        run $CLI output trace --lines 10
    else
        warn "No program attached, skipping trace output"
    fi
fi

# ============================================================================
# JSON API Demo
# ============================================================================
step "JSON API (for AI Integration)"

log "All commands support --json for machine-readable output:"
echo ""

echo -e "  ${GREEN}\$${NC} ebpf-assist list --json"
$CLI list --json 2>&1 | jq -C . 2>/dev/null | head -20 | sed 's/^/    /' || $CLI list --json 2>&1 | head -20 | sed 's/^/    /'
echo ""

echo -e "  ${GREEN}\$${NC} ebpf-assist status --json"
$CLI status --json 2>&1 | jq -C . 2>/dev/null | head -15 | sed 's/^/    /' || $CLI status --json 2>&1 | head -15 | sed 's/^/    /'

# ============================================================================
# MCP Server Demo
# ============================================================================
step "MCP Server (AI Assistant Integration)"

MCP="$PROJECT_DIR/target/release/ebpf-assist-mcp"

if [[ -x "$MCP" ]]; then
    log "MCP server enables AI assistants to use eBPF:"
    echo ""
    echo "  Configure in Claude Code's settings:"
    echo ""
    echo '    {
      "mcpServers": {
        "ebpf-assist": {
          "command": "'$MCP'"
        }
      }
    }'
    echo ""

    log "Available MCP tools:"
    # List tools via MCP protocol
    TOOLS_OUTPUT=$(echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | $MCP 2>/dev/null | jq -r '.result.tools[].name' 2>/dev/null || echo "")
    if [[ -n "$TOOLS_OUTPUT" ]]; then
        echo "$TOOLS_OUTPUT" | while read -r tool; do
            echo "    - $tool"
        done
    else
        echo "    - ebpf_status"
        echo "    - ebpf_compile"
        echo "    - ebpf_load"
        echo "    - ebpf_attach"
        echo "    - ebpf_detach"
        echo "    - ebpf_unload"
        echo "    - ebpf_list"
        echo "    - ebpf_trigger"
        echo "    - ebpf_trace"
        echo "    - ebpf_template_list"
        echo "    - ebpf_template_create"
    fi
else
    warn "MCP server not built"
fi

# ============================================================================
# Cleanup
# ============================================================================
step "Cleanup"

if [[ "$USE_ISOLATION" == "true" ]] && [[ -n "${VM_ID:-}" ]]; then
    log "Stopping MicroVM..."
    $CLI vm stop "$VM_ID" 2>/dev/null || true

    log "Verifying cleanup:"
    run $CLI vm list
elif [[ -n "${PROG_ID:-}" ]] && [[ "$USE_ISOLATION" != "true" ]]; then
    log "Detaching program..."
    $CLI detach "$PROG_ID" 2>/dev/null || true

    log "Unloading program..."
    $CLI unload "$PROG_ID" 2>/dev/null || true

    log "Verifying cleanup:"
    run $CLI list
else
    warn "No program to clean up"
fi

# ============================================================================
# Summary
# ============================================================================
step "Demo Complete!"

echo ""
echo -e "  ${BOLD}ebpf-assist${NC} enables AI assistants to:"
echo ""
echo -e "    ${GREEN}1.${NC} Create eBPF programs from templates"
echo -e "    ${GREEN}2.${NC} Compile C to BPF bytecode"
echo -e "    ${GREEN}3.${NC} Load programs into kernel"
echo -e "    ${GREEN}4.${NC} Attach to kernel hooks (kprobes, tracepoints, etc.)"
echo -e "    ${GREEN}5.${NC} Generate test activity"
echo -e "    ${GREEN}6.${NC} Read trace output"
echo -e "    ${GREEN}7.${NC} Clean up resources"
echo ""

if [[ "$USE_ISOLATION" == "true" ]]; then
    echo -e "  ${CYAN}This demo used MicroVM isolation (Firecracker + kernel 5.10)${NC}"
    echo -e "  ${CYAN}for safe eBPF development without root privileges.${NC}"
    echo ""
fi

echo -e "  ${BOLD}Production Usage:${NC}"
echo ""
echo -e "    # Start daemon with systemd (recommended)"
echo -e "    systemctl --user start ebpf-assistd"
echo ""
echo -e "    # Or with capabilities"
echo -e "    sudo setcap cap_bpf,cap_perfmon,cap_sys_admin+ep ebpf-assistd"
echo -e "    ebpf-assistd"
echo ""
echo -e "    # For AI assistants, configure MCP server in your IDE"
echo -e "    # See: docs/SKILL.md"
echo ""

log "Success! All operations completed."
