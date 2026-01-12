#!/bin/bash
# ebpf-assist Feature Demo
# Run this in a terminal to see all features in action
#
# Usage:
#   ./scripts/demo.sh          # Needs daemon running with caps
#   sudo ./scripts/demo.sh     # Run everything with root

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Find project directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CLI="$PROJECT_DIR/target/release/ebpf-assist"
DAEMON="$PROJECT_DIR/target/release/ebpf-assistd"

# Demo directory
DEMO_DIR=$(mktemp -d)
STARTED_DAEMON=false

cleanup() {
    if $STARTED_DAEMON && [[ -n "$DAEMON_PID" ]]; then
        kill $DAEMON_PID 2>/dev/null || true
    fi
    rm -rf "$DEMO_DIR"
}
trap cleanup EXIT

header() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${CYAN}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

step() {
    echo -e "${YELLOW}▶${NC} ${BOLD}$1${NC}"
    sleep 0.5
}

cmd() {
    echo -e "  ${GREEN}\$${NC} $1"
    sleep 0.3
}

run() {
    echo -e "  ${GREEN}\$${NC} $*"
    "$@" 2>&1 | sed 's/^/    /'
    echo ""
    sleep 0.5
}

pause() {
    echo ""
    echo -e "${CYAN}Press Enter to continue...${NC}"
    read -r
}

# ============================================================================
header "🐝 ebpf-assist Demo"
echo -e "This demo shows the main features of ebpf-assist,"
echo -e "a tool that enables AI assistants to work with eBPF programs."
echo ""
echo -e "Prerequisites:"
echo -e "  • clang and libbpf-dev installed"
echo -e "  • ebpf-assistd daemon running (or will start it)"
echo ""
pause

# ============================================================================
header "1️⃣  Check System Status"

step "Check if daemon is running"
if $CLI ping --json 2>/dev/null | jq -e '.running' >/dev/null 2>&1; then
    echo -e "    ${GREEN}✓ Daemon is running${NC}"
else
    echo -e "    ${YELLOW}Starting daemon...${NC}"
    $DAEMON &>/dev/null &
    DAEMON_PID=$!
    STARTED_DAEMON=true
    sleep 1
    if $CLI ping --json 2>/dev/null | jq -e '.running' >/dev/null 2>&1; then
        echo -e "    ${GREEN}✓ Daemon started (PID: $DAEMON_PID)${NC}"
    else
        echo -e "    ${RED}✗ Failed to start daemon${NC}"
        exit 1
    fi
fi
echo ""

step "Check version"
run $CLI --version

step "Check daemon status"
run $CLI status

pause

# ============================================================================
header "2️⃣  Create eBPF Program from Template"

cd "$DEMO_DIR"

step "List available templates"
echo -e "    Templates: ${CYAN}kprobe, kretprobe, tracepoint, xdp, raw_tracepoint${NC}"
echo ""

step "Create a kprobe to monitor file opens"
run $CLI new kprobe file_monitor --target do_sys_openat2

step "View the generated code"
echo -e "  ${GREEN}\$${NC} cat file_monitor.c"
echo ""
cat file_monitor.c | head -30 | sed 's/^/    /'
echo -e "    ${CYAN}... (truncated)${NC}"
echo ""

pause

# ============================================================================
header "3️⃣  Compile eBPF Program"

step "Compile the program to BPF bytecode"
run $CLI compile file_monitor.c

step "Verify the object file was created"
run ls -la file_monitor.o

pause

# ============================================================================
header "4️⃣  Load Program into Kernel"

step "Check authentication status"
run $CLI auth

step "Load the compiled program"
LOAD_OUTPUT=$($CLI load file_monitor.o 2>&1)
LOAD_EXIT=$?
if [[ $LOAD_EXIT -ne 0 ]] || echo "$LOAD_OUTPUT" | grep -qi "error\|failed\|capability"; then
    echo "$LOAD_OUTPUT" | sed 's/^/    /'
    echo ""
    echo -e "    ${RED}Load failed - likely missing capabilities${NC}"
    echo -e "    ${YELLOW}To run the full demo with kernel operations:${NC}"
    echo -e "    ${CYAN}  sudo $0${NC}"
    echo ""
    echo -e "    Skipping kernel operations, showing remaining features..."
    SKIP_KERNEL=true
else
    echo "$LOAD_OUTPUT" | sed 's/^/    /'
    SKIP_KERNEL=false
fi
echo ""

step "List loaded programs"
run $CLI list

pause

# ============================================================================
header "5️⃣  Attach to Kernel Hook"

if [[ "$SKIP_KERNEL" == "true" ]]; then
    echo -e "    ${YELLOW}⏭ Skipped (no program loaded)${NC}"
    echo ""
    PROG_ID=""
else
    step "Attach to the do_sys_openat2 function"
    # Get program ID from list
    PROG_ID=$($CLI list --json 2>/dev/null | jq -r '.programs[0].id // empty')
    if [[ -n "$PROG_ID" ]]; then
        run $CLI attach "$PROG_ID" do_sys_openat2
        step "Verify attachment"
        run $CLI list
    else
        echo -e "    ${RED}No program to attach${NC}"
    fi
fi

pause

# ============================================================================
header "6️⃣  Trigger and Observe"

if [[ "$SKIP_KERNEL" == "true" ]]; then
    step "Trigger file activity (works without program loaded)"
    run $CLI trigger syscall openat /tmp/demo_test_file

    step "Trace output would show bpf_printk messages here"
    echo -e "    ${YELLOW}⏭ Skipped (no program attached)${NC}"
else
    step "Trigger file activity"
    run $CLI trigger syscall openat /tmp/demo_test_file

    step "Read trace output (bpf_printk)"
    run $CLI output trace --lines 5
fi

pause

# ============================================================================
header "7️⃣  JSON Output Mode"

step "All commands support --json for machine-readable output"

cmd "$CLI list --json"
$CLI list --json 2>&1 | jq . | sed 's/^/    /'
echo ""

cmd "$CLI status --json"
$CLI status --json 2>&1 | jq . | sed 's/^/    /'
echo ""

pause

# ============================================================================
header "8️⃣  Cleanup"

if [[ "$SKIP_KERNEL" == "true" ]] || [[ -z "$PROG_ID" ]]; then
    echo -e "    ${YELLOW}⏭ Skipped (no program to clean up)${NC}"
else
    step "Detach the program"
    run $CLI detach "$PROG_ID"

    step "Unload the program"
    run $CLI unload "$PROG_ID"

    step "Verify cleanup"
    run $CLI list
fi

# ============================================================================
header "🎉 Demo Complete!"

echo -e "You've seen the core ebpf-assist workflow:"
echo ""
echo -e "  ${GREEN}1.${NC} ${BOLD}new${NC}      - Create program from template"
echo -e "  ${GREEN}2.${NC} ${BOLD}compile${NC}  - Compile C to BPF bytecode"
echo -e "  ${GREEN}3.${NC} ${BOLD}load${NC}     - Load into kernel"
echo -e "  ${GREEN}4.${NC} ${BOLD}attach${NC}   - Connect to kernel hook"
echo -e "  ${GREEN}5.${NC} ${BOLD}trigger${NC}  - Generate activity"
echo -e "  ${GREEN}6.${NC} ${BOLD}output${NC}   - Read trace output"
echo -e "  ${GREEN}7.${NC} ${BOLD}detach${NC}   - Disconnect from hook"
echo -e "  ${GREEN}8.${NC} ${BOLD}unload${NC}   - Remove from kernel"
echo ""

if [[ "$SKIP_KERNEL" == "true" ]]; then
    echo -e "${YELLOW}Note: Kernel operations were skipped due to missing capabilities.${NC}"
    echo -e "To run the full demo: ${CYAN}sudo $0${NC}"
    echo ""
fi

echo -e "For AI integration, use the MCP server: ${CYAN}ebpf-assist-mcp${NC}"
echo -e "Documentation: ${CYAN}docs/SKILL.md${NC}"
echo ""
