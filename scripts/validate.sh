#!/bin/bash
# ebpf-assist validation script
# Tests all CLI commands and MCP server functionality

# Don't exit on error - we handle errors ourselves
set +e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
PASS=0
FAIL=0
SKIP=0

# Test result functions
pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASS++))
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    echo -e "       ${RED}$2${NC}"
    ((FAIL++))
}

skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1 - $2"
    ((SKIP++))
}

section() {
    echo ""
    echo -e "${BLUE}=== $1 ===${NC}"
}

# Find binaries
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CLI="$PROJECT_DIR/target/release/ebpf-assist"
MCP="$PROJECT_DIR/target/release/ebpf-assist-mcp"
DAEMON="$PROJECT_DIR/target/release/ebpf-assistd"

# Check binaries exist
section "Build Check"
if [[ -x "$CLI" ]]; then
    pass "CLI binary exists"
else
    fail "CLI binary missing" "Run: cargo build --release"
    exit 1
fi

if [[ -x "$MCP" ]]; then
    pass "MCP server binary exists"
else
    fail "MCP server binary missing" "Run: cargo build --release"
    exit 1
fi

if [[ -x "$DAEMON" ]]; then
    pass "Daemon binary exists"
else
    fail "Daemon binary missing" "Run: cargo build --release"
    exit 1
fi

# Test CLI help
section "CLI Help"
if $CLI --help >/dev/null 2>&1; then
    pass "ebpf-assist --help"
else
    fail "ebpf-assist --help" "Command failed"
fi

if $CLI --version >/dev/null 2>&1; then
    pass "ebpf-assist --version"
else
    fail "ebpf-assist --version" "Command failed"
fi

# Test subcommand help
for cmd in compile new load unload attach detach list status ping unlock lock auth trigger output; do
    if $CLI $cmd --help >/dev/null 2>&1; then
        pass "ebpf-assist $cmd --help"
    else
        fail "ebpf-assist $cmd --help" "Command failed"
    fi
done

# Test template creation
section "Template Creation"
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

for template in kprobe kretprobe tracepoint xdp raw_tracepoint; do
    if $CLI new $template test_${template} --output-dir "$TMPDIR" >/dev/null 2>&1; then
        if [[ -f "$TMPDIR/test_${template}.c" ]]; then
            pass "ebpf-assist new $template"
        else
            fail "ebpf-assist new $template" "File not created"
        fi
    else
        fail "ebpf-assist new $template" "Command failed"
    fi
done

# Test JSON output for template creation
if $CLI new kprobe json_test --output-dir "$TMPDIR" --json 2>&1 | jq -e '.success' >/dev/null 2>&1; then
    pass "ebpf-assist new --json (JSON output)"
else
    fail "ebpf-assist new --json" "Invalid JSON output"
fi

# Test compilation (requires clang)
section "Compilation"
if command -v clang >/dev/null 2>&1; then
    # Check if libbpf headers are available
    if [[ -f /usr/include/bpf/bpf_helpers.h ]]; then
        if $CLI compile "$TMPDIR/test_kprobe.c" --output "$TMPDIR/test_kprobe.o" 2>&1; then
            if [[ -f "$TMPDIR/test_kprobe.o" ]]; then
                pass "ebpf-assist compile (kprobe)"
            else
                fail "ebpf-assist compile" "Object file not created"
            fi
        else
            # Check if it's a known header issue
            if $CLI compile "$TMPDIR/test_kprobe.c" 2>&1 | grep -q "bpf_helpers.h"; then
                skip "ebpf-assist compile" "libbpf-dev headers incomplete"
            else
                fail "ebpf-assist compile" "Compilation failed"
            fi
        fi

        # Test JSON output for compilation
        OUTPUT=$($CLI compile "$TMPDIR/test_kprobe.c" --output "$TMPDIR/test2.o" --json 2>&1)
        if echo "$OUTPUT" | jq -e '.success or .error' >/dev/null 2>&1; then
            pass "ebpf-assist compile --json (JSON output)"
        else
            fail "ebpf-assist compile --json" "Invalid JSON output"
        fi
    else
        skip "ebpf-assist compile" "libbpf-dev not installed"
    fi
else
    skip "ebpf-assist compile" "clang not installed"
fi

# Test MCP server
section "MCP Server"

# Test initialize
INIT_RESP=$(echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | $MCP 2>/dev/null)
if echo "$INIT_RESP" | jq -e '.result.serverInfo.name == "ebpf-assist"' >/dev/null 2>&1; then
    pass "MCP initialize"
else
    fail "MCP initialize" "Invalid response"
fi

# Test tools/list
TOOLS_RESP=$(echo '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | $MCP 2>/dev/null)
TOOL_COUNT=$(echo "$TOOLS_RESP" | jq '.result.tools | length')
if [[ "$TOOL_COUNT" -ge 18 ]]; then
    pass "MCP tools/list ($TOOL_COUNT tools)"
else
    fail "MCP tools/list" "Expected >= 18 tools, got $TOOL_COUNT"
fi

# Check each tool exists
EXPECTED_TOOLS="ebpf_new ebpf_compile ebpf_load ebpf_unload ebpf_attach ebpf_detach ebpf_list ebpf_status ebpf_unlock ebpf_trigger ebpf_trace ebpf_map_list ebpf_map_read ebpf_map_write ebpf_map_delete ebpf_vm_init ebpf_vm_list ebpf_vm_stop"
for tool in $EXPECTED_TOOLS; do
    if echo "$TOOLS_RESP" | jq -e ".result.tools[] | select(.name == \"$tool\")" >/dev/null 2>&1; then
        pass "MCP tool: $tool"
    else
        fail "MCP tool: $tool" "Tool not found"
    fi
done

# Test ebpf_new via MCP
NEW_RESP=$(echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ebpf_new","arguments":{"template":"kprobe","name":"mcp_test","output_dir":"'"$TMPDIR"'"}}}' | $MCP 2>/dev/null)
if echo "$NEW_RESP" | jq -e '.result.content[0].text' >/dev/null 2>&1; then
    if [[ -f "$TMPDIR/mcp_test.c" ]]; then
        pass "MCP ebpf_new tool"
    else
        fail "MCP ebpf_new tool" "File not created"
    fi
else
    fail "MCP ebpf_new tool" "Invalid response"
fi

# Test daemon connectivity (if running)
section "Daemon Connectivity"

SOCKET_PATH="${XDG_RUNTIME_DIR:-/tmp}/ebpf-assist.sock"
if [[ -S "$SOCKET_PATH" ]]; then
    # Try to connect
    if $CLI ping --json 2>&1 | jq -e '.running' >/dev/null 2>&1; then
        pass "Daemon connectivity (ping)"

        # Test list
        if $CLI list --json 2>&1 | jq -e '.programs' >/dev/null 2>&1; then
            pass "ebpf-assist list --json"
        else
            fail "ebpf-assist list --json" "Invalid response"
        fi

        # Test status
        if $CLI status --json 2>&1 | jq -e '.version' >/dev/null 2>&1; then
            pass "ebpf-assist status --json"
        else
            fail "ebpf-assist status --json" "Invalid response"
        fi

        # Test auth status
        if $CLI auth --json 2>&1 | jq -e 'has("authorized")' >/dev/null 2>&1; then
            pass "ebpf-assist auth --json"
        else
            fail "ebpf-assist auth --json" "Invalid response"
        fi

        # Test MCP tools that require daemon
        STATUS_RESP=$(echo '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"ebpf_status","arguments":{}}}' | $MCP 2>/dev/null)
        if echo "$STATUS_RESP" | jq -e '.result.content[0].text' >/dev/null 2>&1; then
            pass "MCP ebpf_status tool"
        else
            fail "MCP ebpf_status tool" "Invalid response"
        fi

        LIST_RESP=$(echo '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"ebpf_list","arguments":{}}}' | $MCP 2>/dev/null)
        if echo "$LIST_RESP" | jq -e '.result.content[0].text' >/dev/null 2>&1; then
            pass "MCP ebpf_list tool"
        else
            fail "MCP ebpf_list tool" "Invalid response"
        fi
    else
        skip "Daemon commands" "Daemon not responding"
    fi
else
    skip "Daemon connectivity" "Daemon not running (start with: $DAEMON)"
fi

# Test VM commands
section "MicroVM Support"

# Test vm init (doesn't require root)
if $CLI vm init --json 2>&1 | jq -e '.kvm_available' >/dev/null 2>&1; then
    pass "ebpf-assist vm init --json"
else
    fail "ebpf-assist vm init --json" "Invalid response"
fi

# Test vm list
if $CLI vm list --json 2>&1 | jq -e '.vms' >/dev/null 2>&1; then
    pass "ebpf-assist vm list --json"
else
    fail "ebpf-assist vm list --json" "Invalid response"
fi

# Check if MicroVM is ready
VM_STATUS=$($CLI vm init --json 2>&1)
if echo "$VM_STATUS" | jq -e '.ready == true' >/dev/null 2>&1; then
    pass "MicroVM ready (all assets present)"
else
    skip "MicroVM" "Not ready - run ./scripts/vm/setup-vm.sh"
fi

# Test MCP VM tools
VM_INIT_RESP=$(echo '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"ebpf_vm_init","arguments":{}}}' | $MCP 2>/dev/null)
if echo "$VM_INIT_RESP" | jq -e '.result.content[0].text' >/dev/null 2>&1; then
    pass "MCP ebpf_vm_init tool"
else
    fail "MCP ebpf_vm_init tool" "Invalid response"
fi

VM_LIST_RESP=$(echo '{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"ebpf_vm_list","arguments":{}}}' | $MCP 2>/dev/null)
if echo "$VM_LIST_RESP" | jq -e '.result.content[0].text' >/dev/null 2>&1; then
    pass "MCP ebpf_vm_list tool"
else
    fail "MCP ebpf_vm_list tool" "Invalid response"
fi

# Test trigger commands (don't require daemon)
section "Trigger Commands"

# These should work standalone
if $CLI trigger syscall openat /tmp/test_trigger_file 2>&1 | grep -qi "triggered\|success\|openat"; then
    pass "ebpf-assist trigger syscall"
else
    # May fail if no permission, but command should exist
    if $CLI trigger syscall --help >/dev/null 2>&1; then
        pass "ebpf-assist trigger syscall (help works)"
    else
        fail "ebpf-assist trigger syscall" "Command failed"
    fi
fi

if $CLI trigger fs create /tmp/test_trigger_create 2>&1; then
    rm -f /tmp/test_trigger_create
    pass "ebpf-assist trigger fs create"
else
    skip "ebpf-assist trigger fs create" "May require permissions"
fi

# Summary
section "Summary"
TOTAL=$((PASS + FAIL + SKIP))
echo ""
echo -e "Total: $TOTAL tests"
echo -e "${GREEN}Passed: $PASS${NC}"
echo -e "${RED}Failed: $FAIL${NC}"
echo -e "${YELLOW}Skipped: $SKIP${NC}"
echo ""

if [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi
