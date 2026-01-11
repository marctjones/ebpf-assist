# ebpf-assist

Enable AI assistants to develop, test, and iterate on eBPF programs without requiring interactive sudo.

## Problem

AI coding assistants (Claude Code, Goose, Aider, Cursor, etc.) cannot:
1. Run `sudo` interactively (no password prompt works)
2. Load eBPF programs (requires CAP_BPF, CAP_SYS_ADMIN)
3. Trigger controlled kernel activity for testing
4. Safely experiment with programs that might crash the kernel

## Solution

A privileged daemon + MCP server that:
1. Authenticates once via GUI (polkit) or terminal
2. Caches credentials for configurable duration (default 15 min)
3. Enforces policy on what programs/operations are allowed
4. Provides test harness for triggering kernel events
5. Optionally isolates in MicroVM for risky operations

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Claude Code / AI Assistant                  │
└─────────────────────────┬───────────────────────────────────────┘
                          │ MCP or Unix socket
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                      ebpf-assist daemon                          │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────────────┐  │
│  │ Policy Engine │ │ Auth Cache    │ │ Audit Log             │  │
│  └───────────────┘ └───────────────┘ └───────────────────────┘  │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────────────┐  │
│  │ eBPF Loader   │ │ Test Harness  │ │ Output Collector      │  │
│  └───────────────┘ └───────────────┘ └───────────────────────┘  │
│  ┌─────────────────────────┐  ┌─────────────────────────────┐   │
│  │ Local Executor          │  │ MicroVM Manager (optional)  │   │
│  └─────────────────────────┘  └─────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Usage

```bash
# Load eBPF program (host kernel - fast iteration)
ebpf-assist load program.o

# Load with isolation (MicroVM - safe experimentation)
ebpf-assist load --isolate program.o

# Trigger kernel activity for testing
ebpf-assist trigger syscall openat /etc/passwd
ebpf-assist trigger net tcp-connect 10.0.0.1:80

# Collect output from BPF maps/ring buffers
ebpf-assist output ring events
ebpf-assist output map stats

# Full test workflow
ebpf-assist test run \
  --program probe.o \
  --attach kprobe:sys_openat \
  --trigger "syscall openat /tmp/test" \
  --expect-output "contains:/tmp/test"
```

## Two Modes

| Mode | Use Case | Speed | Safety |
|------|----------|-------|--------|
| **Host** | Fast iteration, trust your code | Fast | Lower |
| **MicroVM** | Risky ops, full kernel control | Slower | Higher |

## Design Principles

1. **Minimal privilege** - Only the capabilities needed, not full root
2. **Explicit consent** - User authenticates, AI operates within bounds
3. **Auditable** - Every operation logged
4. **Lightweight** - No Docker, no heavy VMs unless opted in
5. **AI-native** - MCP server with structured JSON output
6. **Standalone** - Works with any AI assistant

## Part of the AI Assist Tool Family

ebpf-assist is part of a family of tools solving "AI assistants need privileged operations":

- [idlergear](https://github.com/marctjones/idlergear) - Knowledge management for AI sessions
- **ebpf-assist** - eBPF/kernel operations (this project)
- More coming...

## Installation

### From Source

```bash
# Build
cargo build --release

# Install binaries
sudo cp target/release/ebpf-assistd /usr/local/bin/
sudo cp target/release/ebpf-assist /usr/local/bin/

# Install systemd service (for per-user daemon with capabilities)
sudo cp systemd/ebpf-assistd@.service /etc/systemd/system/
sudo systemctl daemon-reload

# Enable for your user
sudo systemctl enable --now ebpf-assistd@$USER
```

### Running Manually (for development)

```bash
# Run daemon (needs CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN)
sudo setcap cap_bpf,cap_perfmon,cap_net_admin=p target/release/ebpf-assistd
./target/release/ebpf-assistd

# Or with sudo (not recommended for production)
sudo ./target/release/ebpf-assistd
```

## CLI Commands

### Program Management (requires daemon)
```bash
ebpf-assist load <path>           # Load eBPF program
ebpf-assist unload <id>           # Unload program by ID
ebpf-assist attach <id> <target>  # Attach to kprobe/tracepoint/interface
ebpf-assist detach <id>           # Detach from target
ebpf-assist list                  # List all loaded programs
ebpf-assist status                # Show daemon status
ebpf-assist ping                  # Check if daemon is running
```

### Test Harness (no daemon needed)
```bash
# Trigger syscalls for kprobe/tracepoint testing
ebpf-assist trigger syscall openat /etc/passwd
ebpf-assist trigger syscall execve /bin/ls -la
ebpf-assist trigger syscall connect 127.0.0.1:80

# Trigger filesystem activity
ebpf-assist trigger fs create /tmp/test.txt
ebpf-assist trigger fs rename /tmp/a.txt /tmp/b.txt
ebpf-assist trigger fs chmod /tmp/test.txt 755

# Trigger process activity
ebpf-assist trigger proc exec /bin/echo hello
ebpf-assist trigger proc fork

# Trigger network activity
ebpf-assist trigger net tcp-connect 10.0.0.1:80
ebpf-assist trigger net udp-send 10.0.0.1:53 "query"
ebpf-assist trigger net dns google.com
ebpf-assist trigger net ping 8.8.8.8

# Read eBPF output (requires root for trace_pipe)
sudo ebpf-assist output trace --lines 20 --timeout 10
```

## Status

**Phase 1.5 complete** - Daemon, CLI, and test harness working. See [Issues](https://github.com/marctjones/ebpf-assist/issues) for roadmap.

- [x] Phase 1: Daemon with capability control + CLI
- [x] Phase 1.5: Test harness for triggering kernel activity
- [ ] Phase 2: Polkit integration for GUI authentication
- [ ] Phase 3: MCP server for AI assistants
- [ ] Phase 4: MicroVM isolation (optional)

## License

MIT OR Apache-2.0
