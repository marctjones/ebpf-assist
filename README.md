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

## Status

**Early design phase** - See [Issues](https://github.com/marctjones/ebpf-assist/issues) for roadmap and design decisions.

## License

TBD
