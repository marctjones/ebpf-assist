# ebpf-assist Vision

**One-liner:** Enable AI assistants to develop, test, and iterate on eBPF programs without requiring interactive sudo.

## Problem

AI coding assistants cannot:
1. Run `sudo` (no interactive password prompt)
2. Load eBPF programs (requires CAP_BPF, CAP_SYS_ADMIN)
3. Trigger controlled kernel activity for testing
4. Safely experiment with programs that might crash the kernel

## Solution

A privileged daemon + MCP server that:
1. Authenticates once via GUI (polkit) or terminal
2. Caches credentials for configurable duration
3. Enforces policy on what programs/operations are allowed
4. Provides test harness for triggering kernel events
5. Optionally isolates in MicroVM for risky operations

## Design Principles

1. **Minimal privilege** - Only the capabilities needed, not full root
2. **Explicit consent** - User authenticates, AI operates within bounds
3. **Auditable** - Every operation logged
4. **Lightweight** - No Docker, no heavy VMs unless opted in
5. **AI-native** - MCP server with structured JSON output
6. **Standalone** - Works with any AI assistant

## Part of the AI Assist Tool Family

- **idlergear** - Knowledge management for AI sessions
- **ebpf-assist** - eBPF/kernel operations (this project)
- Future: sudo-assist, vm-assist, secrets-assist

## Success Looks Like

```
User: "Write a kprobe that traces TCP connections from nginx"

AI:
1. Writes tcp_trace.bpf.c
2. Compiles it
3. ebpf_load("tcp_trace.o")  ← user sees polkit prompt, approves
4. ebpf_attach("kprobe:tcp_v4_connect")
5. ebpf_trigger("proc exec nginx")
6. ebpf_trigger("net tcp-connect 10.0.0.1:80")
7. ebpf_output("ring events") → shows nginx connection
8. "Here's the trace. Want me to add port filtering?"
```

No terminal switching. No copy-paste sudo commands. Approve once and iterate.

