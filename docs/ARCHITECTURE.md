# ebpf-assist Architecture

## Overview

ebpf-assist uses a two-layer security model to enable AI assistants to load eBPF programs safely.

## Security Layers

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: AUTHORIZATION (polkit)                             │
│   → Native GNOME/KDE dialog prompts for password            │
│   → Caches approval for 15 min                              │
│   → User sees familiar system auth dialog                   │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Layer 2: CAPABILITY CONTROL (per-operation)                 │
│   → Daemon has caps in permitted set (not effective)        │
│   → Only raises to effective during actual operation        │
│   → Drops immediately after                                 │
└─────────────────────────────────────────────────────────────┘
```

## Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 Claude Code / AI Assistant                   │
└─────────────────────────┬───────────────────────────────────┘
                          │ MCP protocol (Phase 3)
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    ebpf-assist CLI                           │
│                                                              │
│  ┌────────────────────────┐  ┌────────────────────────────┐ │
│  │ Program Management     │  │ Test Harness               │ │
│  │ load, unload, attach   │  │ trigger syscall/fs/proc/net│ │
│  │ detach, list, status   │  │ output trace/map           │ │
│  │ (requires daemon)      │  │ (standalone, no daemon)    │ │
│  └────────────────────────┘  └────────────────────────────┘ │
└─────────────────────────┬───────────────────────────────────┘
                          │ Unix socket + JSON
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    ebpf-assistd (daemon)                     │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │ AuthManager  │  │ CapManager   │  │ EbpfLoader (aya) │   │
│  │ (polkit)     │  │ (capctl)     │  │                  │   │
│  └──────────────┘  └──────────────┘  └──────────────────┘   │
│                                                              │
│  Permitted: CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN             │
│  Effective: NONE (raised only during operations)             │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                     Linux Kernel                             │
│                  (eBPF subsystem)                            │
└─────────────────────────────────────────────────────────────┘
```

## Request Flow

```
1. AI calls ebpf_load("probe.o")
         ↓
2. CLI sends request to daemon via Unix socket
         ↓
3. Daemon checks polkit authorization
         ↓
   ┌─ Not authorized ─→ Trigger polkit dialog ─→ User enters password
   │                                                     ↓
   └─ Authorized (cached) ←─────────────────────────────┘
         ↓
4. Daemon raises CAP_BPF into effective set
         ↓
5. aya loads the eBPF program
         ↓
6. Daemon drops CAP_BPF from effective set
         ↓
7. Return program ID to AI
```

## Key Technologies

| Component | Technology | Why |
|-----------|------------|-----|
| eBPF loading | aya | Pure Rust, no system deps |
| Capabilities | capctl | Per-operation cap control |
| Authorization | polkit | Native desktop integration |
| IPC | Unix socket + JSON | Simple, secure |
| Async | tokio | Industry standard |

## Execution Modes

| Mode | Command | Use Case |
|------|---------|----------|
| Host | `ebpf-assist load prog.o` | Fast iteration |
| Isolated | `ebpf-assist load --isolate prog.o` | Safe testing (Phase 4) |

## Test Harness

The CLI includes standalone tools for testing eBPF programs (no daemon required):

```
ebpf-assist trigger syscall openat /etc/passwd   # Trigger syscall
ebpf-assist trigger fs create /tmp/test          # Filesystem activity
ebpf-assist trigger proc exec /bin/ls            # Process activity
ebpf-assist trigger net tcp-connect 10.0.0.1:80  # Network activity
ebpf-assist output trace                         # Read bpf_printk output
```

This enables the AI workflow:
1. Write eBPF program
2. Load and attach via daemon
3. Trigger activity with CLI
4. Read output to verify behavior

## Design Decisions

1. **No containers** - Host or MicroVM only
2. **aya over libbpf-rs** - Pure Rust, easier install
3. **Two-layer security** - Polkit + per-op capabilities
4. **Native polkit UI** - No custom auth dialogs
5. **Standalone test harness** - Trigger commands work without daemon

## Implementation Status

- [x] Phase 1: Daemon with capability control + CLI
- [x] Phase 1.5: Test harness (trigger/output commands)
- [x] Phase 2: Polkit integration for GUI authentication
- [ ] Phase 3: MCP server for AI assistants
- [ ] Phase 4: MicroVM isolation (optional)

## Polkit Integration

The daemon integrates with polkit for user authentication:

```
┌─────────────────────────────────────────────────────────────┐
│  CLI: ebpf-assist unlock                                     │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  Daemon: AuthManager                                         │
│    → Checks polkit via D-Bus                                │
│    → Caches result for 15 min                               │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  polkit: org.freedesktop.PolicyKit1                          │
│    → Shows native GNOME/KDE auth dialog                     │
│    → User enters password                                   │
└─────────────────────────────────────────────────────────────┘
```

Polkit action IDs:
- `org.ebpf-assist.manage` - General eBPF management
- `org.ebpf-assist.load` - Loading programs
- `org.ebpf-assist.attach` - Attaching to hooks
