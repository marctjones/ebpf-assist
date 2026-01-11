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

## Design Decisions

1. **No containers** - Host or MicroVM only
2. **aya over libbpf-rs** - Pure Rust, easier install
3. **Two-layer security** - Polkit + per-op capabilities
4. **Native polkit UI** - No custom auth dialogs

