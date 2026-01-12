# ebpf-assist AI Skill Documentation

This document describes how AI assistants can use ebpf-assist to develop, test, and debug eBPF programs.

## Overview

ebpf-assist is a tool that enables AI assistants to:
- Create eBPF programs from templates
- Compile eBPF C code to object files
- Load and attach eBPF programs to the kernel
- Trigger kernel activity for testing
- Read program output (trace_pipe, maps)
- Iterate on eBPF code with instant feedback

## Available Commands

### Program Development

| Command | Description | Example |
|---------|-------------|---------|
| `new` | Create program from template | `ebpf-assist new kprobe my_probe --target do_sys_openat2` |
| `compile` | Compile C to BPF object | `ebpf-assist compile my_probe.c` |

### Program Lifecycle

| Command | Description | Example |
|---------|-------------|---------|
| `load` | Load BPF object into kernel | `ebpf-assist load my_probe.o` |
| `unload` | Remove program from kernel | `ebpf-assist unload 1` |
| `attach` | Connect to kernel hook | `ebpf-assist attach 1 do_sys_openat2` |
| `detach` | Disconnect from hook | `ebpf-assist detach 1` |
| `list` | Show all loaded programs | `ebpf-assist list` |

### Testing

| Command | Description | Example |
|---------|-------------|---------|
| `trigger syscall` | Trigger a syscall | `ebpf-assist trigger syscall openat /tmp/test` |
| `trigger fs` | File operations | `ebpf-assist trigger fs create /tmp/test` |
| `trigger proc` | Process operations | `ebpf-assist trigger proc exec /bin/ls` |
| `trigger net` | Network operations | `ebpf-assist trigger net tcp-connect localhost:80` |
| `output trace` | Read bpf_printk output | `ebpf-assist output trace` |

### System

| Command | Description | Example |
|---------|-------------|---------|
| `status` | Daemon status | `ebpf-assist status` |
| `ping` | Check daemon | `ebpf-assist ping` |
| `unlock` | Authenticate with polkit | `ebpf-assist unlock` |
| `auth` | Check auth status | `ebpf-assist auth` |

## Template Types

| Type | Description | Attach Target |
|------|-------------|---------------|
| `kprobe` | Hook function entry | Function name (e.g., `do_sys_openat2`) |
| `kretprobe` | Hook function return | Function name |
| `tracepoint` | Static kernel tracepoint | Format: `category:name` (e.g., `syscalls:sys_enter_openat`) |
| `xdp` | Network packet processing | Interface name (e.g., `eth0`) |
| `raw_tracepoint` | Raw tracepoint | Tracepoint name (e.g., `sys_enter`) |

## Typical AI Workflow

### 1. Create a New Program

```bash
# Create kprobe for file opens
ebpf-assist new kprobe file_monitor --target do_sys_openat2
```

Output:
```
Created: ./file_monitor.c
  Template: Kprobe
  Next steps:
    1. Edit ./file_monitor.c as needed
    2. Compile: ebpf-assist compile ./file_monitor.c
    3. Load: ebpf-assist load file_monitor.o
```

### 2. Edit the Program (Optional)

The generated template is ready to use, but you can modify it:

```c
SEC("kprobe/do_sys_openat2")
int file_monitor(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("file_monitor: pid=%d", pid);
    return 0;
}
```

### 3. Compile

```bash
ebpf-assist compile file_monitor.c
```

Output:
```
Compiled: file_monitor.c -> file_monitor.o
```

### 4. Load and Attach

```bash
# Load the program
ebpf-assist load file_monitor.o
# Output: Loaded program: ID: 1, Name: file_monitor, Type: Kprobe

# Attach to the kernel hook
ebpf-assist attach 1 do_sys_openat2
# Output: Attached program 1 to do_sys_openat2
```

### 5. Trigger and Observe

```bash
# Trigger file activity
ebpf-assist trigger syscall openat /tmp/test

# Read the output
ebpf-assist output trace
# Output: file_monitor: pid=12345
```

### 6. Iterate

```bash
# Detach before unloading
ebpf-assist detach 1

# Unload
ebpf-assist unload 1

# Make changes, recompile, reload...
```

## JSON Output Mode

Add `--json` flag for machine-readable output:

```bash
ebpf-assist list --json
```

Output:
```json
{
  "programs": [
    {
      "id": 1,
      "name": "file_monitor",
      "type": "Kprobe",
      "attached": true,
      "target": "do_sys_openat2"
    }
  ]
}
```

## Error Handling

ebpf-assist provides helpful error messages:

```bash
ebpf-assist load missing.o
```

Output:
```
Error: [NotFound] File not found: missing.o

💡 File not found. Did you compile the program?
   Run: ebpf-assist compile <source.c>
```

## Authentication

eBPF operations require authentication via polkit:

```bash
# Check auth status
ebpf-assist auth
# Output: Not authorized

# Authenticate (triggers desktop dialog)
ebpf-assist unlock
# Output: Authorization granted (cached for 15 minutes)
```

## MCP Integration

For AI assistants using MCP (Model Context Protocol), configure:

```json
{
  "mcpServers": {
    "ebpf-assist": {
      "command": "/usr/local/bin/ebpf-assist-mcp"
    }
  }
}
```

Available MCP tools:
- `ebpf_compile` - Compile eBPF source code
- `ebpf_load` - Load program into kernel
- `ebpf_unload` - Unload program
- `ebpf_attach` - Attach to hook
- `ebpf_detach` - Detach from hook
- `ebpf_list` - List programs
- `ebpf_status` - Daemon status
- `ebpf_unlock` - Authenticate
- `ebpf_trigger` - Trigger activity
- `ebpf_trace` - Read trace output

## Prerequisites

### System Requirements
- Linux with eBPF support (kernel 5.x+)
- clang for compilation
- libbpf-dev for BPF headers

### Installation

```bash
# Ubuntu/Debian
sudo apt install clang libbpf-dev

# Fedora
sudo dnf install clang libbpf-devel

# Arch
sudo pacman -S clang libbpf
```

## Common Patterns

### Pattern 1: System Call Monitoring

```bash
# Monitor file opens
ebpf-assist new kprobe open_monitor --target do_sys_openat2
ebpf-assist compile open_monitor.c
ebpf-assist load open_monitor.o
ebpf-assist attach 1 do_sys_openat2

# Test
ebpf-assist trigger syscall openat /etc/passwd
ebpf-assist output trace
```

### Pattern 2: Network Packet Analysis

```bash
# XDP packet counter
ebpf-assist new xdp packet_counter
ebpf-assist compile packet_counter.c
ebpf-assist load packet_counter.o
ebpf-assist attach 1 eth0

# Test
ebpf-assist trigger net tcp-connect localhost:80
ebpf-assist output trace
```

### Pattern 3: Process Tracking

```bash
# Track execve calls
ebpf-assist new tracepoint exec_monitor --target syscalls/sys_enter_execve
ebpf-assist compile exec_monitor.c
ebpf-assist load exec_monitor.o
ebpf-assist attach 1 syscalls:sys_enter_execve

# Test
ebpf-assist trigger proc exec /bin/ls
ebpf-assist output trace
```

## Troubleshooting

### "Authorization required"
Run `ebpf-assist unlock` to authenticate.

### "File not found"
Compile first: `ebpf-assist compile source.c`

### "bpf_helpers.h not found"
Install libbpf-dev: `sudo apt install libbpf-dev`

### "Function not found"
Check `/proc/kallsyms` for valid function names.

### "Verifier rejected"
- Check for unbounded loops
- Add null checks for pointer access
- Initialize all variables before use
