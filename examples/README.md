# Example eBPF Programs

These are example eBPF programs for testing ebpf-assist.

## Prerequisites

To build these examples, you need:

```bash
# Ubuntu/Debian
sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r)

# Fedora
sudo dnf install clang llvm libbpf-devel kernel-devel
```

## Building

```bash
make
```

This produces `.bpf.o` files that can be loaded with ebpf-assist.

## Usage

Start the daemon first:

```bash
# With capabilities (requires sudo or systemd service with AmbientCapabilities)
ebpf-assistd
```

Then use the CLI:

```bash
# Load a program
ebpf-assist load minimal_kprobe.bpf.o

# List loaded programs
ebpf-assist list

# Attach to a kernel function
ebpf-assist attach 1 do_sys_openat2

# Check trace output
sudo cat /sys/kernel/debug/tracing/trace_pipe

# Detach and unload
ebpf-assist detach 1
ebpf-assist unload 1
```

## Programs

- `minimal_kprobe.bpf.c` - Simple kprobe that traces file opens
