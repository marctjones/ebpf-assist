# Makefile for building example eBPF programs
# Requires: clang, llvm, libbpf headers

CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)

# Find libbpf headers
LIBBPF_HEADERS := $(shell pkg-config --cflags libbpf 2>/dev/null || echo "-I/usr/include")

EXAMPLES := minimal_kprobe.bpf.o

.PHONY: all clean

all: $(EXAMPLES)

%.bpf.o: %.bpf.c
	$(CLANG) $(BPF_CFLAGS) $(LIBBPF_HEADERS) -c $< -o $@

clean:
	rm -f *.bpf.o
