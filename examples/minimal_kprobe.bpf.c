// SPDX-License-Identifier: GPL-2.0
// Minimal kprobe example for testing ebpf-assist

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/do_sys_openat2")
int trace_openat(void *ctx) {
    bpf_printk("openat called\\n");
    return 0;
}
