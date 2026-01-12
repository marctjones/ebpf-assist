//! eBPF program compilation helper.
//!
//! Wraps clang to compile eBPF C code to object files.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

/// Compiler options for eBPF programs.
#[derive(Debug, Clone)]
pub struct CompileOptions {
    /// Include directories
    pub includes: Vec<PathBuf>,
    /// Preprocessor defines
    pub defines: Vec<(String, Option<String>)>,
    /// Generate BTF (BPF Type Format) for CO-RE
    pub btf: bool,
    /// Optimization level (0-3, default 2)
    pub opt_level: u8,
    /// Target architecture (default: bpf)
    pub target: String,
    /// Additional clang flags
    pub extra_flags: Vec<String>,
}

impl Default for CompileOptions {
    fn default() -> Self {
        Self {
            includes: vec![],
            defines: vec![],
            btf: true,
            opt_level: 2,
            target: "bpf".to_string(),
            extra_flags: vec![],
        }
    }
}

/// Result of a compilation.
#[derive(Debug)]
pub struct CompileResult {
    pub output_path: PathBuf,
    pub warnings: Vec<String>,
}

/// Find clang binary.
fn find_clang() -> Result<PathBuf> {
    // Try common clang names
    for name in &["clang", "clang-17", "clang-16", "clang-15", "clang-14"] {
        if let Ok(path) = which::which(name) {
            return Ok(path);
        }
    }
    bail!(
        "clang not found. Please install clang:\n\
         Ubuntu/Debian: sudo apt install clang\n\
         Fedora: sudo dnf install clang\n\
         Arch: sudo pacman -S clang"
    );
}

/// Find common BPF header locations.
///
/// We prioritize libbpf headers and system UAPI headers over kernel-internal headers
/// to avoid issues with incomplete kernel header installations.
fn find_bpf_headers() -> Vec<PathBuf> {
    let mut paths = vec![];

    // Priority 1: libbpf and system headers (these work standalone)
    let system_headers = [
        "/usr/include",        // System includes (has linux/bpf.h from UAPI)
    ];

    for path in &system_headers {
        let p = PathBuf::from(path);
        if p.is_dir() {
            paths.push(p);
        }
    }

    paths
}

/// Compile an eBPF C source file to an object file.
pub fn compile(source: &Path, output: Option<&Path>, options: &CompileOptions) -> Result<CompileResult> {
    let clang = find_clang()?;

    // Determine output path
    let output_path = match output {
        Some(p) => p.to_path_buf(),
        None => {
            let mut p = source.to_path_buf();
            p.set_extension("o");
            p
        }
    };

    // Build clang command
    let mut cmd = Command::new(&clang);

    // Target
    cmd.arg("-target").arg(&options.target);

    // Optimization
    cmd.arg(format!("-O{}", options.opt_level));

    // Generate debug info for BTF
    if options.btf {
        cmd.arg("-g");
    }

    // Compile only, don't link
    cmd.arg("-c");

    // Add standard BPF defines
    cmd.arg("-D__BPF_TRACING__");
    cmd.arg("-D__TARGET_ARCH_x86");

    // Add user defines
    for (key, value) in &options.defines {
        match value {
            Some(v) => cmd.arg(format!("-D{}={}", key, v)),
            None => cmd.arg(format!("-D{}", key)),
        };
    }

    // Add standard include paths
    for path in find_bpf_headers() {
        cmd.arg("-I").arg(&path);
    }

    // Add user include paths
    for path in &options.includes {
        cmd.arg("-I").arg(path);
    }

    // Extra flags
    for flag in &options.extra_flags {
        cmd.arg(flag);
    }

    // Source and output
    cmd.arg(source);
    cmd.arg("-o").arg(&output_path);

    // Run clang
    let output = cmd
        .output()
        .with_context(|| format!("Failed to run clang: {}", clang.display()))?;

    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        // Parse and improve error messages
        let improved = improve_error_message(&stderr);
        bail!("Compilation failed:\n{}", improved);
    }

    // Parse warnings from stderr
    let warnings: Vec<String> = stderr
        .lines()
        .filter(|line| line.contains("warning:"))
        .map(String::from)
        .collect();

    Ok(CompileResult {
        output_path,
        warnings,
    })
}

/// Improve error messages with helpful suggestions.
fn improve_error_message(stderr: &str) -> String {
    let mut improved = String::new();

    for line in stderr.lines() {
        improved.push_str(line);
        improved.push('\n');

        // Add helpful suggestions based on common errors
        if line.contains("fatal error: 'bpf/bpf_helpers.h' file not found") {
            improved.push_str("\n  💡 Suggestion: Install libbpf development headers:\n");
            improved.push_str("     Ubuntu/Debian: sudo apt install libbpf-dev\n");
            improved.push_str("     Fedora: sudo dnf install libbpf-devel\n");
        } else if line.contains("fatal error: 'linux/bpf.h' file not found") {
            improved.push_str("\n  💡 Suggestion: Install kernel headers:\n");
            improved.push_str("     Ubuntu/Debian: sudo apt install linux-headers-$(uname -r)\n");
            improved.push_str("     Fedora: sudo dnf install kernel-devel\n");
        } else if line.contains("unknown target CPU") {
            improved.push_str("\n  💡 Suggestion: Your clang may not support BPF target.\n");
            improved.push_str("     Try installing a newer clang version.\n");
        } else if line.contains("use of undeclared identifier") {
            if line.contains("bpf_printk") {
                improved.push_str("\n  💡 Suggestion: Add at the top of your file:\n");
                improved.push_str("     #include <bpf/bpf_helpers.h>\n");
            } else if line.contains("PT_REGS") || line.contains("ctx->") {
                improved.push_str("\n  💡 Suggestion: For accessing function arguments, include:\n");
                improved.push_str("     #include <bpf/bpf_tracing.h>\n");
            }
        } else if line.contains("invalid program type") {
            improved.push_str("\n  💡 Suggestion: Check your SEC() annotation matches a valid program type.\n");
            improved.push_str("     Common types: kprobe/, kretprobe/, tracepoint/, xdp\n");
        }
    }

    improved
}

/// Template types for new eBPF programs.
#[derive(Debug, Clone, Copy)]
pub enum TemplateType {
    Kprobe,
    Kretprobe,
    Tracepoint,
    Xdp,
    RawTracepoint,
}

impl std::str::FromStr for TemplateType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "kprobe" => Ok(Self::Kprobe),
            "kretprobe" => Ok(Self::Kretprobe),
            "tracepoint" | "tp" => Ok(Self::Tracepoint),
            "xdp" => Ok(Self::Xdp),
            "raw_tracepoint" | "raw_tp" => Ok(Self::RawTracepoint),
            _ => bail!("Unknown template type: {}. Valid types: kprobe, kretprobe, tracepoint, xdp, raw_tracepoint", s),
        }
    }
}

/// Generate a new eBPF program from a template.
pub fn generate_template(template: TemplateType, name: &str, target: Option<&str>) -> String {
    match template {
        TemplateType::Kprobe => generate_kprobe_template(name, target),
        TemplateType::Kretprobe => generate_kretprobe_template(name, target),
        TemplateType::Tracepoint => generate_tracepoint_template(name, target),
        TemplateType::Xdp => generate_xdp_template(name),
        TemplateType::RawTracepoint => generate_raw_tracepoint_template(name, target),
    }
}

fn generate_kprobe_template(name: &str, target: Option<&str>) -> String {
    let target = target.unwrap_or("do_sys_openat2");
    format!(r#"// {name}.c - Kprobe eBPF program
// Compile: ebpf-assist compile {name}.c
// Load:    ebpf-assist load {name}.o
// Attach:  ebpf-assist attach <id> {target}

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/{target}")
int {name}(struct pt_regs *ctx)
{{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    bpf_printk("{name}: pid=%d triggered {target}", pid);

    return 0;
}}
"#)
}

fn generate_kretprobe_template(name: &str, target: Option<&str>) -> String {
    let target = target.unwrap_or("do_sys_openat2");
    format!(r#"// {name}.c - Kretprobe eBPF program
// Compile: ebpf-assist compile {name}.c
// Load:    ebpf-assist load {name}.o
// Attach:  ebpf-assist attach <id> {target}

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("kretprobe/{target}")
int {name}(struct pt_regs *ctx)
{{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    long ret = PT_REGS_RC(ctx);

    bpf_printk("{name}: pid=%d {target} returned %ld", pid, ret);

    return 0;
}}
"#)
}

fn generate_tracepoint_template(name: &str, target: Option<&str>) -> String {
    let target = target.unwrap_or("syscalls/sys_enter_openat");
    let (category, event) = target.split_once('/').unwrap_or(("syscalls", "sys_enter_openat"));
    format!(r#"// {name}.c - Tracepoint eBPF program
// Compile: ebpf-assist compile {name}.c
// Load:    ebpf-assist load {name}.o
// Attach:  ebpf-assist attach <id> {category}:{event}

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tracepoint/{category}/{event}")
int {name}(void *ctx)
{{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    bpf_printk("{name}: pid=%d triggered {event}", pid);

    return 0;
}}
"#)
}

fn generate_xdp_template(name: &str) -> String {
    format!(r#"// {name}.c - XDP eBPF program
// Compile: ebpf-assist compile {name}.c
// Load:    ebpf-assist load {name}.o
// Attach:  ebpf-assist attach <id> eth0  (replace with your interface)

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int {name}(struct xdp_md *ctx)
{{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only process IPv4
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    bpf_printk("{name}: packet from %pI4", &ip->saddr);

    return XDP_PASS;  // XDP_DROP to drop, XDP_TX to bounce back
}}
"#)
}

fn generate_raw_tracepoint_template(name: &str, target: Option<&str>) -> String {
    let target = target.unwrap_or("sys_enter");
    format!(r#"// {name}.c - Raw tracepoint eBPF program
// Compile: ebpf-assist compile {name}.c
// Load:    ebpf-assist load {name}.o
// Attach:  ebpf-assist attach <id> {target}

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("raw_tracepoint/{target}")
int {name}(struct bpf_raw_tracepoint_args *ctx)
{{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    bpf_printk("{name}: pid=%d triggered {target}", pid);

    return 0;
}}
"#)
}
