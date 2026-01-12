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
        "/usr/include", // System includes (has linux/bpf.h from UAPI)
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
pub fn compile(
    source: &Path,
    output: Option<&Path>,
    options: &CompileOptions,
) -> Result<CompileResult> {
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
                improved
                    .push_str("\n  💡 Suggestion: For accessing function arguments, include:\n");
                improved.push_str("     #include <bpf/bpf_tracing.h>\n");
            }
        } else if line.contains("invalid program type") {
            improved.push_str(
                "\n  💡 Suggestion: Check your SEC() annotation matches a valid program type.\n",
            );
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
    format!(
        r#"// {name}.c - Kprobe eBPF program
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
"#
    )
}

fn generate_kretprobe_template(name: &str, target: Option<&str>) -> String {
    let target = target.unwrap_or("do_sys_openat2");
    format!(
        r#"// {name}.c - Kretprobe eBPF program
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
"#
    )
}

fn generate_tracepoint_template(name: &str, target: Option<&str>) -> String {
    let target = target.unwrap_or("syscalls/sys_enter_openat");
    let (category, event) = target
        .split_once('/')
        .unwrap_or(("syscalls", "sys_enter_openat"));
    format!(
        r#"// {name}.c - Tracepoint eBPF program
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
"#
    )
}

fn generate_xdp_template(name: &str) -> String {
    format!(
        r#"// {name}.c - XDP eBPF program
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
"#
    )
}

fn generate_raw_tracepoint_template(name: &str, target: Option<&str>) -> String {
    let target = target.unwrap_or("sys_enter");
    format!(
        r#"// {name}.c - Raw tracepoint eBPF program
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
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== CompileOptions Tests ====================

    #[test]
    fn test_compile_options_default() {
        let opts = CompileOptions::default();
        assert!(opts.includes.is_empty());
        assert!(opts.defines.is_empty());
        assert!(opts.btf);
        assert_eq!(opts.opt_level, 2);
        assert_eq!(opts.target, "bpf");
        assert!(opts.extra_flags.is_empty());
    }

    #[test]
    fn test_compile_options_clone() {
        let opts = CompileOptions {
            includes: vec![PathBuf::from("/usr/include")],
            defines: vec![("DEBUG".to_string(), Some("1".to_string()))],
            btf: true,
            opt_level: 3,
            target: "bpf".to_string(),
            extra_flags: vec!["-Wall".to_string()],
        };
        let cloned = opts.clone();
        assert_eq!(cloned.includes.len(), 1);
        assert_eq!(cloned.defines.len(), 1);
        assert_eq!(cloned.opt_level, 3);
    }

    #[test]
    fn test_compile_options_debug() {
        let opts = CompileOptions::default();
        let debug_str = format!("{:?}", opts);
        assert!(debug_str.contains("CompileOptions"));
        assert!(debug_str.contains("btf"));
    }

    // ==================== TemplateType Tests ====================

    #[test]
    fn test_template_type_from_str_kprobe() {
        let t: TemplateType = "kprobe".parse().unwrap();
        assert!(matches!(t, TemplateType::Kprobe));
    }

    #[test]
    fn test_template_type_from_str_kretprobe() {
        let t: TemplateType = "kretprobe".parse().unwrap();
        assert!(matches!(t, TemplateType::Kretprobe));
    }

    #[test]
    fn test_template_type_from_str_tracepoint() {
        let t: TemplateType = "tracepoint".parse().unwrap();
        assert!(matches!(t, TemplateType::Tracepoint));
    }

    #[test]
    fn test_template_type_from_str_tp_alias() {
        let t: TemplateType = "tp".parse().unwrap();
        assert!(matches!(t, TemplateType::Tracepoint));
    }

    #[test]
    fn test_template_type_from_str_xdp() {
        let t: TemplateType = "xdp".parse().unwrap();
        assert!(matches!(t, TemplateType::Xdp));
    }

    #[test]
    fn test_template_type_from_str_raw_tracepoint() {
        let t: TemplateType = "raw_tracepoint".parse().unwrap();
        assert!(matches!(t, TemplateType::RawTracepoint));
    }

    #[test]
    fn test_template_type_from_str_raw_tp_alias() {
        let t: TemplateType = "raw_tp".parse().unwrap();
        assert!(matches!(t, TemplateType::RawTracepoint));
    }

    #[test]
    fn test_template_type_from_str_case_insensitive() {
        let t: TemplateType = "KPROBE".parse().unwrap();
        assert!(matches!(t, TemplateType::Kprobe));

        let t: TemplateType = "Xdp".parse().unwrap();
        assert!(matches!(t, TemplateType::Xdp));

        let t: TemplateType = "TracePoint".parse().unwrap();
        assert!(matches!(t, TemplateType::Tracepoint));
    }

    #[test]
    fn test_template_type_from_str_invalid() {
        let result: Result<TemplateType> = "invalid".parse();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Unknown template type"));
    }

    #[test]
    fn test_template_type_clone_copy() {
        let t = TemplateType::Kprobe;
        let cloned = t.clone();
        let copied = t;
        assert!(matches!(cloned, TemplateType::Kprobe));
        assert!(matches!(copied, TemplateType::Kprobe));
    }

    #[test]
    fn test_template_type_debug() {
        let t = TemplateType::Kprobe;
        let debug = format!("{:?}", t);
        assert!(debug.contains("Kprobe"));
    }

    // ==================== Template Generation Tests ====================

    #[test]
    fn test_generate_kprobe_template() {
        let content = generate_template(TemplateType::Kprobe, "my_probe", None);
        assert!(content.contains("my_probe.c - Kprobe"));
        assert!(content.contains("SEC(\"kprobe/"));
        assert!(content.contains("do_sys_openat2")); // default target
        assert!(content.contains("bpf_printk"));
        assert!(content.contains("LICENSE"));
    }

    #[test]
    fn test_generate_kprobe_template_custom_target() {
        let content = generate_template(TemplateType::Kprobe, "my_probe", Some("tcp_connect"));
        assert!(content.contains("SEC(\"kprobe/tcp_connect\")"));
        assert!(content.contains("tcp_connect"));
    }

    #[test]
    fn test_generate_kretprobe_template() {
        let content = generate_template(TemplateType::Kretprobe, "ret_probe", None);
        assert!(content.contains("ret_probe.c - Kretprobe"));
        assert!(content.contains("SEC(\"kretprobe/"));
        assert!(content.contains("PT_REGS_RC")); // return value access
    }

    #[test]
    fn test_generate_kretprobe_template_custom_target() {
        let content = generate_template(TemplateType::Kretprobe, "ret_probe", Some("sys_read"));
        assert!(content.contains("SEC(\"kretprobe/sys_read\")"));
    }

    #[test]
    fn test_generate_tracepoint_template() {
        let content = generate_template(TemplateType::Tracepoint, "tp_probe", None);
        assert!(content.contains("tp_probe.c - Tracepoint"));
        assert!(content.contains("SEC(\"tracepoint/"));
        assert!(content.contains("syscalls/sys_enter_openat")); // default
    }

    #[test]
    fn test_generate_tracepoint_template_custom_target() {
        let content = generate_template(
            TemplateType::Tracepoint,
            "tp_probe",
            Some("sched/sched_switch"),
        );
        assert!(content.contains("SEC(\"tracepoint/sched/sched_switch\")"));
    }

    #[test]
    fn test_generate_xdp_template() {
        let content = generate_template(TemplateType::Xdp, "my_xdp", None);
        assert!(content.contains("my_xdp.c - XDP"));
        assert!(content.contains("SEC(\"xdp\")"));
        assert!(content.contains("struct xdp_md"));
        assert!(content.contains("XDP_PASS"));
        assert!(content.contains("struct ethhdr"));
        assert!(content.contains("struct iphdr"));
    }

    #[test]
    fn test_generate_raw_tracepoint_template() {
        let content = generate_template(TemplateType::RawTracepoint, "raw_tp", None);
        assert!(content.contains("raw_tp.c - Raw tracepoint"));
        assert!(content.contains("SEC(\"raw_tracepoint/"));
        assert!(content.contains("sys_enter")); // default target
    }

    #[test]
    fn test_generate_raw_tracepoint_template_custom_target() {
        let content =
            generate_template(TemplateType::RawTracepoint, "raw_tp", Some("sched_switch"));
        assert!(content.contains("SEC(\"raw_tracepoint/sched_switch\")"));
    }

    #[test]
    fn test_generated_templates_have_license() {
        for template_type in [
            TemplateType::Kprobe,
            TemplateType::Kretprobe,
            TemplateType::Tracepoint,
            TemplateType::Xdp,
            TemplateType::RawTracepoint,
        ] {
            let content = generate_template(template_type, "test", None);
            assert!(
                content.contains("LICENSE"),
                "Template {:?} missing LICENSE",
                template_type
            );
            assert!(
                content.contains("GPL"),
                "Template {:?} missing GPL",
                template_type
            );
        }
    }

    #[test]
    fn test_generated_templates_have_bpf_includes() {
        for template_type in [
            TemplateType::Kprobe,
            TemplateType::Kretprobe,
            TemplateType::Tracepoint,
            TemplateType::Xdp,
            TemplateType::RawTracepoint,
        ] {
            let content = generate_template(template_type, "test", None);
            assert!(
                content.contains("#include <linux/bpf.h>"),
                "Template {:?} missing bpf.h",
                template_type
            );
            assert!(
                content.contains("#include <bpf/bpf_helpers.h>"),
                "Template {:?} missing bpf_helpers.h",
                template_type
            );
        }
    }

    // ==================== Error Message Improvement Tests ====================

    #[test]
    fn test_improve_error_message_bpf_helpers() {
        let input = "fatal error: 'bpf/bpf_helpers.h' file not found";
        let result = improve_error_message(input);
        assert!(result.contains("libbpf-dev"));
        assert!(result.contains("apt install"));
    }

    #[test]
    fn test_improve_error_message_linux_bpf() {
        let input = "fatal error: 'linux/bpf.h' file not found";
        let result = improve_error_message(input);
        assert!(result.contains("kernel headers"));
        assert!(result.contains("linux-headers"));
    }

    #[test]
    fn test_improve_error_message_unknown_target() {
        let input = "unknown target CPU 'bpf'";
        let result = improve_error_message(input);
        assert!(result.contains("newer clang"));
    }

    #[test]
    fn test_improve_error_message_undeclared_bpf_printk() {
        let input = "use of undeclared identifier 'bpf_printk'";
        let result = improve_error_message(input);
        assert!(result.contains("bpf/bpf_helpers.h"));
    }

    #[test]
    fn test_improve_error_message_undeclared_pt_regs() {
        let input = "use of undeclared identifier 'PT_REGS_PARM1'";
        let result = improve_error_message(input);
        assert!(result.contains("bpf/bpf_tracing.h"));
    }

    #[test]
    fn test_improve_error_message_invalid_program_type() {
        let input = "invalid program type in SEC() annotation";
        let result = improve_error_message(input);
        assert!(result.contains("SEC()"));
        assert!(result.contains("kprobe/"));
    }

    #[test]
    fn test_improve_error_message_passthrough() {
        let input = "some random error without special handling";
        let result = improve_error_message(input);
        assert!(result.contains("some random error"));
    }

    // ==================== find_bpf_headers Tests ====================

    #[test]
    fn test_find_bpf_headers_returns_vec() {
        let headers = find_bpf_headers();
        // Should return a vec (may be empty or contain /usr/include)
        let _ = headers.len();
    }

    #[test]
    fn test_find_bpf_headers_checks_existence() {
        let headers = find_bpf_headers();
        // All returned paths should exist
        for path in headers {
            assert!(
                path.is_dir(),
                "Path {} should be a directory",
                path.display()
            );
        }
    }
}
