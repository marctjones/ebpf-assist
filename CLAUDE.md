# CLAUDE.md

## Project: ebpf-assist

Enable AI assistants to develop, test, and iterate on eBPF programs without requiring interactive sudo.

## IdlerGear Usage

**ALWAYS run at session start:**
```bash
idlergear context
```

**FORBIDDEN files:** `TODO.md`, `NOTES.md`, `SESSION_*.md`, `SCRATCH.md`
**FORBIDDEN comments:** `// TODO:`, `# FIXME:`, `/* HACK: */`

**Use instead:**
- `idlergear task create "..."` - Create actionable tasks
- `idlergear note create "..."` - Capture quick thoughts
- `idlergear reference add "..."` - Store permanent documentation

## Key Design Decisions

1. **Two modes only**: Host (fast) or MicroVM (safe) - no containers
2. **Rust implementation** using aya for eBPF
3. **Polkit for auth** with credential caching
4. **MCP server** for AI integration

## Architecture Overview

- `ebpf-assistd` - Privileged daemon (runs with CAP_BPF, etc.)
- `ebpf-assist` - CLI tool (unprivileged, talks to daemon)
- MCP server mode for AI assistants

## Current Phase

Early design - see GitHub issues for roadmap.
