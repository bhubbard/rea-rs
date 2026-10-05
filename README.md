# REA-RS: Reverse Engineer Anything (Pure Rust)

<div align="center">

### Reverse engineer anything with AI agents, from app behavior down to native binaries.

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MCP Server](https://img.shields.io/badge/MCP-2024--11--05-blue.svg)](#mcp-server-for-ai-agents)
[![Rust 2021](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)

**A high-performance, memory-safe, pure-Rust fork of [morluto/rea](https://github.com/morluto/rea).**

[Quickstart](#quickstart) · [Features](#features) · [CLI Usage](#cli-usage) · [MCP Server](#mcp-server-for-ai-agents) · [Investigation Model](#investigation-model)

</div>

---

## Overview

**REA-RS** gives AI coding assistants (Claude Code, Cursor, Codex, Gemini CLI, Windsurf) and security analysts a unified, deterministic framework to investigate native binaries and application behavior.

Unlike the Node.js upstream, **REA-RS** is compiled to a single native binary:
- **Instant startup (<5ms)**: No Node.js runtime, no npm dependencies, no JIT warm-up.
- **Pure Rust Native Analysis**: Full support for **Mach-O (including Universal / Fat binaries)**, **ELF**, **PE32/PE32+**, and **.NET PE/CLI (ECMA-335 CIL)**.
- **Spec-Compliant MCP Server**: Direct JSON-RPC 2.0 communication over stdio implementing the Model Context Protocol (MCP).
- **Cryptographic Evidence Ledger**: Every finding is recorded as deterministic, content-addressed Evidence (`sha256:<digest>`).
- **Control Flow Graph (CFG) & Decompilation**: Basic block partitioning, branch resolution, and structured pseudocode generation.
- **Residual Unknowns Registry**: Tracks hypotheses, contradictions, and validation statuses with immutable revisions.
- **Finite Replay Machine**: Event-driven state machine transition verification and invariant checking.

---

## Quickstart

### Build from Source

```bash
git clone https://github.com/bhubbard/rea-rs.git
cd rea-rs
cargo build --release
```

The compiled binary will be located at `target/release/rea`.

### One-Command Agent Setup

Configure REA as an MCP server across all detected AI coding assistants:

```bash
# Preview what would be configured
rea setup --dry-run

# Configure all detected clients (Claude Code, Claude Desktop, Cursor, Gemini CLI, Windsurf)
rea setup --all-detected

# Or configure a specific client:
rea setup --client cursor
rea setup --client claude_code
```

---

## CLI Usage

### 1. Inspect Binary Headers & Sections

```bash
rea inspect /bin/ls
rea inspect /bin/ls --json
```

Outputs format (Mach-O, ELF, PE), architecture, entry point, UUID, section tables, and per-section entropy.

### 2. Extract Strings

```bash
# Extract strings with minimum length 6 matching "usage"
rea strings /bin/ls --min-len 6 --query usage
```

Attributing each string to its file offset, encoding (ASCII vs UTF-16LE), and containing section (`__cstring`, `.rodata`).

### 3. Symbol Discovery & Demangling

```bash
rea symbols /path/to/binary --query main
```

Automatically demangles Rust (`rustc-demangle`), C++ (`cpp_demangle`), and Swift symbols with export/import status.

### 4. Function Dossier & Pseudocode

```bash
# Analyze procedure by symbol name or address
rea dossier /bin/ls --procedure 0x100000700
```

Generates:
- Entry point address and byte size
- Decoded instruction stream
- Basic block partitioning
- Branch condition targets and CFG topology
- Direct callees & strings referenced
- Reconstructed structured pseudocode

### 5. Control Flow Graph (CFG)

```bash
rea cfg /bin/ls --procedure 0x100000700
```

### 6. .NET Managed Assembly Inspection (CIL)

```bash
rea managed /path/to/Assembly.dll
```

Inspects CLR headers, metadata streams (`#~`, `#Strings`, `#US`), TypeDef / MethodDef rows, and decodes ECMA-335 CIL bytecodes (`ldarg`, `call`, `stloc`, `ret`).

### 7. Binary & Artifact Comparison

```bash
rea compare /bin/ls /bin/echo
```

Computes size delta, added/removed sections, symbol changes, and string content similarity.

### 8. System Diagnostics

```bash
rea doctor
```

Inspects host OS/architecture, available disassembler providers (`native-rs`, `hopper`, `ghidra`), and agent configuration readiness.

---

## MCP Server for AI Agents

Start the Model Context Protocol server over stdio:

```bash
rea mcp
```

### Supported MCP Tools

| Tool | Description |
|------|-------------|
| `inspect_artifact` | Deep binary artifact inspection (Mach-O, ELF, PE, .NET CLI). |
| `extract_strings` | Extract ASCII and UTF-16LE strings with offsets and section mapping. |
| `search_symbols` | Search symbols with automatic Rust and C++ demangling. |
| `analyze_function` | Build function dossier: CFG, callees, strings, and pseudocode. |
| `disassemble_procedure`| Disassemble instructions with branch flow classification. |
| `inspect_cfg` | Extract Control Flow Graph basic blocks and typed branching edges. |
| `binary_overview` | High-level summary of binary format, sections, symbols, and mitigations. |
| `inspect_managed_assembly`| Inspect .NET PE metadata tables, types, and CIL methods. |
| `compare_artifacts` | Compare two binary artifacts for structural and semantic differences. |
| `compare_functions` | Compare two function dossiers across CFG topology and callees. |
| `record_evidence` | Record content-addressed, reproducible Evidence in the session bundle. |
| `get_evidence_bundle` | Return all Evidence records and residual unknowns in the session. |
| `export_evidence_bundle` | Export session evidence to byte-stable canonical JSON. |
| `import_evidence_bundle` | Import and merge an Evidence bundle from JSON. |
| `run_replay_machine` | Validate finite state replay machine against ordered events. |
| `list_unknowns` | List residual unknowns in the investigation registry. |
| `record_unknown` | Register a new residual unknown or hypothesis. |
| `doctor` | Diagnose host environment, available disassemblers, and agents. |

---

## Investigation Model

1. **Decompile & Inspect**: Open any app, library, or binary. Extract readable code, symbols, string references, and structure without source code.
2. **Understand & Trace**: Connect symbols, trace call paths, evaluate control flow graphs, and analyze dependent components.
3. **Recreate & Verify**: Leverage structured evidence and pseudocode to recreate or adapt features with clear provenance.

---

## Testing

Run all unit and integration test suites:

```bash
cargo test
```

Includes tests for:
- Binary format identification & Shannon entropy
- x86_64, x86, and ARM64 instruction disassembly
- Basic block partitioning & CFG edge generation
- ECMA-335 CIL bytecode decoding
- Canonical Evidence hashing & bundle serialization
- Finite replay state machine execution & journals
- MCP tool registration and tool invocation

---

## License

MIT License. See [LICENSE](LICENSE) for details.
