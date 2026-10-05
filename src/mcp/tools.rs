use crate::binary::analyzer::NativeAnalyzer;
use crate::binary::dossier::build_function_dossier;
use crate::comparison::artifacts::compare_artifacts;
use crate::comparison::functions::compare_functions;
use crate::dotnet::inspect_managed_assembly;
use crate::evidence::{EvidenceBundle, EvidenceRecord, UnknownRecord, UnknownSeverity};
use crate::mcp::protocol::{McpPrompt, McpTool, McpToolCallResult};
use crate::replay::machine::{run_replay_machine, ReplayEvent, ReplayMachineSpec};
use serde_json::json;
use std::sync::{Arc, Mutex};

pub struct ToolRegistry {
    bundle: Arc<Mutex<EvidenceBundle>>,
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            bundle: Arc::new(Mutex::new(EvidenceBundle::new())),
        }
    }

    pub fn list_tools(&self) -> Vec<McpTool> {
        vec![
            McpTool {
                name: "inspect_artifact".to_string(),
                description: "Deep binary artifact inspection (Mach-O, ELF, PE, .NET CLI). Returns format, architecture, CPU details, entry point, UUID, sections, entropy, and signs evidence.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Absolute path to the binary or application file" }
                    },
                    "required": ["path"]
                }),
            },
            McpTool {
                name: "extract_strings".to_string(),
                description: "Extract ASCII and UTF-16LE strings with file offsets and section mapping.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Target binary path" },
                        "min_len": { "type": "integer", "description": "Minimum string length (default: 4)", "default": 4 },
                        "query": { "type": "string", "description": "Optional search filter string" }
                    },
                    "required": ["path"]
                }),
            },
            McpTool {
                name: "search_symbols".to_string(),
                description: "Search imported, exported, and local symbols with automatic Rust and C++ demangling.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Target binary path" },
                        "query": { "type": "string", "description": "Optional symbol name query" }
                    },
                    "required": ["path"]
                }),
            },
            McpTool {
                name: "analyze_function".to_string(),
                description: "Build a comprehensive function dossier: entrypoint, size, basic block CFG, callees, strings referenced, and pseudocode.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Target binary path" },
                        "procedure": { "type": "string", "description": "Procedure symbol name or hex address (e.g. 0x1000)" },
                        "max_instructions": { "type": "integer", "description": "Maximum instructions to decode", "default": 512 }
                    },
                    "required": ["path", "procedure"]
                }),
            },
            McpTool {
                name: "disassemble_procedure".to_string(),
                description: "Disassemble instructions for a procedure with flow control classification and branch target analysis.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Target binary path" },
                        "procedure": { "type": "string", "description": "Procedure symbol name or hex address" },
                        "max_instructions": { "type": "integer", "default": 256 }
                    },
                    "required": ["path", "procedure"]
                }),
            },
            McpTool {
                name: "inspect_cfg".to_string(),
                description: "Extract the Control Flow Graph (CFG) for a procedure: basic blocks and typed branching edges.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Target binary path" },
                        "procedure": { "type": "string", "description": "Procedure symbol name or hex address" }
                    },
                    "required": ["path", "procedure"]
                }),
            },
            McpTool {
                name: "binary_overview".to_string(),
                description: "High-level overview of a binary: format, sections, symbol count, string counts, and security mitigations.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Target binary path" }
                    },
                    "required": ["path"]
                }),
            },
            McpTool {
                name: "inspect_managed_assembly".to_string(),
                description: "Inspect a .NET PE/CLI assembly: CLR runtime header, metadata streams (#~, #Strings, #US), assembly definition, and TypeDef/MethodDef lists.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Path to .NET managed PE/DLL/EXE file" }
                    },
                    "required": ["path"]
                }),
            },
            McpTool {
                name: "compare_artifacts".to_string(),
                description: "Compare two binary artifacts: section diffs, symbol additions/deletions, size deltas, and string similarity.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "left": { "type": "string", "description": "Path to first binary" },
                        "right": { "type": "string", "description": "Path to second binary" }
                    },
                    "required": ["left", "right"]
                }),
            },
            McpTool {
                name: "compare_functions".to_string(),
                description: "Compare two function dossiers: CFG topology diff, block count delta, instruction count, common/added/removed callees, and similarity score.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "left_path": { "type": "string" },
                        "left_procedure": { "type": "string" },
                        "right_path": { "type": "string" },
                        "right_procedure": { "type": "string" }
                    },
                    "required": ["left_path", "left_procedure", "right_path", "right_procedure"]
                }),
            },
            McpTool {
                name: "record_evidence".to_string(),
                description: "Record an immutable, content-addressed Evidence record in the active session bundle.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "artifact_id": { "type": "string" },
                        "provider": { "type": "string", "default": "native-rs" },
                        "authority": { "type": "string", "default": "static-analysis" },
                        "confidence": { "type": "number", "default": 1.0 },
                        "facets": { "type": "object" },
                        "limitations": { "type": "array", "items": { "type": "string" } }
                    },
                    "required": ["artifact_id", "facets"]
                }),
            },
            McpTool {
                name: "get_evidence_bundle".to_string(),
                description: "Return all Evidence records and residual unknowns currently collected in the session.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {}
                }),
            },
            McpTool {
                name: "export_evidence_bundle".to_string(),
                description: "Export the session's deterministic Evidence bundle to a local JSON file.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Destination file path" },
                        "overwrite": { "type": "boolean", "default": false }
                    },
                    "required": ["path"]
                }),
            },
            McpTool {
                name: "import_evidence_bundle".to_string(),
                description: "Import and merge an Evidence bundle from a local JSON file.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Path to bundle JSON file" }
                    },
                    "required": ["path"]
                }),
            },
            McpTool {
                name: "run_replay_machine".to_string(),
                description: "Validate a finite state replay machine against ordered events and return the transition journal.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "spec": { "type": "object" },
                        "events": { "type": "array", "items": { "type": "object" } }
                    },
                    "required": ["spec", "events"]
                }),
            },
            McpTool {
                name: "list_unknowns".to_string(),
                description: "List residual unknowns in the active investigation registry.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {}
                }),
            },
            McpTool {
                name: "record_unknown".to_string(),
                description: "Register a new residual unknown or hypothesis in the investigation registry.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "id": { "type": "string" },
                        "domain": { "type": "string" },
                        "severity": { "type": "string", "enum": ["low", "medium", "high", "critical"] },
                        "hypothesis": { "type": "string" },
                        "related_evidence_ids": { "type": "array", "items": { "type": "string" } }
                    },
                    "required": ["id", "domain", "severity", "hypothesis"]
                }),
            },
            McpTool {
                name: "doctor".to_string(),
                description: "Check system health: native architecture, available disassemblers (native, Hopper, Ghidra), compilers, and environment status.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {}
                }),
            },
        ]
    }

    pub fn list_prompts(&self) -> Vec<McpPrompt> {
        vec![
            McpPrompt {
                name: "investigate_feature".to_string(),
                description: "Guide the agent to investigate a specific app feature from binary down to pseudocode.".to_string(),
                arguments: vec![
                    crate::mcp::protocol::McpPromptArgument {
                        name: "app_path".to_string(),
                        description: "Path to the application or binary".to_string(),
                        required: true,
                    },
                    crate::mcp::protocol::McpPromptArgument {
                        name: "feature".to_string(),
                        description: "Name or description of the feature to reverse engineer".to_string(),
                        required: true,
                    },
                ],
            },
            McpPrompt {
                name: "decompile_procedure".to_string(),
                description: "Decompile a specific procedure into pseudocode, CFG, and callee relationships.".to_string(),
                arguments: vec![
                    crate::mcp::protocol::McpPromptArgument {
                        name: "app_path".to_string(),
                        description: "Path to binary".to_string(),
                        required: true,
                    },
                    crate::mcp::protocol::McpPromptArgument {
                        name: "procedure".to_string(),
                        description: "Procedure name or hex address".to_string(),
                        required: true,
                    },
                ],
            },
        ]
    }

    pub fn call_tool(&self, name: &str, params: serde_json::Value) -> McpToolCallResult {
        match name {
            "inspect_artifact" => {
                let path = match params.get("path").and_then(|p| p.as_str()) {
                    Some(p) => p,
                    None => return McpToolCallResult::error("Missing 'path' argument"),
                };
                match NativeAnalyzer::inspect_artifact(path) {
                    Ok((info, sections, record)) => {
                        self.bundle.lock().unwrap().add_record(record.clone());
                        McpToolCallResult::json(&json!({
                            "artifact": info,
                            "sections": sections,
                            "evidence": record,
                        }))
                    }
                    Err(e) => McpToolCallResult::error(e.to_string()),
                }
            }
            "extract_strings" => {
                let path = match params.get("path").and_then(|p| p.as_str()) {
                    Some(p) => p,
                    None => return McpToolCallResult::error("Missing 'path' argument"),
                };
                let min_len = params.get("min_len").and_then(|m| m.as_u64()).unwrap_or(4) as usize;
                let query = params.get("query").and_then(|q| q.as_str());

                match NativeAnalyzer::strings(path, min_len, query) {
                    Ok((strings, record)) => {
                        self.bundle.lock().unwrap().add_record(record.clone());
                        McpToolCallResult::json(&json!({
                            "count": strings.len(),
                            "strings": strings,
                            "evidence": record,
                        }))
                    }
                    Err(e) => McpToolCallResult::error(e.to_string()),
                }
            }
            "search_symbols" => {
                let path = match params.get("path").and_then(|p| p.as_str()) {
                    Some(p) => p,
                    None => return McpToolCallResult::error("Missing 'path' argument"),
                };
                let query = params.get("query").and_then(|q| q.as_str());

                match NativeAnalyzer::symbols(path, query) {
                    Ok((symbols, record)) => {
                        self.bundle.lock().unwrap().add_record(record.clone());
                        McpToolCallResult::json(&json!({
                            "count": symbols.len(),
                            "symbols": symbols,
                            "evidence": record,
                        }))
                    }
                    Err(e) => McpToolCallResult::error(e.to_string()),
                }
            }
            "analyze_function" => {
                let path = match params.get("path").and_then(|p| p.as_str()) {
                    Some(p) => p,
                    None => return McpToolCallResult::error("Missing 'path' argument"),
                };
                let procedure = match params.get("procedure").and_then(|p| p.as_str()) {
                    Some(p) => p,
                    None => return McpToolCallResult::error("Missing 'procedure' argument"),
                };
                let max_inst = params.get("max_instructions").and_then(|m| m.as_u64()).unwrap_or(512) as usize;

                match NativeAnalyzer::function_dossier(path, procedure, max_inst) {
                    Ok((dossier, record)) => {
                        self.bundle.lock().unwrap().add_record(record.clone());
                        McpToolCallResult::json(&json!({
                            "dossier": dossier,
                            "evidence": record,
                        }))
                    }
                    Err(e) => McpToolCallResult::error(e.to_string()),
                }
            }
            "disassemble_procedure" => {
                let path = match params.get("path").and_then(|p| p.as_str()) {
                    Some(p) => p,
                    None => return McpToolCallResult::error("Missing 'path' argument"),
                };
                let procedure = match params.get("procedure").and_then(|p| p.as_str()) {
                    Some(p) => p,
                    None => return McpToolCallResult::error("Missing 'procedure' argument"),
                };
                let max_inst = params.get("max_instructions").and_then(|m| m.as_u64()).unwrap_or(256) as usize;

                match build_function_dossier(path, procedure, max_inst) {
                    Ok(dossier) => {
                        let instructions: Vec<_> = dossier.cfg.blocks.into_iter().flat_map(|b| b.instructions).collect();
                        McpToolCallResult::json(&json!({
                            "procedure": dossier.name,
                            "address": dossier.address,
                            "instructions": instructions,
                        }))
                    }
                    Err(e) => McpToolCallResult::error(e.to_string()),
                }
            }
            "inspect_cfg" => {
                let path = match params.get("path").and_then(|p| p.as_str()) {
                    Some(p) => p,
                    None => return McpToolCallResult::error("Missing 'path' argument"),
                };
                let procedure = match params.get("procedure").and_then(|p| p.as_str()) {
                    Some(p) => p,
                    None => return McpToolCallResult::error("Missing 'procedure' argument"),
                };

                match build_function_dossier(path, procedure, 512) {
                    Ok(dossier) => McpToolCallResult::json(&dossier.cfg),
                    Err(e) => McpToolCallResult::error(e.to_string()),
                }
            }
            "binary_overview" => {
                let path = match params.get("path").and_then(|p| p.as_str()) {
                    Some(p) => p,
                    None => return McpToolCallResult::error("Missing 'path' argument"),
                };
                match NativeAnalyzer::inspect_artifact(path) {
                    Ok((info, sections, record)) => {
                        McpToolCallResult::json(&json!({
                            "overview": {
                                "file_name": info.file_name,
                                "size": info.size_bytes,
                                "format": info.format,
                                "architecture": info.architecture,
                                "sha256": info.sha256,
                                "sections_count": sections.len(),
                                "symbols_count": info.symbol_count,
                            },
                            "sections": sections,
                            "evidence": record,
                        }))
                    }
                    Err(e) => McpToolCallResult::error(e.to_string()),
                }
            }
            "inspect_managed_assembly" => {
                let path = match params.get("path").and_then(|p| p.as_str()) {
                    Some(p) => p,
                    None => return McpToolCallResult::error("Missing 'path' argument"),
                };
                match inspect_managed_assembly(path) {
                    Ok(assembly) => McpToolCallResult::json(&assembly),
                    Err(e) => McpToolCallResult::error(e.to_string()),
                }
            }
            "compare_artifacts" => {
                let left = match params.get("left").and_then(|p| p.as_str()) {
                    Some(p) => p,
                    None => return McpToolCallResult::error("Missing 'left' path"),
                };
                let right = match params.get("right").and_then(|p| p.as_str()) {
                    Some(p) => p,
                    None => return McpToolCallResult::error("Missing 'right' path"),
                };
                match compare_artifacts(left, right) {
                    Ok(delta) => McpToolCallResult::json(&delta),
                    Err(e) => McpToolCallResult::error(e.to_string()),
                }
            }
            "compare_functions" => {
                let left_path = match params.get("left_path").and_then(|p| p.as_str()) {
                    Some(p) => p,
                    None => return McpToolCallResult::error("Missing 'left_path'"),
                };
                let left_proc = match params.get("left_procedure").and_then(|p| p.as_str()) {
                    Some(p) => p,
                    None => return McpToolCallResult::error("Missing 'left_procedure'"),
                };
                let right_path = match params.get("right_path").and_then(|p| p.as_str()) {
                    Some(p) => p,
                    None => return McpToolCallResult::error("Missing 'right_path'"),
                };
                let right_proc = match params.get("right_procedure").and_then(|p| p.as_str()) {
                    Some(p) => p,
                    None => return McpToolCallResult::error("Missing 'right_procedure'"),
                };

                let left_dossier = match build_function_dossier(left_path, left_proc, 512) {
                    Ok(d) => d,
                    Err(e) => return McpToolCallResult::error(format!("Left dossier error: {}", e)),
                };
                let right_dossier = match build_function_dossier(right_path, right_proc, 512) {
                    Ok(d) => d,
                    Err(e) => return McpToolCallResult::error(format!("Right dossier error: {}", e)),
                };

                let delta = compare_functions(&left_dossier, &right_dossier);
                McpToolCallResult::json(&delta)
            }
            "record_evidence" => {
                let artifact_id = match params.get("artifact_id").and_then(|a| a.as_str()) {
                    Some(a) => a,
                    None => return McpToolCallResult::error("Missing 'artifact_id'"),
                };
                let provider = params.get("provider").and_then(|p| p.as_str()).unwrap_or("native-rs");
                let authority = params.get("authority").and_then(|a| a.as_str()).unwrap_or("static-analysis");
                let confidence = params.get("confidence").and_then(|c| c.as_f64()).unwrap_or(1.0);
                let facets = params.get("facets").cloned().unwrap_or(json!({}));
                let limitations: Vec<String> = params
                    .get("limitations")
                    .and_then(|l| l.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                    .unwrap_or_default();

                let record = EvidenceRecord::new(artifact_id, provider, authority, confidence, facets, limitations);
                self.bundle.lock().unwrap().add_record(record.clone());
                McpToolCallResult::json(&record)
            }
            "get_evidence_bundle" => {
                let bundle = self.bundle.lock().unwrap().clone();
                McpToolCallResult::json(&bundle)
            }
            "export_evidence_bundle" => {
                let path = match params.get("path").and_then(|p| p.as_str()) {
                    Some(p) => p,
                    None => return McpToolCallResult::error("Missing 'path'"),
                };
                let overwrite = params.get("overwrite").and_then(|o| o.as_bool()).unwrap_or(false);
                let bundle = self.bundle.lock().unwrap().clone();
                match bundle.export_to_file(path, overwrite) {
                    Ok(_) => McpToolCallResult::success(format!("Evidence bundle exported successfully to {}", path)),
                    Err(e) => McpToolCallResult::error(e.to_string()),
                }
            }
            "import_evidence_bundle" => {
                let path = match params.get("path").and_then(|p| p.as_str()) {
                    Some(p) => p,
                    None => return McpToolCallResult::error("Missing 'path'"),
                };
                match EvidenceBundle::import_from_file(path) {
                    Ok(imported) => {
                        let mut b = self.bundle.lock().unwrap();
                        for r in imported.records {
                            b.add_record(r);
                        }
                        for u in imported.unknowns {
                            b.add_unknown(u);
                        }
                        McpToolCallResult::success(format!("Imported evidence bundle from {}", path))
                    }
                    Err(e) => McpToolCallResult::error(e.to_string()),
                }
            }
            "run_replay_machine" => {
                let spec: ReplayMachineSpec = match params.get("spec").and_then(|s| serde_json::from_value(s.clone()).ok()) {
                    Some(s) => s,
                    None => return McpToolCallResult::error("Invalid or missing 'spec'"),
                };
                let events: Vec<ReplayEvent> = match params.get("events").and_then(|e| serde_json::from_value(e.clone()).ok()) {
                    Some(e) => e,
                    None => return McpToolCallResult::error("Invalid or missing 'events'"),
                };
                match run_replay_machine(&spec, &events) {
                    Ok(journal) => McpToolCallResult::json(&journal),
                    Err(e) => McpToolCallResult::error(e.to_string()),
                }
            }
            "list_unknowns" => {
                let bundle = self.bundle.lock().unwrap();
                McpToolCallResult::json(&bundle.unknowns)
            }
            "record_unknown" => {
                let id = match params.get("id").and_then(|i| i.as_str()) {
                    Some(i) => i,
                    None => return McpToolCallResult::error("Missing 'id'"),
                };
                let domain = match params.get("domain").and_then(|d| d.as_str()) {
                    Some(d) => d,
                    None => return McpToolCallResult::error("Missing 'domain'"),
                };
                let severity = match params.get("severity").and_then(|s| s.as_str()) {
                    Some("low") => UnknownSeverity::Low,
                    Some("medium") => UnknownSeverity::Medium,
                    Some("high") => UnknownSeverity::High,
                    Some("critical") => UnknownSeverity::Critical,
                    _ => UnknownSeverity::Medium,
                };
                let hypothesis = match params.get("hypothesis").and_then(|h| h.as_str()) {
                    Some(h) => h,
                    None => return McpToolCallResult::error("Missing 'hypothesis'"),
                };
                let related_ids: Vec<String> = params
                    .get("related_evidence_ids")
                    .and_then(|r| r.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                    .unwrap_or_default();

                let unknown = UnknownRecord::new(id, domain, severity, hypothesis, related_ids);
                self.bundle.lock().unwrap().add_unknown(unknown.clone());
                McpToolCallResult::json(&unknown)
            }
            "doctor" => {
                let providers = crate::providers::list_providers();
                let status = json!({
                    "rea_version": "3.2.1",
                    "host_os": std::env::consts::OS,
                    "host_arch": std::env::consts::ARCH,
                    "providers": providers.into_iter().map(|(id, desc, avail)| json!({
                        "id": id,
                        "description": desc,
                        "available": avail
                    })).collect::<Vec<_>>(),
                });
                McpToolCallResult::json(&status)
            }
            other => McpToolCallResult::error(format!("Unknown tool: {}", other)),
        }
    }
}
