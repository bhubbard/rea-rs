pub mod args;
pub mod doctor;
pub mod setup;

pub use args::{Cli, Commands, EvidenceCommands};
pub use doctor::run_doctor;
pub use setup::{configure_agent, detect_clients, SUPPORTED_CLIENTS};

use crate::binary::analyzer::NativeAnalyzer;
use crate::binary::dossier::build_function_dossier;
use crate::comparison::artifacts::compare_artifacts;
use crate::dotnet::inspect_managed_assembly;
use crate::error::Result;
use crate::evidence::EvidenceBundle;
use crate::mcp::run_mcp_server;
use crate::replay::machine::run_replay_machine;
use colored::Colorize;

pub async fn execute_cli(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Inspect { path, json } => {
            let (info, sections, evidence) = NativeAnalyzer::inspect_artifact(&path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "artifact": info,
                    "sections": sections,
                    "evidence": evidence,
                }))?);
            } else {
                println!("\n{}", "Artifact Binary Inspection:".bold().cyan());
                println!("  Path:         {}", info.path);
                println!("  Format:       {:?}", info.format);
                println!("  Architecture: {:?}", info.architecture);
                println!("  Size:         {} bytes", info.size_bytes);
                println!("  SHA-256:      {}", info.sha256);
                if let Some(entry) = info.entry_point {
                    println!("  Entry Point:  0x{:x}", entry);
                }
                if let Some(uuid) = &info.uuid {
                    println!("  UUID:         {}", uuid);
                }
                println!("  Sections:     {}", info.section_count);
                println!("  Symbols:      {}", info.symbol_count);

                println!("\n{}", "Sections:".bold());
                for s in sections.iter().take(20) {
                    println!("  {:<20} addr=0x{:08x} size={:<8} perm={} entropy={:.2}",
                        s.name.bold(), s.address, s.size, s.permissions, s.entropy);
                }
                if sections.len() > 20 {
                    println!("  ... and {} more sections", sections.len() - 20);
                }
            }
        }
        Commands::Strings { path, min_len, query, json } => {
            let (strings, evidence) = NativeAnalyzer::strings(&path, min_len, query.as_deref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "count": strings.len(),
                    "strings": strings,
                    "evidence": evidence,
                }))?);
            } else {
                println!("\n{} (found {} strings):", "Extracted Strings".bold().cyan(), strings.len());
                for s in strings.iter().take(50) {
                    let sec = s.section.as_deref().unwrap_or("?");
                    let kind = if s.is_utf16 { "UTF16" } else { "ASCII" };
                    println!("  0x{:08x} [{}] ({:<12}) {}", s.offset, kind.dimmed(), sec.yellow(), s.value);
                }
                if strings.len() > 50 {
                    println!("  ... and {} more strings", strings.len() - 50);
                }
            }
        }
        Commands::Symbols { path, query, json } => {
            let (symbols, evidence) = NativeAnalyzer::symbols(&path, query.as_deref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "count": symbols.len(),
                    "symbols": symbols,
                    "evidence": evidence,
                }))?);
            } else {
                println!("\n{} (found {} symbols):", "Symbol Table".bold().cyan(), symbols.len());
                for sym in symbols.iter().take(50) {
                    let disp = sym.demangled_name.as_ref().unwrap_or(&sym.name);
                    let exp = if sym.is_exported { "EXP".green() } else { "   ".normal() };
                    let imp = if sym.is_imported { "IMP".yellow() } else { "   ".normal() };
                    println!("  0x{:08x} [{}] [{}] {:<10?} {}", sym.address, exp, imp, sym.kind, disp);
                }
                if symbols.len() > 50 {
                    println!("  ... and {} more symbols", symbols.len() - 50);
                }
            }
        }
        Commands::Dossier { path, procedure, max_instructions, json } => {
            let (dossier, evidence) = NativeAnalyzer::function_dossier(&path, &procedure, max_instructions)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "dossier": dossier,
                    "evidence": evidence,
                }))?);
            } else {
                let disp = dossier.demangled_name.as_ref().unwrap_or(&dossier.name);
                println!("\n{} {}", "Function Dossier:".bold().cyan(), disp.bold());
                println!("  Address:           0x{:x}", dossier.address);
                println!("  Size:              {} bytes", dossier.size);
                println!("  Instruction Count: {}", dossier.instruction_count);
                println!("  Basic Blocks:      {}", dossier.block_count);
                if !dossier.called_symbols.is_empty() {
                    println!("  Callees:           {}", dossier.called_symbols.join(", "));
                }
                if !dossier.string_references.is_empty() {
                    println!("  Referenced Strings: {:?}", dossier.string_references);
                }
                if let Some(pseudo) = &dossier.pseudocode {
                    println!("\n{}", "Pseudocode Reconstruction:".bold().green());
                    println!("{}", pseudo);
                }
            }
        }
        Commands::Disasm { path, procedure, max_instructions, json } => {
            let dossier = build_function_dossier(&path, &procedure, max_instructions)?;
            if json {
                let insts: Vec<_> = dossier.cfg.blocks.into_iter().flat_map(|b| b.instructions).collect();
                println!("{}", serde_json::to_string_pretty(&insts)?);
            } else {
                println!("\n{} {}:", "Disassembly for".bold().cyan(), dossier.name.bold());
                for block in &dossier.cfg.blocks {
                    println!("  {}:", format!("bb_{:x}", block.start_address).yellow());
                    for inst in &block.instructions {
                        println!("    0x{:08x}:  {:<16}  {:<8} {}",
                            inst.address, inst.bytes.dimmed(), inst.mnemonic.bold(), inst.operands);
                    }
                }
            }
        }
        Commands::Cfg { path, procedure, json } => {
            let dossier = build_function_dossier(&path, &procedure, 512)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&dossier.cfg)?);
            } else {
                println!("\n{} {}:", "Control Flow Graph for".bold().cyan(), dossier.name.bold());
                println!("  Total Blocks: {}", dossier.cfg.blocks.len());
                println!("  Total Edges:  {}", dossier.cfg.edges.len());
                for edge in &dossier.cfg.edges {
                    println!("    Block {} ──[{:?}]──> Block {}", edge.from_block, edge.edge_type, edge.to_block);
                }
            }
        }
        Commands::Managed { path, json } => {
            let assembly = inspect_managed_assembly(&path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&assembly)?);
            } else {
                println!("\n{}", ".NET Managed PE Assembly Inspection:".bold().cyan());
                println!("  Assembly Name:   {}", assembly.name.bold());
                println!("  Version:         {}", assembly.version);
                println!("  Runtime Version: {}", assembly.runtime_version.green());
                println!("\n{}", "Declared Types:".bold());
                for t in &assembly.types {
                    println!("  class {}", t.full_name.bold());
                    for m in &t.methods {
                        println!("    0x{:04x}: {}", m.rva, m.name.yellow());
                    }
                }
            }
        }
        Commands::Compare { left, right, json } => {
            let delta = compare_artifacts(&left, &right)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&delta)?);
            } else {
                println!("\n{}", "Artifact Comparison:".bold().cyan());
                println!("  Left:               {}", delta.left_path);
                println!("  Right:              {}", delta.right_path);
                println!("  Identical:          {}", if delta.is_identical { "YES".green() } else { "NO".yellow() });
                println!("  Size Delta:         {} bytes", delta.size_delta_bytes);
                println!("  String Similarity:  {:.1}%", delta.string_similarity * 100.0);
                if !delta.added_sections.is_empty() {
                    println!("  Added Sections:     {:?}", delta.added_sections);
                }
                if !delta.removed_sections.is_empty() {
                    println!("  Removed Sections:   {:?}", delta.removed_sections);
                }
                if !delta.added_symbols.is_empty() {
                    println!("  Added Symbols:      {} new symbols", delta.added_symbols.len());
                }
            }
        }
        Commands::Evidence { command } => match command {
            EvidenceCommands::Export { output, overwrite } => {
                let bundle = EvidenceBundle::new();
                bundle.export_to_file(&output, overwrite)?;
                println!("{} Exported evidence bundle to {}", "✓".green(), output.display());
            }
            EvidenceCommands::Inspect { bundle } => {
                let b = EvidenceBundle::import_from_file(&bundle)?;
                println!("\n{}", "Evidence Bundle:".bold().cyan());
                println!("  Bundle ID:  {}", b.bundle_id);
                println!("  Created At: {}", b.created_at);
                println!("  Records:    {}", b.records.len());
                println!("  Unknowns:   {}", b.unknowns.len());
            }
        },
        Commands::Replay { scenario } => {
            let content = std::fs::read_to_string(&scenario)?;
            let spec: crate::replay::machine::ReplayMachineSpec = serde_json::from_str(&content)?;
            let events = vec![];
            let journal = run_replay_machine(&spec, &events)?;
            println!("{}", serde_json::to_string_pretty(&journal)?);
        }
        Commands::Mcp => {
            run_mcp_server().await?;
        }
        Commands::Setup { client, all_detected, dry_run } => {
            println!("\n{}", "REA Agent Integration Setup".bold().cyan());
            println!("{}", "==================================================".dimmed());

            let clients = detect_clients();
            let mut configured_any = false;

            for (c, detected, _path) in &clients {
                let should_configure = match &client {
                    Some(selected) => selected == c.id || selected == &c.display_name.to_lowercase().replace(' ', "_"),
                    None => all_detected && *detected,
                };

                if should_configure {
                    configure_agent(c, dry_run)?;
                    configured_any = true;
                } else {
                    let status = if *detected { "Detected (skip)".yellow() } else { "Not detected".dimmed() };
                    println!("  {:<16} - {}", c.display_name, status);
                }
            }

            if !configured_any && client.is_none() && !all_detected {
                println!("\n{}", "Run with --all-detected to automatically configure all detected agents,".cyan());
                println!("or specify --client <client_id> (e.g. claude_code, cursor, gemini_cli, windsurf).");
            }
        }
        Commands::Doctor => {
            run_doctor();
        }
    }
    Ok(())
}
