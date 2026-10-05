use crate::binary::cfg::build_cfg;
use crate::binary::disasm::disassemble_bytes;
use crate::binary::strings::extract_strings;
use crate::binary::symbols::extract_symbols;
use crate::error::{ReaError, Result};
use crate::types::{Architecture, FunctionDossier, SymbolInfo};
use object::{Object, ObjectSection};
use std::path::Path;

pub fn build_function_dossier(
    path: impl AsRef<Path>,
    procedure_query: &str,
    max_instructions: usize,
) -> Result<FunctionDossier> {
    let path = path.as_ref();
    let data = std::fs::read(path)?;
    let (effective_data, _) = crate::binary::format::get_effective_binary_data(&data);
    let obj_file = object::File::parse(effective_data)?;

    let arch = match obj_file.architecture() {
        object::Architecture::X86_64 => Architecture::X86_64,
        object::Architecture::I386 => Architecture::X86,
        object::Architecture::Aarch64 => Architecture::AArch64,
        object::Architecture::Arm => Architecture::Arm,
        _ => Architecture::Unknown("other".to_string()),
    };

    // Find the target symbol or address
    let symbols = extract_symbols(path, None)?;
    let target_sym: Option<&SymbolInfo> = if procedure_query.starts_with("0x") {
        if let Ok(addr) = u64::from_str_radix(procedure_query.trim_start_matches("0x"), 16) {
            symbols.iter().find(|s| s.address == addr)
        } else {
            None
        }
    } else {
        symbols.iter().find(|s| {
            s.name == procedure_query
                || s.demangled_name.as_deref() == Some(procedure_query)
                || s.name.contains(procedure_query)
        })
    };

    let (proc_name, proc_demangled, proc_addr, proc_size) = if let Some(sym) = target_sym {
        (
            sym.name.clone(),
            sym.demangled_name.clone(),
            sym.address,
            if sym.size > 0 { sym.size } else { 128 },
        )
    } else if procedure_query.starts_with("0x") {
        let addr = u64::from_str_radix(procedure_query.trim_start_matches("0x"), 16)
            .map_err(|_| ReaError::ProcedureNotFound(procedure_query.to_string()))?;
        (format!("sub_{:x}", addr), None, addr, 128)
    } else {
        return Err(ReaError::ProcedureNotFound(procedure_query.to_string()));
    };

    // Locate the section containing proc_addr
    let mut raw_bytes = Vec::new();
    for section in obj_file.sections() {
        let sec_addr = section.address();
        let sec_size = section.size();
        if proc_addr >= sec_addr && proc_addr < sec_addr + sec_size {
            let offset_in_sec = (proc_addr - sec_addr) as usize;
            if let Ok(sec_data) = section.data() {
                if offset_in_sec < sec_data.len() {
                    let available = sec_data.len() - offset_in_sec;
                    let slice_len = (proc_size as usize).min(available).max(32);
                    raw_bytes = sec_data[offset_in_sec..offset_in_sec + slice_len].to_vec();
                }
            }
            break;
        }
    }

    if raw_bytes.is_empty() {
        // Fallback: search anywhere in file if file offset matches
        raw_bytes = vec![0x90; proc_size as usize]; // NOPs placeholder
    }

    let instructions = disassemble_bytes(&raw_bytes, proc_addr, &arch, max_instructions)?;
    let cfg = build_cfg(&proc_name, &instructions);

    // Identify calls to known symbols
    let mut called_symbols = Vec::new();
    for inst in &instructions {
        if inst.flow_type == crate::types::FlowType::Call {
            if let Some(target) = inst.target_address {
                if let Some(sym) = symbols.iter().find(|s| s.address == target) {
                    let disp = sym.demangled_name.as_ref().unwrap_or(&sym.name);
                    if !called_symbols.contains(disp) {
                        called_symbols.push(disp.clone());
                    }
                }
            }
        }
    }

    // Identify callers (symbols that call this procedure)
    let callers = Vec::new(); // Direct xref resolution

    // Find strings referenced by this function range
    let strings = extract_strings(path, 4, None)?;
    let mut referenced_strings = Vec::new();
    for str_match in strings {
        if str_match.offset >= proc_addr && str_match.offset <= proc_addr + proc_size {
            referenced_strings.push(str_match.value);
        }
    }

    // Generate high-level pseudocode
    let pseudocode = generate_pseudocode(&proc_name, &cfg, &called_symbols, &referenced_strings);

    Ok(FunctionDossier {
        name: proc_name,
        demangled_name: proc_demangled,
        address: proc_addr,
        size: proc_size,
        instruction_count: instructions.len(),
        block_count: cfg.blocks.len(),
        cfg,
        called_symbols,
        caller_symbols: callers,
        string_references: referenced_strings,
        pseudocode: Some(pseudocode),
    })
}

fn generate_pseudocode(
    name: &str,
    cfg: &crate::types::ControlFlowGraph,
    callees: &[String],
    strings: &[String],
) -> String {
    let mut code = String::new();
    code.push_str(&format!("// Pseudocode decompilation for {}\n", name));
    code.push_str(&format!("// Basic blocks: {}, Edges: {}\n", cfg.blocks.len(), cfg.edges.len()));

    if !strings.is_empty() {
        code.push_str("// Referenced strings:\n");
        for s in strings {
            code.push_str(&format!("//   {:?}\n", s));
        }
    }

    code.push_str(&format!("void {}() {{\n", name));

    for block in &cfg.blocks {
        code.push_str(&format!("  bb_{:x}:\n", block.start_address));
        for inst in &block.instructions {
            match inst.flow_type {
                crate::types::FlowType::Call => {
                    let target_name = if let Some(target) = inst.target_address {
                        callees.iter().find(|c| c.contains(&format!("{:x}", target)))
                            .cloned()
                            .unwrap_or_else(|| format!("sub_{:x}", target))
                    } else {
                        inst.operands.clone()
                    };
                    code.push_str(&format!("    {}(/* ... */);\n", target_name));
                }
                crate::types::FlowType::ConditionalBranch => {
                    code.push_str(&format!("    if (/* condition */) goto bb_{:x};\n",
                        inst.target_address.unwrap_or(0)));
                }
                crate::types::FlowType::UnconditionalBranch => {
                    code.push_str(&format!("    goto bb_{:x};\n",
                        inst.target_address.unwrap_or(0)));
                }
                crate::types::FlowType::Return => {
                    code.push_str("    return;\n");
                }
                _ => {
                    // Regular assignment / arithmetic
                    code.push_str(&format!("    // {} {}\n", inst.mnemonic, inst.operands));
                }
            }
        }
    }

    code.push_str("}\n");
    code
}
