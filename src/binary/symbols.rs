use crate::binary::format::get_effective_binary_data;
use crate::error::Result;
use crate::types::{SymbolInfo, SymbolKind};
use object::{Object, ObjectSection, ObjectSymbol, SymbolSection};
use std::fs;
use std::path::Path;

pub fn extract_symbols(
    path: impl AsRef<Path>,
    query_filter: Option<&str>,
) -> Result<Vec<SymbolInfo>> {
    let data = fs::read(path.as_ref())?;
    let (effective_data, _) = get_effective_binary_data(&data);
    let obj_file = object::File::parse(effective_data)?;

    let mut symbols = Vec::new();

    for sym in obj_file.symbols() {
        let name = match sym.name() {
            Ok(n) if !n.is_empty() => n.to_string(),
            _ => continue,
        };

        let demangled = demangle_symbol(&name);

        let keep = match query_filter {
            Some(q) => {
                let q_lower = q.to_lowercase();
                name.to_lowercase().contains(&q_lower)
                    || demangled
                        .as_ref()
                        .map(|d| d.to_lowercase().contains(&q_lower))
                        .unwrap_or(false)
            }
            None => true,
        };

        if !keep {
            continue;
        }

        let kind = match sym.kind() {
            object::SymbolKind::Text => SymbolKind::Function,
            object::SymbolKind::Data => SymbolKind::Data,
            object::SymbolKind::Section => SymbolKind::Section,
            object::SymbolKind::File => SymbolKind::File,
            object::SymbolKind::Tls => SymbolKind::Tls,
            _ => SymbolKind::Unknown,
        };

        let is_exported = !sym.is_local() && !sym.is_undefined();
        let is_imported = sym.is_undefined();

        let section_name = match sym.section() {
            SymbolSection::Section(idx) => obj_file
                .section_by_index(idx)
                .ok()
                .and_then(|s| s.name().ok())
                .map(|s| s.to_string()),
            _ => None,
        };

        symbols.push(SymbolInfo {
            name,
            demangled_name: demangled,
            address: sym.address(),
            size: sym.size(),
            kind,
            is_exported,
            is_imported,
            section: section_name,
        });
    }

    // Sort by address
    symbols.sort_by_key(|s| s.address);
    Ok(symbols)
}

pub fn demangle_symbol(mangled: &str) -> Option<String> {
    // 1. Rust demangling
    let rust_demangled = rustc_demangle::demangle(mangled).to_string();
    if rust_demangled != mangled {
        return Some(rust_demangled);
    }

    // 2. C++ demangling (_Z or ? prefix)
    if mangled.starts_with("_Z") || mangled.starts_with("__Z") {
        let candidate = mangled.trim_start_matches('_');
        if let Ok(sym) = cpp_demangle::Symbol::new(candidate) {
            return Some(sym.to_string());
        }
    }

    // 3. Swift demangling prefix ($s or _$s)
    if mangled.starts_with("$s") || mangled.starts_with("_$s") {
        return Some(format!("[Swift] {}", mangled));
    }

    None
}
