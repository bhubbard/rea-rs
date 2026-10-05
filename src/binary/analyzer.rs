use super::dossier::build_function_dossier;
use super::format::inspect_binary_file;
use super::strings::extract_strings;
use super::symbols::extract_symbols;
use crate::error::Result;
use crate::evidence::EvidenceRecord;
use crate::types::{ArtifactInfo, FunctionDossier, SectionInfo, StringMatch, SymbolInfo};
use serde_json::json;
use std::path::Path;

pub struct NativeAnalyzer;

impl NativeAnalyzer {
    pub fn inspect_artifact(path: impl AsRef<Path>) -> Result<(ArtifactInfo, Vec<SectionInfo>, EvidenceRecord)> {
        let (info, sections) = inspect_binary_file(&path)?;

        let record = EvidenceRecord::new(
            &info.sha256,
            "native-rs",
            "static-analysis",
            1.0,
            json!({
                "format": info.format,
                "architecture": info.architecture,
                "entry_point": info.entry_point,
                "section_count": info.section_count,
                "symbol_count": info.symbol_count,
                "uuid": info.uuid,
            }),
            vec!["Static binary header and section table inspection".to_string()],
        );

        Ok((info, sections, record))
    }

    pub fn strings(
        path: impl AsRef<Path>,
        min_len: usize,
        query: Option<&str>,
    ) -> Result<(Vec<StringMatch>, EvidenceRecord)> {
        let matches = extract_strings(&path, min_len, query)?;
        let (info, _) = inspect_binary_file(&path)?;

        let record = EvidenceRecord::new(
            &info.sha256,
            "native-rs",
            "static-analysis",
            0.95,
            json!({
                "total_strings_found": matches.len(),
                "min_length": min_len,
                "query": query,
            }),
            vec!["Sequential binary string scanning; does not guarantee runtime referenced state".to_string()],
        );

        Ok((matches, record))
    }

    pub fn symbols(
        path: impl AsRef<Path>,
        query: Option<&str>,
    ) -> Result<(Vec<SymbolInfo>, EvidenceRecord)> {
        let symbols = extract_symbols(&path, query)?;
        let (info, _) = inspect_binary_file(&path)?;

        let record = EvidenceRecord::new(
            &info.sha256,
            "native-rs",
            "static-analysis",
            0.98,
            json!({
                "total_symbols_found": symbols.len(),
                "query": query,
            }),
            vec!["Symbol table and dynamic symbol table extraction with Rust/C++ demangling".to_string()],
        );

        Ok((symbols, record))
    }

    pub fn function_dossier(
        path: impl AsRef<Path>,
        procedure: &str,
        max_instructions: usize,
    ) -> Result<(FunctionDossier, EvidenceRecord)> {
        let dossier = build_function_dossier(&path, procedure, max_instructions)?;
        let (info, _) = inspect_binary_file(&path)?;

        let record = EvidenceRecord::new(
            &info.sha256,
            "native-rs",
            "static-analysis",
            0.92,
            json!({
                "procedure": dossier.name,
                "address": dossier.address,
                "instruction_count": dossier.instruction_count,
                "block_count": dossier.block_count,
                "callees": dossier.called_symbols,
            }),
            vec![
                "Static linear disassembly and CFG leader reconstruction; indirect jumps/thunks may require dynamic resolution".to_string()
            ],
        );

        Ok((dossier, record))
    }
}
