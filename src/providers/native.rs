use crate::binary::analyzer::NativeAnalyzer;
use crate::error::Result;
use crate::evidence::EvidenceRecord;
use crate::types::{ArtifactInfo, FunctionDossier, SectionInfo, StringMatch, SymbolInfo};
use std::path::Path;

pub struct NativeProvider;

impl NativeProvider {
    pub const ID: &'static str = "native-rs";

    pub fn is_available() -> bool {
        true
    }

    pub fn inspect_artifact(path: impl AsRef<Path>) -> Result<(ArtifactInfo, Vec<SectionInfo>, EvidenceRecord)> {
        NativeAnalyzer::inspect_artifact(path)
    }

    pub fn strings(path: impl AsRef<Path>, min_len: usize, query: Option<&str>) -> Result<(Vec<StringMatch>, EvidenceRecord)> {
        NativeAnalyzer::strings(path, min_len, query)
    }

    pub fn symbols(path: impl AsRef<Path>, query: Option<&str>) -> Result<(Vec<SymbolInfo>, EvidenceRecord)> {
        NativeAnalyzer::symbols(path, query)
    }

    pub fn dossier(path: impl AsRef<Path>, procedure: &str, max_instructions: usize) -> Result<(FunctionDossier, EvidenceRecord)> {
        NativeAnalyzer::function_dossier(path, procedure, max_instructions)
    }
}
