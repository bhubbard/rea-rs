use crate::binary::analyzer::NativeAnalyzer;
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactDelta {
    pub left_path: String,
    pub right_path: String,
    pub left_sha256: String,
    pub right_sha256: String,
    pub is_identical: bool,
    pub size_delta_bytes: i64,
    pub added_sections: Vec<String>,
    pub removed_sections: Vec<String>,
    pub modified_sections: Vec<String>,
    pub added_symbols: Vec<String>,
    pub removed_symbols: Vec<String>,
    pub string_similarity: f64,
}

pub fn compare_artifacts(left: impl AsRef<Path>, right: impl AsRef<Path>) -> Result<ArtifactDelta> {
    let (left_info, left_sections, _) = NativeAnalyzer::inspect_artifact(&left)?;
    let (right_info, right_sections, _) = NativeAnalyzer::inspect_artifact(&right)?;

    let is_identical = left_info.sha256 == right_info.sha256;
    let size_delta_bytes = right_info.size_bytes as i64 - left_info.size_bytes as i64;

    let left_sec_names: Vec<String> = left_sections.iter().map(|s| s.name.clone()).collect();
    let right_sec_names: Vec<String> = right_sections.iter().map(|s| s.name.clone()).collect();

    let added_sections: Vec<String> = right_sec_names
        .iter()
        .filter(|s| !left_sec_names.contains(s))
        .cloned()
        .collect();

    let removed_sections: Vec<String> = left_sec_names
        .iter()
        .filter(|s| !right_sec_names.contains(s))
        .cloned()
        .collect();

    let modified_sections: Vec<String> = left_sections
        .iter()
        .filter_map(|ls| {
            if let Some(rs) = right_sections.iter().find(|rs| rs.name == ls.name) {
                if (rs.size != ls.size) || ((rs.entropy - ls.entropy).abs() > 0.05) {
                    Some(ls.name.clone())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    // Symbols delta
    let (left_syms, _) = NativeAnalyzer::symbols(&left, None)?;
    let (right_syms, _) = NativeAnalyzer::symbols(&right, None)?;

    let left_sym_names: std::collections::HashSet<String> =
        left_syms.iter().map(|s| s.name.clone()).collect();
    let right_sym_names: std::collections::HashSet<String> =
        right_syms.iter().map(|s| s.name.clone()).collect();

    let added_symbols: Vec<String> = right_sym_names
        .difference(&left_sym_names)
        .take(100)
        .cloned()
        .collect();

    let removed_symbols: Vec<String> = left_sym_names
        .difference(&right_sym_names)
        .take(100)
        .cloned()
        .collect();

    // Strings similarity
    let (left_strs, _) = NativeAnalyzer::strings(&left, 4, None)?;
    let (right_strs, _) = NativeAnalyzer::strings(&right, 4, None)?;
    let left_str_set: std::collections::HashSet<String> =
        left_strs.iter().map(|s| s.value.clone()).collect();
    let right_str_set: std::collections::HashSet<String> =
        right_strs.iter().map(|s| s.value.clone()).collect();

    let intersection_count = left_str_set.intersection(&right_str_set).count();
    let union_count = left_str_set.union(&right_str_set).count();
    let string_similarity = if union_count > 0 {
        intersection_count as f64 / union_count as f64
    } else {
        1.0
    };

    Ok(ArtifactDelta {
        left_path: left_info.path,
        right_path: right_info.path,
        left_sha256: left_info.sha256,
        right_sha256: right_info.sha256,
        is_identical,
        size_delta_bytes,
        added_sections,
        removed_sections,
        modified_sections,
        added_symbols,
        removed_symbols,
        string_similarity,
    })
}
