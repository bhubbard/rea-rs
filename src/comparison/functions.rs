use crate::types::FunctionDossier;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDelta {
    pub procedure_left: String,
    pub procedure_right: String,
    pub instruction_count_delta: i64,
    pub block_count_delta: i64,
    pub identical_cfg_topology: bool,
    pub common_callees: Vec<String>,
    pub added_callees: Vec<String>,
    pub removed_callees: Vec<String>,
    pub similarity_score: f64,
}

pub fn compare_functions(left: &FunctionDossier, right: &FunctionDossier) -> FunctionDelta {
    let instruction_count_delta = right.instruction_count as i64 - left.instruction_count as i64;
    let block_count_delta = right.block_count as i64 - left.block_count as i64;

    let left_edges: Vec<(usize, usize)> = left
        .cfg
        .edges
        .iter()
        .map(|e| (e.from_block, e.to_block))
        .collect();
    let right_edges: Vec<(usize, usize)> = right
        .cfg
        .edges
        .iter()
        .map(|e| (e.from_block, e.to_block))
        .collect();
    let identical_cfg_topology =
        left.block_count == right.block_count && left_edges == right_edges;

    let left_callees: std::collections::HashSet<String> =
        left.called_symbols.iter().cloned().collect();
    let right_callees: std::collections::HashSet<String> =
        right.called_symbols.iter().cloned().collect();

    let common_callees: Vec<String> = left_callees
        .intersection(&right_callees)
        .cloned()
        .collect();
    let added_callees: Vec<String> = right_callees
        .difference(&left_callees)
        .cloned()
        .collect();
    let removed_callees: Vec<String> = left_callees
        .difference(&right_callees)
        .cloned()
        .collect();

    // Heuristic similarity score
    let callee_sim = if !left_callees.is_empty() || !right_callees.is_empty() {
        let union_len = left_callees.union(&right_callees).count();
        common_callees.len() as f64 / union_len as f64
    } else {
        1.0
    };

    let block_sim = 1.0 - (block_count_delta.unsigned_abs() as f64
        / (left.block_count.max(right.block_count).max(1) as f64));
    let similarity_score = ((callee_sim * 0.5) + (block_sim.max(0.0) * 0.5)).clamp(0.0, 1.0);

    FunctionDelta {
        procedure_left: left.name.clone(),
        procedure_right: right.name.clone(),
        instruction_count_delta,
        block_count_delta,
        identical_cfg_topology,
        common_callees,
        added_callees,
        removed_callees,
        similarity_score,
    }
}
