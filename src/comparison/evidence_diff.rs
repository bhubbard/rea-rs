use crate::evidence::EvidenceBundle;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleDelta {
    pub left_bundle_id: String,
    pub right_bundle_id: String,
    pub shared_evidence_count: usize,
    pub left_only_evidence_ids: Vec<String>,
    pub right_only_evidence_ids: Vec<String>,
    pub open_unknowns_delta: i64,
}

pub fn compare_bundles(left: &EvidenceBundle, right: &EvidenceBundle) -> BundleDelta {
    let left_ids: std::collections::HashSet<String> =
        left.records.iter().map(|r| r.evidence_id.clone()).collect();
    let right_ids: std::collections::HashSet<String> =
        right.records.iter().map(|r| r.evidence_id.clone()).collect();

    let shared_count = left_ids.intersection(&right_ids).count();
    let left_only: Vec<String> = left_ids.difference(&right_ids).cloned().collect();
    let right_only: Vec<String> = right_ids.difference(&left_ids).cloned().collect();

    let left_open_unknowns = left
        .unknowns
        .iter()
        .filter(|u| u.status == crate::evidence::UnknownStatus::Open)
        .count() as i64;
    let right_open_unknowns = right
        .unknowns
        .iter()
        .filter(|u| u.status == crate::evidence::UnknownStatus::Open)
        .count() as i64;

    BundleDelta {
        left_bundle_id: left.bundle_id.clone(),
        right_bundle_id: right.bundle_id.clone(),
        shared_evidence_count: shared_count,
        left_only_evidence_ids: left_only,
        right_only_evidence_ids: right_only,
        open_unknowns_delta: right_open_unknowns - left_open_unknowns,
    }
}
