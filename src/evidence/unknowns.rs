use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum UnknownStatus {
    Open,
    Resolved,
    Withdrawn,
    Contradicted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum UnknownSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnknownRecord {
    pub id: String,
    pub status: UnknownStatus,
    pub domain: String,
    pub severity: UnknownSeverity,
    pub hypothesis: String,
    pub details: Option<String>,
    pub related_evidence_ids: Vec<String>,
    pub created_at: String,
    pub revision: usize,
}

impl UnknownRecord {
    pub fn new(
        id: impl Into<String>,
        domain: impl Into<String>,
        severity: UnknownSeverity,
        hypothesis: impl Into<String>,
        related_evidence_ids: Vec<String>,
    ) -> Self {
        Self {
            id: id.into(),
            status: UnknownStatus::Open,
            domain: domain.into(),
            severity,
            hypothesis: hypothesis.into(),
            details: None,
            related_evidence_ids,
            created_at: Utc::now().to_rfc3339(),
            revision: 1,
        }
    }

    pub fn resolve(&mut self, explanation: impl Into<String>) {
        self.status = UnknownStatus::Resolved;
        self.details = Some(explanation.into());
        self.revision += 1;
    }
}
