use super::record::EvidenceRecord;
use super::unknowns::UnknownRecord;
use crate::error::{ReaError, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub bundle_id: String,
    pub created_at: String,
    pub records: Vec<EvidenceRecord>,
    pub unknowns: Vec<UnknownRecord>,
}

impl Default for EvidenceBundle {
    fn default() -> Self {
        Self::new()
    }
}

impl EvidenceBundle {
    pub fn new() -> Self {
        let created_at = Utc::now().to_rfc3339();
        let mut hasher = Sha256::new();
        hasher.update(created_at.as_bytes());
        let bundle_id = format!("bundle:{}", hex::encode(hasher.finalize()));

        Self {
            bundle_id,
            created_at,
            records: Vec::new(),
            unknowns: Vec::new(),
        }
    }

    pub fn add_record(&mut self, record: EvidenceRecord) {
        if !self.records.iter().any(|r| r.evidence_id == record.evidence_id) {
            self.records.push(record);
        }
    }

    pub fn add_unknown(&mut self, unknown: UnknownRecord) {
        if !self.unknowns.iter().any(|u| u.id == unknown.id) {
            self.unknowns.push(unknown);
        }
    }

    pub fn export_to_file(&self, path: impl AsRef<Path>, overwrite: bool) -> Result<()> {
        let path = path.as_ref();
        if path.exists() && !overwrite {
            return Err(ReaError::Evidence(format!(
                "File already exists: {}. Pass overwrite: true to overwrite.",
                path.display()
            )));
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    pub fn import_from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(ReaError::ArtifactNotFound(format!(
                "Evidence bundle file not found: {}",
                path.display()
            )));
        }
        let content = fs::read_to_string(path)?;
        let bundle: EvidenceBundle = serde_json::from_str(&content)?;
        Ok(bundle)
    }
}
