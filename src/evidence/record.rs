use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceRecord {
    pub evidence_id: String,
    pub artifact_id: String,
    pub provider: String,
    pub authority: String,
    pub confidence: f64,
    pub timestamp: String,
    pub facets: serde_json::Value,
    pub limitations: Vec<String>,
}

impl EvidenceRecord {
    pub fn new(
        artifact_id: impl Into<String>,
        provider: impl Into<String>,
        authority: impl Into<String>,
        confidence: f64,
        facets: serde_json::Value,
        limitations: Vec<String>,
    ) -> Self {
        let artifact_id = artifact_id.into();
        let provider = provider.into();
        let authority = authority.into();
        let timestamp = Utc::now().to_rfc3339();

        // Calculate deterministic canonical SHA-256 ID based on facets + artifact + provider
        let canonical_str = format!(
            "{}:{}:{}:{}",
            artifact_id,
            provider,
            authority,
            serde_json::to_string(&facets).unwrap_or_default()
        );
        let mut hasher = Sha256::new();
        hasher.update(canonical_str.as_bytes());
        let hash_hex = hex::encode(hasher.finalize());
        let evidence_id = format!("sha256:{}", hash_hex);

        Self {
            evidence_id,
            artifact_id,
            provider,
            authority,
            confidence: confidence.clamp(0.0, 1.0),
            timestamp,
            facets,
            limitations,
        }
    }
}
