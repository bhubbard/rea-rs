use rea::evidence::{EvidenceBundle, EvidenceRecord, UnknownRecord, UnknownSeverity, UnknownStatus};
use serde_json::json;
use tempfile::NamedTempFile;

#[test]
fn test_evidence_record_hashing() {
    let rec1 = EvidenceRecord::new(
        "sha256:1111",
        "native-rs",
        "static-analysis",
        1.0,
        json!({"symbol": "main", "address": 0x1000}),
        vec!["static".to_string()],
    );

    let rec2 = EvidenceRecord::new(
        "sha256:1111",
        "native-rs",
        "static-analysis",
        1.0,
        json!({"symbol": "main", "address": 0x1000}),
        vec!["static".to_string()],
    );

    assert_eq!(rec1.evidence_id, rec2.evidence_id);
    assert!(rec1.evidence_id.starts_with("sha256:"));
}

#[test]
fn test_evidence_bundle_export_import() {
    let mut bundle = EvidenceBundle::new();
    let rec = EvidenceRecord::new(
        "sha256:target",
        "native-rs",
        "static-analysis",
        0.9,
        json!({"facet": "test"}),
        vec![],
    );
    bundle.add_record(rec.clone());

    let mut unknown = UnknownRecord::new(
        "unk_1",
        "native",
        UnknownSeverity::Medium,
        "Is function X reachable?",
        vec![rec.evidence_id.clone()],
    );
    bundle.add_unknown(unknown.clone());

    let temp_file = NamedTempFile::new().unwrap();
    let path = temp_file.path().to_path_buf();

    bundle.export_to_file(&path, true).expect("export bundle");

    let imported = EvidenceBundle::import_from_file(&path).expect("import bundle");
    assert_eq!(imported.records.len(), 1);
    assert_eq!(imported.records[0].evidence_id, rec.evidence_id);
    assert_eq!(imported.unknowns.len(), 1);
    assert_eq!(imported.unknowns[0].id, "unk_1");

    // Test unknown resolution
    unknown.resolve("Yes, reachable from main at 0x1020");
    assert_eq!(unknown.status, UnknownStatus::Resolved);
    assert_eq!(unknown.revision, 2);
}
