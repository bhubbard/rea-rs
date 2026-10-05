use rea::mcp::ToolRegistry;
use serde_json::json;

#[test]
fn test_mcp_registry_tools_and_prompts() {
    let registry = ToolRegistry::new();
    let tools = registry.list_tools();
    assert!(tools.len() >= 15);

    let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert!(tool_names.contains(&"inspect_artifact"));
    assert!(tool_names.contains(&"extract_strings"));
    assert!(tool_names.contains(&"search_symbols"));
    assert!(tool_names.contains(&"analyze_function"));
    assert!(tool_names.contains(&"compare_artifacts"));
    assert!(tool_names.contains(&"record_evidence"));
    assert!(tool_names.contains(&"run_replay_machine"));

    let prompts = registry.list_prompts();
    assert!(!prompts.is_empty());
    assert_eq!(prompts[0].name, "investigate_feature");
}

#[test]
fn test_mcp_doctor_tool_call() {
    let registry = ToolRegistry::new();
    let res = registry.call_tool("doctor", json!({}));
    assert!(res.is_error.is_none() || res.is_error == Some(false));
    assert!(!res.content.is_empty());
    let text = &res.content[0].text;
    assert!(text.contains("rea_version"));
    assert!(text.contains("native-rs"));
}

#[test]
fn test_mcp_evidence_lifecycle_tool_calls() {
    let registry = ToolRegistry::new();
    let rec_res = registry.call_tool(
        "record_evidence",
        json!({
            "artifact_id": "sha256:test1234",
            "provider": "native-rs",
            "authority": "static-analysis",
            "confidence": 0.95,
            "facets": {
                "symbols_count": 42
            },
            "limitations": ["unit-test"]
        }),
    );

    assert!(rec_res.is_error.is_none() || rec_res.is_error == Some(false));

    let bundle_res = registry.call_tool("get_evidence_bundle", json!({}));
    assert!(!bundle_res.content.is_empty());
    let bundle_json = &bundle_res.content[0].text;
    assert!(bundle_json.contains("sha256:test1234"));
    assert!(bundle_json.contains("native-rs"));
}
