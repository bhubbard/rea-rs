use super::protocol::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
use super::tools::ToolRegistry;
use crate::error::Result;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub async fn run_mcp_server() -> Result<()> {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut stdout = tokio::io::stdout();

    let registry = ToolRegistry::new();
    let mut line = String::new();

    while reader.read_line(&mut line).await? > 0 {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            line.clear();
            continue;
        }

        let request: JsonRpcRequest = match serde_json::from_str(trimmed) {
            Ok(req) => req,
            Err(e) => {
                let error_resp = JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: None,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32700,
                        message: format!("Parse error: {}", e),
                        data: None,
                    }),
                };
                let resp_str = serde_json::to_string(&error_resp)?;
                stdout.write_all(resp_str.as_bytes()).await?;
                stdout.write_all(b"\n").await?;
                stdout.flush().await?;
                line.clear();
                continue;
            }
        };

        let response = handle_request(&registry, request).await;
        if let Some(resp) = response {
            let resp_str = serde_json::to_string(&resp)?;
            stdout.write_all(resp_str.as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }

        line.clear();
    }

    Ok(())
}

async fn handle_request(
    registry: &ToolRegistry,
    req: JsonRpcRequest,
) -> Option<JsonRpcResponse> {
    let id = req.id.clone();

    // If it's a notification (id is None), don't send response unless required
    match req.method.as_str() {
        "initialize" => {
            Some(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id,
                result: Some(json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {
                            "listChanged": false
                        },
                        "prompts": {
                            "listChanged": false
                        }
                    },
                    "serverInfo": {
                        "name": "rea",
                        "version": "3.2.1"
                    }
                })),
                error: None,
            })
        }
        "notifications/initialized" => None,
        "ping" => Some(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(json!({})),
            error: None,
        }),
        "tools/list" => {
            let tools = registry.list_tools();
            Some(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id,
                result: Some(json!({ "tools": tools })),
                error: None,
            })
        }
        "tools/call" => {
            let params = req.params.unwrap_or(json!({}));
            let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

            let result = registry.call_tool(tool_name, arguments);
            Some(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id,
                result: Some(serde_json::to_value(&result).unwrap_or(json!({}))),
                error: None,
            })
        }
        "prompts/list" => {
            let prompts = registry.list_prompts();
            Some(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id,
                result: Some(json!({ "prompts": prompts })),
                error: None,
            })
        }
        "prompts/get" => {
            let params = req.params.unwrap_or(json!({}));
            let prompt_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            Some(JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id,
                result: Some(json!({
                    "description": format!("Prompt {}", prompt_name),
                    "messages": [
                        {
                            "role": "user",
                            "content": {
                                "type": "text",
                                "text": format!("Execute the {} workflow with REA tools.", prompt_name)
                            }
                        }
                    ]
                })),
                error: None,
            })
        }
        other => Some(JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code: -32601,
                message: format!("Method not found: {}", other),
                data: None,
            }),
        }),
    }
}
