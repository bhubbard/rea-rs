use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPrompt {
    pub name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub arguments: Vec<McpPromptArgument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPromptArgument {
    pub name: String,
    pub description: String,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolCallResult {
    pub content: Vec<McpContentItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpContentItem {
    #[serde(rename = "type")]
    pub item_type: String,
    pub text: String,
}

impl McpToolCallResult {
    pub fn success(text: impl Into<String>) -> Self {
        Self {
            content: vec![McpContentItem {
                item_type: "text".to_string(),
                text: text.into(),
            }],
            is_error: None,
        }
    }

    pub fn error(text: impl Into<String>) -> Self {
        Self {
            content: vec![McpContentItem {
                item_type: "text".to_string(),
                text: text.into(),
            }],
            is_error: Some(true),
        }
    }

    pub fn json<T: Serialize>(value: &T) -> Self {
        match serde_json::to_string_pretty(value) {
            Ok(json_str) => Self::success(json_str),
            Err(e) => Self::error(format!("JSON serialization error: {}", e)),
        }
    }
}
