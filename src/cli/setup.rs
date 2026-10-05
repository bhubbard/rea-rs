use crate::error::Result;
use colored::Colorize;
use serde_json::json;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct AgentClient {
    pub id: &'static str,
    pub display_name: &'static str,
    pub relative_config_path: &'static [&'static str],
    pub is_json: bool,
}

pub const SUPPORTED_CLIENTS: &[AgentClient] = &[
    AgentClient {
        id: "claude_code",
        display_name: "Claude Code",
        relative_config_path: &[".claude.json"],
        is_json: true,
    },
    AgentClient {
        id: "claude_desktop",
        display_name: "Claude Desktop",
        relative_config_path: &["Library", "Application Support", "Claude", "claude_desktop_config.json"],
        is_json: true,
    },
    AgentClient {
        id: "cursor",
        display_name: "Cursor",
        relative_config_path: &[".cursor", "mcp.json"],
        is_json: true,
    },
    AgentClient {
        id: "gemini_cli",
        display_name: "Gemini CLI",
        relative_config_path: &[".gemini", "settings.json"],
        is_json: true,
    },
    AgentClient {
        id: "windsurf",
        display_name: "Windsurf",
        relative_config_path: &[".codeium", "windsurf", "mcp_config.json"],
        is_json: true,
    },
];

pub fn get_client_config_path(client: &AgentClient) -> Option<PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
        .map(PathBuf::from)?;
    let mut p = home;
    for part in client.relative_config_path {
        p.push(part);
    }
    Some(p)
}

pub fn detect_clients() -> Vec<(&'static AgentClient, bool, Option<PathBuf>)> {
    let mut results = Vec::new();
    for client in SUPPORTED_CLIENTS {
        if let Some(config_path) = get_client_config_path(client) {
            let parent_exists = config_path.parent().map(|p| p.exists()).unwrap_or(false);
            let config_exists = config_path.exists();
            let detected = config_exists || parent_exists;
            results.push((client, detected, Some(config_path)));
        } else {
            results.push((client, false, None));
        }
    }
    results
}

pub fn configure_agent(client: &AgentClient, dry_run: bool) -> Result<bool> {
    let config_path = match get_client_config_path(client) {
        Some(p) => p,
        None => return Ok(false),
    };

    println!("{} {} ({})", "Configuring:".bold().cyan(), client.display_name, config_path.display());

    let rea_bin = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "rea".to_string());

    let rea_server_config = json!({
        "command": rea_bin,
        "args": ["mcp"]
    });

    if dry_run {
        println!("  {} Would write MCP server config to {}", "[dry-run]".yellow(), config_path.display());
        return Ok(true);
    }

    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut current_json = if config_path.exists() {
        let content = fs::read_to_string(&config_path).unwrap_or_default();
        serde_json::from_str(&content).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };

    // Add "mcpServers" -> "rea"
    if !current_json.is_object() {
        current_json = json!({});
    }

    let root_obj = current_json.as_object_mut().unwrap();
    let mcp_servers = root_obj
        .entry("mcpServers")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .unwrap();

    mcp_servers.insert("rea".to_string(), rea_server_config);

    let formatted = serde_json::to_string_pretty(&current_json)?;
    fs::write(&config_path, formatted)?;

    println!("  {} Successfully configured {} in {}", "✓".green(), client.display_name, config_path.display());
    Ok(true)
}
