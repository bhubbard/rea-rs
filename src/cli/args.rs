use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "rea",
    bin_name = "rea",
    about = "Reverse engineer anything with agents, from app behavior down to native binaries",
    version,
    author
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Inspect binary headers, format, architecture, and section layout
    Inspect {
        /// Target binary or application file path
        path: PathBuf,
        /// Output formatted JSON
        #[arg(long)]
        json: bool,
    },

    /// Extract ASCII and UTF-16LE strings with section mapping
    Strings {
        /// Target binary path
        path: PathBuf,
        /// Minimum string length
        #[arg(short, long, default_value = "4")]
        min_len: usize,
        /// Filter by string substring
        #[arg(short, long)]
        query: Option<String>,
        /// Output formatted JSON
        #[arg(long)]
        json: bool,
    },

    /// Extract and demangle exported, imported, and local symbols
    Symbols {
        /// Target binary path
        path: PathBuf,
        /// Filter by symbol name
        #[arg(short, long)]
        query: Option<String>,
        /// Output formatted JSON
        #[arg(long)]
        json: bool,
    },

    /// Build a complete function dossier with CFG, callees, strings, and pseudocode
    Dossier {
        /// Target binary path
        path: PathBuf,
        /// Procedure symbol name or hex address (e.g. 0x1000)
        #[arg(short, long)]
        procedure: String,
        /// Maximum instructions to decode
        #[arg(short, long, default_value = "512")]
        max_instructions: usize,
        /// Output formatted JSON
        #[arg(long)]
        json: bool,
    },

    /// Disassemble a procedure with flow control classification
    Disasm {
        /// Target binary path
        path: PathBuf,
        /// Procedure symbol name or hex address
        #[arg(short, long)]
        procedure: String,
        /// Maximum instructions to decode
        #[arg(short, long, default_value = "256")]
        max_instructions: usize,
        /// Output formatted JSON
        #[arg(long)]
        json: bool,
    },

    /// Extract the Control Flow Graph (CFG) for a procedure
    Cfg {
        /// Target binary path
        path: PathBuf,
        /// Procedure symbol name or hex address
        #[arg(short, long)]
        procedure: String,
        /// Output formatted JSON
        #[arg(long)]
        json: bool,
    },

    /// Inspect a .NET managed PE/CLI assembly and metadata streams
    Managed {
        /// Target .NET PE file path
        path: PathBuf,
        /// Output formatted JSON
        #[arg(long)]
        json: bool,
    },

    /// Deep comparison between two binary artifacts
    Compare {
        /// First binary path
        left: PathBuf,
        /// Second binary path
        right: PathBuf,
        /// Output formatted JSON
        #[arg(long)]
        json: bool,
    },

    /// Manage reproducible Evidence bundles
    Evidence {
        #[command(subcommand)]
        command: EvidenceCommands,
    },

    /// Run a finite replay machine against recorded events
    Replay {
        /// Replay machine scenario JSON file path
        scenario: PathBuf,
    },

    /// Start the Model Context Protocol (MCP) server over stdio
    Mcp,

    /// Detect and configure AI agent integrations (Claude, Cursor, Codex, Gemini, Windsurf)
    Setup {
        /// Target client to configure (e.g. claude_code, cursor, gemini_cli, windsurf)
        #[arg(long)]
        client: Option<String>,
        /// Configure all detected supported agents
        #[arg(long)]
        all_detected: bool,
        /// Print what would change without modifying files
        #[arg(long)]
        dry_run: bool,
    },

    /// Check system readiness, available disassemblers, and agent integrations
    Doctor,
}

#[derive(Subcommand, Debug)]
pub enum EvidenceCommands {
    /// Export evidence bundle to a file
    Export {
        output: PathBuf,
        #[arg(long)]
        overwrite: bool,
    },
    /// Inspect an existing evidence bundle
    Inspect {
        bundle: PathBuf,
    },
}
