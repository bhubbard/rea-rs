use thiserror::Error;

#[derive(Error, Debug)]
pub enum ReaError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Object parsing error: {0}")]
    Object(#[from] object::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid binary format: {0}")]
    InvalidFormat(String),

    #[error("Artifact not found: {0}")]
    ArtifactNotFound(String),

    #[error("Procedure not found: {0}")]
    ProcedureNotFound(String),

    #[error("Analysis error: {0}")]
    Analysis(String),

    #[error("Managed .NET error: {0}")]
    Managed(String),

    #[error("Replay machine error: {0}")]
    Replay(String),

    #[error("Evidence error: {0}")]
    Evidence(String),

    #[error("MCP protocol error: {0}")]
    Mcp(String),

    #[error("Provider error: {0}")]
    Provider(String),
}

pub type Result<T> = std::result::Result<T, ReaError>;
