use std::env;
use std::path::{Path, PathBuf};

pub struct GhidraProvider;

impl GhidraProvider {
    pub const ID: &'static str = "ghidra";

    pub fn detect_installation() -> Option<PathBuf> {
        if let Ok(dir) = env::var("GHIDRA_INSTALL_DIR") {
            let path = PathBuf::from(dir);
            if path.exists() {
                return Some(path);
            }
        }

        let candidates = [
            "/opt/ghidra",
            "/usr/local/opt/ghidra",
            "/Applications/ghidra",
        ];

        for c in candidates {
            let path = Path::new(c);
            if path.exists() {
                return Some(path.to_path_buf());
            }
        }
        None
    }

    pub fn is_available() -> bool {
        Self::detect_installation().is_some()
    }
}
