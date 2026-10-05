use std::path::{Path, PathBuf};

pub struct HopperProvider;

impl HopperProvider {
    pub const ID: &'static str = "hopper";

    pub fn detect_installation() -> Option<PathBuf> {
        let candidates = [
            "/Applications/Hopper Disassembler v4.app",
            "/Applications/Hopper Disassembler v5.app",
            "/Applications/Hopper Disassembler.app",
            "/usr/bin/hopper",
            "/usr/local/bin/hopper",
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
