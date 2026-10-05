pub mod analyzer;
pub mod cfg;
pub mod disasm;
pub mod dossier;
pub mod format;
pub mod strings;
pub mod symbols;

pub use analyzer::NativeAnalyzer;
pub use cfg::build_cfg;
pub use disasm::disassemble_bytes;
pub use dossier::build_function_dossier;
pub use format::{calculate_entropy, inspect_binary_file};
pub use strings::extract_strings;
pub use symbols::{demangle_symbol, extract_symbols};
