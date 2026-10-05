pub mod ghidra;
pub mod hopper;
pub mod native;

pub use ghidra::GhidraProvider;
pub use hopper::HopperProvider;
pub use native::NativeProvider;

pub fn list_providers() -> Vec<(&'static str, &'static str, bool)> {
    vec![
        (
            NativeProvider::ID,
            "Native Rust static analyzer and disassembler (pure Rust, zero-dependency)",
            NativeProvider::is_available(),
        ),
        (
            HopperProvider::ID,
            "Hopper Disassembler GUI and bridge connector",
            HopperProvider::is_available(),
        ),
        (
            GhidraProvider::ID,
            "Ghidra SRE framework headless bridge connector",
            GhidraProvider::is_available(),
        ),
    ]
}
