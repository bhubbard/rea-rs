use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BinaryFormat {
    MachO32,
    MachO64,
    MachOFat,
    Elf32,
    Elf64,
    Pe32,
    Pe32Plus,
    DotNetCli,
    Archive,
    Unknown(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Architecture {
    X86,
    X86_64,
    Arm,
    AArch64,
    Mips,
    RiscV,
    Wasm,
    Cil,
    Unknown(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactInfo {
    pub path: String,
    pub file_name: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub is_64_bit: bool,
    pub is_little_endian: bool,
    pub entry_point: Option<u64>,
    pub image_base: Option<u64>,
    pub uuid: Option<String>,
    pub section_count: usize,
    pub symbol_count: usize,
    pub is_pie: bool,
    pub is_dotnet: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub permissions: String, // e.g. "r-x", "rw-", "r--"
    pub entropy: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolInfo {
    pub name: String,
    pub demangled_name: Option<String>,
    pub address: u64,
    pub size: u64,
    pub kind: SymbolKind,
    pub is_exported: bool,
    pub is_imported: bool,
    pub section: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SymbolKind {
    Function,
    Data,
    Section,
    File,
    Tls,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringMatch {
    pub offset: u64,
    pub value: String,
    pub length: usize,
    pub is_utf16: bool,
    pub section: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassembledInstruction {
    pub address: u64,
    pub bytes: String,
    pub mnemonic: String,
    pub operands: String,
    pub flow_type: FlowType,
    pub target_address: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FlowType {
    Normal,
    ConditionalBranch,
    UnconditionalBranch,
    Call,
    Return,
    IndirectBranch,
    Interrupt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: usize,
    pub start_address: u64,
    pub end_address: u64,
    pub instruction_count: usize,
    pub instructions: Vec<DisassembledInstruction>,
    pub successors: Vec<usize>,
    pub predecessors: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgEdge {
    pub from_block: usize,
    pub to_block: usize,
    pub edge_type: CfgEdgeType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CfgEdgeType {
    Fallthrough,
    BranchTrue,
    BranchFalse,
    Unconditional,
    Call,
    Return,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowGraph {
    pub procedure_name: String,
    pub entry_address: u64,
    pub blocks: Vec<BasicBlock>,
    pub edges: Vec<CfgEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDossier {
    pub name: String,
    pub demangled_name: Option<String>,
    pub address: u64,
    pub size: u64,
    pub instruction_count: usize,
    pub block_count: usize,
    pub cfg: ControlFlowGraph,
    pub called_symbols: Vec<String>,
    pub caller_symbols: Vec<String>,
    pub string_references: Vec<String>,
    pub pseudocode: Option<String>,
}
