pub mod cil;
pub mod metadata;
pub mod pe;
pub mod tables;

pub use cil::{decode_cil_method_body, CilInstruction};
pub use metadata::{parse_clr_metadata, ClrMetadataRoot, ClrStream};
pub use pe::{read_dotnet_pe, rva_to_file_offset, ClrHeaderInfo, SectionHeader};
pub use tables::{extract_assembly_info, DotNetAssemblyInfo, DotNetMethodInfo, DotNetTypeInfo};

use crate::error::Result;
use std::path::Path;

pub fn inspect_managed_assembly(path: impl AsRef<Path>) -> Result<DotNetAssemblyInfo> {
    let (data, header, sections) = read_dotnet_pe(path)?;
    let metadata_file_offset = rva_to_file_offset(header.metadata_rva, &sections)
        .ok_or_else(|| crate::error::ReaError::Managed("Failed to map metadata RVA".to_string()))? as usize;
    let meta_root = parse_clr_metadata(&data, metadata_file_offset)?;
    let assembly = extract_assembly_info(&meta_root);
    Ok(assembly)
}
