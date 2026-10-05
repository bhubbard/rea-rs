use crate::error::{ReaError, Result};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ClrHeaderInfo {
    pub major_runtime_version: u16,
    pub minor_runtime_version: u16,
    pub metadata_rva: u32,
    pub metadata_size: u32,
    pub flags: u32,
    pub entry_point_token: u32,
}

#[derive(Debug, Clone)]
pub struct SectionHeader {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_data_size: u32,
    pub raw_data_pointer: u32,
}

pub fn read_dotnet_pe(path: impl AsRef<Path>) -> Result<(Vec<u8>, ClrHeaderInfo, Vec<SectionHeader>)> {
    let data = fs::read(path.as_ref())?;
    if data.len() < 0x40 || data[0] != 0x4D || data[1] != 0x5A {
        return Err(ReaError::Managed("Not a valid MS-DOS executable".to_string()));
    }

    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if data.len() < pe_offset + 0x18 + 0x60 || &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err(ReaError::Managed("Not a valid PE executable".to_string()));
    }

    let num_sections = u16::from_le_bytes([data[pe_offset + 6], data[pe_offset + 7]]) as usize;
    let opt_header_size = u16::from_le_bytes([data[pe_offset + 20], data[pe_offset + 21]]) as usize;
    let opt_header_offset = pe_offset + 24;

    let magic = u16::from_le_bytes([data[opt_header_offset], data[opt_header_offset + 1]]);
    let clr_dir_offset = if magic == 0x10b {
        opt_header_offset + 96 + (14 * 8)
    } else if magic == 0x20b {
        opt_header_offset + 112 + (14 * 8)
    } else {
        return Err(ReaError::Managed("Invalid optional header magic".to_string()));
    };

    if data.len() < clr_dir_offset + 8 {
        return Err(ReaError::Managed("PE header too small for CLR directory".to_string()));
    }

    let clr_rva = u32::from_le_bytes([
        data[clr_dir_offset],
        data[clr_dir_offset + 1],
        data[clr_dir_offset + 2],
        data[clr_dir_offset + 3],
    ]);
    let clr_size = u32::from_le_bytes([
        data[clr_dir_offset + 4],
        data[clr_dir_offset + 5],
        data[clr_dir_offset + 6],
        data[clr_dir_offset + 7],
    ]);

    if clr_rva == 0 || clr_size == 0 {
        return Err(ReaError::Managed("Binary does not contain CLR header (not a .NET assembly)".to_string()));
    }

    // Read section headers
    let sections_offset = opt_header_offset + opt_header_size;
    let mut sections = Vec::new();
    for i in 0..num_sections {
        let sec_offset = sections_offset + (i * 40);
        if data.len() < sec_offset + 40 {
            break;
        }
        let sec_bytes = &data[sec_offset..sec_offset + 40];
        let name_raw = &sec_bytes[0..8];
        let name_end = name_raw.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_raw[..name_end]).to_string();

        let virtual_size = u32::from_le_bytes([sec_bytes[8], sec_bytes[9], sec_bytes[10], sec_bytes[11]]);
        let virtual_address = u32::from_le_bytes([sec_bytes[12], sec_bytes[13], sec_bytes[14], sec_bytes[15]]);
        let raw_data_size = u32::from_le_bytes([sec_bytes[16], sec_bytes[17], sec_bytes[18], sec_bytes[19]]);
        let raw_data_pointer = u32::from_le_bytes([sec_bytes[20], sec_bytes[21], sec_bytes[22], sec_bytes[23]]);

        sections.push(SectionHeader {
            name,
            virtual_size,
            virtual_address,
            raw_data_size,
            raw_data_pointer,
        });
    }

    let clr_file_offset = rva_to_file_offset(clr_rva, &sections)
        .ok_or_else(|| ReaError::Managed("Failed to map CLR RVA to file offset".to_string()))? as usize;

    if data.len() < clr_file_offset + 72 {
        return Err(ReaError::Managed("Truncated CLR header".to_string()));
    }

    let clr_bytes = &data[clr_file_offset..clr_file_offset + 72];
    let major_runtime_version = u16::from_le_bytes([clr_bytes[4], clr_bytes[5]]);
    let minor_runtime_version = u16::from_le_bytes([clr_bytes[6], clr_bytes[7]]);
    let metadata_rva = u32::from_le_bytes([clr_bytes[8], clr_bytes[9], clr_bytes[10], clr_bytes[11]]);
    let metadata_size = u32::from_le_bytes([clr_bytes[12], clr_bytes[13], clr_bytes[14], clr_bytes[15]]);
    let flags = u32::from_le_bytes([clr_bytes[16], clr_bytes[17], clr_bytes[18], clr_bytes[19]]);
    let entry_point_token = u32::from_le_bytes([clr_bytes[20], clr_bytes[21], clr_bytes[22], clr_bytes[23]]);

    let header = ClrHeaderInfo {
        major_runtime_version,
        minor_runtime_version,
        metadata_rva,
        metadata_size,
        flags,
        entry_point_token,
    };

    Ok((data, header, sections))
}

pub fn rva_to_file_offset(rva: u32, sections: &[SectionHeader]) -> Option<u32> {
    for sec in sections {
        if rva >= sec.virtual_address && rva < sec.virtual_address + sec.virtual_size {
            let offset_in_sec = rva - sec.virtual_address;
            return Some(sec.raw_data_pointer + offset_in_sec);
        }
    }
    None
}
