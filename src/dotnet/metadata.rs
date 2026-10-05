use crate::error::{ReaError, Result};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ClrMetadataRoot {
    pub version_string: String,
    pub streams: HashMap<String, ClrStream>,
}

#[derive(Debug, Clone)]
pub struct ClrStream {
    pub offset: u32,
    pub size: u32,
    pub data: Vec<u8>,
}

pub fn parse_clr_metadata(data: &[u8], metadata_file_offset: usize) -> Result<ClrMetadataRoot> {
    if data.len() < metadata_file_offset + 16 {
        return Err(ReaError::Managed("Metadata offset out of bounds".to_string()));
    }

    let meta = &data[metadata_file_offset..];
    // Magic: 0x424A5342 ("BSJB")
    if &meta[0..4] != b"BSJB" {
        return Err(ReaError::Managed("Invalid CLR metadata signature (expected BSJB)".to_string()));
    }

    let version_len = u32::from_le_bytes([meta[12], meta[13], meta[14], meta[15]]) as usize;
    if meta.len() < 16 + version_len + 4 {
        return Err(ReaError::Managed("Metadata truncated before version string".to_string()));
    }

    let version_raw = &meta[16..16 + version_len];
    let version_end = version_raw.iter().position(|&b| b == 0).unwrap_or(version_len);
    let version_string = String::from_utf8_lossy(&version_raw[..version_end]).to_string();

    let mut cursor = 16 + version_len;
    // Align cursor to 4 bytes if needed
    // let flags = u16::from_le_bytes([meta[cursor], meta[cursor + 1]]);
    let streams_count = u16::from_le_bytes([meta[cursor + 2], meta[cursor + 3]]) as usize;
    cursor += 4;

    let mut streams = HashMap::new();

    for _ in 0..streams_count {
        if cursor + 8 > meta.len() {
            break;
        }
        let stream_offset = u32::from_le_bytes([meta[cursor], meta[cursor + 1], meta[cursor + 2], meta[cursor + 3]]);
        let stream_size = u32::from_le_bytes([meta[cursor + 4], meta[cursor + 5], meta[cursor + 6], meta[cursor + 7]]);
        cursor += 8;

        // Stream name is 4-byte aligned null-terminated ASCII
        let name_start = cursor;
        while cursor < meta.len() && meta[cursor] != 0 {
            cursor += 1;
        }
        let stream_name = String::from_utf8_lossy(&meta[name_start..cursor]).to_string();
        cursor += 1; // skip null
        // Align to 4-byte boundary
        while cursor % 4 != 0 && cursor < meta.len() {
            cursor += 1;
        }

        let abs_start = metadata_file_offset + stream_offset as usize;
        let abs_end = (abs_start + stream_size as usize).min(data.len());
        let stream_data = if abs_start < data.len() {
            data[abs_start..abs_end].to_vec()
        } else {
            Vec::new()
        };

        streams.insert(
            stream_name,
            ClrStream {
                offset: stream_offset,
                size: stream_size,
                data: stream_data,
            },
        );
    }

    Ok(ClrMetadataRoot {
        version_string,
        streams,
    })
}
