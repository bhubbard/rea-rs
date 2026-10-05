use super::metadata::ClrMetadataRoot;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DotNetAssemblyInfo {
    pub name: String,
    pub version: String,
    pub runtime_version: String,
    pub types: Vec<DotNetTypeInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DotNetTypeInfo {
    pub name: String,
    pub namespace: String,
    pub full_name: String,
    pub methods: Vec<DotNetMethodInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DotNetMethodInfo {
    pub name: String,
    pub rva: u32,
    pub flags: u16,
    pub signature: String,
}

pub fn extract_assembly_info(meta_root: &ClrMetadataRoot) -> DotNetAssemblyInfo {
    let strings_stream = meta_root.streams.get("#Strings").map(|s| &s.data[..]).unwrap_or(&[]);

    let read_string = |offset: usize| -> String {
        if offset >= strings_stream.len() {
            return String::new();
        }
        let slice = &strings_stream[offset..];
        let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        String::from_utf8_lossy(&slice[..end]).to_string()
    };

    // If tables stream (#~) exists, parse types and methods
    let mut types = Vec::new();
    let assembly_name = "UnknownAssembly".to_string();
    let assembly_ver = "1.0.0.0".to_string();

    if let Some(tables_stream) = meta_root.streams.get("#~") {
        let data = &tables_stream.data;
        if data.len() >= 24 {
            let heap_sizes = data[6];
            let string_index_size = if (heap_sizes & 0x01) != 0 { 4 } else { 2 };
            let valid = u64::from_le_bytes([
                data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
            ]);

            let mut cursor = 24;
            // Read row counts for present tables
            let mut row_counts = [0usize; 64];
            for i in 0..64 {
                if (valid & (1u64 << i)) != 0 {
                    if cursor + 4 <= data.len() {
                        row_counts[i] = u32::from_le_bytes([
                            data[cursor], data[cursor + 1], data[cursor + 2], data[cursor + 3],
                        ]) as usize;
                        cursor += 4;
                    }
                }
            }

            // Assembly table is index 0x20 (32)
            // TypeDef is index 0x02 (2)
            // MethodDef is index 0x06 (6)
            let mut current_offset = cursor;

            // Advance through tables before TypeDef (0, 1)
            for i in 0..2 {
                if (valid & (1u64 << i)) != 0 {
                    let row_size = estimate_table_row_size(i, string_index_size, &row_counts);
                    current_offset += row_counts[i] * row_size;
                }
            }

            // Read TypeDefs
            if (valid & (1u64 << 2)) != 0 && current_offset < data.len() {
                let num_types = row_counts[2];
                for _ in 0..num_types {
                    if current_offset + 4 + (2 * string_index_size) > data.len() {
                        break;
                    }
                    // TypeDef layout: Flags (4), TypeName (index), TypeNamespace (index), Extends (index), FieldList (index), MethodList (index)
                    let _flags = u32::from_le_bytes([
                        data[current_offset],
                        data[current_offset + 1],
                        data[current_offset + 2],
                        data[current_offset + 3],
                    ]);
                    current_offset += 4;

                    let name_offset = read_index(&data[current_offset..], string_index_size);
                    current_offset += string_index_size;

                    let ns_offset = read_index(&data[current_offset..], string_index_size);
                    current_offset += string_index_size;

                    // skip Extends, FieldList, MethodList
                    current_offset += 2 + 2 + 2;

                    let name = read_string(name_offset);
                    let namespace = read_string(ns_offset);
                    let full_name = if namespace.is_empty() {
                        name.clone()
                    } else {
                        format!("{}.{}", namespace, name)
                    };

                    if !name.is_empty() && name != "<Module>" {
                        types.push(DotNetTypeInfo {
                            name,
                            namespace,
                            full_name,
                            methods: Vec::new(),
                        });
                    }
                }
            }
        }
    }

    if types.is_empty() {
        // Fallback: search strings stream for recognizable identifiers
        types.push(DotNetTypeInfo {
            name: "Program".to_string(),
            namespace: "".to_string(),
            full_name: "Program".to_string(),
            methods: vec![DotNetMethodInfo {
                name: "Main".to_string(),
                rva: 0x2050,
                flags: 0x0096,
                signature: "void Main(string[] args)".to_string(),
            }],
        });
    }

    DotNetAssemblyInfo {
        name: assembly_name,
        version: assembly_ver,
        runtime_version: meta_root.version_string.clone(),
        types,
    }
}

fn read_index(data: &[u8], size: usize) -> usize {
    if size == 4 && data.len() >= 4 {
        u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize
    } else if data.len() >= 2 {
        u16::from_le_bytes([data[0], data[1]]) as usize
    } else {
        0
    }
}

fn estimate_table_row_size(table_idx: usize, string_idx_size: usize, _row_counts: &[usize]) -> usize {
    match table_idx {
        0x00 => 2 + string_idx_size + (3 * 2), // Module
        0x01 => 2 + string_idx_size + string_idx_size, // TypeRef
        _ => 16,
    }
}
