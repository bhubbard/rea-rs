use crate::error::{ReaError, Result};
use crate::types::{Architecture, ArtifactInfo, BinaryFormat, SectionInfo};
use object::{Object, ObjectSection};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

pub fn get_effective_binary_data(data: &[u8]) -> (&[u8], bool) {
    if data.len() >= 8 && (&data[0..4] == &[0xca, 0xfe, 0xba, 0xbe] || &data[0..4] == &[0xbe, 0xba, 0xfe, 0xca]) {
        let nfat_arch = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let host_is_arm64 = cfg!(target_arch = "aarch64");
        let mut chosen_slice = None;

        for i in 0..nfat_arch {
            let entry_offset = 8 + i * 20;
            if entry_offset + 20 > data.len() {
                break;
            }
            let cputype = u32::from_be_bytes([
                data[entry_offset],
                data[entry_offset + 1],
                data[entry_offset + 2],
                data[entry_offset + 3],
            ]);
            let slice_offset = u32::from_be_bytes([
                data[entry_offset + 8],
                data[entry_offset + 9],
                data[entry_offset + 10],
                data[entry_offset + 11],
            ]) as usize;
            let slice_size = u32::from_be_bytes([
                data[entry_offset + 12],
                data[entry_offset + 13],
                data[entry_offset + 14],
                data[entry_offset + 15],
            ]) as usize;

            if slice_offset + slice_size <= data.len() {
                let slice = &data[slice_offset..slice_offset + slice_size];
                // 0x0100000c = CPU_TYPE_ARM64, 0x01000007 = CPU_TYPE_X86_64
                if host_is_arm64 && cputype == 0x0100000c {
                    return (slice, true);
                } else if !host_is_arm64 && cputype == 0x01000007 {
                    return (slice, true);
                }
                if chosen_slice.is_none() {
                    chosen_slice = Some(slice);
                }
            }
        }
        if let Some(s) = chosen_slice {
            return (s, true);
        }
    }
    (data, false)
}

pub fn inspect_binary_file(path: impl AsRef<Path>) -> Result<(ArtifactInfo, Vec<SectionInfo>)> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(ReaError::ArtifactNotFound(path.display().to_string()));
    }

    let data = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let sha256 = hex::encode(hasher.finalize());

    let file_name = path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let (effective_data, is_fat) = get_effective_binary_data(&data);

    let obj_file = object::File::parse(effective_data)
        .map_err(|e| ReaError::InvalidFormat(format!("Failed to parse object: {}", e)))?;

    let format = if is_fat {
        BinaryFormat::MachOFat
    } else {
        match obj_file.format() {
            object::BinaryFormat::MachO => {
                if obj_file.is_64() {
                    BinaryFormat::MachO64
                } else {
                    BinaryFormat::MachO32
                }
            }
        object::BinaryFormat::Elf => {
            if obj_file.is_64() {
                BinaryFormat::Elf64
            } else {
                BinaryFormat::Elf32
            }
        }
        object::BinaryFormat::Pe => {
            // Check if .NET CLI
            if is_dotnet_pe(&data) {
                BinaryFormat::DotNetCli
            } else if obj_file.is_64() {
                BinaryFormat::Pe32Plus
            } else {
                BinaryFormat::Pe32
            }
        }
        object::BinaryFormat::Coff => BinaryFormat::Archive,
        other => BinaryFormat::Unknown(format!("{:?}", other)),
        }
    };

    let architecture = match obj_file.architecture() {
        object::Architecture::X86_64 => Architecture::X86_64,
        object::Architecture::I386 => Architecture::X86,
        object::Architecture::Aarch64 => Architecture::AArch64,
        object::Architecture::Arm => Architecture::Arm,
        object::Architecture::Mips => Architecture::Mips,
        object::Architecture::Riscv64 | object::Architecture::Riscv32 => Architecture::RiscV,
        object::Architecture::Wasm32 => Architecture::Wasm,
        other => Architecture::Unknown(format!("{:?}", other)),
    };

    let is_dotnet = format == BinaryFormat::DotNetCli;
    let entry_point = Some(obj_file.entry());
    let image_base = Some(obj_file.relative_address_base());

    let uuid = obj_file
        .mach_uuid()
        .ok()
        .flatten()
        .map(|u| format!("{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]))
        .or_else(|| {
            obj_file.build_id().ok().flatten().map(hex::encode)
        });

    let mut sections = Vec::new();
    for section in obj_file.sections() {
        let name = section.name().unwrap_or("<unnamed>").to_string();
        let address = section.address();
        let size = section.size();
        let (file_offset, _) = section.file_range().unwrap_or((0, 0));

        let section_data = section.data().unwrap_or(&[]);
        let entropy = calculate_entropy(section_data);

        // Derive permissions using section.kind()
        let kind = section.kind();
        let is_exec = kind == object::SectionKind::Text;
        let is_write = kind == object::SectionKind::Data || kind == object::SectionKind::UninitializedData;

        let mut perms = String::new();
        perms.push('r');
        perms.push(if is_write { 'w' } else { '-' });
        perms.push(if is_exec { 'x' } else { '-' });

        sections.push(SectionInfo {
            name,
            address,
            size,
            file_offset,
            permissions: perms,
            entropy,
        });
    }

    let symbol_count = obj_file.symbols().count();

    let info = ArtifactInfo {
        path: path.display().to_string(),
        file_name,
        size_bytes: data.len() as u64,
        sha256,
        format,
        architecture,
        is_64_bit: obj_file.is_64(),
        is_little_endian: obj_file.is_little_endian(),
        entry_point,
        image_base,
        uuid,
        section_count: sections.len(),
        symbol_count,
        is_pie: true,
        is_dotnet,
    };

    Ok((info, sections))
}

pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn is_dotnet_pe(data: &[u8]) -> bool {
    // Check for DOS signature MZ (0x4D, 0x5A)
    if data.len() < 0x40 || data[0] != 0x4D || data[1] != 0x5A {
        return false;
    }
    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if data.len() < pe_offset + 0x18 + 0x60 {
        return false;
    }
    // Check PE signature PE\0\0
    if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return false;
    }
    let magic = u16::from_le_bytes([data[pe_offset + 0x18], data[pe_offset + 0x19]]);
    let clr_dir_offset = if magic == 0x10b {
        // PE32: Optional header is 96 bytes before data directories, CLR is directory 14 (14 * 8 = 112)
        pe_offset + 0x18 + 96 + 112
    } else if magic == 0x20b {
        // PE32+: Optional header is 112 bytes before data directories, CLR is directory 14
        pe_offset + 0x18 + 112 + 112
    } else {
        return false;
    };

    if data.len() < clr_dir_offset + 8 {
        return false;
    }
    let clr_rva = u32::from_le_bytes([
        data[clr_dir_offset],
        data[clr_dir_offset + 1],
        data[clr_dir_offset + 2],
        data[clr_dir_offset + 3],
    ]);
    clr_rva != 0
}
