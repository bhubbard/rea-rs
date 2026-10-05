use crate::error::Result;
use crate::types::{Architecture, DisassembledInstruction, FlowType};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};

pub fn disassemble_bytes(
    bytes: &[u8],
    base_address: u64,
    arch: &Architecture,
    max_instructions: usize,
) -> Result<Vec<DisassembledInstruction>> {
    match arch {
        Architecture::X86_64 => disassemble_x86(bytes, base_address, 64, max_instructions),
        Architecture::X86 => disassemble_x86(bytes, base_address, 32, max_instructions),
        Architecture::AArch64 => disassemble_arm64(bytes, base_address, max_instructions),
        _ => disassemble_generic(bytes, base_address, max_instructions),
    }
}

fn disassemble_x86(
    bytes: &[u8],
    base_address: u64,
    bitness: u32,
    max_instructions: usize,
) -> Result<Vec<DisassembledInstruction>> {
    let mut decoder = Decoder::with_ip(bitness, bytes, base_address, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut instructions = Vec::new();
    let mut output_str = String::new();

    let mut instr = Instruction::default();
    while decoder.can_decode() && instructions.len() < max_instructions {
        decoder.decode_out(&mut instr);

        output_str.clear();
        formatter.format(&instr, &mut output_str);

        // Separate mnemonic and operands
        let mut parts = output_str.splitn(2, ' ');
        let mnemonic = parts.next().unwrap_or("").to_string();
        let operands = parts.next().unwrap_or("").trim().to_string();

        let raw_len = instr.len();
        let ip_offset = (instr.ip() - base_address) as usize;
        let raw_slice = if ip_offset + raw_len <= bytes.len() {
            &bytes[ip_offset..ip_offset + raw_len]
        } else {
            &[]
        };
        let raw_hex = hex::encode(raw_slice);

        let (flow_type, target_address) = match instr.flow_control() {
            iced_x86::FlowControl::Next => (FlowType::Normal, None),
            iced_x86::FlowControl::UnconditionalBranch => {
                (FlowType::UnconditionalBranch, Some(instr.near_branch_target()))
            }
            iced_x86::FlowControl::ConditionalBranch => {
                (FlowType::ConditionalBranch, Some(instr.near_branch_target()))
            }
            iced_x86::FlowControl::Call => (FlowType::Call, Some(instr.near_branch_target())),
            iced_x86::FlowControl::Return => (FlowType::Return, None),
            iced_x86::FlowControl::IndirectBranch => (FlowType::IndirectBranch, None),
            iced_x86::FlowControl::Interrupt => (FlowType::Interrupt, None),
            _ => (FlowType::Normal, None),
        };

        instructions.push(DisassembledInstruction {
            address: instr.ip(),
            bytes: raw_hex,
            mnemonic,
            operands,
            flow_type,
            target_address,
        });
    }

    Ok(instructions)
}

fn disassemble_arm64(
    bytes: &[u8],
    base_address: u64,
    max_instructions: usize,
) -> Result<Vec<DisassembledInstruction>> {
    let mut instructions = Vec::new();
    let count = bytes.len() / 4;
    let limit = count.min(max_instructions);

    for i in 0..limit {
        let addr = base_address + (i as u64 * 4);
        let chunk = &bytes[i * 4..(i + 1) * 4];
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let raw_hex = hex::encode(chunk);

        // Decode basic AArch64 control flow
        let (mnemonic, operands, flow_type, target_address) = decode_arm64_instruction(word, addr);

        instructions.push(DisassembledInstruction {
            address: addr,
            bytes: raw_hex,
            mnemonic,
            operands,
            flow_type,
            target_address,
        });
    }

    Ok(instructions)
}

fn decode_arm64_instruction(word: u32, addr: u64) -> (String, String, FlowType, Option<u64>) {
    // Check ret (0xd65f03c0)
    if word == 0xd65f03c0 {
        return ("ret".to_string(), "".to_string(), FlowType::Return, None);
    }
    // Check b (unconditional)
    if (word >> 26) == 0b000101 {
        let imm26 = word & 0x03ffffff;
        let sign_extended = sign_extend_26(imm26) as i64 * 4;
        let target = (addr as i64 + sign_extended) as u64;
        return (
            "b".to_string(),
            format!("0x{:x}", target),
            FlowType::UnconditionalBranch,
            Some(target),
        );
    }
    // Check bl (branch with link / call)
    if (word >> 26) == 0b100101 {
        let imm26 = word & 0x03ffffff;
        let sign_extended = sign_extend_26(imm26) as i64 * 4;
        let target = (addr as i64 + sign_extended) as u64;
        return (
            "bl".to_string(),
            format!("0x{:x}", target),
            FlowType::Call,
            Some(target),
        );
    }
    // Check b.cond
    if (word >> 24) == 0b01010100 && (word & 0x10) == 0 {
        let imm19 = (word >> 5) & 0x7ffff;
        let sign_extended = sign_extend_19(imm19) as i64 * 4;
        let target = (addr as i64 + sign_extended) as u64;
        let cond = word & 0xf;
        let cond_name = match cond {
            0 => "eq", 1 => "ne", 2 => "cs", 3 => "cc",
            4 => "mi", 5 => "pl", 6 => "vs", 7 => "vc",
            8 => "hi", 9 => "ls", 10 => "ge", 11 => "lt",
            12 => "gt", 13 => "le", 14 => "al", _ => "nv",
        };
        return (
            format!("b.{}", cond_name),
            format!("0x{:x}", target),
            FlowType::ConditionalBranch,
            Some(target),
        );
    }
    // Check cbz / cbnz
    if (word >> 25) == 0b0011010 || (word >> 25) == 0b1011010 {
        let is_cbnz = (word & (1 << 24)) != 0;
        let imm19 = (word >> 5) & 0x7ffff;
        let rt = word & 0x1f;
        let sign_extended = sign_extend_19(imm19) as i64 * 4;
        let target = (addr as i64 + sign_extended) as u64;
        let op = if is_cbnz { "cbnz" } else { "cbz" };
        return (
            op.to_string(),
            format!("x{}, 0x{:x}", rt, target),
            FlowType::ConditionalBranch,
            Some(target),
        );
    }

    // Default unknown / general opcode
    ("inst".to_string(), format!("0x{:08x}", word), FlowType::Normal, None)
}

fn sign_extend_26(imm: u32) -> i32 {
    if (imm & 0x02000000) != 0 {
        (imm | 0xfc000000) as i32
    } else {
        imm as i32
    }
}

fn sign_extend_19(imm: u32) -> i32 {
    if (imm & 0x00040000) != 0 {
        (imm | 0xfff80000) as i32
    } else {
        imm as i32
    }
}

fn disassemble_generic(
    bytes: &[u8],
    base_address: u64,
    max_instructions: usize,
) -> Result<Vec<DisassembledInstruction>> {
    let mut instructions = Vec::new();
    let limit = (bytes.len() / 4).min(max_instructions);

    for i in 0..limit {
        let addr = base_address + (i as u64 * 4);
        let chunk = &bytes[i * 4..(i + 1) * 4];
        let raw_hex = hex::encode(chunk);
        instructions.push(DisassembledInstruction {
            address: addr,
            bytes: raw_hex,
            mnemonic: "dw".to_string(),
            operands: format!("0x{:02x}{:02x}{:02x}{:02x}", chunk[3], chunk[2], chunk[1], chunk[0]),
            flow_type: FlowType::Normal,
            target_address: None,
        });
    }

    Ok(instructions)
}
