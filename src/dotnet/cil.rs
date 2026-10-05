use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CilInstruction {
    pub offset: u32,
    pub opcode: String,
    pub operand: Option<String>,
    pub raw_bytes: String,
}

pub fn decode_cil_method_body(bytes: &[u8]) -> Vec<CilInstruction> {
    let mut instructions = Vec::new();
    if bytes.is_empty() {
        return instructions;
    }
    let header_byte = bytes[0];
    let (code_offset, code_size) = if (header_byte & 0x03) == 0x02 {
        let size = (header_byte >> 2) as usize;
        (1, size.min(bytes.len() - 1))
    } else if (header_byte & 0x03) == 0x03 {
        if bytes.len() < 12 {
            (0, bytes.len())
        } else {
            let size = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
            (12, size.min(bytes.len() - 12))
        }
    } else {
        (0, bytes.len())
    };

    let mut cursor = code_offset;
    let end = code_offset + code_size;

    while cursor < end && cursor < bytes.len() {
        let inst_start = cursor;
        let b1 = bytes[cursor];
        cursor += 1;

        let (opcode, operand_len) = match b1 {
            0x00 => ("nop", 0),
            0x01 => ("break", 0),
            0x02 => ("ldarg.0", 0),
            0x03 => ("ldarg.1", 0),
            0x04 => ("ldarg.2", 0),
            0x05 => ("ldarg.3", 0),
            0x06 => ("ldloc.0", 0),
            0x07 => ("ldloc.1", 0),
            0x08 => ("ldloc.2", 0),
            0x09 => ("ldloc.3", 0),
            0x0a => ("stloc.0", 0),
            0x0b => ("stloc.1", 0),
            0x0c => ("stloc.2", 0),
            0x0d => ("stloc.3", 0),
            0x14 => ("ldnull", 0),
            0x15 => ("ldc.i4.m1", 0),
            0x16 => ("ldc.i4.0", 0),
            0x17 => ("ldc.i4.1", 0),
            0x18 => ("ldc.i4.2", 0),
            0x19 => ("ldc.i4.3", 0),
            0x1a => ("ldc.i4.4", 0),
            0x1b => ("ldc.i4.5", 0),
            0x1f => ("ldc.i4.s", 1),
            0x20 => ("ldc.i4", 4),
            0x25 => ("dup", 0),
            0x26 => ("pop", 0),
            0x28 => ("call", 4),
            0x2a => ("ret", 0),
            0x2b => ("br.s", 1),
            0x2c => ("brfalse.s", 1),
            0x2d => ("brtrue.s", 1),
            0x2e => ("beq.s", 1),
            0x2f => ("bge.s", 1),
            0x30 => ("bgt.s", 1),
            0x31 => ("ble.s", 1),
            0x32 => ("blt.s", 1),
            0x33 => ("bne.un.s", 1),
            0x38 => ("br", 4),
            0x39 => ("brfalse", 4),
            0x3a => ("brtrue", 4),
            0x3b => ("beq", 4),
            0x58 => ("add", 0),
            0x59 => ("sub", 0),
            0x5a => ("mul", 0),
            0x5b => ("div", 0),
            0x6f => ("callvirt", 4),
            0x72 => ("ldstr", 4),
            0x73 => ("newobj", 4),
            0x7b => ("ldfld", 4),
            0x7c => ("ldflda", 4),
            0x7d => ("stfld", 4),
            0x7e => ("ldsfld", 4),
            0x80 => ("stsfld", 4),
            0xa2 => ("throw", 0),
            0xfe => {
                // Two-byte opcode
                if cursor < bytes.len() {
                    let b2 = bytes[cursor];
                    cursor += 1;
                    match b2 {
                        0x01 => ("ceq", 0),
                        0x02 => ("cgt", 0),
                        0x03 => ("cgt.un", 0),
                        0x04 => ("clt", 0),
                        0x05 => ("clt.un", 0),
                        0x06 => ("ldftn", 4),
                        0x07 => ("ldvirtftn", 4),
                        0x0e => ("ldloc", 2),
                        0x0f => ("ldloca", 2),
                        0x10 => ("stloc", 2),
                        _ => ("two_byte_op", 0),
                    }
                } else {
                    ("truncated_op", 0)
                }
            }
            _ => ("unknown_op", 0),
        };

        let operand = if operand_len > 0 && cursor + operand_len <= bytes.len() {
            let op_slice = &bytes[cursor..cursor + operand_len];
            cursor += operand_len;
            Some(match operand_len {
                1 => format!("0x{:02x}", op_slice[0]),
                2 => format!("0x{:04x}", u16::from_le_bytes([op_slice[0], op_slice[1]])),
                4 => format!("0x{:08x}", u32::from_le_bytes([op_slice[0], op_slice[1], op_slice[2], op_slice[3]])),
                _ => hex::encode(op_slice),
            })
        } else {
            None
        };

        let raw = hex::encode(&bytes[inst_start..cursor]);

        instructions.push(CilInstruction {
            offset: (inst_start - code_offset) as u32,
            opcode: opcode.to_string(),
            operand,
            raw_bytes: raw,
        });
    }

    instructions
}
