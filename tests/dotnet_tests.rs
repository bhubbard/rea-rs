use rea::dotnet::cil::decode_cil_method_body;

#[test]
fn test_decode_cil_method_body() {
    // ECMA-335 CIL tiny method header:
    // Header byte: 0x2A (Tiny header, code size = 0x2A >> 2 = 10 bytes)
    // ldarg.0 (0x02)
    // ldc.i4.1 (0x17)
    // add (0x58)
    // stloc.0 (0x0a)
    // ldloc.0 (0x06)
    // ret (0x2a)
    let bytecode: [u8; 7] = [
        0x1A, // Tiny header, code_size = 6
        0x02, // ldarg.0
        0x17, // ldc.i4.1
        0x58, // add
        0x0a, // stloc.0
        0x06, // ldloc.0
        0x2a, // ret
    ];

    let instructions = decode_cil_method_body(&bytecode);
    assert_eq!(instructions.len(), 6);
    assert_eq!(instructions[0].opcode, "ldarg.0");
    assert_eq!(instructions[1].opcode, "ldc.i4.1");
    assert_eq!(instructions[2].opcode, "add");
    assert_eq!(instructions[3].opcode, "stloc.0");
    assert_eq!(instructions[4].opcode, "ldloc.0");
    assert_eq!(instructions[5].opcode, "ret");
}
