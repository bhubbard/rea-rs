use rea::binary::cfg::build_cfg;
use rea::binary::disasm::disassemble_bytes;
use rea::binary::format::{calculate_entropy, inspect_binary_file};
use rea::binary::strings::extract_strings;
use rea::types::Architecture;
use std::path::Path;

#[test]
fn test_calculate_entropy() {
    let empty = [];
    assert_eq!(calculate_entropy(&empty), 0.0);

    let uniform = vec![0x41; 100];
    assert_eq!(calculate_entropy(&uniform), 0.0);

    let mut random_like = Vec::new();
    for i in 0..256 {
        random_like.push(i as u8);
    }
    let ent = calculate_entropy(&random_like);
    assert!((ent - 8.0).abs() < 0.01);
}

#[test]
fn test_disasm_and_cfg_x86_64() {
    // x86_64 machine code:
    // push rbp (0x55)
    // mov rbp, rsp (0x48 0x89 0xe5)
    // cmp edi, 0 (0x83 0xff 0x00)
    // je +4 (0x74 0x04)
    // mov eax, 1 (0xb8 0x01 0x00 0x00 0x00)
    // jmp +5 (0xeb 0x05)
    // xor eax, eax (0x31 0xc0)
    // pop rbp (0x5d)
    // ret (0xc3)
    let code: [u8; 20] = [
        0x55,
        0x48, 0x89, 0xe5,
        0x83, 0xff, 0x00,
        0x74, 0x07,
        0xb8, 0x01, 0x00, 0x00, 0x00,
        0xeb, 0x02,
        0x31, 0xc0,
        0x5d,
        0xc3,
    ];

    let insts = disassemble_bytes(&code, 0x1000, &Architecture::X86_64, 100).expect("disassembly");
    assert!(!insts.is_empty());

    let cfg = build_cfg("test_proc", &insts);
    assert!(cfg.blocks.len() >= 2);
    assert!(!cfg.edges.is_empty());
}

#[test]
fn test_inspect_host_binary() {
    let host_bin = if Path::new("/bin/ls").exists() {
        "/bin/ls"
    } else if Path::new("/bin/echo").exists() {
        "/bin/echo"
    } else if Path::new("/usr/bin/true").exists() {
        "/usr/bin/true"
    } else {
        return;
    };

    let res = inspect_binary_file(host_bin);
    assert!(res.is_ok());
    let (info, sections) = res.unwrap();
    assert_eq!(info.path, host_bin);
    assert!(info.size_bytes > 0);
    assert!(!info.sha256.is_empty());
    assert!(!sections.is_empty());

    let strings = extract_strings(host_bin, 4, None).expect("strings");
    assert!(!strings.is_empty());
}
