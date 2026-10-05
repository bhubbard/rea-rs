use crate::error::Result;
use crate::types::StringMatch;
use object::{Object, ObjectSection};
use std::fs;
use std::path::Path;

pub fn extract_strings(
    path: impl AsRef<Path>,
    min_length: usize,
    query_filter: Option<&str>,
) -> Result<Vec<StringMatch>> {
    let data = fs::read(path.as_ref())?;
    let mut matches = Vec::new();

    // Map section offsets if object parses
    let section_ranges: Vec<(u64, u64, String)> = if let Ok(obj) = object::File::parse(&*data) {
        obj.sections()
            .filter_map(|s| {
                let name = s.name().unwrap_or("").to_string();
                s.file_range().map(|(start, size)| (start, start + size, name))
            })
            .collect()
    } else {
        Vec::new()
    };

    let find_section = |offset: u64| -> Option<String> {
        section_ranges
            .iter()
            .find(|(start, end, _)| offset >= *start && offset < *end)
            .map(|(_, _, name)| name.clone())
    };

    // 1. ASCII string extraction
    let mut current_start = 0;
    let mut current_ascii = Vec::new();

    for (idx, &byte) in data.iter().enumerate() {
        if byte.is_ascii_graphic() || byte == b' ' || byte == b'\t' {
            if current_ascii.is_empty() {
                current_start = idx as u64;
            }
            current_ascii.push(byte);
        } else {
            if current_ascii.len() >= min_length {
                if let Ok(s) = std::str::from_utf8(&current_ascii) {
                    let keep = match query_filter {
                        Some(q) => s.to_lowercase().contains(&q.to_lowercase()),
                        None => true,
                    };
                    if keep {
                        matches.push(StringMatch {
                            offset: current_start,
                            value: s.to_string(),
                            length: current_ascii.len(),
                            is_utf16: false,
                            section: find_section(current_start),
                        });
                    }
                }
            }
            current_ascii.clear();
        }
    }

    // 2. UTF-16LE string extraction (2 bytes per char: ASCII byte + 0x00)
    let mut i = 0;
    while i + 1 < data.len() {
        let b1 = data[i];
        let b2 = data[i + 1];

        if (b1.is_ascii_graphic() || b1 == b' ' || b1 == b'\t') && b2 == 0 {
            let start = i as u64;
            let mut u16_chars = Vec::new();
            while i + 1 < data.len() {
                let c1 = data[i];
                let c2 = data[i + 1];
                if (c1.is_ascii_graphic() || c1 == b' ' || c1 == b'\t') && c2 == 0 {
                    u16_chars.push(c1 as char);
                    i += 2;
                } else {
                    break;
                }
            }
            if u16_chars.len() >= min_length {
                let s: String = u16_chars.into_iter().collect();
                let keep = match query_filter {
                    Some(q) => s.to_lowercase().contains(&q.to_lowercase()),
                    None => true,
                };
                if keep {
                    matches.push(StringMatch {
                        offset: start,
                        value: s,
                        length: (i as u64 - start) as usize,
                        is_utf16: true,
                        section: find_section(start),
                    });
                }
            }
        } else {
            i += 1;
        }
    }

    // Sort by offset
    matches.sort_by_key(|m| m.offset);
    Ok(matches)
}
