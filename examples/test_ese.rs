// Quick test of ESE parser
// cargo run --example test_ese -- /tmp/ntds_test.dit

use std::env;
use std::fs;

fn main() {
    env_logger::init();

    let path = env::args().nth(1).expect("Usage: test_ese <ntds.dit path>");
    let data = fs::read(&path).expect("Failed to read file");

    println!("File: {} ({} bytes)", path, data.len());

    let db = vmkatz::ntds::ese::EseDb::open(&data).expect("Failed to open ESE database");

    let tables = db.table_names();
    println!("Tables found: {} -> {:?}", tables.len(), tables);

    if let Some(cols) = db.columns("datatable") {
        println!("datatable: {} columns", cols.len());

        let interesting = [
            ("ATTm590045", "sAMAccountName"),
            ("ATTk589879", "unicodePwd"),
            ("ATTk589914", "dBCSPwd"),
            ("ATTr589970", "objectSid"),
            ("ATTj589832", "userAccountControl"),
            ("ATTk590689", "pekList"),
        ];
        for (name, desc) in &interesting {
            if let Some(col) = cols.iter().find(|c| c.name == *name) {
                println!("  {} ({}) -> id={} type={} tagged={}",
                    name, desc, col.id, col.col_type, col.is_tagged);
            } else {
                println!("  {} ({}) -> NOT FOUND", name, desc);
            }
        }
    }

    // Scan for PEK
    println!("\n=== PEK search ===");
    db.for_each_row("datatable", |read_col| {
        if let Some(pek_data) = read_col("ATTk590689") {
            let sam = read_col("ATTm590045").map(|d| decode_string(&d)).unwrap_or_default();
            println!("  PEK found! sam='{}' len={} ver=0x{:02x}",
                sam, pek_data.len(),
                if pek_data.len() >= 4 { u32::from_le_bytes(pek_data[..4].try_into().unwrap()) } else { 0 });
        }
    }).expect("Failed to iterate datatable for PEK");

    // Read user records
    println!("\n=== User records ===");
    let mut count = 0;
    db.for_each_row("datatable", |read_col| {
        if let Some(sam_data) = read_col("ATTm590045") {
            let name = decode_string(&sam_data);

            let sid = read_col("ATTr589970");
            let rid = sid.as_ref().and_then(|s| extract_rid(s));

            let uac = read_col("ATTj589832")
                .and_then(|d| if d.len() >= 4 { Some(u32::from_le_bytes(d[..4].try_into().unwrap())) } else { None });

            let nt_len = read_col("ATTk589879").map(|d| d.len()).unwrap_or(0);
            let lm_len = read_col("ATTk589914").map(|d| d.len()).unwrap_or(0);

            if lm_len > 0 || nt_len > 0 {
                println!("  {} | RID={:?} | UAC={:?} | nt_pwd={} | lm_pwd={}",
                    name, rid, uac, nt_len, lm_len);
            }

            count += 1;
        }
    }).expect("Failed to iterate datatable");

    println!("\nTotal records with sAMAccountName: {}", count);
}

fn decode_string(data: &[u8]) -> String {
    if data.len() >= 2 && data.len().is_multiple_of(2) {
        let u16s: Vec<u16> = data.chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        let s = String::from_utf16_lossy(&u16s);
        if !s.is_empty() && s.chars().all(|c| !c.is_control()) {
            return s;
        }
    }
    String::from_utf8_lossy(data).trim_end_matches('\0').to_string()
}

fn extract_rid(sid: &[u8]) -> Option<u32> {
    if sid.len() < 8 { return None; }
    let sub_auth_count = sid[1] as usize;
    let expected_len = 8 + sub_auth_count * 4;
    if sid.len() < expected_len || sub_auth_count == 0 { return None; }
    let rid_offset = 8 + (sub_auth_count - 1) * 4;
    let rid_bytes: [u8; 4] = sid[rid_offset..rid_offset + 4].try_into().ok()?;
    let rid_le = u32::from_le_bytes(rid_bytes);
    let rid_be = u32::from_be_bytes(rid_bytes);
    Some(rid_le.min(rid_be))
}
