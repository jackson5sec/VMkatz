// End-to-end NTDS.dit hash extraction test
// Usage: cargo run --example test_ntds -- <ntds.dit> <SYSTEM hive>

use std::env;
use std::fs;

struct L;
impl log::Log for L {
    fn enabled(&self, m: &log::Metadata) -> bool { m.level() <= log::max_level() }
    fn log(&self, r: &log::Record) { if self.enabled(r.metadata()) { eprintln!("[{}] {}", r.level(), r.args()); } }
    fn flush(&self) {}
}

fn main() {
    let _ = log::set_logger(&L).map(|()| log::set_max_level(log::LevelFilter::Info));

    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: test_ntds <ntds.dit path> <SYSTEM hive path>");
        std::process::exit(1);
    }

    let ntds_data = fs::read(&args[1]).expect("Failed to read NTDS.dit");
    let system_data = fs::read(&args[2]).expect("Failed to read SYSTEM hive");

    println!("NTDS.dit: {} bytes", ntds_data.len());
    println!("SYSTEM:   {} bytes", system_data.len());

    match vmkatz::ntds::extract_ad_hashes(&ntds_data, &system_data, false) {
        Ok(entries) => {
            println!("\n=== Extracted {} hash entries ===\n", entries.len());
            // Standard empty LM hash (hash of empty password using LanMan algorithm)
            let empty_lm = "aad3b435b51404eeaad3b435b51404ee";
            for entry in &entries {
                let nt_hex = hex::encode(entry.nt_hash);
                let lm_hex = if entry.lm_hash == [0u8; 16] {
                    empty_lm.to_string()
                } else {
                    hex::encode(entry.lm_hash)
                };
                println!(
                    "{}:{}:{}:{}:::",
                    entry.username, entry.rid, lm_hex, nt_hex,
                );
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
