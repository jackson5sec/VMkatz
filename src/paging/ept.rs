//! Extended Page Table (EPT) walker for nested virtualization (VBS/Hyper-V).
//!
//! When VBS is enabled, Hyper-V runs inside the VM as a nested hypervisor.
//! ESXi captures L1 guest physical memory, but the Windows kernel runs in
//! L2 guest physical space mapped through Hyper-V's EPT (SLAT).
//!
//! This module finds and walks the EPT to reconstruct L2→L1 translation,
//! allowing us to scan L2 physical memory for EPROCESS structures.

use crate::error::{GovmemError, Result};
use crate::memory::PhysicalMemory;

const PAGE_SIZE: u64 = 4096;
const EPT_PRESENT_MASK: u64 = 0x7; // bits 2:0 = RWX
const EPT_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000; // bits 51:12
const EPT_LARGE_PAGE: u64 = 1 << 7; // bit 7 = large page

/// EPT-translated physical memory layer.
/// Wraps an L1 PhysicalMemory and translates L2 addresses through the EPT.
pub struct EptLayer<'a, P: PhysicalMemory> {
    l1: &'a P,
    ept_pml4: u64, // L1 physical address of the EPT PML4 table
    l2_size: u64,  // Maximum L2 physical address observed
}

impl<'a, P: PhysicalMemory> EptLayer<'a, P> {
    /// Create an EPT layer with a known PML4 root address.
    pub fn new(l1: &'a P, ept_pml4: u64, l2_size: u64) -> Self {
        Self {
            l1,
            ept_pml4,
            l2_size,
        }
    }

    /// Translate an L2 guest physical address to L1 physical address via EPT.
    pub fn translate_l2(&self, l2_phys: u64) -> Result<u64> {
        let pml4_idx = (l2_phys >> 39) & 0x1FF;
        let pdpt_idx = (l2_phys >> 30) & 0x1FF;
        let pd_idx = (l2_phys >> 21) & 0x1FF;
        let pt_idx = (l2_phys >> 12) & 0x1FF;
        let offset = l2_phys & 0xFFF;

        // PML4
        let pml4e = self.read_ept_entry(self.ept_pml4 + pml4_idx * 8)?;
        if pml4e & EPT_PRESENT_MASK == 0 {
            return Err(GovmemError::UnmappablePhysical(l2_phys));
        }

        // PDPT
        let pdpt_base = pml4e & EPT_ADDR_MASK;
        let pdpte = self.read_ept_entry(pdpt_base + pdpt_idx * 8)?;
        if pdpte & EPT_PRESENT_MASK == 0 {
            return Err(GovmemError::UnmappablePhysical(l2_phys));
        }
        // 1GB large page
        if pdpte & EPT_LARGE_PAGE != 0 {
            let base = pdpte & 0x000F_FFFF_C000_0000; // bits 51:30
            return Ok(base | (l2_phys & 0x3FFF_FFFF));
        }

        // PD
        let pd_base = pdpte & EPT_ADDR_MASK;
        let pde = self.read_ept_entry(pd_base + pd_idx * 8)?;
        if pde & EPT_PRESENT_MASK == 0 {
            return Err(GovmemError::UnmappablePhysical(l2_phys));
        }
        // 2MB large page
        if pde & EPT_LARGE_PAGE != 0 {
            let base = pde & 0x000F_FFFF_FFE0_0000; // bits 51:21
            return Ok(base | (l2_phys & 0x001F_FFFF));
        }

        // PT
        let pt_base = pde & EPT_ADDR_MASK;
        let pte = self.read_ept_entry(pt_base + pt_idx * 8)?;
        if pte & EPT_PRESENT_MASK == 0 {
            return Err(GovmemError::UnmappablePhysical(l2_phys));
        }

        Ok((pte & EPT_ADDR_MASK) | offset)
    }

    fn read_ept_entry(&self, l1_addr: u64) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.l1.read_phys(l1_addr, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }
}

impl<'a, P: PhysicalMemory> PhysicalMemory for EptLayer<'a, P> {
    fn read_phys(&self, phys_addr: u64, buf: &mut [u8]) -> Result<()> {
        // Handle reads that might cross page boundaries
        let mut offset = 0;
        while offset < buf.len() {
            let current_addr = phys_addr + offset as u64;
            let page_remaining = PAGE_SIZE as usize - (current_addr as usize & 0xFFF);
            let to_read = std::cmp::min(buf.len() - offset, page_remaining);

            let l1_addr = self.translate_l2(current_addr)?;
            self.l1.read_phys(l1_addr, &mut buf[offset..offset + to_read])?;
            offset += to_read;
        }
        Ok(())
    }

    fn phys_size(&self) -> u64 {
        self.l2_size
    }
}

/// Scan L1 physical memory for potential EPT PML4 tables.
/// Returns the best candidate (L1 physical address of PML4, estimated L2 size).
pub fn find_ept_root<P: PhysicalMemory>(l1: &P) -> Result<(u64, u64)> {
    let l1_size = l1.phys_size();
    let mut best_pml4: u64 = 0;
    let mut best_mapped: u64 = 0;
    let mut best_l2_max: u64 = 0;

    log::info!(
        "EPT scan: searching {} MB for EPT PML4 tables...",
        l1_size / (1024 * 1024)
    );

    let mut page_buf = vec![0u8; PAGE_SIZE as usize];
    let mut candidates = 0u32;

    let mut addr: u64 = 0;
    while addr < l1_size {
        if l1.read_phys(addr, &mut page_buf).is_err() {
            addr += PAGE_SIZE;
            continue;
        }

        // Skip zero pages
        if page_buf.iter().all(|&b| b == 0) {
            addr += PAGE_SIZE;
            continue;
        }

        // Check if this page looks like an EPT PML4 table:
        // - EPT PML4 has 512 entries (8 bytes each) = 4KB
        // - Valid entries have RWX bits set and point to valid L1 addresses
        // - Most entries are zero (sparse)
        let (valid, zero, invalid, max_l2) = score_ept_page(&page_buf, l1_size);

        // A good PML4: some valid entries, mostly zeros, no invalid entries
        if valid >= 1 && valid <= 64 && zero >= 400 && invalid == 0 {
            candidates += 1;

            // Walk one level deeper to count total mapped pages
            let mapped = count_ept_mapped_pages(l1, addr, l1_size);

            log::debug!(
                "EPT candidate at L1=0x{:x}: {} valid PML4E, ~{} mapped pages, max_l2=0x{:x}",
                addr,
                valid,
                mapped,
                max_l2
            );

            if mapped > best_mapped {
                best_mapped = mapped;
                best_pml4 = addr;
                best_l2_max = max_l2;
            }
        }

        addr += PAGE_SIZE;
    }

    log::info!(
        "EPT scan: {} candidates found, best at L1=0x{:x} with ~{} mapped pages",
        candidates,
        best_pml4,
        best_mapped
    );

    if best_mapped < 100 {
        return Err(GovmemError::SystemProcessNotFound);
    }

    // L2 size = max L2 address + 1GB margin
    let l2_size = (best_l2_max + 1) * (1u64 << 39);
    Ok((best_pml4, l2_size))
}

/// Score a page as a potential EPT PML4/PDPT/PD table.
/// Returns (valid_entries, zero_entries, invalid_entries, max_l2_index).
fn score_ept_page(page: &[u8], l1_size: u64) -> (u32, u32, u32, u64) {
    let mut valid = 0u32;
    let mut zero = 0u32;
    let mut invalid = 0u32;
    let mut max_idx: u64 = 0;

    for i in 0..512 {
        let off = i * 8;
        let entry = u64::from_le_bytes(page[off..off + 8].try_into().unwrap());

        if entry == 0 {
            zero += 1;
            continue;
        }

        let rwx = entry & EPT_PRESENT_MASK;
        let phys = entry & EPT_ADDR_MASK;

        // Valid EPT entry: has at least one RWX bit and points within L1 memory
        if rwx != 0 && phys < l1_size && phys != 0 {
            valid += 1;
            max_idx = i as u64;
        } else {
            invalid += 1;
        }
    }

    (valid, zero, invalid, max_idx)
}

/// Count roughly how many pages are mapped by this EPT PML4.
/// Only walks 2 levels deep for speed (PML4 → PDPT).
fn count_ept_mapped_pages<P: PhysicalMemory>(l1: &P, pml4_addr: u64, l1_size: u64) -> u64 {
    let mut total_pages: u64 = 0;
    let mut pml4_buf = [0u8; PAGE_SIZE as usize];

    if l1.read_phys(pml4_addr, &mut pml4_buf).is_err() {
        return 0;
    }

    for i in 0..512u64 {
        let pml4e = u64::from_le_bytes(pml4_buf[(i * 8) as usize..(i * 8 + 8) as usize].try_into().unwrap());
        if pml4e & EPT_PRESENT_MASK == 0 {
            continue;
        }

        let pdpt_addr = pml4e & EPT_ADDR_MASK;
        if pdpt_addr >= l1_size {
            continue;
        }

        let mut pdpt_buf = [0u8; PAGE_SIZE as usize];
        if l1.read_phys(pdpt_addr, &mut pdpt_buf).is_err() {
            continue;
        }

        for j in 0..512u64 {
            let pdpte = u64::from_le_bytes(
                pdpt_buf[(j * 8) as usize..(j * 8 + 8) as usize].try_into().unwrap(),
            );
            if pdpte & EPT_PRESENT_MASK == 0 {
                continue;
            }

            // 1GB large page
            if pdpte & EPT_LARGE_PAGE != 0 {
                total_pages += 262144; // 1GB / 4KB
                continue;
            }

            let pd_addr = pdpte & EPT_ADDR_MASK;
            if pd_addr >= l1_size {
                continue;
            }

            // Count PD entries (don't go to PT level for speed)
            let mut pd_buf = [0u8; PAGE_SIZE as usize];
            if l1.read_phys(pd_addr, &mut pd_buf).is_err() {
                continue;
            }

            for k in 0..512u64 {
                let pde = u64::from_le_bytes(
                    pd_buf[(k * 8) as usize..(k * 8 + 8) as usize].try_into().unwrap(),
                );
                if pde & EPT_PRESENT_MASK == 0 {
                    continue;
                }
                if pde & EPT_LARGE_PAGE != 0 {
                    total_pages += 512; // 2MB / 4KB
                } else {
                    // Assume ~256 out of 512 PT entries are valid on average
                    total_pages += 256;
                }
            }
        }
    }

    total_pages
}
