use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{GovmemError, Result};

/// Raw flat disk image — no container format, just raw sectors.
/// Handles flat VMDKs (`-flat.vmdk`), raw dumps (`.raw`, `.img`, `.dd`).
pub struct RawDisk {
    file: File,
    size: u64,
}

impl RawDisk {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).map_err(GovmemError::Io)?;
        let size = file.metadata().map_err(GovmemError::Io)?.len();
        log::info!(
            "Raw disk: {} ({} MB)",
            path.file_name().unwrap_or_default().to_string_lossy(),
            size / (1024 * 1024)
        );
        Ok(Self { file, size })
    }
}

impl Read for RawDisk {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

impl Seek for RawDisk {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.file.seek(pos)
    }
}

impl super::DiskImage for RawDisk {
    fn disk_size(&self) -> u64 {
        self.size
    }
}
