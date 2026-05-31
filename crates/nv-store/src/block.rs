//! Block device abstraction for platform-independent NV storage.
//!
//! On Linux/QEMU: file-backed I/O for testing.  On QNX: raw partition
//! I/O for production.

pub trait BlockDevice {
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<usize, BlockError>;
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), BlockError>;
    fn sync(&mut self) -> Result<(), BlockError>;
    fn size(&self) -> u64;
}

#[derive(Debug)]
pub enum BlockError {
    Io(std::io::Error),
    OutOfBounds { offset: u64, len: usize, size: u64 },
}

impl From<std::io::Error> for BlockError {
    fn from(e: std::io::Error) -> Self {
        BlockError::Io(e)
    }
}

impl std::fmt::Display for BlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockError::Io(e) => write!(f, "I/O error: {e}"),
            BlockError::OutOfBounds { offset, len, size } => {
                write!(f, "access at {offset}+{len} exceeds device size {size}")
            }
        }
    }
}

impl std::error::Error for BlockError {}

/// In-memory block device for testing. No filesystem needed.
pub struct MemBlockDevice {
    data: Vec<u8>,
}

impl MemBlockDevice {
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
        }
    }

    pub fn raw(&self) -> &[u8] {
        &self.data
    }
}

impl BlockDevice for MemBlockDevice {
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<usize, BlockError> {
        let off = offset as usize;
        let len = buf.len();
        if off + len > self.data.len() {
            return Err(BlockError::OutOfBounds {
                offset,
                len,
                size: self.data.len() as u64,
            });
        }
        buf.copy_from_slice(&self.data[off..off + len]);
        Ok(len)
    }

    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), BlockError> {
        let off = offset as usize;
        let len = data.len();
        if off + len > self.data.len() {
            return Err(BlockError::OutOfBounds {
                offset,
                len,
                size: self.data.len() as u64,
            });
        }
        self.data[off..off + len].copy_from_slice(data);
        Ok(())
    }

    fn sync(&mut self) -> Result<(), BlockError> {
        Ok(())
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

/// File-backed block device for Linux testing.
pub struct FileBlockDevice {
    file: std::fs::File,
    size: u64,
}

impl FileBlockDevice {
    pub fn open(path: &std::path::Path) -> Result<Self, BlockError> {
        use std::io::Seek;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        let size = file.seek(std::io::SeekFrom::End(0))?;
        Ok(Self { file, size })
    }

    pub fn create(path: &std::path::Path, size: u64) -> Result<Self, BlockError> {
        use std::io::{Seek, Write};
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.set_len(size)?;
        // QNX qnx6's ftruncate(grow) is a silent no-op — set_len returns OK
        // but the file stays 0 bytes, and the next read/write OutOfBounds.
        // Force the file to actually be `size` bytes by writing a sentinel
        // zero at the last position; sparse holes between are filled on
        // demand by any FS that supports them.
        if size > 0 {
            file.seek(std::io::SeekFrom::Start(size - 1))?;
            file.write_all(&[0])?;
            file.flush()?;
        }
        Ok(Self { file, size })
    }
}

impl BlockDevice for FileBlockDevice {
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<usize, BlockError> {
        use std::io::{Read, Seek};
        if offset + buf.len() as u64 > self.size {
            return Err(BlockError::OutOfBounds {
                offset,
                len: buf.len(),
                size: self.size,
            });
        }
        let mut file = &self.file;
        file.seek(std::io::SeekFrom::Start(offset))?;
        let n = file.read(buf)?;
        Ok(n)
    }

    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), BlockError> {
        use std::io::{Seek, Write};
        if offset + data.len() as u64 > self.size {
            return Err(BlockError::OutOfBounds {
                offset,
                len: data.len(),
                size: self.size,
            });
        }
        self.file.seek(std::io::SeekFrom::Start(offset))?;
        self.file.write_all(data)?;
        Ok(())
    }

    fn sync(&mut self) -> Result<(), BlockError> {
        self.file.sync_all()?;
        Ok(())
    }

    fn size(&self) -> u64 {
        self.size
    }
}
