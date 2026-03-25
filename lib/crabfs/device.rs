use crate::error::DeviceError;

pub trait BlockDevice {
    /// Read data from the device at the specified offset.
    ///
    /// # Errors
    ///
    /// * `DeviceError::Io` - If an I/O error occurs.
    /// * `DeviceError::ShortRead` - If the read operation does not read the expected number of bytes.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), DeviceError>;

    /// Write data to the device at the specified offset.
    ///
    /// # Errors
    ///
    /// * `DeviceError::Io` - If an I/O error occurs.
    /// * `DeviceError::ShortWrite` - If the write operation does not write the expected number of bytes.
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<(), DeviceError>;
}

#[cfg(feature = "std")]
pub struct StdFileDevice {
    file: std::fs::File,
}

#[cfg(feature = "std")]
impl StdFileDevice {
    /// Open an existing file for reading and writing.
    ///
    /// # Errors
    ///
    /// * `DeviceError::Io` - If an I/O error occurs.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, DeviceError> {
        let file = std::fs::File::open(path).map_err(|_| DeviceError::Io)?;
        Ok(Self { file })
    }

    /// Create a new file for reading and writing.
    ///
    /// # Errors
    ///
    /// * `DeviceError::Io` - If an I/O error occurs.
    pub fn create(path: impl AsRef<std::path::Path>) -> Result<Self, DeviceError> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|_| DeviceError::Io)?;
        Ok(Self { file })
    }

    /// Resize the backing file.
    ///
    /// # Errors
    ///
    /// * `DeviceError::Io` - If an I/O error occurs.
    pub fn set_len(&mut self, len: u64) -> Result<(), DeviceError> {
        self.file.set_len(len).map_err(|_| DeviceError::Io)
    }
}

#[cfg(feature = "std")]
impl BlockDevice for StdFileDevice {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), DeviceError> {
        use std::io::Read;
        use std::io::Seek;
        use std::io::SeekFrom;

        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|_| DeviceError::Io)?;
        let mut read_total = 0usize;
        while read_total < buf.len() {
            let n = self
                .file
                .read(&mut buf[read_total..])
                .map_err(|_| DeviceError::Io)?;
            if n == 0 {
                return Err(DeviceError::ShortRead {
                    expected: buf.len(),
                    actual: read_total,
                });
            }
            read_total += n;
        }
        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<(), DeviceError> {
        use std::io::Seek;
        use std::io::SeekFrom;
        use std::io::Write;

        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|_| DeviceError::Io)?;
        let mut write_total = 0usize;
        while write_total < buf.len() {
            let n = self
                .file
                .write(&buf[write_total..])
                .map_err(|_| DeviceError::Io)?;
            if n == 0 {
                return Err(DeviceError::ShortWrite {
                    expected: buf.len(),
                    actual: write_total,
                });
            }
            write_total += n;
        }
        Ok(())
    }
}
