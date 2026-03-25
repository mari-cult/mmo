extern crate alloc;
use alloc::vec::Vec;
use lz4_flex::block::{compress_prepend_size, decompress_size_prepended};

pub struct CompressedStorage {
    data: Vec<u8>,
}

impl CompressedStorage {
    pub fn new(input: &[u8]) -> Self {
        let compressed = compress_prepend_size(input);
        Self { data: compressed }
    }

    pub fn decompress(&self) -> Vec<u8> {
        decompress_size_prepended(&self.data).expect("Decompression failed")
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }
}
