#![no_std]

extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

pub mod crc;
pub mod device;
pub mod endian;
pub mod error;
pub mod geometry;
pub mod on_disk;
#[cfg(feature = "std")]
pub mod pack;
pub mod reader;
pub mod writer;
pub use crate::writer::{MkfsOptions, mkfs};
