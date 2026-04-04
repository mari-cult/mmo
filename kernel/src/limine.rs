use limine_sys::*;

#[repr(C)]
pub struct Request<T> {
    id: [u64; 4],
    revision: u64,
    response: *mut T,
}

impl<T> Request<T> {
    pub const fn new(id: [u64; 4]) -> Self {
        Self {
            id,
            revision: 0,
            response: core::ptr::null_mut(),
        }
    }

    pub fn response(&self) -> Option<&'static T> {
        unsafe { self.response.as_ref() }
    }
}

unsafe impl<T> Sync for Request<T> {}


pub const COMMON_MAGIC: [u64; 2] = [0xc7b1dd30df4c8b88, 0x0a82e883a194f07b];

pub const HHDM_REQUEST_ID: [u64; 4] = [
    COMMON_MAGIC[0],
    COMMON_MAGIC[1],
    0x48dcf1cb8ad2b852,
    0x63984e959a98244b,
];

pub const MEMMAP_REQUEST_ID: [u64; 4] = [
    COMMON_MAGIC[0],
    COMMON_MAGIC[1],
    0x67cf3d9d378a806f,
    0xe304acdfc50c3c62,
];

pub const EXECUTABLE_CMDLINE_REQUEST_ID: [u64; 4] = [
    COMMON_MAGIC[0],
    COMMON_MAGIC[1],
    0x4b161536e598651e,
    0xb390ad4a2f1f303a,
];

pub const MP_REQUEST_ID: [u64; 4] = [
    COMMON_MAGIC[0],
    COMMON_MAGIC[1],
    0x95a67b819a1b857e,
    0xa0b61b723b6a73e0,
];

pub const BASE_REVISION_ID: [u64; 3] = [0xf9562b2d5c95a6c8, 0x6a7b384944536bdc, 0];

#[used]
#[unsafe(link_section = ".limine_requests_start_marker")]
static REQUESTS_START_MARKER: [u64; 4] =
    [0xf6b8f4b39de7d1ae, 0xfab91a6940fcb9cf, 0x785c6ed015d3e316, 0x181e920a7852b9d9];

#[used]
#[unsafe(link_section = ".limine_requests_end_marker")]
static REQUESTS_END_MARKER: [u64; 2] = [0xadc0e0531bb10d03, 0x9572709f31764c62];

#[used]
#[unsafe(link_section = ".limine_requests")]
pub static BASE_REVISION: [u64; 3] = [0xf9562b2d5c95a6c8, 0x6a7b384944536bdc, 2];

pub fn base_revision_supported() -> bool {
    BASE_REVISION[2] == 0
}

pub const LIMINE_MEMMAP_USABLE: u32 = 0;
pub const LIMINE_MEMMAP_RESERVED: u32 = 1;
pub const LIMINE_MEMMAP_ACPI_RECLAIMABLE: u32 = 2;
pub const LIMINE_MEMMAP_ACPI_NVS: u32 = 3;
pub const LIMINE_MEMMAP_BAD_MEMORY: u32 = 4;
pub const LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE: u32 = 5;
pub const LIMINE_MEMMAP_EXECUTABLE_AND_MODULES: u32 = 6;
pub const LIMINE_MEMMAP_FRAMEBUFFER: u32 = 7;
pub const LIMINE_MEMMAP_RESERVED_MAPPED: u32 = 8;

