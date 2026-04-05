extern crate alloc;

use crate::allocator;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::instructions::port::Port;
use x86_64::structures::paging::{Page, PageSize, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

const MMIO_BASE_START: u64 = 0xffff_fd00_0000_0000;
static NEXT_MMIO_BASE: AtomicU64 = AtomicU64::new(MMIO_BASE_START);

#[derive(Debug, Clone, Copy)]
pub struct PciAddress {
    pub bus: u8,
    pub slot: u8,
    pub function: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct PciBar {
    pub index: u8,
    pub address: u64,
    pub is_mmio: bool,
    pub is_64bit: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct PciDevice {
    pub address: PciAddress,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub bars: [Option<PciBar>; 6],
}

#[derive(Debug, Clone, Copy)]
pub struct PciCapability {
    pub id: u8,
    pub offset: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciError {
    MmioNotAvailable,
    MapFailed,
}

fn config_address(addr: PciAddress, offset: u8) -> u32 {
    0x8000_0000
        | (u32::from(addr.bus) << 16)
        | (u32::from(addr.slot) << 11)
        | (u32::from(addr.function) << 8)
        | (u32::from(offset) & 0xfc)
}

pub fn read_config_dword(addr: PciAddress, offset: u8) -> u32 {
    let mut address_port = Port::<u32>::new(PCI_CONFIG_ADDRESS);
    let mut data_port = Port::<u32>::new(PCI_CONFIG_DATA);
    unsafe {
        address_port.write(config_address(addr, offset));
        data_port.read()
    }
}

pub fn write_config_dword(addr: PciAddress, offset: u8, value: u32) {
    let mut address_port = Port::<u32>::new(PCI_CONFIG_ADDRESS);
    let mut data_port = Port::<u32>::new(PCI_CONFIG_DATA);
    unsafe {
        address_port.write(config_address(addr, offset));
        data_port.write(value);
    }
}

pub fn read_config_word(addr: PciAddress, offset: u8) -> u16 {
    let shift = u32::from((offset & 0x2) * 8);
    ((read_config_dword(addr, offset) >> shift) & 0xffff) as u16
}

pub fn read_config_byte(addr: PciAddress, offset: u8) -> u8 {
    let shift = u32::from((offset & 0x3) * 8);
    ((read_config_dword(addr, offset) >> shift) & 0xff) as u8
}

pub fn scan_bus0() -> [Option<PciDevice>; 32] {
    let mut out: [Option<PciDevice>; 32] = [None; 32];
    for slot in 0u8..32 {
        let addr0 = PciAddress {
            bus: 0,
            slot,
            function: 0,
        };
        let vendor = read_config_word(addr0, 0x00);
        if vendor == 0xffff {
            continue;
        }

        let header_type = read_config_byte(addr0, 0x0e);
        let function_count = if (header_type & 0x80) != 0 { 8 } else { 1 };
        for function in 0u8..function_count {
            let addr = PciAddress {
                bus: 0,
                slot,
                function,
            };
            let vendor_id = read_config_word(addr, 0x00);
            if vendor_id == 0xffff {
                continue;
            }
            let device_id = read_config_word(addr, 0x02);
            let class_code = read_config_byte(addr, 0x0b);
            let subclass = read_config_byte(addr, 0x0a);
            let prog_if = read_config_byte(addr, 0x09);
            let bars = parse_bars(addr);

            out[slot as usize] = Some(PciDevice {
                address: addr,
                vendor_id,
                device_id,
                class_code,
                subclass,
                prog_if,
                bars,
            });
        }
    }
    out
}

pub fn scan_devices() -> Vec<PciDevice> {
    let mut devices = Vec::new();
    for bus in 0u16..=255 {
        for slot in 0u8..32 {
            let addr0 = PciAddress {
                bus: bus as u8,
                slot,
                function: 0,
            };
            let vendor = read_config_word(addr0, 0x00);
            if vendor == 0xffff {
                continue;
            }

            let header_type = read_config_byte(addr0, 0x0e);
            let function_count = if (header_type & 0x80) != 0 { 8 } else { 1 };
            for function in 0u8..function_count {
                let addr = PciAddress {
                    bus: bus as u8,
                    slot,
                    function,
                };
                let vendor_id = read_config_word(addr, 0x00);
                if vendor_id == 0xffff {
                    continue;
                }

                let device_id = read_config_word(addr, 0x02);
                let class_code = read_config_byte(addr, 0x0b);
                let subclass = read_config_byte(addr, 0x0a);
                let prog_if = read_config_byte(addr, 0x09);
                let bars = parse_bars(addr);

                devices.push(PciDevice {
                    address: addr,
                    vendor_id,
                    device_id,
                    class_code,
                    subclass,
                    prog_if,
                    bars,
                });
            }
        }
    }
    devices
}

fn parse_bars(addr: PciAddress) -> [Option<PciBar>; 6] {
    let mut bars: [Option<PciBar>; 6] = [None; 6];
    let mut i = 0usize;
    while i < 6 {
        let off = 0x10 + (i as u8 * 4);
        let raw = read_config_dword(addr, off);
        if raw == 0 || raw == 0xffff_ffff {
            i += 1;
            continue;
        }

        let is_mmio = (raw & 1) == 0;
        let bar = if is_mmio {
            let typ = (raw >> 1) & 0x3;
            let is_64bit = typ == 0x2;
            let mut address = u64::from(raw & 0xffff_fff0);
            if is_64bit && (i + 1) < 6 {
                let high = u64::from(read_config_dword(addr, off + 4));
                address |= high << 32;
            }
            Some(PciBar {
                index: i as u8,
                address,
                is_mmio: true,
                is_64bit,
            })
        } else {
            Some(PciBar {
                index: i as u8,
                address: u64::from(raw & 0xffff_fffc),
                is_mmio: false,
                is_64bit: false,
            })
        };
        bars[i] = bar;
        if bar.is_some_and(|b| b.is_64bit) {
            i += 2;
        } else {
            i += 1;
        }
    }
    bars
}

pub fn capabilities(addr: PciAddress) -> [Option<PciCapability>; 32] {
    let mut out: [Option<PciCapability>; 32] = [None; 32];
    let status = read_config_word(addr, 0x06);
    if (status & (1 << 4)) == 0 {
        return out;
    }

    let mut ptr = read_config_byte(addr, 0x34) & 0xfc;
    let mut idx = 0usize;
    let mut guard = 0usize;
    while ptr >= 0x40 && idx < out.len() && guard < 64 {
        let cap_id = read_config_byte(addr, ptr);
        out[idx] = Some(PciCapability {
            id: cap_id,
            offset: ptr,
        });
        idx += 1;
        ptr = read_config_byte(addr, ptr + 1) & 0xfc;
        guard += 1;
    }
    out
}

pub fn map_mmio(phys_addr: u64, length: u64) -> Result<VirtAddr, PciError> {
    if !allocator::runtime_ready() {
        return Err(PciError::MmioNotAvailable);
    }

    let page_offset = phys_addr & (Size4KiB::SIZE - 1);
    let map_start_phys = phys_addr - page_offset;
    let map_len = (length + page_offset + (Size4KiB::SIZE - 1)) & !(Size4KiB::SIZE - 1);

    let virt_base = NEXT_MMIO_BASE.fetch_add(map_len, Ordering::SeqCst);
    let pages = (map_len / Size4KiB::SIZE) as usize;
    for page_idx in 0..pages {
        let virt = VirtAddr::new(virt_base + (page_idx as u64 * Size4KiB::SIZE));
        let phys = PhysAddr::new(map_start_phys + (page_idx as u64 * Size4KiB::SIZE));
        let page = Page::containing_address(virt);
        let frame = PhysFrame::containing_address(phys);
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_CACHE;
        match allocator::map_existing_page(page, frame, flags) {
            Ok(()) | Err(allocator::VmError::PageAlreadyMapped) => {}
            Err(_) => return Err(PciError::MapFailed),
        }
    }

    Ok(VirtAddr::new(virt_base + page_offset))
}
