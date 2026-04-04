extern crate alloc;

use crate::arch::{
    FlagUpdateError, FrameAllocator, MapToError, Mapper as _, OffsetPageTable, Page, PageSize,
    PageTableFlags, PhysAddr, PhysFrame, Size4KiB, UnmapError, VirtAddr,
};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use limine_sys::*;
use crate::limine::{Request, MEMMAP_REQUEST_ID};
use spin::{Lazy, Mutex};

pub struct BootInfoFrameAllocator {
    memory_map: &'static [&'static limine_memmap_entry],
    recycled: Vec<PhysFrame>,
    current_entry: usize,
    current_addr: u64,
}

impl BootInfoFrameAllocator {
    pub unsafe fn init(memory_map: &'static Request<limine_memmap_response>) -> Self {
        let response = memory_map.response().unwrap();
        Self::init_from_limine(response)
    }

    pub fn init_from_limine(response: &'static limine_memmap_response) -> Self {
        let entries = unsafe {
            core::slice::from_raw_parts(response.entries as *const &limine_memmap_entry, response.entry_count as usize)
        };
        BootInfoFrameAllocator {
            memory_map: entries,
            recycled: Vec::new(),
            current_entry: 0,
            current_addr: 0,
        }
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        if let Some(frame) = self.recycled.pop() {
            return Some(frame);
        }
        while self.current_entry < self.memory_map.len() {
            let entry = self.memory_map[self.current_entry];
            let usable = entry.type_ == crate::limine::LIMINE_MEMMAP_USABLE as u64;
            if !usable {
                self.current_entry += 1;
                self.current_addr = 0;
                continue;
            }

            let start = entry.base;
            let end = entry.base + entry.length;

            if self.current_addr == 0 {
                self.current_addr = start;
            }
            let addr = self.current_addr;
            if addr + 4096 <= end {
                self.current_addr += 4096;
                return Some(PhysFrame::containing_address(PhysAddr::new(addr)));
            } else {
                self.current_entry += 1;
                self.current_addr = 0;
            }
        }
        None
    }
}

pub fn deallocate_frame(frame: PhysFrame) -> Result<(), VmError> {
    FRAME_ALLOCATOR.lock().as_mut().unwrap().recycled.push(frame);
    Ok(())
}

pub const HEAP_START: usize = 0x_4444_4444_0000;
pub const HEAP_SIZE: usize = 100 * 1024 * 1024; // 100 MiB

#[global_allocator]
pub static ALLOCATOR: linked_list_allocator::LockedHeap =
    linked_list_allocator::LockedHeap::empty();

static FRAME_ALLOCATOR: Mutex<Option<BootInfoFrameAllocator>> = Mutex::new(None);
static PHYSICAL_MEMORY_OFFSET: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmError {
    FrameAllocationFailed,
    MapToFailed,
    UnmapFailed,
    FlagUpdateFailed,
    RuntimeNotInitialized,
    InvalidPage,
    PageNotMapped,
    ParentEntryHugePage,
    PageAlreadyMapped,
}

impl From<MapToError<Size4KiB>> for VmError {
    fn from(_: MapToError<Size4KiB>) -> Self {
        Self::MapToFailed
    }
}

impl From<UnmapError> for VmError {
    fn from(_: UnmapError) -> Self {
        Self::UnmapFailed
    }
}

impl From<FlagUpdateError> for VmError {
    fn from(_: FlagUpdateError) -> Self {
        Self::FlagUpdateFailed
    }
}

pub fn init_heap(
    hhdm_offset: u64,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), MapToError<Size4KiB>> {
    let mut mapper = unsafe { crate::arch::paging::init(VirtAddr::new(hhdm_offset)) };
    let page_range = {
        let heap_start = VirtAddr::new(HEAP_START as u64);
        let heap_end = heap_start + HEAP_SIZE as u64 - 1u64;
        let heap_start_page = Page::containing_address(heap_start);
        let heap_end_page = Page::containing_address(heap_end);
        Page::range_inclusive(heap_start_page, heap_end_page)
    };

    for page in page_range {
        let frame = frame_allocator
            .allocate_frame()
            .ok_use(MapToError::FrameAllocationFailed)?;
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        unsafe {
            mapper.map_to(page, frame, flags, frame_allocator)?.flush();
        }
    }

    unsafe {
        ALLOCATOR.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }

    Ok(())
}

pub fn init_runtime(physical_memory_offset: VirtAddr, frame_allocator: BootInfoFrameAllocator) {
    PHYSICAL_MEMORY_OFFSET.store(physical_memory_offset.as_u64(), Ordering::SeqCst);
    *FRAME_ALLOCATOR.lock() = Some(frame_allocator);
}

pub fn physical_memory_offset() -> Result<VirtAddr, VmError> {
    match PHYSICAL_MEMORY_OFFSET.load(Ordering::SeqCst) {
        0 => Err(VmError::RuntimeNotInitialized),
        offset => Ok(VirtAddr::new(offset)),
    }
}

pub fn allocate_frame() -> Result<PhysFrame<Size4KiB>, VmError> {
    try_allocate_frame()?.ok_or(VmError::FrameAllocationFailed)
}

pub fn allocate_and_map_page(page: Page<Size4KiB>, flags: PageTableFlags) -> Result<PhysFrame<Size4KiB>, VmError> {
    let frame = allocate_frame()?;
    with_runtime(|mapper, frame_allocator| {
        unsafe {
            mapper.map_to(page, frame, flags, frame_allocator)?.flush();
        }
        Ok(())
    })?;
    Ok(frame)
}

pub fn unmap_page(page: Page<Size4KiB>) -> Result<PhysFrame<Size4KiB>, VmError> {
    with_runtime(|mapper, _| {
        let (frame, flush) = mapper.unmap(page)?;
        flush.flush();
        Ok(frame)
    })
}

pub fn runtime_ready() -> bool {
    PHYSICAL_MEMORY_OFFSET.load(Ordering::SeqCst) != 0
}

pub fn map_existing_page(page: Page<Size4KiB>, frame: PhysFrame<Size4KiB>, flags: PageTableFlags) -> Result<(), VmError> {
    with_runtime(|mapper, frame_allocator| {
        unsafe {
            mapper.map_to(page, frame, flags, frame_allocator)?.flush();
        }
        Ok(())
    })
}

pub fn map_existing_page_in(root_frame: PhysFrame<Size4KiB>, page: Page<Size4KiB>, frame: PhysFrame<Size4KiB>, flags: PageTableFlags) -> Result<(), VmError> {
    with_runtime_in(root_frame, |mapper, frame_allocator| {
        unsafe {
            mapper.map_to(page, frame, flags, frame_allocator)?.flush();
        }
        Ok(())
    })
}

pub fn unmap_page_in(root_frame: PhysFrame<Size4KiB>, page: Page<Size4KiB>) -> Result<PhysFrame<Size4KiB>, VmError> {
    with_runtime_in(root_frame, |mapper, _| {
        let (frame, flush) = mapper.unmap(page)?;
        flush.flush();
        Ok(frame)
    })
}

pub fn update_page_flags_in(root_frame: PhysFrame<Size4KiB>, page: Page<Size4KiB>, flags: PageTableFlags) -> Result<(), VmError> {
    with_runtime_in(root_frame, |mapper, _| {
        let flush = unsafe { mapper.update_flags(page, flags)? };
        flush.flush();
        Ok(())
    })
}

pub fn zero_page(page: Page<Size4KiB>) {
    unsafe {
        core::ptr::write_bytes(page.start_address().as_mut_ptr::<u8>(), 0, 4096);
    }
}

pub fn zero_frame(frame: PhysFrame<Size4KiB>) -> Result<(), VmError> {
    let offset = physical_memory_offset()?;
    let virt = offset + frame.start_address().as_u64();
    unsafe {
        core::ptr::write_bytes(virt.as_mut_ptr::<u8>(), 0, 4096);
    }
    Ok(())
}

fn with_runtime<T>(
    f: impl FnOnce(&mut OffsetPageTable, &mut BootInfoFrameAllocator) -> Result<T, VmError>,
) -> Result<T, VmError> {
    let offset = physical_memory_offset()?;
    let root_frame = crate::arch::get_current_paging_root();
    with_runtime_in_with_offset(root_frame, offset, f)
}

fn with_runtime_in<T>(
    root_frame: PhysFrame<Size4KiB>,
    f: impl FnOnce(&mut OffsetPageTable, &mut BootInfoFrameAllocator) -> Result<T, VmError>,
) -> Result<T, VmError> {
    let offset = physical_memory_offset()?;
    with_runtime_in_with_offset(root_frame, offset, f)
}

fn with_runtime_in_with_offset<T>(
    root_frame: PhysFrame<Size4KiB>,
    offset: VirtAddr,
    f: impl FnOnce(&mut OffsetPageTable, &mut BootInfoFrameAllocator) -> Result<T, VmError>,
) -> Result<T, VmError> {
    let mut guard = FRAME_ALLOCATOR.lock();
    let frame_allocator = guard.as_mut().ok_or(VmError::RuntimeNotInitialized)?;
    let mut mapper = unsafe { crate::arch::paging::init_for_frame(offset, root_frame) };
    f(&mut mapper, frame_allocator)
}

fn try_allocate_frame() -> Result<Option<PhysFrame<Size4KiB>>, VmError> {
    let mut guard = FRAME_ALLOCATOR.lock();
    let frame_allocator = guard.as_mut().ok_or(VmError::RuntimeNotInitialized)?;
    Ok(frame_allocator.allocate_frame())
}

pub trait OptionExt<T> {
    fn ok_use<E>(self, err: E) -> Result<T, E>;
}

impl<T> OptionExt<T> for Option<T> {
    fn ok_use<E>(self, err: E) -> Result<T, E> {
        match self {
            Some(x) => Ok(x),
            None => Err(err),
        }
    }
}
