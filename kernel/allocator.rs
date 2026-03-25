extern crate alloc;

use crate::paging;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use limine::request::MemoryMapRequest;
use spin::{Lazy, Mutex};
use x86_64::structures::paging::{
    FrameAllocator, Mapper as _, OffsetPageTable, Page, PageSize, PageTableFlags, PhysFrame,
    Size4KiB,
    mapper::{MapToError, UnmapError},
};
use x86_64::{PhysAddr, VirtAddr};

pub struct BootInfoFrameAllocator {
    memory_map: &'static [&'static limine::memory_map::Entry],
    next: usize,
    recycled: Vec<PhysFrame>,
}

impl BootInfoFrameAllocator {
    pub unsafe fn init(memory_map: &'static MemoryMapRequest) -> Self {
        let response = memory_map.get_response().unwrap();
        Self::init_from_limine(response)
    }

    pub fn init_from_limine(response: &'static limine::response::MemoryMapResponse) -> Self {
        BootInfoFrameAllocator {
            memory_map: response.entries(),
            next: 0,
            recycled: Vec::new(),
        }
    }

    fn usable_frames(&self) -> impl Iterator<Item = PhysFrame> {
        self.memory_map
            .into_iter()
            .filter(|r| unsafe {
                core::mem::transmute::<limine::memory_map::EntryType, u64>(r.entry_type) == 0
            })
            .map(|r| r.base..r.base + r.length)
            .flat_map(|r| r.step_by(4096))
            .map(|addr| PhysFrame::containing_address(PhysAddr::new(addr)))
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        if let Some(frame) = self.recycled.pop() {
            return Some(frame);
        }
        let frame = self.usable_frames().nth(self.next);
        self.next += 1;
        frame
    }
}

pub const HEAP_START: usize = 0x_4444_4444_0000;
pub const HEAP_SIZE: usize = 1024 * 1024; // 1 MiB

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmError {
    RuntimeNotInitialized,
    FrameAllocationFailed,
    PageAlreadyMapped,
    ParentEntryHugePage,
    PageNotMapped,
}

pub fn init_heap(
    mapper: &mut OffsetPageTable,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), MapToError<Size4KiB>> {
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
            .ok_use(x86_64::structures::paging::mapper::MapToError::FrameAllocationFailed)?;
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

use linked_list_allocator::LockedHeap;

#[global_allocator]
pub static ALLOCATOR: LockedHeap = LockedHeap::empty();

static PHYSICAL_MEMORY_OFFSET: AtomicU64 = AtomicU64::new(0);
pub static FRAME_ALLOCATOR: Lazy<Mutex<Option<BootInfoFrameAllocator>>> =
    Lazy::new(|| Mutex::new(None));

pub fn init_runtime(physical_memory_offset: VirtAddr, frame_allocator: BootInfoFrameAllocator) {
    PHYSICAL_MEMORY_OFFSET.store(physical_memory_offset.as_u64(), Ordering::SeqCst);
    *FRAME_ALLOCATOR.lock() = Some(frame_allocator);
}

pub fn runtime_ready() -> bool {
    PHYSICAL_MEMORY_OFFSET.load(Ordering::SeqCst) != 0
}

pub fn allocate_and_map_page(
    page: Page<Size4KiB>,
    flags: PageTableFlags,
) -> Result<PhysFrame<Size4KiB>, VmError> {
    let frame = loop {
        if let Some(frame) = try_allocate_frame()? {
            break frame;
        }

        let reclaimed = crate::reclaim::reclaim_one().map_err(|err| match err {
            crate::reclaim::ReclaimError::Vm(vm) => vm,
            _ => VmError::FrameAllocationFailed,
        })?;
        if !reclaimed {
            return Err(VmError::FrameAllocationFailed);
        }
    };

    map_existing_page(page, frame, flags)?;
    Ok(frame)
}

pub fn map_existing_page(
    page: Page<Size4KiB>,
    frame: PhysFrame<Size4KiB>,
    flags: PageTableFlags,
) -> Result<(), VmError> {
    with_runtime(|mapper, frame_allocator| {
        unsafe {
            mapper
                .map_to(page, frame, flags, frame_allocator)
                .map_err(map_error_to_vm)?
                .flush();
        }
        Ok(())
    })
}

pub fn unmap_page(page: Page<Size4KiB>) -> Result<PhysFrame<Size4KiB>, VmError> {
    with_runtime(|mapper, _frame_allocator| {
        let (frame, flush) = mapper.unmap(page).map_err(unmap_error_to_vm)?;
        flush.flush();
        Ok(frame)
    })
}

pub fn deallocate_frame(frame: PhysFrame<Size4KiB>) -> Result<(), VmError> {
    let mut guard = FRAME_ALLOCATOR.lock();
    let frame_allocator = guard.as_mut().ok_or(VmError::RuntimeNotInitialized)?;
    frame_allocator.recycled.push(frame);
    Ok(())
}

pub fn zero_page(page: Page<Size4KiB>) {
    unsafe {
        core::ptr::write_bytes(
            page.start_address().as_mut_ptr::<u8>(),
            0,
            Size4KiB::SIZE as usize,
        );
    }
}

pub fn physical_memory_offset() -> Result<VirtAddr, VmError> {
    let offset = PHYSICAL_MEMORY_OFFSET.load(Ordering::SeqCst);
    if offset == 0 {
        Err(VmError::RuntimeNotInitialized)
    } else {
        Ok(VirtAddr::new(offset))
    }
}

fn with_runtime<T>(
    f: impl FnOnce(&mut OffsetPageTable, &mut BootInfoFrameAllocator) -> Result<T, VmError>,
) -> Result<T, VmError> {
    let offset = physical_memory_offset()?;
    let mut guard = FRAME_ALLOCATOR.lock();
    let frame_allocator = guard.as_mut().ok_or(VmError::RuntimeNotInitialized)?;
    let mut mapper = unsafe { paging::init(offset) };
    f(&mut mapper, frame_allocator)
}

fn try_allocate_frame() -> Result<Option<PhysFrame<Size4KiB>>, VmError> {
    let mut guard = FRAME_ALLOCATOR.lock();
    let frame_allocator = guard.as_mut().ok_or(VmError::RuntimeNotInitialized)?;
    Ok(frame_allocator.allocate_frame())
}

fn map_error_to_vm(err: MapToError<Size4KiB>) -> VmError {
    match err {
        MapToError::FrameAllocationFailed => VmError::FrameAllocationFailed,
        MapToError::ParentEntryHugePage => VmError::ParentEntryHugePage,
        MapToError::PageAlreadyMapped(_) => VmError::PageAlreadyMapped,
    }
}

fn unmap_error_to_vm(err: UnmapError) -> VmError {
    match err {
        UnmapError::ParentEntryHugePage => VmError::ParentEntryHugePage,
        UnmapError::PageNotMapped => VmError::PageNotMapped,
        UnmapError::InvalidFrameAddress(_) => VmError::PageNotMapped,
    }
}

trait OptionExt<T> {
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
