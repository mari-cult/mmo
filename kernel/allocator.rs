use limine::request::MemoryMapRequest;
use x86_64::structures::paging::{
    FrameAllocator, Mapper as _, OffsetPageTable, Page, PageTableFlags, PhysFrame, Size4KiB,
};
use x86_64::{PhysAddr, VirtAddr};

pub struct BootInfoFrameAllocator {
    memory_map: &'static [&'static limine::memory_map::Entry],
    next: usize,
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
        let frame = self.usable_frames().nth(self.next);
        self.next += 1;
        frame
    }
}

pub const HEAP_START: usize = 0x_4444_4444_0000;
pub const HEAP_SIZE: usize = 1024 * 1024; // 1 MiB

pub fn init_heap(
    mapper: &mut OffsetPageTable,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), x86_64::structures::paging::mapper::MapToError<Size4KiB>> {
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
