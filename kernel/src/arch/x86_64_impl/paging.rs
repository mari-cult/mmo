use x86_64::VirtAddr;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{OffsetPageTable, PageTable, PhysFrame};

/// Initialize a new OffsetPageTable.
///
/// This function is unsafe because the caller must guarantee that the
/// complete physical memory is mapped to virtual memory at the passed
/// `physical_memory_offset`. Also, this function must be only called once
/// to avoid aliasing `&mut` references (which is undefined behavior).
pub unsafe fn init(physical_memory_offset: VirtAddr) -> OffsetPageTable<'static> {
    let (level_4_table_frame, _) = Cr3::read();
    unsafe { init_for_frame(physical_memory_offset, level_4_table_frame) }
}

/// Initialize an OffsetPageTable for a specific level-4 frame.
///
/// This function is unsafe because the caller must guarantee that the
/// referenced page table frame is valid and reachable through the HHDM.
pub unsafe fn init_for_frame(
    physical_memory_offset: VirtAddr,
    level_4_table_frame: PhysFrame,
) -> OffsetPageTable<'static> {
    let phys = level_4_table_frame.start_address();
    let virt = physical_memory_offset + phys.as_u64();
    let page_table_ptr: *mut PageTable = virt.as_mut_ptr();

    unsafe { OffsetPageTable::new(&mut *page_table_ptr, physical_memory_offset) }
}

pub unsafe fn copy_kernel_mappings(new_table: &mut PageTable, current_table: &PageTable) {
    let mut current_rsp = 0usize;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) current_rsp, options(nomem, preserves_flags, nostack));
    }

    for idx in 256..512 {
        new_table[idx] = current_table[idx].clone();
    }

    // Special case for some bootstrap regions if they are in the lower half
    // but needed for the transition.
    for virt in [
        crate::allocator::HEAP_START as u64,
        0x0000_6666_0000_0000, // KERNEL_VIRTIO_DMA_BASE
        current_rsp as u64,
    ] {
        let idx = ((virt >> 39) & 0x1ff) as usize;
        if idx < 256 {
            new_table[idx] = current_table[idx].clone();
        }
    }
}

pub unsafe fn switch_to(root_frame: PhysFrame) {
    let (_, flags) = Cr3::read();
    unsafe {
        Cr3::write(root_frame, flags);
    }
}
