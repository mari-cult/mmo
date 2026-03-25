#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

extern crate alloc;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("This kernel only supports x86_64");

pub mod allocator;
pub mod gdt;
pub mod idt;
pub mod paging;
pub mod process;
pub mod serial;
pub mod syscall;
pub mod zram;
pub mod apic;

use core::{arch::asm, panic::PanicInfo};
use limine::request::{HhdmRequest, MemoryMapRequest};

#[used]
#[unsafe(link_section = ".requests")]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

#[used]
#[unsafe(link_section = ".requests")]
static MEMORY_MAP_REQUEST: MemoryMapRequest = MemoryMapRequest::new();

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    loop {}
}

#[uefi::entry]
fn efi_main(
    handle: uefi::Handle,
    system_table: uefi::table::SystemTable<uefi::table::Boot>,
) -> uefi::Status {
    uefi::helpers::init().unwrap();
    println!("LINUX-LIKE KERNEL: Booted via EFI STUB!");

    // Allocate a heap from UEFI
    let heap_pages = (allocator::HEAP_SIZE + 4095) / 4096;
    let heap_ptr = system_table
        .boot_services()
        .allocate_pages(
            uefi::table::boot::AllocateType::AnyPages,
            uefi::table::boot::MemoryType::LOADER_DATA,
            heap_pages,
        )
        .expect("Failed to allocate heap pages from UEFI");

    unsafe {
        allocator::ALLOCATOR
            .lock()
            .init(heap_ptr as *mut u8, allocator::HEAP_SIZE);
    }

    println!(
        "LINUX-LIKE KERNEL: Heap initialized via UEFI at {:p}",
        heap_ptr as *const u8
    );

    // Exit UEFI boot services
    unsafe {
        let _ = uefi::boot::exit_boot_services(uefi::table::boot::MemoryType::LOADER_DATA);
    }

    // Transition to the kernel
    println!("Transitioning to kernel..."); // This might not work if UEFI console is gone
    
    kernel_main()
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main() -> ! {
    unsafe {
        asm!("cli");
    }
    println!("LINUX-LIKE KERNEL: Initializing (CPU INTERRUPTS DISABLED)...");

    gdt::init();
    idt::init();
    apic::init();
    println!("LINUX-LIKE KERNEL: GDT/IDT/APIC initialized.");

    if let Some(hhdm) = HHDM_REQUEST.get_response() {
        let physical_memory_offset = x86_64::VirtAddr::new(hhdm.offset());
        let mut mapper = unsafe { paging::init(physical_memory_offset) };
        if let Some(mmap) = MEMORY_MAP_REQUEST.get_response() {
            let mut frame_allocator = allocator::BootInfoFrameAllocator::init_from_limine(mmap);
            allocator::init_heap(&mut mapper, &mut frame_allocator)
                .expect("Heap initialization failed");
        }
    } else {
        println!(
            "LINUX-LIKE KERNEL: No Limine response. Continuing with UEFI stub initialization..."
        );
    }

    println!("LINUX-LIKE KERNEL: Heap initialized.");

    syscall::init();
    println!("LINUX-LIKE KERNEL: Syscalls initialized.");

    // Create test tasks
    let task1 = process::Task::new(1, 0, test_task_1);
    let task2 = process::Task::new(2, 0, test_task_2);

    process::SCHEDULER.lock().add_task(task1);
    process::SCHEDULER.lock().add_task(task2);

    println!("LINUX-LIKE KERNEL: Starting scheduler...");
    crate::process::SCHEDULER.lock().schedule();

    crate::apic::complete_interrupt();
    // Demo: Compressed Storage
    let original = b"This is a long string that will be compressed using lz4_flex in our kernel's zram-like storage system.";
    let compressed = zram::CompressedStorage::new(original);
    println!(
        "LINUX-LIKE KERNEL: Compressed {} bytes to {} bytes",
        original.len(),
        compressed.size()
    );
    let decompressed = compressed.decompress();
    assert_eq!(original.as_slice(), decompressed.as_slice());
    println!("LINUX-LIKE KERNEL: Decompression successful!");

    loop {
        unsafe {
            asm!("hlt");
        }
    }
}

pub extern "C" fn test_task_1() -> ! {
    loop {
        println!("TASK 1: Working...");
        for _ in 0..1000000 {
            unsafe {
                asm!("nop");
            }
        }
    }
}

pub extern "C" fn test_task_2() -> ! {
    loop {
        println!("TASK 2: Working...");
        for _ in 0..1000000 {
            unsafe {
                asm!("nop");
            }
        }
    }
}
