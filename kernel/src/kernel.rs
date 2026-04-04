#![no_std]
#![no_main]
#![feature(abi_x86_interrupt, step_trait)]

extern crate alloc;

pub mod allocator;
pub mod arch;
pub mod cmdline;
pub mod limine;
pub mod log;
pub mod process;
pub mod reclaim;
pub mod syscall;
pub mod user;
pub mod vfs;
pub mod virtio_blk;
pub mod zram;

use crate::limine::{HHDM_REQUEST_ID, MEMMAP_REQUEST_ID, Request};
use core::panic::PanicInfo;
use limine_sys::*;

#[used]
#[unsafe(link_section = ".limine_requests")]
static HHDM_REQUEST: Request<limine_hhdm_response> = Request::new(HHDM_REQUEST_ID);

#[used]
#[unsafe(link_section = ".limine_requests")]
static MEMORY_MAP_REQUEST: Request<limine_memmap_response> = Request::new(MEMMAP_REQUEST_ID);

#[used]
#[unsafe(link_section = ".limine_requests")]
static mut ENTRY_POINT_REQUEST: limine_entry_point_request = limine_entry_point_request {
    id: [
        crate::limine::COMMON_MAGIC[0],
        crate::limine::COMMON_MAGIC[1],
        0x13d86caac783f9a6,
        0x469521c291ef44d5,
    ],
    revision: 0,
    response: core::ptr::null_mut(),
    entry: unsafe { core::mem::transmute(kernel_main as *const ()) },
};

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    arch::halt()
}

#[cfg(not(target_os = "uefi"))]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    kernel_main()
}

#[cfg(target_os = "uefi")]
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
    arch::disable_interrupts();
    println!("LINUX-LIKE KERNEL: Initializing (CPU INTERRUPTS DISABLED)...");
    if crate::limine::base_revision_supported() {
        println!("LINUX-LIKE KERNEL: Limine base revision supported");
    }
    let mut _reclaim_demo_base = None;
    if let Some(hhdm) = HHDM_REQUEST.response() {
        let hhdm_offset = hhdm.offset;
        arch::init_paging(hhdm_offset);
        if let Some(mmap) = MEMORY_MAP_REQUEST.response() {
            let mut frame_allocator = allocator::BootInfoFrameAllocator::init_from_limine(mmap);
            allocator::init_heap(hhdm_offset, &mut frame_allocator)
                .expect("Heap initialization failed");
            allocator::init_runtime(arch::VirtAddr::new(hhdm_offset), frame_allocator);
            _reclaim_demo_base =
                Some(reclaim::allocate_region(3).expect("failed to allocate reclaim demo region"));
        }
    } else {
        println!(
            "LINUX-LIKE KERNEL: No Limine response. Continuing with UEFI stub initialization..."
        );
    }

    println!("LINUX-LIKE KERNEL: Heap initialized.");
    let params = cmdline::params();
    log::init(params);
    if !params.raw.is_empty() {
        kinfo!("cmdline=\"{}\"", params.raw);
    }
    kdebug!(
        "logging configured debug={} quiet={} loglevel={:?}",
        params.debug,
        params.quiet,
        params.loglevel
    );

    arch::init_hardware();
    println!("LINUX-LIKE KERNEL: GDT/IDT/APIC/Exceptions initialized.");

    let online_cpus = arch::init_smp();
    process::configure_topology(online_cpus);
    println!(
        "LINUX-LIKE KERNEL: SMP topology online_cpus={}",
        online_cpus
    );

    syscall::init();
    println!("LINUX-LIKE KERNEL: Syscalls initialized.");

    let mut init_task = None;
    match (
        cmdline::resolved_root_device(),
        cmdline::resolved_root_fstype(),
        virtio_blk::VirtioBlkDevice::probe(),
    ) {
        (Some(cmdline::RootDevice::VirtioBlk0), Some(cmdline::RootFsType::Crabfs), Ok(dev)) => {
            println!("LINUX-LIKE KERNEL: PCI found modern virtio-blk");
            match vfs::mount_root(dev) {
                Ok(()) => {
                    println!("LINUX-LIKE KERNEL: crabfs root mounted");
                    let init_path = cmdline::resolved_init_path();
                    match user::create_init_task(3, &init_path) {
                        Ok(task) => {
                            println!("LINUX-LIKE KERNEL: PID1 {} task prepared", init_path);
                            init_task = Some(task);
                        }
                        Err(err) => {
                            println!(
                                "LINUX-LIKE KERNEL: PID1 {} prepare failed: {:?}",
                                init_path, err
                            );
                        }
                    }
                }
                Err(_) => {
                    println!("LINUX-LIKE KERNEL: crabfs mount failed");
                }
            }
        }
        _ => {
            println!("LINUX-LIKE KERNEL: Root device not found or unsupported");
        }
    }

    if let Some(task) = init_task {
        process::SCHEDULER.lock().add_task(task);
        println!("LINUX-LIKE KERNEL: added PID1 userspace task");
    } else {
        let task1 = process::Task::new(1, 0, test_task_1);
        let task2 = process::Task::new(2, 0, test_task_2);

        process::SCHEDULER.lock().add_task(task1);
        process::SCHEDULER.lock().add_task(task2);
        println!("LINUX-LIKE KERNEL: using fallback kernel demo tasks");
    }

    println!("LINUX-LIKE KERNEL: Starting scheduler...");
    crate::process::start();
}

pub extern "C" fn test_task_1() -> ! {
    loop {
        println!("TASK 1: Working...");
        for _ in 0..1000000 {
            arch::nop();
        }
    }
}

pub extern "C" fn test_task_2() -> ! {
    loop {
        println!("TASK 2: Working...");
        for _ in 0..1000000 {
            arch::nop();
        }
    }
}
