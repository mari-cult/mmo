#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

extern crate alloc;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("This kernel only supports x86_64");

pub mod allocator;
pub mod apic;
pub mod cmdline;
pub mod gdt;
pub mod idt;
pub mod log;
pub mod paging;
pub mod pci;
pub mod process;
pub mod reclaim;
pub mod serial;
pub mod smp;
pub mod syscall;
pub mod user;
pub mod vfs;
pub mod virtio_blk;
pub mod zram;

use core::{arch::asm, panic::PanicInfo};
use limine::{
    BaseRevision,
    request::{
        EntryPointRequest, HhdmRequest, MemoryMapRequest, RequestsEndMarker, RequestsStartMarker,
        StackSizeRequest,
    },
};
use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};

const LIMINE_STACK_SIZE: u64 = 1024 * 1024;

#[used]
#[unsafe(link_section = ".limine_requests_start_marker")]
static REQUESTS_START_MARKER: RequestsStartMarker = RequestsStartMarker::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static BASE_REVISION: BaseRevision = BaseRevision::with_revision(6);

#[used]
#[unsafe(link_section = ".limine_requests")]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static MEMORY_MAP_REQUEST: MemoryMapRequest = MemoryMapRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static STACK_SIZE_REQUEST: StackSizeRequest = StackSizeRequest::new().with_size(LIMINE_STACK_SIZE);

#[used]
#[unsafe(link_section = ".limine_requests")]
static ENTRY_POINT_REQUEST: EntryPointRequest =
    EntryPointRequest::new().with_entry_point(kernel_main);

#[used]
#[unsafe(link_section = ".limine_requests_end_marker")]
static REQUESTS_END_MARKER: RequestsEndMarker = RequestsEndMarker::new();

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    loop {}
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
    unsafe {
        asm!("cli");
    }
    println!("LINUX-LIKE KERNEL: Initializing (CPU INTERRUPTS DISABLED)...");
    if BASE_REVISION.is_valid() {
        println!(
            "LINUX-LIKE KERNEL: Limine base revision loaded={}",
            BASE_REVISION.loaded_revision().unwrap_or(0)
        );
    }
    let mut reclaim_demo_base = None;
    if let Some(hhdm) = HHDM_REQUEST.get_response() {
        let physical_memory_offset = x86_64::VirtAddr::new(hhdm.offset());
        apic::set_hhdm_offset(physical_memory_offset);
        let mut mapper = unsafe { paging::init(physical_memory_offset) };
        if let Some(mmap) = MEMORY_MAP_REQUEST.get_response() {
            let mut frame_allocator = allocator::BootInfoFrameAllocator::init_from_limine(mmap);
            allocator::init_heap(&mut mapper, &mut frame_allocator)
                .expect("Heap initialization failed");
            allocator::init_runtime(physical_memory_offset, frame_allocator);
            reclaim_demo_base =
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

    gdt::init();
    idt::init();
    init_local_cpu_features();
    apic::init();
    println!("LINUX-LIKE KERNEL: GDT/IDT/APIC initialized.");

    let topology = smp::init();
    process::configure_topology(topology.online_cpus);
    println!(
        "LINUX-LIKE KERNEL: SMP topology online_cpus={}, discovered_cpus={}, bsp_lapic_id={}",
        topology.online_cpus, topology.discovered_cpus, topology.bootstrap_lapic_id
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
                    println!(
                        "LINUX-LIKE KERNEL: lookup libc={} readline={} ncursesw={} tinfow={}",
                        vfs::lookup("/usr/lib/libc.so").is_ok(),
                        vfs::lookup("/usr/lib/libreadline.so.8").is_ok(),
                        vfs::lookup("/usr/lib/libncursesw.so.6").is_ok(),
                        vfs::lookup("/usr/lib/libtinfow.so.6").is_ok()
                    );
                    for path in [
                        "/usr/bin/clear",
                        "/usr/bin/bash",
                        "/usr/lib/ld-musl-x86_64.so.1",
                        "/lib/ld-musl-x86_64.so.1",
                        "/usr/lib/libtinfotw.so.6",
                        "/lib/libtinfotw.so.6",
                        "/usr/lib/libc.so",
                        "/usr/lib/libreadline.so.8",
                        "/usr/lib/libncursesw.so.6",
                        "/usr/lib/libtinfow.so.6",
                    ] {
                        let _ = vfs::cache_path(path);
                        match vfs::stat_path(path, true) {
                            Ok(st) => {
                                println!(
                                    "LINUX-LIKE KERNEL: stat path={} ino={} mode={:#o} size={}",
                                    path, st.ino, st.mode, st.size
                                );
                            }
                            Err(err) => {
                                println!("LINUX-LIKE KERNEL: stat path={} err={:?}", path, err);
                            }
                        }
                    }
                    let _ = vfs::cache_missing_path("/usr/etc/ld-musl-x86_64.path");
                    if let Ok(path_bytes) = vfs::read_all("/etc/ld-musl-x86_64.path") {
                        if let Ok(path_text) = core::str::from_utf8(&path_bytes) {
                            println!("LINUX-LIKE KERNEL: ld-musl path file={:?}", path_text);
                        }
                    }
                    let init_path = cmdline::resolved_init_path();
                    user::debug_file_elf(&init_path);
                    user::debug_file_elf("/lib/ld-musl-x86_64.so.1");
                    user::debug_file_elf("/usr/lib/libtinfotw.so.6");
                    user::debug_file_elf("/lib/libtinfotw.so.6");
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
        (None, _, _) => {
            println!("LINUX-LIKE KERNEL: unsupported root= parameter");
        }
        (_, None, _) => {
            println!("LINUX-LIKE KERNEL: unsupported rootfstype= parameter");
        }
        (_, _, Err(_)) => {
            println!("LINUX-LIKE KERNEL: no modern virtio-blk device detected");
        }
    }

    if false {
        let reclaim_base = reclaim_demo_base.expect("reclaim demo base");
        unsafe {
            for offset in 0..zram::PAGE_SIZE {
                reclaim_base
                    .as_mut_ptr::<u8>()
                    .add(offset)
                    .write((offset % 251) as u8);
                reclaim_base
                    .as_mut_ptr::<u8>()
                    .add(zram::PAGE_SIZE + offset)
                    .write(((offset * 3) % 251) as u8);
                reclaim_base
                    .as_mut_ptr::<u8>()
                    .add(2 * zram::PAGE_SIZE + offset)
                    .write(0x5a);
            }
        }

        reclaim::reclaim_page(reclaim_base + zram::PAGE_SIZE as u64)
            .expect("failed to reclaim page 1");
        reclaim::reclaim_page(reclaim_base + (2 * zram::PAGE_SIZE) as u64)
            .expect("failed to reclaim page 2");

        let restored_byte_1 = unsafe {
            reclaim_base
                .as_ptr::<u8>()
                .add(zram::PAGE_SIZE + 123)
                .read_volatile()
        };
        let restored_byte_2 = unsafe {
            reclaim_base
                .as_ptr::<u8>()
                .add(2 * zram::PAGE_SIZE + 17)
                .read_volatile()
        };
        assert_eq!(restored_byte_1, ((123 * 3) % 251) as u8);
        assert_eq!(restored_byte_2, 0x5a);

        let reclaim_stats = reclaim::stats();
        println!(
            "LINUX-LIKE KERNEL: reclaim allocated_pages={}, resident_pages={}, compressed_pages={}, reclaims={}, restored_faults={}",
            reclaim_stats.allocated_pages,
            reclaim_stats.resident_pages,
            reclaim_stats.compressed_pages,
            reclaim_stats.reclaims,
            reclaim_stats.restored_faults
        );
    } else {
        println!("LINUX-LIKE KERNEL: reclaim demo unavailable without Limine memory services");
    }

    if false {
        let mut zram_device = zram::ZramDevice::new(64);
        let mut zswap_cache = zram::ZswapCache::new(64);

        let mut raw_page = [0u8; zram::PAGE_SIZE];
        let mut seed = 0x1234_5678u32;
        for byte in raw_page.iter_mut() {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *byte = (seed >> 24) as u8;
        }

        let mut compressible_page = [0u8; zram::PAGE_SIZE];
        for (index, byte) in compressible_page.iter_mut().enumerate() {
            *byte = if index % 2 == 0 { b'A' } else { b'B' };
        }

        zram_device
            .store_page(0, &raw_page)
            .expect("zram store failed");
        zram_device
            .store_page(1, &compressible_page)
            .expect("zram store failed");
        let raw_roundtrip = zram_device.load_page(0).expect("zram load failed");
        let compressed_roundtrip = zram_device.load_page(1).expect("zram load failed");
        assert_eq!(raw_page.as_slice(), raw_roundtrip.as_slice());
        assert_eq!(
            compressible_page.as_slice(),
            compressed_roundtrip.as_slice()
        );

        zswap_cache
            .store(7, &compressible_page)
            .expect("zswap store failed");
        let zswap_roundtrip = zswap_cache.load(7).expect("zswap load failed");
        assert_eq!(compressible_page.as_slice(), zswap_roundtrip.as_slice());
        zswap_cache.invalidate(7).expect("zswap invalidate failed");

        let zram_stats = zram_device.stats();
        let zswap_stats = zswap_cache.stats();
        println!(
            "LINUX-LIKE KERNEL: zram stores={}, loads={}, raw_pages={}, compressed_pages={}, logical_bytes={}, stored_bytes={}, zspages={}",
            zram_stats.stores,
            zram_stats.loads,
            zram_stats.raw_pages,
            zram_stats.compressed_pages,
            zram_stats.logical_bytes,
            zram_stats.stored_bytes,
            zram_stats.allocator.zspages
        );
        println!(
            "LINUX-LIKE KERNEL: zswap hits={}, misses={}, backend_invalidations={}",
            zswap_stats.hits, zswap_stats.misses, zswap_stats.backend.invalidations
        );
    }

    if let Some(task) = init_task {
        process::SCHEDULER.lock().add_task(task);
        println!("LINUX-LIKE KERNEL: added PID1 userspace task");
    } else {
        let task1 = process::Task::with_params(
            1,
            0,
            test_task_1,
            process::SchedParams {
                class_hint: Some(process::TaskClass::Game),
                nice: -5,
                preferred_cpu: Some(process::CpuId(0)),
                process_id: 0,
            },
        );
        let task2 = process::Task::new(2, 0, test_task_2);

        process::SCHEDULER.lock().add_task(task1);
        process::SCHEDULER.lock().add_task(task2);
        println!("LINUX-LIKE KERNEL: using fallback kernel demo tasks");
    }

    println!("LINUX-LIKE KERNEL: Starting scheduler...");
    crate::process::start();
}

pub fn init_local_cpu_features() {
    unsafe {
        Cr0::update(|cr0| {
            cr0.remove(Cr0Flags::EMULATE_COPROCESSOR | Cr0Flags::TASK_SWITCHED);
            cr0.insert(Cr0Flags::MONITOR_COPROCESSOR);
        });
        Cr4::update(|cr4| {
            cr4.insert(Cr4Flags::OSFXSR | Cr4Flags::OSXMMEXCPT_ENABLE);
        });
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
