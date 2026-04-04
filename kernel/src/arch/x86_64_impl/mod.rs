pub mod apic;
pub mod gdt;
pub mod idt;
pub mod paging;
pub mod pci;
pub mod serial;
pub mod smp;

pub use apic::*;
pub use gdt::*;
pub use idt::*;
pub use paging::*;
pub use pci::*;
pub use serial::*;
pub use smp::{CpuTopology, MAX_CPUS};

use core::arch::asm;
use x86_64::instructions::segmentation::{CS, SS, Segment};
use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};

pub type VirtAddr = x86_64::VirtAddr;
pub type PhysAddr = x86_64::PhysAddr;

pub use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageSize, PageTable, PageTableFlags, PhysFrame, Size4KiB,
    mapper::{FlagUpdateError, MapToError, UnmapError},
};

pub fn init_paging(hhdm_offset: u64) {
    let physical_memory_offset = x86_64::VirtAddr::new(hhdm_offset);
    apic::set_hhdm_offset(physical_memory_offset);
    unsafe { paging::init(physical_memory_offset) };
}

pub const ARCH_NAME: &str = "x86_64";
pub const DYNLINK_PATH: &str = "/lib/ld-musl-x86_64.so.1";
pub const DYNLINK_CONF: &str = "/usr/etc/ld-musl-x86_64.path";

#[repr(C)]
pub struct SyscallFrame {
    pub nr: usize,
    pub a0: usize,
    pub a1: usize,
    pub a2: usize,
    pub a3: usize,
    pub a4: usize,
    pub a5: usize,
    pub user_rsp: usize,
    pub rcx: usize,
    pub r11: usize,
    pub rdi: usize,
    pub rsi: usize,
    pub rdx: usize,
    pub r10: usize,
    pub r8: usize,
    pub r9: usize,
    pub rbp: usize,
    pub rbx: usize,
    pub r12: usize,
    pub r13: usize,
    pub r14: usize,
    pub r15: usize,
}

pub fn init_hardware() {
    gdt::init();
    idt::init();
    init_local_cpu_features();
    apic::init();
}

pub fn init_syscalls(cpu_id: usize, stack_top: usize) {
    use crate::arch::smp::MAX_CPUS;
    use x86_64::registers::model_specific::{
        Efer, EferFlags, GsBase, KernelGsBase, LStar, SFMask, Star,
    };
    use x86_64::registers::rflags::RFlags;

    let handler_addr = syscall_handler as *const () as usize;
    unsafe {
        let cpu = cpu_id.min(MAX_CPUS.saturating_sub(1));
        SYSCALL_CPU_LOCALS[cpu].kernel_rsp = stack_top;
        let cpu_local = VirtAddr::from_ptr(core::ptr::addr_of!(SYSCALL_CPU_LOCALS[cpu]));
        GsBase::write(cpu_local);
        KernelGsBase::write(cpu_local);
    }
    Star::write(
        gdt::user_code_selector(),
        gdt::user_data_selector(),
        x86_64::instructions::segmentation::CS::get_reg(),
        x86_64::instructions::segmentation::SS::get_reg(),
    )
    .expect("invalid syscall STAR selectors");
    LStar::write(VirtAddr::new(handler_addr as u64));
    SFMask::write(
        RFlags::INTERRUPT_FLAG
            | RFlags::TRAP_FLAG
            | RFlags::DIRECTION_FLAG
            | RFlags::ALIGNMENT_CHECK
            | RFlags::NESTED_TASK,
    );
    unsafe {
        Efer::update(|efer| efer.insert(EferFlags::SYSTEM_CALL_EXTENSIONS));
    }
}

#[repr(C)]
struct SyscallCpuLocal {
    kernel_rsp: usize,
    user_rsp: usize,
    return_rax: usize,
}

static mut SYSCALL_CPU_LOCALS: [SyscallCpuLocal; 8] = [const {
    SyscallCpuLocal {
        kernel_rsp: 0,
        user_rsp: 0,
        return_rax: 0,
    }
}; 8];

pub fn set_kernel_stack_top(cpu_id: usize, stack_top: usize) {
    unsafe {
        let cpu = cpu_id.min(7);
        SYSCALL_CPU_LOCALS[cpu].kernel_rsp = stack_top;
    }
}

#[unsafe(naked)]
pub unsafe extern "C" fn syscall_handler() -> ! {
    core::arch::naked_asm!(
        "mov %rsp, %gs:8",
        "mov %gs:0, %rsp",
        "sub $176, %rsp",
        "mov %rax, 0(%rsp)",
        "mov %rdi, 8(%rsp)",
        "mov %rsi, 16(%rsp)",
        "mov %rdx, 24(%rsp)",
        "mov %r10, 32(%rsp)",
        "mov %r8, 40(%rsp)",
        "mov %r9, 48(%rsp)",
        "mov %gs:8, %rax",
        "mov %rax, 56(%rsp)",
        "mov %rcx, 64(%rsp)",
        "mov %r11, 72(%rsp)",
        "mov %rdi, 80(%rsp)",
        "mov %rsi, 88(%rsp)",
        "mov %rdx, 96(%rsp)",
        "mov %r10, 104(%rsp)",
        "mov %r8, 112(%rsp)",
        "mov %r9, 120(%rsp)",
        "mov %rbp, 128(%rsp)",
        "mov %rbx, 136(%rsp)",
        "mov %r12, 144(%rsp)",
        "mov %r13, 152(%rsp)",
        "mov %r14, 160(%rsp)",
        "mov %r15, 168(%rsp)",
        "mov %rsp, %rdi",
        "call syscall_dispatch",
        "mov %rax, %gs:16",
        "mov 168(%rsp), %r15",
        "mov 160(%rsp), %r14",
        "mov 152(%rsp), %r13",
        "mov 144(%rsp), %r12",
        "mov 136(%rsp), %rbx",
        "mov 128(%rsp), %rbp",
        "mov 120(%rsp), %r9",
        "mov 112(%rsp), %r8",
        "mov 104(%rsp), %r10",
        "mov 96(%rsp), %rdx",
        "mov 88(%rsp), %rsi",
        "mov 80(%rsp), %rdi",
        "mov 72(%rsp), %r11",
        "mov 64(%rsp), %rcx",
        "mov 56(%rsp), %rsp",
        "mov %gs:16, %rax",
        "sysretq",
        options(att_syntax)
    )
}

pub fn get_fs_base() -> u64 {
    use x86_64::registers::model_specific::FsBase;
    FsBase::read().as_u64()
}

pub fn set_fs_base(val: u64) {
    use x86_64::registers::model_specific::FsBase;
    unsafe {
        FsBase::write(VirtAddr::new(val));
    }
}

pub fn get_current_paging_root() -> PhysFrame<Size4KiB> {
    let (frame, _) = x86_64::registers::control::Cr3::read();
    frame
}

pub fn init_smp() -> usize {
    let topology = smp::init();
    topology.online_cpus
}

use core::arch::global_asm;

global_asm!(include_str!("switch.s"), options(att_syntax));

pub fn without_interrupts<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    x86_64::instructions::interrupts::without_interrupts(f)
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SavedTaskContext {
    pub r15: usize,
    pub r14: usize,
    pub r13: usize,
    pub r12: usize,
    pub r11: usize,
    pub r10: usize,
    pub r9: usize,
    pub r8: usize,
    pub rbp: usize,
    pub rdi: usize,
    pub rsi: usize,
    pub rdx: usize,
    pub rcx: usize,
    pub rbx: usize,
    pub rax: usize,
    pub rip: usize,
    pub cs: usize,
    pub rflags: usize,
    pub rsp: usize,
    pub ss: usize,
}

unsafe extern "sysv64" {
    pub fn restore_task_context(next_ctx: *const SavedTaskContext) -> !;
}

pub fn get_initial_segments() -> (usize, usize) {
    (usize::from(CS::get_reg().0), usize::from(SS::get_reg().0))
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

pub fn complete_interrupt() {
    apic::complete_interrupt();
}

pub fn halt() -> ! {
    loop {
        unsafe {
            asm!("hlt");
        }
    }
}

pub fn disable_interrupts() {
    unsafe {
        asm!("cli");
    }
}

pub fn enable_interrupts() {
    unsafe {
        asm!("sti");
    }
}

pub fn nop() {
    unsafe {
        asm!("nop");
    }
}
