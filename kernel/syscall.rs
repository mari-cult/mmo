use crate::println;
use x86_64::VirtAddr;
use x86_64::registers::model_specific::LStar;

pub fn init() {
    let handler_addr = syscall_handler as *const () as usize;
    unsafe {
        LStar::write(VirtAddr::new(handler_addr as u64));

        // Enable syscall/sysret
        x86_64::registers::model_specific::Efer::update(|efer| {
            efer.insert(x86_64::registers::model_specific::EferFlags::SYSTEM_CALL_EXTENSIONS);
        });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sys_write(fd: usize, buf: *const u8, len: usize) -> usize {
    let s = unsafe {
        core::str::from_utf8(core::slice::from_raw_parts(buf, len)).unwrap_or("Invalid UTF-8")
    };
    println!("SYSCALL: write(fd={}, buf=\"{}\", len={})", fd, s, len);
    len
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sys_exit(code: usize) -> ! {
    println!("SYSCALL: exit(code={})", code);
    crate::process::on_task_exit()
}

#[unsafe(naked)]
pub unsafe extern "C" fn syscall_handler() -> ! {
    core::arch::naked_asm!(
        "swapgs",
        "mov %rsp, %gs:16", // Save user stack
        "mov %gs:8, %rsp",  // Load kernel stack
        "push %rcx",        // Save user RIP
        "push %r11",        // Save user RFLAGS
        "push %rbp",
        "push %rbx",
        "push %r12",
        "push %r13",
        "push %r14",
        "push %r15",
        "mov %rdi, %rax", // Syscall number in RAX (conventionally RAx, but Limine/Linux uses RAX)
        // For simplicity, we directly call dispatch
        "call syscall_dispatch",
        "pop %r15",
        "pop %r14",
        "pop %r13",
        "pop %r12",
        "pop %rbx",
        "pop %rbp",
        "pop %r11",
        "pop %rcx",
        "mov %gs:16, %rsp", // Restore user stack
        "swapgs",
        "sysretq",
        options(att_syntax)
    )
}

#[unsafe(no_mangle)]
extern "C" fn syscall_dispatch(rax: usize, rdi: usize, rsi: usize, rdx: usize) -> usize {
    match rax {
        1 => unsafe { sys_write(rdi, rsi as *const u8, rdx) },
        60 => unsafe { sys_exit(rdi) },
        _ => {
            println!("SYSCALL: unknown rax={}", rax);
            0
        }
    }
}
