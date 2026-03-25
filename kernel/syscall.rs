extern crate alloc;

use crate::{gdt, print, println, process, user, vfs};
use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::VirtAddr;
use x86_64::instructions::segmentation::Segment;
use x86_64::registers::model_specific::{Efer, EferFlags, KernelGsBase, LStar, SFMask, Star};
use x86_64::registers::rflags::RFlags;

const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const EBADF: i32 = 9;
const EAGAIN: i32 = 11;
const EACCES: i32 = 13;
const EFAULT: i32 = 14;
const EBUSY: i32 = 16;
const EEXIST: i32 = 17;
const ENODEV: i32 = 19;
const ENOTDIR: i32 = 20;
const EISDIR: i32 = 21;
const EINVAL: i32 = 22;
const ENFILE: i32 = 23;
const EMFILE: i32 = 24;
const ENOSPC: i32 = 28;
const EROFS: i32 = 30;
const ENOSYS: i32 = 38;
const ENAMETOOLONG: i32 = 36;

const SYS_READ: usize = 0;
const SYS_WRITE: usize = 1;
const SYS_OPEN: usize = 2;
const SYS_CLOSE: usize = 3;
const SYS_FSTAT: usize = 5;
const SYS_PREAD64: usize = 17;
const SYS_LSEEK: usize = 8;
const SYS_IOCTL: usize = 16;
const SYS_GETUID: usize = 102;
const SYS_GETGID: usize = 104;
const SYS_GETEUID: usize = 107;
const SYS_GETEGID: usize = 108;
const SYS_MMAP: usize = 9;
const SYS_MPROTECT: usize = 10;
const SYS_MUNMAP: usize = 11;
const SYS_BRK: usize = 12;
const SYS_RT_SIGACTION: usize = 13;
const SYS_RT_SIGPROCMASK: usize = 14;
const SYS_POLL: usize = 7;
const SYS_PPOLL: usize = 271;
const SYS_NANOSLEEP: usize = 35;
const SYS_GETPID: usize = 39;
const SYS_ACCESS: usize = 21;
const SYS_WRITEV: usize = 20;
const SYS_GETCWD: usize = 79;
const SYS_ARCH_PRCTL: usize = 158;
const SYS_GETPPID: usize = 110;
const SYS_SET_TID_ADDRESS: usize = 218;
const SYS_GETRANDOM: usize = 318;
const SYS_SET_ROBUST_LIST: usize = 273;
const SYS_RSEQ: usize = 334;
const SYS_PRLIMIT64: usize = 302;
const SYS_CLOCK_GETTIME: usize = 228;
const SYS_EXIT_GROUP: usize = 231;
const SYS_OPENAT: usize = 257;
const SYS_NEWFSTATAT: usize = 262;
const SYS_READLINKAT: usize = 267;
const SYS_EXECVE: usize = 59;
const SYS_UNAME: usize = 63;
const SYS_EXIT: usize = 60;

static UNKNOWN_SYSCALL_SEEN: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];
static SYSCALL_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);

#[repr(C)]
struct SyscallCpuLocal {
    kernel_rsp: usize,
    user_rsp: usize,
}

static mut SYSCALL_CPU_LOCAL: SyscallCpuLocal = SyscallCpuLocal {
    kernel_rsp: 0,
    user_rsp: 0,
};

#[repr(C)]
struct SyscallArgs {
    nr: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LinuxStat {
    st_dev: u64,
    st_ino: u64,
    st_nlink: u64,
    st_mode: u32,
    st_uid: u32,
    st_gid: u32,
    __pad0: u32,
    st_rdev: u64,
    st_size: i64,
    st_blksize: i64,
    st_blocks: i64,
    st_atime: i64,
    st_atime_nsec: i64,
    st_mtime: i64,
    st_mtime_nsec: i64,
    st_ctime: i64,
    st_ctime_nsec: i64,
    __unused: [i64; 3],
}

#[repr(C)]
struct LinuxUtsname {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
    domainname: [u8; 65],
}

#[repr(C)]
struct LinuxIovec {
    iov_base: *const u8,
    iov_len: usize,
}

fn neg_errno(code: i32) -> usize {
    (-(code as isize)) as usize
}

fn from_vfs_err(err: vfs::VfsError) -> i32 {
    match err {
        vfs::VfsError::NotMounted => ENODEV,
        vfs::VfsError::NotFound => ENOENT,
        vfs::VfsError::NotDirectory => ENOTDIR,
        vfs::VfsError::InvalidPath => EINVAL,
        vfs::VfsError::Io => EIO,
        vfs::VfsError::InvalidFd => EBADF,
    }
}

const EIO: i32 = 5;

pub fn init() {
    let handler_addr = syscall_handler as *const () as usize;
    unsafe { SYSCALL_CPU_LOCAL.kernel_rsp = gdt::kernel_privilege_stack_top().as_u64() as usize };
    KernelGsBase::write(VirtAddr::from_ptr(&raw const SYSCALL_CPU_LOCAL));
    Star::write(
        gdt::user_code_selector(),
        gdt::user_data_selector(),
        x86_64::instructions::segmentation::CS::get_reg(),
        x86_64::instructions::segmentation::SS::get_reg(),
    )
    .expect("invalid syscall STAR selectors");
    LStar::write(VirtAddr::new(handler_addr as u64));
    SFMask::write(RFlags::INTERRUPT_FLAG | RFlags::TRAP_FLAG);
    unsafe {
        Efer::update(|efer| efer.insert(EferFlags::SYSTEM_CALL_EXTENSIONS));
    }
}

#[unsafe(naked)]
pub unsafe extern "C" fn syscall_handler() -> ! {
    core::arch::naked_asm!(
        "swapgs",
        "mov %rsp, %gs:8",
        "mov %gs:0, %rsp",
        "push %rcx",
        "push %r11",
        "push %rbp",
        "push %rbx",
        "push %r12",
        "push %r13",
        "push %r14",
        "push %r15",
        "mov %rdi, %r12",
        "mov %rsi, %r13",
        "mov %rdx, %r14",
        "mov %r10, %r15",
        "mov %r8, %rbx",
        "mov %rax, %rdi",
        "mov %r12, %rsi",
        "mov %r13, %rdx",
        "mov %r14, %rcx",
        "mov %r15, %r8",
        "mov %rbx, %r9",
        "sub $56, %rsp",
        "mov %rax, 0(%rsp)",
        "mov %r12, 8(%rsp)",
        "mov %r13, 16(%rsp)",
        "mov %r14, 24(%rsp)",
        "mov %r15, 32(%rsp)",
        "mov %rbx, 40(%rsp)",
        "mov %r9, 48(%rsp)",
        "mov %rsp, %rdi",
        "call syscall_dispatch",
        "add $56, %rsp",
        "pop %r15",
        "pop %r14",
        "pop %r13",
        "pop %r12",
        "pop %rbx",
        "pop %rbp",
        "pop %r11",
        "pop %rcx",
        "mov %gs:8, %rsp",
        "swapgs",
        "sysretq",
        options(att_syntax)
    )
}

fn read_cstr(ptr: *const u8, max_len: usize) -> Result<String, i32> {
    if ptr.is_null() {
        return Err(EFAULT);
    }
    let mut len = 0usize;
    while len < max_len {
        let b = unsafe { ptr.add(len).read_volatile() };
        if b == 0 {
            let s = unsafe { core::slice::from_raw_parts(ptr, len) };
            return Ok(String::from_utf8_lossy(s).into_owned());
        }
        len += 1;
    }
    Err(ENAMETOOLONG)
}

fn write_uts(dst: *mut LinuxUtsname) -> usize {
    if dst.is_null() {
        return neg_errno(EFAULT);
    }
    let mut out = LinuxUtsname {
        sysname: [0; 65],
        nodename: [0; 65],
        release: [0; 65],
        version: [0; 65],
        machine: [0; 65],
        domainname: [0; 65],
    };
    copy_field(&mut out.sysname, b"linux-like");
    copy_field(&mut out.nodename, b"qemu");
    copy_field(&mut out.release, b"0.1");
    copy_field(&mut out.version, b"#1");
    copy_field(&mut out.machine, b"x86_64");
    copy_field(&mut out.domainname, b"local");
    unsafe {
        dst.write_volatile(out);
    }
    0
}

fn copy_field(dst: &mut [u8], src: &[u8]) {
    let n = src.len().min(dst.len().saturating_sub(1));
    dst[..n].copy_from_slice(&src[..n]);
    dst[n] = 0;
}

fn write_stat(stat_ptr: *mut LinuxStat, ino: u64, mode: u16, size: u64) -> usize {
    if stat_ptr.is_null() {
        return neg_errno(EFAULT);
    }
    let st = LinuxStat {
        st_dev: 1,
        st_ino: ino,
        st_nlink: 1,
        st_mode: u32::from(mode),
        st_uid: 0,
        st_gid: 0,
        __pad0: 0,
        st_rdev: 0,
        st_size: size as i64,
        st_blksize: 4096,
        st_blocks: (size as i64 + 511) / 512,
        st_atime: 0,
        st_atime_nsec: 0,
        st_mtime: 0,
        st_mtime_nsec: 0,
        st_ctime: 0,
        st_ctime_nsec: 0,
        __unused: [0; 3],
    };
    unsafe { stat_ptr.write_volatile(st) };
    0
}

fn log_unknown_once(nr: usize) {
    let bucket = (nr / 64).min(UNKNOWN_SYSCALL_SEEN.len() - 1);
    let bit = nr % 64;
    let mask = 1u64 << bit;
    let prev = UNKNOWN_SYSCALL_SEEN[bucket].fetch_or(mask, Ordering::SeqCst);
    if (prev & mask) == 0 {
        println!("SYSCALL: unimplemented nr={}", nr);
    }
}

#[unsafe(no_mangle)]
extern "C" fn syscall_dispatch(args: *const SyscallArgs) -> usize {
    if args.is_null() {
        return neg_errno(EFAULT);
    }
    let args = unsafe { &*args };
    let nr = args.nr;
    let a0 = args.a0;
    let a1 = args.a1;
    let a2 = args.a2;
    let a3 = args.a3;
    let a4 = args.a4;
    let a5 = args.a5;
    let trace_idx = SYSCALL_TRACE_COUNT.fetch_add(1, Ordering::SeqCst);
    if trace_idx < 16 {
        println!("SYSCALL: nr={} a0={:#x} a1={:#x} a2={:#x}", nr, a0, a1, a2);
    }
    match nr {
        SYS_READ => {
            let fd = a0 as i32;
            let buf = a1 as *mut u8;
            let len = a2;
            if buf.is_null() {
                return neg_errno(EFAULT);
            }
            if fd == 0 {
                return 0;
            }
            let out = unsafe { core::slice::from_raw_parts_mut(buf, len) };
            match vfs::read(fd, out) {
                Ok(n) => n,
                Err(e) => neg_errno(from_vfs_err(e)),
            }
        }
        SYS_WRITE => {
            let fd = a0 as i32;
            let buf = a1 as *const u8;
            let len = a2;
            if buf.is_null() {
                return neg_errno(EFAULT);
            }
            let data = unsafe { core::slice::from_raw_parts(buf, len) };
            if fd == 1 || fd == 2 {
                if let Ok(s) = core::str::from_utf8(data) {
                    print!("{}", s);
                } else {
                    for b in data {
                        print!("{}", *b as char);
                    }
                }
                len
            } else {
                neg_errno(EBADF)
            }
        }
        SYS_WRITEV => {
            let fd = a0 as i32;
            let iov = a1 as *const LinuxIovec;
            let iovcnt = a2;
            if iov.is_null() {
                return neg_errno(EFAULT);
            }
            let mut total = 0usize;
            for idx in 0..iovcnt {
                let ent = unsafe { &*iov.add(idx) };
                if ent.iov_base.is_null() {
                    return neg_errno(EFAULT);
                }
                let data = unsafe { core::slice::from_raw_parts(ent.iov_base, ent.iov_len) };
                let wrote = if fd == 1 || fd == 2 {
                    if let Ok(s) = core::str::from_utf8(data) {
                        print!("{}", s);
                    } else {
                        for b in data {
                            print!("{}", *b as char);
                        }
                    }
                    ent.iov_len
                } else {
                    return neg_errno(EBADF);
                };
                total = total.saturating_add(wrote);
            }
            total
        }
        SYS_CLOSE => match vfs::close(a0 as i32) {
            Ok(()) => 0,
            Err(e) => neg_errno(from_vfs_err(e)),
        },
        SYS_FSTAT => match vfs::fstat(a0 as i32) {
            Ok(st) => write_stat(a1 as *mut LinuxStat, st.ino, st.mode, st.size),
            Err(e) => neg_errno(from_vfs_err(e)),
        },
        SYS_PREAD64 => {
            let fd = a0 as i32;
            let buf = a1 as *mut u8;
            let len = a2;
            let offset = a3 as u64;
            if buf.is_null() {
                return neg_errno(EFAULT);
            }
            let out = unsafe { core::slice::from_raw_parts_mut(buf, len) };
            match vfs::pread(fd, offset, out) {
                Ok(n) => n,
                Err(e) => neg_errno(from_vfs_err(e)),
            }
        }
        SYS_LSEEK => match vfs::lseek(a0 as i32, a1 as i64, a2 as i32) {
            Ok(v) => v as usize,
            Err(e) => neg_errno(from_vfs_err(e)),
        },
        SYS_IOCTL => neg_errno(ENOSYS),
        SYS_MMAP => match user::mmap(
            a0 as u64, a1 as u64, a2 as i32, a3 as i32, a4 as i32, a5 as u64,
        ) {
            Ok(addr) => addr as usize,
            Err(_) => neg_errno(ENOSYS),
        },
        SYS_MPROTECT => match user::mprotect(a0 as u64, a1 as u64, a2 as i32) {
            Ok(()) => 0,
            Err(_) => neg_errno(ENOSYS),
        },
        SYS_MUNMAP => match user::munmap(a0 as u64, a1 as u64) {
            Ok(()) => 0,
            Err(_) => neg_errno(ENOSYS),
        },
        SYS_BRK => user::brk((a0 != 0).then_some(a0 as u64)) as usize,
        SYS_RT_SIGACTION | SYS_RT_SIGPROCMASK => 0,
        SYS_NANOSLEEP => {
            user::nanosleep(0);
            0
        }
        SYS_GETPID => user::pid() as usize,
        SYS_GETUID | SYS_GETEUID | SYS_GETGID | SYS_GETEGID => 0,
        SYS_GETPPID => user::ppid() as usize,
        SYS_ACCESS => {
            let path = match read_cstr(a0 as *const u8, 4096) {
                Ok(v) => v,
                Err(e) => return neg_errno(e),
            };
            if vfs::exists(&path) {
                0
            } else {
                neg_errno(ENOENT)
            }
        }
        SYS_GETCWD => {
            let dst = a0 as *mut u8;
            let len = a1;
            if dst.is_null() || len == 0 {
                return neg_errno(EFAULT);
            }
            let cwd = vfs::getcwd();
            let bytes = cwd.as_bytes();
            if bytes.len() + 1 > len {
                return neg_errno(ERANGE);
            }
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
                dst.add(bytes.len()).write(0);
            }
            a0
        }
        SYS_ARCH_PRCTL => match user::arch_prctl(a0, a1 as u64) {
            Ok(v) => v as usize,
            Err(_) => neg_errno(EINVAL),
        },
        SYS_SET_TID_ADDRESS => {
            user::set_tid_address(a0 as u64);
            user::pid() as usize
        }
        SYS_CLOCK_GETTIME => 0,
        SYS_EXIT | SYS_EXIT_GROUP => process::on_task_exit(),
        SYS_OPEN => {
            let path = match read_cstr(a0 as *const u8, 4096) {
                Ok(v) => v,
                Err(e) => return neg_errno(e),
            };
            match vfs::open(&path, a1 as i32) {
                Ok(fd) => fd as usize,
                Err(e) => neg_errno(from_vfs_err(e)),
            }
        }
        SYS_OPENAT => {
            let path = match read_cstr(a1 as *const u8, 4096) {
                Ok(v) => v,
                Err(e) => return neg_errno(e),
            };
            match vfs::open(&path, a2 as i32) {
                Ok(fd) => fd as usize,
                Err(e) => neg_errno(from_vfs_err(e)),
            }
        }
        SYS_NEWFSTATAT => {
            let path = match read_cstr(a1 as *const u8, 4096) {
                Ok(v) => v,
                Err(e) => return neg_errno(e),
            };
            let fd = match vfs::open(&path, 0) {
                Ok(fd) => fd,
                Err(e) => return neg_errno(from_vfs_err(e)),
            };
            let rc = match vfs::fstat(fd) {
                Ok(st) => write_stat(a2 as *mut LinuxStat, st.ino, st.mode, st.size),
                Err(e) => neg_errno(from_vfs_err(e)),
            };
            let _ = vfs::close(fd);
            rc
        }
        SYS_READLINKAT => {
            let path = match read_cstr(a1 as *const u8, 4096) {
                Ok(v) => v,
                Err(e) => return neg_errno(e),
            };
            let out = a2 as *mut u8;
            let size = a3;
            if out.is_null() {
                return neg_errno(EFAULT);
            }
            if path == "/proc/self/exe" {
                let binding = user::CURRENT.lock();
                let exe = binding
                    .init_path
                    .as_deref()
                    .unwrap_or("/bin/sh")
                    .as_bytes()
                    .to_vec();
                let n = exe.len().min(size);
                unsafe { core::ptr::copy_nonoverlapping(exe.as_ptr(), out, n) };
                n
            } else {
                match vfs::readlink(&path) {
                    Ok(target) => {
                        let bytes = target.as_bytes();
                        let n = bytes.len().min(size);
                        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), out, n) };
                        n
                    }
                    Err(e) => neg_errno(from_vfs_err(e)),
                }
            }
        }
        SYS_EXECVE => {
            let path = match read_cstr(a0 as *const u8, 4096) {
                Ok(v) => v,
                Err(e) => return neg_errno(e),
            };
            match user::execve(&path, &[], &[]) {
                Ok(()) => 0,
                Err(_) => neg_errno(ENOENT),
            }
        }
        SYS_UNAME => write_uts(a0 as *mut LinuxUtsname),
        SYS_SET_ROBUST_LIST => 0,
        SYS_PRLIMIT64 => 0,
        SYS_GETRANDOM => {
            let buf = a0 as *mut u8;
            let len = a1;
            if buf.is_null() {
                return neg_errno(EFAULT);
            }
            for i in 0..len {
                unsafe {
                    buf.add(i)
                        .write(((i as u64).wrapping_mul(37).wrapping_add(0x5a) & 0xff) as u8);
                }
            }
            len
        }
        SYS_RSEQ => neg_errno(ENOSYS),
        SYS_POLL | SYS_PPOLL => 0,
        _ => {
            log_unknown_once(nr);
            neg_errno(ENOSYS)
        }
    }
}

const ERANGE: i32 = 34;
