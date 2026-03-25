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
const ECHILD: i32 = 10;
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
const ENOTTY: i32 = 25;
const EROFS: i32 = 30;
const ERANGE: i32 = 34;
const ENOSYS: i32 = 38;
const ENAMETOOLONG: i32 = 36;
const FD_CLOEXEC: i32 = 1;
const F_DUPFD: i32 = 0;
const F_GETFD: i32 = 1;
const F_SETFD: i32 = 2;
const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const F_DUPFD_CLOEXEC: i32 = 1030;

const SYS_READ: usize = 0;
const SYS_WRITE: usize = 1;
const SYS_PIPE: usize = 22;
const SYS_OPEN: usize = 2;
const SYS_STAT: usize = 4;
const SYS_CLOSE: usize = 3;
const SYS_FSTAT: usize = 5;
const SYS_LSTAT: usize = 6;
const SYS_FCNTL: usize = 72;
const SYS_PREAD64: usize = 17;
const SYS_GETDENTS64: usize = 217;
const SYS_READV: usize = 19;
const SYS_LSEEK: usize = 8;
const SYS_DUP: usize = 32;
const SYS_DUP2: usize = 33;
const SYS_IOCTL: usize = 16;
const SYS_GETUID: usize = 102;
const SYS_GETGID: usize = 104;
const SYS_GETEUID: usize = 107;
const SYS_GETEGID: usize = 108;
const SYS_GETRESUID: usize = 118;
const SYS_GETRESGID: usize = 120;
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
const SYS_SETPGID: usize = 109;
const SYS_GETPGID: usize = 121;
const SYS_SET_TID_ADDRESS: usize = 218;
const SYS_GETRANDOM: usize = 318;
const SYS_SET_ROBUST_LIST: usize = 273;
const SYS_RSEQ: usize = 334;
const SYS_PRLIMIT64: usize = 302;
const SYS_CLOCK_GETTIME: usize = 228;
const SYS_PIPE2: usize = 293;
const SYS_EXIT_GROUP: usize = 231;
const SYS_OPENAT: usize = 257;
const SYS_FACCESSAT: usize = 269;
const SYS_FACCESSAT2: usize = 439;
const SYS_NEWFSTATAT: usize = 262;
const SYS_STATX: usize = 332;
const TCGETS: usize = 0x5401;
const TIOCGWINSZ: usize = 0x5413;
const TIOCGPGRP: usize = 0x540f;
const TIOCSPGRP: usize = 0x5410;
const SYS_READLINKAT: usize = 267;
const SYS_EXECVE: usize = 59;
const SYS_CLONE: usize = 56;
const SYS_FORK: usize = 57;
const SYS_VFORK: usize = 58;
const SYS_WAIT4: usize = 61;
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
#[derive(Clone, Copy)]
struct LinuxStatxTimestamp {
    tv_sec: i64,
    tv_nsec: u32,
    __pad: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LinuxStatx {
    stx_mask: u32,
    stx_blksize: u32,
    stx_attributes: u64,
    stx_nlink: u32,
    stx_uid: u32,
    stx_gid: u32,
    stx_mode: u16,
    __pad0: u16,
    stx_ino: u64,
    stx_size: u64,
    stx_blocks: u64,
    stx_attributes_mask: u64,
    stx_atime: LinuxStatxTimestamp,
    stx_btime: LinuxStatxTimestamp,
    stx_ctime: LinuxStatxTimestamp,
    stx_mtime: LinuxStatxTimestamp,
    stx_rdev_major: u32,
    stx_rdev_minor: u32,
    stx_dev_major: u32,
    stx_dev_minor: u32,
    __pad1: [u64; 14],
}

#[repr(C)]
struct LinuxIovec {
    iov_base: *const u8,
    iov_len: usize,
}

#[repr(C)]
struct LinuxWinsize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

#[repr(C)]
struct LinuxTermios {
    c_iflag: u32,
    c_oflag: u32,
    c_cflag: u32,
    c_lflag: u32,
    c_line: u8,
    c_cc: [u8; 19],
}

#[repr(C)]
struct LinuxTimespec {
    tv_sec: i64,
    tv_nsec: i64,
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
const AT_FDCWD: i32 = -100;
const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
const AT_EMPTY_PATH: i32 = 0x1000;
const STATX_TYPE: u32 = 0x0001;
const STATX_MODE: u32 = 0x0002;
const STATX_NLINK: u32 = 0x0004;
const STATX_UID: u32 = 0x0008;
const STATX_GID: u32 = 0x0010;
const STATX_ATIME: u32 = 0x0020;
const STATX_MTIME: u32 = 0x0040;
const STATX_CTIME: u32 = 0x0080;
const STATX_INO: u32 = 0x0100;
const STATX_SIZE: u32 = 0x0200;
const STATX_BLOCKS: u32 = 0x0400;
const STATX_BASIC_STATS: u32 = 0x07ff;

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

#[unsafe(naked)]
pub unsafe extern "C" fn syscall_handler() -> ! {
    core::arch::naked_asm!(
        "swapgs",
        "mov %rsp, %gs:8",
        "mov %gs:0, %rsp",
        "push %rcx",
        "push %r11",
        "push %rdi",
        "push %rsi",
        "push %rdx",
        "push %r10",
        "push %r8",
        "push %r9",
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
        "mov %r9, %rbp",
        "mov %rax, %rdi",
        "mov %r12, %rsi",
        "mov %r13, %rdx",
        "mov %r14, %rcx",
        "mov %r15, %r8",
        "mov %rbx, %r9",
        "sub $64, %rsp",
        "mov %rax, 0(%rsp)",
        "mov %r12, 8(%rsp)",
        "mov %r13, 16(%rsp)",
        "mov %r14, 24(%rsp)",
        "mov %r15, 32(%rsp)",
        "mov %rbx, 40(%rsp)",
        "mov %rbp, 48(%rsp)",
        "mov %rsp, %rdi",
        "call syscall_dispatch",
        "add $64, %rsp",
        "pop %r15",
        "pop %r14",
        "pop %r13",
        "pop %r12",
        "pop %rbx",
        "pop %rbp",
        "pop %r9",
        "pop %r8",
        "pop %r10",
        "pop %rdx",
        "pop %rsi",
        "pop %rdi",
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

fn cstr_eq(ptr: *const u8, lit: &str) -> Result<bool, i32> {
    if ptr.is_null() {
        return Err(EFAULT);
    }
    let bytes = lit.as_bytes();
    for (idx, expected) in bytes.iter().enumerate() {
        let got = unsafe { ptr.add(idx).read_volatile() };
        if got != *expected {
            return Ok(false);
        }
    }
    let term = unsafe { ptr.add(bytes.len()).read_volatile() };
    Ok(term == 0)
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

fn write_statx(statx_ptr: *mut LinuxStatx, ino: u64, mode: u16, size: u64, mask: u32) -> usize {
    if statx_ptr.is_null() {
        return neg_errno(EFAULT);
    }
    let stx = LinuxStatx {
        stx_mask: mask | STATX_BASIC_STATS,
        stx_blksize: 4096,
        stx_attributes: 0,
        stx_nlink: 1,
        stx_uid: 0,
        stx_gid: 0,
        stx_mode: mode,
        __pad0: 0,
        stx_ino: ino,
        stx_size: size,
        stx_blocks: size.div_ceil(512),
        stx_attributes_mask: 0,
        stx_atime: LinuxStatxTimestamp {
            tv_sec: 0,
            tv_nsec: 0,
            __pad: 0,
        },
        stx_btime: LinuxStatxTimestamp {
            tv_sec: 0,
            tv_nsec: 0,
            __pad: 0,
        },
        stx_ctime: LinuxStatxTimestamp {
            tv_sec: 0,
            tv_nsec: 0,
            __pad: 0,
        },
        stx_mtime: LinuxStatxTimestamp {
            tv_sec: 0,
            tv_nsec: 0,
            __pad: 0,
        },
        stx_rdev_major: 0,
        stx_rdev_minor: 0,
        stx_dev_major: 0,
        stx_dev_minor: 1,
        __pad1: [0; 14],
    };
    unsafe { statx_ptr.write_volatile(stx) };
    0
}

fn align_up_usize(value: usize, align: usize) -> usize {
    if align == 0 {
        return value;
    }
    (value + align - 1) & !(align - 1)
}

fn crabfs_ftype_to_dt(ftype: u8) -> u8 {
    match ftype {
        1 => 8,  // DT_REG
        2 => 4,  // DT_DIR
        7 => 10, // DT_LNK
        _ => 0,  // DT_UNKNOWN
    }
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
    if trace_idx < 2048 && nr != SYS_WRITEV {
        println!(
            "SYSCALL: nr={} a0={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x} a5={:#x}",
            nr, a0, a1, a2, a3, a4, a5
        );
    }
    match nr {
        SYS_READ => {
            let fd = a0 as i32;
            let buf = a1 as *mut u8;
            let len = a2;
            if buf.is_null() {
                return neg_errno(EFAULT);
            }
            let out = unsafe { core::slice::from_raw_parts_mut(buf, len) };
            let path = if fd >= 3 {
                vfs::path_of_fd(fd).ok()
            } else {
                None
            };
            match vfs::read(fd, out) {
                Ok(n) => {
                    if let Some(path) = path.as_deref() {
                        println!("READ fd={} path={} len={} -> {}", fd, path, len, n);
                    }
                    n
                }
                Err(e) => {
                    if let Some(path) = path.as_deref() {
                        println!("READ err fd={} path={} len={} err={:?}", fd, path, len, e);
                    }
                    neg_errno(from_vfs_err(e))
                }
            }
        }
        SYS_READV => {
            let fd = a0 as i32;
            let iov = a1 as *const LinuxIovec;
            let iovcnt = a2;
            if iov.is_null() {
                return neg_errno(EFAULT);
            }
            let mut total = 0usize;
            for idx in 0..iovcnt {
                let ent = unsafe { &mut *(iov.add(idx) as *mut LinuxIovec) };
                if ent.iov_base.is_null() {
                    return neg_errno(EFAULT);
                }
                let out = unsafe {
                    core::slice::from_raw_parts_mut(ent.iov_base as *mut u8, ent.iov_len)
                };
                match vfs::read(fd, out) {
                    Ok(n) => {
                        total = total.saturating_add(n);
                        if n < ent.iov_len {
                            break;
                        }
                    }
                    Err(e) => return neg_errno(from_vfs_err(e)),
                }
            }
            total
        }
        SYS_WRITE => {
            let fd = a0 as i32;
            let buf = a1 as *const u8;
            let len = a2;
            if buf.is_null() {
                return neg_errno(EFAULT);
            }
            let data = unsafe { core::slice::from_raw_parts(buf, len) };
            if fd == 1 || fd == 2 || vfs::is_special_tty(fd).unwrap_or(false) {
                if let Ok(s) = core::str::from_utf8(data) {
                    print!("{}", s);
                } else {
                    for b in data {
                        print!("{}", *b as char);
                    }
                }
                len
            } else if vfs::is_special_null(fd).unwrap_or(false) {
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
                let wrote = if fd == 1 || fd == 2 || vfs::is_special_tty(fd).unwrap_or(false) {
                    if let Ok(s) = core::str::from_utf8(data) {
                        print!("{}", s);
                    } else {
                        for b in data {
                            print!("{}", *b as char);
                        }
                    }
                    ent.iov_len
                } else if vfs::is_special_null(fd).unwrap_or(false) {
                    ent.iov_len
                } else {
                    return neg_errno(EBADF);
                };
                total = total.saturating_add(wrote);
            }
            total
        }
        SYS_PIPE | SYS_PIPE2 => {
            let pipefd = a0 as *mut i32;
            if pipefd.is_null() {
                return neg_errno(EFAULT);
            }
            if nr == SYS_PIPE2 {
                let flags = a1 as i32;
                // We only support blocking pipes with optional CLOEXEC currently.
                if (flags & !(0x80000)) != 0 {
                    return neg_errno(EINVAL);
                }
            }
            let rfd = match vfs::open("/dev/null", 0) {
                Ok(fd) => fd,
                Err(e) => return neg_errno(from_vfs_err(e)),
            };
            let wfd = match vfs::open("/dev/null", 1) {
                Ok(fd) => fd,
                Err(e) => {
                    let _ = vfs::close(rfd);
                    return neg_errno(from_vfs_err(e));
                }
            };
            unsafe {
                pipefd.write_volatile(rfd);
                pipefd.add(1).write_volatile(wfd);
            }
            if nr == SYS_PIPE2 {
                let flags = a1 as i32;
                if (flags & 0x80000) != 0 {
                    let _ = vfs::set_fd_flags(rfd, FD_CLOEXEC);
                    let _ = vfs::set_fd_flags(wfd, FD_CLOEXEC);
                }
            }
            0
        }
        SYS_CLOSE => {
            let fd = a0 as i32;
            let path = if fd >= 3 {
                vfs::path_of_fd(fd).ok()
            } else {
                None
            };
            match vfs::close(fd) {
                Ok(()) => {
                    if let Some(path) = path.as_deref() {
                        println!("CLOSE fd={} path={}", fd, path);
                    }
                    0
                }
                Err(e) => {
                    if let Some(path) = path.as_deref() {
                        println!("CLOSE err fd={} path={} err={:?}", fd, path, e);
                    }
                    neg_errno(from_vfs_err(e))
                }
            }
        }
        SYS_STAT => {
            let path = match read_cstr(a0 as *const u8, 4096) {
                Ok(v) => v,
                Err(e) => {
                    println!("STAT read_cstr err ptr={:#x} err={}", a0, e);
                    return neg_errno(e);
                }
            };
            println!("STAT path={}", path);
            match vfs::stat_path(&path, true) {
                Ok(st) => {
                    println!("STAT ok path={} size={}", path, st.size);
                    write_stat(a1 as *mut LinuxStat, st.ino, st.mode, st.size)
                }
                Err(e) => {
                    println!("STAT err path={} err={:?}", path, e);
                    neg_errno(from_vfs_err(e))
                }
            }
        }
        SYS_FSTAT => match vfs::fstat(a0 as i32) {
            Ok(st) => {
                if let Ok(path) = vfs::path_of_fd(a0 as i32) {
                    println!("FSTAT fd={} path={} size={}", a0 as i32, path, st.size);
                }
                write_stat(a1 as *mut LinuxStat, st.ino, st.mode, st.size)
            }
            Err(e) => {
                if let Ok(path) = vfs::path_of_fd(a0 as i32) {
                    println!("FSTAT err fd={} path={} err={:?}", a0 as i32, path, e);
                } else {
                    println!("FSTAT err fd={} err={:?}", a0 as i32, e);
                }
                neg_errno(from_vfs_err(e))
            }
        },
        SYS_LSTAT => {
            let path = match read_cstr(a0 as *const u8, 4096) {
                Ok(v) => v,
                Err(e) => {
                    println!("LSTAT read_cstr err ptr={:#x} err={}", a0, e);
                    return neg_errno(e);
                }
            };
            println!("LSTAT path={}", path);
            match vfs::stat_path(&path, false) {
                Ok(st) => {
                    println!("LSTAT ok path={} size={}", path, st.size);
                    write_stat(a1 as *mut LinuxStat, st.ino, st.mode, st.size)
                }
                Err(e) => {
                    println!("LSTAT err path={} err={:?}", path, e);
                    neg_errno(from_vfs_err(e))
                }
            }
        }
        SYS_FCNTL => {
            let fd = a0 as i32;
            let cmd = a1 as i32;
            let arg = a2 as i32;
            if let Ok(path) = vfs::path_of_fd(fd) {
                println!("FCNTL fd={} path={} cmd={} arg={:#x}", fd, path, cmd, arg);
            } else {
                println!("FCNTL fd={} cmd={} arg={:#x}", fd, cmd, arg);
            }
            match cmd {
                F_GETFD => match vfs::get_fd_flags(fd) {
                    Ok(flags) => flags as usize,
                    Err(e) => neg_errno(from_vfs_err(e)),
                },
                F_SETFD => match vfs::set_fd_flags(fd, arg & FD_CLOEXEC) {
                    Ok(()) => 0,
                    Err(e) => neg_errno(from_vfs_err(e)),
                },
                F_GETFL => match vfs::get_status_flags(fd) {
                    Ok(flags) => flags as usize,
                    Err(e) => neg_errno(from_vfs_err(e)),
                },
                F_SETFL => match vfs::set_status_flags(fd, arg) {
                    Ok(()) => 0,
                    Err(e) => neg_errno(from_vfs_err(e)),
                },
                F_DUPFD | F_DUPFD_CLOEXEC => match vfs::dup_fd(fd, arg, cmd == F_DUPFD_CLOEXEC) {
                    Ok(new_fd) => new_fd as usize,
                    Err(e) => neg_errno(from_vfs_err(e)),
                },
                _ => neg_errno(ENOSYS),
            }
        }
        SYS_DUP => match vfs::dup_fd(a0 as i32, 0, false) {
            Ok(new_fd) => new_fd as usize,
            Err(e) => neg_errno(from_vfs_err(e)),
        },
        SYS_DUP2 => {
            let oldfd = a0 as i32;
            let newfd = a1 as i32;
            if oldfd == newfd {
                if vfs::path_of_fd(oldfd).is_ok() {
                    oldfd as usize
                } else {
                    neg_errno(EBADF)
                }
            } else {
                match vfs::dup2_fd(oldfd, newfd, false) {
                    Ok(fd) => fd as usize,
                    Err(e) => neg_errno(from_vfs_err(e)),
                }
            }
        }
        SYS_PREAD64 => {
            let fd = a0 as i32;
            let buf = a1 as *mut u8;
            let len = a2;
            let offset = a3 as u64;
            if buf.is_null() {
                return neg_errno(EFAULT);
            }
            let out = unsafe { core::slice::from_raw_parts_mut(buf, len) };
            let path = if fd >= 3 {
                vfs::path_of_fd(fd).ok()
            } else {
                None
            };
            match vfs::pread(fd, offset, out) {
                Ok(n) => {
                    if let Some(path) = path.as_deref() {
                        println!(
                            "PREAD64 fd={} path={} off={:#x} len={} -> {}",
                            fd, path, offset, len, n
                        );
                    }
                    n
                }
                Err(e) => {
                    if let Some(path) = path.as_deref() {
                        println!(
                            "PREAD64 err fd={} path={} off={:#x} len={} err={:?}",
                            fd, path, offset, len, e
                        );
                    }
                    neg_errno(from_vfs_err(e))
                }
            }
        }
        SYS_GETDENTS64 => {
            let fd = a0 as i32;
            let dirp = a1 as *mut u8;
            let count = a2;
            if dirp.is_null() {
                return neg_errno(EFAULT);
            }
            let entries = match vfs::list_dir_entries(fd) {
                Ok(v) => v,
                Err(e) => return neg_errno(from_vfs_err(e)),
            };
            let mut index = match vfs::get_dir_offset(fd) {
                Ok(v) => v as usize,
                Err(e) => return neg_errno(from_vfs_err(e)),
            };
            if index >= entries.len() {
                return 0;
            }

            let mut written = 0usize;
            while index < entries.len() {
                let ent = &entries[index];
                let name_bytes = ent.name.as_bytes();
                let hdr_len = 19usize;
                let reclen = align_up_usize(hdr_len + name_bytes.len() + 1, 8);
                if reclen > (count - written) {
                    break;
                }

                let base = unsafe { dirp.add(written) };
                unsafe {
                    core::ptr::write_unaligned(base as *mut u64, ent.ino);
                    core::ptr::write_unaligned(base.add(8) as *mut i64, (index + 1) as i64);
                    core::ptr::write_unaligned(base.add(16) as *mut u16, reclen as u16);
                    base.add(18).write(crabfs_ftype_to_dt(ent.ftype));
                    let name_dst = base.add(hdr_len);
                    core::ptr::copy_nonoverlapping(name_bytes.as_ptr(), name_dst, name_bytes.len());
                    name_dst.add(name_bytes.len()).write(0);
                    if reclen > hdr_len + name_bytes.len() + 1 {
                        core::ptr::write_bytes(
                            name_dst.add(name_bytes.len() + 1),
                            0,
                            reclen - hdr_len - name_bytes.len() - 1,
                        );
                    }
                }

                written += reclen;
                index += 1;
            }

            let _ = vfs::set_dir_offset(fd, index as u64);
            written
        }
        SYS_LSEEK => match vfs::lseek(a0 as i32, a1 as i64, a2 as i32) {
            Ok(v) => v as usize,
            Err(e) => neg_errno(from_vfs_err(e)),
        },
        SYS_IOCTL => {
            let fd = a0 as i32;
            let req = a1;
            let argp = a2 as *mut u8;
            if !vfs::is_special_tty(fd).unwrap_or(false) {
                return neg_errno(ENOTTY);
            }
            match req {
                TIOCGWINSZ => {
                    if argp.is_null() {
                        return neg_errno(EFAULT);
                    }
                    let ws = LinuxWinsize {
                        ws_row: 25,
                        ws_col: 80,
                        ws_xpixel: 0,
                        ws_ypixel: 0,
                    };
                    unsafe { (argp as *mut LinuxWinsize).write_volatile(ws) };
                    0
                }
                TIOCGPGRP => {
                    if argp.is_null() {
                        return neg_errno(EFAULT);
                    }
                    unsafe { (argp as *mut i32).write_volatile(user::pid() as i32) };
                    0
                }
                TIOCSPGRP => {
                    if argp.is_null() {
                        return neg_errno(EFAULT);
                    }
                    0
                }
                TCGETS => {
                    if argp.is_null() {
                        return neg_errno(EFAULT);
                    }
                    let tio = LinuxTermios {
                        c_iflag: 0x0000_0500, // ICRNL | IXON
                        c_oflag: 0x0000_0005, // OPOST | ONLCR
                        c_cflag: 0x0000_00bf, // B38400 | CS8 | CREAD
                        c_lflag: 0x0000_8a3b, // ISIG | ICANON | ECHO* | IEXTEN
                        c_line: 0,
                        c_cc: [0; 19],
                    };
                    unsafe { (argp as *mut LinuxTermios).write_volatile(tio) };
                    0
                }
                _ => neg_errno(ENOTTY),
            }
        }
        SYS_MMAP => match user::mmap(
            a0 as u64, a1 as u64, a2 as i32, a3 as i32, a4 as i32, a5 as u64,
        ) {
            Ok(addr) => {
                if (a3 as i32 & 0x20) == 0 {
                    println!(
                        "MMAP file-backed: fd={} addr={:#x} len={:#x} off={:#x} -> {:#x}",
                        a4 as i32, a0, a1, a5, addr
                    );
                }
                addr as usize
            }
            Err(err) => {
                if (a3 as i32 & 0x20) == 0 {
                    println!(
                        "MMAP file-backed err: fd={} addr={:#x} len={:#x} prot={:#x} flags={:#x} off={:#x} err={:?}",
                        a4 as i32, a0, a1, a2, a3, a5, err
                    );
                }
                neg_errno(ENOSYS)
            }
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
        SYS_RT_SIGACTION => {
            let oldact = a2 as *mut u8;
            if !oldact.is_null() {
                // Return "no handler installed" for stubbed signal support.
                unsafe { core::ptr::write_bytes(oldact, 0, 32) };
            }
            0
        }
        SYS_RT_SIGPROCMASK => {
            let oldset = a2 as *mut u8;
            let sigsetsize = a3;
            if sigsetsize == 0 || sigsetsize > 128 {
                return neg_errno(EINVAL);
            }
            if !oldset.is_null() {
                unsafe { core::ptr::write_bytes(oldset, 0, sigsetsize) };
            }
            0
        }
        SYS_NANOSLEEP => {
            user::nanosleep(0);
            0
        }
        SYS_GETPID => user::pid() as usize,
        SYS_GETUID | SYS_GETEUID | SYS_GETGID | SYS_GETEGID => 0,
        SYS_GETRESUID | SYS_GETRESGID => {
            let r1 = a0 as *mut u32;
            let r2 = a1 as *mut u32;
            let r3 = a2 as *mut u32;
            if r1.is_null() || r2.is_null() || r3.is_null() {
                return neg_errno(EFAULT);
            }
            unsafe {
                r1.write_volatile(0);
                r2.write_volatile(0);
                r3.write_volatile(0);
            }
            0
        }
        SYS_GETPPID => user::ppid() as usize,
        SYS_CLONE | SYS_FORK | SYS_VFORK => neg_errno(EAGAIN),
        SYS_WAIT4 => neg_errno(ECHILD),
        SYS_SETPGID => {
            let pid = a0 as i32;
            let pgid = a1 as i32;
            if pid < 0 || pgid < 0 {
                neg_errno(EINVAL)
            } else {
                0
            }
        }
        SYS_GETPGID => {
            let pid = a0 as i32;
            if pid < 0 {
                neg_errno(EINVAL)
            } else {
                user::pid() as usize
            }
        }
        SYS_ACCESS => {
            let path = match read_cstr(a0 as *const u8, 4096) {
                Ok(v) => v,
                Err(e) => {
                    println!("ACCESS read_cstr err ptr={:#x} err={}", a0, e);
                    return neg_errno(e);
                }
            };
            println!("ACCESS path={} mode={:#x}", path, a1);
            if vfs::exists(&path) {
                println!("ACCESS ok path={}", path);
                0
            } else {
                println!("ACCESS err path={}", path);
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
        SYS_CLOCK_GETTIME => {
            let tp = a1 as *mut LinuxTimespec;
            if tp.is_null() {
                return neg_errno(EFAULT);
            }
            unsafe {
                tp.write_volatile(LinuxTimespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                });
            }
            0
        }
        SYS_EXIT | SYS_EXIT_GROUP => process::on_task_exit(),
        SYS_OPEN => {
            if let Ok(true) = cstr_eq(a0 as *const u8, "/usr/etc/ld-musl-x86_64.path") {
                return neg_errno(ENOENT);
            }
            let path = match read_cstr(a0 as *const u8, 4096) {
                Ok(v) => v,
                Err(e) => {
                    println!("OPEN read_cstr err ptr={:#x} err={}", a0, e);
                    return neg_errno(e);
                }
            };
            println!("OPEN path={} flags={:#x}", path, a1);
            match vfs::open(&path, a1 as i32) {
                Ok(fd) => {
                    println!("OPEN ok path={} fd={}", path, fd);
                    fd as usize
                }
                Err(e) => {
                    println!("OPEN err path={} err={:?}", path, e);
                    neg_errno(from_vfs_err(e))
                }
            }
        }
        SYS_OPENAT => {
            if let Ok(true) = cstr_eq(a1 as *const u8, "/usr/etc/ld-musl-x86_64.path") {
                return neg_errno(ENOENT);
            }
            let path = match read_cstr(a1 as *const u8, 4096) {
                Ok(v) => v,
                Err(e) => {
                    println!("OPENAT read_cstr err ptr={:#x} err={}", a1, e);
                    return neg_errno(e);
                }
            };
            println!("OPENAT dirfd={} path={} flags={:#x}", a0 as i32, path, a2);
            match vfs::open(&path, a2 as i32) {
                Ok(fd) => {
                    println!("OPENAT ok path={} fd={}", path, fd);
                    fd as usize
                }
                Err(e) => {
                    println!("OPENAT err path={} err={:?}", path, e);
                    neg_errno(from_vfs_err(e))
                }
            }
        }
        SYS_FACCESSAT | SYS_FACCESSAT2 => {
            let path = match read_cstr(a1 as *const u8, 4096) {
                Ok(v) => v,
                Err(e) => {
                    println!("FACCESSAT read_cstr err ptr={:#x} err={}", a1, e);
                    return neg_errno(e);
                }
            };
            println!(
                "FACCESSAT dirfd={} path={} mode={:#x} flags={:#x}",
                a0 as i32, path, a2, a3
            );
            if vfs::exists(&path) {
                println!("FACCESSAT ok path={}", path);
                0
            } else {
                println!("FACCESSAT err path={}", path);
                neg_errno(ENOENT)
            }
        }
        SYS_NEWFSTATAT => {
            let path = match read_cstr(a1 as *const u8, 4096) {
                Ok(v) => v,
                Err(e) => {
                    println!("NEWFSTATAT read_cstr err ptr={:#x} err={}", a1, e);
                    return neg_errno(e);
                }
            };
            println!(
                "NEWFSTATAT dirfd={} path={} flags={:#x}",
                a0 as i32, path, a3
            );
            let dirfd = a0 as i32;
            let flags = a3 as i32;
            if path.is_empty() {
                if (flags & AT_EMPTY_PATH) == 0 {
                    println!("NEWFSTATAT err empty path without AT_EMPTY_PATH");
                    return neg_errno(ENOENT);
                }
                if dirfd == AT_FDCWD {
                    println!("NEWFSTATAT err empty path with AT_FDCWD");
                    return neg_errno(EINVAL);
                }
                return match vfs::fstat(dirfd) {
                    Ok(st) => {
                        println!("NEWFSTATAT ok fd={} size={}", dirfd, st.size);
                        write_stat(a2 as *mut LinuxStat, st.ino, st.mode, st.size)
                    }
                    Err(e) => {
                        println!("NEWFSTATAT fstat err fd={} err={:?}", dirfd, e);
                        neg_errno(from_vfs_err(e))
                    }
                };
            }
            let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
            match vfs::stat_path(&path, follow) {
                Ok(st) => {
                    println!("NEWFSTATAT ok path={} size={}", path, st.size);
                    write_stat(a2 as *mut LinuxStat, st.ino, st.mode, st.size)
                }
                Err(e) => {
                    println!("NEWFSTATAT err path={} err={:?}", path, e);
                    neg_errno(from_vfs_err(e))
                }
            }
        }
        SYS_STATX => {
            let dirfd = a0 as i32;
            let path = match read_cstr(a1 as *const u8, 4096) {
                Ok(v) => v,
                Err(e) => {
                    println!("STATX read_cstr err ptr={:#x} err={}", a1, e);
                    return neg_errno(e);
                }
            };
            let flags = a2 as i32;
            let mask = a3 as u32;
            println!(
                "STATX dirfd={} path={} flags={:#x} mask={:#x}",
                dirfd, path, flags, mask
            );
            if path.is_empty() {
                if (flags & AT_EMPTY_PATH) == 0 {
                    println!("STATX err empty path without AT_EMPTY_PATH");
                    return neg_errno(ENOENT);
                }
                if dirfd == AT_FDCWD {
                    println!("STATX err empty path with AT_FDCWD");
                    return neg_errno(EINVAL);
                }
                return match vfs::fstat(dirfd) {
                    Ok(st) => {
                        println!("STATX ok fd={} size={}", dirfd, st.size);
                        write_statx(a4 as *mut LinuxStatx, st.ino, st.mode, st.size, mask)
                    }
                    Err(e) => {
                        println!("STATX fstat err fd={} err={:?}", dirfd, e);
                        neg_errno(from_vfs_err(e))
                    }
                };
            }
            let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
            match vfs::stat_path(&path, follow) {
                Ok(st) => {
                    println!("STATX ok path={} size={}", path, st.size);
                    write_statx(a4 as *mut LinuxStatx, st.ino, st.mode, st.size, mask)
                }
                Err(e) => {
                    println!("STATX err path={} err={:?}", path, e);
                    neg_errno(from_vfs_err(e))
                }
            }
        }
        SYS_READLINKAT => {
            let path = match read_cstr(a1 as *const u8, 4096) {
                Ok(v) => v,
                Err(e) => {
                    println!("READLINKAT read_cstr err ptr={:#x} err={}", a1, e);
                    return neg_errno(e);
                }
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
                Err(e) => {
                    println!("EXECVE read_cstr err ptr={:#x} err={}", a0, e);
                    return neg_errno(e);
                }
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
