extern crate alloc;

use crate::arch::{ARCH_NAME, DYNLINK_CONF, DYNLINK_PATH, SyscallFrame, MAX_CPUS};
use crate::{kdebug, ktrace, kwarn, process, user, vfs};
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const E2BIG: i32 = 7;
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
const EPIPE: i32 = 32;
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
const SYS_FADVISE64: usize = 221;
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
const TCSETS: usize = 0x5402;
const TCSETSW: usize = 0x5403;
const TCSETSF: usize = 0x5404;
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

const SYSCALL_STACK_SIZE: usize = 4096 * 16;

#[repr(align(16))]
struct SyscallStack([u8; SYSCALL_STACK_SIZE]);

static mut SYSCALL_STACKS: [SyscallStack; MAX_CPUS] =
    [const { SyscallStack([0; SYSCALL_STACK_SIZE]) }; MAX_CPUS];

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

#[repr(C)]
struct LinuxPollFd {
    fd: i32,
    events: i16,
    revents: i16,
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
        vfs::VfsError::WouldBlock => EAGAIN,
        vfs::VfsError::BrokenPipe => EPIPE,
    }
}

fn from_user_err(err: user::UserError) -> i32 {
    match err {
        user::UserError::InvalidFd => EBADF,
        user::UserError::InvalidElf => ENOENT,
        user::UserError::Unsupported => ENOSYS,
        user::UserError::Vfs | user::UserError::Vm => EIO,
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
    init_for_cpu(0);
}

pub fn init_for_cpu(cpu_id: usize) {
    let cpu = cpu_id.min(MAX_CPUS.saturating_sub(1));
    let stack_top =
        unsafe { core::ptr::addr_of!(SYSCALL_STACKS[cpu]) as *const u8 as usize + SYSCALL_STACK_SIZE };
    crate::arch::init_syscalls(cpu, stack_top);
}

pub fn set_kernel_stack_top(stack_top: usize) {
    let cpu = crate::arch::smp::current_cpu().min(MAX_CPUS.saturating_sub(1));
    crate::arch::set_kernel_stack_top(cpu, stack_top);
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

fn read_cstr_array(ptr: *const *const u8, max_count: usize) -> Result<Vec<String>, i32> {
    if ptr.is_null() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for idx in 0..max_count {
        let item = unsafe { ptr.add(idx).read_volatile() };
        if item.is_null() {
            return Ok(out);
        }
        out.push(read_cstr(item, 4096)?);
    }
    Err(E2BIG)
}

fn apply_saved_context(frame: &mut SyscallFrame, ctx: &crate::arch::SavedTaskContext) {
    frame.r15 = ctx.r15;
    frame.r14 = ctx.r14;
    frame.r13 = ctx.r13;
    frame.r12 = ctx.r12;
    frame.r11 = ctx.rflags;
    frame.r10 = ctx.r10;
    frame.r9 = ctx.r9;
    frame.r8 = ctx.r8;
    frame.rbp = ctx.rbp;
    frame.rdi = ctx.rdi;
    frame.rsi = ctx.rsi;
    frame.rdx = ctx.rdx;
    frame.rcx = ctx.rip;
    frame.user_rsp = ctx.rsp;
    frame.nr = ctx.rax;
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
    copy_field(&mut out.sysname, b"Linux");
    copy_field(&mut out.nodename, b"qemu");
    copy_field(&mut out.release, b"6.7");
    copy_field(&mut out.version, b"#67");
    copy_field(&mut out.machine, ARCH_NAME.as_bytes());
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
        kwarn!("SYSCALL: unimplemented nr={}", nr);
    }
}

#[unsafe(no_mangle)]
extern "C" fn syscall_dispatch(frame: *mut SyscallFrame) -> usize {
    if frame.is_null() {
        return neg_errno(EFAULT);
    }
    let frame = unsafe { &mut *frame };
    let nr = frame.nr;
    let a0 = frame.a0;
    let a1 = frame.a1;
    let a2 = frame.a2;
    let a3 = frame.a3;
    let a4 = frame.a4;
    let a5 = frame.a5;
    let trace_idx = SYSCALL_TRACE_COUNT.fetch_add(1, Ordering::SeqCst);
    if trace_idx < 2048 && nr != SYS_WRITEV {
        ktrace!(
            "SYSCALL: nr={} a0={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x} a5={:#x}",
            nr,
            a0,
            a1,
            a2,
            a3,
            a4,
            a5
        );
    }
    if nr == SYS_FORK || nr == SYS_SET_TID_ADDRESS || nr == SYS_RT_SIGPROCMASK {
        kdebug!(
            "SYSCALL frame: nr={} rcx={:#x} rsp={:#x} r11={:#x} fsbase={:#x} rdi={:#x} rsi={:#x} rdx={:#x} r10={:#x}",
            nr,
            frame.rcx,
            frame.user_rsp,
            frame.r11,
            crate::arch::get_fs_base(),
            frame.rdi,
            frame.rsi,
            frame.rdx,
            frame.r10
        );
        if frame.user_rsp != 0 {
            let sp = frame.user_rsp as *const usize;
            let q0 = unsafe { sp.read_volatile() };
            let q1 = unsafe { sp.add(1).read_volatile() };
            let q2 = unsafe { sp.add(2).read_volatile() };
            let q19 = unsafe { sp.add(19).read_volatile() };
            let q20 = unsafe { sp.add(20).read_volatile() };
            kdebug!(
                "SYSCALL stack: nr={} [rsp]={:#x} [rsp+8]={:#x} [rsp+16]={:#x} [rsp+0x98]={:#x} [rsp+0xa0]={:#x}",
                nr,
                q0,
                q1,
                q2,
                q19,
                q20
            );
        }
        if nr == SYS_SET_TID_ADDRESS && frame.rdx != 0 {
            let tcb = frame.rdx as *const usize;
            let q0 = unsafe { tcb.read_volatile() };
            let q6 = unsafe { tcb.add(6).read_volatile() };
            let q18 = unsafe { tcb.add(18).read_volatile() };
            let q19 = unsafe { tcb.add(19).read_volatile() };
            kdebug!(
                "SYSCALL tcb: self={:#x} [0]={:#x} [0x30]={:#x} [0x90]={:#x} [0x98]={:#x}",
                frame.rdx,
                q0,
                q6,
                q18,
                q19
            );
        }
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
                user::path_of_fd(fd).ok()
            } else {
                None
            };
            let handle = match user::handle_for_fd(fd) {
                Ok(handle) => handle,
                Err(err) => return neg_errno(from_user_err(err)),
            };
            match vfs::read(handle, out) {
                Ok(n) => {
                    if let Some(path) = path.as_deref() {
                        ktrace!("READ fd={} path={} len={} -> {}", fd, path, len, n);
                    }
                    n
                }
                Err(e) => {
                    if let Some(path) = path.as_deref() {
                        ktrace!("READ err fd={} path={} len={} err={:?}", fd, path, len, e);
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
            let handle = match user::handle_for_fd(fd) {
                Ok(handle) => handle,
                Err(err) => return neg_errno(from_user_err(err)),
            };
            let mut total = 0usize;
            for idx in 0..iovcnt {
                let ent = unsafe { &mut *(iov.add(idx) as *mut LinuxIovec) };
                if ent.iov_base.is_null() {
                    return neg_errno(EFAULT);
                }
                let out = unsafe {
                    core::slice::from_raw_parts_mut(ent.iov_base as *mut u8, ent.iov_len)
                };
                match vfs::read(handle, out) {
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
            let handle = match user::handle_for_fd(fd) {
                Ok(handle) => handle,
                Err(err) => return neg_errno(from_user_err(err)),
            };
            match vfs::write(handle, data) {
                Ok(n) => n,
                Err(e) => neg_errno(from_vfs_err(e)),
            }
        }
        SYS_WRITEV => {
            let fd = a0 as i32;
            let iov = a1 as *const LinuxIovec;
            let iovcnt = a2;
            if iov.is_null() {
                return neg_errno(EFAULT);
            }
            let handle = match user::handle_for_fd(fd) {
                Ok(handle) => handle,
                Err(err) => return neg_errno(from_user_err(err)),
            };
            let mut total = 0usize;
            for idx in 0..iovcnt {
                let ent = unsafe { &*iov.add(idx) };
                if ent.iov_base.is_null() {
                    return neg_errno(EFAULT);
                }
                let data = unsafe { core::slice::from_raw_parts(ent.iov_base, ent.iov_len) };
                let wrote = match vfs::write(handle, data) {
                    Ok(n) => n,
                    Err(e) => return neg_errno(from_vfs_err(e)),
                };
                total = total.saturating_add(wrote);
                if wrote < ent.iov_len {
                    break;
                }
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
            let (rhandle, whandle) = match vfs::create_pipe() {
                Ok(handles) => handles,
                Err(e) => return neg_errno(from_vfs_err(e)),
            };
            let rfd = match user::install_fd(rhandle, 0, 0) {
                Ok(fd) => fd,
                Err(e) => {
                    let _ = vfs::close(rhandle);
                    let _ = vfs::close(whandle);
                    return neg_errno(from_user_err(e));
                }
            };
            let wfd = match user::install_fd(whandle, 0, 0) {
                Ok(fd) => fd,
                Err(e) => {
                    let _ = user::close_fd(rfd);
                    let _ = vfs::close(whandle);
                    return neg_errno(from_user_err(e));
                }
            };
            unsafe {
                pipefd.write_volatile(rfd);
                pipefd.add(1).write_volatile(wfd);
            }
            if nr == SYS_PIPE2 {
                let flags = a1 as i32;
                if (flags & 0x80000) != 0 {
                    let _ = user::set_fd_flags(rfd, FD_CLOEXEC);
                    let _ = user::set_fd_flags(wfd, FD_CLOEXEC);
                }
            }
            0
        }
        SYS_CLOSE => {
            let fd = a0 as i32;
            let path = if fd >= 3 {
                user::path_of_fd(fd).ok()
            } else {
                None
            };
            match user::close_fd(fd) {
                Ok(()) => {
                    if let Some(path) = path.as_deref() {
                        ktrace!("CLOSE fd={} path={}", fd, path);
                    }
                    0
                }
                Err(e) => {
                    if let Some(path) = path.as_deref() {
                        ktrace!("CLOSE err fd={} path={} err={:?}", fd, path, e);
                    }
                    neg_errno(from_user_err(e))
                }
            }
        }
        SYS_STAT => {
            let path = match read_cstr(a0 as *const u8, 4096) {
                Ok(v) => v,
                Err(e) => {
                    kdebug!("STAT read_cstr err ptr={:#x} err={}", a0, e);
                    return neg_errno(e);
                }
            };
            ktrace!("STAT path={}", path);
            match vfs::stat_path(&path, true) {
                Ok(st) => {
                    ktrace!("STAT ok path={} size={}", path, st.size);
                    write_stat(a1 as *mut LinuxStat, st.ino, st.mode, st.size)
                }
                Err(e) => {
                    ktrace!("STAT err path={} err={:?}", path, e);
                    neg_errno(from_vfs_err(e))
                }
            }
        }
        SYS_FSTAT => match user::handle_for_fd(a0 as i32)
            .map_err(from_user_err)
            .and_then(|handle| vfs::fstat(handle).map_err(from_vfs_err))
        {
            Ok(st) => {
                if let Ok(path) = user::path_of_fd(a0 as i32) {
                    ktrace!("FSTAT fd={} path={} size={}", a0 as i32, path, st.size);
                }
                write_stat(a1 as *mut LinuxStat, st.ino, st.mode, st.size)
            }
            Err(e) => {
                if let Ok(path) = user::path_of_fd(a0 as i32) {
                    ktrace!("FSTAT err fd={} path={} err={:?}", a0 as i32, path, e);
                } else {
                    ktrace!("FSTAT err fd={} err={:?}", a0 as i32, e);
                }
                neg_errno(e)
            }
        },
        SYS_LSTAT => {
            let path = match read_cstr(a0 as *const u8, 4096) {
                Ok(v) => v,
                Err(e) => {
                    kdebug!("LSTAT read_cstr err ptr={:#x} err={}", a0, e);
                    return neg_errno(e);
                }
            };
            ktrace!("LSTAT path={}", path);
            match vfs::stat_path(&path, false) {
                Ok(st) => {
                    ktrace!("LSTAT ok path={} size={}", path, st.size);
                    write_stat(a1 as *mut LinuxStat, st.ino, st.mode, st.size)
                }
                Err(e) => {
                    ktrace!("LSTAT err path={} err={:?}", path, e);
                    neg_errno(from_vfs_err(e))
                }
            }
        }
        SYS_FCNTL => {
            let fd = a0 as i32;
            let cmd = a1 as i32;
            let arg = a2 as i32;
            if let Ok(path) = user::path_of_fd(fd) {
                ktrace!("FCNTL fd={} path={} cmd={} arg={:#x}", fd, path, cmd, arg);
            } else {
                ktrace!("FCNTL fd={} cmd={} arg={:#x}", fd, cmd, arg);
            }
            match cmd {
                F_GETFD => match user::get_fd_flags(fd) {
                    Ok(flags) => flags as usize,
                    Err(e) => neg_errno(from_user_err(e)),
                },
                F_SETFD => match user::set_fd_flags(fd, arg & FD_CLOEXEC) {
                    Ok(()) => 0,
                    Err(e) => neg_errno(from_user_err(e)),
                },
                F_GETFL => match user::get_status_flags(fd) {
                    Ok(flags) => flags as usize,
                    Err(e) => neg_errno(from_user_err(e)),
                },
                F_SETFL => match user::set_status_flags(fd, arg) {
                    Ok(()) => 0,
                    Err(e) => neg_errno(from_user_err(e)),
                },
                F_DUPFD | F_DUPFD_CLOEXEC => match user::dup_fd(fd, arg, cmd == F_DUPFD_CLOEXEC) {
                    Ok(new_fd) => new_fd as usize,
                    Err(e) => neg_errno(from_user_err(e)),
                },
                _ => neg_errno(ENOSYS),
            }
        }
        SYS_DUP => match user::dup_fd(a0 as i32, 0, false) {
            Ok(new_fd) => new_fd as usize,
            Err(e) => neg_errno(from_user_err(e)),
        },
        SYS_DUP2 => {
            let oldfd = a0 as i32;
            let newfd = a1 as i32;
            if oldfd == newfd {
                if user::path_of_fd(oldfd).is_ok() {
                    oldfd as usize
                } else {
                    neg_errno(EBADF)
                }
            } else {
                match user::dup2_fd(oldfd, newfd, false) {
                    Ok(fd) => fd as usize,
                    Err(e) => neg_errno(from_user_err(e)),
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
                user::path_of_fd(fd).ok()
            } else {
                None
            };
            let handle = match user::handle_for_fd(fd) {
                Ok(handle) => handle,
                Err(err) => return neg_errno(from_user_err(err)),
            };
            match vfs::pread(handle, offset, out) {
                Ok(n) => {
                    if let Some(path) = path.as_deref() {
                        ktrace!(
                            "PREAD64 fd={} path={} off={:#x} len={} -> {}",
                            fd,
                            path,
                            offset,
                            len,
                            n
                        );
                    }
                    n
                }
                Err(e) => {
                    if let Some(path) = path.as_deref() {
                        ktrace!(
                            "PREAD64 err fd={} path={} off={:#x} len={} err={:?}",
                            fd,
                            path,
                            offset,
                            len,
                            e
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
            let handle = match user::handle_for_fd(fd) {
                Ok(handle) => handle,
                Err(err) => return neg_errno(from_user_err(err)),
            };
            let entries = match vfs::list_dir_entries(handle) {
                Ok(v) => v,
                Err(e) => return neg_errno(from_vfs_err(e)),
            };
            let mut index = match vfs::get_dir_offset(handle) {
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

            let _ = vfs::set_dir_offset(handle, index as u64);
            written
        }
        SYS_LSEEK => match user::handle_for_fd(a0 as i32)
            .map_err(from_user_err)
            .and_then(|handle| vfs::lseek(handle, a1 as i64, a2 as i32).map_err(from_vfs_err))
        {
            Ok(v) => v as usize,
            Err(e) => neg_errno(e),
        },
        SYS_IOCTL => {
            let fd = a0 as i32;
            let req = a1;
            let argp = a2 as *mut u8;
            let handle = match user::handle_for_fd(fd) {
                Ok(handle) => handle,
                Err(err) => return neg_errno(from_user_err(err)),
            };
            if !vfs::is_special_tty(handle).unwrap_or(false) {
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
                        c_iflag: crate::arch::serial::tty_iflag(),
                        c_oflag: crate::arch::serial::tty_oflag(),
                        c_cflag: crate::arch::serial::tty_cflag(),
                        c_lflag: crate::arch::serial::tty_lflag(),
                        c_line: 0,
                        c_cc: [0; 19],
                    };
                    unsafe { (argp as *mut LinuxTermios).write_volatile(tio) };
                    0
                }
                TCSETS | TCSETSW | TCSETSF => {
                    if argp.is_null() {
                        return neg_errno(EFAULT);
                    }
                    let tio = unsafe { (argp as *const LinuxTermios).read_volatile() };
                    crate::arch::serial::set_tty_termios(
                        tio.c_iflag,
                        tio.c_oflag,
                        tio.c_cflag,
                        tio.c_lflag,
                    );
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
                    ktrace!(
                        "MMAP file-backed: fd={} addr={:#x} len={:#x} off={:#x} -> {:#x}",
                        a4 as i32,
                        a0,
                        a1,
                        a5,
                        addr
                    );
                }
                addr as usize
            }
            Err(err) => {
                if (a3 as i32 & 0x20) == 0 {
                    kdebug!(
                        "MMAP file-backed err: fd={} addr={:#x} len={:#x} prot={:#x} flags={:#x} off={:#x} err={:?}",
                        a4 as i32,
                        a0,
                        a1,
                        a2,
                        a3,
                        a5,
                        err
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
        SYS_CLONE | SYS_FORK | SYS_VFORK => match user::fork_from_syscall(frame) {
            Ok(pid) => pid as usize,
            Err(_) => neg_errno(ENOSYS),
        },
        SYS_WAIT4 => match user::wait4(a0 as i32, a1 as *mut i32) {
            Ok(pid) => pid as usize,
            Err(_) => neg_errno(ECHILD),
        },
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
                    kdebug!("ACCESS read_cstr err ptr={:#x} err={}", a0, e);
                    return neg_errno(e);
                }
            };
            ktrace!("ACCESS path={} mode={:#x}", path, a1);
            if vfs::exists(&path) {
                ktrace!("ACCESS ok path={}", path);
                0
            } else {
                ktrace!("ACCESS err path={}", path);
                neg_errno(ENOENT)
            }
        }
        SYS_GETCWD => {
            let dst = a0 as *mut u8;
            let len = a1;
            if dst.is_null() || len == 0 {
                return neg_errno(EFAULT);
            }
            let cwd = user::cwd();
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
        SYS_EXIT | SYS_EXIT_GROUP => {
            user::exit_current(a0 as i32);
            process::on_task_exit()
        }
        SYS_OPEN => {
            if let Ok(true) = cstr_eq(a0 as *const u8, DYNLINK_CONF) {
                return neg_errno(ENOENT);
            }
            let path = match read_cstr(a0 as *const u8, 4096) {
                Ok(v) => v,
                Err(e) => {
                    kdebug!("OPEN read_cstr err ptr={:#x} err={}", a0, e);
                    return neg_errno(e);
                }
            };
            ktrace!("OPEN path={} flags={:#x}", path, a1);
            match user::open_fd(&path, a1 as i32) {
                Ok(fd) => {
                    ktrace!("OPEN ok path={} fd={}", path, fd);
                    fd as usize
                }
                Err(e) => {
                    ktrace!("OPEN err path={} err={:?}", path, e);
                    neg_errno(from_user_err(e))
                }
            }
        }
        SYS_OPENAT => {
            if let Ok(true) = cstr_eq(a1 as *const u8, DYNLINK_CONF) {
                return neg_errno(ENOENT);
            }
            let path = match read_cstr(a1 as *const u8, 4096) {
                Ok(v) => v,
                Err(e) => {
                    kdebug!("OPENAT read_cstr err ptr={:#x} err={}", a1, e);
                    return neg_errno(e);
                }
            };
            ktrace!("OPENAT dirfd={} path={} flags={:#x}", a0 as i32, path, a2);
            match user::open_fd(&path, a2 as i32) {
                Ok(fd) => {
                    ktrace!("OPENAT ok path={} fd={}", path, fd);
                    fd as usize
                }
                Err(e) => {
                    ktrace!("OPENAT err path={} err={:?}", path, e);
                    neg_errno(from_user_err(e))
                }
            }
        }
        SYS_FACCESSAT | SYS_FACCESSAT2 => {
            let path = match read_cstr(a1 as *const u8, 4096) {
                Ok(v) => v,
                Err(e) => {
                    kdebug!("FACCESSAT read_cstr err ptr={:#x} err={}", a1, e);
                    return neg_errno(e);
                }
            };
            ktrace!(
                "FACCESSAT dirfd={} path={} mode={:#x} flags={:#x}",
                a0 as i32,
                path,
                a2,
                a3
            );
            if vfs::exists(&path) {
                ktrace!("FACCESSAT ok path={}", path);
                0
            } else {
                ktrace!("FACCESSAT err path={}", path);
                neg_errno(ENOENT)
            }
        }
        SYS_NEWFSTATAT => {
            let path = match read_cstr(a1 as *const u8, 4096) {
                Ok(v) => v,
                Err(e) => {
                    kdebug!("NEWFSTATAT read_cstr err ptr={:#x} err={}", a1, e);
                    return neg_errno(e);
                }
            };
            ktrace!(
                "NEWFSTATAT dirfd={} path={} flags={:#x}",
                a0 as i32,
                path,
                a3
            );
            let dirfd = a0 as i32;
            let flags = a3 as i32;
            if path.is_empty() {
                if (flags & AT_EMPTY_PATH) == 0 {
                    kdebug!("NEWFSTATAT err empty path without AT_EMPTY_PATH");
                    return neg_errno(ENOENT);
                }
                if dirfd == AT_FDCWD {
                    kdebug!("NEWFSTATAT err empty path with AT_FDCWD");
                    return neg_errno(EINVAL);
                }
                let handle = match user::handle_for_fd(dirfd) {
                    Ok(handle) => handle,
                    Err(err) => return neg_errno(from_user_err(err)),
                };
                return match vfs::fstat(handle) {
                    Ok(st) => {
                        ktrace!("NEWFSTATAT ok fd={} size={}", dirfd, st.size);
                        write_stat(a2 as *mut LinuxStat, st.ino, st.mode, st.size)
                    }
                    Err(e) => {
                        ktrace!("NEWFSTATAT fstat err fd={} err={:?}", dirfd, e);
                        neg_errno(from_vfs_err(e))
                    }
                };
            }
            let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
            match vfs::stat_path(&path, follow) {
                Ok(st) => {
                    ktrace!("NEWFSTATAT ok path={} size={}", path, st.size);
                    write_stat(a2 as *mut LinuxStat, st.ino, st.mode, st.size)
                }
                Err(e) => {
                    ktrace!("NEWFSTATAT err path={} err={:?}", path, e);
                    neg_errno(from_vfs_err(e))
                }
            }
        }
        SYS_STATX => {
            let dirfd = a0 as i32;
            let path = match read_cstr(a1 as *const u8, 4096) {
                Ok(v) => v,
                Err(e) => {
                    kdebug!("STATX read_cstr err ptr={:#x} err={}", a1, e);
                    return neg_errno(e);
                }
            };
            let flags = a2 as i32;
            let mask = a3 as u32;
            ktrace!(
                "STATX dirfd={} path={} flags={:#x} mask={:#x}",
                dirfd,
                path,
                flags,
                mask
            );
            if path.is_empty() {
                if (flags & AT_EMPTY_PATH) == 0 {
                    kdebug!("STATX err empty path without AT_EMPTY_PATH");
                    return neg_errno(ENOENT);
                }
                if dirfd == AT_FDCWD {
                    kdebug!("STATX err empty path with AT_FDCWD");
                    return neg_errno(EINVAL);
                }
                let handle = match user::handle_for_fd(dirfd) {
                    Ok(handle) => handle,
                    Err(err) => return neg_errno(from_user_err(err)),
                };
                return match vfs::fstat(handle) {
                    Ok(st) => {
                        ktrace!("STATX ok fd={} size={}", dirfd, st.size);
                        write_statx(a4 as *mut LinuxStatx, st.ino, st.mode, st.size, mask)
                    }
                    Err(e) => {
                        ktrace!("STATX fstat err fd={} err={:?}", dirfd, e);
                        neg_errno(from_vfs_err(e))
                    }
                };
            }
            let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
            match vfs::stat_path(&path, follow) {
                Ok(st) => {
                    ktrace!("STATX ok path={} size={}", path, st.size);
                    write_statx(a4 as *mut LinuxStatx, st.ino, st.mode, st.size, mask)
                }
                Err(e) => {
                    ktrace!("STATX err path={} err={:?}", path, e);
                    neg_errno(from_vfs_err(e))
                }
            }
        }
        SYS_READLINKAT => {
            let path = match read_cstr(a1 as *const u8, 4096) {
                Ok(v) => v,
                Err(e) => {
                    kdebug!("READLINKAT read_cstr err ptr={:#x} err={}", a1, e);
                    return neg_errno(e);
                }
            };
            let out = a2 as *mut u8;
            let size = a3;
            if out.is_null() {
                return neg_errno(EFAULT);
            }
            if path == "/proc/self/exe" {
                let exe = user::current_init_path()
                    .unwrap_or_else(|| "/bin/sh".into())
                    .into_bytes();
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
                    kdebug!("EXECVE read_cstr err ptr={:#x} err={}", a0, e);
                    return neg_errno(e);
                }
            };
            let argv = match read_cstr_array(a1 as *const *const u8, 128) {
                Ok(argv) => argv,
                Err(e) => return neg_errno(e),
            };
            let envp = match read_cstr_array(a2 as *const *const u8, 256) {
                Ok(envp) => envp,
                Err(e) => return neg_errno(e),
            };
            let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            let envp_refs: Vec<&str> = envp.iter().map(String::as_str).collect();
            match user::execve(&path, &argv_refs, &envp_refs) {
                Ok(ctx) => {
                    kdebug!(
                        "SYSCALL: execve path={} rip={:#x} rsp={:#x}",
                        path,
                        ctx.rip,
                        ctx.rsp
                    );
                    apply_saved_context(frame, &ctx);
                    0
                }
                Err(err) => {
                    kdebug!("SYSCALL: execve path={} err={:?}", path, err);
                    neg_errno(ENOENT)
                }
            }
        }
        SYS_UNAME => write_uts(a0 as *mut LinuxUtsname),
        SYS_SET_ROBUST_LIST => 0,
        SYS_PRLIMIT64 => 0,
        SYS_FADVISE64 => 0,
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
        SYS_POLL | SYS_PPOLL => {
            let fds = a0 as *mut LinuxPollFd;
            let nfds = a1;
            if nfds == 0 {
                return 0;
            }
            if fds.is_null() {
                return neg_errno(EFAULT);
            }
            let mut ready = 0usize;
            for idx in 0..nfds {
                let pfd = unsafe { &mut *fds.add(idx) };
                pfd.revents = 0;
                let handle = match user::handle_for_fd(pfd.fd) {
                    Ok(handle) => handle,
                    Err(_) => continue,
                };
                if let Ok(mask) = vfs::poll_mask(handle) {
                    pfd.revents |= pfd.events & mask;
                }
                if pfd.revents != 0 {
                    ready += 1;
                }
            }
            ready
        }
        _ => {
            log_unknown_once(nr);
            neg_errno(ENOSYS)
        }
    }
}
