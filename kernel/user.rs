extern crate alloc;

use crate::vfs;
use crate::{allocator, gdt, process};
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use goblin::elf::Elf;
use goblin::elf::program_header::{PT_LOAD, PT_PHDR};
use spin::{Lazy, Mutex};
use x86_64::VirtAddr;
use x86_64::registers::model_specific::FsBase;
use x86_64::structures::paging::{Page, PageSize, PageTableFlags, Size4KiB};

const PAGE_SIZE: u64 = Size4KiB::SIZE;
const USER_STACK_TOP: u64 = 0x0000_7fff_ff00_0000;
const USER_STACK_PAGES: u64 = 16;
const USER_MAIN_BASE: u64 = 0x0000_0000_4000_0000;
const USER_INTERP_BASE: u64 = 0x0000_0000_7000_0000;
const USER_MMAP_BASE: u64 = 0x0000_0000_5000_0000;

const PROT_READ: i32 = 0x1;
const PROT_WRITE: i32 = 0x2;
const PROT_EXEC: i32 = 0x4;
const MAP_FIXED: i32 = 0x10;
const MAP_ANONYMOUS: i32 = 0x20;

const ARCH_SET_FS: usize = 0x1002;
const ARCH_GET_FS: usize = 0x1003;

const AT_NULL: usize = 0;
const AT_PHDR: usize = 3;
const AT_PHENT: usize = 4;
const AT_PHNUM: usize = 5;
const AT_PAGESZ: usize = 6;
const AT_BASE: usize = 7;
const AT_ENTRY: usize = 9;
const AT_UID: usize = 11;
const AT_EUID: usize = 12;
const AT_GID: usize = 13;
const AT_EGID: usize = 14;
const AT_SECURE: usize = 23;
const AT_RANDOM: usize = 25;
const AT_EXECFN: usize = 31;

#[derive(Debug, Clone)]
pub struct UserProcess {
    pub pid: u32,
    pub ppid: u32,
    pub cwd: String,
    pub brk: u64,
    pub tid_addr: u64,
    pub init_path: Option<String>,
    pub fs_base: u64,
    pub next_mmap_base: u64,
    pub mappings: BTreeMap<u64, UserMapping>,
    pub task_id: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
pub struct UserMapping {
    pub start: u64,
    pub len: u64,
    pub prot: i32,
}

impl Default for UserProcess {
    fn default() -> Self {
        Self {
            pid: 1,
            ppid: 0,
            cwd: "/".to_string(),
            brk: USER_MMAP_BASE,
            tid_addr: 0,
            init_path: None,
            fs_base: 0,
            next_mmap_base: USER_MMAP_BASE,
            mappings: BTreeMap::new(),
            task_id: None,
        }
    }
}

pub static CURRENT: Lazy<Mutex<UserProcess>> = Lazy::new(|| Mutex::new(UserProcess::default()));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserError {
    Vfs,
    InvalidElf,
    Vm,
    Unsupported,
}

struct LoadedElf {
    entry: u64,
    phdr_addr: u64,
    phentsize: usize,
    phnum: usize,
    load_base: u64,
    brk_end: u64,
}

struct InitialStack {
    rsp: u64,
    argc: usize,
    argv_ptr: u64,
    envp_ptr: u64,
}

pub fn bootstrap_init(path: &str) -> Result<(), UserError> {
    let bytes = vfs::read_all(path).map_err(|_| UserError::Vfs)?;
    validate_elf(&bytes)?;
    let mut p = CURRENT.lock();
    p.init_path = Some(path.to_string());
    Ok(())
}

fn validate_elf(bytes: &[u8]) -> Result<Elf<'_>, UserError> {
    let elf = Elf::parse(bytes).map_err(|_| UserError::InvalidElf)?;
    if !elf.is_64 {
        return Err(UserError::InvalidElf);
    }
    Ok(elf)
}

pub fn pid() -> u32 {
    CURRENT.lock().pid
}

pub fn ppid() -> u32 {
    CURRENT.lock().ppid
}

pub fn set_tid_address(addr: u64) {
    CURRENT.lock().tid_addr = addr;
}

pub fn brk(new_brk: Option<u64>) -> u64 {
    let mut p = CURRENT.lock();
    if let Some(v) = new_brk {
        let target = align_up(v, PAGE_SIZE);
        if target > p.brk {
            let start = p.brk;
            let len = target - start;
            drop(p);
            let _ = map_region(start, len, PROT_READ | PROT_WRITE);
            p = CURRENT.lock();
        }
        p.brk = target;
    }
    p.brk
}

pub fn cwd() -> String {
    CURRENT.lock().cwd.clone()
}

pub fn nanosleep(_ns: u64) {}

pub fn arch_prctl(code: usize, addr: u64) -> Result<u64, UserError> {
    match code {
        ARCH_SET_FS => {
            FsBase::write(VirtAddr::new(addr));
            CURRENT.lock().fs_base = addr;
            Ok(0)
        }
        ARCH_GET_FS => Ok(CURRENT.lock().fs_base),
        _ => Err(UserError::Unsupported),
    }
}

pub fn create_init_task(task_id: usize, path: &str) -> Result<process::Task, UserError> {
    let bash_argv = [
        path,
        "--noprofile",
        "--norc",
        "-c",
        "echo gentoo-userspace-online; while :; do :; done",
    ];
    let default_argv = [path];
    let argv = if path == "/usr/bin/bash" {
        &bash_argv[..]
    } else {
        &default_argv[..]
    };
    let envp = ["HOME=/", "PATH=/bin:/usr/bin:/sbin:/usr/sbin", "TERM=linux"];
    load_task_from_elf(task_id, path, &argv, &envp)
}

pub fn execve(path: &str, _argv: &[&str], _envp: &[&str]) -> Result<(), UserError> {
    let bytes = vfs::read_all(path).map_err(|_| UserError::Vfs)?;
    validate_elf(&bytes)?;
    let mut p = CURRENT.lock();
    p.init_path = Some(path.to_string());
    Ok(())
}

pub fn mmap(
    addr: u64,
    len: u64,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: u64,
) -> Result<u64, UserError> {
    if len == 0 {
        return Err(UserError::Unsupported);
    }
    let len = align_up(len, PAGE_SIZE);
    let start = if (flags & MAP_FIXED) != 0 && addr != 0 {
        align_down(addr, PAGE_SIZE)
    } else {
        let mut state = CURRENT.lock();
        let next = align_up(state.next_mmap_base, PAGE_SIZE);
        state.next_mmap_base = next.saturating_add(len);
        next
    };

    map_region(start, len, prot)?;
    if (flags & MAP_ANONYMOUS) == 0 && fd >= 0 {
        let mut remaining = len;
        let mut page_off = 0u64;
        while remaining != 0 {
            let page_len = remaining.min(PAGE_SIZE);
            let mut buf = vec![0u8; page_len as usize];
            let n = vfs::pread(fd, offset + page_off, &mut buf).map_err(|_| UserError::Vfs)?;
            unsafe {
                core::ptr::copy_nonoverlapping(buf.as_ptr(), (start + page_off) as *mut u8, n);
            }
            remaining -= page_len;
            page_off += page_len;
        }
    }
    CURRENT
        .lock()
        .mappings
        .insert(start, UserMapping { start, len, prot });
    Ok(start)
}

pub fn munmap(addr: u64, len: u64) -> Result<(), UserError> {
    let start = align_down(addr, PAGE_SIZE);
    let len = align_up(len, PAGE_SIZE);
    let page_count = len / PAGE_SIZE;
    for idx in 0..page_count {
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(start + idx * PAGE_SIZE));
        if let Ok(frame) = allocator::unmap_page(page) {
            let _ = allocator::deallocate_frame(frame);
        }
    }
    CURRENT.lock().mappings.remove(&start);
    Ok(())
}

pub fn mprotect(_addr: u64, _len: u64, _prot: i32) -> Result<(), UserError> {
    Ok(())
}

fn load_task_from_elf(
    task_id: usize,
    path: &str,
    argv: &[&str],
    envp: &[&str],
) -> Result<process::Task, UserError> {
    let bytes = vfs::read_all(path).map_err(|_| UserError::Vfs)?;
    let elf = validate_elf(&bytes)?;

    let main_base = if elf.header.e_type == goblin::elf::header::ET_DYN {
        USER_MAIN_BASE
    } else {
        0
    };
    let main = load_elf_image(&bytes, &elf, main_base)?;

    let interp_path = elf.interpreter.map(str::to_string);
    let interp = if let Some(ref interp_path) = interp_path {
        let interp_bytes = vfs::read_all(interp_path).map_err(|_| UserError::Vfs)?;
        let interp_elf = validate_elf(&interp_bytes)?;
        Some(load_elf_image(
            &interp_bytes,
            &interp_elf,
            USER_INTERP_BASE,
        )?)
    } else {
        None
    };

    let stack_bottom = USER_STACK_TOP - USER_STACK_PAGES * PAGE_SIZE;
    map_region(
        stack_bottom,
        USER_STACK_PAGES * PAGE_SIZE,
        PROT_READ | PROT_WRITE,
    )?;
    let stack = build_initial_stack(USER_STACK_TOP, path, argv, envp, &main, interp.as_ref())?;

    let entry = interp
        .as_ref()
        .map(|image| image.entry)
        .unwrap_or(main.entry);

    {
        let mut state = CURRENT.lock();
        state.init_path = Some(path.to_string());
        state.task_id = Some(task_id);
        state.brk = align_up(main.brk_end.max(USER_MMAP_BASE), PAGE_SIZE);
        state.next_mmap_base = state.brk.saturating_add(PAGE_SIZE);
    }

    let ctx = process::SavedTaskContext {
        rip: entry as usize,
        cs: usize::from(gdt::user_code_selector().0),
        rflags: 0x2,
        rsp: stack.rsp as usize,
        ss: usize::from(gdt::user_data_selector().0),
        rdi: stack.argc,
        rsi: stack.argv_ptr as usize,
        rdx: stack.envp_ptr as usize,
        ..process::SavedTaskContext::default()
    };

    Ok(process::Task::with_initial_context(
        task_id,
        0,
        ctx,
        process::SchedParams::default(),
    ))
}

fn load_elf_image(bytes: &[u8], elf: &Elf<'_>, base: u64) -> Result<LoadedElf, UserError> {
    let mut brk_end = 0u64;
    for ph in &elf.program_headers {
        if ph.p_type != PT_LOAD {
            continue;
        }
        let seg_start = base + align_down(ph.p_vaddr, PAGE_SIZE);
        let seg_end = base + align_up(ph.p_vaddr + ph.p_memsz, PAGE_SIZE);
        let seg_len = seg_end.saturating_sub(seg_start);
        let prot = ph_to_prot(ph.p_flags);
        map_region(seg_start, seg_len, prot)?;
        let file_start = usize::try_from(ph.p_offset).map_err(|_| UserError::InvalidElf)?;
        let file_end =
            usize::try_from(ph.p_offset + ph.p_filesz).map_err(|_| UserError::InvalidElf)?;
        if file_end > bytes.len() {
            return Err(UserError::InvalidElf);
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes[file_start..file_end].as_ptr(),
                (base + ph.p_vaddr) as *mut u8,
                usize::try_from(ph.p_filesz).map_err(|_| UserError::InvalidElf)?,
            );
            if ph.p_memsz > ph.p_filesz {
                core::ptr::write_bytes(
                    (base + ph.p_vaddr + ph.p_filesz) as *mut u8,
                    0,
                    usize::try_from(ph.p_memsz - ph.p_filesz).map_err(|_| UserError::InvalidElf)?,
                );
            }
        }
        brk_end = brk_end.max(base + ph.p_vaddr + ph.p_memsz);
    }

    let mut phdr_addr = 0u64;
    for ph in &elf.program_headers {
        if ph.p_type == PT_PHDR {
            phdr_addr = base + ph.p_vaddr;
        }
    }
    if phdr_addr == 0 {
        if let Some(first_load) = elf.program_headers.iter().find(|ph| ph.p_type == PT_LOAD) {
            phdr_addr = base + first_load.p_vaddr + elf.header.e_phoff - first_load.p_offset;
        }
    }

    Ok(LoadedElf {
        entry: base + elf.entry,
        phdr_addr,
        phentsize: elf.header.e_phentsize as usize,
        phnum: elf.header.e_phnum as usize,
        load_base: base,
        brk_end: align_up(brk_end, PAGE_SIZE),
    })
}

fn build_initial_stack(
    stack_top: u64,
    path: &str,
    argv: &[&str],
    envp: &[&str],
    main: &LoadedElf,
    interp: Option<&LoadedElf>,
) -> Result<InitialStack, UserError> {
    let mut rsp = stack_top;
    let mut argv_ptrs = Vec::with_capacity(argv.len());
    let mut env_ptrs = Vec::with_capacity(envp.len());

    let execfn_ptr = push_bytes(&mut rsp, path.as_bytes())?;
    let random_ptr = push_bytes(&mut rsp, &[0x55; 16])?;

    for env in envp.iter().rev() {
        env_ptrs.push(push_bytes(&mut rsp, env.as_bytes())?);
    }
    env_ptrs.reverse();
    for arg in argv.iter().rev() {
        argv_ptrs.push(push_bytes(&mut rsp, arg.as_bytes())?);
    }
    argv_ptrs.reverse();

    rsp &= !0xf;
    let auxv = [
        (AT_PHDR, main.phdr_addr),
        (AT_PHENT, main.phentsize as u64),
        (AT_PHNUM, main.phnum as u64),
        (AT_PAGESZ, PAGE_SIZE),
        (AT_BASE, interp.map(|img| img.load_base).unwrap_or(0)),
        (AT_ENTRY, main.entry),
        (AT_UID, 0),
        (AT_EUID, 0),
        (AT_GID, 0),
        (AT_EGID, 0),
        (AT_SECURE, 0),
        (AT_RANDOM, random_ptr),
        (AT_EXECFN, execfn_ptr),
    ];

    push_usize(&mut rsp, 0);
    push_usize(&mut rsp, AT_NULL);
    for (key, value) in auxv.iter().rev() {
        push_usize(&mut rsp, *value as usize);
        push_usize(&mut rsp, *key);
    }
    push_usize(&mut rsp, 0);
    for ptr in env_ptrs.iter().rev() {
        push_usize(&mut rsp, *ptr as usize);
    }
    let envp_ptr = rsp;
    push_usize(&mut rsp, 0);
    for ptr in argv_ptrs.iter().rev() {
        push_usize(&mut rsp, *ptr as usize);
    }
    let argv_ptr = rsp;
    push_usize(&mut rsp, argv.len());
    Ok(InitialStack {
        rsp,
        argc: argv.len(),
        argv_ptr,
        envp_ptr,
    })
}

fn push_bytes(rsp: &mut u64, bytes: &[u8]) -> Result<u64, UserError> {
    let len = bytes.len() + 1;
    *rsp = rsp.saturating_sub(len as u64);
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), *rsp as *mut u8, bytes.len());
        (*rsp as *mut u8).add(bytes.len()).write(0);
    }
    Ok(*rsp)
}

fn push_usize(rsp: &mut u64, value: usize) {
    *rsp = rsp.saturating_sub(core::mem::size_of::<usize>() as u64);
    unsafe {
        (*rsp as *mut usize).write(value);
    }
}

fn ph_to_prot(flags: u32) -> i32 {
    let mut prot = 0;
    if (flags & goblin::elf64::program_header::PF_R) != 0 {
        prot |= PROT_READ;
    }
    if (flags & goblin::elf64::program_header::PF_W) != 0 {
        prot |= PROT_WRITE;
    }
    if (flags & goblin::elf64::program_header::PF_X) != 0 {
        prot |= PROT_EXEC;
    }
    prot
}

fn map_region(start: u64, len: u64, prot: i32) -> Result<(), UserError> {
    let page_count = len.div_ceil(PAGE_SIZE);
    let flags = page_flags(prot);
    for idx in 0..page_count {
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(start + idx * PAGE_SIZE));
        match allocator::allocate_and_map_page(page, flags) {
            Ok(_) => {}
            Err(allocator::VmError::PageAlreadyMapped) => {}
            Err(_) => return Err(UserError::Vm),
        }
        allocator::zero_page(page);
    }
    Ok(())
}

fn page_flags(prot: i32) -> PageTableFlags {
    let mut flags =
        PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE | PageTableFlags::WRITABLE;
    if (prot & PROT_EXEC) == 0 {
        flags |= PageTableFlags::NO_EXECUTE;
    }
    flags
}

fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

fn align_up(value: u64, align: u64) -> u64 {
    if value == 0 {
        0
    } else {
        (value + align - 1) & !(align - 1)
    }
}
