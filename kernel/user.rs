extern crate alloc;

use crate::vfs;
use crate::{allocator, gdt, kdebug, ktrace, process, smp::MAX_CPUS, syscall::SyscallFrame};
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use goblin::elf::Elf;
use goblin::elf::dynamic::{DT_NEEDED, DT_NULL, DT_STRTAB, Dyn};
use goblin::elf::program_header::{PT_LOAD, PT_PHDR};
use spin::{Lazy, Mutex};
use x86_64::VirtAddr;
use x86_64::registers::control::Cr3;
use x86_64::registers::model_specific::FsBase;
use x86_64::structures::paging::{Page, PageSize, PageTable, PageTableFlags, PhysFrame, Size4KiB};

const PAGE_SIZE: u64 = Size4KiB::SIZE;
const USER_STACK_TOP: u64 = 0x0000_7fff_ff00_0000;
const USER_STACK_PAGES: u64 = 64;
const USER_MAIN_BASE: u64 = 0x0000_0000_4000_0000;
const USER_INTERP_BASE: u64 = 0x0000_0000_7000_0000;
const USER_BRK_BASE: u64 = 0x0000_0000_5000_0000;
const USER_MMAP_BASE: u64 = 0x0000_0001_0000_0000;
const KERNEL_VIRTIO_DMA_BASE: u64 = 0x0000_6666_0000_0000;

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
    pub address_space_id: u32,
    pub tid_addr: u64,
    pub init_path: Option<String>,
    pub fs_base: u64,
    pub task_id: Option<usize>,
    pub fd_table: Vec<Option<UserFd>>,
    pub exited: bool,
    pub exit_status: i32,
    pub waiting_task: Option<usize>,
    pub children: Vec<u32>,
}

#[derive(Debug, Clone, Copy)]
pub struct UserMapping {
    pub start: u64,
    pub len: u64,
    pub prot: i32,
    pub frame: PhysFrame<Size4KiB>,
}

#[derive(Debug, Clone)]
struct AddressSpace {
    root_frame: PhysFrame<Size4KiB>,
    brk: u64,
    next_mmap_base: u64,
    mappings: BTreeMap<u64, UserMapping>,
}

impl Default for AddressSpace {
    fn default() -> Self {
        Self {
            root_frame: PhysFrame::containing_address(x86_64::PhysAddr::new(0)),
            brk: USER_BRK_BASE,
            next_mmap_base: USER_MMAP_BASE,
            mappings: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UserFd {
    pub handle: i32,
    pub fd_flags: i32,
}

impl Default for UserProcess {
    fn default() -> Self {
        Self {
            pid: 1,
            ppid: 0,
            cwd: "/".to_string(),
            address_space_id: 1,
            tid_addr: 0,
            init_path: None,
            fs_base: 0,
            task_id: None,
            fd_table: Vec::new(),
            exited: false,
            exit_status: 0,
            waiting_task: None,
            children: Vec::new(),
        }
    }
}

static CURRENTS: Lazy<[Mutex<UserProcess>; MAX_CPUS]> =
    Lazy::new(|| core::array::from_fn(|_| Mutex::new(UserProcess::default())));

#[derive(Default)]
struct UserRegistry {
    next_pid: u32,
    next_address_space_id: u32,
    active_pids: [u32; MAX_CPUS],
    by_pid: BTreeMap<u32, UserProcess>,
    spaces: BTreeMap<u32, AddressSpace>,
    task_to_pid: BTreeMap<usize, u32>,
}

static REGISTRY: Lazy<Mutex<UserRegistry>> = Lazy::new(|| {
    Mutex::new(UserRegistry {
        next_pid: 2,
        next_address_space_id: 2,
        ..UserRegistry::default()
    })
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserError {
    Vfs,
    InvalidElf,
    Vm,
    Unsupported,
    InvalidFd,
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

fn current_task_id() -> Option<usize> {
    process::current_task_id()
}

fn current_cpu() -> usize {
    crate::smp::current_cpu().min(MAX_CPUS.saturating_sub(1))
}

fn current_slot() -> &'static Mutex<UserProcess> {
    &CURRENTS[current_cpu()]
}

fn active_pid() -> Option<u32> {
    match REGISTRY.lock().active_pids[current_cpu()] {
        0 => None,
        pid => Some(pid),
    }
}

fn current_pid_internal() -> u32 {
    if let Some(pid) = active_pid() {
        return pid;
    }
    current_slot().lock().pid
}

fn save_current_snapshot(registry: &mut UserRegistry) {
    let cpu = current_cpu();
    let pid = registry.active_pids[cpu];
    if pid != 0 {
        registry.by_pid.insert(pid, current_slot().lock().clone());
    }
}

fn install_current_snapshot(registry: &mut UserRegistry, pid: u32) {
    if let Some(snapshot) = registry.by_pid.get(&pid).cloned() {
        *current_slot().lock() = snapshot;
        registry.active_pids[current_cpu()] = pid;
    }
}

fn switch_active_process(pid: Option<u32>) {
    let cpu = current_cpu();
    let new_snapshot = {
        let mut registry = REGISTRY.lock();
        let old_pid = match registry.active_pids[cpu] {
            0 => None,
            pid => Some(pid),
        };
        if old_pid == pid {
            return;
        }

        let old_snapshot = if old_pid.is_some() {
            Some(current_slot().lock().clone())
        } else {
            None
        };
        let new_snapshot = pid.and_then(|next_pid| registry.by_pid.get(&next_pid).cloned());
        if let Some(ref old) = old_snapshot {
            if let Some(old_pid) = old_pid {
                registry.by_pid.insert(old_pid, old.clone());
            }
        }
        new_snapshot
    };

    if let Some(new_proc) = new_snapshot {
        if let Err(err) = switch_address_space(new_proc.address_space_id) {
            kdebug!(
                "USER: switch_address_space pid={:?} asid={} failed: {:?}",
                pid,
                new_proc.address_space_id,
                err
            );
        }
        FsBase::write(VirtAddr::new(new_proc.fs_base));
        *current_slot().lock() = new_proc;
    } else {
        FsBase::write(VirtAddr::new(0));
    }
    REGISTRY.lock().active_pids[cpu] = pid.unwrap_or(0);
}

pub fn activate_task(task_id: usize) {
    let pid = REGISTRY.lock().task_to_pid.get(&task_id).copied();
    switch_active_process(pid);
}

fn allocate_pid(registry: &mut UserRegistry) -> u32 {
    let pid = registry.next_pid.max(1);
    registry.next_pid = pid.saturating_add(1);
    pid
}

fn allocate_address_space_id(registry: &mut UserRegistry) -> u32 {
    let asid = registry.next_address_space_id.max(1);
    registry.next_address_space_id = asid.saturating_add(1);
    asid
}

fn current_address_space_id() -> u32 {
    current_slot().lock().address_space_id
}

fn current_root_frame() -> Result<PhysFrame<Size4KiB>, UserError> {
    let asid = current_address_space_id();
    let registry = REGISTRY.lock();
    registry
        .spaces
        .get(&asid)
        .map(|space| space.root_frame)
        .ok_or(UserError::Vm)
}

fn with_current_address_space<T>(f: impl FnOnce(&mut AddressSpace) -> T) -> T {
    let asid = current_address_space_id();
    let mut registry = REGISTRY.lock();
    let space = registry.spaces.entry(asid).or_default();
    f(space)
}

fn current_mappings() -> Vec<UserMapping> {
    let asid = current_address_space_id();
    address_space_mappings(asid)
}

fn address_space_mappings(asid: u32) -> Vec<UserMapping> {
    let registry = REGISTRY.lock();
    registry
        .spaces
        .get(&asid)
        .map(|space| space.mappings.values().copied().collect())
        .unwrap_or_default()
}

fn with_address_space<T>(asid: u32, f: impl FnOnce(&mut AddressSpace) -> T) -> T {
    let mut registry = REGISTRY.lock();
    let space = registry.spaces.entry(asid).or_default();
    f(space)
}

fn create_address_space() -> Result<AddressSpace, UserError> {
    let root_frame = allocator::allocate_frame().map_err(|_| UserError::Vm)?;
    allocator::zero_frame(root_frame).map_err(|_| UserError::Vm)?;

    let offset = allocator::physical_memory_offset().map_err(|_| UserError::Vm)?;
    let new_ptr = (offset.as_u64() + root_frame.start_address().as_u64()) as *mut PageTable;
    let (current_root, _) = Cr3::read();
    let current_ptr = (offset.as_u64() + current_root.start_address().as_u64()) as *const PageTable;

    unsafe {
        let new_table = &mut *new_ptr;
        let current_table = &*current_ptr;
        let mut current_rsp = 0usize;
        core::arch::asm!("mov {}, rsp", out(reg) current_rsp, options(nomem, preserves_flags, nostack));

        for idx in 256..512 {
            new_table[idx] = current_table[idx].clone();
        }

        for virt in [
            allocator::HEAP_START as u64,
            KERNEL_VIRTIO_DMA_BASE,
            current_rsp as u64,
            create_address_space as *const () as usize as u64,
        ] {
            let idx = ((virt >> 39) & 0x1ff) as usize;
            new_table[idx] = current_table[idx].clone();
        }
    }

    Ok(AddressSpace {
        root_frame,
        brk: USER_BRK_BASE,
        next_mmap_base: USER_MMAP_BASE,
        mappings: BTreeMap::new(),
    })
}

fn switch_address_space(asid: u32) -> Result<(), UserError> {
    let root_frame = {
        let registry = REGISTRY.lock();
        registry
            .spaces
            .get(&asid)
            .map(|space| space.root_frame)
            .ok_or(UserError::Vm)?
    };
    let (_, flags) = Cr3::read();
    unsafe {
        Cr3::write(root_frame, flags);
    }
    Ok(())
}

fn destroy_current_image() -> Result<(), UserError> {
    destroy_address_space_contents(current_address_space_id())
}

fn destroy_address_space_contents(asid: u32) -> Result<(), UserError> {
    let mappings = address_space_mappings(asid);
    let root_frame = {
        let registry = REGISTRY.lock();
        registry
            .spaces
            .get(&asid)
            .map(|space| space.root_frame)
            .ok_or(UserError::Vm)?
    };
    for mapping in mappings {
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(mapping.start));
        if let Ok(frame) = allocator::unmap_page_in(root_frame, page) {
            let _ = allocator::deallocate_frame(frame);
        }
    }
    with_address_space(asid, |space| {
        space.mappings.clear();
        space.brk = USER_BRK_BASE;
        space.next_mmap_base = USER_MMAP_BASE;
    });
    Ok(())
}

fn destroy_address_space(asid: u32) -> Result<(), UserError> {
    destroy_address_space_contents(asid)?;
    let root_frame = {
        let mut registry = REGISTRY.lock();
        registry
            .spaces
            .remove(&asid)
            .map(|space| space.root_frame)
            .ok_or(UserError::Vm)?
    };
    let _ = allocator::deallocate_frame(root_frame);
    Ok(())
}

pub fn exit_current(status: i32) {
    let pid = current_pid_internal();
    let task_id = current_task_id();
    let mut current = current_slot().lock();
    current.exited = true;
    current.exit_status = status;
    current.task_id = None;
    let handles: Vec<i32> = current
        .fd_table
        .iter_mut()
        .filter_map(|entry| entry.take().map(|fd| fd.handle))
        .collect();
    drop(current);
    for handle in handles {
        let _ = vfs::close(handle);
    }
    let mut registry = REGISTRY.lock();
    if let Some(task_id) = task_id {
        registry.task_to_pid.remove(&task_id);
    }
    registry.by_pid.insert(pid, current_slot().lock().clone());
}

fn seed_standard_fds(proc: &mut UserProcess) -> Result<(), UserError> {
    proc.fd_table.clear();
    proc.fd_table.resize(3, None);
    for (fd, handle) in [0, 1, 2].into_iter().enumerate() {
        let cloned = vfs::clone_handle(handle).map_err(|_| UserError::Vfs)?;
        proc.fd_table[fd] = Some(UserFd {
            handle: cloned,
            fd_flags: 0,
        });
    }
    Ok(())
}

fn clone_fd_table(src: &[Option<UserFd>]) -> Result<Vec<Option<UserFd>>, UserError> {
    let mut out = Vec::with_capacity(src.len());
    for entry in src {
        if let Some(fd) = entry {
            out.push(Some(UserFd {
                handle: vfs::clone_handle(fd.handle).map_err(|_| UserError::Vfs)?,
                fd_flags: fd.fd_flags,
            }));
        } else {
            out.push(None);
        }
    }
    Ok(out)
}

fn frame_bytes(frame: PhysFrame<Size4KiB>) -> Result<*mut u8, UserError> {
    let offset = allocator::physical_memory_offset().map_err(|_| UserError::Vm)?;
    Ok((offset.as_u64() + frame.start_address().as_u64()) as *mut u8)
}

fn duplicate_mappings(
    src: &BTreeMap<u64, UserMapping>,
) -> Result<BTreeMap<u64, UserMapping>, UserError> {
    let mut out = BTreeMap::new();
    for (virt, mapping) in src {
        let frame = allocator::allocate_frame().map_err(|_| UserError::Vm)?;
        unsafe {
            core::ptr::copy_nonoverlapping(
                frame_bytes(mapping.frame)?,
                frame_bytes(frame)?,
                PAGE_SIZE as usize,
            );
        }
        out.insert(
            *virt,
            UserMapping {
                start: *virt,
                len: mapping.len,
                prot: mapping.prot,
                frame,
            },
        );
    }
    Ok(out)
}

fn duplicate_address_space(parent_asid: u32) -> Result<AddressSpace, UserError> {
    let parent_space = {
        let registry = REGISTRY.lock();
        registry
            .spaces
            .get(&parent_asid)
            .cloned()
            .ok_or(UserError::Vm)?
    };
    let mappings = duplicate_mappings(&parent_space.mappings)?;
    let child = create_address_space()?;
    for mapping in mappings.values() {
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(mapping.start));
        allocator::map_existing_page_in(
            child.root_frame,
            page,
            mapping.frame,
            page_flags(mapping.prot),
        )
        .map_err(|_| UserError::Vm)?;
    }
    Ok(AddressSpace {
        root_frame: child.root_frame,
        brk: parent_space.brk,
        next_mmap_base: parent_space.next_mmap_base,
        mappings,
    })
}

fn reap_child(pid: i32) -> Result<Option<(u32, i32)>, UserError> {
    let self_pid = current_pid_internal();
    let children = current_slot().lock().children.clone();
    if children.is_empty() {
        return Err(UserError::Unsupported);
    }

    let mut registry = REGISTRY.lock();
    for child_pid in children {
        if pid != -1 && pid as u32 != child_pid {
            continue;
        }
        let Some(proc) = registry.by_pid.get(&child_pid) else {
            continue;
        };
        if !proc.exited {
            continue;
        }
        let status = proc.exit_status;
        registry.by_pid.remove(&child_pid);
        current_slot()
            .lock()
            .children
            .retain(|candidate| *candidate != child_pid);
        if let Some(parent) = registry.by_pid.get_mut(&self_pid) {
            parent.children.retain(|candidate| *candidate != child_pid);
        }
        return Ok(Some((child_pid, status)));
    }
    Ok(None)
}

pub fn bootstrap_init(path: &str) -> Result<(), UserError> {
    let bytes = vfs::read_all(path).map_err(|_| UserError::Vfs)?;
    validate_elf(&bytes)?;
    let mut p = current_slot().lock();
    p.init_path = Some(path.to_string());
    Ok(())
}

pub fn debug_file_elf(path: &str) {
    let Ok(bytes) = vfs::read_all(path) else {
        kdebug!("USER-ELF file path={} read failed", path);
        return;
    };
    let Ok(elf) = validate_elf(&bytes) else {
        kdebug!("USER-ELF file path={} parse failed", path);
        return;
    };
    let needed = elf.libraries.clone();
    kdebug!(
        "USER-ELF file path={} entry={:#x} interp={:?} needed_count={}",
        path,
        elf.entry,
        elf.interpreter,
        needed.len()
    );
    for lib in needed {
        ktrace!("USER-ELF file needed={}", lib);
    }
}

fn validate_elf(bytes: &[u8]) -> Result<Elf<'_>, UserError> {
    let elf = Elf::parse(bytes).map_err(|_| UserError::InvalidElf)?;
    if !elf.is_64 {
        return Err(UserError::InvalidElf);
    }
    Ok(elf)
}

pub fn pid() -> u32 {
    current_pid_internal()
}

pub fn ppid() -> u32 {
    current_slot().lock().ppid
}

pub fn set_tid_address(addr: u64) {
    current_slot().lock().tid_addr = addr;
}

pub fn brk(new_brk: Option<u64>) -> u64 {
    let mut brk = with_current_address_space(|space| space.brk);
    if let Some(v) = new_brk {
        let target = align_up(v, PAGE_SIZE);
        if target > brk {
            let start = brk;
            let len = target - start;
            let _ = map_region(start, len, PROT_READ | PROT_WRITE);
        }
        brk = target;
    }
    with_current_address_space(|space| {
        space.brk = brk;
        space.brk
    })
}

pub fn cwd() -> String {
    current_slot().lock().cwd.clone()
}

pub fn current_init_path() -> Option<String> {
    current_slot().lock().init_path.clone()
}

pub fn nanosleep(_ns: u64) {}

pub fn arch_prctl(code: usize, addr: u64) -> Result<u64, UserError> {
    match code {
        ARCH_SET_FS => {
            FsBase::write(VirtAddr::new(addr));
            current_slot().lock().fs_base = addr;
            Ok(0)
        }
        ARCH_GET_FS => Ok(current_slot().lock().fs_base),
        _ => Err(UserError::Unsupported),
    }
}

pub fn create_init_task(task_id: usize, path: &str) -> Result<process::Task, UserError> {
    let bash_argv = [path, "--noprofile", "--norc", "--noediting"];
    let ldso_argv = [path, "/usr/bin/clear"];
    let default_argv = [path];
    let argv = if path == "/usr/bin/bash" {
        &bash_argv[..]
    } else if path == "/usr/lib/ld-musl-x86_64.so.1" || path == "/lib/ld-musl-x86_64.so.1" {
        &ldso_argv[..]
    } else {
        &default_argv[..]
    };
    let envp = [
        "HOME=/",
        "PATH=/bin:/usr/bin:/sbin:/usr/sbin",
        "TERM=vt100",
        "PS1=bash-mmm# ",
    ];
    {
        let mut current = current_slot().lock();
        *current = UserProcess::default();
        current.pid = 1;
        current.ppid = 0;
        current.address_space_id = 1;
        current.task_id = Some(task_id);
        current.children.clear();
        current.exited = false;
        current.exit_status = 0;
        current.waiting_task = None;
        seed_standard_fds(&mut current)?;
    }
    {
        let mut registry = REGISTRY.lock();
        let space = create_address_space()?;
        registry.spaces.insert(1, space);
        registry.by_pid.insert(1, current_slot().lock().clone());
    }
    switch_active_process(Some(1));
    let task = load_task_from_elf(task_id, 1, path, &argv, &envp)?;
    let mut registry = REGISTRY.lock();
    registry.task_to_pid.insert(task_id, 1);
    registry.by_pid.insert(1, current_slot().lock().clone());
    Ok(task)
}

pub fn execve(
    path: &str,
    argv: &[&str],
    envp: &[&str],
) -> Result<process::SavedTaskContext, UserError> {
    let pid = current_pid_internal();
    let task_id = current_task_id().ok_or(UserError::Unsupported)?;
    let (old_asid, old_init_path) = {
        let state = current_slot().lock();
        (state.address_space_id, state.init_path.clone())
    };
    let new_asid = {
        let mut registry = REGISTRY.lock();
        let asid = allocate_address_space_id(&mut registry);
        let space = create_address_space()?;
        registry.spaces.insert(asid, space);
        asid
    };

    {
        let mut state = current_slot().lock();
        state.address_space_id = new_asid;
    }
    switch_address_space(new_asid)?;

    let ctx = match load_exec_context(task_id, pid, path, argv, envp) {
        Ok(ctx) => ctx,
        Err(err) => {
            {
                let mut state = current_slot().lock();
                state.address_space_id = old_asid;
                state.init_path = old_init_path;
            }
            let _ = switch_address_space(old_asid);
            let _ = destroy_address_space(new_asid);
            return Err(err);
        }
    };

    destroy_address_space(old_asid)?;
    REGISTRY
        .lock()
        .by_pid
        .insert(pid, current_slot().lock().clone());
    kdebug!(
        "USER: execve path={} pid={} rip={:#x} rsp={:#x}",
        path,
        pid,
        ctx.rip,
        ctx.rsp
    );
    Ok(ctx)
}

pub fn fork_from_syscall(frame: &SyscallFrame) -> Result<u32, UserError> {
    let parent = current_slot().lock().clone();
    let child_task_id = process::allocate_task_id();
    let child_pid = {
        let mut registry = REGISTRY.lock();
        let pid = allocate_pid(&mut registry);
        registry.task_to_pid.insert(child_task_id, pid);
        pid
    };

    let mut child = parent.clone();
    child.pid = child_pid;
    child.ppid = parent.pid;
    child.task_id = Some(child_task_id);
    child.children.clear();
    child.waiting_task = None;
    child.exited = false;
    child.exit_status = 0;
    child.fd_table = clone_fd_table(&parent.fd_table)?;
    let child_space = duplicate_address_space(parent.address_space_id)?;
    child.address_space_id = {
        let mut registry = REGISTRY.lock();
        let asid = allocate_address_space_id(&mut registry);
        registry.spaces.insert(asid, child_space);
        asid
    };

    {
        let mut current = current_slot().lock();
        current.children.push(child_pid);
    }

    REGISTRY.lock().by_pid.insert(child_pid, child);

    let ctx = process::SavedTaskContext {
        r15: frame.r15,
        r14: frame.r14,
        r13: frame.r13,
        r12: frame.r12,
        r11: frame.r11,
        r10: frame.r10,
        r9: frame.r9,
        r8: frame.r8,
        rbp: frame.rbp,
        rdi: frame.rdi,
        rsi: frame.rsi,
        rdx: frame.rdx,
        rcx: frame.rcx,
        rbx: frame.rbx,
        rax: 0,
        rip: frame.rcx,
        cs: usize::from(gdt::user_code_selector().0),
        rflags: frame.r11,
        rsp: frame.user_rsp,
        ss: usize::from(gdt::user_data_selector().0),
    };
    kdebug!(
        "USER: fork parent_pid={} child_pid={} child_task={} rip={:#x} rsp={:#x} rax={:#x}",
        parent.pid,
        child_pid,
        child_task_id,
        ctx.rip,
        ctx.rsp,
        ctx.rax
    );
    let task = process::Task::with_initial_context(
        child_task_id,
        0,
        ctx,
        process::SchedParams {
            process_id: child_pid,
            ..process::SchedParams::default()
        },
    );
    process::SCHEDULER.lock().add_task(task);
    Ok(child_pid)
}

pub fn wait4(pid: i32, status_ptr: *mut i32) -> Result<u32, UserError> {
    loop {
        if let Some((child_pid, status)) = reap_child(pid)? {
            if !status_ptr.is_null() {
                unsafe { status_ptr.write_volatile(status << 8) };
            }
            return Ok(child_pid);
        }
        x86_64::instructions::interrupts::enable();
        unsafe { core::arch::asm!("hlt") };
        x86_64::instructions::interrupts::disable();
    }
}

fn fd_entry(fd: i32) -> Result<UserFd, UserError> {
    let slot = usize::try_from(fd).map_err(|_| UserError::InvalidFd)?;
    current_slot()
        .lock()
        .fd_table
        .get(slot)
        .and_then(|entry| *entry)
        .ok_or(UserError::InvalidFd)
}

fn fd_entry_mut<F, T>(fd: i32, f: F) -> Result<T, UserError>
where
    F: FnOnce(&mut UserFd) -> T,
{
    let slot = usize::try_from(fd).map_err(|_| UserError::InvalidFd)?;
    let mut current = current_slot().lock();
    let entry = current
        .fd_table
        .get_mut(slot)
        .and_then(Option::as_mut)
        .ok_or(UserError::InvalidFd)?;
    Ok(f(entry))
}

fn alloc_fd_slot(min_fd: i32) -> Result<usize, UserError> {
    let start = usize::try_from(min_fd.max(0)).map_err(|_| UserError::InvalidFd)?;
    let mut current = current_slot().lock();
    if current.fd_table.len() < start {
        current.fd_table.resize(start, None);
    }
    if let Some((idx, _)) = current
        .fd_table
        .iter()
        .enumerate()
        .skip(start)
        .find(|(_, entry)| entry.is_none())
    {
        return Ok(idx);
    }
    let idx = current.fd_table.len();
    current.fd_table.push(None);
    Ok(idx)
}

pub fn open_fd(path: &str, flags: i32) -> Result<i32, UserError> {
    let handle = vfs::open(path, flags).map_err(|_| UserError::Vfs)?;
    install_fd(handle, 0, 0)
}

pub fn install_fd(handle: i32, min_fd: i32, fd_flags: i32) -> Result<i32, UserError> {
    let slot = alloc_fd_slot(min_fd)?;
    current_slot().lock().fd_table[slot] = Some(UserFd { handle, fd_flags });
    Ok(slot as i32)
}

pub fn close_fd(fd: i32) -> Result<(), UserError> {
    let slot = usize::try_from(fd).map_err(|_| UserError::InvalidFd)?;
    let handle = {
        let mut current = current_slot().lock();
        let entry = current
            .fd_table
            .get_mut(slot)
            .and_then(Option::take)
            .ok_or(UserError::InvalidFd)?;
        entry.handle
    };
    vfs::close(handle).map_err(|_| UserError::Vfs)
}

pub fn handle_for_fd(fd: i32) -> Result<i32, UserError> {
    Ok(fd_entry(fd)?.handle)
}

pub fn path_of_fd(fd: i32) -> Result<String, UserError> {
    let handle = handle_for_fd(fd)?;
    vfs::path_of_fd(handle).map_err(|_| UserError::Vfs)
}

pub fn get_fd_flags(fd: i32) -> Result<i32, UserError> {
    Ok(fd_entry(fd)?.fd_flags)
}

pub fn set_fd_flags(fd: i32, flags: i32) -> Result<(), UserError> {
    fd_entry_mut(fd, |entry| entry.fd_flags = flags)?;
    Ok(())
}

pub fn get_status_flags(fd: i32) -> Result<i32, UserError> {
    let handle = handle_for_fd(fd)?;
    vfs::get_status_flags(handle).map_err(|_| UserError::Vfs)
}

pub fn set_status_flags(fd: i32, flags: i32) -> Result<(), UserError> {
    let handle = handle_for_fd(fd)?;
    vfs::set_status_flags(handle, flags).map_err(|_| UserError::Vfs)
}

pub fn dup_fd(oldfd: i32, min_fd: i32, cloexec: bool) -> Result<i32, UserError> {
    let src = fd_entry(oldfd)?;
    let slot = alloc_fd_slot(min_fd)?;
    let handle = vfs::clone_handle(src.handle).map_err(|_| UserError::Vfs)?;
    current_slot().lock().fd_table[slot] = Some(UserFd {
        handle,
        fd_flags: if cloexec { 1 } else { 0 },
    });
    Ok(slot as i32)
}

pub fn dup2_fd(oldfd: i32, newfd: i32, cloexec: bool) -> Result<i32, UserError> {
    if oldfd == newfd {
        return Ok(newfd);
    }
    let src = fd_entry(oldfd)?;
    let new_slot = usize::try_from(newfd).map_err(|_| UserError::InvalidFd)?;
    let handle = vfs::clone_handle(src.handle).map_err(|_| UserError::Vfs)?;
    let old_handle = {
        let mut current = current_slot().lock();
        if current.fd_table.len() <= new_slot {
            current.fd_table.resize(new_slot + 1, None);
        }
        let old = current.fd_table[new_slot].replace(UserFd {
            handle,
            fd_flags: if cloexec { 1 } else { 0 },
        });
        old.map(|entry| entry.handle)
    };
    if let Some(handle) = old_handle {
        let _ = vfs::close(handle);
    }
    Ok(newfd)
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
        let next = with_current_address_space(|space| {
            let next = align_up(space.next_mmap_base, PAGE_SIZE);
            space.next_mmap_base = next.saturating_add(len);
            next
        });
        next
    };

    map_region(start, len, prot)?;
    if (flags & MAP_ANONYMOUS) == 0 && fd >= 0 {
        let handle = handle_for_fd(fd)?;
        let mut remaining = len;
        let mut page_off = 0u64;
        while remaining != 0 {
            let page_len = remaining.min(PAGE_SIZE);
            let dst = unsafe {
                core::slice::from_raw_parts_mut((start + page_off) as *mut u8, page_len as usize)
            };
            let n = vfs::pread(handle, offset + page_off, dst).map_err(|_| UserError::Vfs)?;
            unsafe {
                if n < page_len as usize {
                    core::ptr::write_bytes(
                        (start + page_off + n as u64) as *mut u8,
                        0,
                        page_len as usize - n,
                    );
                }
            }
            remaining -= page_len;
            page_off += page_len;
        }
    }
    Ok(start)
}

pub fn munmap(addr: u64, len: u64) -> Result<(), UserError> {
    let start = align_down(addr, PAGE_SIZE);
    let len = align_up(len, PAGE_SIZE);
    let root_frame = current_root_frame()?;
    let page_count = len / PAGE_SIZE;
    for idx in 0..page_count {
        let virt = start + idx * PAGE_SIZE;
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virt));
        if let Ok(frame) = allocator::unmap_page_in(root_frame, page) {
            let _ = allocator::deallocate_frame(frame);
        }
        with_current_address_space(|space| {
            space.mappings.remove(&virt);
        });
    }
    Ok(())
}

pub fn mprotect(_addr: u64, _len: u64, _prot: i32) -> Result<(), UserError> {
    Ok(())
}

fn load_task_from_elf(
    task_id: usize,
    pid: u32,
    path: &str,
    argv: &[&str],
    envp: &[&str],
) -> Result<process::Task, UserError> {
    let ctx = load_exec_context(task_id, pid, path, argv, envp)?;
    Ok(process::Task::with_initial_context(
        task_id,
        0,
        ctx,
        process::SchedParams {
            process_id: pid,
            ..process::SchedParams::default()
        },
    ))
}

fn load_exec_context(
    task_id: usize,
    pid: u32,
    path: &str,
    argv: &[&str],
    envp: &[&str],
) -> Result<process::SavedTaskContext, UserError> {
    let bytes = vfs::read_all(path).map_err(|_| UserError::Vfs)?;
    let elf = validate_elf(&bytes)?;

    let main_base = if elf.header.e_type == goblin::elf::header::ET_DYN {
        USER_MAIN_BASE
    } else {
        0
    };
    let main = load_elf_image(&bytes, &elf, main_base)?;
    debug_loaded_image("main", path, &elf, &main);

    let interp_path = elf.interpreter.map(str::to_string);
    let interp = if let Some(ref interp_path) = interp_path {
        let interp_bytes = vfs::read_all(interp_path).map_err(|_| UserError::Vfs)?;
        let interp_elf = validate_elf(&interp_bytes)?;
        let image = load_elf_image(&interp_bytes, &interp_elf, USER_INTERP_BASE)?;
        debug_loaded_image("interp", interp_path, &interp_elf, &image);
        Some(image)
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
    if path == "/usr/bin/bash" {
        let q0 = unsafe { *(stack.rsp as *const u64) };
        let q1 = unsafe { *((stack.rsp + 8) as *const u64) };
        let q2 = unsafe { *((stack.rsp + 16) as *const u64) };
        let q3 = unsafe { *((stack.rsp + 24) as *const u64) };
        ktrace!(
            "USER-STACK rsp={:#x} argc={} argv_ptr={:#x} envp_ptr={:#x} q0={:#x} q1={:#x} q2={:#x} q3={:#x}",
            stack.rsp,
            stack.argc,
            stack.argv_ptr,
            stack.envp_ptr,
            q0,
            q1,
            q2,
            q3
        );
    }

    let entry = interp
        .as_ref()
        .map(|image| image.entry)
        .unwrap_or(main.entry);

    {
        let mut state = current_slot().lock();
        state.pid = pid;
        state.init_path = Some(path.to_string());
        state.task_id = Some(task_id);
        state.exited = false;
        state.exit_status = 0;
    }
    with_current_address_space(|space| {
        space.brk = align_up(main.brk_end.max(USER_BRK_BASE), PAGE_SIZE);
        space.next_mmap_base = USER_MMAP_BASE.max(space.brk.saturating_add(PAGE_SIZE));
    });

    Ok(process::SavedTaskContext {
        rip: entry as usize,
        cs: usize::from(gdt::user_code_selector().0),
        rflags: 0x202,
        rsp: stack.rsp as usize,
        ss: usize::from(gdt::user_data_selector().0),
        rdi: 0,
        rsi: 0,
        rdx: 0,
        ..process::SavedTaskContext::default()
    })
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
        let file_page_start = usize::try_from(align_down(ph.p_offset, PAGE_SIZE))
            .map_err(|_| UserError::InvalidElf)?;
        let file_end =
            usize::try_from(ph.p_offset + ph.p_filesz).map_err(|_| UserError::InvalidElf)?;
        if file_end > bytes.len() {
            return Err(UserError::InvalidElf);
        }
        let page_delta = usize::try_from(ph.p_offset - align_down(ph.p_offset, PAGE_SIZE))
            .map_err(|_| UserError::InvalidElf)?;
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes[file_page_start..file_end].as_ptr(),
                seg_start as *mut u8,
                usize::try_from(ph.p_filesz)
                    .map_err(|_| UserError::InvalidElf)?
                    .saturating_add(page_delta),
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

fn debug_loaded_image(label: &str, path: &str, elf: &Elf<'_>, loaded: &LoadedElf) {
    let mut strtab_addr = 0u64;
    let mut needed_offsets = Vec::new();
    for ph in &elf.program_headers {
        if ph.p_type != goblin::elf::program_header::PT_DYNAMIC {
            continue;
        }
        let dyn_count = (ph.p_memsz as usize) / core::mem::size_of::<Dyn>();
        let dyns = unsafe {
            core::slice::from_raw_parts((loaded.load_base + ph.p_vaddr) as *const Dyn, dyn_count)
        };
        for dynent in dyns {
            match dynent.d_tag {
                tag if tag == DT_NULL => break,
                tag if tag == DT_STRTAB => strtab_addr = relocate_image_addr(dynent.d_val, loaded),
                tag if tag == DT_NEEDED => needed_offsets.push(dynent.d_val as usize),
                _ => {}
            }
        }
    }

    kdebug!(
        "USER-ELF {} path={} base={:#x} entry={:#x} phdr={:#x} strtab={:#x} needed_count={}",
        label,
        path,
        loaded.load_base,
        loaded.entry,
        loaded.phdr_addr,
        strtab_addr,
        needed_offsets.len()
    );

    for off in needed_offsets {
        let name =
            read_c_string((strtab_addr + off as u64) as *const u8, 128).unwrap_or("<invalid>");
        ktrace!("USER-ELF {} needed={}", label, name);
    }
}

fn relocate_image_addr(addr: u64, loaded: &LoadedElf) -> u64 {
    if addr >= loaded.load_base {
        addr
    } else {
        loaded.load_base + addr
    }
}

fn read_c_string(ptr: *const u8, max_len: usize) -> Option<&'static str> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    while len < max_len {
        let b = unsafe { ptr.add(len).read_volatile() };
        if b == 0 {
            let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
            return core::str::from_utf8(bytes).ok();
        }
        len += 1;
    }
    None
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
    let root_frame = current_root_frame()?;
    for idx in 0..page_count {
        let virt = start + idx * PAGE_SIZE;
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virt));
        let frame = allocator::allocate_frame().map_err(|_| UserError::Vm)?;
        allocator::zero_frame(frame).map_err(|_| UserError::Vm)?;
        let frame = match allocator::map_existing_page_in(root_frame, page, frame, flags) {
            Ok(()) => frame,
            Err(allocator::VmError::PageAlreadyMapped) => {
                allocator::deallocate_frame(frame).map_err(|_| UserError::Vm)?;
                allocator::update_page_flags_in(root_frame, page, flags)
                    .map_err(|_| UserError::Vm)?;
                let asid = current_address_space_id();
                let registry = REGISTRY.lock();
                let mapping = registry
                    .spaces
                    .get(&asid)
                    .and_then(|space| space.mappings.get(&virt))
                    .copied()
                    .ok_or(UserError::Vm)?;
                mapping.frame
            }
            Err(_) => return Err(UserError::Vm),
        };
        with_current_address_space(|space| {
            space.mappings.insert(
                virt,
                UserMapping {
                    start: virt,
                    len: PAGE_SIZE,
                    prot,
                    frame,
                },
            );
        });
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
