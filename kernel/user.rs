extern crate alloc;

use crate::nt::{
    self, AccessMask, ClientId, FilePositionInformation, FileStandardInformation, Handle,
    IoStatusBlock, NtStatus, ObjectAttributes, Peb, ProcessBasicInformation,
    RtlUserProcessParameters, Teb, UnicodeString, STATUS_ACCESS_DENIED, STATUS_BUFFER_TOO_SMALL,
    STATUS_END_OF_FILE, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_HANDLE,
    STATUS_INVALID_IMAGE_FORMAT, STATUS_INVALID_PARAMETER, STATUS_NOT_IMPLEMENTED,
    STATUS_NOT_SUPPORTED, STATUS_NO_MEMORY, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS,
    STATUS_UNSUCCESSFUL,
};
use crate::vfs;
use crate::{allocator, gdt, kdebug, process, smp::MAX_CPUS};
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use goblin::pe::PE;
use spin::{Lazy, Mutex};
use x86_64::registers::control::Cr3;
use x86_64::registers::model_specific::FsBase;
use x86_64::structures::paging::{Page, PageSize, PageTable, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::VirtAddr;

const PAGE_SIZE: u64 = Size4KiB::SIZE;
const USER_STACK_TOP: u64 = 0x0000_7fff_ff00_0000;
const USER_STACK_PAGES: u64 = 64;
const USER_ENV_BASE: u64 = 0x0000_7fff_f000_0000;
const USER_ENV_PAGES: u64 = 16;
const USER_ALLOC_BASE: u64 = 0x0000_0001_0000_0000;
const KERNEL_VIRTIO_DMA_BASE: u64 = 0x0000_6666_0000_0000;

#[derive(Debug, Clone, Copy)]
struct HandleEntry {
    object_id: u32,
    access: AccessMask,
}

#[derive(Debug, Clone)]
pub struct UserProcess {
    pid: u32,
    ppid: u32,
    address_space_id: u32,
    task_id: Option<usize>,
    image_path: Option<String>,
    peb_addr: u64,
    teb_addr: u64,
    params_addr: u64,
    fs_base: u64,
    image_base: u64,
    handles: Vec<Option<HandleEntry>>,
    standard_input: Handle,
    standard_output: Handle,
    standard_error: Handle,
    process_object: u32,
    thread_object: u32,
    exited: bool,
    exit_status: NtStatus,
}

impl Default for UserProcess {
    fn default() -> Self {
        Self {
            pid: 1,
            ppid: 0,
            address_space_id: 1,
            task_id: None,
            image_path: None,
            peb_addr: 0,
            teb_addr: 0,
            params_addr: 0,
            fs_base: 0,
            image_base: 0,
            handles: Vec::new(),
            standard_input: 0,
            standard_output: 0,
            standard_error: 0,
            process_object: 0,
            thread_object: 0,
            exited: false,
            exit_status: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UserMapping {
    pub start: u64,
    pub len: u64,
    pub prot: u32,
    pub frame: PhysFrame<Size4KiB>,
}

#[derive(Debug, Clone)]
struct AddressSpace {
    root_frame: PhysFrame<Size4KiB>,
    next_alloc_base: u64,
    mappings: BTreeMap<u64, UserMapping>,
}

impl Default for AddressSpace {
    fn default() -> Self {
        Self {
            root_frame: PhysFrame::containing_address(x86_64::PhysAddr::new(0)),
            next_alloc_base: USER_ALLOC_BASE,
            mappings: BTreeMap::new(),
        }
    }
}

#[derive(Default)]
struct UserRegistry {
    next_pid: u32,
    next_address_space_id: u32,
    active_pids: [u32; MAX_CPUS],
    by_pid: BTreeMap<u32, UserProcess>,
    spaces: BTreeMap<u32, AddressSpace>,
    task_to_pid: BTreeMap<usize, u32>,
}

#[derive(Debug, Clone, Copy)]
struct LoadedImage {
    entry: u64,
    image_base: u64,
    size_of_image: u64,
}

static CURRENTS: Lazy<[Mutex<UserProcess>; MAX_CPUS]> =
    Lazy::new(|| core::array::from_fn(|_| Mutex::new(UserProcess::default())));

static REGISTRY: Lazy<Mutex<UserRegistry>> = Lazy::new(|| {
    Mutex::new(UserRegistry {
        next_pid: 2,
        next_address_space_id: 2,
        ..UserRegistry::default()
    })
});

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
    active_pid().unwrap_or_else(|| current_slot().lock().pid)
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

fn current_root_frame() -> Result<PhysFrame<Size4KiB>, NtStatus> {
    let asid = current_address_space_id();
    let registry = REGISTRY.lock();
    registry
        .spaces
        .get(&asid)
        .map(|space| space.root_frame)
        .ok_or(STATUS_UNSUCCESSFUL)
}

fn with_current_address_space<T>(f: impl FnOnce(&mut AddressSpace) -> T) -> T {
    let asid = current_address_space_id();
    let mut registry = REGISTRY.lock();
    let space = registry.spaces.entry(asid).or_default();
    f(space)
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

fn create_address_space() -> Result<AddressSpace, NtStatus> {
    let root_frame = allocator::allocate_frame().map_err(|_| STATUS_NO_MEMORY)?;
    allocator::zero_frame(root_frame).map_err(|_| STATUS_NO_MEMORY)?;

    let offset = allocator::physical_memory_offset().map_err(|_| STATUS_NO_MEMORY)?;
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
        next_alloc_base: USER_ALLOC_BASE,
        mappings: BTreeMap::new(),
    })
}

fn switch_address_space(asid: u32) -> Result<(), NtStatus> {
    let root_frame = {
        let registry = REGISTRY.lock();
        registry
            .spaces
            .get(&asid)
            .map(|space| space.root_frame)
            .ok_or(STATUS_UNSUCCESSFUL)?
    };
    let (_, flags) = Cr3::read();
    unsafe { Cr3::write(root_frame, flags) };
    Ok(())
}

fn destroy_address_space_contents(asid: u32) -> Result<(), NtStatus> {
    let mappings = address_space_mappings(asid);
    let root_frame = {
        let registry = REGISTRY.lock();
        registry
            .spaces
            .get(&asid)
            .map(|space| space.root_frame)
            .ok_or(STATUS_UNSUCCESSFUL)?
    };
    for mapping in mappings {
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(mapping.start));
        if let Ok(frame) = allocator::unmap_page_in(root_frame, page) {
            let _ = allocator::deallocate_frame(frame);
        }
    }
    with_address_space(asid, |space| {
        space.mappings.clear();
        space.next_alloc_base = USER_ALLOC_BASE;
    });
    Ok(())
}

fn destroy_address_space(asid: u32) -> Result<(), NtStatus> {
    destroy_address_space_contents(asid)?;
    let root_frame = {
        let mut registry = REGISTRY.lock();
        registry
            .spaces
            .remove(&asid)
            .map(|space| space.root_frame)
            .ok_or(STATUS_UNSUCCESSFUL)?
    };
    let _ = allocator::deallocate_frame(root_frame);
    Ok(())
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
        let _ = switch_address_space(new_proc.address_space_id);
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

pub fn pid() -> u32 {
    current_pid_internal()
}

pub fn current_init_path() -> Option<String> {
    current_slot().lock().image_path.clone()
}

fn slot_to_handle(slot: usize) -> Handle {
    (slot + 1) * 4
}

fn handle_to_slot(handle: Handle) -> Result<usize, NtStatus> {
    if handle == 0 || (handle & 0x3) != 0 {
        return Err(STATUS_INVALID_HANDLE);
    }
    Ok((handle / 4).saturating_sub(1))
}

fn install_handle(object_id: u32, access: AccessMask) -> Result<Handle, NtStatus> {
    nt::retain(object_id)?;
    let mut current = current_slot().lock();
    if let Some((idx, slot)) = current
        .handles
        .iter_mut()
        .enumerate()
        .find(|(_, slot)| slot.is_none())
    {
        *slot = Some(HandleEntry { object_id, access });
        return Ok(slot_to_handle(idx));
    }
    current
        .handles
        .push(Some(HandleEntry { object_id, access }));
    Ok(slot_to_handle(current.handles.len() - 1))
}

fn resolve_handle_entry(handle: Handle) -> Result<HandleEntry, NtStatus> {
    if handle == usize::MAX {
        let current = current_slot().lock();
        return Ok(HandleEntry {
            object_id: current.process_object,
            access: nt::PROCESS_ALL_ACCESS,
        });
    }
    if handle == usize::MAX - 4 {
        let current = current_slot().lock();
        return Ok(HandleEntry {
            object_id: current.thread_object,
            access: nt::THREAD_ALL_ACCESS,
        });
    }
    let slot = handle_to_slot(handle)?;
    current_slot()
        .lock()
        .handles
        .get(slot)
        .and_then(|entry| *entry)
        .ok_or(STATUS_INVALID_HANDLE)
}

pub fn close_handle(handle: Handle) -> NtStatus {
    if handle == usize::MAX || handle == usize::MAX - 4 {
        return STATUS_ACCESS_DENIED;
    }
    let slot = match handle_to_slot(handle) {
        Ok(slot) => slot,
        Err(status) => return status,
    };
    let object_id = {
        let mut current = current_slot().lock();
        let Some(entry) = current.handles.get_mut(slot).and_then(Option::take) else {
            return STATUS_INVALID_HANDLE;
        };
        entry.object_id
    };
    match nt::release(object_id) {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

fn seed_standard_handles(current: &mut UserProcess) -> Result<(), NtStatus> {
    for (path, access, out) in [
        ("/dev/stdin", nt::FILE_GENERIC_READ, 0usize),
        ("/dev/stdout", nt::FILE_GENERIC_WRITE, 1usize),
        ("/dev/stderr", nt::FILE_GENERIC_WRITE, 2usize),
    ] {
        let vfs_handle = vfs::open(path, 0).map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;
        let object_id = nt::create_file(path.to_string(), vfs_handle);
        nt::retain(object_id)?;
        current.handles.push(Some(HandleEntry { object_id, access }));
        let handle = slot_to_handle(current.handles.len() - 1);
        match out {
            0 => current.standard_input = handle,
            1 => current.standard_output = handle,
            _ => current.standard_error = handle,
        }
    }
    Ok(())
}

fn current_process_basic() -> ProcessBasicInformation {
    let current = current_slot().lock();
    ProcessBasicInformation {
        peb_base_address: current.peb_addr as usize,
        unique_process_id: current.pid as usize,
        inherited_from_unique_process_id: current.ppid as usize,
        ..ProcessBasicInformation::default()
    }
}

fn map_region(start: u64, len: u64, prot: u32) -> Result<(), NtStatus> {
    let page_count = len.div_ceil(PAGE_SIZE);
    let flags = page_flags(prot);
    let root_frame = current_root_frame()?;
    for idx in 0..page_count {
        let virt = start + idx * PAGE_SIZE;
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virt));
        let frame = allocator::allocate_frame().map_err(|_| STATUS_NO_MEMORY)?;
        allocator::zero_frame(frame).map_err(|_| STATUS_NO_MEMORY)?;
        let frame = match allocator::map_existing_page_in(root_frame, page, frame, flags) {
            Ok(()) => frame,
            Err(allocator::VmError::PageAlreadyMapped) => {
                allocator::deallocate_frame(frame).map_err(|_| STATUS_NO_MEMORY)?;
                allocator::update_page_flags_in(root_frame, page, flags)
                    .map_err(|_| STATUS_NO_MEMORY)?;
                let asid = current_address_space_id();
                let registry = REGISTRY.lock();
                let mapping = registry
                    .spaces
                    .get(&asid)
                    .and_then(|space| space.mappings.get(&virt))
                    .copied()
                    .ok_or(STATUS_UNSUCCESSFUL)?;
                mapping.frame
            }
            Err(_) => return Err(STATUS_NO_MEMORY),
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

fn page_flags(prot: u32) -> PageTableFlags {
    let mut flags =
        PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE | PageTableFlags::WRITABLE;
    let executable = matches!(
        prot,
        nt::PAGE_EXECUTE | nt::PAGE_EXECUTE_READ | nt::PAGE_EXECUTE_READWRITE
    );
    let writable = matches!(prot, nt::PAGE_READWRITE | nt::PAGE_EXECUTE_READWRITE);
    if !writable {
        flags.remove(PageTableFlags::WRITABLE);
    }
    if !executable {
        flags |= PageTableFlags::NO_EXECUTE;
    }
    flags
}

fn allocate_user_region(len: u64, prot: u32) -> Result<u64, NtStatus> {
    let len = align_up(len, PAGE_SIZE);
    let base = with_current_address_space(|space| {
        let base = align_up(space.next_alloc_base, PAGE_SIZE);
        space.next_alloc_base = base.saturating_add(len).saturating_add(PAGE_SIZE);
        base
    });
    map_region(base, len, prot)?;
    Ok(base)
}

pub fn allocate_virtual_memory(
    process_handle: Handle,
    base_address: *mut usize,
    region_size: *mut usize,
    protect: u32,
) -> NtStatus {
    if process_handle != usize::MAX || base_address.is_null() || region_size.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let requested = unsafe { (*region_size) as u64 };
    if requested == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let base = if unsafe { *base_address } != 0 {
        align_down(unsafe { *base_address } as u64, PAGE_SIZE)
    } else {
        match allocate_user_region(requested, protect) {
            Ok(base) => base,
            Err(status) => return status,
        }
    };
    if unsafe { *base_address } != 0 {
        let len = align_up(requested, PAGE_SIZE);
        if let Err(status) = map_region(base, len, protect) {
            return status;
        }
    }
    unsafe {
        *base_address = base as usize;
        *region_size = align_up(requested, PAGE_SIZE) as usize;
    }
    STATUS_SUCCESS
}

pub fn free_virtual_memory(
    process_handle: Handle,
    base_address: *mut usize,
    region_size: *mut usize,
) -> NtStatus {
    if process_handle != usize::MAX || base_address.is_null() || region_size.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let start = align_down(unsafe { *base_address } as u64, PAGE_SIZE);
    let len = align_up(unsafe { *region_size } as u64, PAGE_SIZE);
    let root_frame = match current_root_frame() {
        Ok(frame) => frame,
        Err(status) => return status,
    };
    for idx in 0..(len / PAGE_SIZE) {
        let virt = start + idx * PAGE_SIZE;
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virt));
        if let Ok(frame) = allocator::unmap_page_in(root_frame, page) {
            let _ = allocator::deallocate_frame(frame);
        }
        with_current_address_space(|space| {
            space.mappings.remove(&virt);
        });
    }
    STATUS_SUCCESS
}

pub fn protect_virtual_memory(
    process_handle: Handle,
    base_address: *mut usize,
    region_size: *mut usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> NtStatus {
    if process_handle != usize::MAX || base_address.is_null() || region_size.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let start = align_down(unsafe { *base_address } as u64, PAGE_SIZE);
    let len = align_up(unsafe { *region_size } as u64, PAGE_SIZE);
    let root_frame = match current_root_frame() {
        Ok(frame) => frame,
        Err(status) => return status,
    };
    let mut prev = new_protect;
    for idx in 0..(len / PAGE_SIZE) {
        let virt = start + idx * PAGE_SIZE;
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virt));
        let old = with_current_address_space(|space| {
            space.mappings.get(&virt).map(|mapping| mapping.prot)
        });
        if let Some(old) = old {
            prev = old;
        }
        if allocator::update_page_flags_in(root_frame, page, page_flags(new_protect)).is_err() {
            return STATUS_UNSUCCESSFUL;
        }
        with_current_address_space(|space| {
            if let Some(mapping) = space.mappings.get_mut(&virt) {
                mapping.prot = new_protect;
            }
        });
    }
    if !old_protect.is_null() {
        unsafe { *old_protect = prev };
    }
    STATUS_SUCCESS
}

fn read_utf16_string(us: *const UnicodeString) -> Result<String, NtStatus> {
    if us.is_null() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let us = unsafe { &*us };
    if us.buffer.is_null() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let len = usize::from(us.length) / 2;
    let slice = unsafe { core::slice::from_raw_parts(us.buffer, len) };
    let mut out = String::new();
    for ch in core::char::decode_utf16(slice.iter().copied()) {
        out.push(ch.map_err(|_| STATUS_INVALID_PARAMETER)?);
    }
    Ok(out)
}

fn path_from_object_attributes(attributes: *const ObjectAttributes) -> Result<String, NtStatus> {
    if attributes.is_null() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let attrs = unsafe { &*attributes };
    if attrs.object_name.is_null() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    read_utf16_string(attrs.object_name)
}

pub fn create_file(
    out_handle: *mut Handle,
    _desired_access: AccessMask,
    object_attributes: *const ObjectAttributes,
    io_status: *mut IoStatusBlock,
) -> NtStatus {
    if out_handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let nt_path = match path_from_object_attributes(object_attributes) {
        Ok(path) => path,
        Err(status) => return status,
    };
    let vfs_path = match nt::resolve_nt_path(&nt_path) {
        Ok(path) => path,
        Err(status) => return status,
    };
    let vfs_handle = match vfs::open(&vfs_path, 0) {
        Ok(handle) => handle,
        Err(_) => return STATUS_OBJECT_NAME_NOT_FOUND,
    };
    let object_id = nt::create_file(vfs_path.clone(), vfs_handle);
    let handle = match install_handle(object_id, nt::FILE_GENERIC_READ | nt::FILE_GENERIC_WRITE) {
        Ok(handle) => handle,
        Err(status) => {
            let _ = nt::release(object_id);
            return status;
        }
    };
    let _ = nt::release(object_id);
    unsafe { *out_handle = handle };
    if !io_status.is_null() {
        unsafe {
            *io_status = IoStatusBlock {
                status: STATUS_SUCCESS,
                information: 1,
            };
        }
    }
    STATUS_SUCCESS
}

pub fn read_file(
    handle: Handle,
    io_status: *mut IoStatusBlock,
    buffer: *mut u8,
    length: usize,
) -> NtStatus {
    if buffer.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let entry = match resolve_handle_entry(handle) {
        Ok(entry) => entry,
        Err(status) => return status,
    };
    let n = match nt::with_file(entry.object_id, |file| {
        let out = unsafe { core::slice::from_raw_parts_mut(buffer, length) };
        vfs::read(file.vfs_handle, out)
    }) {
        Ok(Ok(n)) => n,
        Ok(Err(_)) => return STATUS_UNSUCCESSFUL,
        Err(status) => return status,
    };
    if !io_status.is_null() {
        unsafe {
            *io_status = IoStatusBlock {
                status: if n == 0 {
                    STATUS_END_OF_FILE
                } else {
                    STATUS_SUCCESS
                },
                information: n,
            };
        }
    }
    if n == 0 {
        STATUS_END_OF_FILE
    } else {
        STATUS_SUCCESS
    }
}

pub fn write_file(
    handle: Handle,
    io_status: *mut IoStatusBlock,
    buffer: *const u8,
    length: usize,
) -> NtStatus {
    if buffer.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let entry = match resolve_handle_entry(handle) {
        Ok(entry) => entry,
        Err(status) => return status,
    };
    let n = match nt::with_file(entry.object_id, |file| {
        let data = unsafe { core::slice::from_raw_parts(buffer, length) };
        vfs::write(file.vfs_handle, data)
    }) {
        Ok(Ok(n)) => n,
        Ok(Err(_)) => return STATUS_UNSUCCESSFUL,
        Err(status) => return status,
    };
    if !io_status.is_null() {
        unsafe {
            *io_status = IoStatusBlock {
                status: STATUS_SUCCESS,
                information: n,
            };
        }
    }
    STATUS_SUCCESS
}

pub fn query_information_file(
    handle: Handle,
    io_status: *mut IoStatusBlock,
    file_information: *mut u8,
    length: u32,
    info_class: u32,
) -> NtStatus {
    if file_information.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let entry = match resolve_handle_entry(handle) {
        Ok(entry) => entry,
        Err(status) => return status,
    };
    let status = match info_class {
        nt::FILE_STANDARD_INFORMATION_CLASS => {
            if length < core::mem::size_of::<FileStandardInformation>() as u32 {
                STATUS_INFO_LENGTH_MISMATCH
            } else {
                let stat = match nt::with_file(entry.object_id, |file| vfs::fstat(file.vfs_handle)) {
                    Ok(Ok(stat)) => stat,
                    Ok(Err(_)) => return STATUS_UNSUCCESSFUL,
                    Err(status) => return status,
                };
                unsafe {
                    *(file_information as *mut FileStandardInformation) = FileStandardInformation {
                        allocation_size: stat.size as i64,
                        end_of_file: stat.size as i64,
                        number_of_links: 1,
                        delete_pending: 0,
                        directory: if (stat.mode & 0o040000) != 0 { 1 } else { 0 },
                        reserved: [0; 2],
                    };
                }
                STATUS_SUCCESS
            }
        }
        nt::FILE_POSITION_INFORMATION_CLASS => {
            if length < core::mem::size_of::<FilePositionInformation>() as u32 {
                STATUS_INFO_LENGTH_MISMATCH
            } else {
                let offset = match nt::with_file(entry.object_id, |file| vfs::lseek(file.vfs_handle, 0, 1)) {
                    Ok(Ok(offset)) => offset,
                    Ok(Err(_)) => return STATUS_UNSUCCESSFUL,
                    Err(status) => return status,
                };
                unsafe {
                    *(file_information as *mut FilePositionInformation) = FilePositionInformation {
                        current_byte_offset: offset as i64,
                    };
                }
                STATUS_SUCCESS
            }
        }
        nt::FILE_NAME_INFORMATION_CLASS => {
            let path = match nt::with_file(entry.object_id, |file| file.path.clone()) {
                Ok(path) => path,
                Err(status) => return status,
            };
            let utf16: Vec<u16> = path.encode_utf16().collect();
            let required = 4 + utf16.len() * 2;
            if usize::try_from(length).unwrap_or(0) < required {
                STATUS_BUFFER_TOO_SMALL
            } else {
                unsafe {
                    *(file_information as *mut u32) = (utf16.len() * 2) as u32;
                    core::ptr::copy_nonoverlapping(
                        utf16.as_ptr(),
                        (file_information.add(4)) as *mut u16,
                        utf16.len(),
                    );
                }
                STATUS_SUCCESS
            }
        }
        _ => STATUS_NOT_SUPPORTED,
    };
    if !io_status.is_null() {
        unsafe {
            *io_status = IoStatusBlock {
                status,
                information: usize::try_from(length).unwrap_or(0),
            };
        }
    }
    status
}

pub fn create_event(out_handle: *mut Handle, event_type: u32, initial_state: bool) -> NtStatus {
    if out_handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let manual_reset = event_type == nt::EVENT_TYPE_NOTIFICATION;
    let object_id = nt::create_event(manual_reset, initial_state);
    let handle = match install_handle(object_id, nt::EVENT_QUERY_STATE | nt::EVENT_MODIFY_STATE | nt::SYNCHRONIZE) {
        Ok(handle) => handle,
        Err(status) => {
            let _ = nt::release(object_id);
            return status;
        }
    };
    let _ = nt::release(object_id);
    unsafe { *out_handle = handle };
    STATUS_SUCCESS
}

pub fn set_event(handle: Handle, previous_state: *mut i32) -> NtStatus {
    let entry = match resolve_handle_entry(handle) {
        Ok(entry) => entry,
        Err(status) => return status,
    };
    match nt::with_event_mut(entry.object_id, |event| {
        let old = i32::from(event.signaled);
        event.signaled = true;
        (old, event.manual_reset)
    }) {
        Ok((old, _manual_reset)) => {
            if !previous_state.is_null() {
                unsafe { *previous_state = old };
            }
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

pub fn wait_for_single_object(handle: Handle) -> NtStatus {
    let entry = match resolve_handle_entry(handle) {
        Ok(entry) => entry,
        Err(status) => return status,
    };
    match nt::with_event_mut(entry.object_id, |event| {
        if event.signaled {
            if !event.manual_reset {
                event.signaled = false;
            }
            true
        } else {
            false
        }
    }) {
        Ok(true) => STATUS_SUCCESS,
        Ok(false) => STATUS_NOT_IMPLEMENTED,
        Err(status) => status,
    }
}

pub fn create_section(
    out_handle: *mut Handle,
    _desired_access: AccessMask,
    _object_attributes: *const ObjectAttributes,
    maximum_size: *const i64,
    protection: u32,
    attributes: u32,
    file_handle: Handle,
) -> NtStatus {
    if out_handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let path = if file_handle != 0 {
        let entry = match resolve_handle_entry(file_handle) {
            Ok(entry) => entry,
            Err(status) => return status,
        };
        match nt::with_file(entry.object_id, |file| file.path.clone()) {
            Ok(path) => Some(path),
            Err(status) => return status,
        }
    } else {
        None
    };
    let size = if maximum_size.is_null() {
        0
    } else {
        unsafe { *maximum_size }.max(0) as u64
    };
    let object_id = nt::create_section(path, protection, attributes, size);
    let handle = match install_handle(object_id, nt::SECTION_ALL_ACCESS) {
        Ok(handle) => handle,
        Err(status) => {
            let _ = nt::release(object_id);
            return status;
        }
    };
    let _ = nt::release(object_id);
    unsafe { *out_handle = handle };
    STATUS_SUCCESS
}

pub fn map_view_of_section(
    section_handle: Handle,
    process_handle: Handle,
    base_address: *mut usize,
    view_size: *mut usize,
    win32_protect: u32,
) -> NtStatus {
    if base_address.is_null() || view_size.is_null() || process_handle != usize::MAX {
        return STATUS_INVALID_PARAMETER;
    }
    let entry = match resolve_handle_entry(section_handle) {
        Ok(entry) => entry,
        Err(status) => return status,
    };
    let section = match nt::with_section(entry.object_id, |section| section.clone()) {
        Ok(section) => section,
        Err(status) => return status,
    };
    if (section.attributes & nt::SEC_IMAGE) != 0 {
        return STATUS_NOT_IMPLEMENTED;
    }
    let size = unsafe { *view_size }.max(section.size as usize);
    let status = allocate_virtual_memory(process_handle, base_address, view_size, win32_protect);
    if status != STATUS_SUCCESS {
        return status;
    }
    if let Some(path) = section.path {
        let file = match vfs::open(&path, 0) {
            Ok(file) => file,
            Err(_) => return STATUS_OBJECT_NAME_NOT_FOUND,
        };
        let data = unsafe { core::slice::from_raw_parts_mut(*base_address as *mut u8, size) };
        let n = match vfs::pread(file, 0, data) {
            Ok(n) => n,
            Err(_) => {
                let _ = vfs::close(file);
                return STATUS_UNSUCCESSFUL;
            }
        };
        if n < size {
            unsafe { core::ptr::write_bytes((*base_address + n) as *mut u8, 0, size - n) };
        }
        let _ = vfs::close(file);
    }
    STATUS_SUCCESS
}

pub fn unmap_view_of_section(process_handle: Handle, base_address: usize) -> NtStatus {
    let mut base = base_address;
    let mut size = PAGE_SIZE as usize;
    let _ = process_handle;
    free_virtual_memory(usize::MAX, &mut base, &mut size)
}

pub fn query_information_process(
    process_handle: Handle,
    info_class: u32,
    process_information: *mut u8,
    process_information_length: u32,
    return_length: *mut u32,
) -> NtStatus {
    if process_information.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let _ = match resolve_handle_entry(process_handle) {
        Ok(entry) => entry,
        Err(status) if process_handle == usize::MAX => {
            HandleEntry {
                object_id: current_slot().lock().process_object,
                access: nt::PROCESS_ALL_ACCESS,
            }
        }
        Err(status) => return status,
    };
    match info_class {
        nt::PROCESS_BASIC_INFORMATION_CLASS => {
            let required = core::mem::size_of::<ProcessBasicInformation>() as u32;
            if process_information_length < required {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            unsafe {
                *(process_information as *mut ProcessBasicInformation) = current_process_basic();
                if !return_length.is_null() {
                    *return_length = required;
                }
            }
            STATUS_SUCCESS
        }
        _ => STATUS_NOT_SUPPORTED,
    }
}

pub fn terminate_process(handle: Handle, exit_status: NtStatus) -> NtStatus {
    if handle != usize::MAX {
        return STATUS_NOT_IMPLEMENTED;
    }
    exit_current(exit_status);
    STATUS_SUCCESS
}

pub fn terminate_thread(handle: Handle, exit_status: NtStatus) -> NtStatus {
    if handle != usize::MAX - 4 {
        return STATUS_NOT_IMPLEMENTED;
    }
    exit_current(exit_status);
    STATUS_SUCCESS
}

pub fn create_user_process(_path: &str) -> NtStatus {
    STATUS_NOT_IMPLEMENTED
}

pub fn exit_current(status: NtStatus) {
    let pid = current_pid_internal();
    let task_id = process::current_task_id();
    let mut current = current_slot().lock();
    current.exited = true;
    current.exit_status = status;
    current.task_id = None;
    let object_ids: Vec<u32> = current
        .handles
        .iter_mut()
        .filter_map(|entry| entry.take().map(|entry| entry.object_id))
        .collect();
    drop(current);
    for object_id in object_ids {
        let _ = nt::release(object_id);
    }
    let mut registry = REGISTRY.lock();
    if let Some(proc) = registry.by_pid.get_mut(&pid) {
        proc.exited = true;
        proc.exit_status = status;
        proc.task_id = None;
    }
    if let Some(task_id) = task_id {
        registry.task_to_pid.remove(&task_id);
    }
}

pub fn create_init_task(task_id: usize, path: &str) -> Result<process::Task, NtStatus> {
    nt::init_namespace();
    let pid = 1;
    {
        let mut current = current_slot().lock();
        *current = UserProcess::default();
        current.pid = pid;
        current.ppid = 0;
        current.address_space_id = 1;
        current.task_id = Some(task_id);
        current.process_object = nt::create_process(pid);
        current.thread_object = nt::create_thread(pid, task_id);
        seed_standard_handles(&mut current)?;
    }
    {
        let mut registry = REGISTRY.lock();
        let space = create_address_space()?;
        registry.spaces.insert(1, space);
        registry.by_pid.insert(pid, current_slot().lock().clone());
        registry.task_to_pid.insert(task_id, pid);
    }
    switch_active_process(Some(pid));
    let ctx = load_init_context(task_id, pid, path)?;
    REGISTRY
        .lock()
        .by_pid
        .insert(pid, current_slot().lock().clone());
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

fn load_init_context(task_id: usize, pid: u32, nt_path: &str) -> Result<process::SavedTaskContext, NtStatus> {
    let vfs_path = nt::resolve_nt_path(nt_path)?;
    let bytes = vfs::read_all(&vfs_path).map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;
    let image = load_pe_image(&bytes)?;

    let stack_bottom = USER_STACK_TOP - USER_STACK_PAGES * PAGE_SIZE;
    map_region(stack_bottom, USER_STACK_PAGES * PAGE_SIZE, nt::PAGE_READWRITE)?;
    let stack_top = USER_STACK_TOP;

    {
        let mut current = current_slot().lock();
        current.image_base = image.image_base;
    }
    let (peb_addr, teb_addr, params_addr) = build_process_environment(nt_path, stack_top)?;
    {
        let mut current = current_slot().lock();
        current.pid = pid;
        current.task_id = Some(task_id);
        current.image_path = Some(nt_path.to_string());
        current.peb_addr = peb_addr;
        current.teb_addr = teb_addr;
        current.params_addr = params_addr;
        current.fs_base = teb_addr;
    }
    FsBase::write(VirtAddr::new(teb_addr));

    Ok(process::SavedTaskContext {
        rip: image.entry as usize,
        cs: usize::from(gdt::user_code_selector().0),
        rflags: 0x202,
        rsp: align_down(stack_top - 0x20, 16) as usize,
        ss: usize::from(gdt::user_data_selector().0),
        ..process::SavedTaskContext::default()
    })
}

fn load_pe_image(bytes: &[u8]) -> Result<LoadedImage, NtStatus> {
    let pe = PE::parse(bytes).map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
    if !pe.is_64 {
        return Err(STATUS_INVALID_IMAGE_FORMAT);
    }
    if pe.header.coff_header.machine != goblin::pe::header::COFF_MACHINE_X86_64 {
        return Err(nt::STATUS_IMAGE_MACHINE_TYPE_MISMATCH);
    }
    if !pe.libraries.is_empty() {
        return Err(STATUS_NOT_SUPPORTED);
    }
    let optional = pe.header.optional_header.ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
    let image_base = pe.image_base;
    let size_of_image = optional.windows_fields.size_of_image as u64;
    let size_of_headers = optional.windows_fields.size_of_headers as usize;
    map_region(image_base, align_up(size_of_image, PAGE_SIZE), nt::PAGE_READWRITE)?;
    unsafe {
        core::ptr::write_bytes(image_base as *mut u8, 0, size_of_image as usize);
        core::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            image_base as *mut u8,
            size_of_headers.min(bytes.len()),
        );
    }
    for section in &pe.sections {
        let virt = image_base + section.virtual_address as u64;
        let raw_offset = section.pointer_to_raw_data as usize;
        let raw_size = section.size_of_raw_data as usize;
        let virtual_size = (section.virtual_size.max(section.size_of_raw_data)) as usize;
        if raw_size != 0 {
            let end = raw_offset.saturating_add(raw_size).min(bytes.len());
            unsafe {
                core::ptr::copy_nonoverlapping(
                    bytes[raw_offset..end].as_ptr(),
                    virt as *mut u8,
                    end.saturating_sub(raw_offset),
                );
            }
        }
        if virtual_size > raw_size {
            unsafe {
                core::ptr::write_bytes(
                    (virt + raw_size as u64) as *mut u8,
                    0,
                    virtual_size.saturating_sub(raw_size),
                );
            }
        }
        let prot = section_to_protection(section.characteristics);
        protect_region(virt, align_up(virtual_size as u64, PAGE_SIZE), prot)?;
    }
    let headers_protect = nt::PAGE_READONLY;
    protect_region(image_base, align_up(size_of_headers as u64, PAGE_SIZE), headers_protect)?;
    let entry = image_base + pe.entry as u64;
    kdebug!(
        "USER-PE path image_base={:#x} size={:#x} entry={:#x}",
        image_base,
        size_of_image,
        entry
    );
    Ok(LoadedImage {
        entry,
        image_base,
        size_of_image,
    })
}

fn protect_region(start: u64, len: u64, prot: u32) -> Result<(), NtStatus> {
    let root_frame = current_root_frame()?;
    let page_count = align_up(len, PAGE_SIZE) / PAGE_SIZE;
    for idx in 0..page_count {
        let virt = start + idx * PAGE_SIZE;
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virt));
        allocator::update_page_flags_in(root_frame, page, page_flags(prot))
            .map_err(|_| STATUS_UNSUCCESSFUL)?;
        with_current_address_space(|space| {
            if let Some(mapping) = space.mappings.get_mut(&virt) {
                mapping.prot = prot;
            }
        });
    }
    Ok(())
}

fn section_to_protection(characteristics: u32) -> u32 {
    let executable = (characteristics & 0x2000_0000) != 0;
    let readable = (characteristics & 0x4000_0000) != 0;
    let writable = (characteristics & 0x8000_0000) != 0;
    match (executable, readable, writable) {
        (true, true, true) => nt::PAGE_EXECUTE_READWRITE,
        (true, true, false) => nt::PAGE_EXECUTE_READ,
        (true, false, false) => nt::PAGE_EXECUTE,
        (false, true, true) => nt::PAGE_READWRITE,
        (false, true, false) => nt::PAGE_READONLY,
        _ => nt::PAGE_NOACCESS,
    }
}

fn build_process_environment(nt_path: &str, stack_top: u64) -> Result<(u64, u64, u64), NtStatus> {
    let env_base = USER_ENV_BASE;
    map_region(env_base, USER_ENV_PAGES * PAGE_SIZE, nt::PAGE_READWRITE)?;
    let mut cursor = env_base;
    let image_utf16: Vec<u16> = nt_path.encode_utf16().collect();
    let cmd_utf16: Vec<u16> = nt_path.encode_utf16().collect();

    let params_addr = cursor;
    cursor += core::mem::size_of::<RtlUserProcessParameters>() as u64;
    let image_buf = align_up(cursor, 2);
    copy_utf16(image_buf, &image_utf16);
    cursor = image_buf + ((image_utf16.len() * 2 + 2) as u64);
    let cmd_buf = align_up(cursor, 2);
    copy_utf16(cmd_buf, &cmd_utf16);
    cursor = cmd_buf + ((cmd_utf16.len() * 2 + 2) as u64);
    let peb_addr = align_up(cursor, 16);
    cursor = peb_addr + core::mem::size_of::<Peb>() as u64;
    let teb_addr = align_up(cursor, 16);

    let mut params = RtlUserProcessParameters::default();
    {
        let current = current_slot().lock();
        params.standard_input = current.standard_input;
        params.standard_output = current.standard_output;
        params.standard_error = current.standard_error;
    }
    params.image_path_name = UnicodeString {
        length: (image_utf16.len() * 2) as u16,
        maximum_length: (image_utf16.len() * 2 + 2) as u16,
        buffer: image_buf as *const u16,
    };
    params.command_line = UnicodeString {
        length: (cmd_utf16.len() * 2) as u16,
        maximum_length: (cmd_utf16.len() * 2 + 2) as u16,
        buffer: cmd_buf as *const u16,
    };
    unsafe { *(params_addr as *mut RtlUserProcessParameters) = params };

    let peb = Peb {
        image_base_address: current_slot().lock().image_base as usize,
        process_parameters: params_addr as *mut RtlUserProcessParameters,
        ..Peb::default()
    };
    unsafe { *(peb_addr as *mut Peb) = peb };
    let teb = Teb {
        process_environment_block: peb_addr as *mut Peb,
        client_id: ClientId {
            unique_process: current_slot().lock().pid as usize,
            unique_thread: process::current_task_id().unwrap_or(0),
        },
        ..Teb::default()
    };
    unsafe { *(teb_addr as *mut Teb) = teb };
    let _ = stack_top;
    Ok((peb_addr, teb_addr, params_addr))
}

fn copy_utf16(dst: u64, text: &[u16]) {
    unsafe {
        core::ptr::copy_nonoverlapping(text.as_ptr(), dst as *mut u16, text.len());
        (dst as *mut u16).add(text.len()).write(0);
    }
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
