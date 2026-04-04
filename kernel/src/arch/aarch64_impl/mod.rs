pub mod serial;

pub use serial::*;

use core::arch::asm;
use core::marker::PhantomData;
use core::ops::{Add, AddAssign, Sub, SubAssign};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct VirtAddr(u64);

impl VirtAddr {
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }
    pub fn as_u64(self) -> u64 {
        self.0
    }
    pub fn as_ptr<T>(self) -> *const T {
        self.0 as *const T
    }
    pub fn as_mut_ptr<T>(self) -> *mut T {
        self.0 as *mut T
    }
}

impl Add<u64> for VirtAddr {
    type Output = Self;
    fn add(self, other: u64) -> Self {
        Self(self.0 + other)
    }
}

impl Sub<u64> for VirtAddr {
    type Output = Self;
    fn sub(self, other: u64) -> Self {
        Self(self.0 - other)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct PhysAddr(u64);

impl PhysAddr {
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl Add<u64> for PhysAddr {
    type Output = Self;
    fn add(self, other: u64) -> Self {
        Self(self.0 + other)
    }
}

pub const MAX_CPUS: usize = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SavedTaskContext {
    pub x0: usize,
    pub x1: usize,
    pub x2: usize,
    pub x3: usize,
    pub x4: usize,
    pub x5: usize,
    pub x6: usize,
    pub x7: usize,
    pub x8: usize,
    pub x9: usize,
    pub x10: usize,
    pub x11: usize,
    pub x12: usize,
    pub x13: usize,
    pub x14: usize,
    pub x15: usize,
    pub x16: usize,
    pub x17: usize,
    pub x18: usize,
    pub x19: usize,
    pub x20: usize,
    pub x21: usize,
    pub x22: usize,
    pub x23: usize,
    pub x24: usize,
    pub x25: usize,
    pub x26: usize,
    pub x27: usize,
    pub x28: usize,
    pub x29: usize,
    pub x30: usize,
    pub sp: usize,
    pub elr: usize,
    pub spsr: usize,

    // x86_64 compatibility fields
    pub rip: usize,
    pub rsp: usize,
    pub rax: usize,
    pub rdi: usize,
    pub rsi: usize,
    pub rdx: usize,
    pub rbp: usize,
    pub rbx: usize,
    pub rcx: usize,
    pub r8: usize,
    pub r9: usize,
    pub r10: usize,
    pub r11: usize,
    pub r12: usize,
    pub r13: usize,
    pub r14: usize,
    pub r15: usize,
    pub cs: usize,
    pub ss: usize,
    pub rflags: usize,
}

// Aliases for core logic that assumes x86 names for now
impl SavedTaskContext {
    pub fn rip(&self) -> usize {
        self.elr
    }
    pub fn rsp(&self) -> usize {
        self.sp
    }
    pub fn rax(&self) -> usize {
        self.x0
    }
}

pub mod gdt {
    pub struct SegmentSelector(pub u16);
    pub fn user_code_selector() -> SegmentSelector {
        SegmentSelector(0)
    }
    pub fn user_data_selector() -> SegmentSelector {
        SegmentSelector(0)
    }
    pub const DOUBLE_FAULT_IST_INDEX: u8 = 0;
}

impl gdt::SegmentSelector {
    pub fn as_u16(self) -> u16 {
        self.0
    }
    pub const fn zero() -> Self {
        Self(0)
    }
}

pub mod smp {
    pub const MAX_CPUS: usize = 1;
    pub fn current_cpu() -> usize {
        0
    }
}

pub mod apic {
    pub fn complete_interrupt() {}
    pub fn current_lapic_id() -> Option<u32> {
        None
    }
}

pub mod pci {
    use super::{PhysAddr, VirtAddr};
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PciAddress {
        pub bus: u8,
        pub slot: u8,
        pub function: u8,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PciBar {
        pub index: u8,
        pub address: u64,
        pub is_mmio: bool,
        pub is_64bit: bool,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PciDevice {
        pub address: PciAddress,
        pub vendor_id: u16,
        pub device_id: u16,
        pub class_code: u8,
        pub subclass: u8,
        pub prog_if: u8,
        pub bars: [Option<PciBar>; 6],
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PciCapability {
        pub id: u8,
        pub offset: u8,
    }
    pub fn read_config_dword(_addr: PciAddress, _offset: u8) -> u32 {
        0
    }
    pub fn read_config_byte(_addr: PciAddress, _offset: u8) -> u8 {
        0
    }
    pub fn scan_bus0() -> [Option<PciDevice>; 32] {
        [None; 32]
    }
    pub fn capabilities(_addr: PciAddress) -> [Option<PciCapability>; 32] {
        [None; 32]
    }
    pub fn map_mmio(_phys_addr: u64, _length: u64) -> Result<VirtAddr, ()> {
        Ok(VirtAddr::new(0))
    }
}

pub trait PageSize: Clone + PartialOrd + Ord {
    const SIZE: u64;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Size4KiB;
impl PageSize for Size4KiB {
    const SIZE: u64 = 4096;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Page<S: PageSize = Size4KiB> {
    pub start_address: VirtAddr,
    _phantom: PhantomData<S>,
}

impl<S: PageSize> Page<S> {
    pub fn containing_address(addr: VirtAddr) -> Self {
        Self {
            start_address: VirtAddr::new(addr.as_u64() & !(S::SIZE - 1)),
            _phantom: PhantomData,
        }
    }
    pub fn range_inclusive(start: Self, end: Self) -> core::ops::RangeInclusive<Self> {
        start..=end
    }
    pub fn start_address(&self) -> VirtAddr {
        self.start_address
    }
}

impl<S: PageSize> core::iter::Step for Page<S> {
    fn steps_between(start: &Self, end: &Self) -> (usize, Option<usize>) {
        if start.start_address.as_u64() > end.start_address.as_u64() {
            (0, Some(0))
        } else {
            let diff = (end.start_address.as_u64() - start.start_address.as_u64()) / S::SIZE;
            (diff as usize, Some(diff as usize))
        }
    }
    fn forward_checked(start: Self, count: usize) -> Option<Self> {
        Some(Self {
            start_address: VirtAddr::new(start.start_address.as_u64() + count as u64 * S::SIZE),
            _phantom: PhantomData,
        })
    }
    fn backward_checked(start: Self, count: usize) -> Option<Self> {
        Some(Self {
            start_address: VirtAddr::new(start.start_address.as_u64() - count as u64 * S::SIZE),
            _phantom: PhantomData,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysFrame<S: PageSize = Size4KiB> {
    pub start_address: PhysAddr,
    _phantom: PhantomData<S>,
}

impl<S: PageSize> PhysFrame<S> {
    pub fn containing_address(addr: PhysAddr) -> Self {
        Self {
            start_address: PhysAddr::new(addr.as_u64() & !(S::SIZE - 1)),
            _phantom: PhantomData,
        }
    }
    pub fn start_address(&self) -> PhysAddr {
        self.start_address
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PageTableFlags: u64 {
        const PRESENT = 1 << 0;
        const WRITABLE = 1 << 1;
        const USER_ACCESSIBLE = 1 << 2;
        const NO_EXECUTE = 1 << 3;
        const NO_CACHE = 1 << 4;
    }
}

pub mod paging {
    use super::*;
    pub unsafe fn init(_hhdm_offset: VirtAddr) -> OffsetPageTable {
        OffsetPageTable
    }
    pub unsafe fn init_for_frame(_offset: VirtAddr, _root: PhysFrame) -> OffsetPageTable {
        OffsetPageTable
    }
    pub unsafe fn copy_kernel_mappings(_new: &mut PageTable, _old: &PageTable) {}
    pub unsafe fn switch_to(_frame: PhysFrame) {}
}

pub struct OffsetPageTable;
pub trait Mapper<S: PageSize> {
    fn map_to(
        &mut self,
        page: Page<S>,
        frame: PhysFrame<S>,
        flags: PageTableFlags,
        alloc: &mut impl FrameAllocator<S>,
    ) -> Result<MapperFlush<S>, MapToError<S>>;
    fn unmap(&mut self, page: Page<S>) -> Result<(PhysFrame<S>, MapperFlush<S>), UnmapError>;
    unsafe fn update_flags(
        &mut self,
        page: Page<S>,
        flags: PageTableFlags,
    ) -> Result<MapperFlush<S>, FlagUpdateError>;
}

impl<S: PageSize> Mapper<S> for OffsetPageTable {
    fn map_to(
        &mut self,
        _page: Page<S>,
        _frame: PhysFrame<S>,
        _flags: PageTableFlags,
        _alloc: &mut impl FrameAllocator<S>,
    ) -> Result<MapperFlush<S>, MapToError<S>> {
        Ok(MapperFlush(PhantomData))
    }
    fn unmap(&mut self, _page: Page<S>) -> Result<(PhysFrame<S>, MapperFlush<S>), UnmapError> {
        Ok((
            PhysFrame {
                start_address: PhysAddr::new(0),
                _phantom: PhantomData,
            },
            MapperFlush(PhantomData),
        ))
    }
    unsafe fn update_flags(
        &mut self,
        _page: Page<S>,
        _flags: PageTableFlags,
    ) -> Result<MapperFlush<S>, FlagUpdateError> {
        Ok(MapperFlush(PhantomData))
    }
}

pub struct MapperFlush<S: PageSize>(PhantomData<S>);
impl<S: PageSize> MapperFlush<S> {
    pub fn flush(&self) {}
}

pub unsafe trait FrameAllocator<S: PageSize> {
    fn allocate_frame(&mut self) -> Option<PhysFrame<S>>;
}

#[derive(Debug)]
pub enum MapToError<S: PageSize> {
    FrameAllocationFailed,
    _Phantom(PhantomData<S>),
}
#[derive(Debug)]
pub enum UnmapError {
    PageNotMapped,
}
#[derive(Debug)]
pub enum FlagUpdateError {
    PageNotMapped,
}

#[repr(C, align(4096))]
pub struct PageTable([u64; 512]);
impl PageTable {
    pub fn clone(&self) -> Self {
        Self(self.0)
    }
}
impl core::ops::Index<usize> for PageTable {
    type Output = u64;
    fn index(&self, index: usize) -> &u64 {
        &self.0[index]
    }
}
impl core::ops::IndexMut<usize> for PageTable {
    fn index_mut(&mut self, index: usize) -> &mut u64 {
        &mut self.0[index]
    }
}

pub fn init_paging(_hhdm_offset: u64) {}
pub fn init_hardware() {}
pub fn init_smp() -> usize {
    1
}

pub fn without_interrupts<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    f()
}

pub const ARCH_NAME: &str = "aarch64";
pub const DYNLINK_PATH: &str = "/lib/ld-musl-aarch64.so.1";
pub const DYNLINK_CONF: &str = "/usr/etc/ld-musl-aarch64.path";

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

pub fn init_syscalls(_cpu_id: usize, _stack_top: usize) {}
pub fn set_kernel_stack_top(_cpu_id: usize, _stack_top: usize) {}
pub fn get_fs_base() -> u64 {
    0
}
pub fn set_fs_base(_val: u64) {}

pub unsafe fn restore_task_context(_next_ctx: *const SavedTaskContext) -> ! {
    loop {}
}

pub fn get_initial_segments() -> (usize, usize) {
    (0, 0)
}

pub fn get_current_paging_root() -> PhysFrame {
    PhysFrame {
        start_address: PhysAddr::new(0),
        _phantom: PhantomData,
    }
}

pub fn complete_interrupt() {}

pub fn halt() -> ! {
    loop {
        unsafe {
            asm!("wfi");
        }
    }
}

pub fn disable_interrupts() {
    unsafe {
        asm!("msr daifset, #2");
    }
}

pub fn enable_interrupts() {
    unsafe {
        asm!("msr daifclr, #2");
    }
}

pub fn nop() {
    unsafe {
        asm!("nop");
    }
}
