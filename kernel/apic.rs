use x86_64::registers::model_specific::Msr;
use crate::println;

pub const APIC_BASE_MSR: u32 = 0x1B;

pub struct LocalApic {
    base_addr: u64,
}

impl LocalApic {
    pub unsafe fn new() -> Self {
        let apic_base_msr = Msr::new(APIC_BASE_MSR);
        let base_addr = unsafe { apic_base_msr.read() & 0xFFFFF000 };
        println!("APIC: Base address at {:#x}", base_addr);
        Self { base_addr }
    }

    unsafe fn write(&self, offset: u32, value: u32) {
        let ptr = (self.base_addr + offset as u64) as *mut u32;
        unsafe { ptr.write_volatile(value) };
    }

    unsafe fn read(&self, offset: u32) -> u32 {
        let ptr = (self.base_addr + offset as u64) as *const u32;
        unsafe { ptr.read_volatile() }
    }

    pub unsafe fn init(&self) {
        unsafe {
            // Spurious Interrupt Vector Register
            // Enable APIC by setting bit 8, and use vector 255 for spurious interrupts
            self.write(0xF0, self.read(0xF0) | 0x100 | 0xFF);

            // Timer Divide Configuration Register
            // Divide by 16
            self.write(0x3E0, 0x03);

            // LVT Timer Register
            // Periodic mode (bit 17), Vector 32 (Timer)
            self.write(0x320, (1 << 17) | 32);

            // Initial Count Register
            // Set to a reasonable value for periodic ticks
            self.write(0x380, 0x1000000);
        }
        
        println!("APIC: Initialized timer.");
    }
    
    pub unsafe fn complete_interrupt(&self) {
        // End of Interrupt (EOI) register
        unsafe { self.write(0x0B0, 0) };
    }
}

pub static mut APIC: Option<LocalApic> = None;

pub fn init() {
    unsafe {
        let apic = LocalApic::new();
        apic.init();
        APIC = Some(apic);
    }
}

pub fn complete_interrupt() {
    unsafe {
        if let Some(ref apic) = APIC {
            apic.complete_interrupt();
        }
    }
}
