use crate::println;
use core::arch::asm;
use core::hint::spin_loop;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use limine_sys::*;
use crate::limine::{Request, MP_REQUEST_ID};

pub const MAX_CPUS: usize = 32;
const AP_BOOT_SPINS: usize = 2_000_000;

#[used]
#[unsafe(link_section = ".limine_requests")]
pub static MP_REQUEST: Request<limine_mp_response> = Request::new(MP_REQUEST_ID);

static DISCOVERED_CPUS: AtomicUsize = AtomicUsize::new(1);
static ONLINE_CPUS: AtomicUsize = AtomicUsize::new(1);
static AP_READY: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];
static LAPIC_IDS: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(u32::MAX) }; MAX_CPUS];

#[derive(Debug, Clone, Copy)]
pub struct CpuTopology {
    pub discovered_cpus: usize,
    pub online_cpus: usize,
    pub bootstrap_lapic_id: u32,
}

pub fn init() -> CpuTopology {
    if let Some(response) = MP_REQUEST.response() {
        let cpu_count = response.cpu_count as usize;
        let cpus = unsafe {
            core::slice::from_raw_parts(response.cpus as *const &limine_mp_info, cpu_count)
        };
        let discovered = cpu_count.max(1).min(MAX_CPUS);

        DISCOVERED_CPUS.store(discovered, Ordering::SeqCst);
        ONLINE_CPUS.store(1, Ordering::SeqCst);

        for ready in AP_READY.iter().take(discovered) {
            ready.store(false, Ordering::SeqCst);
        }

        for (logical_id, cpu) in cpus.iter().take(discovered).enumerate() {
            unsafe {
                let cpu_ptr = *cpu as *const limine_mp_info as *mut limine_mp_info;
                (*cpu_ptr).extra_argument = logical_id as u64;
                LAPIC_IDS[logical_id].store((*cpu_ptr).lapic_id, Ordering::SeqCst);
                if (*cpu_ptr).lapic_id == response.bsp_lapic_id {
                    AP_READY[logical_id].store(true, Ordering::SeqCst);
                    continue;
                }

                (*cpu_ptr).goto_address = core::mem::transmute(ap_entry as *const ());
            }
        }

        for _ in 0..AP_BOOT_SPINS {
            if ONLINE_CPUS.load(Ordering::SeqCst) >= discovered {
                break;
            }
            spin_loop();
        }

        let online = ONLINE_CPUS.load(Ordering::SeqCst).min(discovered);
        println!(
            "SMP: Limine MP discovered {} CPUs, {} online, BSP lapic_id={}",
            discovered,
            online,
            response.bsp_lapic_id
        );

        CpuTopology {
            discovered_cpus: discovered,
            online_cpus: online,
            bootstrap_lapic_id: response.bsp_lapic_id,
        }
    } else {
        println!("SMP: no Limine MP response, running BSP-only");
        CpuTopology {
            discovered_cpus: 1,
            online_cpus: 1,
            bootstrap_lapic_id: 0,
        }
    }
}

pub fn discovered_cpus() -> usize {
    DISCOVERED_CPUS.load(Ordering::SeqCst)
}

pub fn online_cpus() -> usize {
    ONLINE_CPUS.load(Ordering::SeqCst)
}

pub fn logical_cpu_id(lapic_id: u32) -> Option<usize> {
    let discovered = DISCOVERED_CPUS.load(Ordering::SeqCst).min(MAX_CPUS);
    (0..discovered).find(|idx| LAPIC_IDS[*idx].load(Ordering::SeqCst) == lapic_id)
}

pub fn current_cpu() -> usize {
    let Some(lapic_id) = crate::arch::apic::current_lapic_id() else {
        return 0;
    };
    logical_cpu_id(lapic_id).unwrap_or(0)
}

unsafe extern "C" fn ap_entry(cpu: *mut limine_mp_info) -> ! {
    let logical_id = unsafe { (*cpu).extra_argument as usize };
    crate::arch::gdt::init_for_cpu(logical_id);
    crate::arch::idt::load_local();
    crate::arch::init_local_cpu_features();
    crate::arch::apic::init();
    crate::syscall::init_for_cpu(logical_id);
    ONLINE_CPUS.fetch_add(1, Ordering::SeqCst);
    if logical_id < MAX_CPUS {
        AP_READY[logical_id].store(true, Ordering::SeqCst);
    }

    loop {
        unsafe {
            asm!("sti; hlt; cli");
        }
    }
}
