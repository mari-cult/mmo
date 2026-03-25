use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;
use x86_64::instructions::port::Port;

pub struct SerialPort {
    data: Port<u8>,
    interrupt_enable: Port<u8>,
    fifo_control: Port<u8>,
    line_control: Port<u8>,
    modem_control: Port<u8>,
    line_status: Port<u8>,
}

impl SerialPort {
    pub const fn new(port: u16) -> Self {
        Self {
            data: Port::new(port),
            interrupt_enable: Port::new(port + 1),
            fifo_control: Port::new(port + 2),
            line_control: Port::new(port + 3),
            modem_control: Port::new(port + 4),
            line_status: Port::new(port + 5),
        }
    }

    pub fn init(&mut self) {
        unsafe {
            self.interrupt_enable.write(0x00);
            self.line_control.write(0x80);
            self.data.write(0x03);
            self.interrupt_enable.write(0x00);
            self.line_control.write(0x03);
            self.fifo_control.write(0xC7);
            self.modem_control.write(0x0B);
        }
    }

    pub fn send(&mut self, data: u8) {
        while unsafe { self.line_status.read() } & 0x20 == 0 {}
        unsafe {
            self.data.write(data);
        }
    }
}

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            self.send(byte);
        }
        Ok(())
    }
}

pub static SERIAL1: Mutex<SerialPort> = Mutex::new(SerialPort::new(0x3F8));
static SERIAL_READY: AtomicBool = AtomicBool::new(false);

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::serial::_print(format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use core::fmt::Write;
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut serial = SERIAL1.lock();
        if !SERIAL_READY.swap(true, Ordering::SeqCst) {
            serial.init();
        }
        serial.write_fmt(args).expect("Printing to serial failed");
    });
}
