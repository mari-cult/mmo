use core::fmt;
use spin::Mutex;

pub struct SerialPort {
    base_address: *mut u32,
}

impl SerialPort {
    pub const fn new() -> Self {
        Self {
            base_address: 0x0900_0000 as *mut u32,
        }
    }

    pub fn init(&mut self) {
        // PL011 initialization is usually handled by firmware/Limine for basic output.
        // On QEMU virt, 0x09000000 is the default UART.
    }

    pub fn send(&mut self, data: u8) {
        unsafe {
            // Wait for UART to be ready to transmit (FR register, TXFF bit)
            while (self.base_address.add(6).read_volatile() & (1 << 5)) != 0 {}
            // Write data to DR register
            self.base_address.read_volatile(); // dummy read for some reason? no.
            self.base_address.write_volatile(data as u32);
        }
    }
}

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.send(b'\r');
            }
            self.send(byte);
        }
        Ok(())
    }
}

unsafe impl Send for SerialPort {}
unsafe impl Sync for SerialPort {}

pub static SERIAL_PORT: Mutex<SerialPort> = Mutex::new(SerialPort::new());

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::arch::serial::_print(format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

pub fn _print(args: fmt::Arguments) {
    use core::fmt::Write;
    SERIAL_PORT.lock().write_fmt(args).unwrap();
}

pub fn tty_iflag() -> u32 {
    0
}
pub fn tty_oflag() -> u32 {
    0
}
pub fn tty_cflag() -> u32 {
    0
}
pub fn tty_lflag() -> u32 {
    0
}
pub fn set_tty_termios(_i: u32, _o: u32, _c: u32, _l: u32) {}
pub fn read_byte_blocking() -> u8 {
    0
}
pub fn try_read_byte() -> Option<u8> {
    None
}
pub fn echo_input_byte(_b: u8) {}
pub fn has_input() -> bool {
    false
}
