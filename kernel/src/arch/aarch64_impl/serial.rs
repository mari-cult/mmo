use core::fmt;
use spin::Mutex;

pub struct SerialPort {}

impl SerialPort {
    pub const fn new() -> Self {
        Self {}
    }
    pub fn init(&mut self) {}
    pub fn send(&mut self, _data: u8) {}
}

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            self.send(byte);
        }
        Ok(())
    }
}

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

pub fn tty_iflag() -> u32 { 0 }
pub fn tty_oflag() -> u32 { 0 }
pub fn tty_cflag() -> u32 { 0 }
pub fn tty_lflag() -> u32 { 0 }
pub fn set_tty_termios(_i: u32, _o: u32, _c: u32, _l: u32) {}
pub fn read_byte_blocking() -> u8 { 0 }
pub fn try_read_byte() -> Option<u8> { None }
pub fn echo_input_byte(_b: u8) {}
pub fn has_input() -> bool { false }
