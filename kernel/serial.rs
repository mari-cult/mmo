use core::fmt;
use spin::Mutex;
use x86_64::instructions::port::Port;

pub struct SerialPort {
    data: Port<u8>,
}

impl SerialPort {
    pub const fn new(port: u16) -> Self {
        Self {
            data: Port::new(port),
        }
    }

    pub fn send(&mut self, data: u8) {
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
        SERIAL1
            .lock()
            .write_fmt(args)
            .expect("Printing to serial failed");
    });
}
