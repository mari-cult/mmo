use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;
use x86_64::instructions::port::Port;

const TTY_LFLAG_ECHO: u32 = 0x0000_0008;
const DEFAULT_TTY_IFLAG: u32 = 0x0000_0500;
const DEFAULT_TTY_OFLAG: u32 = 0x0000_0005;
const DEFAULT_TTY_CFLAG: u32 = 0x0000_00bf;
const DEFAULT_TTY_LFLAG: u32 = 0x0000_8a3b;

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

    pub fn received(&mut self) -> bool {
        (unsafe { self.line_status.read() } & 0x01) != 0
    }

    pub fn receive(&mut self) -> Option<u8> {
        if self.received() {
            Some(unsafe { self.data.read() })
        } else {
            None
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
static TTY_IFLAG: AtomicU32 = AtomicU32::new(DEFAULT_TTY_IFLAG);
static TTY_OFLAG: AtomicU32 = AtomicU32::new(DEFAULT_TTY_OFLAG);
static TTY_CFLAG: AtomicU32 = AtomicU32::new(DEFAULT_TTY_CFLAG);
static TTY_LFLAG: AtomicU32 = AtomicU32::new(DEFAULT_TTY_LFLAG);

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

pub fn try_read_byte() -> Option<u8> {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut serial = SERIAL1.lock();
        if !SERIAL_READY.swap(true, Ordering::SeqCst) {
            serial.init();
        }
        serial.receive()
    })
}

pub fn has_input() -> bool {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut serial = SERIAL1.lock();
        if !SERIAL_READY.swap(true, Ordering::SeqCst) {
            serial.init();
        }
        serial.received()
    })
}

pub fn read_byte_blocking() -> u8 {
    loop {
        if let Some(byte) = try_read_byte() {
            return byte;
        }
        core::hint::spin_loop();
    }
}

pub fn tty_iflag() -> u32 {
    TTY_IFLAG.load(Ordering::SeqCst)
}

pub fn tty_oflag() -> u32 {
    TTY_OFLAG.load(Ordering::SeqCst)
}

pub fn tty_cflag() -> u32 {
    TTY_CFLAG.load(Ordering::SeqCst)
}

pub fn tty_lflag() -> u32 {
    TTY_LFLAG.load(Ordering::SeqCst)
}

pub fn set_tty_termios(iflag: u32, oflag: u32, cflag: u32, lflag: u32) {
    TTY_IFLAG.store(iflag, Ordering::SeqCst);
    TTY_OFLAG.store(oflag, Ordering::SeqCst);
    TTY_CFLAG.store(cflag, Ordering::SeqCst);
    TTY_LFLAG.store(lflag, Ordering::SeqCst);
}

pub fn tty_echo_enabled() -> bool {
    (tty_lflag() & TTY_LFLAG_ECHO) != 0
}

pub fn echo_input_byte(byte: u8) {
    if !tty_echo_enabled() {
        return;
    }
    match byte {
        0x08 | 0x7f => _print(format_args!("\u{8} \u{8}")),
        b'\n' => _print(format_args!("\n")),
        _ => _print(format_args!("{}", byte as char)),
    }
}
