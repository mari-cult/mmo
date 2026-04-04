use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

impl Level {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Trace => "TRACE",
        }
    }

    pub const fn from_linux_console_level(level: u8) -> Self {
        match level {
            0..=3 => Self::Error,
            4 => Self::Warn,
            5..=6 => Self::Info,
            _ => Self::Debug,
        }
    }
}

static CONSOLE_LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);
static TRACE_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn init(params: &crate::cmdline::KernelParams) {
    let console_level = if let Ok(level) = params.loglevel.parse::<u8>() {
        Level::from_linux_console_level(level)
    } else if params.quiet {
        Level::Warn
    } else if params.debug {
        Level::Debug
    } else {
        Level::Info
    };

    CONSOLE_LEVEL.store(console_level as u8, Ordering::SeqCst);
    TRACE_ENABLED.store(
        params.debug
            || params
                .loglevel
                .parse::<u8>()
                .map(|l| l >= 7)
                .unwrap_or(false),
        Ordering::SeqCst,
    );
}

pub fn enabled(level: Level) -> bool {
    if level == Level::Trace {
        return TRACE_ENABLED.load(Ordering::SeqCst);
    }
    level as u8 <= CONSOLE_LEVEL.load(Ordering::SeqCst)
}

pub fn log(level: Level, args: fmt::Arguments<'_>) {
    if !enabled(level) {
        return;
    }
    crate::print!("[{}] ", level.as_str());
    crate::println!("{}", args);
}

#[macro_export]
macro_rules! kerror {
    ($($arg:tt)*) => {
        $crate::log::log($crate::log::Level::Error, format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! kwarn {
    ($($arg:tt)*) => {
        $crate::log::log($crate::log::Level::Warn, format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! kinfo {
    ($($arg:tt)*) => {
        $crate::log::log($crate::log::Level::Info, format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! kdebug {
    ($($arg:tt)*) => {
        $crate::log::log($crate::log::Level::Debug, format_args!($($arg)*));
    };
}

#[macro_export]
macro_rules! ktrace {
    ($($arg:tt)*) => {
        $crate::log::log($crate::log::Level::Trace, format_args!($($arg)*));
    };
}
