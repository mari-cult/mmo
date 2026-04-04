#[cfg(target_arch = "x86_64")]
mod x86_64_impl;
#[cfg(target_arch = "x86_64")]
pub use self::x86_64_impl::*;

#[cfg(target_arch = "aarch64")]
mod aarch64_impl;
#[cfg(target_arch = "aarch64")]
pub use self::aarch64_impl::*;
