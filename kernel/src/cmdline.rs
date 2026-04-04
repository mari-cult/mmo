extern crate alloc;

use alloc::string::{String, ToString};
use limine_sys::*;
use crate::limine::{Request, EXECUTABLE_CMDLINE_REQUEST_ID};
use spin::Lazy;

#[derive(Debug, Clone, Default)]
pub struct KernelParams {
    pub raw: String,
    pub init: Option<String>,
    pub root: Option<String>,
    pub rootfstype: Option<String>,
    pub loglevel: String,
    pub debug: bool,
    pub quiet: bool,
}

#[used]
#[unsafe(link_section = ".limine_requests")]
static EXECUTABLE_CMDLINE_REQUEST: Request<limine_executable_cmdline_response> =
    Request::new(EXECUTABLE_CMDLINE_REQUEST_ID);

pub fn params() -> &'static KernelParams {
    static PARAMS: Lazy<KernelParams> = Lazy::new(parse_kernel_params);
    &*PARAMS
}

pub fn resolved_init_path() -> String {
    params().init.clone().unwrap_or_else(|| "/sbin/init".to_string())
}

pub enum RootDevice {
    VirtioBlk0,
}

pub fn resolved_root_device() -> Option<RootDevice> {
    match params().root.as_deref() {
        Some("/dev/vda") | Some("virtio0") => Some(RootDevice::VirtioBlk0),
        _ => None,
    }
}

pub enum RootFsType {
    Crabfs,
}

pub fn resolved_root_fstype() -> Option<RootFsType> {
    match params().rootfstype.as_deref() {
        Some("crabfs") => Some(RootFsType::Crabfs),
        _ => None,
    }
}

fn parse_kernel_params() -> KernelParams {
    let raw = EXECUTABLE_CMDLINE_REQUEST
        .response()
        .map(|response| unsafe {
            core::ffi::CStr::from_ptr(response.cmdline).to_str().unwrap_or("")
        })
        .unwrap_or("")
        .trim()
        .to_string();

    let mut params = KernelParams {
        raw: raw.clone(),
        loglevel: "info".to_string(),
        ..Default::default()
    };

    for token in raw.split_whitespace() {
        if let Some((key, value)) = token.split_once('=') {
            match key {
                "init" => params.init = Some(value.to_string()),
                "root" => params.root = Some(value.to_string()),
                "rootfstype" => params.rootfstype = Some(value.to_string()),
                "loglevel" => params.loglevel = value.to_string(),
                _ => {}
            }
            continue;
        }

        match token {
            "debug" => params.debug = true,
            "quiet" => params.quiet = true,
            _ => {}
        }
    }

    params
}
