use std::ffi::CStr;
use std::net::Ipv4Addr;

use anyhow::{bail, Context, Result};

pub fn ensure_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("TC eBPF backend must run as root");
    }
    Ok(())
}

pub fn interface_ipv4(name: &str) -> Result<Ipv4Addr> {
    let mut addrs = std::ptr::null_mut();
    let rc = unsafe { libc::getifaddrs(&mut addrs) };
    if rc != 0 {
        bail!("getifaddrs failed");
    }

    let mut cursor = addrs;
    while !cursor.is_null() {
        let ifa = unsafe { &*cursor };
        if !ifa.ifa_addr.is_null() {
            let if_name = unsafe { CStr::from_ptr(ifa.ifa_name) }
                .to_str()
                .context("interface name is not valid UTF-8")?;
            if if_name == name {
                let family = unsafe { (*ifa.ifa_addr).sa_family as i32 };
                if family == libc::AF_INET {
                    let sockaddr = unsafe { *(ifa.ifa_addr as *const libc::sockaddr_in) };
                    unsafe { libc::freeifaddrs(addrs) };
                    return Ok(Ipv4Addr::from(u32::from_be(sockaddr.sin_addr.s_addr)));
                }
            }
        }
        cursor = unsafe { (*cursor).ifa_next };
    }

    unsafe { libc::freeifaddrs(addrs) };
    bail!("interface `{name}` has no IPv4 address")
}

pub fn interface_exists(name: &str) -> bool {
    let c_name = match std::ffi::CString::new(name) {
        Ok(value) => value,
        Err(_) => return false,
    };
    unsafe { libc::if_nametoindex(c_name.as_ptr()) != 0 }
}
