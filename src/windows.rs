use crate::{Autoproxy, Error, Result, Sysproxy};
use std::{
    ffi::c_void,
    mem::{size_of, ManuallyDrop},
    net::SocketAddr,
    str::FromStr,
};
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        NetworkManagement::Rras::{RasEnumEntriesW, ERROR_BUFFER_TOO_SMALL, RASENTRYNAMEW},
        Networking::WinInet::{
            InternetSetOptionW, INTERNET_OPTION_PER_CONNECTION_OPTION,
            INTERNET_OPTION_PROXY_SETTINGS_CHANGED, INTERNET_OPTION_REFRESH,
            INTERNET_PER_CONN_AUTOCONFIG_URL, INTERNET_PER_CONN_FLAGS, INTERNET_PER_CONN_OPTIONW,
            INTERNET_PER_CONN_OPTIONW_0, INTERNET_PER_CONN_OPTION_LISTW,
            INTERNET_PER_CONN_PROXY_BYPASS, INTERNET_PER_CONN_PROXY_SERVER, PROXY_TYPE_AUTO_DETECT,
            PROXY_TYPE_AUTO_PROXY_URL, PROXY_TYPE_DIRECT, PROXY_TYPE_PROXY,
        },
        System::Memory::{GetProcessHeap, HeapAlloc, HeapFree, HEAP_NONE, HEAP_ZERO_MEMORY},
    },
};
use winreg::{enums, RegKey};

pub use windows::core::Error as Win32Error;

const SUB_KEY: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

fn encode_wide<S: AsRef<std::ffi::OsStr>>(string: S) -> Vec<u16> {
    std::os::windows::prelude::OsStrExt::encode_wide(string.as_ref())
        .chain(std::iter::once(0))
        .collect::<Vec<u16>>()
}

/// unset proxy
///
/// **对于包含中文字符的拨号连接或 VPN 连接，可能无法正确设置其代理，建议使用全英文重命名该连接名称**
fn unset_proxy() -> Result<()> {
    let mut p_opts = ManuallyDrop::new(Vec::<INTERNET_PER_CONN_OPTIONW>::with_capacity(1));
    p_opts.push(INTERNET_PER_CONN_OPTIONW {
        dwOption: INTERNET_PER_CONN_FLAGS,
        Value: {
            let mut v = INTERNET_PER_CONN_OPTIONW_0::default();
            v.dwValue = PROXY_TYPE_DIRECT;
            v
        },
    });
    let mut opts = INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        dwOptionCount: 1,
        dwOptionError: 0,
        pOptions: p_opts.as_mut_ptr(),
        pszConnection: PWSTR::null(),
    };

    // 局域网 LAN 代理设置
    apply(&opts)?;
    // 拨号连接/VPN 代理设置
    let ras_conns = get_ras_connections()?;
    for ras_conn in ras_conns.iter() {
        opts.pszConnection = PWSTR::from_raw(encode_wide(ras_conn).as_ptr() as *mut u16);
        apply(&opts)?;
        println!("unset RAS[{ras_conn}] proxy success");
    }

    unsafe {
        ManuallyDrop::drop(&mut p_opts);
    }

    Ok(())
}

/// set auto proxy
///
/// **对于包含中文字符的拨号连接或 VPN 连接，可能无法正确设置其代理，建议使用全英文重命名该连接名称**
#[inline]
fn set_auto_proxy(server: String) -> Result<()> {
    let mut p_opts = ManuallyDrop::new(Vec::<INTERNET_PER_CONN_OPTIONW>::with_capacity(2));
    p_opts.push(INTERNET_PER_CONN_OPTIONW {
        dwOption: INTERNET_PER_CONN_FLAGS,
        Value: INTERNET_PER_CONN_OPTIONW_0 {
            dwValue: PROXY_TYPE_AUTO_DETECT | PROXY_TYPE_AUTO_PROXY_URL | PROXY_TYPE_DIRECT,
        },
    });

    let mut s = ManuallyDrop::new(encode_wide(&server));
    p_opts.push(INTERNET_PER_CONN_OPTIONW {
        dwOption: INTERNET_PER_CONN_AUTOCONFIG_URL,
        Value: INTERNET_PER_CONN_OPTIONW_0 {
            pszValue: PWSTR::from_raw(s.as_ptr() as *mut u16),
        },
    });

    let mut opts = INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        dwOptionCount: 2,
        dwOptionError: 0,
        pOptions: p_opts.as_mut_ptr(),
        pszConnection: PWSTR::null(),
    };

    // 局域网 LAN 代理设置
    apply(&opts)?;
    // 拨号连接/VPN 代理设置
    let ras_conns = get_ras_connections()?;
    for ras_conn in ras_conns.iter() {
        opts.pszConnection = PWSTR::from_raw(encode_wide(ras_conn).as_ptr() as *mut u16);
        apply(&opts)?;
        println!("set RAS[{ras_conn}] auto proxy success");
    }

    unsafe {
        ManuallyDrop::drop(&mut s);
        ManuallyDrop::drop(&mut p_opts);
    }

    Ok(())
}

/// set global proxy
///
/// **对于包含中文字符的拨号连接或 VPN 连接，可能无法正确设置其代理，建议使用全英文重命名该连接名称**
fn set_global_proxy(server: String, bypass: String) -> Result<()> {
    let mut p_opts = ManuallyDrop::new(Vec::<INTERNET_PER_CONN_OPTIONW>::with_capacity(3));
    p_opts.push(INTERNET_PER_CONN_OPTIONW {
        dwOption: INTERNET_PER_CONN_FLAGS,
        Value: INTERNET_PER_CONN_OPTIONW_0 {
            dwValue: PROXY_TYPE_PROXY | PROXY_TYPE_DIRECT,
        },
    });

    let mut s = ManuallyDrop::new(encode_wide(&server));
    p_opts.push(INTERNET_PER_CONN_OPTIONW {
        dwOption: INTERNET_PER_CONN_PROXY_SERVER,
        Value: INTERNET_PER_CONN_OPTIONW_0 {
            pszValue: PWSTR::from_raw(s.as_ptr() as *mut u16),
        },
    });

    let mut b = ManuallyDrop::new(encode_wide(&bypass));
    p_opts.push(INTERNET_PER_CONN_OPTIONW {
        dwOption: INTERNET_PER_CONN_PROXY_BYPASS,
        Value: INTERNET_PER_CONN_OPTIONW_0 {
            pszValue: PWSTR::from_raw(b.as_ptr() as *mut u16),
        },
    });

    let mut opts = INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        dwOptionCount: 3,
        dwOptionError: 0,
        pOptions: p_opts.as_mut_ptr(),
        pszConnection: PWSTR::null(),
    };
    // 局域网 LAN 代理设置
    apply(&opts)?;
    // 拨号连接/VPN 代理设置
    let ras_conns = get_ras_connections()?;
    for ras_conn in ras_conns.iter() {
        opts.pszConnection = PWSTR::from_raw(encode_wide(ras_conn).as_ptr() as *mut u16);
        apply(&opts)?;
        println!("set RAS[{ras_conn}] global proxy success");
    }

    unsafe {
        ManuallyDrop::drop(&mut s);
        ManuallyDrop::drop(&mut b);
        ManuallyDrop::drop(&mut p_opts);
    }

    Ok(())
}

fn apply(options: &INTERNET_PER_CONN_OPTION_LISTW) -> Result<()> {
    unsafe {
        // setting options
        let opts = options as *const INTERNET_PER_CONN_OPTION_LISTW as *const c_void;
        InternetSetOptionW(
            None,
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            Some(opts),
            size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        )?;
        // propagating changes
        InternetSetOptionW(None, INTERNET_OPTION_PROXY_SETTINGS_CHANGED, None, 0)?;
        // refreshing
        InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0)?;
    }
    Ok(())
}

impl Sysproxy {
    pub fn get_system_proxy() -> Result<Sysproxy> {
        let hkcu = RegKey::predef(enums::HKEY_CURRENT_USER);
        let cur_var = hkcu.open_subkey_with_flags(SUB_KEY, enums::KEY_READ)?;
        let enable = cur_var.get_value::<u32, _>("ProxyEnable").unwrap_or(0u32) == 1u32;
        let server = cur_var
            .get_value::<String, _>("ProxyServer")
            .unwrap_or_default();

        let (host, port) = if server.is_empty() {
            ("".into(), 0)
        } else {
            let socket = SocketAddr::from_str(&server).or(Err(Error::ParseStr(server)))?;
            let host = socket.ip().to_string();
            let port = socket.port();
            (host, port)
        };

        let bypass = cur_var.get_value("ProxyOverride").unwrap_or_default();

        Ok(Sysproxy {
            enable,
            host,
            port,
            bypass,
        })
    }

    pub fn set_system_proxy(&self) -> Result<()> {
        match self.enable {
            true => set_global_proxy(format!("{}:{}", self.host, self.port), self.bypass.clone()),
            false => unset_proxy(),
        }
    }
}

impl Autoproxy {
    pub fn get_auto_proxy() -> Result<Autoproxy> {
        let hkcu = RegKey::predef(enums::HKEY_CURRENT_USER);
        let cur_var = hkcu.open_subkey_with_flags(SUB_KEY, enums::KEY_READ)?;
        let url = cur_var.get_value::<String, _>("AutoConfigURL");
        let enable = url.is_ok();
        let url = url.unwrap_or_else(|_| "".into());

        Ok(Autoproxy { enable, url })
    }

    pub fn set_auto_proxy(&self) -> Result<()> {
        match self.enable {
            true => set_auto_proxy(self.url.clone()),
            false => unset_proxy(),
        }
    }
}

/// refer: https://learn.microsoft.com/zh-cn/windows/win32/api/ras/nf-ras-rasenumentriesw
///
/// 获取所有远程访问服务 （包含拨号连接和 VPN 连接）
fn get_ras_connections() -> Result<Vec<String>> {
    println!("start get RAS connections...");
    let mut connections = Vec::new();

    unsafe {
        let mut buffer_size = 0u32;
        let mut entry_count = 0u32;

        // 第一次调用获取所需缓冲区大小
        let result_code = RasEnumEntriesW(
            PCWSTR::null(),
            PCWSTR::null(),
            None,
            &mut buffer_size,
            &mut entry_count,
        );

        println!("get allocate buffer size result code: {result_code}");
        if result_code == ERROR_BUFFER_TOO_SMALL {
            // Allocate the memory needed for the array of RAS entry names.
            let buffer_ptr = HeapAlloc(GetProcessHeap()?, HEAP_ZERO_MEMORY, buffer_size as usize);
            if buffer_ptr.is_null() {
                log::error!("HeapAlloc failed!");
                return Ok(connections);
            }
            let lp_ras_entry_name = buffer_ptr as *mut RASENTRYNAMEW;
            // The first RASENTRYNAME structure in the array must contain the structure size
            (*lp_ras_entry_name).dwSize = std::mem::size_of::<RASENTRYNAMEW>() as u32;

            // 获取所有 RAS 列表
            let result_code = RasEnumEntriesW(
                PCWSTR::null(),
                PCWSTR::null(),
                Some(lp_ras_entry_name),
                &mut buffer_size,
                &mut entry_count,
            );
            // 如果函数成功，则返回值 ERROR_SUCCESS, 但是该 API 返回 u32, 参照对比 ERROR_SUCCESS 后，该值应该为 0
            println!("get RAS entries result code: {result_code}");
            if result_code == 0 && entry_count > 0 {
                for i in 0..entry_count as isize {
                    let entry = &*lp_ras_entry_name.offset(i);
                    let name_arr = entry.szEntryName;
                    // 去除宽字符多余的 0，以便更好的打印 RAS 名称
                    let len = name_arr.iter().position(|&x| x == 0).unwrap_or(0);
                    let name = String::from_utf16_lossy(&name_arr[..len]);
                    connections.push(name);
                }
                println!(
                    "找到 {} 个拨号连接/VPN, {:?}",
                    connections.len(),
                    connections
                );
            }
            // Deallocate memory for the connection buffer
            HeapFree(GetProcessHeap()?, HEAP_NONE, Some(buffer_ptr))?;
            return Ok(connections);
        }

        if entry_count >= 1 {
            println!("The operation failed to acquire the buffer size");
        } else {
            println!("There were no RAS entry names found");
        }
    }

    Ok(connections)
}
