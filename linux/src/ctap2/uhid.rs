//! `/dev/uhid` 虚拟 FIDO2 HID 设备（Linux only）。
//!
//! 事件布局与 `spike/uhid_fido.py` 一致：每个事件固定 4380 字节，
//! `UHID_CREATE2` / `UHID_INPUT2` / `UHID_DESTROY` 请求都通过同一读写下发。

use crate::ctap2::authenticator::{Authenticator, CredentialBackend};
use crate::ctap2::hid::{Ctap2Handler, CtapHid, HID_REPORT_SIZE};
use anyhow::{anyhow, bail, Context, Result};
use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub const UHID_DEV_PATH: &str = "/dev/uhid";
pub const UHID_EVENT_SIZE: usize = 4380;
pub const UHID_DATA_MAX: usize = 4096;

const UHID_DESTROY: u32 = 1;
const UHID_START: u32 = 2;
const UHID_STOP: u32 = 3;
const UHID_OPEN: u32 = 4;
const UHID_CLOSE: u32 = 5;
const UHID_OUTPUT: u32 = 6;
const UHID_FEATURE: u32 = 9;
const UHID_CREATE2: u32 = 11;
const UHID_INPUT2: u32 = 12;
const UHID_GET_REPORT: u32 = 13;
const UHID_GET_REPORT_REPLY: u32 = 14;
const UHID_SET_REPORT: u32 = 15;

/// `struct uhid_output_req.rtype` 是 HID 报表类型：0=input，1=output，2=feature。
const UHID_RTYPE_INPUT: u8 = 0;
const UHID_RTYPE_OUTPUT: u8 = 1;

const UHID_BUS_USB: u16 = 0x03;
const DEVICE_NAME: &str = "Virtual FIDO2 Key";
const DEVICE_PHYS: &str = "";
const DEVICE_UNIQ: &str = "";
const DEVICE_VID: u32 = 0x1209;
const DEVICE_PID: u32 = 0x0001;
const DEVICE_VERSION: u32 = 0x0100;
const DEVICE_COUNTRY: u32 = 0x0000;

/// FIDO 标准 64 字节 in/out report descriptor。
const REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
    0x09, 0x01, // Usage (U2F HID Authenticator Device)
    0xA1, 0x01, // Collection (Application)
    0x09, 0x20, //   Usage (Input Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x81, 0x02, //   Input (Data,Var,Abs)
    0x09, 0x21, //   Usage (Output Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x91, 0x02, //   Output (Data,Var,Abs)
    0xC0, // End Collection
];

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP_REQUESTED.store(true, Ordering::SeqCst);
}

/// 打开 `/dev/uhid`。
pub struct UhidDevice {
    fd: RawFd,
}

impl UhidDevice {
    pub fn open() -> Result<Self> {
        let path = CString::new(UHID_DEV_PATH).expect("静态路径");
        // SAFETY: open 是标准 libc 调用；fd 由 Drop 关闭。
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("打开 {UHID_DEV_PATH} 失败"));
        }
        Ok(Self { fd })
    }

    /// 写一个完整 4380 字节事件（循环直到写完）。
    pub fn write_event(&self, event: &[u8]) -> Result<()> {
        if event.len() != UHID_EVENT_SIZE {
            bail!("uhid 事件必须 {UHID_EVENT_SIZE} 字节，实际 {}", event.len());
        }
        let mut written = 0;
        while written < event.len() {
            // SAFETY: event 指针与剩余长度有效。
            let n = unsafe {
                libc::write(
                    self.fd,
                    event[written..].as_ptr() as *const libc::c_void,
                    event.len() - written,
                )
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err).context("写 uhid 事件失败");
            }
            if n == 0 {
                bail!("写 uhid 事件返回 0");
            }
            written += n as usize;
        }
        Ok(())
    }

    /// 读一个完整 4380 字节事件。返回 `Ok(false)` 表示 EOF 或收到退出信号。
    pub fn read_event(&self, buf: &mut [u8; UHID_EVENT_SIZE]) -> Result<bool> {
        let mut read = 0;
        while read < UHID_EVENT_SIZE {
            if STOP_REQUESTED.load(Ordering::SeqCst) {
                return Ok(false);
            }
            // SAFETY: buf 指针与剩余长度有效。
            let n = unsafe {
                libc::read(
                    self.fd,
                    buf[read..].as_mut_ptr() as *mut libc::c_void,
                    UHID_EVENT_SIZE - read,
                )
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    if STOP_REQUESTED.load(Ordering::SeqCst) {
                        return Ok(false);
                    }
                    continue;
                }
                return Err(err).context("读 uhid 事件失败");
            }
            if n == 0 {
                return Ok(false);
            }
            read += n as usize;
        }
        Ok(true)
    }
}

impl Drop for UhidDevice {
    fn drop(&mut self) {
        let _ = self.write_event(&build_destroy());
        // SAFETY: fd 只在这里关闭一次。
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// 构造完整 uhid_event（type + body + 补零）。
pub fn build_event(event_type: u32, body: &[u8]) -> Vec<u8> {
    assert!(
        body.len() <= UHID_EVENT_SIZE - 4,
        "uhid 事件 body 过大: {}",
        body.len()
    );
    let mut out = vec![0u8; UHID_EVENT_SIZE];
    out[..4].copy_from_slice(&event_type.to_le_bytes());
    out[4..4 + body.len()].copy_from_slice(body);
    out
}

/// 构造 UHID_CREATE2。
pub fn build_create2(report_descriptor: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(128 + 64 + 64 + 16 + UHID_DATA_MAX);
    push_fixed(&mut body, DEVICE_NAME.as_bytes(), 128);
    push_fixed(&mut body, DEVICE_PHYS.as_bytes(), 64);
    push_fixed(&mut body, DEVICE_UNIQ.as_bytes(), 64);
    body.extend_from_slice(&(report_descriptor.len() as u16).to_le_bytes());
    body.extend_from_slice(&UHID_BUS_USB.to_le_bytes());
    body.extend_from_slice(&DEVICE_VID.to_le_bytes());
    body.extend_from_slice(&DEVICE_PID.to_le_bytes());
    body.extend_from_slice(&DEVICE_VERSION.to_le_bytes());
    body.extend_from_slice(&DEVICE_COUNTRY.to_le_bytes());
    let mut desc = vec![0u8; UHID_DATA_MAX];
    desc[..report_descriptor.len()].copy_from_slice(report_descriptor);
    body.extend_from_slice(&desc);
    build_event(UHID_CREATE2, &body)
}

/// 构造 UHID_INPUT2（一个 64 字节报表）。
pub fn build_input2(report: &[u8]) -> Result<Vec<u8>> {
    if report.len() > UHID_DATA_MAX {
        bail!("input report 过大: {}", report.len());
    }
    let mut body = Vec::with_capacity(2 + report.len());
    body.extend_from_slice(&(report.len() as u16).to_le_bytes());
    body.extend_from_slice(report);
    Ok(build_event(UHID_INPUT2, &body))
}

/// 构造 UHID_GET_REPORT_REPLY（空数据，避免内核一直等待）。
pub fn build_get_report_reply(report_id: u32, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + data.len());
    body.extend_from_slice(&report_id.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes()); // err
    body.extend_from_slice(&(data.len() as u16).to_le_bytes());
    body.extend_from_slice(data);
    build_event(UHID_GET_REPORT_REPLY, &body)
}

/// 构造 UHID_DESTROY。
pub fn build_destroy() -> Vec<u8> {
    build_event(UHID_DESTROY, &[])
}

/// 解析 UHID_OUTPUT：返回 (data, size, rtype)。
pub fn parse_output(event: &[u8]) -> (Vec<u8>, usize, u8) {
    let base = 4 + UHID_DATA_MAX;
    let size = u16::from_le_bytes([event[base], event[base + 1]]) as usize;
    let rtype = event[base + 2];
    let size = size.min(UHID_DATA_MAX);
    (event[4..4 + size].to_vec(), size, rtype)
}

/// 解析 UHID_GET_REPORT：返回 (id, rnum, rtype)。
pub fn parse_get_report(event: &[u8]) -> (u32, u8, u8) {
    let id = u32::from_le_bytes([event[4], event[5], event[6], event[7]]);
    (id, event[8], event[9])
}

/// 读取事件类型。
pub fn event_type(event: &[u8]) -> u32 {
    u32::from_le_bytes([event[0], event[1], event[2], event[3]])
}

/// 运行 uhid daemon（前台，直到 Ctrl-C / SIGTERM）。
pub fn run_daemon<B: CredentialBackend>(authenticator: Authenticator<B>) -> Result<()> {
    // 安装退出信号：read 被 EINTR 打断后检查 STOP_REQUESTED。
    unsafe {
        libc::signal(libc::SIGINT, on_signal as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as libc::sighandler_t);
    }

    let device = Arc::new(UhidDevice::open()?);
    device.write_event(&build_create2(REPORT_DESCRIPTOR))?;
    eprintln!(
        "vkey-hid: uhid 设备已创建 name={DEVICE_NAME} vid=0x{DEVICE_VID:04X} pid=0x{DEVICE_PID:04X}"
    );

    let sender = {
        let device = device.clone();
        Box::new(move |frame: &[u8]| -> Result<()> { device.write_event(&build_input2(frame)?) })
    };
    let mut ctaphid = CtapHid::new(authenticator, sender);

    let mut buf = [0u8; UHID_EVENT_SIZE];
    loop {
        if !device.read_event(&mut buf)? {
            break;
        }
        match event_type(&buf) {
            UHID_START => eprintln!("vkey-hid: UHID_START"),
            UHID_OPEN => eprintln!("vkey-hid: UHID_OPEN"),
            UHID_STOP => eprintln!("vkey-hid: UHID_STOP"),
            UHID_CLOSE => eprintln!("vkey-hid: UHID_CLOSE"),
            UHID_OUTPUT => {
                let (data, size, rtype) = parse_output(&buf);
                if rtype != UHID_RTYPE_OUTPUT && rtype != UHID_RTYPE_INPUT {
                    // feature report 不处理。
                    continue;
                }
                process_output(&mut ctaphid, &data, size)?;
            }
            UHID_GET_REPORT => {
                let (id, rnum, rtype) = parse_get_report(&buf);
                eprintln!("vkey-hid: UHID_GET_REPORT id={id} rnum={rnum} rtype={rtype}");
                device.write_event(&build_get_report_reply(id, &[]))?;
            }
            UHID_SET_REPORT | UHID_FEATURE => {
                // 内核不为 SET_REPORT/FEATURE 等待回复；回 REPLY 反而可能 -EBUSY。
            }
            other => eprintln!("vkey-hid: 未处理 uhid 事件 {other}"),
        }
    }

    ctaphid.reset();
    eprintln!("vkey-hid: 退出，销毁 uhid 设备");
    Ok(())
}

fn process_output<H: Ctap2Handler>(
    ctaphid: &mut CtapHid<H>,
    data: &[u8],
    size: usize,
) -> Result<()> {
    // hidapi 约定：无 report ID 时首字节是 0x00，必须剥掉。
    let data = if size == HID_REPORT_SIZE + 1 && data[0] == 0 {
        &data[1..]
    } else {
        data
    };
    if data.len() % HID_REPORT_SIZE != 0 {
        // 短包直接忽略（与 spike 一致）。
        return Ok(());
    }
    for chunk in data.chunks_exact(HID_REPORT_SIZE) {
        ctaphid.handle_report(chunk)?;
    }
    Ok(())
}

fn push_fixed(out: &mut Vec<u8>, value: &[u8], len: usize) {
    let mut buf = vec![0u8; len];
    let n = value.len().min(len);
    buf[..n].copy_from_slice(&value[..n]);
    out.extend_from_slice(&buf);
}

/// 非 Linux 平台占位（保持模块 API 存在，便于 main 给出明确错误）。
pub fn unsupported_error() -> anyhow::Error {
    anyhow!("uhid 仅支持 Linux；Windows 请使用 selftest/status/sync")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_layout_matches_spike() {
        let ev = build_create2(REPORT_DESCRIPTOR);
        assert_eq!(ev.len(), UHID_EVENT_SIZE);
        assert_eq!(event_type(&ev), UHID_CREATE2);
        // name 从偏移 4 开始，128 字节。
        assert_eq!(&ev[4..4 + DEVICE_NAME.len()], DEVICE_NAME.as_bytes());
        // report descriptor 长度字段在 4+128+64+64。
        let base = 4 + 128 + 64 + 64;
        assert_eq!(
            u16::from_le_bytes([ev[base], ev[base + 1]]) as usize,
            REPORT_DESCRIPTOR.len()
        );
        assert_eq!(
            &ev[base + 16..base + 16 + REPORT_DESCRIPTOR.len()],
            REPORT_DESCRIPTOR
        );
    }

    #[test]
    fn input2_and_output_roundtrip() {
        let frame = [0x42u8; 64];
        let ev = build_input2(&frame).unwrap();
        assert_eq!(event_type(&ev), UHID_INPUT2);
        // 模拟 UHID_OUTPUT：size=65，data=0x00 + 64。
        let mut output = vec![0u8; UHID_EVENT_SIZE];
        output[..4].copy_from_slice(&UHID_OUTPUT.to_le_bytes());
        output[4] = 0x00;
        output[5..69].copy_from_slice(&frame);
        let base = 4 + UHID_DATA_MAX;
        output[base..base + 2].copy_from_slice(&65u16.to_le_bytes());
        output[base + 2] = UHID_RTYPE_OUTPUT;
        let (data, size, rtype) = parse_output(&output);
        assert_eq!(size, 65);
        assert_eq!(rtype, UHID_RTYPE_OUTPUT);
        assert_eq!(data[0], 0x00);
        assert_eq!(&data[1..], &frame);
    }

    #[test]
    fn get_report_reply_layout() {
        let ev = build_get_report_reply(7, b"abc");
        assert_eq!(event_type(&ev), UHID_GET_REPORT_REPLY);
        assert_eq!(u32::from_le_bytes([ev[4], ev[5], ev[6], ev[7]]), 7);
        assert_eq!(u16::from_le_bytes([ev[8], ev[9]]), 0);
        assert_eq!(u16::from_le_bytes([ev[10], ev[11]]), 3);
        assert_eq!(&ev[12..15], b"abc");
    }
}
