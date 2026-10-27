//! CTAPHID 分片 / 重组 / CID / INIT / PING / CANCEL / ERROR。
//!
//! 帧格式（与 `spike/uhid_fido.py` 一致）：
//! - 首包：`CID(4) | CMD(1) | BCNT(2) | DATA(57)`
//! - 续包：`CID(4) | SEQ(1) | DATA(59)`
//! - 每帧补齐到 64 字节；无 report ID 时 Chrome 额外写 0x00 前缀（由 uhid 层剥离）

use anyhow::{bail, Result};
use std::collections::HashMap;

pub const HID_REPORT_SIZE: usize = 64;
pub const INIT_PAYLOAD: usize = 57;
pub const CONT_PAYLOAD: usize = 59;
pub const MAX_MESSAGE_SIZE: usize = 7609;

pub const CID_BROADCAST: u32 = 0xFFFF_FFFF;
const CID_FIRST: u32 = 1;

pub const CTAPHID_PING: u8 = 0x81;
pub const CTAPHID_INIT: u8 = 0x86;
pub const CTAPHID_CBOR: u8 = 0x90;
pub const CTAPHID_CANCEL: u8 = 0x11;
pub const CTAPHID_ERROR: u8 = 0xBF;

const CMD_INIT_MASK: u8 = 0x80;
const CTAPHID_ERR_INVALID_CMD: u8 = 0x01;
const CTAPHID_ERR_INVALID_LEN: u8 = 0x03;

const PROTO_VERSION: u8 = 2;
const DEV_VERSION: [u8; 3] = [0, 0, 0];
/// bit2 = CBOR（CTAP2）支持。
const CAP_FLAGS: u8 = 0x04;

/// 把 64 字节报文交给 uhid（或测试收集器）的回调类型。
pub type FrameSender = Box<dyn FnMut(&[u8]) -> Result<()>>;

/// CTAP2 命令处理接口。`payload` 是 CTAPHID_CBOR 的完整载荷（首字节为命令）。
pub trait Ctap2Handler {
    fn handle_cbor(&mut self, payload: &[u8]) -> Vec<u8>;
}

struct Pending {
    cmd: u8,
    bcnt: usize,
    buf: Vec<u8>,
    next_seq: u8,
}

/// CTAPHID 协议状态机。
pub struct CtapHid<H: Ctap2Handler> {
    handler: H,
    send: FrameSender,
    pending: HashMap<u32, Pending>,
    next_cid: u32,
}

impl<H: Ctap2Handler> CtapHid<H> {
    /// 构造状态机；`send` 负责把 64 字节报文交给 uhid（或测试收集器）。
    pub fn new(handler: H, send: FrameSender) -> Self {
        Self {
            handler,
            send,
            pending: HashMap::new(),
            next_cid: CID_FIRST,
        }
    }

    /// 当前未完成分片数量（测试 / 诊断用）。
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// 最后一次分配的 CID（测试 / 诊断用）。
    pub fn last_cid(&self) -> u32 {
        self.next_cid.saturating_sub(1)
    }

    /// 处理一个 64 字节 HID 报文。
    pub fn handle_report(&mut self, report: &[u8]) -> Result<()> {
        if report.len() < HID_REPORT_SIZE {
            bail!("HID 报文长度不足 64 字节: {}", report.len());
        }
        let cid = u32::from_be_bytes([report[0], report[1], report[2], report[3]]);
        let header = report[4];
        if header & CMD_INIT_MASK != 0 {
            self.handle_init_packet(cid, header, report)
        } else {
            self.handle_cont_packet(cid, header, report)
        }
    }

    /// 清空所有未完成分片（CANCEL / 退出时调用）。
    pub fn reset(&mut self) {
        self.pending.clear();
    }

    /// 把载荷切分为 64 字节报文。
    pub fn fragment(cid: u32, cmd: u8, payload: &[u8]) -> Vec<Vec<u8>> {
        let cid_bytes = cid.to_be_bytes();
        let mut out = Vec::new();
        let mut first = Vec::with_capacity(HID_REPORT_SIZE);
        first.extend_from_slice(&cid_bytes);
        first.push(cmd);
        first.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        let first_end = payload.len().min(INIT_PAYLOAD);
        first.extend_from_slice(&payload[..first_end]);
        first.resize(HID_REPORT_SIZE, 0);
        out.push(first);

        let mut offset = first_end;
        let mut seq: u8 = 0;
        while offset < payload.len() {
            let end = (offset + CONT_PAYLOAD).min(payload.len());
            let mut frame = Vec::with_capacity(HID_REPORT_SIZE);
            frame.extend_from_slice(&cid_bytes);
            frame.push(seq);
            frame.extend_from_slice(&payload[offset..end]);
            frame.resize(HID_REPORT_SIZE, 0);
            out.push(frame);
            offset = end;
            seq = seq.wrapping_add(1);
        }
        out
    }

    fn handle_init_packet(&mut self, cid: u32, cmd: u8, report: &[u8]) -> Result<()> {
        let bcnt = usize::from(u16::from_be_bytes([report[5], report[6]]));
        if bcnt > MAX_MESSAGE_SIZE {
            return self.send(cid, CTAPHID_ERROR, &[CTAPHID_ERR_INVALID_LEN]);
        }
        let chunk = &report[7..7 + INIT_PAYLOAD];
        if bcnt <= INIT_PAYLOAD {
            return self.dispatch(cid, cmd, &chunk[..bcnt]);
        }
        self.pending.insert(
            cid,
            Pending {
                cmd,
                bcnt,
                buf: chunk.to_vec(),
                next_seq: 0,
            },
        );
        Ok(())
    }

    fn handle_cont_packet(&mut self, cid: u32, seq: u8, report: &[u8]) -> Result<()> {
        let Some(current) = self.pending.get(&cid) else {
            // 没有首包时忽略续包（spike 行为）。
            return Ok(());
        };
        if seq != current.next_seq {
            // 序号错乱：丢弃整条消息，不做部分拼接。
            self.pending.remove(&cid);
            return Ok(());
        }
        {
            let state = self.pending.get_mut(&cid).expect("pending 刚存在");
            state.buf.extend_from_slice(&report[5..5 + CONT_PAYLOAD]);
            state.next_seq = state.next_seq.wrapping_add(1);
        }
        let done = self
            .pending
            .get(&cid)
            .map(|s| s.buf.len() >= s.bcnt)
            .unwrap_or(false);
        if done {
            let state = self.pending.remove(&cid).expect("pending 刚存在");
            let payload = state.buf[..state.bcnt].to_vec();
            return self.dispatch(cid, state.cmd, &payload);
        }
        Ok(())
    }

    fn dispatch(&mut self, cid: u32, cmd: u8, payload: &[u8]) -> Result<()> {
        match cmd {
            CTAPHID_INIT => self.on_init(cid, payload),
            CTAPHID_PING => self.send(cid, CTAPHID_PING, payload),
            CTAPHID_CBOR => {
                let response = self.handler.handle_cbor(payload);
                self.send(cid, CTAPHID_CBOR, &response)
            }
            other if (other & 0x7F) == CTAPHID_CANCEL => {
                // CANCEL 没有响应；清空所有未完成分片。
                self.pending.clear();
                Ok(())
            }
            _ => self.send(cid, CTAPHID_ERROR, &[CTAPHID_ERR_INVALID_CMD]),
        }
    }

    fn on_init(&mut self, cid: u32, payload: &[u8]) -> Result<()> {
        let mut nonce = [0u8; 8];
        let n = payload.len().min(8);
        nonce[..n].copy_from_slice(&payload[..n]);
        let new_cid = if cid == CID_BROADCAST {
            self.allocate_cid()
        } else {
            cid
        };
        let mut body = Vec::with_capacity(17);
        body.extend_from_slice(&nonce);
        body.extend_from_slice(&new_cid.to_be_bytes());
        body.push(PROTO_VERSION);
        body.extend_from_slice(&DEV_VERSION);
        body.push(CAP_FLAGS);
        self.send(cid, CTAPHID_INIT, &body)
    }

    fn allocate_cid(&mut self) -> u32 {
        let cid = self.next_cid;
        self.next_cid = if cid >= 0x7FFF_FFFF {
            CID_FIRST
        } else {
            cid + 1
        };
        cid
    }

    fn send(&mut self, cid: u32, cmd: u8, payload: &[u8]) -> Result<()> {
        for frame in Self::fragment(cid, cmd, payload) {
            (self.send)(&frame)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct EchoHandler;

    impl Ctap2Handler for EchoHandler {
        fn handle_cbor(&mut self, payload: &[u8]) -> Vec<u8> {
            payload.to_vec()
        }
    }

    fn collector() -> (Rc<RefCell<Vec<Vec<u8>>>>, FrameSender) {
        let frames = Rc::new(RefCell::new(Vec::<Vec<u8>>::new()));
        let sink = frames.clone();
        let f: FrameSender = Box::new(move |frame: &[u8]| {
            sink.borrow_mut().push(frame.to_vec());
            Ok(())
        });
        (frames, f)
    }

    fn reassemble(frames: &[Vec<u8>]) -> (u32, u8, Vec<u8>) {
        assert!(!frames.is_empty());
        let cid = u32::from_be_bytes([frames[0][0], frames[0][1], frames[0][2], frames[0][3]]);
        let cmd = frames[0][4];
        let bcnt = usize::from(u16::from_be_bytes([frames[0][5], frames[0][6]]));
        let mut data = Vec::new();
        data.extend_from_slice(&frames[0][7..7 + INIT_PAYLOAD]);
        for frame in &frames[1..] {
            data.extend_from_slice(&frame[5..5 + CONT_PAYLOAD]);
        }
        data.truncate(bcnt);
        (cid, cmd, data)
    }

    fn init_report(cid: u32, nonce: [u8; 8]) -> Vec<u8> {
        let mut report = Vec::with_capacity(64);
        report.extend_from_slice(&cid.to_be_bytes());
        report.push(CTAPHID_INIT);
        report.extend_from_slice(&8u16.to_be_bytes());
        report.extend_from_slice(&nonce);
        report.resize(64, 0);
        report
    }

    #[test]
    fn fragment_reassemble_large_payload() {
        let payload: Vec<u8> = (0..MAX_MESSAGE_SIZE).map(|i| (i % 251) as u8).collect();
        let frames = CtapHid::<EchoHandler>::fragment(0x01020304, CTAPHID_CBOR, &payload);
        assert_eq!(
            frames.len(),
            1 + (MAX_MESSAGE_SIZE - INIT_PAYLOAD).div_ceil(CONT_PAYLOAD)
        );
        let (cid, cmd, data) = reassemble(&frames);
        assert_eq!(cid, 0x01020304);
        assert_eq!(cmd, CTAPHID_CBOR);
        assert_eq!(data, payload);
    }

    #[test]
    fn init_allocates_unique_cids() {
        let (frames, sink) = collector();
        let mut hid = CtapHid::new(EchoHandler, sink);
        hid.handle_report(&init_report(CID_BROADCAST, [1, 2, 3, 4, 5, 6, 7, 8]))
            .unwrap();
        hid.handle_report(&init_report(CID_BROADCAST, [8, 7, 6, 5, 4, 3, 2, 1]))
            .unwrap();
        let frames = frames.borrow();
        // 帧头占 7 字节，body = nonce(8) | new_cid(4) | proto(1) | dev(3) | caps(1)。
        let cid1 = u32::from_be_bytes([frames[0][15], frames[0][16], frames[0][17], frames[0][18]]);
        let cid2 = u32::from_be_bytes([frames[1][15], frames[1][16], frames[1][17], frames[1][18]]);
        assert_ne!(cid1, cid2);
        assert_ne!(cid1, CID_BROADCAST);
        assert_ne!(cid2, CID_BROADCAST);
        assert_eq!(&frames[0][7..15], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(frames[0][19], 2);
        assert_eq!(frames[0][23], 0x04);
    }

    #[test]
    fn out_of_order_continuation_is_rejected() {
        let payload = vec![0xAAu8; 200];
        let frames = CtapHid::<EchoHandler>::fragment(7, CTAPHID_CBOR, &payload);
        let (out, sink) = collector();
        let mut hid = CtapHid::new(EchoHandler, sink);
        hid.handle_report(&frames[0]).unwrap();
        assert_eq!(hid.pending_len(), 1);
        // 跳过 seq=0 直接发 seq=1。
        hid.handle_report(&frames[2]).unwrap();
        assert_eq!(hid.pending_len(), 0);
        // 后续正确的 seq=0 也应被忽略（整条消息已丢弃）。
        hid.handle_report(&frames[1]).unwrap();
        assert!(out.borrow().is_empty(), "错序消息不应产生任何响应");
    }

    #[test]
    fn cancel_clears_pending() {
        let payload = vec![0x55u8; 200];
        let frames = CtapHid::<EchoHandler>::fragment(9, CTAPHID_CBOR, &payload);
        let (out, sink) = collector();
        let mut hid = CtapHid::new(EchoHandler, sink);
        hid.handle_report(&frames[0]).unwrap();
        assert_eq!(hid.pending_len(), 1);

        let mut cancel = Vec::with_capacity(64);
        cancel.extend_from_slice(&9u32.to_be_bytes());
        cancel.push(CTAPHID_CANCEL | 0x80);
        cancel.extend_from_slice(&0u16.to_be_bytes());
        cancel.resize(64, 0);
        hid.handle_report(&cancel).unwrap();
        assert_eq!(hid.pending_len(), 0);
        hid.handle_report(&frames[1]).unwrap();
        assert!(out.borrow().is_empty(), "CANCEL 后不应再拼包或响应");
    }

    #[test]
    fn ping_echoes_payload() {
        let (out, sink) = collector();
        let mut hid = CtapHid::new(EchoHandler, sink);
        let frames = CtapHid::<EchoHandler>::fragment(3, CTAPHID_PING, b"hello");
        hid.handle_report(&frames[0]).unwrap();
        let frames = out.borrow();
        let (_, cmd, data) = reassemble(&frames);
        assert_eq!(cmd, CTAPHID_PING);
        assert_eq!(data, b"hello");
    }

    #[test]
    fn unsupported_command_returns_error() {
        let (out, sink) = collector();
        let mut hid = CtapHid::new(EchoHandler, sink);
        let frames = CtapHid::<EchoHandler>::fragment(4, 0x82, b"");
        hid.handle_report(&frames[0]).unwrap();
        let frames = out.borrow();
        let (_, cmd, data) = reassemble(&frames);
        assert_eq!(cmd, CTAPHID_ERROR);
        assert_eq!(data, vec![CTAPHID_ERR_INVALID_CMD]);
    }
}
