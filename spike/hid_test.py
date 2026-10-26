#!/usr/bin/env python3
"""不依赖第三方库，直接用 hidraw 验证虚拟 FIDO2 设备是否按 CTAPHID 协议应答。"""
import os
import select
import sys
import time

DEV = sys.argv[1] if len(sys.argv) > 1 else "/dev/hidraw5"
INIT_CMD = 0x86
CBOR_CMD = 0x90


def send_report(fd: int, cid: bytes, cmd: int, payload: bytes) -> None:
    """按 CTAPHID 分帧规则发送：首包 4+1+2+57，续包 4+1+59。"""
    head = cid + bytes([cmd]) + len(payload).to_bytes(2, "big") + payload[:57]
    os.write(fd, head.ljust(64, b"\x00"))
    rest = payload[57:]
    seq = 0
    while rest:
        chunk = cid + bytes([seq]) + rest[:59]
        os.write(fd, chunk.ljust(64, b"\x00"))
        rest = rest[59:]
        seq += 1


def read_response(fd: int, timeout: float = 3.0) -> tuple:
    """读满一条 CTAPHID 应答（处理续包），返回 (cid, cmd, payload)。"""
    deadline = time.time() + timeout
    cid = cmd = None
    payload = b""
    need = None
    while time.time() < deadline:
        if not select.select([fd], [], [], 1.0)[0]:
            continue
        pkt = os.read(fd, 64)
        if len(pkt) < 7:
            continue
        if cid is None:
            cid = pkt[0:4]
            cmd = pkt[4]
            need = int.from_bytes(pkt[5:7], "big")
            payload = pkt[7:64]
        else:
            payload += pkt[5:64]
        if need is not None and len(payload) >= need:
            return cid, cmd, payload[:need]
    raise TimeoutError("no complete CTAPHID response")


def main() -> None:
    fd = os.open(DEV, os.O_RDWR)
    try:
        nonce = os.urandom(8)
        send_report(fd, b"\xff\xff\xff\xff", INIT_CMD, nonce)
        cid, cmd, payload = read_response(fd)
        print("INIT   cmd=0x%02x payload=%s" % (cmd, payload.hex()))
        ok_nonce = payload[0:8] == nonce
        new_cid = payload[8:12]
        proto = payload[12]
        print("       nonce_echo=%s new_cid=%s proto=%d" % (ok_nonce, new_cid.hex(), proto))

        send_report(fd, cid, CBOR_CMD, b"\x04")
        cid2, cmd2, payload2 = read_response(fd)
        print("GETINFO cmd=0x%02x payload=%s" % (cmd2, payload2.hex()))
        print("       status=0x%02x cbor=%s" % (payload2[0], payload2[1:].hex()))
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
