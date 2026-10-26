#!/usr/bin/env python3
"""在真实 uhid 设备上跑一次 makeCredential + getAssertion，并验签。

复用 uhid_fido.py 里的 CBOR 编解码，避免重复实现。
"""
import hashlib
import os
import select
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from uhid_fido import cbor_decode as _cbor_decode, cbor_encode
def cbor_decode(data):
    return _cbor_decode(data)[0]  # noqa: E402

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import (  # noqa: E402
    decode_dss_signature,
)

DEV = sys.argv[1] if len(sys.argv) > 1 else "/dev/hidraw6"
RP_ID = "webauthn.io"


def send_report(fd: int, cid: bytes, cmd: int, payload: bytes) -> None:
    head = cid + bytes([cmd]) + len(payload).to_bytes(2, "big") + payload[:57]
    os.write(fd, head.ljust(64, b"\x00"))
    rest, seq = payload[57:], 0
    while rest:
        os.write(fd, (cid + bytes([seq]) + rest[:59]).ljust(64, b"\x00"))
        rest, seq = rest[59:], seq + 1


def read_response(fd: int, timeout: float = 5.0):
    """读一条完整 CTAPHID 应答，返回 (cid, cmd, payload)。"""
    deadline = time.time() + timeout
    cid = cmd = None
    need = None
    payload = b""
    while time.time() < deadline:
        if not select.select([fd], [], [], 1.0)[0]:
            continue
        pkt = os.read(fd, 64)
        if len(pkt) < 7:
            continue
        if cid is None:
            cid, cmd = pkt[0:4], pkt[4]
            need = int.from_bytes(pkt[5:7], "big")
            payload = pkt[7:64]
        else:
            payload += pkt[5:64]
        if need is not None and len(payload) >= need:
            return cid, cmd, payload[:need]
    raise TimeoutError("no complete CTAPHID response")


def parse_auth_data(auth_data: bytes):
    """拆出 rpIdHash/flags/signCount/credId/COSE 公钥。"""
    rp_hash = auth_data[0:32]
    flags = auth_data[32]
    sign_count = int.from_bytes(auth_data[33:37], "big")
    aaguid = auth_data[37:53]
    cred_len = int.from_bytes(auth_data[53:55], "big")
    cred_id = auth_data[55:55 + cred_len]
    cose = auth_data[55 + cred_len:]
    m = cbor_decode(cose)
    x = m[-2].to_bytes(32, "big") if isinstance(m[-2], int) else m[-2]
    y = m[-3].to_bytes(32, "big") if isinstance(m[-3], int) else m[-3]
    pub = ec.EllipticCurvePublicNumbers(
        int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
    ).public_key()
    return rp_hash, flags, sign_count, aaguid, cred_id, pub


def verify(pub, signature: bytes, message: bytes) -> bool:
    r, s = decode_dss_signature(signature)
    try:
        pub.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:  # noqa: BLE001 - 验签失败就是 False
        return False


def main() -> None:
    fd = os.open(DEV, os.O_RDWR)
    try:
        send_report(fd, b"\xff\xff\xff\xff", 0x86, os.urandom(8))
        cid, _, _ = read_response(fd)
        print("INIT ok, cid=%s" % cid.hex())

        client_data_hash = hashlib.sha256(b"fake-client-data").digest()
        request = {
            1: client_data_hash,
            2: {"id": RP_ID, "name": RP_ID},
            3: {"id": b"user-1", "name": "a@b.c", "displayName": "A"},
            4: [{"alg": -7, "type": "public-key"}],
            7: {"rk": True, "uv": False},
        }
        send_report(fd, cid, 0x90, bytes([0x01]) + cbor_encode(request))
        _, cmd, resp = read_response(fd)
        print("makeCredential status=0x%02x len=%d" % (resp[0], len(resp)))
        if resp[0] != 0:
            print("FAILED: status != 0")
            return
        att = cbor_decode(resp[1:])
        auth_data = att[2]
        rp_hash, flags, sc, aaguid, cred_id, pub = parse_auth_data(auth_data)
        ok = verify(pub, att[3], auth_data + client_data_hash) if att[3] else None
        print("  fmt=%s flags=0x%02x rpIdHash_ok=%s credId=%s"
              % (att[1], flags, rp_hash == hashlib.sha256(RP_ID.encode()).digest(), cred_id.hex()))
        print("  self-signature_ok=%s" % ok)

        assertion_req = {
            1: RP_ID,
            2: hashlib.sha256(b"assert-client-data").digest(),
            3: [{"id": cred_id, "type": "public-key"}],
            5: {"up": True, "uv": False},
        }
        send_report(fd, cid, 0x90, bytes([0x02]) + cbor_encode(assertion_req))
        _, _, aresp = read_response(fd)
        print("getAssertion status=0x%02x len=%d" % (aresp[0], len(aresp)))
        if aresp[0] != 0:
            print("FAILED: status != 0")
            return
        asrt = cbor_decode(aresp[1:])
        a_auth = asrt[2]
        a_rp_hash = a_auth[0:32]
        a_flags = a_auth[32]
        a_sc = int.from_bytes(a_auth[33:37], "big")
        sig_ok = verify(pub, asrt[3], a_auth + hashlib.sha256(b"assert-client-data").digest())
        print("  flags=0x%02x signCount=%d->%d rpIdHash_ok=%s signature_ok=%s"
              % (a_flags, sc, a_sc,
                 a_rp_hash == hashlib.sha256(RP_ID.encode()).digest(), sig_ok))
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
