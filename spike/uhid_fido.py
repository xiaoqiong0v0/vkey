#!/usr/bin/env python3
"""可行性 spike：通过 /dev/uhid 创建虚拟 FIDO2 HID 设备，并实现最小 CTAPHID 应答。

依赖：标准库 + cryptography（只用于 ES256 签名；缺失时启动即退出，退出码 2）。
仅支持 Linux。不是完整的 FIDO2 authenticator：
  - CTAPHID：INIT / PING / CBOR / CANCEL，其余回 CTAPHID_ERROR(0xBF)
  - CTAP2：GetInfo / MakeCredential(fmt="none") / GetAssertion，其余回 invalid command
  - UV：不做任何校验（spike），收到请求直接视为已确认
  - 凭证只存内存，进程退出即丢失

用法：
    python3 uhid_fido.py
Ctrl-C 退出（发送 UHID_DESTROY）。
"""

from __future__ import annotations

import hashlib
import os
import secrets
import struct
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

# 第三方：只用于 ES256。导入失败时记下原因，由 main() 打印指引并以退出码 2 结束。
_CRYPTO_ERROR: Optional[str] = None
_crypto_ec: Any = None
_crypto_hashes: Any = None
_decode_dss_signature: Any = None
try:
    from cryptography.hazmat.primitives import hashes as _crypto_hashes
    from cryptography.hazmat.primitives.asymmetric import ec as _crypto_ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature as _decode_dss_signature,
    )
except ImportError as _crypto_exc:
    _CRYPTO_ERROR = f"{type(_crypto_exc).__name__}: {_crypto_exc}"

# ---------------------------------------------------------------- UHID UAPI

UHID_DEV_PATH = "/dev/uhid"
UHID_EVENT_SIZE = 4380      # sizeof(struct uhid_event)，读写都必须按这个长度
UHID_DATA_MAX = 4096        # UHID_DATA_MAX

# struct uhid_event.type
UHID_DESTROY = 1
UHID_START = 2
UHID_STOP = 3
UHID_OPEN = 4
UHID_CLOSE = 5
UHID_OUTPUT = 6
UHID_FEATURE = 9
UHID_CREATE2 = 11
UHID_INPUT2 = 12
UHID_GET_REPORT = 13
UHID_GET_REPORT_REPLY = 14
# 注意：9 是 UHID_FEATURE；SET_REPORT 在当前内核实为 15（应答 16），不是 9
UHID_SET_REPORT = 15

# struct uhid_output_req.rtype —— 内核传的是 HID 报表类型：
# 0=INPUT, 1=OUTPUT, 2=FEATURE（hidraw write 落到 1）
UHID_RTYPE_OUTPUT = 0
UHID_RTYPE_OUTPUT_KERNEL = 1

UHID_BUS_USB = 0x03

DEVICE_NAME = "Virtual FIDO2 Key"
DEVICE_PHYS = ""
DEVICE_UNIQ = ""
DEVICE_VID = 0x1209
DEVICE_PID = 0x0001
DEVICE_VERSION = 0x0100
DEVICE_COUNTRY = 0x0000

# FIDO 标准 64 字节 in/out report descriptor
REPORT_DESCRIPTOR = bytes((
    0x06, 0xD0, 0xF1,  # Usage Page (FIDO Alliance)
    0x09, 0x01,        # Usage (U2F HID Authenticator Device)
    0xA1, 0x01,        # Collection (Application)
    0x09, 0x20,        #   Usage (Input Report Data)
    0x15, 0x00,        #   Logical Minimum (0)
    0x26, 0xFF, 0x00,  #   Logical Maximum (255)
    0x75, 0x08,        #   Report Size (8)
    0x95, 0x40,        #   Report Count (64)
    0x81, 0x02,        #   Input (Data,Var,Abs)
    0x09, 0x21,        #   Usage (Output Report Data)
    0x15, 0x00,        #   Logical Minimum (0)
    0x26, 0xFF, 0x00,  #   Logical Maximum (255)
    0x75, 0x08,        #   Report Size (8)
    0x95, 0x40,        #   Report Count (64)
    0x91, 0x02,        #   Output (Data,Var,Abs)
    0xC0,              # End Collection
))

# ---------------------------------------------------------------- CTAPHID

HID_REPORT_SIZE = 64
CTAPHID_INIT_PAYLOAD = 57       # 首包可携带的数据长度
CTAPHID_CONT_PAYLOAD = 59       # 续包可携带的数据长度

CTAPHID_PING = 0x81
CTAPHID_INIT = 0x86
CTAPHID_CBOR = 0x90
CTAPHID_CANCEL = 0x11           # 命令号；线上首包 cmd 字节带 0x80 → 0x91
CTAPHID_ERROR = 0xBF

CTAPHID_CMD_INIT_MASK = 0x80

CID_BROADCAST = 0xFFFFFFFF
CID_DEFAULT = 0x00000001
_CID_COUNTER = {"next": CID_DEFAULT}   # 每次广播 INIT 分配唯一 CID，多 handle 并存时不会互相串台

CTAPHID_ERR_INVALID_CMD = 0x01

CTAPHID_PROTO_VERSION = 2
CTAPHID_DEV_VERSION = (0, 0, 0)
CTAPHID_CAP_FLAGS = 0x04   # bit2 = CBOR(CTAP2) 支持；0x00 会让浏览器回落 U2F

# ---------------------------------------------------------------- CTAP2

CTAP2_OK = 0x00
CTAP2_ERR_INVALID_COMMAND = 0x01
CTAP2_ERR_INVALID_CBOR = 0x12
CTAP2_ERR_MISSING_PARAMETER = 0x14
CTAP2_ERR_UNSUPPORTED_OPTION = 0x2B
CTAP2_ERR_NO_CREDENTIALS = 0x2E

CTAP2_MAKE_CREDENTIAL = 0x01
CTAP2_GET_ASSERTION = 0x02
CTAP2_AUTHENTICATOR_GET_INFO = 0x04
CTAP2_AUTHENTICATOR_SELECTION = 0x0B
# 已知但本 spike 不实现的命令（clientPin / reset / credMgmt / selection 等）
CTAP2_UNIMPLEMENTED = frozenset({0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0C, 0x0D})

AAGUID = bytes([0xA0] * 16)
MAX_MSG_SIZE = 1200

# authenticatorData.flags
FLAG_UP = 0x01                  # user present
FLAG_AT = 0x40                  # attested credential data included
MAKECREDENTIAL_FLAGS = FLAG_UP | FLAG_AT      # 0x41
GETASSERTION_FLAGS = FLAG_UP                  # 0x01（不带 AT）

ATTESTATION_FMT_NONE = "none"
PUBLIC_KEY_CREDENTIAL_TYPE = "public-key"
CREDENTIAL_ID_LEN = 32          # 随机 credId 长度
INITIAL_SIGN_COUNT = 1          # makeCredential 返回的初始 signCount

# COSE_Key 标签（RFC 9052）
COSE_KEY_KTY = 1
COSE_KEY_ALG = 3
COSE_KEY_CRV = -1
COSE_KEY_X = -2
COSE_KEY_Y = -3
COSE_KTY_EC2 = 2
COSE_ALG_ES256 = -7
COSE_CRV_P256 = 1
ES256_COORD_LEN = 32            # P-256 坐标 / 签名分量字节数

# ---------------------------------------------------------------- CBOR

CBOR_UINT = 0
CBOR_NINT = 1
CBOR_BYTES = 2
CBOR_TEXT = 3
CBOR_ARRAY = 4
CBOR_MAP = 5
CBOR_TAG = 6
CBOR_SIMPLE = 7

CBOR_FALSE = 0xF4   # CBOR simple value false（0x14 是正整数 20，写错会让 Chrome 拒绝整份 GetInfo）
CBOR_TRUE = 0xF5    # CBOR simple value true（0x15 是正整数 21）
CBOR_SIMPLE_FALSE = 20
CBOR_SIMPLE_TRUE = 21
CBOR_SIMPLE_NULL = 22
CBOR_SIMPLE_UNDEFINED = 23
CBOR_INDEFINITE = 31


# ---------------------------------------------------------------- 事件构造


def build_event(event_type: int, body: bytes = b"") -> bytes:
    """构造一个完整的 struct uhid_event（type 4 字节 + 联合体 + 补零到 4380）。"""
    if len(body) > UHID_EVENT_SIZE - 4:
        raise ValueError(f"event body too large: {len(body)}")
    return struct.pack("<I", event_type) + body + b"\x00" * (UHID_EVENT_SIZE - 4 - len(body))


def build_create2(report_descriptor: bytes) -> bytes:
    """构造 UHID_CREATE2 请求（uhid_create2_req 为 packed，紧跟 type 之后）。"""
    body = struct.pack(
        "<128s64s64sHHIIII",
        DEVICE_NAME.encode("utf-8"),
        DEVICE_PHYS.encode("utf-8"),
        DEVICE_UNIQ.encode("utf-8"),
        len(report_descriptor),
        UHID_BUS_USB,
        DEVICE_VID,
        DEVICE_PID,
        DEVICE_VERSION,
        DEVICE_COUNTRY,
    )
    body += report_descriptor.ljust(UHID_DATA_MAX, b"\x00")
    return build_event(UHID_CREATE2, body)


def build_input2(report: bytes) -> bytes:
    """构造 UHID_INPUT2 请求（packed: u16 size + data）。"""
    if len(report) > UHID_DATA_MAX:
        raise ValueError(f"input report too large: {len(report)}")
    return build_event(UHID_INPUT2, struct.pack("<H", len(report)) + report)


def build_get_report_reply(report_id: int, data: bytes = b"", err: int = 0) -> bytes:
    """构造 UHID_GET_REPORT_REPLY（packed: u32 id + u16 err + u16 size + data）。"""
    if len(data) > UHID_DATA_MAX:
        raise ValueError(f"reply data too large: {len(data)}")
    return build_event(
        UHID_GET_REPORT_REPLY, struct.pack("<IHH", report_id, err, len(data)) + data
    )


def build_destroy() -> bytes:
    """构造 UHID_DESTROY 请求（body 为空）。"""
    return build_event(UHID_DESTROY)


def parse_output(buf: bytes) -> Tuple[bytes, int, int]:
    """解析 UHID_OUTPUT：返回 (data[0:size], size, rtype)。"""
    size, rtype = struct.unpack_from("<HB", buf, 4 + UHID_DATA_MAX)
    size = min(size, UHID_DATA_MAX)
    return buf[4:4 + size], size, rtype


def parse_get_report(buf: bytes) -> Tuple[int, int, int]:
    """解析 UHID_GET_REPORT：返回 (id, rnum, rtype)。"""
    report_id, rnum, rtype = struct.unpack_from("<IBB", buf, 4)
    return report_id, rnum, rtype


# ---------------------------------------------------------------- CBOR 编码


def _cbor_head(major: int, value: int) -> bytes:
    """编码 CBOR item head：major type + 最小编码长度的参数。"""
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 0x100:
        return bytes([(major << 5) | 24, value])
    if value < 0x10000:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value < 0x100000000:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")


def cbor_encode(value: object) -> bytes:
    """手写 CBOR 编码器，只支持 text/bytes/bool/int/map。

    map 按 canonical 顺序编码：key 编码后长度升序，同长度按字节序升序。
    """
    if value is True:
        return bytes([CBOR_TRUE])
    if value is False:
        return bytes([CBOR_FALSE])
    if isinstance(value, int):
        if value >= 0:
            return _cbor_head(CBOR_UINT, value)
        return _cbor_head(CBOR_NINT, -1 - value)
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        return _cbor_head(CBOR_BYTES, len(raw)) + raw
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _cbor_head(CBOR_TEXT, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        parts = [cbor_encode(item) for item in value]
        return _cbor_head(CBOR_ARRAY, len(parts)) + b"".join(parts)
    if isinstance(value, dict):
        items: List[Tuple[bytes, bytes]] = []
        for key, item in value.items():
            encoded_key = cbor_encode(key)
            items.append((encoded_key, cbor_encode(item)))
        items.sort(key=lambda pair: (len(pair[0]), pair[0]))
        return _cbor_head(CBOR_MAP, len(items)) + b"".join(k + v for k, v in items)
    raise TypeError(f"unsupported CBOR value type: {type(value)!r}")


# ---------------------------------------------------------------- CBOR 解码


class CborDecodeError(ValueError):
    """CBOR 解码失败（数据截断、保留编码或不支持的类型）。"""


def _cbor_arg(data: bytes, offset: int, info: int) -> Tuple[int, int]:
    """读取 CBOR 附加参数（长度 / 整数值），返回 (value, next_offset)。"""
    if info < 24:
        return info, offset
    if info in (24, 25, 26, 27):
        size = 1 << (info - 24)
        end = offset + size
        if end > len(data):
            raise CborDecodeError("truncated CBOR argument")
        return int.from_bytes(data[offset:end], "big"), end
    if info == CBOR_INDEFINITE:
        raise CborDecodeError("indefinite length not supported")
    raise CborDecodeError(f"reserved additional info {info}")


def cbor_decode(data: bytes, offset: int = 0) -> Tuple[object, int]:
    """解码 data[offset:] 中的一个 CBOR data item。

    参数:
        data: 原始字节。
        offset: 起始偏移。
    返回:
        (value, next_offset)。value 可能是 int / bytes / str / list / dict / bool / None。
    覆盖类型:
        uint / nint / bytes / text / array / map（可任意嵌套）/ bool / null；
        tag(6) 忽略标签后返回内层值；float 与 indefinite length 不支持，抛 CborDecodeError。
    """
    if offset >= len(data):
        raise CborDecodeError("unexpected end of CBOR data")
    major = data[offset] >> 5
    info = data[offset] & 0x1F
    offset += 1

    if major == CBOR_SIMPLE:
        if info == CBOR_SIMPLE_FALSE:
            return False, offset
        if info == CBOR_SIMPLE_TRUE:
            return True, offset
        if info in (CBOR_SIMPLE_NULL, CBOR_SIMPLE_UNDEFINED):
            return None, offset
        raise CborDecodeError(f"unsupported simple value {info}")

    value, offset = _cbor_arg(data, offset, info)

    if major == CBOR_TAG:
        # 忽略语义标签（CTAP2 请求里实际不会出现，容错用）
        inner, next_offset = cbor_decode(data, offset)
        return inner, next_offset
    if major == CBOR_UINT:
        return value, offset
    if major == CBOR_NINT:
        return -1 - value, offset
    if major == CBOR_BYTES:
        end = offset + value
        if end > len(data):
            raise CborDecodeError("truncated byte string")
        return data[offset:end], end
    if major == CBOR_TEXT:
        end = offset + value
        if end > len(data):
            raise CborDecodeError("truncated text string")
        return data[offset:end].decode("utf-8"), end
    if major == CBOR_ARRAY:
        items: List[object] = []
        for _ in range(value):
            item, offset = cbor_decode(data, offset)
            items.append(item)
        return items, offset
    if major == CBOR_MAP:
        entries: Dict[object, object] = {}
        for _ in range(value):
            key, offset = cbor_decode(data, offset)
            item, offset = cbor_decode(data, offset)
            entries[key] = item
        return entries, offset
    raise CborDecodeError(f"unsupported major type {major}")


# ---------------------------------------------------------------- CTAPHID 协议栈

SendReport = Callable[[bytes], None]


def get_info_response() -> Dict[object, object]:
    """authenticatorGetInfo 应答体（versions 必须是 array，真客户端才不会解析失败）。"""
    # 二分用：只留规范 Required 字段（versions + aaguid）
    return {
        1: ["FIDO_2_0", "FIDO_2_1"],
        3: AAGUID,
        4: {"up": True, "plat": False},
        5: MAX_MSG_SIZE,
        9: ["usb"],
        10: [{"type": "public-key", "alg": -7}],
    }


def ctap2_error(error: int) -> bytes:
    """CTAP2 错误应答：按规范只回一个状态字节（不带 CBOR）。"""
    return bytes([error])


def check_crypto_dependency() -> bool:
    """启动期检查 cryptography 是否可用；不可用时打印安装指引并返回 False。"""
    if _CRYPTO_ERROR is None:
        return True
    print("!! 缺少依赖 cryptography，无法做 ES256 签名，拒绝启动。", file=sys.stderr)
    print("!!   Fedora:  sudo dnf install python3-cryptography", file=sys.stderr)
    print("!!   其它:    python3 -m pip install cryptography", file=sys.stderr)
    print(f"!! import 失败原因: {_CRYPTO_ERROR}", file=sys.stderr)
    return False


def cose_key_es256(public_key: Any) -> bytes:
    """把 P-256 公钥编码成 COSE_Key：{1:2, 3:-7, -1:1, -2:x, -3:y}。"""
    numbers = public_key.public_numbers()
    return cbor_encode({
        COSE_KEY_KTY: COSE_KTY_EC2,
        COSE_KEY_ALG: COSE_ALG_ES256,
        COSE_KEY_CRV: COSE_CRV_P256,
        COSE_KEY_X: numbers.x.to_bytes(ES256_COORD_LEN, "big"),
        COSE_KEY_Y: numbers.y.to_bytes(ES256_COORD_LEN, "big"),
    })


def es256_sign(private_key: Any, message: bytes) -> bytes:
    """用 P-256 私钥对 message 做 ECDSA-SHA256，返回 WebAuthn 要求的 DER（ASN.1）签名。

    注意：FIDO2/WebAuthn 的 ES256 签名是 DER 编码的 Ecdsa-Sig-Value，
    不是 raw r||s；返回 raw 会让浏览器验签失败。
    """
    return private_key.sign(message, _crypto_ec.ECDSA(_crypto_hashes.SHA256()))


def generate_p256_key() -> Any:
    """生成一颗 P-256（SECP256R1）私钥对象。"""
    return _crypto_ec.generate_private_key(_crypto_ec.SECP256R1())


def rp_id_hash(rp_id: str) -> bytes:
    """计算 rpIdHash = SHA-256(rpId)。"""
    return hashlib.sha256(rp_id.encode("utf-8")).digest()


@dataclass
class Credential:
    """一颗内存里的 ES256 凭证。"""

    rp_id: str
    rp_id_hash: bytes
    user_handle: bytes
    private_key: Any
    sign_count: int = 0


class Authenticator:
    """内存版 CTAP2 authenticator：ES256 + 无 attestation（fmt="none"）。

    凭证全部放在内存 dict 里（credId -> Credential），进程退出即丢。
    """

    def __init__(self) -> None:
        self._credentials: Dict[bytes, Credential] = {}

    # ---- 公共接口

    def credential_count(self) -> int:
        """返回已保存的凭证条数（启动 / 新增后打印用）。"""
        return len(self._credentials)

    def make_credential(self, request: Dict[object, object]) -> bytes:
        """处理 authenticatorMakeCredential，返回 CTAPHID_CBOR 载荷（状态字节 + CBOR）。

        应答：{1: "none", 2: authData, 3: {}}；
        authData = rpIdHash || flags(0x41) || signCount(1) || aaguid || credIdLen || credId(32) || COSE_Key。
        """
        client_data_hash = request.get(1)
        rp = request.get(2)
        user = request.get(3)
        if not isinstance(client_data_hash, bytes) or len(client_data_hash) != 32:
            print("!! makeCredential: clientDataHash 缺失或长度不为 32")
            return ctap2_error(CTAP2_ERR_MISSING_PARAMETER)
        # CTAP2 的 rp/user 是 text key 的子 map：rp{"id","name"}、user{"id","name","displayName"}
        if not isinstance(rp, dict) or not isinstance(rp.get("id"), str):
            print("!! makeCredential: rp.id 缺失")
            return ctap2_error(CTAP2_ERR_MISSING_PARAMETER)
        rp_id = rp["id"]
        user_handle = user.get("id") if isinstance(user, dict) and isinstance(user.get("id"), bytes) else b""
        print("!! auto-UV (spike)")

        private_key = generate_p256_key()
        cred_id = secrets.token_bytes(CREDENTIAL_ID_LEN)
        credential = Credential(
            rp_id=rp_id,
            rp_id_hash=rp_id_hash(rp_id),
            user_handle=user_handle,
            private_key=private_key,
            sign_count=INITIAL_SIGN_COUNT,
        )
        self._credentials[cred_id] = credential

        auth_data = (
            credential.rp_id_hash
            + bytes([MAKECREDENTIAL_FLAGS])
            + credential.sign_count.to_bytes(4, "big")
            + AAGUID
            + len(cred_id).to_bytes(2, "big")
            + cred_id
            + cose_key_es256(private_key.public_key())
        )
        # fmt="none" 的 attStmt 必须为空，签名不回传；这里算一次仅用于自检日志
        signature = es256_sign(private_key, auth_data + client_data_hash)
        print(
            f">> makeCredential rp_id={rp_id} credId={cred_id.hex()[:16]}.. "
            f"selfsig={len(signature)}B stored={self.credential_count()}"
        )
        return bytes([CTAP2_OK]) + cbor_encode(
            {1: ATTESTATION_FMT_NONE, 2: auth_data, 3: {}}
        )

    def get_assertion(self, request: Dict[object, object]) -> bytes:
        """处理 authenticatorGetAssertion，返回 CTAPHID_CBOR 载荷（状态字节 + CBOR）。

        应答：{1: {1: credId, 2: "public-key"}, 2: authData, 3: signature, 4: userHandle}；
        authData = rpIdHash || flags(0x01, 无 AT) || signCount(递增)。
        """
        rp_id = request.get(1)
        client_data_hash = request.get(2)
        if not isinstance(rp_id, str):
            print("!! getAssertion: rpId 缺失")
            return ctap2_error(CTAP2_ERR_MISSING_PARAMETER)
        if not isinstance(client_data_hash, bytes) or len(client_data_hash) != 32:
            print("!! getAssertion: clientDataHash 缺失或长度不为 32")
            return ctap2_error(CTAP2_ERR_MISSING_PARAMETER)
        print("!! auto-UV (spike)")

        matched = self._match_credential(rp_id_hash(rp_id), request.get(3))
        if matched is None:
            print(f"!! getAssertion: rp_id={rp_id} 没有可用凭证")
            return ctap2_error(CTAP2_ERR_NO_CREDENTIALS)
        cred_id, credential = matched

        credential.sign_count += 1
        auth_data = (
            credential.rp_id_hash
            + bytes([GETASSERTION_FLAGS])
            + credential.sign_count.to_bytes(4, "big")
        )
        signature = es256_sign(credential.private_key, auth_data + client_data_hash)
        response: Dict[object, object] = {
            1: {1: cred_id, 2: PUBLIC_KEY_CREDENTIAL_TYPE},
            2: auth_data,
            3: signature,
        }
        if credential.user_handle:
            response[4] = credential.user_handle
        print(
            f">> getAssertion rp_id={rp_id} credId={cred_id.hex()[:16]}.. "
            f"count={credential.sign_count}"
        )
        return bytes([CTAP2_OK]) + cbor_encode(response)

    # ---- 私有

    def _match_credential(
        self, rp_hash: bytes, allow_list: object
    ) -> Optional[Tuple[bytes, Credential]]:
        """按 rpIdHash 挑凭证；带 allowList 时按 credId 精确匹配。"""
        if isinstance(allow_list, list) and allow_list:
            for entry in allow_list:
                if not isinstance(entry, dict):
                    continue
                cred_id = entry.get("id")
                if not isinstance(cred_id, bytes):
                    continue
                credential = self._credentials.get(cred_id)
                if credential is not None and credential.rp_id_hash == rp_hash:
                    return cred_id, credential
            return None
        for cred_id, credential in self._credentials.items():
            if credential.rp_id_hash == rp_hash:
                return cred_id, credential
        return None


@dataclass
class _PendingMessage:
    """一个尚未收齐的 CTAPHID 消息（按 CID 保存）。"""

    cmd: int
    bcnt: int
    buf: bytearray
    next_seq: int = 0


class CtapHid:
    """最小 CTAPHID 分片/重组与命令应答。

    收：64 字节报文 → 首包(CID|CMD|BCNT|DATA57) / 续包(CID|SEQ|DATA59)
    发：按同一格式分片，经 UHID_INPUT2 回给内核。
    """

    def __init__(self, send_report: SendReport, authenticator: Authenticator) -> None:
        self._send_report = send_report
        self._authenticator = authenticator
        self._pending: Dict[int, _PendingMessage] = {}

    # ---- 公共接口

    def handle_report(self, report: bytes) -> None:
        """处理一个 64 字节 HID 输入报文（来自主机）。"""
        if len(report) < HID_REPORT_SIZE:
            print(f"!! short report ({len(report)} bytes), ignored")
            return
        cid = int.from_bytes(report[0:4], "big")
        header = report[4]
        if header & CTAPHID_CMD_INIT_MASK:
            self._handle_init_packet(cid, header, report)
        else:
            self._handle_cont_packet(cid, header, report)

    def reset(self) -> None:
        """丢弃所有未完成的分片（退出/复位时调用）。"""
        self._pending.clear()

    # ---- 接收侧

    def _handle_init_packet(self, cid: int, cmd: int, report: bytes) -> None:
        bcnt = int.from_bytes(report[5:7], "big")
        chunk = report[7:7 + CTAPHID_INIT_PAYLOAD]
        if bcnt <= CTAPHID_INIT_PAYLOAD:
            self._dispatch(cid, cmd, chunk[:bcnt])
            return
        self._pending[cid] = _PendingMessage(
            cmd=cmd, bcnt=bcnt, buf=bytearray(chunk[:CTAPHID_INIT_PAYLOAD])
        )

    def _handle_cont_packet(self, cid: int, seq: int, report: bytes) -> None:
        state = self._pending.get(cid)
        if state is None:
            print(f"!! unexpected continuation cid=0x{cid:08X} seq={seq}, ignored")
            return
        if seq != state.next_seq:
            print(f"!! out of order continuation cid=0x{cid:08X} seq={seq}, dropped")
            self._pending.pop(cid, None)
            return
        state.buf += report[5:5 + CTAPHID_CONT_PAYLOAD]
        state.next_seq = seq + 1
        if len(state.buf) >= state.bcnt:
            self._pending.pop(cid, None)
            self._dispatch(cid, state.cmd, bytes(state.buf[:state.bcnt]))

    # ---- 分发

    def _dispatch(self, cid: int, cmd: int, payload: bytes) -> None:
        print(f"<= cmd=0x{cmd:02X} cid={cid:08x} len={len(payload)} data={payload[:96].hex()}")
        if cmd == CTAPHID_INIT:
            self._on_init(cid, payload)
        elif cmd == CTAPHID_PING:
            self._on_ping(cid, payload)
        elif cmd == CTAPHID_CBOR:
            self._on_cbor(cid, payload)
        elif (cmd & 0x7F) == CTAPHID_CANCEL:
            self._on_cancel()
        else:
            print(f"!! unsupported CTAPHID cmd 0x{cmd:02X}")
            self._send(cid, CTAPHID_ERROR, bytes([CTAPHID_ERR_INVALID_CMD]))

    # ---- 命令实现

    def _on_init(self, cid: int, payload: bytes) -> None:
        nonce = payload[:8].ljust(8, b"\x00")
        # 广播 CID 不能继续用；否则沿用原 CID
        if cid == CID_BROADCAST:
            # 每个新连接必须给不同 CID；Chrome 会同时开多个 handle
            new_cid = _CID_COUNTER["next"]
            _CID_COUNTER["next"] = new_cid + 1 if new_cid < 0x7FFFFFFF else CID_DEFAULT
        else:
            new_cid = cid
        body = (
            nonce
            + new_cid.to_bytes(4, "big")
            + bytes([CTAPHID_PROTO_VERSION])
            + bytes(CTAPHID_DEV_VERSION)
            + bytes([CTAPHID_CAP_FLAGS])
        )
        self._send(cid, CTAPHID_INIT, body)

    def _on_ping(self, cid: int, payload: bytes) -> None:
        self._send(cid, CTAPHID_PING, payload)

    def _on_cbor(self, cid: int, payload: bytes) -> None:
        """按 CTAP2 命令分发：GetInfo / MakeCredential / GetAssertion。"""
        if not payload:
            self._send(cid, CTAPHID_CBOR, ctap2_error(CTAP2_ERR_INVALID_COMMAND))
            return
        command = payload[0]
        if command == CTAP2_AUTHENTICATOR_GET_INFO:
            self._send(cid, CTAPHID_CBOR, bytes([CTAP2_OK]) + cbor_encode(get_info_response()))
            return
        if command == CTAP2_AUTHENTICATOR_SELECTION:
            # Chrome 在多认证器场景下先发 selection 让用户确认「用这把」；
            # 回 ok 后它才会继续发 makeCredential/getAssertion。
            print("!! authenticatorSelection -> 模拟用户轻触(1.2s)")
            time.sleep(1.2)
            self._send(cid, CTAPHID_CBOR, bytes([CTAP2_OK]))
            return
        if command not in (CTAP2_MAKE_CREDENTIAL, CTAP2_GET_ASSERTION):
            status = (
                CTAP2_ERR_UNSUPPORTED_OPTION
                if command in CTAP2_UNIMPLEMENTED
                else CTAP2_ERR_INVALID_COMMAND
            )
            print(f"!! unsupported CTAP2 command 0x{command:02X}")
            self._send(cid, CTAPHID_CBOR, ctap2_error(status))
            return
        try:
            request, decoded_len = cbor_decode(payload[1:])
        except CborDecodeError as exc:
            print(f"!! CBOR decode failed: {exc}")
            self._send(cid, CTAPHID_CBOR, ctap2_error(CTAP2_ERR_INVALID_CBOR))
            return
        if not isinstance(request, dict):
            print(f"!! CBOR request is {type(request).__name__}, expected map")
            self._send(cid, CTAPHID_CBOR, ctap2_error(CTAP2_ERR_INVALID_CBOR))
            return
        if decoded_len != len(payload) - 1:
            print(f"!! CBOR trailing bytes ({len(payload) - 1 - decoded_len}), ignored")
        if command == CTAP2_MAKE_CREDENTIAL:
            self._send(cid, CTAPHID_CBOR, self._authenticator.make_credential(request))
        else:
            self._send(cid, CTAPHID_CBOR, self._authenticator.get_assertion(request))

    def _on_cancel(self) -> None:
        """CTAPHID_CANCEL：清空未收齐的分片（本 spike 没有可中断的长任务）。"""
        print("!! CTAPHID_CANCEL received, clearing pending fragments")
        self._pending.clear()

    # ---- 发送侧

    def _send(self, cid: int, cmd: int, payload: bytes) -> None:
        """按 CTAPHID 分片回包，并打印 `> resp ...` 日志。"""
        print(f"> resp cmd=0x{cmd:02X} len={len(payload)}")
        for packet in self._fragment(cid, cmd, payload):
            self._send_report(packet)

    @staticmethod
    def _fragment(cid: int, cmd: int, payload: bytes) -> Iterator[bytes]:
        """把 CTAPHID 载荷切成 64 字节报文（首包 57 字节数据，续包 59 字节）。"""
        cid_bytes = cid.to_bytes(4, "big")
        header = cid_bytes + bytes([cmd]) + len(payload).to_bytes(2, "big")
        yield (header + payload[:CTAPHID_INIT_PAYLOAD]).ljust(HID_REPORT_SIZE, b"\x00")
        offset = CTAPHID_INIT_PAYLOAD
        seq = 0
        while offset < len(payload):
            chunk = payload[offset:offset + CTAPHID_CONT_PAYLOAD]
            yield (cid_bytes + bytes([seq]) + chunk).ljust(HID_REPORT_SIZE, b"\x00")
            offset += CTAPHID_CONT_PAYLOAD
            seq += 1


# ---------------------------------------------------------------- 设备 IO


def write_event(fd: int, event: bytes) -> None:
    """把完整事件写给内核：必须写满 UHID_EVENT_SIZE 字节。"""
    if len(event) != UHID_EVENT_SIZE:
        raise ValueError(f"event must be {UHID_EVENT_SIZE} bytes, got {len(event)}")
    view = memoryview(event)
    written = 0
    while written < UHID_EVENT_SIZE:
        written += os.write(fd, view[written:])


def read_event(fd: int) -> Optional[bytes]:
    """读一个完整事件（内核每次只返回一个 4380 字节事件），EOF 返回 None。"""
    buf = bytearray()
    while len(buf) < UHID_EVENT_SIZE:
        chunk = os.read(fd, UHID_EVENT_SIZE - len(buf))
        if not chunk:
            return None
        buf += chunk
    return bytes(buf)


def reply_empty_get_report(fd: int, report_id: int) -> None:
    """对做不出来的 GET_REPORT 回 0 长度（err=0），避免内核侧一直等。"""
    try:
        write_event(fd, build_get_report_reply(report_id, b""))
    except OSError as exc:
        print(f"!! write UHID_GET_REPORT_REPLY failed: {exc}", file=sys.stderr)


# ---------------------------------------------------------------- 事件处理


def handle_event(fd: int, ctaphid: CtapHid, event: bytes) -> None:
    """处理一条内核事件（只打印日志的事件不退出主循环）。"""
    event_type = struct.unpack_from("<I", event, 0)[0]

    if event_type == UHID_START:
        print(">> UHID_START")
    elif event_type == UHID_OPEN:
        print(">> UHID_OPEN")
    elif event_type == UHID_STOP:
        print(">> UHID_STOP")
    elif event_type == UHID_CLOSE:
        print(">> UHID_CLOSE")
    elif event_type == UHID_OUTPUT:
        data, size, rtype = parse_output(event)
        if rtype not in (UHID_RTYPE_OUTPUT, UHID_RTYPE_OUTPUT_KERNEL):
            print(f">> UHID_OUTPUT rtype={rtype} (feature), ignored")
            return
        # hidapi 约定：设备无 report ID 时，写入首字节补 0x00。
        # Chrome 实测写 65 字节 = 00 + 64 字节 CTAPHID 帧，这里必须剥掉，否则整帧错位。
        if size == HID_REPORT_SIZE + 1 and data[0] == 0x00:
            data = data[1:]
            size = HID_REPORT_SIZE
        if size != HID_REPORT_SIZE:
            print(f"!! output size={size} hex={data[:32].hex()}")
        # 长包：内核可能一次带多个 64 字节 report
        for offset in range(0, size, HID_REPORT_SIZE):
            report = data[offset:offset + HID_REPORT_SIZE]
            if len(report) < HID_REPORT_SIZE:
                print(f"!! truncated output report ({len(report)} bytes), ignored")
                break
            ctaphid.handle_report(report)
    elif event_type == UHID_GET_REPORT:
        report_id, rnum, rtype = parse_get_report(event)
        print(f">> UHID_GET_REPORT id={report_id} rnum={rnum} rtype={rtype}")
        reply_empty_get_report(fd, report_id)
    elif event_type in (UHID_SET_REPORT, UHID_FEATURE):
        # 内核不为 SET_REPORT/FEATURE 等待回复；回 GET_REPORT_REPLY 只会 -EBUSY
        print(f">> UHID_TYPE_{event_type} (set/feature report), no reply")
    else:
        print(f">> unhandled event type={event_type}")


# ---------------------------------------------------------------- 入口


def main() -> int:
    """创建虚拟设备并进入事件循环；Ctrl-C 时销毁设备后退出。"""
    if not check_crypto_dependency():
        return 2
    try:
        fd = os.open(UHID_DEV_PATH, os.O_RDWR)
    except OSError as exc:
        print(f"!! open {UHID_DEV_PATH} failed: {exc}", file=sys.stderr)
        return 1

    def send_report(report: bytes) -> None:
        try:
            write_event(fd, build_input2(report))
        except OSError as exc:
            print(f"!! write UHID_INPUT2 failed: {exc}", file=sys.stderr)

    authenticator = Authenticator()
    ctaphid = CtapHid(send_report, authenticator)
    try:
        write_event(fd, build_create2(REPORT_DESCRIPTOR))
        print(
            f"device created: name={DEVICE_NAME} "
            f"vid=0x{DEVICE_VID:04X} pid=0x{DEVICE_PID:04X}"
        )
        print(f"credentials stored: {authenticator.credential_count()}")
        while True:
            event = read_event(fd)
            if event is None:
                print("!! /dev/uhid returned EOF, exiting")
                break
            handle_event(fd, ctaphid, event)
    except KeyboardInterrupt:
        print("\ninterrupted, destroying device")
    except OSError as exc:
        print(f"!! uhid io error: {exc}", file=sys.stderr)
        return 1
    finally:
        ctaphid.reset()
        try:
            write_event(fd, build_destroy())
        except OSError as exc:
            print(f"!! write UHID_DESTROY failed: {exc}", file=sys.stderr)
        os.close(fd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
