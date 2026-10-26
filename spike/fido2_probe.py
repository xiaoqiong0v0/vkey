#!/usr/bin/env python3
"""用参考实现 python-fido2 验证虚拟设备的 CTAP2 能力。"""
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2

devices = list(CtapHidDevice.list_devices())
print("hid devices:", len(devices))
for dev in devices:
    print("  path:", dev.descriptor.path, "vid/pid: %04x/%04x" % (dev.descriptor.vid, dev.descriptor.pid))
    try:
        info = Ctap2(dev).info
        print("  CTAP2 OK  versions=%s" % (info.versions,))
        print("           aaguid=%s maxMsg=%s options=%s" % (info.aaguid.hex(), info.max_msg_size, info.options))
    except Exception as exc:  # noqa: BLE001
        print("  CTAP2 FAIL %s: %s" % (type(exc).__name__, exc))
