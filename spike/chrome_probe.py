#!/usr/bin/env python3
"""用无头 Chromium + CDP 自动触发一次 WebAuthn create，抓 Chromium 自己的 FIDO 日志。

用途：定位「设备被判为 CTAP1」的真实原因（FIDO_LOG 会打印 GetInfo 解析失败细节）。
"""
import json
import os
import subprocess
import sys
import time
import urllib.request

try:
    import websockets.sync.client as ws_client
except ImportError:
    print("NEED: sudo dnf install -y python3-websockets")
    sys.exit(2)

PORT = 9333
LOG = "/var/tmp/chrome-fido.log"
PROFILE = "/var/tmp/chrome-fido-profile"
BIN = next((b for b in ("chromium-browser", "chromium", "google-chrome") if os.path.exists("/usr/bin/" + b)), "chromium-browser")

CREATE_JS = """
(async () => {
  try {
    const cred = await navigator.credentials.create({publicKey: {
      challenge: new Uint8Array(32),
      rp: {id: 'webauthn.io', name: 'spike'},
      user: {id: new Uint8Array(16), name: 'spike@example.com', displayName: 'spike'},
      pubKeyCredParams: [{type: 'public-key', alg: -7}],
      timeout: 20000,
      authenticatorSelection: {authenticatorAttachment: 'cross-platform', userVerification: 'discouraged'},
      attestation: 'none'
    }});
    return 'OK:' + (cred ? cred.id : 'null');
  } catch (e) {
    return 'ERR:' + e.name + ':' + e.message;
  }
})()
"""


def cdp(ws, msg_id, method, params=None):
    """发一条 CDP 命令并等到对应 id 的回包。"""
    ws.send(json.dumps({"id": msg_id, "method": method, "params": params or {}}))
    while True:
        reply = json.loads(ws.recv(timeout=30))
        if reply.get("id") == msg_id:
            return reply


def main() -> None:
    if os.path.exists(LOG):
        os.remove(LOG)
    log_file = open(LOG, "w", encoding="utf-8")
    proc = subprocess.Popen(
        [
            BIN,
            "--headless=new",
            f"--remote-debugging-port={PORT}",
            f"--user-data-dir={PROFILE}",
            "--no-first-run",
            "--no-default-browser-check",
            "--enable-logging=stderr",
            "--v=1",
            "--vmodule=device/fido/*=3",
            "about:blank",
        ],
        stdout=log_file,
        stderr=log_file,
    )
    try:
        ws_url = None
        for _ in range(60):
            time.sleep(0.5)
            try:
                with urllib.request.urlopen(
                    "http://127.0.0.1:%d/json/version" % PORT, timeout=2
                ) as resp:
                    ws_url = json.load(resp)["webSocketDebuggerUrl"]
                break
            except Exception:  # noqa: BLE001
                continue
        if not ws_url:
            print("devtools not ready")
            return

        with ws_client.connect(ws_url, max_size=None) as ws:
            cdp(ws, 1, "Target.createTarget", {"url": "https://webauthn.io"})
            time.sleep(6)
            targets = cdp(ws, 2, "Target.getTargets")["result"]["targetInfos"]
            page = next(t for t in targets if t["type"] == "page" and "webauthn" in t["url"])
            session = cdp(
                ws, 3, "Target.attachToTarget", {"targetId": page["targetId"], "flatten": True}
            )["result"]["sessionId"]
            cdp(ws, 4, "Runtime.enable", None) if False else None
            ws.send(json.dumps({"id": 4, "method": "Runtime.enable", "sessionId": session}))
            time.sleep(1)
            result = cdp(
                ws,
                5,
                "Runtime.evaluate",
                {
                    "expression": CREATE_JS,
                    "awaitPromise": True,
                    "userGesture": True,
                    "returnByValue": True,
                },
            )
            print("evaluate:", json.dumps(result.get("result", {}), ensure_ascii=False)[:400])
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log_file.close()
        print("== 日志中的 FIDO 相关行 ==")
        for line in open(LOG, encoding="utf-8", errors="replace"):
            low = line.lower()
            if any(k in low for k in ("fido", "getinfo", "ctap", "u2f", "hid")):
                print(line.rstrip()[:300])


if __name__ == "__main__":
    main()
