#!/usr/bin/env python3
"""无头 Chromium + CDP 触发一次 WebAuthn create，抓 Chromium 自己的 FIDO 日志。

简化版：通过 HTTP /json/new 直接拿到页面 target 的 ws，不再走 Target.createTarget。
"""
import json
import os
import subprocess
import sys
import time
import urllib.request

import websockets.sync.client as ws_client

PORT = 9333
LOG = "/var/tmp/chrome-fido.log"
PROFILE = "/var/tmp/chrome-fido-profile"
BIN = next(
    (b for b in ("chromium-browser", "chromium", "google-chrome") if os.path.exists("/usr/bin/" + b)),
    "chromium-browser",
)

CREATE_JS = """
(async () => {
  try {
    const cred = await navigator.credentials.create({publicKey: {
      challenge: new Uint8Array(32),
      rp: {id: 'webauthn.io', name: 'spike'},
      user: {id: new Uint8Array(16), name: 'spike@example.com', displayName: 'spike'},
      pubKeyCredParams: [{type: 'public-key', alg: -7}],
      timeout: 15000,
      authenticatorSelection: {authenticatorAttachment: 'cross-platform', userVerification: 'discouraged'},
      attestation: 'none'
    }});
    return 'OK:' + (cred ? cred.id : 'null');
  } catch (e) {
    return 'ERR:' + e.name + ':' + e.message;
  }
})()
"""


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
            "--vmodule=device/fido/*=3",
            "about:blank",
        ],
        stdout=log_file,
        stderr=log_file,
    )
    try:
        ready = False
        for _ in range(60):
            time.sleep(0.5)
            try:
                urllib.request.urlopen("http://127.0.0.1:%d/json/version" % PORT, timeout=2).read()
                ready = True
                break
            except Exception:  # noqa: BLE001
                continue
        if not ready:
            print("devtools not ready")
            return

        req = urllib.request.Request(
            "http://127.0.0.1:%d/json/new?https://webauthn.io" % PORT, method="PUT"
        )
        page = json.load(urllib.request.urlopen(req, timeout=10))
        print("target:", page.get("url"), "ws:", page.get("webSocketDebuggerUrl"))

        with ws_client.connect(page["webSocketDebuggerUrl"], max_size=None) as ws:
            ws.send(json.dumps({"id": 1, "method": "Runtime.enable"}))
            time.sleep(5)  # 等页面加载完
            ws.send(
                json.dumps(
                    {
                        "id": 2,
                        "method": "Runtime.evaluate",
                        "params": {
                            "expression": CREATE_JS,
                            "awaitPromise": True,
                            "userGesture": True,
                            "returnByValue": True,
                        },
                    }
                )
            )
            while True:
                msg = json.loads(ws.recv(timeout=60))
                if msg.get("id") == 2:
                    print("evaluate:", json.dumps(msg, ensure_ascii=False)[:600])
                    break
    finally:
        time.sleep(1)
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log_file.close()
        print("== FIDO 相关日志 ==")
        hits = 0
        for line in open(LOG, encoding="utf-8", errors="replace"):
            low = line.lower()
            if any(k in low for k in ("fido", "getinfo", "ctap", "u2f")):
                print(line.rstrip()[:280])
                hits += 1
        print("hits=", hits)


if __name__ == "__main__":
    main()
