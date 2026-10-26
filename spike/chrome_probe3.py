#!/usr/bin/env python3
"""无头 Chromium + 本地页面触发 WebAuthn create，抓 Chromium 的 FIDO 日志。

用本地 http://localhost（安全上下文）避免第三方页面的干扰。
"""
import functools
import http.server
import json
import os
import socketserver
import subprocess
import threading
import time
import urllib.request

import websockets.sync.client as ws_client

import socket as _socket
def _free_port() -> int:
    with _socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


CDP_PORT = _free_port()
PAGE_PORT = _free_port()
LOG = "/var/tmp/chrome-fido.log"
PROFILE = "/var/tmp/chrome-fido-profile3"
SITE = "/var/tmp/webauthn-test"
socketserver.TCPServer.allow_reuse_address = True
BIN = next(
    (b for b in ("chromium-browser", "chromium", "google-chrome") if os.path.exists("/usr/bin/" + b)),
    "chromium-browser",
)

PAGE = """<!doctype html><meta charset="utf-8"><title>wa</title><h1>webauthn probe</h1>"""

CREATE_JS = """
(async () => {
  try {
    const cred = await navigator.credentials.create({publicKey: {
      challenge: new Uint8Array(32).fill(7),
      rp: {id: 'localhost', name: 'spike'},
      user: {id: new Uint8Array(16).fill(3), name: 'spike', displayName: 'spike'},
      pubKeyCredParams: [{type: 'public-key', alg: -7}],
      timeout: 15000,
      authenticatorSelection: {residentKey: 'preferred', requireResidentKey: false, userVerification: 'preferred'},
      extensions: {credProps: true},
      attestation: 'none'
    }});
    const assert = await navigator.credentials.get({publicKey: {
      challenge: new Uint8Array(32).fill(9),
      rpId: 'localhost',
      allowCredentials: [{type: 'public-key', id: new Uint8Array(cred.rawId)}],
      timeout: 15000,
      userVerification: 'discouraged'
    }});
    return 'OK create=' + cred.id.slice(0, 12) + ' assertion=' + (assert ? assert.id.slice(0, 12) : 'null');
  } catch (e) {
    return 'ERR:' + e.name + ':' + e.message;
  }
})()
"""


def serve() -> None:
    os.makedirs(SITE, exist_ok=True)
    with open(os.path.join(SITE, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(PAGE)
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=SITE)
    httpd = socketserver.TCPServer(("127.0.0.1", PAGE_PORT), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()


def main() -> None:
    serve()
    if os.path.exists(LOG):
        os.remove(LOG)
    log_file = open(LOG, "w", encoding="utf-8")
    proc = subprocess.Popen(
        [
            BIN,
            "--headless=new",
            f"--remote-debugging-port={CDP_PORT}",
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
        for _ in range(60):
            time.sleep(0.5)
            try:
                urllib.request.urlopen("http://127.0.0.1:%d/json/version" % CDP_PORT, timeout=2).read()
                break
            except Exception:  # noqa: BLE001
                continue

        req = urllib.request.Request(
            "http://127.0.0.1:%d/json/new?http://localhost:%d/" % (CDP_PORT, PAGE_PORT), method="PUT"
        )
        page = json.load(urllib.request.urlopen(req, timeout=10))
        with ws_client.connect(page["webSocketDebuggerUrl"], max_size=None) as ws:
            ws.send(json.dumps({"id": 1, "method": "Runtime.enable"}))
            time.sleep(3)
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
                    print("evaluate:", json.dumps(msg, ensure_ascii=False)[:500])
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
