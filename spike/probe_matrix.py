#!/usr/bin/env python3
"""批量参数扫描：找出 webauthn.io 哪一项让 Chrome 在 selection 后卡住。

对每个预设跑一次无头 Chromium + 本地页面，打印结果与耗时。
"""
import functools
import http.server
import json
import os
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.request

import websockets.sync.client as ws_client

SITE = "/var/tmp/webauthn-test"
BIN = next(
    (b for b in ("chromium-browser", "chromium", "google-chrome") if os.path.exists("/usr/bin/" + b)),
    "chromium-browser",
)
PAGE = "<!doctype html><meta charset='utf-8'><title>wa</title><h1>probe</h1>"

PRESETS = {
    "base": "authenticatorSelection: {authenticatorAttachment: 'cross-platform', userVerification: 'discouraged'}",
    "uv_pref": "authenticatorSelection: {authenticatorAttachment: 'cross-platform', userVerification: 'preferred'}",
    "uv_req": "authenticatorSelection: {authenticatorAttachment: 'cross-platform', userVerification: 'required'}",
    "rk_pref": "authenticatorSelection: {residentKey: 'preferred', requireResidentKey: false, userVerification: 'discouraged'}",
    "rk_req": "authenticatorSelection: {residentKey: 'required', requireResidentKey: true, userVerification: 'discouraged'}",
    "credprops": "authenticatorSelection: {authenticatorAttachment: 'cross-platform', userVerification: 'discouraged'}",
}


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def js_for(name: str) -> str:
    selection = PRESETS[name]
    ext = "extensions: {credProps: true}," if name == "credprops" else ""
    return """
(async () => {
  const t0 = Date.now();
  try {
    const cred = await navigator.credentials.create({publicKey: {
      challenge: new Uint8Array(32).fill(7),
      rp: {id: 'localhost', name: 'spike'},
      user: {id: new Uint8Array(16).fill(3), name: 'spike', displayName: 'spike'},
      pubKeyCredParams: [{type: 'public-key', alg: -7}],
      timeout: 8000,
      %s,
      %s
      attestation: 'none'
    }});
    return 'OK ' + (Date.now() - t0) + 'ms';
  } catch (e) {
    return 'ERR(' + (Date.now() - t0) + 'ms) ' + e.name + ':' + e.message;
  }
})()
""" % (selection, ext)


def run_preset(name: str) -> str:
    cdp_port = free_port()
    page_port = free_port()
    profile = "/var/tmp/cp-%s-%d" % (name, int(time.time()))
    log = "/var/tmp/cp-%s.log" % name
    log_file = open(log, "w", encoding="utf-8")
    proc = subprocess.Popen(
        [
            BIN, "--headless=new",
            f"--remote-debugging-port={cdp_port}",
            f"--user-data-dir={profile}",
            "--no-first-run", "--no-default-browser-check",
            "--enable-logging=stderr", "--vmodule=device/fido/*=3",
            "about:blank",
        ],
        stdout=log_file, stderr=log_file,
    )
    httpd = socketserver.TCPServer(("127.0.0.1", page_port),
                                   functools.partial(http.server.SimpleHTTPRequestHandler, directory=SITE))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        for _ in range(60):
            time.sleep(0.4)
            try:
                urllib.request.urlopen("http://127.0.0.1:%d/json/version" % cdp_port, timeout=2).read()
                break
            except Exception:  # noqa: BLE001
                continue
        req = urllib.request.Request(
            "http://127.0.0.1:%d/json/new?http://localhost:%d/" % (cdp_port, page_port), method="PUT")
        page = json.load(urllib.request.urlopen(req, timeout=10))
        with ws_client.connect(page["webSocketDebuggerUrl"], max_size=None) as ws:
            ws.send(json.dumps({"id": 1, "method": "Runtime.enable"}))
            time.sleep(2)
            ws.send(json.dumps({"id": 2, "method": "Runtime.evaluate",
                                "params": {"expression": js_for(name), "awaitPromise": True,
                                           "userGesture": True, "returnByValue": True}}))
            deadline = time.time() + 25
            while time.time() < deadline:
                try:
                    msg = json.loads(ws.recv(timeout=25))
                except TimeoutError:
                    return "HANG(no reply)"
                if msg.get("id") == 2:
                    return json.dumps(msg.get("result", {}), ensure_ascii=False)[:200]
            return "TIMEOUT"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
        log_file.close()
        httpd.shutdown()


def main() -> None:
    os.makedirs(SITE, exist_ok=True)
    with open(os.path.join(SITE, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(PAGE)
    names = sys.argv[1:] or list(PRESETS)
    for name in names:
        print("%-10s -> %s" % (name, run_preset(name)), flush=True)


if __name__ == "__main__":
    main()
