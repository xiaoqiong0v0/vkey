package api

import (
	htmltemplate "html/template"
	"net/http"
	"strings"
	texttemplate "text/template"
)

// pageData 是 HTML 页面与引导脚本的渲染数据。
type pageData struct {
	Status          string
	Version         string
	Items           int64
	Devices         int64
	RequireMasterPW bool
	ServerURL       string
	Domain          string
}

// indexTemplate 是自检页（纯展示，无任何解密逻辑）。
var indexTemplate = htmltemplate.Must(htmltemplate.New("index").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>vkey 服务端自检</title>
<style>
:root{color-scheme:light dark}
body{font:16px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;margin:0;padding:2.5rem 1.25rem;background:#0f1115;color:#e8eaed}
main{max-width:38rem;margin:0 auto}
h1{font-size:1.4rem;margin:0 0 1.25rem}
dl{display:grid;grid-template-columns:max-content 1fr;gap:.55rem 1.25rem;margin:0}
dt{color:#9aa0a6}
dd{margin:0;font-variant-numeric:tabular-nums}
.ok{color:#6ee7a8}
.muted{color:#9aa0a6;font-size:.9rem;margin-top:2rem}
code{background:#1b1f27;padding:.1rem .35rem;border-radius:.25rem;word-break:break-all}
</style>
</head>
<body>
<main>
<h1>vkey 服务端自检</h1>
<dl>
<dt>状态</dt><dd class="ok">{{.Status}}</dd>
<dt>版本</dt><dd>{{.Version}}</dd>
<dt>同步条目</dt><dd>{{.Items}}</dd>
<dt>已注册设备</dt><dd>{{.Devices}}</dd>
<dt>强制主密码</dt><dd>{{if .RequireMasterPW}}是{{else}}否{{end}}</dd>
<dt>服务器地址</dt><dd><code>{{.ServerURL}}</code></dd>
</dl>
<p class="muted">本页面仅展示服务端状态，不做任何解密、不保存主密码、不生成验证码。<br>
Linux 安装：<code>curl -fsSL {{.ServerURL}}/install.sh | sh</code></p>
</main>
</body>
</html>
`))

// pairPageTemplate 是配对页（只提供提示与 APK 下载占位，不接触密文）。
var pairPageTemplate = htmltemplate.Must(htmltemplate.New("pair").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>vkey 设备配对</title>
<style>
:root{color-scheme:light dark}
body{font:16px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;margin:0;padding:2.5rem 1.25rem;background:#0f1115;color:#e8eaed}
main{max-width:34rem;margin:0 auto}
h1{font-size:1.4rem;margin:0 0 1rem}
p{color:#c3c7cc}
input{width:100%;box-sizing:border-box;margin:.75rem 0;padding:.7rem .8rem;border-radius:.5rem;border:1px solid #333a45;background:#171b22;color:inherit;font:inherit;letter-spacing:.12em;text-transform:uppercase}
.hint{color:#9aa0a6;font-size:.88rem}
a{color:#8ab4f8}
.box{border:1px solid #262b34;border-radius:.75rem;padding:1rem 1.1rem;margin:1.5rem 0}
code{background:#1b1f27;padding:.1rem .35rem;border-radius:.25rem;word-break:break-all}
</style>
</head>
<body>
<main>
<h1>vkey 设备配对</h1>
<p>在已登录的设备上生成配对码（有效期 10 分钟、仅可使用一次），然后在 vkey 客户端里输入完成绑定。</p>
<input type="text" inputmode="text" autocomplete="one-time-code" placeholder="XXXX-XXXX-XXXX-…" aria-label="配对码" readonly>
<p class="hint">出于安全考虑，配对只能在已安装的客户端内完成；本页面不接收、不转发配对码。</p>
<div class="box">
<strong>Android</strong>
<p class="hint">APK 下载占位：<a href="{{.ServerURL}}/dl/vkey-android.apk">vkey-android.apk</a>（M1 尚未发布产物）</p>
</div>
<div class="box">
<strong>Linux</strong>
<p class="hint"><code>curl -fsSL {{.ServerURL}}/install.sh | sh</code></p>
</div>
<p class="hint">服务器：<code>{{.ServerURL}}</code></p>
</main>
</body>
</html>
`))

// installSHTemplate 是 Linux 引导脚本模板（注入 server_url，探测架构）。
var installSHTemplate = texttemplate.Must(texttemplate.New("install.sh").Parse(`#!/usr/bin/env sh
# vkey 引导安装脚本（由 vkeyd 自动生成）
# 服务器：{{.ServerURL}}
set -eu

SERVER_URL="{{.ServerURL}}"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/vkey"
BIN_DIR="${HOME}/.local/bin"

case "$(uname -s)" in
  Linux) ;;
  *) echo "vkey: install.sh 仅支持 Linux" >&2; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "vkey: 不支持的架构 $(uname -m)" >&2; exit 1 ;;
esac

# 产物下载 URL 占位：M1 阶段尚未发布预构建产物（见 shared/protocol.md）。
ARTIFACT_URL="${SERVER_URL}/dl/vkey-hid-linux-${ARCH}.tar.gz"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

echo "vkey: 下载 ${ARTIFACT_URL}"
curl -fsSL "${ARTIFACT_URL}" -o "${TMP_DIR}/vkey-hid.tar.gz"
tar -xzf "${TMP_DIR}/vkey-hid.tar.gz" -C "${TMP_DIR}"

mkdir -p "${BIN_DIR}" "${CONFIG_DIR}" "${HOME}/.config/systemd/user"
install -m 0755 "${TMP_DIR}/vkey-hid" "${BIN_DIR}/vkey-hid"

if [ ! -f "${CONFIG_DIR}/config.toml" ]; then
  cat > "${CONFIG_DIR}/config.toml" <<EOF
server_url = "${SERVER_URL}"
device_id = ""
token = ""
EOF
  chmod 0600 "${CONFIG_DIR}/config.toml"
  echo "vkey: 已写入 ${CONFIG_DIR}/config.toml"
fi

cat > "${HOME}/.config/systemd/user/vkey-hid.service" <<EOF
[Unit]
Description=vkey virtual FIDO2 daemon
After=default.target

[Service]
ExecStart=%h/.local/bin/vkey-hid
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload || true
systemctl --user enable --now vkey-hid.service || true

echo "vkey: 安装完成。请在客户端中完成设备配对（${SERVER_URL}/pair）。"
`))

// installPS1Template 是 Windows 引导脚本模板。
var installPS1Template = texttemplate.Must(texttemplate.New("install.ps1").Parse(`# vkey 引导安装脚本（由 vkeyd 自动生成）
# 服务器：{{.ServerURL}}
$ErrorActionPreference = 'Stop'

$ServerUrl = "{{.ServerURL}}"

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
  'AMD64' { 'amd64' }
  'ARM64' { 'arm64' }
  default { throw "vkey: 不支持的架构 $env:PROCESSOR_ARCHITECTURE" }
}

# 产物下载 URL 占位：M1 阶段尚未发布预构建产物（见 shared/protocol.md）。
$artifactUrl = "$ServerUrl/dl/vkey-win-$arch.msi"
$tmpDir = Join-Path $env:TEMP ("vkey-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
$msi = Join-Path $tmpDir 'vkey-win.msi'

Write-Host "vkey: 下载 $artifactUrl"
Invoke-WebRequest -Uri $artifactUrl -OutFile $msi
Start-Process msiexec.exe -ArgumentList '/i', $msi, '/qn', '/norestart' -Wait

$configDir = Join-Path $env:APPDATA 'vkey'
New-Item -ItemType Directory -Path $configDir -Force | Out-Null
$configPath = Join-Path $configDir 'config.toml'
if (-not (Test-Path $configPath)) {
  @"
server_url = "$ServerUrl"
device_id = ""
token = ""
"@ | Set-Content -Path $configPath -Encoding utf8
  Write-Host "vkey: 已写入 $configPath"
}

Write-Host "vkey: 安装完成。请在客户端中完成设备配对（$ServerUrl/pair）。"
`))

// handleIndex 渲染自检页。
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	data := pageData{
		Status:    "ok",
		Version:   s.opts.Version,
		ServerURL: s.serverURL(r),
		Domain:    s.displayDomain(r),
	}
	items, devices, err := s.store.Counts(r.Context())
	if err != nil {
		s.logErr("统计失败", err)
		data.Status = "degraded"
	}
	data.Items, data.Devices = items, devices
	if u, err := s.firstUser(r.Context()); err == nil {
		data.RequireMasterPW = u.RequireMasterPW
	}
	writeHTML(w, indexTemplate, data)
}

// handlePairPage 渲染配对页。
func (s *Server) handlePairPage(w http.ResponseWriter, r *http.Request) {
	writeHTML(w, pairPageTemplate, pageData{
		ServerURL: s.serverURL(r),
		Domain:    s.displayDomain(r),
	})
}

// handleInstallSH 渲染 Linux 引导脚本。
func (s *Server) handleInstallSH(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Content-Disposition", `inline; filename="install.sh"`)
	data := pageData{ServerURL: s.serverURL(r), Domain: s.displayDomain(r)}
	if err := installSHTemplate.Execute(w, data); err != nil {
		s.logErr("渲染 install.sh 失败", err)
	}
}

// handleInstallPS1 渲染 Windows 引导脚本。
func (s *Server) handleInstallPS1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `inline; filename="install.ps1"`)
	data := pageData{ServerURL: s.serverURL(r), Domain: s.displayDomain(r)}
	if err := installPS1Template.Execute(w, data); err != nil {
		s.logErr("渲染 install.ps1 失败", err)
	}
}

// writeHTML 渲染 HTML 模板并写出。
func writeHTML(w http.ResponseWriter, t *htmltemplate.Template, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.WriteHeader(http.StatusOK)
	_ = t.Execute(w, data)
}

// serverURL 返回注入脚本/页面的服务器地址。
//
// 优先使用 --domain；否则由请求 Host + X-Forwarded-Proto 推导。所有取值都
// 经过字符白名单过滤，避免注入到 shell/PowerShell 脚本。
func (s *Server) serverURL(r *http.Request) string {
	if d := strings.TrimSpace(s.opts.Domain); d != "" {
		scheme := "https"
		if i := strings.Index(d, "://"); i >= 0 {
			if sc := strings.ToLower(d[:i]); sc == "http" || sc == "https" {
				scheme = sc
			}
			d = d[i+3:]
		}
		return scheme + "://" + sanitizeHost(d)
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + sanitizeHost(r.Host)
}

// displayDomain 返回页面展示用的域名（与 serverURL 同源）。
func (s *Server) displayDomain(r *http.Request) string {
	u := s.serverURL(r)
	if i := strings.Index(u, "://"); i >= 0 {
		return u[i+3:]
	}
	return u
}

// sanitizeHost 仅保留主机名/IP/端口允许的字符，异常时退回 localhost。
func sanitizeHost(h string) string {
	h = strings.TrimSpace(h)
	var sb strings.Builder
	for _, c := range h {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '-', c == ':', c == '[', c == ']':
			sb.WriteRune(c)
		}
	}
	out := sb.String()
	if out == "" || len(out) > 253 {
		return "localhost"
	}
	return out
}
