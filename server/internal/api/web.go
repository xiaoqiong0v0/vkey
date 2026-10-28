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
	// DeepLink 是 App 同步配置深链（vkey://config?server=…），仅含服务器地址。
	DeepLink string
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
.hint{color:#9aa0a6;font-size:.88rem}
.box{border:1px solid #262b34;border-radius:.75rem;padding:1rem 1.1rem;margin:1.75rem 0 0}
img.qr{display:block;width:200px;height:200px;margin:.9rem auto;padding:.5rem;border-radius:.5rem;background:#fff}
input.link{width:100%;box-sizing:border-box;margin:.4rem 0 0;padding:.55rem .7rem;border-radius:.5rem;border:1px solid #333a45;background:#171b22;color:inherit;font:inherit;font-size:.88rem}
pre.code{margin:.6rem 0 0;padding:.65rem .8rem;border-radius:.5rem;background:#1b1f27;overflow-x:auto}
pre.code code{background:none;padding:0;word-break:break-all}
code{background:#1b1f27;padding:.1rem .35rem;border-radius:.25rem;word-break:break-all}
a{color:#8ab4f8}
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
<div class="box">
<strong>手机配置</strong>
<p class="hint">扫码后 App 会自动填好地址，再输入配对码或主密钥即可完成同步配置。</p>
<img src="/pair/qr.png" width="200" height="200" alt="同步配置二维码" class="qr">
<label class="hint" for="deeplink">链接（可复制手动输入）：</label>
<input class="link" id="deeplink" type="text" readonly value="{{.DeepLink}}" aria-label="同步配置链接">
<p class="hint">二维码与链接里只有服务器地址，不含配对码、主密钥或任何凭据。</p>
</div>
<div class="box">
<strong>Android</strong>
<p class="hint">下载 APK：<a href="/dl/vkey-android.apk">下载 APK</a>（debug 签名，仅用于内测安装）</p>
</div>
<div class="box">
<strong>Linux</strong>
<p class="hint">一条命令安装（下载并校验二进制、配置 udev/tmpfiles 与 systemd user service）：</p>
<pre class="code"><code>bash -c "$(curl -fsSL {{.ServerURL}}/install.sh)"</code></pre>
</div>
<div class="box">
<strong>Windows</strong>
<p class="hint">暂未提供（后续版本发布 MSI 安装包）。</p>
</div>
<p class="muted">本页面仅展示服务端状态，不做任何解密、不保存主密码、不生成验证码。</p>
</main>
</body>
</html>
`))

// installSHTemplate 是 Linux 一键安装脚本模板（注入 server_url）。
//
// 脚本会下载并校验产物、安装二进制、交互输入凭据、配置 udev/tmpfiles 与
// systemd user service；所有 sudo 操作都可用 --no-sudo 跳过并打印待执行命令。
var installSHTemplate = texttemplate.Must(texttemplate.New("install.sh").Parse(`#!/usr/bin/env bash
# vkey Linux 一键安装脚本（由 vkeyd 生成，请勿手工编辑）
# 服务器：{{.ServerURL}}
# 推荐执行：bash -c "$(curl -fsSL {{.ServerURL}}/install.sh)"
set -euo pipefail

SERVER_URL="{{.ServerURL}}"
PREFIX="${HOME:-}/.local"
DO_SERVICE=1
DO_SUDO=1
ASSUME_YES=0
FORCE_LOGIN=0
MK="${VKEY_MASTER_KEY:-}"
CODE="${VKEY_CODE:-}"
# 数据目录：--data-dir / VKEY_DATA_DIR 显式指定时导出给所有 vkey-hid 调用；
# 未指定（DATA_DIR_SET=0）时沿用客户端默认。
DATA_DIR="${VKEY_DATA_DIR:-}"
DATA_DIR_SET=0
if [ -n "$DATA_DIR" ]; then
  DATA_DIR_SET=1
fi

log() { printf 'vkey: %s\n' "$*"; }
warn() { printf 'vkey: 警告：%s\n' "$*" >&2; }
die() { printf 'vkey: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
vkey Linux 安装脚本

用法：bash install.sh [选项]

  --master-key <k>  首次接入：master_key（base32）
  --code <配对码>   已有设备：一次性配对码
  --server <url>    覆盖脚本内置的服务器地址
  --prefix <dir>    安装前缀（默认 $HOME/.local）
  --data-dir <dir>  数据目录（默认沿用客户端：$XDG_DATA_HOME/vkey 或 ~/.local/share/vkey）
  --no-service      不安装/启用 systemd user service
  --no-sudo         跳过系统集成（udev/tmpfiles/uhid 组），只打印待执行命令
  --force-login     已有本地身份时也重新登录/配对（旧身份指向其它服务器时必选，否则退出）
  --yes             跳过交互确认（含 sudo 与旧身份询问；旧身份指向其它服务器时直接退出）
  -h, --help        显示本帮助

环境变量：VKEY_MASTER_KEY、VKEY_CODE、VKEY_DATA_DIR（与对应参数等价）。
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --master-key)
      [ $# -ge 2 ] || die "--master-key 缺少值"
      MK="$2"; shift 2 ;;
    --code)
      [ $# -ge 2 ] || die "--code 缺少值"
      CODE="$2"; shift 2 ;;
    --server)
      [ $# -ge 2 ] || die "--server 缺少值"
      SERVER_URL="$2"; shift 2 ;;
    --prefix)
      [ $# -ge 2 ] || die "--prefix 缺少值"
      PREFIX="$2"; shift 2 ;;
    --data-dir)
      [ $# -ge 2 ] || die "--data-dir 缺少值"
      DATA_DIR="$2"; DATA_DIR_SET=1; shift 2 ;;
    --no-service) DO_SERVICE=0; shift ;;
    --no-sudo) DO_SUDO=0; shift ;;
    --force-login) FORCE_LOGIN=1; shift ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "未知参数 $1（--help 查看用法）" ;;
  esac
done

SERVER_URL="${SERVER_URL%/}"
PREFIX="${PREFIX%/}"
[ -n "$SERVER_URL" ] || die "服务器地址为空；请用 --server 指定"
[ -n "$PREFIX" ] || die "安装前缀为空"
[ -n "${HOME:-}" ] || die "HOME 未设置"

BIN="$PREFIX/bin/vkey-hid"
SHARE_DIR="$PREFIX/share/vkey"
CURRENT_USER="${USER:-$(id -un)}"
# 未显式指定数据目录时按客户端默认推导（仅用于身份检测与展示，不导出）。
if [ "$DATA_DIR_SET" = 0 ]; then
  if [ -n "${XDG_DATA_HOME:-}" ]; then
    DATA_DIR="$XDG_DATA_HOME/vkey"
  else
    DATA_DIR="$HOME/.local/share/vkey"
  fi
fi
if [ "$DATA_DIR_SET" = 1 ]; then
  export VKEY_DATA_DIR="$DATA_DIR"
fi

# identity_field <字段名>：用 POSIX 工具从 identity.json 取第一个字符串字段（不依赖 jq）。
# server_url 字段的等价写法：
#   sed -n 's/.*"server_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$DATA_DIR/identity.json"
identity_field() {
  sed -n 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$DATA_DIR/identity.json" 2>/dev/null | head -n 1 || true
}

print_sudo_commands() {
  cat <<EOF
系统集成未执行。请手动执行（需要 root）：
  sudo install -m644 $SHARE_DIR/99-vkey-uhid.rules /etc/udev/rules.d/99-vkey-uhid.rules
  sudo install -m644 $SHARE_DIR/vkey-uhid.conf /etc/tmpfiles.d/vkey-uhid.conf
  sudo systemd-tmpfiles --create /etc/tmpfiles.d/vkey-uhid.conf
  sudo groupadd -f uhid
  sudo usermod -aG uhid "$CURRENT_USER"
  sudo udevadm control --reload-rules && sudo udevadm trigger
  sudo loginctl enable-linger "$CURRENT_USER"   # 让 user service 在未登录时也常驻
EOF
}

# ensure_sudo_ready 在下载/登录等任何写入之前确认 sudo 可用。
#
# 判定顺序：免密/已有票据（sudo -n）→ 已配置可执行的 SUDO_ASKPASS（sudo -A）→ 有 TTY 时交互取密码（sudo -v）。
# 三者都不满足时立即退出，避免「已下载/已登录但系统集成未装」的半装状态；
# 退出时不做任何写入（不下载、不 login）。
ensure_sudo_ready() {
  if [ "$DO_SUDO" = 0 ]; then
    return 0
  fi
  if command -v sudo >/dev/null 2>&1; then
    if sudo -n true 2>/dev/null; then
      return 0
    fi
    # 无 TTY（CI/远程管道）但已配置 askpass 时，用 sudo -A 走 askpass 取密码。
    if [ -n "${SUDO_ASKPASS:-}" ] && [ -x "${SUDO_ASKPASS}" ]; then
      log "检测到 SUDO_ASKPASS=$SUDO_ASKPASS，尝试通过 askpass 获取 sudo 权限"
      if sudo -A -v 2>/dev/null; then
        return 0
      fi
    fi
    if [ -t 0 ]; then
      log "配置 udev/tmpfiles/uhid 组需要 sudo 权限，请输入密码"
      if sudo -v; then
        return 0
      fi
    fi
  fi
  warn "无法获得 sudo 权限（未免密，没有可交互的终端，也未配置可用的 SUDO_ASKPASS）。"
  warn "已在下载/登录之前退出，未做任何写入（不会留下半装状态）。"
  cat >&2 <<EOF
请任选其一重试：

  1) 跳过系统集成，只安装二进制并登录（之后逐条手动补全命令）：
     bash install.sh --no-sudo
     后置手动命令：
EOF
  print_sudo_commands >&2
  cat >&2 <<EOF

  2) 保留终端重跑，让 sudo 能当场交互读取密码：
     bash -c "\$(curl -fsSL $SERVER_URL/install.sh)"

  3) 无终端场景（CI/自动部署）改用 askpass 提供密码：
     SUDO_ASKPASS=/path/to/askpass.sh bash -c "\$(curl -fsSL $SERVER_URL/install.sh)"
     （askpass.sh 需可执行，打印密码到 stdout；sudo 以 sudo -A 调用）
EOF
  exit 1
}

[ "$(uname -s)" = "Linux" ] || die "install.sh 仅支持 Linux（当前 $(uname -s)）"
case "$(uname -m)" in
  x86_64|amd64) ARCH="x86_64" ;;
  aarch64|arm64) ARCH="aarch64" ;;
  *) die "不支持的架构 $(uname -m)；当前仅提供 x86_64、aarch64 产物" ;;
esac

# sudo 前置检查：必须在下载/登录之前完成，失败即退出且不做任何写入。
ensure_sudo_ready

# 身份检查：同样必须在下载之前（问答失败就不该消耗流量），且在 sudo 前置检查之后。
# EXISTING   = $DATA_DIR/identity.json 存在
# SAME_SERVER = 其中 server_url 与本次目标一致（解析不到按「不一致」处理，
#               避免把早前测试留下的身份当成生产身份而静默跳过 login）
NEED_LOGIN=1
LOGIN_STATE="已完成"
IDENTITY_SERVER=""
IDENTITY_DEVICE=""
IDENTITY_ASKED=0
if [ -f "$DATA_DIR/identity.json" ]; then
  IDENTITY_SERVER="$(identity_field server_url)"
  IDENTITY_DEVICE="$(identity_field device_name)"
fi

# 旧身份处理矩阵：
#   同 server  + TTY + 未 --yes          → 询问「是否重新认证？[y/N]」（默认保留）
#   同 server  + 非 TTY 或 --yes          → 跳过 login，保留旧身份（日志说明原因）
#   不同 server + TTY + 未 --yes          → 询问「是否重新认证并切换？」（默认是），答否即退出 1
#   不同 server + 非 TTY 或 --yes         → 退出 1 并给出三种解法
# 所有 read 都在 [ -t 0 ] 之内：非 TTY 绝不读取，避免 EOF 被当成「答否」。
if [ -f "$DATA_DIR/identity.json" ] && [ "$FORCE_LOGIN" = 0 ]; then
  if [ "$IDENTITY_SERVER" = "$SERVER_URL" ]; then
    if [ -t 0 ] && [ "$ASSUME_YES" -eq 0 ]; then
      printf 'vkey: 检测到已存在的本地身份（server=%s%s）\n' \
        "$IDENTITY_SERVER" "${IDENTITY_DEVICE:+, device=$IDENTITY_DEVICE}" >&2
      printf '是否重新认证？[y/N] ' >&2
      read -r REPLY || REPLY=""
      IDENTITY_ASKED=1
      case "$REPLY" in
        y|Y|yes|YES) FORCE_LOGIN=1 ;;
      esac
    fi
    if [ "$FORCE_LOGIN" = 1 ]; then
      log "将重新认证，旧身份（$DATA_DIR/identity.json）会被覆盖"
    else
      NEED_LOGIN=0
      LOGIN_STATE="已存在本地身份（跳过 login）"
      # 说明跳过原因：交互确认过 / 非 TTY / --yes，三者行为一致但原因不同。
      if [ "$IDENTITY_ASKED" = 1 ]; then
        IDENTITY_SKIP_REASON="已在提示中确认保留旧身份"
      elif [ ! -t 0 ]; then
        IDENTITY_SKIP_REASON="stdin 不是终端，无法交互确认"
      else
        IDENTITY_SKIP_REASON="已指定 --yes"
      fi
      log "保留旧身份（server=$IDENTITY_SERVER），跳过 login（$IDENTITY_SKIP_REASON；--force-login 可重新认证）"
    fi
  else
    if [ -t 0 ] && [ "$ASSUME_YES" -eq 0 ]; then
      printf 'vkey: ⚠ 检测到旧身份指向 %s，与目标 %s 不一致\n' \
        "${IDENTITY_SERVER:-未知（无法解析）}" "$SERVER_URL" >&2
      printf '是否重新认证并切换到 %s？[Y/n] ' "$SERVER_URL" >&2
      read -r REPLY || REPLY=""
      case "$REPLY" in
        n|N|no|NO)
          die "已取消：保留 $DATA_DIR 中的旧身份（指向 ${IDENTITY_SERVER:-未知（无法解析）}）。
如需保留旧身份而不重新认证，请改用 --data-dir 另置数据目录，或清理 $DATA_DIR 后重跑。" ;;
        *)
          FORCE_LOGIN=1
          log "将重新认证并切换到 $SERVER_URL" ;;
      esac
    else
      if [ -t 0 ]; then
        NO_TTY_HINT="已指定 --yes"
      else
        NO_TTY_HINT="stdin 不是终端，无法交互确认"
      fi
      die "检测到旧身份指向 ${IDENTITY_SERVER:-未知（无法解析）}，与目标 $SERVER_URL 不一致（$NO_TTY_HINT）。请任选其一：
  1) 重新认证并切换：bash install.sh --force-login
  2) 清理旧身份后重装：rm -rf $DATA_DIR
  3) 另置数据目录：bash install.sh --data-dir <dir>"
    fi
  fi
fi

FETCH=""
if command -v curl >/dev/null 2>&1; then
  FETCH="curl"
elif command -v wget >/dev/null 2>&1; then
  FETCH="wget"
fi
[ -n "$FETCH" ] || die "缺少下载工具 curl 或 wget。安装提示：Debian/Ubuntu 执行 sudo apt-get install -y curl tar；Fedora 执行 sudo dnf install -y curl tar"
command -v tar >/dev/null 2>&1 || die "缺少 tar。安装提示：Debian/Ubuntu 执行 sudo apt-get install -y tar；Fedora 执行 sudo dnf install -y tar"
command -v install >/dev/null 2>&1 || die "缺少 install（coreutils）"
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1 && ! command -v openssl >/dev/null 2>&1; then
  die "缺少 sha256 校验工具（sha256sum / shasum / openssl）。安装提示：安装 coreutils 或 openssl"
fi

fetch() {
  if [ "$FETCH" = "curl" ]; then
    curl -fsSL "$1" -o "$2"
  else
    wget -q -O "$2" "$1"
  fi
}

normalize_hash() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    normalize_hash "$(sha256sum "$1" | cut -d' ' -f1)"
  elif command -v shasum >/dev/null 2>&1; then
    normalize_hash "$(shasum -a 256 "$1" | cut -d' ' -f1)"
  else
    normalize_hash "$(openssl dgst -sha256 "$1" | awk '{print $NF}')"
  fi
}

TMP_DIR="$(mktemp -d)" || die "无法创建临时目录"
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

ARTIFACT="vkey-hid-linux-${ARCH}.tar.gz"
log "服务器：$SERVER_URL"
log "下载清单 $SERVER_URL/dl/SHA256SUMS"
fetch "$SERVER_URL/dl/SHA256SUMS" "$TMP_DIR/SHA256SUMS" || die "下载 SHA256SUMS 失败（服务器不可用？）"
log "下载产物 $SERVER_URL/dl/$ARTIFACT"
fetch "$SERVER_URL/dl/$ARTIFACT" "$TMP_DIR/$ARTIFACT" || die "下载 $ARTIFACT 失败（该架构可能尚未发布产物）"

EXPECTED=""
while read -r HASH NAME REST; do
  NAME="${NAME#\*}"
  if [ "$NAME" = "$ARTIFACT" ]; then
    EXPECTED="$(normalize_hash "$HASH")"
    break
  fi
done < "$TMP_DIR/SHA256SUMS"
[ -n "$EXPECTED" ] || die "SHA256SUMS 中没有 $ARTIFACT"
ACTUAL="$(sha256_of "$TMP_DIR/$ARTIFACT")"
if [ "$ACTUAL" != "$EXPECTED" ]; then
  die "sha256 校验失败：期望 $EXPECTED，实际 $ACTUAL（未覆盖任何已安装文件）"
fi
log "sha256 校验通过"

mkdir -p "$TMP_DIR/extract"
tar -xzf "$TMP_DIR/$ARTIFACT" -C "$TMP_DIR/extract" || die "解包失败：$ARTIFACT"
for f in vkey-hid 99-vkey-uhid.rules vkey-hid.service; do
  [ -f "$TMP_DIR/extract/$f" ] || die "产物缺少 $f"
done

mkdir -p "$PREFIX/bin" "$SHARE_DIR"
# 原子替换：先装到同目录临时名再 mv，正在运行的旧二进制不会导致 ETXTBSY。
install -m 0755 "$TMP_DIR/extract/vkey-hid" "$BIN.new"
mv -f "$BIN.new" "$BIN"
install -m 0644 "$TMP_DIR/extract/99-vkey-uhid.rules" "$SHARE_DIR/99-vkey-uhid.rules"
install -m 0644 "$TMP_DIR/extract/vkey-hid.service" "$SHARE_DIR/vkey-hid.service"
printf 'z /dev/uhid 0660 root uhid -\n' > "$SHARE_DIR/vkey-uhid.conf"
chmod 0644 "$SHARE_DIR/vkey-uhid.conf"
log "已安装二进制 $BIN"

# 旧身份判定已在下载之前完成（见上），这里只沿用其结果 NEED_LOGIN / LOGIN_STATE。

# 读取敏感输入：不回显、不写入任何文件；脚本本身退出后即失效。
read_secret() {
  VALUE=""
  printf '%s' "$1" >&2
  if ! read -rs VALUE; then
    stty -echo 2>/dev/null || true
    read -r VALUE || true
    stty echo 2>/dev/null || true
  fi
  printf '\n' >&2
  printf '%s' "$VALUE"
}

if [ "$NEED_LOGIN" = 1 ]; then
  if [ -n "$MK" ] && [ -n "$CODE" ]; then
    die "只能指定 --master-key 或 --code 其中一种"
  fi
  if [ -z "$MK" ] && [ -z "$CODE" ]; then
    if [ ! -t 0 ]; then
      die "stdin 不是终端，无法交互输入凭据。请改用：bash -c \"\$(curl -fsSL $SERVER_URL/install.sh)\"，或显式传 --master-key/--code"
    fi
    printf '请选择接入方式：\n  1) 输入 master_key（首次接入）\n  2) 输入配对码（已有设备）\n> ' >&2
    read -r CHOICE || die "读取选择失败"
    case "$CHOICE" in
      1) MK="$(read_secret 'master_key: ')" ;;
      2) CODE="$(read_secret '配对码: ')" ;;
      *) die "无效选择：$CHOICE" ;;
    esac
  fi
  [ -n "$MK$CODE" ] || die "未提供凭据"
  log "向 $SERVER_URL 接入设备"
  if [ -n "$MK" ]; then
    if ! "$BIN" login --server "$SERVER_URL" --master-key "$MK"; then
      die "login 失败：请检查 master_key 与服务器地址"
    fi
    MK=""
  else
    set -- pair --server "$SERVER_URL" --code "$CODE"
    if [ "$FORCE_LOGIN" = 1 ]; then
      set -- "$@" --force
    fi
    if ! "$BIN" "$@"; then
      die "pair 失败：请检查配对码是否有效、未过期且未被使用"
    fi
    CODE=""
  fi
else
  MK=""
  CODE=""
fi

# 结尾摘要用：login/pair 可能刚在本脚本中完成，重新读取 identity.json 得到最终身份。
FINAL_SERVER=""
FINAL_DEVICE=""
if [ -f "$DATA_DIR/identity.json" ]; then
  FINAL_SERVER="$(identity_field server_url)"
  FINAL_DEVICE="$(identity_field device_name)"
fi

install_system_integration() {
  if [ "$DO_SUDO" = 0 ]; then
    print_sudo_commands
    return 0
  fi
  if ! command -v sudo >/dev/null 2>&1; then
    warn "未找到 sudo，无法执行系统集成"
    print_sudo_commands
    return 1
  fi
  # 判定（sudo 前置检查 ensure_sudo_ready 已通过）：TTY 且未给 --yes ⇒ 询问；否则直接执行。
  # 无 TTY 场景（curl|bash 管道、SUDO_ASKPASS 自动部署、CI）绝不能进入 read：
  # 否则 read 立刻命中 EOF，会被当成「答否」，从而只打印命令而不真正安装系统集成。
  if [ -t 0 ] && [ "$ASSUME_YES" -eq 0 ]; then
    printf '将使用 sudo 配置 udev/tmpfiles 与 uhid 组，继续？[y/N] ' >&2
    read -r REPLY || REPLY=""
    case "$REPLY" in
      y|Y|yes|YES) ;;
      *) print_sudo_commands; return 0 ;;
    esac
  else
    log "非交互或已指定 --yes，直接执行系统集成（udev/tmpfiles/uhid 组）"
  fi
  # 逐条检查：任何一步失败都返回非零，由调用方统一输出「部分安装」总结。
  sudo install -m 0644 "$SHARE_DIR/99-vkey-uhid.rules" /etc/udev/rules.d/99-vkey-uhid.rules || return 1
  sudo install -m 0644 "$SHARE_DIR/vkey-uhid.conf" /etc/tmpfiles.d/vkey-uhid.conf || return 1
  sudo systemd-tmpfiles --create /etc/tmpfiles.d/vkey-uhid.conf || return 1
  sudo groupadd -f uhid || return 1
  sudo usermod -aG uhid "$CURRENT_USER" || return 1
  sudo udevadm control --reload-rules || return 1
  sudo udevadm trigger || return 1
  log "已配置 udev / tmpfiles / uhid 组"
  return 0
}

install_user_service() {
  if [ "$DO_SERVICE" = 0 ]; then
    log "按 --no-service 跳过 systemd user service"
    return 0
  fi
  UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
  mkdir -p "$UNIT_DIR"
  # 显式指定数据目录时，把 VKEY_DATA_DIR 也写进 unit，保证 daemon 与 login 用同一目录。
  if [ "$DATA_DIR_SET" = 1 ]; then
    DATA_DIR_ENV="Environment=VKEY_DATA_DIR=$DATA_DIR"
  else
    DATA_DIR_ENV=""
  fi
  cat > "$UNIT_DIR/vkey-hid.service" <<EOF
[Unit]
Description=vkey FIDO2 虚拟安全密钥（uhid + 零知识同步）
After=graphical-session.target
PartOf=graphical-session.target

[Service]
Type=simple
ExecStart="$PREFIX/bin/vkey-hid" run
$DATA_DIR_ENV
Restart=on-failure
RestartSec=3
TimeoutStopSec=10
Environment=RUST_BACKTRACE=1

[Install]
WantedBy=default.target
EOF
  chmod 0644 "$UNIT_DIR/vkey-hid.service"
  SERVICE_OK=1
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl --user daemon-reload && systemctl --user enable --now vkey-hid; then
      log "已启用 systemd user service：vkey-hid"
    else
      warn "systemctl --user 操作失败（可能没有用户 systemd 会话）。登录图形会话后执行：systemctl --user daemon-reload && systemctl --user enable --now vkey-hid"
      SERVICE_OK=0
    fi
  else
    warn "未找到 systemctl；请稍后手动启用 $UNIT_DIR/vkey-hid.service"
    SERVICE_OK=0
  fi
  if [ "$DO_SUDO" = 1 ] && command -v sudo >/dev/null 2>&1; then
    sudo loginctl enable-linger "$CURRENT_USER" || warn "loginctl enable-linger 失败（不影响安装）"
  fi
  [ "$SERVICE_OK" = 1 ]
}

PARTIAL=0
SUDO_STATE="已完成"
if ! install_system_integration; then
  SUDO_STATE="失败"
  PARTIAL=1
elif [ "$DO_SUDO" = 0 ]; then
  SUDO_STATE="未执行（--no-sudo）"
fi

SERVICE_STATE="已启用"
if ! install_user_service; then
  SERVICE_STATE="失败"
  PARTIAL=1
elif [ "$DO_SERVICE" = 0 ]; then
  SERVICE_STATE="未安装（--no-service）"
fi

if [ "$PARTIAL" = 1 ]; then
  cat >&2 <<EOF

vkey 部分安装：部分步骤未完成，安装尚未完全生效
  服务器:    $SERVER_URL
  二进制:    $BIN
  数据目录:  $DATA_DIR
  本地身份:  ${FINAL_SERVER:-未检测到}${FINAL_DEVICE:+（device=$FINAL_DEVICE）}
  登录:      $LOGIN_STATE

已完成：
  - 下载、校验、安装二进制
  - 账号接入：$LOGIN_STATE

未完成：
  - 系统集成（udev/tmpfiles/uhid 组）：$SUDO_STATE
  - systemd user service：$SERVICE_STATE

请逐条手动补全（需要 root 的命令用 sudo）：
EOF
  print_sudo_commands >&2
  cat >&2 <<EOF
  systemctl --user daemon-reload && systemctl --user enable --now vkey-hid
  重新登录一次后确认：ls -l /dev/uhid

排障：
  systemctl --user status vkey-hid
  journalctl --user -u vkey-hid -n 50 --no-pager
  $BIN status
EOF
  exit 1
fi

if [ "$DO_SERVICE" = 1 ]; then
  SERVICE_STATE="$(systemctl --user is-active vkey-hid 2>/dev/null || printf 'unknown')"
fi

case ":$PATH:" in
  *":$PREFIX/bin:"*) ;;
  *) printf '提示：%s 不在 PATH 中，可加入 shell 配置。\n' "$PREFIX/bin" ;;
esac

cat <<EOF

vkey 安装完成
  服务器:    $SERVER_URL
  二进制:    $BIN
  数据目录:  $DATA_DIR
  本地身份:  ${FINAL_SERVER:-未检测到}${FINAL_DEVICE:+（device=$FINAL_DEVICE）}
  用户服务:  $SERVICE_STATE

重要：需要重新登录一次（组生效）后 daemon 才能打开 /dev/uhid。
      首次安装请注销并重新登录（或重启），然后确认：ls -l /dev/uhid

排障：
  systemctl --user status vkey-hid
  journalctl --user -u vkey-hid -n 50 --no-pager
  $BIN status
EOF
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

// handleIndex 渲染自检页（含同步配置二维码与可复制深链）。
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	serverURL := s.serverURL(r)
	data := pageData{
		Status:    "ok",
		Version:   s.opts.Version,
		ServerURL: serverURL,
		Domain:    s.displayDomain(r),
		DeepLink:  pairDeepLink(serverURL),
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

// handlePairRedirect 把旧配对页 /pair 永久重定向到主页（保留路由，老链接不 404）。
func (s *Server) handlePairRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", http.StatusMovedPermanently)
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
	// img-src 'self' 供主页引用同源二维码（/pair/qr.png）；仍禁止外部资源与内联脚本。
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
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
