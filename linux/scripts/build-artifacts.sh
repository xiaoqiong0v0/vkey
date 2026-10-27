#!/usr/bin/env bash
# 构建 vkey Linux 客户端发布产物（在 Linux 上执行）。
#
# 产出（默认写入 <仓库根>/dist，可用 --dist-dir / VKEY_DIST_DIR 覆盖）：
#   <dist>/vkey-hid-linux-<arch>.tar.gz   内含 vkey-hid / 99-vkey-uhid.rules /
#                                         vkey-hid.service / README.install
#   <dist>/SHA256SUMS                     上述 tarball 的 sha256 清单（供 /dl 白名单）
#
# 用法：
#   linux/scripts/build-artifacts.sh          # x86_64 必须成功；aarch64 缺工具链时明确跳过
#   linux/scripts/build-artifacts.sh --help
#
# 说明：
#   - x86_64 先保证可用；aarch64 在本机无交叉工具链时打印「未构建」并继续（不静默）。
#   - 可重复执行：每次重建 staging 与 dist 中的同名产物。
#   - 本脚本不部署、不访问网络。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LINUX_DIR="$ROOT/linux"
# 产物目录：默认 <仓库根>/dist（= linux/../dist），可用 --dist-dir / VKEY_DIST_DIR 覆盖。
DIST_DIR="${VKEY_DIST_DIR:-$ROOT/dist}"
STAGE_ROOT="$ROOT/.tmp/scratch/build-artifacts"

log() { printf '==> %s\n' "$*"; }
warn() { printf '==> 警告：%s\n' "$*" >&2; }
die() { printf '==> 错误：%s\n' "$*" >&2; exit 1; }

usage() {
  cat <<USAGE
vkey Linux 产物构建

用法：linux/scripts/build-artifacts.sh [选项]

  --dist-dir <dir>  产物输出目录（默认 $ROOT/dist，也可用环境变量 VKEY_DIST_DIR）
  -h, --help        显示本帮助

产物目录（绝对路径）：$DIST_DIR
  vkey-hid-linux-x86_64.tar.gz
  vkey-hid-linux-aarch64.tar.gz   （本机缺少交叉工具链时跳过）
  SHA256SUMS
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dist-dir)
      [ $# -ge 2 ] || die "--dist-dir 缺少值"
      DIST_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "未知参数 $1（--help 查看用法）" ;;
  esac
done

# 统一为绝对路径，便于 --help/结尾展示与实际写入一致。
case "$DIST_DIR" in
  /*) ;;
  *) DIST_DIR="$(pwd)/$DIST_DIR" ;;
esac

command -v cargo >/dev/null 2>&1 || die "未找到 cargo；请先安装 Rust 工具链"
command -v tar >/dev/null 2>&1 || die "未找到 tar"

HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
  x86_64|amd64) HOST_ARCH="x86_64" ;;
  aarch64|arm64) HOST_ARCH="aarch64" ;;
  *) warn "未知主机架构 $HOST_ARCH，将只尝试交叉编译" ;;
esac

mkdir -p "$DIST_DIR" "$STAGE_ROOT"
STAGE=""
cleanup() {
  if [ -n "$STAGE" ]; then
    rm -rf "$STAGE"
  fi
  rm -rf "$STAGE_ROOT"
}
trap cleanup EXIT HUP INT TERM

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# target_triple 返回 cargo --target 使用的三元组。
target_triple() {
  case "$1" in
    x86_64) printf 'x86_64-unknown-linux-gnu' ;;
    aarch64) printf 'aarch64-unknown-linux-gnu' ;;
    *) return 1 ;;
  esac
}

# write_readme 生成 tarball 内的安装说明。
write_readme() {
  local arch="$1" out="$2"
  cat > "$out" <<EOF
vkey-hid Linux 客户端（${arch}）

安装（推荐，由服务端生成脚本）：
  bash -c "\$(curl -fsSL https://vkey.xiaoqiong0v0.cn/install.sh)"

本包内容：
  vkey-hid               客户端二进制（login/pair/run/status/sync/selftest）
  99-vkey-uhid.rules     udev 规则：放行 /dev/uhid 与虚拟 hidraw
  vkey-hid.service       systemd **user** unit（ExecStart 需按安装前缀修改）

手工安装要点：
  1) install -m755 vkey-hid ~/.local/bin/vkey-hid
  2) sudo install -m644 99-vkey-uhid.rules /etc/udev/rules.d/99-vkey-uhid.rules
  3) sudo groupadd -f uhid && sudo usermod -aG uhid "\$USER"（重新登录生效）
  4) 安装 vkey-hid.service 到 ~/.config/systemd/user/ 后
     systemctl --user daemon-reload && systemctl --user enable --now vkey-hid
  5) vkey-hid login --server <url> --master-key <base32>（或 pair --code <配对码>）
EOF
}

# build_arch 编译并打包单一架构；成功返回 0。
build_arch() {
  local arch="$1" triple bin stage out
  triple="$(target_triple "$arch")" || return 1
  log "构建 $arch（target=$triple）"

  if [ "$HOST_ARCH" = "$arch" ]; then
    cargo build --release --manifest-path "$LINUX_DIR/Cargo.toml"
    bin="$LINUX_DIR/target/release/vkey-hid"
  else
    if command -v rustup >/dev/null 2>&1; then
      if ! rustup target list --installed 2>/dev/null | grep -qx "$triple"; then
        warn "$triple 未安装（可执行 rustup target add $triple 并配置交叉链接器）"
        return 1
      fi
    fi
    cargo build --release --manifest-path "$LINUX_DIR/Cargo.toml" --target "$triple" || return 1
    bin="$LINUX_DIR/target/$triple/release/vkey-hid"
  fi

  [ -f "$bin" ] || { warn "未找到编译产物 $bin"; return 1; }

  stage="$STAGE_ROOT/$arch"
  rm -rf "$stage"
  mkdir -p "$stage"
  install -m 0755 "$bin" "$stage/vkey-hid"
  install -m 0644 "$LINUX_DIR/packaging/99-vkey-uhid.rules" "$stage/99-vkey-uhid.rules"
  install -m 0644 "$LINUX_DIR/packaging/vkey-hid.service" "$stage/vkey-hid.service"
  write_readme "$arch" "$stage/README.install"
  chmod 0644 "$stage/README.install"

  out="$DIST_DIR/vkey-hid-linux-$arch.tar.gz"
  rm -f "$out"
  ( cd "$stage" && tar -czf "$out" vkey-hid 99-vkey-uhid.rules vkey-hid.service README.install )
  log "已生成 $out"
  return 0
}

log "仓库根目录：$ROOT"
log "主机架构：$HOST_ARCH"

if ! build_arch x86_64; then
  die "x86_64 构建失败（这是必须产出的架构）"
fi

if ! build_arch aarch64; then
  warn "aarch64 未构建（本机缺少交叉工具链或目标；x86_64 产物不受影响）"
fi

log "生成 SHA256SUMS"
(
  cd "$DIST_DIR"
  : > SHA256SUMS.tmp
  found=0
  for f in vkey-hid-linux-*.tar.gz; do
    [ -f "$f" ] || continue
    # 必须写成单行 `hash  name`：服务端白名单解析与 install.sh 的
    # `while read -r HASH NAME` 都按 sha256sum 格式逐行读取。
    printf '%s  %s\n' "$(sha256_of "$f")" "$f" >> SHA256SUMS.tmp
    found=1
  done
  [ "$found" -eq 1 ] || { rm -f SHA256SUMS.tmp; die "dist 中没有可用的 tarball"; }
  mv SHA256SUMS.tmp SHA256SUMS
)

log "完成。产物目录（绝对路径）：$DIST_DIR"
ls -l "$DIST_DIR"
