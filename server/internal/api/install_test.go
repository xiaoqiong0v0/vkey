package api_test

import (
	"net/http"
	"strings"
	"testing"
)

// TestInstallSHRender 静态校验 /install.sh 的渲染结果。
//
// 本机不是 Linux，因此这里只做字符串/结构断言（不调用 bash 做语法检查）；
// 真正的语法与运行验证由 Linux 侧验收任务负责。
func TestInstallSHRender(t *testing.T) {
	e := newEnv(t)
	resp := e.getNoAuth("/install.sh")
	requireStatus(t, resp, http.StatusOK)
	script := string(resp.body)

	wants := []string{
		// 注入的服务器地址与执行方式
		`SERVER_URL="https://vkey.test"`,
		"bash -c \"$(curl -fsSL",
		"#!/usr/bin/env bash",
		// 严格模式与架构探测
		"set -euo pipefail",
		"uname -m",
		`x86_64|amd64`,
		`aarch64|arm64`,
		"不支持的架构",
		// 依赖检查
		"command -v curl",
		"command -v wget",
		"command -v tar",
		// 产物下载与校验
		"vkey-hid-linux-${ARCH}.tar.gz",
		"/dl/SHA256SUMS",
		"sha256",
		"未覆盖任何已安装文件",
		// 参数与环境
		"--master-key",
		"--code",
		"--server",
		"--prefix",
		"--data-dir",
		"--no-service",
		"--no-sudo",
		"--force-login",
		"--yes",
		"VKEY_MASTER_KEY",
		"VKEY_CODE",
		"VKEY_DATA_DIR",
		// sudo 前置检查与半装（部分安装）提示
		"sudo -n true",
		"sudo -v",
		// 无 TTY 但已配置 askpass 的场景
		"SUDO_ASKPASS",
		"sudo -A",
		"部分安装",
		// 凭据输入
		"[ -t 0 ]",
		"read -rs",
		"identity.json",
		`login --server "$SERVER_URL" --master-key "$MK"`,
		`pair --server "$SERVER_URL" --code "$CODE"`,
		// 系统集成
		"/etc/tmpfiles.d/vkey-uhid.conf",
		"z /dev/uhid 0660 root uhid -",
		"systemd-tmpfiles --create",
		"groupadd -f uhid",
		`usermod -aG uhid`,
		"udevadm control --reload-rules",
		"udevadm trigger",
		// 用户服务（默认落在 ~/.config/systemd/user/vkey-hid.service）
		`UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"`,
		`"$UNIT_DIR/vkey-hid.service"`,
		`$PREFIX/bin/vkey-hid`,
		"systemctl --user enable --now vkey-hid",
		"loginctl enable-linger",
		// 结尾提示
		"需要重新登录一次",
	}
	for _, want := range wants {
		if !strings.Contains(script, want) {
			t.Fatalf("install.sh 缺少内容 %q", want)
		}
	}

	// 不允许残留占位/待办标记。
	for _, bad := range []string{"TODO", "FIXME", "<artifact>", "下载产物占位"} {
		if strings.Contains(script, bad) {
			t.Fatalf("install.sh 不应包含占位标记 %q", bad)
		}
	}

	// sudo 前置检查必须出现在 login 调用之前：否则会先写入身份、再因 sudo 失败留下半装状态。
	sudoIdx := strings.Index(script, "sudo -n true")
	loginIdx := strings.Index(script, `login --server "$SERVER_URL" --master-key "$MK"`)
	if sudoIdx < 0 || loginIdx < 0 {
		t.Fatalf("install.sh 缺少 sudo 前置检查或 login 调用（sudo=%d login=%d）", sudoIdx, loginIdx)
	}
	if sudoIdx > loginIdx {
		t.Fatalf("sudo 前置检查应位于 login 之前（sudo=%d login=%d）", sudoIdx, loginIdx)
	}

	// SUDO_ASKPASS 分支同属 sudo 前置检查，也必须在 login 之前，否则仍会留下半装状态。
	askpassIdx := strings.Index(script, "sudo -A")
	if askpassIdx < 0 {
		t.Fatalf("install.sh 缺少 SUDO_ASKPASS 分支（sudo -A）")
	}
	if askpassIdx > loginIdx {
		t.Fatalf("SUDO_ASKPASS 分支应位于 login 之前（askpass=%d login=%d）", askpassIdx, loginIdx)
	}

	// 系统集成段：只有在「有 TTY 且未给 --yes」时才询问，否则直接执行。
	// 若把询问放在无 TTY 场景下，read 会立刻 EOF 被当成「答否」，
	// 结果只打印待执行命令而不真正安装 udev/tmpfiles/组（SUDO_ASKPASS 部署常见坑）。
	gate := `if [ -t 0 ] && [ "$ASSUME_YES" -eq 0 ]; then`
	gateIdx := strings.Index(script, gate)
	if gateIdx < 0 {
		t.Fatalf("系统集成段缺少「TTY 且未 --yes 才询问」的判定 %q", gate)
	}
	replyIdx := strings.Index(script, "read -r REPLY")
	if replyIdx < 0 || replyIdx < gateIdx {
		t.Fatalf("「继续？[y/N]」的 read 必须位于 TTY 判定之内（gate=%d read=%d）", gateIdx, replyIdx)
	}
	// 系统集成的实际写入步骤必须在询问块之后，保证无 TTY 时一定会执行。
	integrationIdx := strings.Index(script, `sudo install -m 0644 "$SHARE_DIR/99-vkey-uhid.rules"`)
	if integrationIdx < 0 || integrationIdx < replyIdx {
		t.Fatalf("系统集成应无条件执行（read=%d integration=%d）", replyIdx, integrationIdx)
	}
	// --yes 的默认值与解析必须存在，否则上面的判定永远走询问分支。
	if !strings.Contains(script, "ASSUME_YES=0") || !strings.Contains(script, "ASSUME_YES=1") {
		t.Fatalf("install.sh 缺少 ASSUME_YES 的默认值或 --yes 解析")
	}

	// 用户服务安装段（含 --no-service 分支）不应有交互读取，避免同类 EOF 卡死。
	svcStart := strings.Index(script, "install_user_service() {")
	if svcStart < 0 {
		t.Fatalf("install.sh 缺少 install_user_service 函数")
	}
	svcEnd := strings.Index(script[svcStart:], "\n}\n")
	if svcEnd < 0 {
		t.Fatalf("install.sh 中 install_user_service 函数体未闭合")
	}
	svcBody := script[svcStart : svcStart+svcEnd]
	if strings.Contains(svcBody, "read -") {
		t.Fatalf("用户服务安装段不应包含交互读取（无 TTY 时会 EOF）")
	}

	// 关键结构：脚本必须自己渲染服务器地址，且不是被 Go 模板漏渲染的原样输出。
	if strings.Contains(script, "{{") || strings.Contains(script, "}}") {
		t.Fatalf("install.sh 存在未渲染的模板标记")
	}
}
