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

// identityBlock 取出 install.sh 中「身份检查」到下载开始之间的脚本片段。
//
// 该片段的边界由脚本里的固定标记界定：起始注释与 `FETCH=""`（下载工具探测之前）。
func identityBlock(t *testing.T, script string) string {
	t.Helper()
	start := strings.Index(script, "# 身份检查：")
	end := strings.Index(script, `FETCH=""`)
	if start < 0 || end < 0 || end < start {
		t.Fatalf("install.sh 缺少身份检查段标记（start=%d end=%d）", start, end)
	}
	return script[start:end]
}

// assertNoBareRead 断言片段内所有 read 都位于 `if [ -t 0 ]` 判定之内。
//
// 非 TTY 场景下 read 会立刻命中 EOF 并被当成「答否」，因此身份询问必须整体受 TTY 保护。
func assertNoBareRead(t *testing.T, block string) {
	t.Helper()
	var guards []bool
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue // 注释里的 read 不算交互读取
		}
		switch {
		case strings.HasPrefix(trimmed, "if "):
			guards = append(guards, strings.Contains(trimmed, "[ -t 0 ]"))
		case trimmed == "fi" || strings.HasPrefix(trimmed, "fi "):
			if len(guards) > 0 {
				guards = guards[:len(guards)-1]
			}
		case strings.HasPrefix(trimmed, "read ") || strings.Contains(trimmed, " read "):
			guarded := false
			for _, g := range guards {
				if g {
					guarded = true
					break
				}
			}
			if !guarded {
				t.Fatalf("身份检查块中的 read 未受 [ -t 0 ] 保护：%q", trimmed)
			}
		}
	}
}

// TestInstallSHIdentityPrompt 静态校验「检测到旧身份」的提示、询问与退出分支。
//
// 背景：早前测试留下的 identity.json（指向 127.0.0.1）曾导致脚本静默跳过 login，
// 用户误以为已接入生产。这里锁定四条行为：
//  1. 同 server：提示身份并询问「是否重新认证？[y/N]」；
//  2. 不同 server：提示不一致并询问「是否重新认证并切换？（默认是）」；
//  3. 身份检查必须位于下载之前（省流量）；
//  4. 非 TTY 分支绝不 read。
func TestInstallSHIdentityPrompt(t *testing.T) {
	e := newEnv(t)
	resp := e.getNoAuth("/install.sh")
	requireStatus(t, resp, http.StatusOK)
	script := string(resp.body)

	// 文案：两条询问路径与提示内容。
	for _, want := range []string{
		"检测到已存在的本地身份",
		"是否重新认证？[y/N]",
		"检测到旧身份指向",
		"与目标",
		"是否重新认证并切换到",
		"[Y/n]",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("install.sh 缺少旧身份提示 %q", want)
		}
	}

	// server_url 解析：只用 POSIX sed（不依赖 jq），字段为 server_url。
	if !strings.Contains(script, "sed -n") || !strings.Contains(script, "identity_field server_url") {
		t.Fatalf("install.sh 缺少基于 sed 的 server_url 解析")
	}
	if strings.Contains(script, "| jq") || strings.Contains(script, "jq -r") {
		t.Fatalf("install.sh 不应依赖 jq")
	}
	// 解析不到（空串）按「不一致」处理：判定是字面相等比较，SERVER_URL 非空时空串必然不等。
	if !strings.Contains(script, `if [ "$IDENTITY_SERVER" = "$SERVER_URL" ]; then`) {
		t.Fatalf("install.sh 缺少 server_url 一致性判定")
	}

	// 顺序：sudo 前置检查 → 身份检查 → 下载。
	sudoIdx := strings.Index(script, "sudo -n true")
	identIdx := strings.Index(script, "# 身份检查：")
	downloadIdx := strings.Index(script, `log "下载清单`)
	if sudoIdx < 0 || identIdx < 0 || downloadIdx < 0 {
		t.Fatalf("install.sh 缺少 sudo/身份/下载 标记（sudo=%d ident=%d dl=%d）", sudoIdx, identIdx, downloadIdx)
	}
	if sudoIdx > identIdx {
		t.Fatalf("身份检查应在 sudo 前置检查之后（sudo=%d ident=%d）", sudoIdx, identIdx)
	}
	if identIdx > downloadIdx {
		t.Fatalf("身份检查应在下载之前（ident=%d dl=%d）", identIdx, downloadIdx)
	}

	block := identityBlock(t, script)
	assertNoBareRead(t, block)

	// 不同 server 且无法交互时退出，并给出三种解法。
	for _, want := range []string{"bash install.sh --force-login", "rm -rf $DATA_DIR", "--data-dir <dir>"} {
		if !strings.Contains(block, want) {
			t.Fatalf("install.sh 缺少「不同 server 且无法交互」的解法提示 %q", want)
		}
	}

	// 结尾摘要必须给出最终身份（server 与 device）。
	finalIdx := strings.Index(script, "本地身份:")
	if finalIdx < 0 {
		t.Fatalf("install.sh 结尾摘要缺少最终身份展示")
	}
	if !strings.Contains(script[finalIdx:], "FINAL_SERVER") || !strings.Contains(script[finalIdx:], "FINAL_DEVICE") {
		t.Fatalf("结尾摘要应打印最终身份 server 与 device")
	}
}
