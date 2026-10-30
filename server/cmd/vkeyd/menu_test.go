package main

import (
	"bufio"
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"xiaoqiong0v0.cn/vkey/server/internal/store"
)

// TestParseMenuChoice 验证主菜单编号解析：合法、空行、非数字、越界。
func TestParseMenuChoice(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want int
		ok   bool
	}{
		{name: "合法-0", raw: "0", want: 0, ok: true},
		{name: "合法-1", raw: "1", want: 1, ok: true},
		{name: "合法-最大", raw: "6", want: 6, ok: true},
		{name: "合法-带空白", raw: "  3 \r", want: 3, ok: true},
		{name: "空行", raw: "", ok: false},
		{name: "纯空白", raw: "   ", ok: false},
		{name: "非数字", raw: "abc", ok: false},
		{name: "混合", raw: "1x", ok: false},
		{name: "负数", raw: "-1", ok: false},
		{name: "超范围-1", raw: "7", ok: false},
		{name: "超范围-2", raw: "42", ok: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseMenuChoice(tc.raw)
			if ok != tc.ok {
				t.Fatalf("ok = %v，期望 %v（raw=%q）", ok, tc.ok, tc.raw)
			}
			if ok && got != tc.want {
				t.Fatalf("choice = %d，期望 %d", got, tc.want)
			}
			if !ok && got != 0 {
				t.Fatalf("非法输入应返回 0，实际 %d", got)
			}
		})
	}
}

// TestParseConfirm 验证危险操作确认：只接受 y / yes（忽略大小写与空白）。
func TestParseConfirm(t *testing.T) {
	tests := []struct {
		raw  string
		want bool
	}{
		{raw: "y", want: true},
		{raw: "Y", want: true},
		{raw: "yes", want: true},
		{raw: " YES ", want: true},
		{raw: "", want: false},
		{raw: "n", want: false},
		{raw: "no", want: false},
		{raw: "yep", want: false},
		{raw: "是", want: false},
	}
	for _, tc := range tests {
		if got := parseConfirm(tc.raw); got != tc.want {
			t.Fatalf("parseConfirm(%q) = %v，期望 %v", tc.raw, got, tc.want)
		}
	}
}

// TestResolveMenuEntry 验证 TTY 判定：只有终端才进入菜单。
func TestResolveMenuEntry(t *testing.T) {
	if got := resolveMenuEntry(true); got != menuModeInteractive {
		t.Fatalf("TTY 应进入菜单，实际 %v", got)
	}
	if got := resolveMenuEntry(false); got != menuModeUsage {
		t.Fatalf("非 TTY 应只打印 usage，实际 %v", got)
	}
}

// TestFormatBytes 验证目录大小格式化。
func TestFormatBytes(t *testing.T) {
	tests := []struct {
		n    int64
		want string
	}{
		{n: 0, want: "0 B"},
		{n: 512, want: "512 B"},
		{n: 1024, want: "1.0 KiB"},
		{n: 1 << 20, want: "1.0 MiB"},
		{n: 3<<20 + 512<<10, want: "3.5 MiB"},
	}
	for _, tc := range tests {
		if got := formatBytes(tc.n); got != tc.want {
			t.Fatalf("formatBytes(%d) = %q，期望 %q", tc.n, got, tc.want)
		}
	}
}

// newScriptedMenu 用脚本化输入驱动菜单循环（不依赖真实终端）。
func newScriptedMenu(t *testing.T, input string) (*menu, *bytes.Buffer) {
	t.Helper()
	m := &menu{
		dbPath: filepath.Join(t.TempDir(), "menu.db"),
		in:     bufio.NewReader(strings.NewReader(input)),
		out:    &bytes.Buffer{},
		errOut: &bytes.Buffer{},
	}
	if err := m.loop(); err != nil {
		t.Fatalf("menu loop: %v", err)
	}
	buf, _ := m.out.(*bytes.Buffer)
	return m, buf
}

// TestMenuScriptedSession 走一遍「概览 → 策略改 enroll-ttl → 退出」，并回读库验证生效。
func TestMenuScriptedSession(t *testing.T) {
	m, out := newScriptedMenu(t, "1\n"+"3\n"+"2\n"+"1h\n"+"0\n")
	text := out.String()
	for _, want := range []string{
		"vkeyd 控制台",
		"条目数: 0（墓碑 0）",
		"user_mode: single",
		"enroll_ttl: 30m0s",
		"enroll_ttl 已设置为 1h0m0s",
		msgMenuExited,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("菜单输出缺少 %q：\n%s", want, text)
		}
	}

	st, err := store.Open(m.dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = st.Close() }()
	ttl, err := st.EnrollTTLSeconds(context.Background())
	if err != nil {
		t.Fatalf("EnrollTTLSeconds: %v", err)
	}
	if ttl != 3600 {
		t.Fatalf("enroll_ttl = %d，期望 3600", ttl)
	}
}

// TestMenuInvalidInputKeepsRunning 验证非法编号与空行只提示、不退出。
func TestMenuInvalidInputKeepsRunning(t *testing.T) {
	_, out := newScriptedMenu(t, "abc\n\n6\n\n0\n")
	text := out.String()
	if got := strings.Count(text, "无效选择"); got != 2 {
		t.Fatalf("无效选择提示次数 = %d，期望 2：\n%s", got, text)
	}
	if !strings.Contains(text, "数据库路径保持不变") {
		t.Fatalf("空输入应保持原路径：\n%s", text)
	}
	if !strings.Contains(text, msgMenuExited) {
		t.Fatalf("输入 0 后应退出：\n%s", text)
	}
}

// TestMenuDeleteUserNeedsConfirm 验证删用户：不确认时不写库，确认后才级联删除。
func TestMenuDeleteUserNeedsConfirm(t *testing.T) {
	m := &menu{
		dbPath: filepath.Join(t.TempDir(), "menu.db"),
		in:     bufio.NewReader(strings.NewReader("2\n5\nalice\nn\n")),
		out:    &bytes.Buffer{},
		errOut: &bytes.Buffer{},
	}
	st, err := store.Open(m.dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := st.CreateUser(context.Background(), store.User{Username: "alice", Verifier: []byte{1}}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	_ = st.Close()

	if err := m.loop(); err != nil {
		t.Fatalf("menu loop: %v", err)
	}
	st, err = store.Open(m.dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = st.Close() }()
	if _, err := st.UserByUsername(context.Background(), "alice"); err != nil {
		t.Fatalf("未确认时不应删除账号：%v", err)
	}
	out := m.out.(*bytes.Buffer).String()
	if !strings.Contains(out, "将删除 items=") || !strings.Contains(out, msgMenuCancelled) {
		t.Fatalf("缺少 dry-run 清单或取消提示：\n%s", out)
	}
}
