package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"xiaoqiong0v0.cn/vkey/server/internal/store"
)

// TestResolvePurgeMode 验证 purge 的模式决策：
// 开关优先，无开关时按 stdin 是否为终端区分交互式 / 只列清单。
func TestResolvePurgeMode(t *testing.T) {
	tests := []struct {
		name     string
		dryRun   bool
		yes      bool
		isTTY    bool
		wantMode purgeMode
		wantNote bool
	}{
		{name: "无开关+终端=交互", dryRun: false, yes: false, isTTY: true, wantMode: purgeModeInteractive},
		{name: "无开关+非终端=只列清单", dryRun: false, yes: false, isTTY: false, wantMode: purgeModeList},
		{name: "显式 dry-run+终端", dryRun: true, yes: false, isTTY: true, wantMode: purgeModeDryRun},
		{name: "显式 dry-run+非终端", dryRun: true, yes: false, isTTY: false, wantMode: purgeModeDryRun},
		{name: "yes+终端=直接删", dryRun: false, yes: true, isTTY: true, wantMode: purgeModeDelete},
		{name: "yes+非终端=直接删", dryRun: false, yes: true, isTTY: false, wantMode: purgeModeDelete},
		{name: "同时给出时以 dry-run 为准", dryRun: true, yes: true, isTTY: true, wantMode: purgeModeDryRun, wantNote: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mode, note := resolvePurgeMode(tc.dryRun, tc.yes, tc.isTTY)
			if mode != tc.wantMode {
				t.Fatalf("mode = %v，期望 %v", mode, tc.wantMode)
			}
			if (note != "") != tc.wantNote {
				t.Fatalf("note = %q，期望非空=%v", note, tc.wantNote)
			}
		})
	}
}

// TestShortID 验证 id 前缀截断。
func TestShortID(t *testing.T) {
	if got := shortID("abcdefghijkl"); got != "abcdefgh…" {
		t.Fatalf("shortID = %q", got)
	}
	if got := shortID("short"); got != "short" {
		t.Fatalf("shortID = %q", got)
	}
}

// newPurgeCLIStore 建临时库并写入 2 条墓碑 + 1 条正常条目。
func newPurgeCLIStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "purge-cli.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	ctx := context.Background()
	if err := st.CreateUser(ctx, store.User{Username: "default", Verifier: []byte{1}}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	u, err := st.FirstUser(ctx)
	if err != nil {
		t.Fatalf("FirstUser: %v", err)
	}
	if _, err := st.ApplyItems(ctx, u.ID, []store.ItemInput{
		{ID: "tomb-a", Kind: "totp", RPID: "a.example", UpdatedAt: 100, DeletedAt: 200},
		{ID: "tomb-b", Kind: "totp", RPID: "b.example", UpdatedAt: 100, DeletedAt: 300},
		{ID: "alive", Kind: "totp", RPID: "c.example", UpdatedAt: 100},
	}); err != nil {
		t.Fatalf("ApplyItems: %v", err)
	}
	return st
}

// countItems 返回 items 表总行数。
func countItems(t *testing.T, st *store.Store) int64 {
	t.Helper()
	var n int64
	if err := st.DB().QueryRowContext(context.Background(), `SELECT COUNT(1) FROM items`).Scan(&n); err != nil {
		t.Fatalf("统计条目: %v", err)
	}
	return n
}

// TestPurgeDryRunWithoutTTYDoesNotWrite 验证非 TTY 分支只列清单、不写库，并给出加 --yes 的提示。
func TestPurgeDryRunWithoutTTYDoesNotWrite(t *testing.T) {
	st := newPurgeCLIStore(t)
	var buf bytes.Buffer
	if err := purgeDryRun(context.Background(), st, &buf, true); err != nil {
		t.Fatalf("purgeDryRun: %v", err)
	}
	if got := countItems(t, st); got != 3 {
		t.Fatalf("条目数 = %d，期望 3（不应写库）", got)
	}
	out := buf.String()
	for _, want := range []string{"tomb-a", "tomb-b", msgPurgeNoTTY} {
		if !strings.Contains(out, want) {
			t.Fatalf("输出缺少 %q：\n%s", want, out)
		}
	}
	if strings.Contains(out, "alive") {
		t.Fatalf("输出不应包含非墓碑条目：\n%s", out)
	}
}

// TestPurgeDeleteAllKeepsAlive 验证 --yes 分支只删墓碑。
func TestPurgeDeleteAllKeepsAlive(t *testing.T) {
	st := newPurgeCLIStore(t)
	if err := purgeDeleteAll(context.Background(), st); err != nil {
		t.Fatalf("purgeDeleteAll: %v", err)
	}
	if got := countItems(t, st); got != 1 {
		t.Fatalf("条目数 = %d，期望 1（只删墓碑）", got)
	}
}
