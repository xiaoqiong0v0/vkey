package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"xiaoqiong0v0.cn/vkey/server/internal/policy"
	"xiaoqiong0v0.cn/vkey/server/internal/store"
)

// newEnrollTTLDB 建临时库并切到 admin 模式（`user add` 的前提）。
func newEnrollTTLDB(t *testing.T) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "enroll-ttl.db")
	if err := run([]string{"policy", "set", "--db", dbPath, "--user-mode", "admin"}); err != nil {
		t.Fatalf("切换到 admin 模式失败: %v", err)
	}
	return dbPath
}

// pendingCodeTTL 返回库中唯一待用开户码的有效期（expires_at - created_at，秒）。
func pendingCodeTTL(t *testing.T, dbPath string) int64 {
	t.Helper()
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	defer func() { _ = st.Close() }()
	codes, err := st.ListPendingEnrollCodes(context.Background())
	if err != nil {
		t.Fatalf("ListPendingEnrollCodes: %v", err)
	}
	if len(codes) != 1 {
		t.Fatalf("应有 1 条待用开户码，实际 %+v", codes)
	}
	return codes[0].ExpiresAt - codes[0].CreatedAt
}

// metaEnrollTTL 返回库中当前生效的开户码默认有效期（秒）。
func metaEnrollTTL(t *testing.T, dbPath string) int64 {
	t.Helper()
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	defer func() { _ = st.Close() }()
	secs, err := st.EnrollTTLSeconds(context.Background())
	if err != nil {
		t.Fatalf("EnrollTTLSeconds: %v", err)
	}
	return secs
}

// addUser 执行一次 `user add`（不带 --ttl 之外的额外开关）。
func addUser(t *testing.T, dbPath, username string, extra ...string) error {
	t.Helper()
	args := append([]string{"user", "add", username, "--db", dbPath}, extra...)
	_, _, err := runCapture(t, func() error { return run(args) })
	return err
}

// TestEnrollTTLFallsBackToCompiledDefault 未配置 meta 时回落 policy.EnrollTTLSeconds。
func TestEnrollTTLFallsBackToCompiledDefault(t *testing.T) {
	dbPath := newEnrollTTLDB(t)
	if err := addUser(t, dbPath, "alice"); err != nil {
		t.Fatalf("user add: %v", err)
	}
	if got := pendingCodeTTL(t, dbPath); got != policy.EnrollTTLSeconds {
		t.Fatalf("有效期 = %ds，期望回落默认 %ds", got, policy.EnrollTTLSeconds)
	}
}

// TestEnrollTTLUsesMetaDefault 配置 enroll.ttl_seconds 后，未传 --ttl 的签发取 meta 值。
func TestEnrollTTLUsesMetaDefault(t *testing.T) {
	dbPath := newEnrollTTLDB(t)
	if err := run([]string{"policy", "set", "--db", dbPath, "--enroll-ttl=2h"}); err != nil {
		t.Fatalf("policy set --enroll-ttl: %v", err)
	}
	if err := addUser(t, dbPath, "alice"); err != nil {
		t.Fatalf("user add: %v", err)
	}
	if got := pendingCodeTTL(t, dbPath); got != 7200 {
		t.Fatalf("有效期 = %ds，期望 7200s（meta 配置 2h）", got)
	}
}

// TestEnrollTTLExplicitFlagOverridesMeta 显式 --ttl 覆盖 meta 默认值。
func TestEnrollTTLExplicitFlagOverridesMeta(t *testing.T) {
	dbPath := newEnrollTTLDB(t)
	if err := run([]string{"policy", "set", "--db", dbPath, "--enroll-ttl=2h"}); err != nil {
		t.Fatalf("policy set --enroll-ttl: %v", err)
	}
	if err := addUser(t, dbPath, "alice", "--ttl", "15m"); err != nil {
		t.Fatalf("user add --ttl 15m: %v", err)
	}
	if got := pendingCodeTTL(t, dbPath); got != 900 {
		t.Fatalf("有效期 = %ds，期望 900s（命令行 15m 覆盖 meta）", got)
	}
}

// TestEnrollTTLExplicitFlagRejectsZero 显式 --ttl 0 仍按非法处理。
func TestEnrollTTLExplicitFlagRejectsZero(t *testing.T) {
	dbPath := newEnrollTTLDB(t)
	err := addUser(t, dbPath, "alice", "--ttl", "0")
	if err == nil || !strings.Contains(err.Error(), "--ttl") {
		t.Fatalf("--ttl 0 应报错，实际 err = %v", err)
	}
}

// TestPolicySetEnrollTTLRejectsInvalid 非法取值报错且不改库。
func TestPolicySetEnrollTTLRejectsInvalid(t *testing.T) {
	cases := []struct{ name, value string }{
		{name: "零值", value: "0"},
		{name: "负数", value: "-5m"},
		{name: "非 duration", value: "abc"},
		{name: "不足 1 秒", value: "500ms"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dbPath := newEnrollTTLDB(t)
			_, _, err := runCapture(t, func() error {
				return run([]string{"policy", "set", "--db", dbPath, "--enroll-ttl=" + c.value})
			})
			if err == nil {
				t.Fatalf("--enroll-ttl=%s 应被拒绝", c.value)
			}
			if got := metaEnrollTTL(t, dbPath); got != policy.EnrollTTLSeconds {
				t.Fatalf("非法取值不应写库，实际 meta = %ds", got)
			}
		})
	}
}

// TestUpdateShowIncludesEnrollTTL 校验 `update show` 输出 enroll_ttl（默认与配置后）。
func TestUpdateShowIncludesEnrollTTL(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "update-enroll-ttl.db")
	openUpdateCLIStore(t, dbPath) // 建空库

	out, _, err := runCapture(t, func() error {
		return runUpdate([]string{"show", "--db", dbPath})
	})
	if err != nil {
		t.Fatalf("update show: %v", err)
	}
	if want := "enroll_ttl=" + formatDuration(policy.EnrollTTLSeconds); !strings.Contains(out, want) {
		t.Fatalf("未配置时应输出 %q：\n%s", want, out)
	}

	if err := run([]string{"policy", "set", "--db", dbPath, "--enroll-ttl=2h"}); err != nil {
		t.Fatalf("policy set --enroll-ttl: %v", err)
	}
	out, _, err = runCapture(t, func() error {
		return runUpdate([]string{"show", "--db", dbPath})
	})
	if err != nil {
		t.Fatalf("update show: %v", err)
	}
	if !strings.Contains(out, "enroll_ttl=2h0m0s") {
		t.Fatalf("配置 2h 后应输出 enroll_ttl=2h0m0s：\n%s", out)
	}
}
