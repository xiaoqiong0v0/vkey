package main

import (
	"bytes"
	"context"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"xiaoqiong0v0.cn/vkey/server/internal/policy"
	"xiaoqiong0v0.cn/vkey/server/internal/store"
)

// newCLIStore 建临时库与 default 账号（与既有测试风格一致）。
func newCLIStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "user-cli.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.CreateUser(context.Background(), store.User{Username: "default", Verifier: []byte{1}}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return st
}

// TestUserAddRejectedInSingleMode 校验 single 模式下 `user add` 直接拒绝。
func TestUserAddRejectedInSingleMode(t *testing.T) {
	st := newCLIStore(t)
	var out, hint bytes.Buffer
	err := userAddRun(context.Background(), st, "alice", time.Minute, time.Now(), &out, &hint)
	if err == nil || !strings.Contains(err.Error(), "single") {
		t.Fatalf("single 模式应被拒绝并提示，实际 err=%v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("被拒绝时不应有 stdout 输出: %q", out.String())
	}
	// 走完整 run() 入口也应失败。
	if err := run([]string{"user", "add", "alice", "--db", filepath.Join(t.TempDir(), "no.db")}); err == nil {
		t.Fatal("run(user add) 在 single 模式应返回错误")
	}
}

// TestUserAddRunEmitsParsableOutput 校验开户码输出的固定 key=value 形态。
func TestUserAddRunEmitsParsableOutput(t *testing.T) {
	st := newCLIStore(t)
	ctx := context.Background()
	if err := st.SetUserMode(ctx, policy.UserModeAdmin); err != nil {
		t.Fatal(err)
	}
	var out, hint bytes.Buffer
	now := time.Unix(1_800_000_000, 0)
	if err := userAddRun(ctx, st, "alice", time.Hour, now, &out, &hint); err != nil {
		t.Fatalf("userAddRun: %v", err)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("应恰好 4 行，实际:\n%s", out.String())
	}
	fields := map[string]string{}
	for _, ln := range lines {
		k, v, ok := strings.Cut(ln, "=")
		if !ok {
			t.Fatalf("非 key=value 行: %q", ln)
		}
		fields[k] = v
	}
	if fields["username"] != "alice" {
		t.Fatalf("username=%q", fields["username"])
	}
	if !regexp.MustCompile(`^ENROLL-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}$`).MatchString(fields["code"]) {
		t.Fatalf("code=%q 格式非法", fields["code"])
	}
	exp, err := strconv.ParseInt(fields["expires_at"], 10, 64)
	if err != nil || exp != now.Unix()+3600 {
		t.Fatalf("expires_at=%q err=%v", fields["expires_at"], err)
	}
	if fields["code_id"] == "" {
		t.Fatal("缺少 code_id")
	}
	// 提示（stderr）里应给出等价 curl 调用。
	if !strings.Contains(hint.String(), "curl") || !strings.Contains(hint.String(), fields["code"]) {
		t.Fatalf("stderr 提示缺少等价调用:\n%s", hint.String())
	}
	// 库里能查到绑定 alice 的待用 code。
	codes, err := st.ListPendingEnrollCodes(ctx)
	if err != nil || len(codes) != 1 || codes[0].Username != "alice" {
		t.Fatalf("待用 code 异常: %+v err=%v", codes, err)
	}
}

// TestUserAddInvalidUsername 校验用户名基本约束。
func TestUserAddInvalidUsername(t *testing.T) {
	if err := validateCLIUsername(""); err == nil {
		t.Fatal("空用户名应报错")
	}
	if err := validateCLIUsername("a b"); err == nil {
		t.Fatal("含空白应报错")
	}
	if err := validateCLIUsername(strings.Repeat("x", policy.MaxUsernameBytes+1)); err == nil {
		t.Fatal("超长应报错")
	}
	if err := validateCLIUsername("ok-name"); err != nil {
		t.Fatalf("合法用户名报错: %v", err)
	}
}

// TestUserListRun 校验账号与待用开户码清单。
func TestUserListRun(t *testing.T) {
	st := newCLIStore(t)
	ctx := context.Background()
	if err := st.CreateUser(ctx, store.User{Username: "alice", Verifier: []byte{2}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.CreateEnrollCode(ctx, "bob", 1800, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := userListRun(ctx, st, &out); err != nil {
		t.Fatalf("userListRun: %v", err)
	}
	s := out.String()
	for _, want := range []string{"user id=", "username=default", "username=alice", "status=active", "pending_code id=", "username=bob"} {
		if !strings.Contains(s, want) {
			t.Fatalf("输出缺少 %q:\n%s", want, s)
		}
	}
}

// TestUserDeleteDryRunOnlyPrints 校验 delete 不带 --yes 只打印行数、不写库。
func TestUserDeleteDryRunOnlyPrints(t *testing.T) {
	st := newCLIStore(t)
	ctx := context.Background()
	if err := st.CreateUser(ctx, store.User{Username: "victim", Verifier: []byte{3}}); err != nil {
		t.Fatal(err)
	}
	u, _ := st.UserByUsername(ctx, "victim")
	if _, err := st.UpsertDevice(ctx, u.ID, "d", "linux", []byte{4}, []byte{5}, 1); err != nil {
		t.Fatal(err)
	}
	usage, err := st.DeleteUserPreview(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	var out, hint bytes.Buffer
	if err := userDeleteDryRun(&out, &hint, usage); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "will_delete items=0 conflicts=0 devices=1") {
		t.Fatalf("dry-run 输出异常:\n%s", out.String())
	}
	if !strings.Contains(hint.String(), "--yes") {
		t.Fatalf("提示应要求 --yes:\n%s", hint.String())
	}
	// 未写库。
	if _, err := st.UserByID(ctx, u.ID); err != nil {
		t.Fatalf("dry-run 后账号应存在: %v", err)
	}
}

// TestResolveUserRef 校验 --id / <username> 的定位规则。
func TestResolveUserRef(t *testing.T) {
	st := newCLIStore(t)
	ctx := context.Background()
	u, _ := st.UserByUsername(ctx, "default")

	got, err := resolveUserRef(ctx, st, "t", "", []string{"default"})
	if err != nil || got.ID != u.ID {
		t.Fatalf("按用户名解析失败: %v", err)
	}
	got, err = resolveUserRef(ctx, st, "t", u.ID, nil)
	if err != nil || got.Username != "default" {
		t.Fatalf("按 id 解析失败: %v", err)
	}
	if _, err := resolveUserRef(ctx, st, "t", u.ID, []string{"default"}); err == nil {
		t.Fatal("二者同时给出应报错")
	}
	if _, err := resolveUserRef(ctx, st, "t", "", nil); err == nil {
		t.Fatal("二者都不给应报错")
	}
	if _, err := resolveUserRef(ctx, st, "t", "", []string{"ghost"}); err == nil ||
		!strings.Contains(err.Error(), "不存在") {
		t.Fatalf("不存在用户名应报「账号不存在」: %v", err)
	}
}

// TestParseQuotaValue 校验配额取值解析（整数与 MiB 后缀）。
func TestParseQuotaValue(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		bad  bool
	}{
		{in: "1000", want: 1000},
		{in: "-1", want: -1},
		{in: "0", want: 0},
		{in: "20MiB", want: 20 << 20},
		{in: "20M", want: 20 << 20},
		{in: "20971520B", want: 20971520},
		{in: "4K", want: 4 << 10},
		{in: "1GiB", want: 1 << 30},
		{in: "abc", bad: true},
		{in: "", bad: true},
		{in: "1.5K", bad: true},
	}
	for _, c := range cases {
		got, err := parseQuotaValue(c.in)
		if c.bad {
			if err == nil {
				t.Fatalf("parseQuotaValue(%q) 应报错，实际 %d", c.in, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Fatalf("parseQuotaValue(%q) = %d,%v，期望 %d", c.in, got, err, c.want)
		}
	}
}

// TestPolicySetViaRun 校验 `policy set` 的新开关（用户模式 + 配额）。
func TestPolicySetViaRun(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "policy.db")
	if err := run([]string{"policy", "set", "--db", dbPath, "--user-mode", "admin"}); err != nil {
		t.Fatalf("policy set: %v", err)
	}
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	mode, _ := st.UserMode(context.Background())
	if mode != "admin" {
		t.Fatalf("mode = %q", mode)
	}
	if err := run([]string{"policy", "set", "--db", dbPath, "--max-bytes-per-user", "1MiB", "--max-devices-per-user", "-1"}); err != nil {
		t.Fatalf("policy set quotas: %v", err)
	}
	q, _ := st.Quotas(context.Background())
	if q.MaxBytes != 1<<20 || q.MaxDevices != -1 {
		t.Fatalf("配额异常: %+v", q)
	}
	if err := run([]string{"policy", "set", "--db", dbPath}); err == nil {
		t.Fatal("不带任何开关应报错")
	}
	if err := run([]string{"policy", "set", "--db", dbPath, "--user-mode", "weird"}); err == nil {
		t.Fatal("非法模式应报错")
	}
}

// TestUserRevokeFlow 校验 `user add` → `user revoke` 的 CLI 闭环（经 run() 入口）。
func TestUserRevokeFlow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "revoke.db")
	if err := run([]string{"policy", "set", "--db", dbPath, "--user-mode", "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"user", "add", "alice", "--db", dbPath, "--ttl", "5m"}); err != nil {
		t.Fatalf("user add: %v", err)
	}
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	codes, err := st.ListPendingEnrollCodes(context.Background())
	if err != nil || len(codes) != 1 {
		t.Fatalf("应有 1 条待用 code: %+v err=%v", codes, err)
	}
	if err := run([]string{"user", "revoke", codes[0].ID, "--db", dbPath}); err != nil {
		t.Fatalf("user revoke: %v", err)
	}
	codes, _ = st.ListPendingEnrollCodes(context.Background())
	if len(codes) != 0 {
		t.Fatalf("撤销后不应有待用 code: %+v", codes)
	}
	if err := run([]string{"user", "revoke", "no-such-id", "--db", dbPath}); err == nil {
		t.Fatal("撤销不存在 id 应报错")
	}
}
