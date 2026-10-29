package store

import (
	"context"
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestStore 打开临时库并注册清理。
func newTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "vkey-test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// enrollInput 构造一次合法开户请求（占位密钥材料）。
func enrollInput(code, username string, now int64) EnrollInput {
	return EnrollInput{
		Code:           code,
		Username:       username,
		Verifier:       bytes32(0x11),
		DeviceName:     "dev",
		DevicePlatform: "linux",
		DevicePubKey:   bytes32(0x22),
		TokenHash:      bytes32(0x33),
		Now:            now,
	}
}

// bytes32 生成 32 字节占位值。
func bytes32(v byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = v
	}
	return b
}

// TestEnrollCodeFormat 校验开户码明文格式：ENROLL-XXXX-XXXX、去混淆字母表。
func TestEnrollCodeFormat(t *testing.T) {
	for i := 0; i < 50; i++ {
		plain, err := NewEnrollCodePlain()
		if err != nil {
			t.Fatalf("NewEnrollCodePlain: %v", err)
		}
		if !regexp.MustCompile(`^ENROLL-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}$`).MatchString(plain) {
			t.Fatalf("开户码格式非法: %q", plain)
		}
	}
}

// TestEnrollLifecycle 覆盖正常开户：账号+首设备落库、code 消费、重复使用被拒。
func TestEnrollLifecycle(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	_, plain, err := st.CreateEnrollCode(ctx, "alice", 1800, now)
	if err != nil {
		t.Fatalf("CreateEnrollCode: %v", err)
	}

	out, err := st.Enroll(ctx, enrollInput(plain, "", now))
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if out.Username != "alice" || out.UserID == "" || out.DeviceID == "" {
		t.Fatalf("Enroll 结果不完整: %+v", out)
	}
	u, err := st.UserByUsername(ctx, "alice")
	if err != nil || u.DisabledAt != 0 || len(u.Verifier) != 32 {
		t.Fatalf("账号状态异常: %+v err=%v", u, err)
	}
	devs, err := st.ListDevices(ctx, u.ID)
	if err != nil || len(devs) != 1 {
		t.Fatalf("首设备应为 1，实际 %d err=%v", len(devs), err)
	}
	// 开户成功后 code 立即失效。
	if _, err := st.Enroll(ctx, enrollInput(plain, "", now)); !errors.Is(err, ErrEnrollInvalid) {
		t.Fatalf("重复使用应 ErrEnrollInvalid，实际 %v", err)
	}
	// 明文不落库：库里只有 hash，code 记录仍绑定 alice。
	var n int
	if err := st.DB().QueryRow(`SELECT COUNT(1) FROM enroll_codes WHERE username = 'alice'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("开户码记录数异常 n=%d err=%v", n, err)
	}
}

// TestEnrollCaseInsensitive 校验大小写/空白规范化后仍可命中。
func TestEnrollCaseInsensitive(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	_, plain, err := st.CreateEnrollCode(ctx, "alice", 1800, now)
	if err != nil {
		t.Fatalf("CreateEnrollCode: %v", err)
	}
	mangled := "  " + strings.ToLower(plain) + " "
	if _, err := st.Enroll(ctx, enrollInput(mangled, "", now)); err != nil {
		t.Fatalf("规范化后应可开户: %v", err)
	}
}

// TestEnrollExpired 校验过期拒绝且不影响其它 code。
func TestEnrollExpired(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	base := time.Now().Unix()

	_, plain, err := st.CreateEnrollCode(ctx, "alice", 60, base-120)
	if err != nil {
		t.Fatalf("CreateEnrollCode: %v", err)
	}
	if _, err := st.Enroll(ctx, enrollInput(plain, "", base)); !errors.Is(err, ErrEnrollExpired) {
		t.Fatalf("应 ErrEnrollExpired，实际 %v", err)
	}
	// 尚未过期的另一条仍可用。
	_, plain2, err := st.CreateEnrollCode(ctx, "bob", 1800, base)
	if err != nil {
		t.Fatalf("CreateEnrollCode: %v", err)
	}
	if _, err := st.Enroll(ctx, enrollInput(plain2, "", base)); err != nil {
		t.Fatalf("未过期 code 应成功: %v", err)
	}
}

// TestEnrollRevoked 校验撤销后不可用、重复撤销报错。
func TestEnrollRevoked(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	rec, plain, err := st.CreateEnrollCode(ctx, "alice", 1800, now)
	if err != nil {
		t.Fatalf("CreateEnrollCode: %v", err)
	}
	if err := st.RevokeEnrollCode(ctx, rec.ID, now); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := st.Enroll(ctx, enrollInput(plain, "", now)); !errors.Is(err, ErrEnrollInvalid) {
		t.Fatalf("撤销后应 ErrEnrollInvalid，实际 %v", err)
	}
	if err := st.RevokeEnrollCode(ctx, rec.ID, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("重复撤销应 ErrNotFound，实际 %v", err)
	}
	if err := st.RevokeEnrollCode(ctx, "不存在", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("撤销不存在应 ErrNotFound，实际 %v", err)
	}
}

// TestEnrollConcurrentSingleUse 并发提交同一开户码：至多一个成功。
func TestEnrollConcurrentSingleUse(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	_, plain, err := st.CreateEnrollCode(ctx, "alice", 1800, now)
	if err != nil {
		t.Fatalf("CreateEnrollCode: %v", err)
	}

	const n = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	var ok int
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			in := enrollInput(plain, "", now)
			in.TokenHash = bytes32(byte(0x40 + i))
			in.DevicePubKey = bytes32(byte(0x80 + i))
			_, err := st.Enroll(ctx, in)
			if err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
				return
			}
			if !errors.Is(err, ErrEnrollInvalid) {
				t.Errorf("并发失败方应 ErrEnrollInvalid，实际 %v", err)
			}
		}(i)
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("成功数 = %d，期望恰好 1", ok)
	}
	var users, devices int
	if err := st.DB().QueryRow(`SELECT COUNT(1) FROM users`).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := st.DB().QueryRow(`SELECT COUNT(1) FROM devices`).Scan(&devices); err != nil {
		t.Fatal(err)
	}
	if users != 1 || devices != 1 {
		t.Fatalf("users=%d devices=%d，期望各 1", users, devices)
	}
}

// TestEnrollUsernameTaken 校验用户名占用返回 ErrExists（可复用同语义）。
func TestEnrollUsernameTaken(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	if err := st.CreateUser(ctx, User{Username: "alice", Verifier: bytes32(1)}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	_, plain, err := st.CreateEnrollCode(ctx, "alice", 1800, now)
	if err != nil {
		t.Fatalf("CreateEnrollCode: %v", err)
	}
	if _, err := st.Enroll(ctx, enrollInput(plain, "", now)); !errors.Is(err, ErrExists) {
		t.Fatalf("应 ErrExists，实际 %v", err)
	}
	// 用户名被占用时 code 不应被消费（同一事务回滚）。
	var used int
	if err := st.DB().QueryRow(`SELECT COUNT(1) FROM enroll_codes WHERE used_at IS NULL AND username='alice'`).Scan(&used); err != nil || used != 1 {
		t.Fatalf("code 应保持未消费 used=%d err=%v", used, err)
	}
}

// TestEnrollUnboundUsername 覆盖未绑定 code 的用户名规则。
func TestEnrollUnboundUsername(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	_, plain, err := st.CreateEnrollCode(ctx, "", 1800, now)
	if err != nil {
		t.Fatalf("CreateEnrollCode: %v", err)
	}
	if _, err := st.Enroll(ctx, enrollInput(plain, "", now)); !errors.Is(err, ErrEnrollInvalid) {
		t.Fatalf("未绑定且未提供用户名应 ErrEnrollInvalid，实际 %v", err)
	}
	out, err := st.Enroll(ctx, enrollInput(plain, "carol", now))
	if err != nil {
		t.Fatalf("未绑定 code 应接受请求用户名: %v", err)
	}
	if out.Username != "carol" {
		t.Fatalf("username = %q", out.Username)
	}

	// 已绑定的 code：请求给出不一致用户名 → 拒绝。
	_, plain2, err := st.CreateEnrollCode(ctx, "dave", 1800, now)
	if err != nil {
		t.Fatalf("CreateEnrollCode: %v", err)
	}
	if _, err := st.Enroll(ctx, enrollInput(plain2, "mallory", now)); !errors.Is(err, ErrEnrollInvalid) {
		t.Fatalf("用户名不一致应 ErrEnrollInvalid，实际 %v", err)
	}
}

// TestEnrollDeviceQuotaZero 校验 max_devices_per_user=0 时拒绝开户、-1 时放开。
func TestEnrollDeviceQuotaZero(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().Unix()

	if err := st.SetQuota(ctx, MetaKeyMaxDevicesPerUser, 0); err != nil {
		t.Fatalf("SetQuota: %v", err)
	}
	_, plain, err := st.CreateEnrollCode(ctx, "alice", 1800, now)
	if err != nil {
		t.Fatalf("CreateEnrollCode: %v", err)
	}
	if _, err := st.Enroll(ctx, enrollInput(plain, "", now)); !errors.Is(err, ErrQuotaDevices) {
		t.Fatalf("应 ErrQuotaDevices，实际 %v", err)
	}
	if err := st.SetQuota(ctx, MetaKeyMaxDevicesPerUser, -1); err != nil {
		t.Fatalf("SetQuota: %v", err)
	}
	if _, err := st.Enroll(ctx, enrollInput(plain, "", now)); err != nil {
		t.Fatalf("不限制后应成功: %v", err)
	}
}

// TestUserModeAndQuotas 校验模式/配额的默认值、覆盖与非法输入。
func TestUserModeAndQuotas(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	mode, err := st.UserMode(ctx)
	if err != nil || mode != "single" {
		t.Fatalf("默认模式应为 single，实际 %q err=%v", mode, err)
	}
	if err := st.SetUserMode(ctx, "admin"); err != nil {
		t.Fatalf("SetUserMode: %v", err)
	}
	if mode, _ = st.UserMode(ctx); mode != "admin" {
		t.Fatalf("模式应为 admin，实际 %q", mode)
	}
	if err := st.SetUserMode(ctx, "weird"); err == nil {
		t.Fatal("非法模式应报错")
	}

	q, err := st.Quotas(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if q.MaxItems != 1000 || q.MaxBytes != 20<<20 || q.MaxDevices != 10 {
		t.Fatalf("默认配额异常: %+v", q)
	}
	if err := st.SetQuota(ctx, MetaKeyMaxItemsPerUser, 5); err != nil {
		t.Fatal(err)
	}
	if err := st.SetQuota(ctx, "quota.bogus", 1); err == nil {
		t.Fatal("未知配额键应报错")
	}
	q, _ = st.Quotas(ctx)
	if q.MaxItems != 5 {
		t.Fatalf("配额覆盖失败: %+v", q)
	}
}

// TestSetUserDisabledToggle 校验停用/启用只动标记、不动数据。
func TestSetUserDisabledToggle(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.CreateUser(ctx, User{Username: "alice", Verifier: bytes32(1)}); err != nil {
		t.Fatal(err)
	}
	u, _ := st.UserByUsername(ctx, "alice")

	if err := st.SetUserDisabled(ctx, u.ID, 123); err != nil {
		t.Fatal(err)
	}
	after, _ := st.UserByID(ctx, u.ID)
	if after.DisabledAt != 123 {
		t.Fatalf("DisabledAt = %d", after.DisabledAt)
	}
	if err := st.SetUserDisabled(ctx, u.ID, 0); err != nil {
		t.Fatal(err)
	}
	after, _ = st.UserByUsername(ctx, "alice")
	if after.DisabledAt != 0 {
		t.Fatalf("启用后 DisabledAt = %d", after.DisabledAt)
	}
	if err := st.SetUserDisabled(ctx, "no-such-user", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("应 ErrNotFound，实际 %v", err)
	}
}

// TestListUsersCounts 校验账号列表的设备/条目计数。
func TestListUsersCounts(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.CreateUser(ctx, User{Username: "alice", Verifier: bytes32(1)}); err != nil {
		t.Fatal(err)
	}
	u, _ := st.UserByUsername(ctx, "alice")
	if _, err := st.UpsertDevice(ctx, u.ID, "d1", "linux", bytes32(2), bytes32(3), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyItems(ctx, u.ID, []ItemInput{{ID: "i1", Kind: "totp", RPID: "x", Ciphertext: bytes32(4), UpdatedAt: 1}}); err != nil {
		t.Fatal(err)
	}
	rows, err := st.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Username != "alice" || rows[0].Devices != 1 || rows[0].Items != 1 {
		t.Fatalf("列表异常: %+v", rows)
	}
}

// TestDeleteUserCascade 校验级联删除的行数统计与残留清理，其它账号不受影响。
func TestDeleteUserCascade(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	if err := st.CreateUser(ctx, User{Username: "alice", Verifier: bytes32(1)}); err != nil {
		t.Fatal(err)
	}
	ua, _ := st.UserByUsername(ctx, "alice")
	if err := st.CreateUser(ctx, User{Username: "bob", Verifier: bytes32(9)}); err != nil {
		t.Fatal(err)
	}
	ub, _ := st.UserByUsername(ctx, "bob")

	if _, err := st.UpsertDevice(ctx, ub.ID, "d1", "linux", bytes32(2), bytes32(3), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyItems(ctx, ub.ID, []ItemInput{
		{ID: "i1", Kind: "totp", RPID: "x", Ciphertext: bytes32(4), UpdatedAt: 1},
		{ID: "i2", Kind: "totp", RPID: "y", UpdatedAt: 1, DeletedAt: 2}, // 墓碑
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreatePair(ctx, Pair{CodeID: "p1", UserID: ub.ID, CodeHash: bytes32(5), Blob: bytes32(6), ExpiresAt: 999, CreatedAt: 1}); err != nil {
		t.Fatal(err)
	}
	if err := st.Audit(ctx, ub.ID, "d", "test", 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.CreateEnrollCode(ctx, "bob", 1800, 1); err != nil {
		t.Fatal(err)
	}

	usage, err := st.DeleteUserPreview(ctx, ub.ID)
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if usage.Items != 2 || usage.Devices != 1 || usage.Pairs != 1 || usage.Audits != 1 || usage.Codes != 1 {
		t.Fatalf("dry-run 统计异常: %+v", usage)
	}
	// dry-run 不写库。
	if _, err := st.UserByID(ctx, ub.ID); err != nil {
		t.Fatalf("dry-run 后账号应仍存在: %v", err)
	}

	got, err := st.DeleteUserCascade(ctx, ub.ID)
	if err != nil {
		t.Fatalf("DeleteUserCascade: %v", err)
	}
	if got.Items != 2 || got.Devices != 1 || got.Pairs != 1 || got.Audits != 1 || got.Codes != 1 {
		t.Fatalf("删除统计异常: %+v", got)
	}
	if _, err := st.DeleteUserCascade(ctx, ub.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("重复删除应 ErrNotFound，实际 %v", err)
	}
	// 关联表无残留。
	for tbl, col := range map[string]string{
		"items": "user_id", "item_conflicts": "user_id", "devices": "user_id",
		"pairs": "user_id", "audit": "user_id", "enroll_codes": "username",
	} {
		var n int
		arg := ub.ID
		if col == "username" {
			arg = "bob"
		}
		if err := st.DB().QueryRow(`SELECT COUNT(1) FROM `+tbl+` WHERE `+col+` = ?`, arg).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s 残留 n=%d err=%v", tbl, n, err)
		}
	}
	// seq meta 已清理，其它账号完好。
	var seqN int
	if err := st.DB().QueryRow(`SELECT COUNT(1) FROM meta WHERE key = ?`, seqKey(ub.ID)).Scan(&seqN); err != nil || seqN != 0 {
		t.Fatalf("seq 残留 err=%v", err)
	}
	if _, err := st.UserByID(ctx, ua.ID); err != nil {
		t.Fatalf("alice 不应被波及: %v", err)
	}
}

// TestMigrationOldDBAddsDisabledAt 模拟旧库（无 disabled_at 列）打开后自动补列。
func TestMigrationOldDBAddsDisabledAt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := st.CreateUser(ctx, User{Username: "alice", Verifier: bytes32(1)}); err != nil {
		t.Fatal(err)
	}
	// 模拟旧 schema：删列后重新打开，迁移应自动补回。
	if _, err := st.DB().Exec(`ALTER TABLE users DROP COLUMN disabled_at`); err != nil {
		t.Fatalf("构造旧库失败: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st2, err := Open(path)
	if err != nil {
		t.Fatalf("重开旧库: %v", err)
	}
	defer func() { _ = st2.Close() }()
	u, err := st2.UserByUsername(ctx, "alice")
	if err != nil || u.DisabledAt != 0 {
		t.Fatalf("迁移后读取异常: %+v err=%v", u, err)
	}
	if err := st2.SetUserDisabled(ctx, u.ID, 55); err != nil {
		t.Fatalf("迁移后应可停用: %v", err)
	}
}
