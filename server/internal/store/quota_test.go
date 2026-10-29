package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// newQuotaUser 建一个测试账号并返回其 id。
func newQuotaUser(t *testing.T, st *Store, username string) string {
	t.Helper()
	ctx := context.Background()
	if err := st.CreateUser(ctx, User{Username: username, Verifier: bytes32(0x0a)}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	u, err := st.UserByUsername(ctx, username)
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

// TestDeviceQuotaEnforcedOnAllCreatePaths 校验三台上限下：
// CreateDevice/UpsertDevice(新建)/ClaimPair 都受配额约束，幂等路径不消耗配额。
func TestDeviceQuotaEnforcedOnAllCreatePaths(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	userID := newQuotaUser(t, st, "alice")
	if err := st.SetQuota(ctx, MetaKeyMaxDevicesPerUser, 2); err != nil {
		t.Fatal(err)
	}

	// 1) UpsertDevice 新建设备 ×2。
	if _, err := st.UpsertDevice(ctx, userID, "d1", "linux", bytes32(1), bytes32(0x91), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertDevice(ctx, userID, "d2", "linux", bytes32(2), bytes32(0x92), 2); err != nil {
		t.Fatal(err)
	}
	// 同公钥再次认证 = 覆盖旧 token，不新建行、不占配额。
	if _, err := st.UpsertDevice(ctx, userID, "d1b", "linux", bytes32(1), bytes32(0x93), 3); err != nil {
		t.Fatalf("幂等 upsert 不应触发配额: %v", err)
	}
	if _, err := st.UpsertDevice(ctx, userID, "d3", "linux", bytes32(3), bytes32(0x94), 4); !errors.Is(err, ErrQuotaDevices) {
		t.Fatalf("UpsertDevice 超限应 ErrQuotaDevices，实际 %v", err)
	}

	// 2) CreateDevice 超限。
	if _, err := st.CreateDevice(ctx, userID, "d4", "android", bytes32(4), nil, 5); !errors.Is(err, ErrQuotaDevices) {
		t.Fatalf("CreateDevice 超限应 ErrQuotaDevices，实际 %v", err)
	}

	// 3) ClaimPair 超限且失败时不消费配对码、不落设备行。
	p := Pair{CodeID: "c1", UserID: userID, CodeHash: bytes32(0x77), Blob: bytes32(6), ExpiresAt: time.Now().Unix() + 600, CreatedAt: 1}
	if err := st.CreatePair(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ClaimPair(ctx, p.CodeHash, "d5", "android", bytes32(5), bytes32(0x95), time.Now().Unix()); !errors.Is(err, ErrQuotaDevices) {
		t.Fatalf("ClaimPair 超限应 ErrQuotaDevices，实际 %v", err)
	}
	var used int
	if err := st.DB().QueryRow(`SELECT COUNT(1) FROM pairs WHERE code_id='c1' AND used_at IS NULL`).Scan(&used); err != nil || used != 1 {
		t.Fatalf("超限时配对码不应被消费 used=%d err=%v", used, err)
	}
	var devRows int
	if err := st.DB().QueryRow(`SELECT COUNT(1) FROM devices WHERE user_id = ?`, userID).Scan(&devRows); err != nil || devRows != 2 {
		t.Fatalf("超限时不应落新设备行 rows=%d err=%v", devRows, err)
	}

	// 放开配额后同一路径恢复可用。
	if err := st.SetQuota(ctx, MetaKeyMaxDevicesPerUser, -1); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ClaimPair(ctx, p.CodeHash, "d5", "android", bytes32(5), bytes32(0x95), time.Now().Unix()); err != nil {
		t.Fatalf("放开配额后 ClaimPair 应成功: %v", err)
	}
}

// TestClaimPairDisabledUser 校验停用账号的配对码不可领取。
func TestClaimPairDisabledUser(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	userID := newQuotaUser(t, st, "alice")
	p := Pair{CodeID: "c1", UserID: userID, CodeHash: bytes32(0x77), Blob: bytes32(6), ExpiresAt: 9999999999, CreatedAt: 1}
	if err := st.CreatePair(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserDisabled(ctx, userID, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ClaimPair(ctx, p.CodeHash, "d", "linux", bytes32(1), bytes32(2), 100); !errors.Is(err, ErrUserDisabled) {
		t.Fatalf("应 ErrUserDisabled，实际 %v", err)
	}
}

// TestItemsQuotaEnforcement 校验条目数/字节数配额：整批回滚、不部分生效。
func TestItemsQuotaEnforcement(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	userID := newQuotaUser(t, st, "alice")

	ct := make([]byte, 100)
	for i := range ct {
		ct[i] = byte(i)
	}
	mk := func(id string) ItemInput {
		return ItemInput{ID: id, Kind: "totp", RPID: "x", Ciphertext: ct, Nonce: bytes32(7)[:12], UpdatedAt: 1}
	}

	// 条目数配额 = 2：第三批 1 条应整批失败，前两批不受影响。
	if err := st.SetQuota(ctx, MetaKeyMaxItemsPerUser, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyItems(ctx, userID, []ItemInput{mk("i1"), mk("i2")}); err != nil {
		t.Fatalf("配额内应成功: %v", err)
	}
	if _, err := st.ApplyItems(ctx, userID, []ItemInput{mk("i3")}); !errors.Is(err, ErrQuotaItems) {
		t.Fatalf("应 ErrQuotaItems，实际 %v", err)
	}
	var n int
	if err := st.DB().QueryRow(`SELECT COUNT(1) FROM items WHERE user_id=?`, userID).Scan(&n); err != nil || n != 2 {
		t.Fatalf("超限批次必须整批回滚 rows=%d err=%v", n, err)
	}
	// seq 也不应被超限批次占用（整批回滚）。
	seq, err := st.Seq(ctx, userID)
	if err != nil || seq != 2 {
		t.Fatalf("seq = %d（期望 2）err=%v", seq, err)
	}

	// 墓碑释放名额：把 i2 逻辑删除后可以再写一条。
	if _, err := st.ApplyItems(ctx, userID, []ItemInput{{ID: "i2", Kind: "totp", RPID: "x", UpdatedAt: 2, DeletedAt: 2, BaseVersion: 2}}); err != nil {
		t.Fatalf("写墓碑失败: %v", err)
	}
	if _, err := st.ApplyItems(ctx, userID, []ItemInput{mk("i3")}); err != nil {
		t.Fatalf("释放名额后应可写入: %v", err)
	}

	// 字节配额：250B 时 i1(100)+i3(100)=200 允许，再加一条超限。
	if err := st.SetQuota(ctx, MetaKeyMaxItemsPerUser, -1); err != nil {
		t.Fatal(err)
	}
	if err := st.SetQuota(ctx, MetaKeyMaxBytesPerUser, 250); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyItems(ctx, userID, []ItemInput{mk("i4")}); !errors.Is(err, ErrQuotaBytes) {
		t.Fatalf("应 ErrQuotaBytes，实际 %v", err)
	}
	// 更新已有条目不新增字节：i1 同尺寸重写（当前 version=1）应成功。
	if _, err := st.ApplyItems(ctx, userID, []ItemInput{{ID: "i1", Kind: "totp", RPID: "x", Ciphertext: ct, Nonce: bytes32(7)[:12], BaseVersion: 1, UpdatedAt: 5}}); err != nil {
		t.Fatalf("同尺寸重写应成功: %v", err)
	}
}
