package api_test

import (
	"bytes"
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"xiaoqiong0v0.cn/vkey/server/internal/crypto"
	"xiaoqiong0v0.cn/vkey/server/internal/pair"
	"xiaoqiong0v0.cn/vkey/server/internal/policy"
	"xiaoqiong0v0.cn/vkey/server/internal/store"
)

// fixedBase 返回「约等于当下」的固定时钟基准，保证签名时间戳在容差内。
func fixedBase() time.Time { return time.Now() }

// newAdminEnv 构造 admin 模式测试环境（可注入固定时钟）。
func newAdminEnv(t *testing.T, now func() time.Time) *env {
	t.Helper()
	e := newEnvAt(t, now)
	if err := e.st.SetUserMode(context.Background(), policy.UserModeAdmin); err != nil {
		t.Fatalf("SetUserMode: %v", err)
	}
	return e
}

// issueCode 以 createdAt 为签发时间生成开户码，返回明文。
func issueCode(t *testing.T, e *env, username string, createdAt int64, ttl int64) string {
	t.Helper()
	_, plain, err := e.st.CreateEnrollCode(context.Background(), username, ttl, createdAt)
	if err != nil {
		t.Fatalf("CreateEnrollCode: %v", err)
	}
	return plain
}

// enrollBody 构造一次合法开户请求（master_key 只在本地派生 verifier）。
func enrollBody(code, username string, masterKey []byte, dev *testDevice) map[string]any {
	return enrollBodyFull(code, username, masterKey, dev, map[string]any{})
}

// enrollTestDevName 是测试请求里固定的设备名。
//
// 不用 dev.ID：newDevice 造的测试设备 ID 为空，服务端会先报 invalid_device，
// 把「code 不存在 / 已过期 / 用户名占用」等子用例的错误分支提前吞掉。
const enrollTestDevName = "test-dev"

// enrollBodyFull 与 enrollBody 相同，但允许追加/覆盖字段。
func enrollBodyFull(code, username string, mk []byte, dev *testDevice, extra map[string]any) map[string]any {
	verifier, err := crypto.Verifier(mk, username)
	if err != nil {
		panic(err)
	}
	body := map[string]any{
		"code":     code,
		"username": username,
		"verifier": crypto.B64(verifier),
		"device": map[string]any{
			"name":     enrollTestDevName,
			"platform": "linux",
			"pubkey":   crypto.B64(dev.Pub),
		},
	}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

// enrollOutcome 是 /auth/enroll 的响应。
type enrollOutcome struct {
	DeviceID string `json:"device_id"`
	Token    string `json:"token"`
	UserID   string `json:"user_id"`
	Username string `json:"username"`
}

// callEnroll 发送开户请求并解析 200 响应。
func callEnroll(t *testing.T, e *env, body map[string]any) (enrollOutcome, response) {
	t.Helper()
	resp := e.postJSON("/api/v1/auth/enroll", body)
	var out enrollOutcome
	if resp.status == http.StatusOK {
		decode(t, resp, &out)
	}
	return out, resp
}

// asDevice 把开户结果转成可签名的 testDevice。
func asDevice(out enrollOutcome, td *testDevice) *testDevice {
	return &testDevice{ID: out.DeviceID, Token: out.Token, Priv: td.Priv, Pub: td.Pub}
}

// TestEnrollHappyPath 覆盖开户码 → 账号+首设备+token 的完整链路：
// 返回的 token 与 /auth/token 同语义（可直接签名调用受保护接口）。
func TestEnrollHappyPath(t *testing.T) {
	base := fixedBase()
	e := newAdminEnv(t, func() time.Time { return base })

	mk, err := crypto.Random(crypto.KeyLen)
	if err != nil {
		t.Fatal(err)
	}
	dev := newDevice(t)
	dev.ID = "phone-a"
	code := issueCode(t, e, "alice", base.Unix(), policy.EnrollTTLSeconds)

	out, resp := callEnroll(t, e, enrollBody(code, "alice", mk, dev))
	requireStatus(t, resp, http.StatusOK)
	if out.UserID == "" || out.DeviceID == "" || out.Token == "" || out.Username != "alice" {
		t.Fatalf("响应字段缺失: %+v", out)
	}

	// 用返回 token 直接读写条目（验证 token 语义与鉴权链路）。
	alice := asDevice(out, dev)
	ct, nonce := []byte("secret-ciphertext"), bytes.Repeat([]byte{7}, crypto.NonceLen)
	w := e.writeItems(alice, itemPayload("k1", "totp", "a.dev", ct, nonce, 0, base.Unix(), 0))
	requireStatus(t, w, http.StatusOK)
	got := e.getItems(alice, 0)
	if len(got.Items) != 1 || got.Items[0].ID != "k1" {
		t.Fatalf("条目未同步: %+v", got)
	}

	// 服务端只有 verifier，没有 master_key（零知识断言：库里能查到 verifier）。
	u, err := e.st.UserByUsername(context.Background(), "alice")
	if err != nil {
		t.Fatalf("UserByUsername: %v", err)
	}
	want, _ := crypto.Verifier(mk, "alice")
	if !crypto.Equal(u.Verifier, want) {
		t.Fatal("服务端存储的 verifier 不匹配")
	}
	if len(u.WrappedKey) != 0 {
		t.Fatal("未提供主密码字段时 wrapped_key 应为空")
	}

	// 单次使用：重复提交同一 code → invalid_code。
	_, resp = callEnroll(t, e, enrollBody(code, "alice", mk, newDevice(t)))
	if resp.status != http.StatusBadRequest || errCode(t, resp) != "invalid_code" {
		t.Fatalf("重复开户应 400 invalid_code，实际 %d %s", resp.status, resp.body)
	}
}

// TestEnrollRejectedInSingleMode 校验 single 模式不提供自助注册。
func TestEnrollRejectedInSingleMode(t *testing.T) {
	e := newEnv(t)
	resp := e.postJSON("/api/v1/auth/enroll", map[string]any{"code": "ENROLL-AAAA-AAAA"})
	if resp.status != http.StatusForbidden || errCode(t, resp) != "enroll_disabled" {
		t.Fatalf("single 模式应 403 enroll_disabled，实际 %d %s", resp.status, resp.body)
	}
}

// TestEnrollValidationErrors 覆盖请求校验错误码。
func TestEnrollValidationErrors(t *testing.T) {
	base := fixedBase()
	e := newAdminEnv(t, func() time.Time { return base })
	mk, _ := crypto.Random(crypto.KeyLen)
	dev := newDevice(t)
	code := issueCode(t, e, "alice", base.Unix(), policy.EnrollTTLSeconds)

	t.Run("空 code", func(t *testing.T) {
		_, resp := callEnroll(t, e, enrollBody("  ", "alice", mk, dev))
		if resp.status != http.StatusBadRequest || errCode(t, resp) != "invalid_code" {
			t.Fatalf("应 400 invalid_code，实际 %d %s", resp.status, resp.body)
		}
	})
	t.Run("verifier 长度非法", func(t *testing.T) {
		body := enrollBody(code, "alice", mk, dev)
		body["verifier"] = "AAAA"
		_, resp := callEnroll(t, e, body)
		if resp.status != http.StatusBadRequest || errCode(t, resp) != "invalid_verifier" {
			t.Fatalf("应 400 invalid_verifier，实际 %d %s", resp.status, resp.body)
		}
	})
	t.Run("code 不存在", func(t *testing.T) {
		_, resp := callEnroll(t, e, enrollBody("ENROLL-ZZZZ-ZZZZ", "ghost", mk, dev))
		if resp.status != http.StatusBadRequest || errCode(t, resp) != "invalid_code" {
			t.Fatalf("应 400 invalid_code，实际 %d %s", resp.status, resp.body)
		}
	})
	t.Run("已过期", func(t *testing.T) {
		old := issueCode(t, e, "expired-user", base.Unix()-1200, 600)
		_, resp := callEnroll(t, e, enrollBody(old, "expired-user", mk, dev))
		if resp.status != http.StatusGone || errCode(t, resp) != "code_expired" {
			t.Fatalf("应 410 code_expired，实际 %d %s", resp.status, resp.body)
		}
	})
	t.Run("已撤销", func(t *testing.T) {
		rec, plain, err := e.st.CreateEnrollCode(context.Background(), "revoked-user", 1800, base.Unix())
		if err != nil {
			t.Fatal(err)
		}
		if err := e.st.RevokeEnrollCode(context.Background(), rec.ID, base.Unix()); err != nil {
			t.Fatal(err)
		}
		_, resp := callEnroll(t, e, enrollBody(plain, "revoked-user", mk, dev))
		if resp.status != http.StatusBadRequest || errCode(t, resp) != "invalid_code" {
			t.Fatalf("应 400 invalid_code，实际 %d %s", resp.status, resp.body)
		}
	})
	t.Run("用户名已占用", func(t *testing.T) {
		dup := issueCode(t, e, "default", base.Unix(), policy.EnrollTTLSeconds)
		_, resp := callEnroll(t, e, enrollBody(dup, "default", mk, dev))
		if resp.status != http.StatusConflict || errCode(t, resp) != "username_taken" {
			t.Fatalf("应 409 username_taken，实际 %d %s", resp.status, resp.body)
		}
	})
}

// TestEnrollPasswordFields 覆盖可选主密码包裹字段的校验与落库。
func TestEnrollPasswordFields(t *testing.T) {
	base := fixedBase()
	e := newAdminEnv(t, func() time.Time { return base })
	mk, _ := crypto.Random(crypto.KeyLen)
	dev := newDevice(t)

	pwSalt := bytes.Repeat([]byte{3}, crypto.PWSaltLen)
	kek := crypto.DeriveKEK("hunter2", pwSalt)
	wrapped, err := crypto.SealSelfContained(kek, mk, nil)
	if err != nil {
		t.Fatal(err)
	}

	code := issueCode(t, e, "alice", base.Unix(), policy.EnrollTTLSeconds)
	_, resp := callEnroll(t, e, enrollBodyFull(code, "alice", mk, dev, map[string]any{
		"pw_salt": crypto.B64(pwSalt), "wrapped_key": crypto.B64(wrapped),
	}))
	requireStatus(t, resp, http.StatusOK)

	u, err := e.st.UserByUsername(context.Background(), "alice")
	if err != nil || !bytes.Equal(u.PWSalt, pwSalt) || len(u.WrappedKey) == 0 {
		t.Fatalf("包裹字段未落库: %+v err=%v", u, err)
	}

	// 只给一半 → invalid_pw_fields。
	code2 := issueCode(t, e, "bob", base.Unix(), policy.EnrollTTLSeconds)
	_, resp = callEnroll(t, e, enrollBodyFull(code2, "bob", mk, newDevice(t), map[string]any{
		"pw_salt": crypto.B64(pwSalt),
	}))
	if resp.status != http.StatusBadRequest || errCode(t, resp) != "invalid_pw_fields" {
		t.Fatalf("应 400 invalid_pw_fields，实际 %d %s", resp.status, resp.body)
	}
	// salt 长度非法 → invalid_pw_salt。
	_, resp = callEnroll(t, e, enrollBodyFull(code2, "bob", mk, newDevice(t), map[string]any{
		"pw_salt": crypto.B64(bytes.Repeat([]byte{3}, 4)), "wrapped_key": crypto.B64(wrapped),
	}))
	if errCode(t, resp) != "invalid_pw_salt" {
		t.Fatalf("应 invalid_pw_salt，实际 %d %s", resp.status, resp.body)
	}
}

// TestEnrollRateLimit 校验免鉴权端点按 IP 限流 60/min：第 61 次起 429。
func TestEnrollRateLimit(t *testing.T) {
	e := newAdminEnv(t, nil)
	body := map[string]any{"code": "ENROLL-AAAA-AAAA"}
	for i := 0; i < 60; i++ {
		resp := e.postJSON("/api/v1/auth/enroll", body)
		if resp.status != http.StatusBadRequest {
			t.Fatalf("第 %d 次应 400，实际 %d", i+1, resp.status)
		}
	}
	resp := e.postJSON("/api/v1/auth/enroll", body)
	if resp.status != http.StatusTooManyRequests || errCode(t, resp) != "rate_limited" {
		t.Fatalf("第 61 次应 429 rate_limited，实际 %d %s", resp.status, resp.body)
	}
}

// TestPolicyUserModeField 校验 /policy 暴露 user_mode。
func TestPolicyUserModeField(t *testing.T) {
	e := newEnv(t)
	var p struct {
		UserMode        string `json:"user_mode"`
		RequireMasterPW bool   `json:"require_master_pw"`
	}
	resp := e.getNoAuth("/api/v1/policy")
	requireStatus(t, resp, http.StatusOK)
	decode(t, resp, &p)
	if p.UserMode != "single" {
		t.Fatalf("默认 user_mode = %q", p.UserMode)
	}
	if err := e.st.SetUserMode(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	resp = e.getNoAuth("/api/v1/policy")
	decode(t, resp, &p)
	if p.UserMode != "admin" {
		t.Fatalf("切换后 user_mode = %q", p.UserMode)
	}
}

// TestDisableBlocksAllDevices 校验 disable 后全部设备立即 401、重新认证也失败；
// enable 后恢复；配对领取同样被拒；数据保留。
func TestDisableBlocksAllDevices(t *testing.T) {
	e := newEnv(t)
	devA := e.enroll("A", "linux")
	devB := e.enroll("B", "android")
	e.writeItems(devA, itemPayload("keep", "totp", "a.dev", []byte("x"), bytes.Repeat([]byte{7}, 12), 0, time.Now().Unix(), 0))

	// 先登记一个配对码，稍后验证停用状态下不可领取。
	seed := e.enroll("seed", "linux")
	codeBytes, canonical, err := pair.NewCode()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := pair.SealBlob(codeBytes, "pw-1", e.masterKey)
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, e.pairNew(seed, "pw-1", codeBytes, blob, nil), http.StatusOK)

	if err := e.st.SetUserDisabled(context.Background(), e.user.ID, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}

	// 已登录的两台设备：读写都 401 user_disabled。
	resp := e.signedDo(devA, http.MethodGet, "/api/v1/items?since=0", nil)
	if resp.status != http.StatusUnauthorized || errCode(t, resp) != "user_disabled" {
		t.Fatalf("设备 A 应 401 user_disabled，实际 %d %s", resp.status, resp.body)
	}
	resp = e.signedDo(devB, http.MethodGet, "/api/v1/devices", nil)
	if resp.status != http.StatusUnauthorized {
		t.Fatalf("设备 B 应 401，实际 %d", resp.status)
	}

	// 重新认证：与错误凭据同响应（防枚举）。
	verifier, err := crypto.Verifier(e.masterKey, "default")
	if err != nil {
		t.Fatal(err)
	}
	resp = e.postJSON("/api/v1/auth/token", map[string]any{
		"username": "default",
		"verifier": crypto.B64(verifier),
		"device":   map[string]any{"name": "C", "platform": "linux", "pubkey": crypto.B64(newDevice(t).Pub)},
	})
	if resp.status != http.StatusUnauthorized || errCode(t, resp) != "invalid_credentials" {
		t.Fatalf("停用账号重新认证应 invalid_credentials，实际 %d %s", resp.status, resp.body)
	}

	// 配对码领取同样被拒。
	resp = e.claimPair(canonical, "C2", "linux", newDevice(t).Pub)
	if resp.status != http.StatusUnauthorized || errCode(t, resp) != "user_disabled" {
		t.Fatalf("停用后 claim 应 401 user_disabled，实际 %d %s", resp.status, resp.body)
	}

	// enable 恢复 + 数据保留。
	if err := e.st.SetUserDisabled(context.Background(), e.user.ID, 0); err != nil {
		t.Fatal(err)
	}
	got := e.getItems(devA, 0)
	if len(got.Items) != 1 || got.Items[0].ID != "keep" {
		t.Fatalf("恢复后数据应保留: %+v", got)
	}
}

// enrollUser 在 admin 环境里开户一个新用户并返回可签名设备。
func enrollUser(t *testing.T, e *env, base time.Time, username string) (*testDevice, []byte) {
	t.Helper()
	mk, err := crypto.Random(crypto.KeyLen)
	if err != nil {
		t.Fatal(err)
	}
	dev := newDevice(t)
	dev.ID = username + "-dev"
	code := issueCode(t, e, username, base.Unix(), policy.EnrollTTLSeconds)
	out, resp := callEnroll(t, e, enrollBody(code, username, mk, dev))
	if resp.status != http.StatusOK {
		t.Fatalf("开户 %s 失败: %d %s", username, resp.status, resp.body)
	}
	return asDevice(out, dev), mk
}

// TestCrossTenantIsolation 校验多用户数据隔离：同名条目互不可见、
// 跨账号吊销不可达、设备列表互不可见、凭据互不通用。
func TestCrossTenantIsolation(t *testing.T) {
	base := fixedBase()
	e := newAdminEnv(t, func() time.Time { return base })

	alice, mkAlice := enrollUser(t, e, base, "alice")
	bob, _ := enrollUser(t, e, base, "bob")

	now := base.Unix()
	ca := []byte("alice-secret")
	cb := []byte("bob-secret")
	requireStatus(t, e.writeItems(alice, itemPayload("same-id", "totp", "x.dev", ca, bytes.Repeat([]byte{1}, 12), 0, now, 0)), http.StatusOK)
	requireStatus(t, e.writeItems(bob, itemPayload("same-id", "totp", "x.dev", cb, bytes.Repeat([]byte{2}, 12), 0, now, 0)), http.StatusOK)

	// 各自只看到自己的密文。
	ga := e.getItems(alice, 0)
	if len(ga.Items) != 1 || ga.Items[0].CT != crypto.B64(ca) {
		t.Fatalf("alice 视角条目异常: %+v", ga.Items)
	}
	gb := e.getItems(bob, 0)
	if len(gb.Items) != 1 || gb.Items[0].CT != crypto.B64(cb) {
		t.Fatalf("bob 视角条目异常: %+v", gb.Items)
	}
	// bob 用自己的版本重写 same-id 不影响 alice（版本号空间按账号独立）。
	requireStatus(t, e.writeItems(bob, itemPayload("same-id", "totp", "x.dev", append(cb, '!'), bytes.Repeat([]byte{3}, 12), gb.Items[0].Version, now+1, 0)), http.StatusOK)
	ga = e.getItems(alice, 0)
	if ga.Items[0].Version != 1 || ga.Items[0].CT != crypto.B64(ca) {
		t.Fatalf("alice 数据被 bob 影响: %+v", ga.Items)
	}

	// 设备隔离：bob 无法吊销 alice 的设备。
	var aliceDevID struct {
		Devices []struct {
			ID string `json:"id"`
		} `json:"devices"`
	}
	resp := e.signedDo(alice, http.MethodGet, "/api/v1/devices", nil)
	requireStatus(t, resp, http.StatusOK)
	decode(t, resp, &aliceDevID)
	if len(aliceDevID.Devices) != 1 {
		t.Fatalf("alice 设备列表异常: %+v", aliceDevID)
	}
	resp = e.postAuthed(bob, "/api/v1/devices/revoke", map[string]any{"device_id": aliceDevID.Devices[0].ID})
	if resp.status != http.StatusNotFound || errCode(t, resp) != "device_not_found" {
		t.Fatalf("跨账号吊销应 404，实际 %d %s", resp.status, resp.body)
	}
	// alice 的设备仍可用（吊销未生效）。
	resp = e.signedDo(alice, http.MethodGet, "/api/v1/devices", nil)
	requireStatus(t, resp, http.StatusOK)

	// 凭据隔离：alice 的 verifier 登不了 bob 的账号。
	verifier, err := crypto.Verifier(mkAlice, "bob")
	if err != nil {
		t.Fatal(err)
	}
	resp = e.postJSON("/api/v1/auth/token", map[string]any{
		"username": "bob", "verifier": crypto.B64(verifier),
		"device": map[string]any{"name": "x", "platform": "linux", "pubkey": crypto.B64(newDevice(t).Pub)},
	})
	if resp.status != http.StatusUnauthorized || errCode(t, resp) != "invalid_credentials" {
		t.Fatalf("跨账号凭据应 401，实际 %d %s", resp.status, resp.body)
	}
}

// TestQuotaAPI 校验三档配额的 HTTP 语义：409 + quota_items/quota_bytes/quota_devices。
func TestQuotaAPI(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	dev := e.enroll("A", "linux")
	now := time.Now().Unix()
	write := func(id string, ctLen int) response {
		return e.writeItems(dev, itemPayload(id, "totp", "q.dev", bytes.Repeat([]byte("z"), ctLen), bytes.Repeat([]byte{9}, 12), 0, now, 0))
	}

	// 条目数：上限 2。
	if err := e.st.SetQuota(ctx, store.MetaKeyMaxItemsPerUser, 2); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, write("q1", 10), http.StatusOK)
	requireStatus(t, write("q2", 10), http.StatusOK)
	resp := write("q3", 10)
	if resp.status != http.StatusConflict || errCode(t, resp) != "quota_items" {
		t.Fatalf("应 409 quota_items，实际 %d %s", resp.status, resp.body)
	}

	// 字节数：放开条目数、密文上限 64B（当前已用 20B）。
	if err := e.st.SetQuota(ctx, store.MetaKeyMaxItemsPerUser, -1); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetQuota(ctx, store.MetaKeyMaxBytesPerUser, 64); err != nil {
		t.Fatal(err)
	}
	resp = write("q4", 100)
	if resp.status != http.StatusConflict || errCode(t, resp) != "quota_bytes" {
		t.Fatalf("应 409 quota_bytes，实际 %d %s", resp.status, resp.body)
	}
	requireStatus(t, write("q5", 40), http.StatusOK) // 20+40=60 ≤ 64

	// 设备数：放开字节、上限 2 台（当前已有 1 台）。
	if err := e.st.SetQuota(ctx, store.MetaKeyMaxBytesPerUser, -1); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetQuota(ctx, store.MetaKeyMaxDevicesPerUser, 2); err != nil {
		t.Fatal(err)
	}
	second := newDevice(t)
	second.ID = "C"
	e.enroll("B", "android") // 第 2 台设备（配额内）
	resp = e.postJSON("/api/v1/auth/token", map[string]any{
		"username": "default",
		"verifier": func() string { v, _ := crypto.Verifier(e.masterKey, "default"); return crypto.B64(v) }(),
		"device": map[string]any{"name": "C", "platform": "linux", "pubkey": crypto.B64(second.Pub)},
	})
	if resp.status != http.StatusConflict || errCode(t, resp) != "quota_devices" {
		t.Fatalf("应 409 quota_devices，实际 %d %s", resp.status, resp.body)
	}
	// 预注册路径同样受配额约束。
	third := newDevice(t)
	third.ID = "C"
	resp = e.postAuthed(dev, "/api/v1/devices/register", map[string]any{
		"name": "C", "platform": "linux", "pubkey": crypto.B64(third.Pub),
	})
	if resp.status != http.StatusConflict || errCode(t, resp) != "quota_devices" {
		t.Fatalf("register 应 409 quota_devices，实际 %d %s", resp.status, resp.body)
	}
}

// TestEnrollCodeShape 校验开户码在线格式（ENROLL-XXXX-XXXX，大写去混淆字母表）。
func TestEnrollCodeShape(t *testing.T) {
	e := newAdminEnv(t, nil)
	code := issueCode(t, e, "shape-check", time.Now().Unix(), policy.EnrollTTLSeconds)
	if !regexp.MustCompile(`^ENROLL-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}$`).MatchString(code) {
		t.Fatalf("开户码格式异常: %q", code)
	}
	// 不区分大小写：转小写提交同样成功。
	mk, _ := crypto.Random(crypto.KeyLen)
	dev := newDevice(t)
	dev.ID = "d"
	_, resp := callEnroll(t, e, enrollBody(strings.ToLower(code), "shape-check", mk, dev))
	requireStatus(t, resp, http.StatusOK)
}

// TestEnrollMethodNotAllowed 校验新端点的 405 行为与既有约定一致。
func TestEnrollMethodNotAllowed(t *testing.T) {
	e := newEnv(t)
	resp := e.getNoAuth("/api/v1/auth/enroll")
	if resp.status != http.StatusMethodNotAllowed {
		t.Fatalf("GET enroll 应 405，实际 %d", resp.status)
	}
}
