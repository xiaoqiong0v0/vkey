package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"xiaoqiong0v0.cn/vkey/server/internal/crypto"
	"xiaoqiong0v0.cn/vkey/server/internal/pair"
)

// sampleWrappedKey 返回一个布局合法（nonce(12)||ct(32)||tag(16)）的包裹。
func sampleWrappedKey() []byte {
	return bytes.Repeat([]byte{0x5a}, crypto.NonceLen+crypto.KeyLen+crypto.TagLen)
}

// setPassword 调用 POST /api/v1/auth/password。
func (e *env) setPassword(dev *testDevice, pwSalt, wrappedKey []byte) response {
	e.t.Helper()
	return e.postAuthed(dev, "/api/v1/auth/password", map[string]any{
		"pw_salt":     crypto.B64(pwSalt),
		"wrapped_key": crypto.B64(wrappedKey),
	})
}

// deletePassword 调用 DELETE /api/v1/auth/password。
func (e *env) deletePassword(dev *testDevice, confirm string) response {
	e.t.Helper()
	body, err := json.Marshal(map[string]string{"confirm": confirm})
	if err != nil {
		e.t.Fatalf("序列化删除请求失败: %v", err)
	}
	return e.signedDo(dev, http.MethodDelete, "/api/v1/auth/password", body)
}

// policyView 是 /policy 中与主密码相关的字段。
type policyView struct {
	RequireMasterPW         bool `json:"require_master_pw"`
	RequireMasterPWEnforced bool `json:"require_master_pw_enforced"`
}

// getPolicy 读取当前策略。
func (e *env) getPolicy() policyView {
	e.t.Helper()
	resp := e.getNoAuth("/api/v1/policy")
	requireStatus(e.t, resp, http.StatusOK)
	var p policyView
	decode(e.t, resp, &p)
	return p
}

// TestPasswordRoundTripAndClear 验证写入 → auth/token 回读 → 带确认删除。
func TestPasswordRoundTripAndClear(t *testing.T) {
	e := newEnv(t)
	dev := e.enroll("linux", "linux")
	pwSalt := bytes.Repeat([]byte{0x22}, crypto.PWSaltLen)
	wrapped := sampleWrappedKey()

	resp := e.setPassword(dev, pwSalt, wrapped)
	requireStatus(t, resp, http.StatusOK)
	var ok struct {
		OK bool `json:"ok"`
	}
	decode(t, resp, &ok)
	if !ok.OK {
		t.Fatal("写入主密码包裹应返回 ok=true")
	}

	u, err := e.st.FirstUser(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(u.PWSalt, pwSalt) || !bytes.Equal(u.WrappedKey, wrapped) {
		t.Fatalf("库中包裹不匹配: salt=%x wrapped=%d", u.PWSalt, len(u.WrappedKey))
	}

	// auth/token 必须返回刚写入的值。
	verifier, err := crypto.Verifier(e.masterKey, "default")
	if err != nil {
		t.Fatal(err)
	}
	authResp := e.postJSON("/api/v1/auth/token", map[string]any{
		"username": "default",
		"verifier": crypto.B64(verifier),
		"device":   map[string]any{"name": "linux", "platform": "linux", "pubkey": crypto.B64(dev.Pub)},
	})
	requireStatus(t, authResp, http.StatusOK)
	var tokenResp struct {
		Token      string  `json:"token"`
		PWSalt     *string `json:"pw_salt"`
		WrappedKey *string `json:"wrapped_key"`
	}
	decode(t, authResp, &tokenResp)
	// 同一公钥重新认证会轮换 token（协议 §3.3），后续删除请求要用新 token。
	dev.Token = tokenResp.Token
	if tokenResp.PWSalt == nil || *tokenResp.PWSalt != crypto.B64(pwSalt) {
		t.Fatalf("auth/token 未返回新 pw_salt: %+v", tokenResp.PWSalt)
	}
	if tokenResp.WrappedKey == nil || *tokenResp.WrappedKey != crypto.B64(wrapped) {
		t.Fatalf("auth/token 未返回新 wrapped_key: %+v", tokenResp.WrappedKey)
	}

	// 错误 confirm 必须拒绝，且数据保持不变。
	resp = e.deletePassword(dev, "remove")
	requireStatus(t, resp, http.StatusBadRequest)
	if code := errCode(t, resp); code != "invalid_confirm" {
		t.Fatalf("错误码应为 invalid_confirm，实际 %s", code)
	}
	u, err = e.st.FirstUser(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(u.WrappedKey) == 0 {
		t.Fatal("confirm 错误时不应删除包裹")
	}

	// 正确 confirm 删除两列。
	resp = e.deletePassword(dev, "remove-master-password")
	requireStatus(t, resp, http.StatusOK)
	u, err = e.st.FirstUser(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if u.PWSalt != nil || u.WrappedKey != nil {
		t.Fatalf("删除后两列应为 NULL: salt=%v wrapped=%v", u.PWSalt, u.WrappedKey)
	}
}

// TestPasswordValidation 验证 pw_salt / wrapped_key 的长度与编码校验。
func TestPasswordValidation(t *testing.T) {
	e := newEnv(t)
	dev := e.enroll("linux", "linux")

	cases := []struct {
		name       string
		pwSalt     []byte
		wrappedKey []byte
		wantCode   string
	}{
		{"salt 过短", bytes.Repeat([]byte{1}, crypto.PWSaltLen-1), sampleWrappedKey(), "invalid_pw_salt"},
		{"wrapped_key 为空", bytes.Repeat([]byte{2}, crypto.PWSaltLen), nil, "invalid_wrapped_key"},
		{"wrapped_key 过长", bytes.Repeat([]byte{2}, crypto.PWSaltLen), bytes.Repeat([]byte{3}, 81), "invalid_wrapped_key"},
		{"wrapped_key 只有 nonce+tag", bytes.Repeat([]byte{2}, crypto.PWSaltLen), bytes.Repeat([]byte{3}, crypto.NonceLen+crypto.TagLen), "invalid_wrapped_key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := e.setPassword(dev, tc.pwSalt, tc.wrappedKey)
			requireStatus(t, resp, http.StatusBadRequest)
			if code := errCode(t, resp); code != tc.wantCode {
				t.Fatalf("错误码应为 %s，实际 %s", tc.wantCode, code)
			}
		})
	}

	// 非 base64url 的 wrapped_key 同样 400。
	resp := e.postAuthed(dev, "/api/v1/auth/password", map[string]any{
		"pw_salt":     crypto.B64(bytes.Repeat([]byte{2}, crypto.PWSaltLen)),
		"wrapped_key": "!!!not-base64!!!",
	})
	requireStatus(t, resp, http.StatusBadRequest)
	if code := errCode(t, resp); code != "invalid_wrapped_key" {
		t.Fatalf("错误码应为 invalid_wrapped_key，实际 %s", code)
	}
}

// TestPolicyRequireMasterPWEnforced 验证 enforced = require && wrapped_key 非空。
func TestPolicyRequireMasterPWEnforced(t *testing.T) {
	e := newEnv(t)
	dev := e.enroll("linux", "linux")

	if p := e.getPolicy(); p.RequireMasterPW || p.RequireMasterPWEnforced {
		t.Fatalf("默认策略应为 false/false: %+v", p)
	}

	if err := e.st.SetRequireMasterPW(t.Context(), e.user.ID, true); err != nil {
		t.Fatal(err)
	}
	p := e.getPolicy()
	if !p.RequireMasterPW || p.RequireMasterPWEnforced {
		t.Fatalf("没有包裹时 enforced 必须为 false: %+v", p)
	}

	resp := e.setPassword(dev, bytes.Repeat([]byte{0x33}, crypto.PWSaltLen), sampleWrappedKey())
	requireStatus(t, resp, http.StatusOK)
	p = e.getPolicy()
	if !p.RequireMasterPW || !p.RequireMasterPWEnforced {
		t.Fatalf("有包裹时 enforced 必须为 true: %+v", p)
	}

	resp = e.deletePassword(dev, "remove-master-password")
	requireStatus(t, resp, http.StatusOK)
	p = e.getPolicy()
	if !p.RequireMasterPW || p.RequireMasterPWEnforced {
		t.Fatalf("删除包裹后 enforced 必须回到 false: %+v", p)
	}
}

// TestPairClaimReturnsWrappedKey 验证新设备通过 pair/claim 拿到密码包裹。
func TestPairClaimReturnsWrappedKey(t *testing.T) {
	e := newEnv(t)
	dev := e.enroll("linux", "linux")
	pwSalt := bytes.Repeat([]byte{0x44}, crypto.PWSaltLen)
	wrapped := sampleWrappedKey()
	requireStatus(t, e.setPassword(dev, pwSalt, wrapped), http.StatusOK)

	code, canonical, err := pair.NewCode()
	if err != nil {
		t.Fatal(err)
	}
	codeID := "pair-pw-1"
	blob, err := pair.SealBlob(code, codeID, e.masterKey)
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, e.pairNew(dev, codeID, code, blob, pwSalt), http.StatusOK)

	claimant := newDevice(t)
	resp := e.claimPair(canonical, "phone", "android", claimant.Pub)
	requireStatus(t, resp, http.StatusOK)
	var claim struct {
		PWSalt     *string `json:"pw_salt"`
		WrappedKey *string `json:"wrapped_key"`
	}
	decode(t, resp, &claim)
	if claim.PWSalt == nil || *claim.PWSalt != crypto.B64(pwSalt) {
		t.Fatalf("claim 未回传 pw_salt: %+v", claim.PWSalt)
	}
	if claim.WrappedKey == nil || *claim.WrappedKey != crypto.B64(wrapped) {
		t.Fatalf("claim 未回传 wrapped_key: %+v", claim.WrappedKey)
	}
}
