package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"xiaoqiong0v0.cn/vkey/server/internal/crypto"
)

// TestAuthCorrectSignature 验证正常签名可以访问受保护端点。
func TestAuthCorrectSignature(t *testing.T) {
	e := newEnv(t)
	dev := e.enroll("laptop", "linux")

	resp := e.signedDo(dev, http.MethodGet, "/api/v1/items?since=0", nil)
	requireStatus(t, resp, http.StatusOK)
	var out itemsGet
	decode(t, resp, &out)
	if len(out.Items) != 0 || out.Next != 0 {
		t.Fatalf("空库应返回空列表: %+v", out)
	}
}

// TestAuthClockSkew 验证时间戳偏移 ±121 秒被拒绝、±120 秒被接受（固定时钟）。
func TestAuthClockSkew(t *testing.T) {
	fixed := time.Unix(1761436800, 0)
	e := newEnvAt(t, func() time.Time { return fixed })
	dev := e.enroll("laptop", "linux")
	ts := fixed.Unix()

	for _, offset := range []int64{-121, 121} {
		resp := e.signedDoTS(dev, http.MethodGet, "/api/v1/items", nil, ts+offset)
		requireStatus(t, resp, http.StatusUnauthorized)
		if code := errCode(t, resp); code != "ts_skew" {
			t.Fatalf("offset=%d 错误码应为 ts_skew，实际 %s", offset, code)
		}
	}

	// 边界上（±120）仍然通过。
	for _, offset := range []int64{-120, 120} {
		resp := e.signedDoTS(dev, http.MethodGet, "/api/v1/items", nil, ts+offset)
		requireStatus(t, resp, http.StatusOK)
	}
}

// TestAuthTamperedBody 验证签名与请求体不一致时被拒绝。
func TestAuthTamperedBody(t *testing.T) {
	e := newEnv(t)
	dev := e.enroll("laptop", "linux")

	signedBody := []byte(`{"items":[]}`)
	sentBody := []byte(`{"items":[{"id":"evil","kind":"totp","rp_id":"r","ct":"AAAA","nonce":"AAAAAAAAAAAAAAAA","base_version":0,"updated_at":1}]}`)
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+"/api/v1/items", bytes.NewReader(sentBody))
	if err != nil {
		t.Fatal(err)
	}
	e.signRequest(req, dev, http.MethodPost, "/api/v1/items", signedBody, time.Now().Unix())
	resp := e.do(req)
	requireStatus(t, resp, http.StatusUnauthorized)
	if code := errCode(t, resp); code != "bad_signature" {
		t.Fatalf("错误码应为 bad_signature，实际 %s", code)
	}
}

// TestAuthUnknownToken 验证未知 token 被拒绝。
func TestAuthUnknownToken(t *testing.T) {
	e := newEnv(t)
	dev := e.enroll("laptop", "linux")

	random, err := crypto.Random(crypto.TokenLen)
	if err != nil {
		t.Fatal(err)
	}
	ghost := &testDevice{Token: crypto.B64(random), Priv: dev.Priv, Pub: dev.Pub}
	resp := e.signedDo(ghost, http.MethodGet, "/api/v1/items", nil)
	requireStatus(t, resp, http.StatusUnauthorized)
	if code := errCode(t, resp); code != "invalid_token" {
		t.Fatalf("错误码应为 invalid_token，实际 %s", code)
	}
}

// TestAuthRevokedDevice 验证吊销后的设备 token 立即失效。
func TestAuthRevokedDevice(t *testing.T) {
	e := newEnv(t)
	dev := e.enroll("laptop", "linux")

	if err := e.st.RevokeDevice(context.Background(), e.user.ID, dev.ID, time.Now().Unix()); err != nil {
		t.Fatalf("吊销设备失败: %v", err)
	}
	resp := e.signedDo(dev, http.MethodGet, "/api/v1/items", nil)
	requireStatus(t, resp, http.StatusUnauthorized)
	if code := errCode(t, resp); code != "invalid_token" {
		t.Fatalf("错误码应为 invalid_token，实际 %s", code)
	}
}

// TestAuthBadVerifier 验证 verifier 错误时返回 401。
func TestAuthBadVerifier(t *testing.T) {
	e := newEnv(t)
	dev := newDevice(t)

	resp := e.postJSON("/api/v1/auth/token", map[string]any{
		"username": "default",
		"verifier": crypto.B64(make([]byte, crypto.KeyLen)),
		"device": map[string]any{
			"name": "laptop", "platform": "linux", "pubkey": crypto.B64(dev.Pub),
		},
	})
	requireStatus(t, resp, http.StatusUnauthorized)
	if code := errCode(t, resp); code != "invalid_credentials" {
		t.Fatalf("错误码应为 invalid_credentials，实际 %s", code)
	}

	// 未知用户名同样是 401，避免账号枚举。
	resp = e.postJSON("/api/v1/auth/token", map[string]any{
		"username": "nobody",
		"verifier": crypto.B64(make([]byte, crypto.KeyLen)),
		"device": map[string]any{
			"name": "laptop", "platform": "linux", "pubkey": crypto.B64(dev.Pub),
		},
	})
	requireStatus(t, resp, http.StatusUnauthorized)
}

// TestAuthReauthRotatesToken 验证同一设备重新认证会作废旧 token（协议已载明）。
func TestAuthReauthRotatesToken(t *testing.T) {
	e := newEnv(t)
	dev := e.enroll("laptop", "linux")

	// 用同一公钥再次认证。
	verifier, err := crypto.Verifier(e.masterKey, "default")
	if err != nil {
		t.Fatal(err)
	}
	resp := e.postJSON("/api/v1/auth/token", map[string]any{
		"username": "default",
		"verifier": crypto.B64(verifier),
		"device": map[string]any{
			"name": "laptop", "platform": "linux", "pubkey": crypto.B64(dev.Pub),
		},
	})
	requireStatus(t, resp, http.StatusOK)
	var out struct {
		Token    string `json:"token"`
		DeviceID string `json:"device_id"`
	}
	decode(t, resp, &out)
	if out.DeviceID != dev.ID {
		t.Fatalf("同一公钥应复用设备 id: got %s want %s", out.DeviceID, dev.ID)
	}

	// 旧 token 失效。
	resp = e.signedDo(dev, http.MethodGet, "/api/v1/items", nil)
	requireStatus(t, resp, http.StatusUnauthorized)

	// 新 token 可用。
	dev.Token = out.Token
	resp = e.signedDo(dev, http.MethodGet, "/api/v1/items", nil)
	requireStatus(t, resp, http.StatusOK)
}

// TestMethodNotAllowedJSON 验证错误方法返回统一 JSON 错误。
func TestMethodNotAllowedJSON(t *testing.T) {
	e := newEnv(t)
	dev := e.enroll("laptop", "linux")

	resp := e.signedDo(dev, http.MethodDelete, "/api/v1/items", nil)
	requireStatus(t, resp, http.StatusMethodNotAllowed)
	if code := errCode(t, resp); code != "method_not_allowed" {
		t.Fatalf("错误码应为 method_not_allowed，实际 %s", code)
	}

	// 未知 API 路径返回 404 JSON。
	resp = e.signedDo(dev, http.MethodGet, "/api/v1/nope", nil)
	requireStatus(t, resp, http.StatusNotFound)
	if code := errCode(t, resp); code != "not_found" {
		t.Fatalf("错误码应为 not_found，实际 %s", code)
	}
}

// TestAuthMissingHeaders 验证缺失签名头时的错误码。
func TestAuthMissingHeaders(t *testing.T) {
	e := newEnv(t)
	dev := e.enroll("laptop", "linux")

	req, err := http.NewRequest(http.MethodGet, e.srv.URL+"/api/v1/items", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp := e.do(req)
	requireStatus(t, resp, http.StatusUnauthorized)
	if code := errCode(t, resp); code != "missing_token" {
		t.Fatalf("错误码应为 missing_token，实际 %s", code)
	}

	req, err = http.NewRequest(http.MethodGet, e.srv.URL+"/api/v1/items", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+dev.Token)
	resp = e.do(req)
	requireStatus(t, resp, http.StatusUnauthorized)
	if code := errCode(t, resp); code != "missing_ts" {
		t.Fatalf("错误码应为 missing_ts，实际 %s", code)
	}

	// 时间戳正确但缺签名。
	req, err = http.NewRequest(http.MethodGet, e.srv.URL+"/api/v1/items", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+dev.Token)
	req.Header.Set("X-Vkey-Ts", jsonNumber(time.Now().Unix()))
	resp = e.do(req)
	requireStatus(t, resp, http.StatusUnauthorized)
	if code := errCode(t, resp); code != "missing_sig" {
		t.Fatalf("错误码应为 missing_sig，实际 %s", code)
	}
}

// jsonNumber 把 int64 转成十进制字符串（避免额外导入 strconv）。
func jsonNumber(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}
