package api_test

import (
	"net/http"
	"testing"

	"xiaoqiong0v0.cn/vkey/server/internal/crypto"
)

// TestDeviceRegisterAndRevoke 覆盖 devices/register 与 devices/revoke 的完整链路。
func TestDeviceRegisterAndRevoke(t *testing.T) {
	e := newEnv(t)
	a := e.enroll("desk", "linux")
	b := newDevice(t)

	// 预注册设备公钥（幂等）。
	regResp := e.postAuthed(a, "/api/v1/devices/register", map[string]any{
		"name": "phone", "platform": "android", "pubkey": crypto.B64(b.Pub),
	})
	requireStatus(t, regResp, http.StatusOK)
	var reg struct {
		DeviceID string `json:"device_id"`
	}
	decode(t, regResp, &reg)
	if reg.DeviceID == "" {
		t.Fatal("devices/register 未返回 device_id")
	}

	again := e.postAuthed(a, "/api/v1/devices/register", map[string]any{
		"name": "phone", "platform": "android", "pubkey": crypto.B64(b.Pub),
	})
	requireStatus(t, again, http.StatusOK)
	var reg2 struct {
		DeviceID string `json:"device_id"`
	}
	decode(t, again, &reg2)
	if reg2.DeviceID != reg.DeviceID {
		t.Fatalf("重复注册应幂等: got %s want %s", reg2.DeviceID, reg.DeviceID)
	}

	// 预注册的设备用 verifier 认证后应复用同一 id。
	verifier, err := crypto.Verifier(e.masterKey, "default")
	if err != nil {
		t.Fatal(err)
	}
	authResp := e.postJSON("/api/v1/auth/token", map[string]any{
		"username": "default",
		"verifier": crypto.B64(verifier),
		"device": map[string]any{
			"name": "phone", "platform": "android", "pubkey": crypto.B64(b.Pub),
		},
	})
	requireStatus(t, authResp, http.StatusOK)
	var auth struct {
		Token    string `json:"token"`
		DeviceID string `json:"device_id"`
	}
	decode(t, authResp, &auth)
	if auth.DeviceID != reg.DeviceID {
		t.Fatalf("认证应复用预注册设备: got %s want %s", auth.DeviceID, reg.DeviceID)
	}
	b.Token, b.ID = auth.Token, auth.DeviceID
	requireStatus(t, e.signedDo(b, http.MethodGet, "/api/v1/items", nil), http.StatusOK)

	// 吊销设备 B。
	revokeResp := e.postAuthed(a, "/api/v1/devices/revoke", map[string]any{"device_id": reg.DeviceID})
	requireStatus(t, revokeResp, http.StatusOK)
	var revoke struct {
		OK bool `json:"ok"`
	}
	decode(t, revokeResp, &revoke)
	if !revoke.OK {
		t.Fatal("devices/revoke 未返回 ok:true")
	}
	requireStatus(t, e.signedDo(b, http.MethodGet, "/api/v1/items", nil), http.StatusUnauthorized)

	// 重复吊销 → 404。
	revokeAgain := e.postAuthed(a, "/api/v1/devices/revoke", map[string]any{"device_id": reg.DeviceID})
	requireStatus(t, revokeAgain, http.StatusNotFound)
	if code := errCode(t, revokeAgain); code != "device_not_found" {
		t.Fatalf("错误码应为 device_not_found，实际 %s", code)
	}

	// 吊销不存在的设备 → 404。
	missing := e.postAuthed(a, "/api/v1/devices/revoke", map[string]any{"device_id": "missing"})
	requireStatus(t, missing, http.StatusNotFound)
}
