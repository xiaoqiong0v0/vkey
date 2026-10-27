package api_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"xiaoqiong0v0.cn/vkey/server/internal/crypto"
)

// deviceListWire 是 GET /api/v1/devices 的单台设备线上形式。
type deviceListWire struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Platform  string `json:"platform"`
	CreatedAt int64  `json:"created_at"`
	LastSeen  int64  `json:"last_seen"`
	Current   bool   `json:"current"`
}

// deviceListGet 是 GET /api/v1/devices 的响应。
type deviceListGet struct {
	Devices []deviceListWire `json:"devices"`
}

// TestDeviceList 覆盖 GET /api/v1/devices 的鉴权、响应形状、current 标记、
// last_seen 降序与吊销过滤，并断言不泄漏公钥/token。
func TestDeviceList(t *testing.T) {
	e := newEnv(t)
	a := e.enroll("desk", "linux")
	b := e.enroll("phone", "android")

	// 无签名 → 401。
	requireStatus(t, e.getNoAuth("/api/v1/devices"), http.StatusUnauthorized)

	// 把 B 的 last_seen 调到未来，确保降序断言不受 A 本次请求刷新自身 last_seen 影响。
	if _, err := e.st.DB().Exec(
		`UPDATE devices SET last_seen = ? WHERE id = ?`, time.Now().Unix()+1000, b.ID); err != nil {
		t.Fatalf("更新 last_seen 失败: %v", err)
	}

	resp := e.signedDo(a, http.MethodGet, "/api/v1/devices", nil)
	requireStatus(t, resp, http.StatusOK)
	var out deviceListGet
	decode(t, resp, &out)
	if len(out.Devices) != 2 {
		t.Fatalf("应返回 2 台设备，实际 %d: %s", len(out.Devices), resp.body)
	}
	// last_seen 降序：B 在前。
	if out.Devices[0].ID != b.ID || out.Devices[1].ID != a.ID {
		t.Fatalf("应按 last_seen 降序排列: %+v", out.Devices)
	}
	// current 只标记发起本次请求的设备。
	for _, d := range out.Devices {
		if want := d.ID == a.ID; d.Current != want {
			t.Fatalf("设备 %s 的 current=%v，期望 %v", d.ID, d.Current, want)
		}
	}
	// 字段形状与取值。
	self := out.Devices[1]
	if self.Name != "desk" || self.Platform != "linux" {
		t.Fatalf("设备字段不符: %+v", self)
	}
	if self.CreatedAt <= 0 || self.LastSeen <= 0 {
		t.Fatalf("created_at/last_seen 应为正数: %+v", self)
	}
	// 不泄漏公钥与 token（断言响应体不含这些字段名）。
	body := string(resp.body)
	for _, banned := range []string{"pubkey", "token"} {
		if strings.Contains(body, banned) {
			t.Fatalf("响应体不应包含 %q: %s", banned, body)
		}
	}

	// 吊销 B 后列表只剩 A。
	requireStatus(t, e.postAuthed(a, "/api/v1/devices/revoke", map[string]any{"device_id": b.ID}), http.StatusOK)
	after := e.signedDo(a, http.MethodGet, "/api/v1/devices", nil)
	requireStatus(t, after, http.StatusOK)
	var afterOut deviceListGet
	decode(t, after, &afterOut)
	if len(afterOut.Devices) != 1 || afterOut.Devices[0].ID != a.ID {
		t.Fatalf("吊销后应只剩当前设备: %s", after.body)
	}
	if strings.Contains(string(after.body), b.ID) {
		t.Fatalf("吊销的设备不应再出现: %s", after.body)
	}
}

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
