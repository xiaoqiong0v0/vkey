package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"xiaoqiong0v0.cn/vkey/server/internal/crypto"
	"xiaoqiong0v0.cn/vkey/server/internal/pair"
)

// TestPairSingleUseAndBlob 验证配对码单次可用、blob 可解出 master_key。
func TestPairSingleUseAndBlob(t *testing.T) {
	e := newEnv(t)
	a := e.enroll("desk", "linux")

	code, canonical, err := pair.NewCode()
	if err != nil {
		t.Fatal(err)
	}
	codeID := "pair-demo-1"
	pwSalt := bytes.Repeat([]byte{0x11}, crypto.PWSaltLen)
	blob, err := pair.SealBlob(code, codeID, e.masterKey)
	if err != nil {
		t.Fatal(err)
	}

	resp := e.pairNew(a, codeID, code, blob, pwSalt)
	requireStatus(t, resp, http.StatusOK)
	var newResp struct {
		CodeID    string `json:"code_id"`
		Code      string `json:"code"`
		ExpiresAt int64  `json:"expires_at"`
	}
	decode(t, resp, &newResp)
	if newResp.CodeID != codeID || newResp.Code != canonical {
		t.Fatalf("pair/new 回显异常: %+v", newResp)
	}
	now := time.Now().Unix()
	if newResp.ExpiresAt < now+590 || newResp.ExpiresAt > now+610 {
		t.Fatalf("配对码 TTL 异常: %d", newResp.ExpiresAt)
	}

	// 用展示形式（带 '-'）领取，验证服务端会规范化。
	b := newDevice(t)
	claim := e.claimPair(pair.Display(code), "phone", "android", b.Pub)
	requireStatus(t, claim, http.StatusOK)
	var claimResp struct {
		Token    string  `json:"token"`
		DeviceID string  `json:"device_id"`
		Blob     string  `json:"blob"`
		PWSalt   *string `json:"pw_salt"`
		CodeID   string  `json:"code_id"`
	}
	decode(t, claim, &claimResp)
	if claimResp.Token == "" || claimResp.DeviceID == "" || claimResp.CodeID != codeID {
		t.Fatalf("claim 响应异常: %+v", claimResp)
	}
	if claimResp.PWSalt == nil || *claimResp.PWSalt != crypto.B64(pwSalt) {
		t.Fatalf("claim 未回传 pw_salt: %+v", claimResp.PWSalt)
	}
	gotBlob, err := crypto.ParseB64(claimResp.Blob)
	if err != nil {
		t.Fatalf("blob 不是合法 base64url: %v", err)
	}
	mk, err := pair.OpenBlob(code, claimResp.CodeID, gotBlob)
	if err != nil {
		t.Fatalf("解 blob 失败: %v", err)
	}
	if !bytes.Equal(mk, e.masterKey) {
		t.Fatal("配对解出的 master_key 不一致")
	}

	// 同一配对码二次领取 → 409。
	second := e.claimPair(canonical, "phone2", "android", b.Pub)
	requireStatus(t, second, http.StatusConflict)
	if code := errCode(t, second); code != "code_used" {
		t.Fatalf("错误码应为 code_used，实际 %s", code)
	}
}

// TestPairExpired 验证过期配对码返回 410。
func TestPairExpired(t *testing.T) {
	e := newEnv(t)
	code, canonical, err := pair.NewCode()
	if err != nil {
		t.Fatal(err)
	}
	codeID := "pair-expired-1"
	blob, err := pair.SealBlob(code, codeID, e.masterKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	_, err = e.st.DB().ExecContext(context.Background(),
		`INSERT INTO pairs(code_id, user_id, code_hash, blob, pw_salt, expires_at, used_at, created_at)
		 VALUES(?, ?, ?, ?, ?, ?, NULL, ?)`,
		codeID, e.user.ID, pair.Hash(code), blob, nil, now-1, now-601)
	if err != nil {
		t.Fatalf("构造过期配对码失败: %v", err)
	}

	b := newDevice(t)
	resp := e.claimPair(canonical, "phone", "android", b.Pub)
	requireStatus(t, resp, http.StatusGone)
	if got := errCode(t, resp); got != "code_expired" {
		t.Fatalf("错误码应为 code_expired，实际 %s", got)
	}
}

// TestPairNotFound 验证不存在的配对码返回 404。
func TestPairNotFound(t *testing.T) {
	e := newEnv(t)
	_, canonical, err := pair.NewCode()
	if err != nil {
		t.Fatal(err)
	}
	b := newDevice(t)
	resp := e.claimPair(canonical, "phone", "android", b.Pub)
	requireStatus(t, resp, http.StatusNotFound)
	if got := errCode(t, resp); got != "code_not_found" {
		t.Fatalf("错误码应为 code_not_found，实际 %s", got)
	}
}

// TestPairNewValidation 验证 pair/new 的入参校验。
func TestPairNewValidation(t *testing.T) {
	e := newEnv(t)
	a := e.enroll("desk", "linux")

	bad := []map[string]any{
		{"code_id": "bad id", "code": crypto.Base32Upper(make([]byte, 32)), "blob": crypto.B64(bytes.Repeat([]byte{1}, 48))},
		{"code_id": "ok-1", "code": "!!!", "blob": crypto.B64(bytes.Repeat([]byte{1}, 48))},
		{"code_id": "ok-2", "code": crypto.Base32Upper(make([]byte, 32)), "blob": "!!!"},
	}
	for i, body := range bad {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		resp := e.signedDo(a, http.MethodPost, "/api/v1/pair/new", b)
		requireStatus(t, resp, http.StatusBadRequest)
		if code := errCode(t, resp); code == "" {
			t.Fatalf("case %d 缺少错误码", i)
		}
	}
}
