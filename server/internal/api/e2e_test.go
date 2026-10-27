package api_test

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"xiaoqiong0v0.cn/vkey/server/internal/crypto"
	"xiaoqiong0v0.cn/vkey/server/internal/pair"
)

// TestEndToEndSync 覆盖 M1 闭环：
// init → A 认证 → A 生成配对码 → B 领取并解出 master_key → B 认证 →
// A 写条目 → B 拉取并解密。
func TestEndToEndSync(t *testing.T) {
	e := newEnv(t)

	// 1) 设备 A 用 verifier 上线。
	a := e.enroll("desk", "linux")

	// 2) A 生成配对码并用 PairKEK 包裹 master_key。
	code, _, err := pair.NewCode()
	if err != nil {
		t.Fatal(err)
	}
	codeID := "pair-e2e-1"
	blob, err := pair.SealBlob(code, codeID, e.masterKey)
	if err != nil {
		t.Fatal(err)
	}
	resp := e.pairNew(a, codeID, code, blob, nil)
	requireStatus(t, resp, http.StatusOK)

	// 3) 设备 B 领取配对码（用带 '-' 的展示形式，验证规范化）。
	b := newDevice(t)
	claimResp := e.claimPair(pair.Display(code), "phone", "android", b.Pub)
	requireStatus(t, claimResp, http.StatusOK)
	var claim struct {
		Token    string  `json:"token"`
		DeviceID string  `json:"device_id"`
		Blob     string  `json:"blob"`
		PWSalt   *string `json:"pw_salt"`
		CodeID   string  `json:"code_id"`
	}
	decode(t, claimResp, &claim)
	if claim.PWSalt != nil {
		t.Fatalf("未设置主密码时不应返回 pw_salt: %v", *claim.PWSalt)
	}

	// 4) B 用 blob 解出 master_key。
	rawBlob, err := crypto.ParseB64(claim.Blob)
	if err != nil {
		t.Fatal(err)
	}
	masterKeyB, err := pair.OpenBlob(code, claim.CodeID, rawBlob)
	if err != nil {
		t.Fatalf("B 解 blob 失败: %v", err)
	}
	if !bytes.Equal(masterKeyB, e.masterKey) {
		t.Fatal("B 解出的 master_key 与 A 不一致")
	}

	// 5) B 用自己算出的 verifier 换取正式 token（覆盖领取时签发的临时 token）。
	verifierB, err := crypto.Verifier(masterKeyB, "default")
	if err != nil {
		t.Fatal(err)
	}
	authResp := e.postJSON("/api/v1/auth/token", map[string]any{
		"username": "default",
		"verifier": crypto.B64(verifierB),
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
	if auth.DeviceID != claim.DeviceID {
		t.Fatalf("同一公钥应复用设备 id: got %s want %s", auth.DeviceID, claim.DeviceID)
	}

	// 领取时签发的临时 token 已被覆盖（协议明示：重新认证作废旧 token）。
	staleDev := &testDevice{Token: claim.Token, Priv: b.Priv, Pub: b.Pub}
	resp = e.signedDo(staleDev, http.MethodGet, "/api/v1/items", nil)
	requireStatus(t, resp, http.StatusUnauthorized)

	b.Token = auth.Token
	b.ID = auth.DeviceID

	// 6) A 写一条 TOTP 条目（客户端侧加密）。
	plaintext := []byte(`{"kind":"totp","label":"e2e@example.com","issuer":"E2E","secret":"JBSWY3DPEHPK3PXP","algorithm":"SHA1","digits":6,"period":30}`)
	itemID := "e2e-item-1"
	nonce := bytes.Repeat([]byte{0x42}, crypto.NonceLen)
	itemKey, err := crypto.ItemKey(e.masterKey, itemID)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := crypto.Seal(itemKey, nonce, plaintext, crypto.ItemAAD(itemID))
	if err != nil {
		t.Fatal(err)
	}
	writeResp := e.writeItems(a, itemPayload(itemID, "totp", "example.com", ct, nonce, 0, time.Now().Unix(), 0))
	requireStatus(t, writeResp, http.StatusOK)
	var write itemsPost
	decode(t, writeResp, &write)
	if write.Results[0].Status != "applied" || write.Results[0].Version != 1 {
		t.Fatalf("A 写入结果异常: %+v", write.Results[0])
	}

	// 7) B 自增拉取并解密成功。
	pulled := e.getItems(b, 0)
	if len(pulled.Items) != 1 || pulled.Next != 1 {
		t.Fatalf("B 拉取结果异常: %+v", pulled)
	}
	wire := pulled.Items[0]
	if wire.ID != itemID || wire.Kind != "totp" || wire.RPID != "example.com" {
		t.Fatalf("B 拉到的条目字段异常: %+v", wire)
	}
	gotCT, err := crypto.ParseB64(wire.CT)
	if err != nil {
		t.Fatal(err)
	}
	gotNonce, err := crypto.ParseB64(wire.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	itemKeyB, err := crypto.ItemKey(masterKeyB, wire.ID)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := crypto.Open(itemKeyB, gotNonce, gotCT, crypto.ItemAAD(wire.ID))
	if err != nil {
		t.Fatalf("B 解密失败: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("B 解出的明文不一致:\n got %s\nwant %s", decrypted, plaintext)
	}

	// 交叉校验：换 item_id 派生密钥必须解不开（AAD/密钥双绑定）。
	wrongKey, err := crypto.ItemKey(masterKeyB, "other-item")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.Open(wrongKey, gotNonce, gotCT, crypto.ItemAAD("other-item")); err == nil {
		t.Fatal("错误 item_id 不应解密成功")
	}
}
