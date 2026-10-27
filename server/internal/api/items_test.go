package api_test

import (
	"context"
	"net/http"
	"testing"
)

// TestItemsIncrementalPull 验证增量拉取与 next 语义。
func TestItemsIncrementalPull(t *testing.T) {
	e := newEnv(t)
	dev := e.enroll("laptop", "linux")
	nonce := make([]byte, 12)

	resp := e.writeItems(dev, itemPayload("item-1", "totp", "example.com", []byte("ct-1"), nonce, 0, 100, 0))
	requireStatus(t, resp, http.StatusOK)
	var post itemsPost
	decode(t, resp, &post)
	if len(post.Results) != 1 || post.Results[0].Status != "applied" || post.Results[0].Version != 1 {
		t.Fatalf("首次写入结果异常: %+v", post.Results)
	}

	got := e.getItems(dev, 0)
	if len(got.Items) != 1 || got.Next != 1 {
		t.Fatalf("since=0 结果异常: %+v", got)
	}
	if got.Items[0].ID != "item-1" || got.Items[0].Version != 1 || got.Items[0].RPID != "example.com" {
		t.Fatalf("条目字段异常: %+v", got.Items[0])
	}

	got = e.getItems(dev, 1)
	if len(got.Items) != 0 || got.Next != 1 {
		t.Fatalf("since=1 应为空: %+v", got)
	}
}

// TestItemsLWW 验证 LWW 的三种分支与冲突副本落库。
func TestItemsLWW(t *testing.T) {
	e := newEnv(t)
	dev := e.enroll("laptop", "linux")
	nonce := make([]byte, 12)

	// 基线 v1。
	resp := e.writeItems(dev, itemPayload("item-1", "totp", "example.com", []byte("ct-1"), nonce, 0, 100, 0))
	requireStatus(t, resp, http.StatusOK)

	// 正常推进：base_version == 当前 version → applied@2。
	resp = e.writeItems(dev, itemPayload("item-1", "totp", "example.com", []byte("ct-2"), nonce, 1, 200, 0))
	requireStatus(t, resp, http.StatusOK)
	var post itemsPost
	decode(t, resp, &post)
	if post.Results[0].Status != "applied" || post.Results[0].Version != 2 {
		t.Fatalf("base 匹配应 applied@2: %+v", post.Results[0])
	}

	// 分支一：base_version 落后且 updated_at 更旧 → conflict，服务端不变。
	resp = e.writeItems(dev, itemPayload("item-1", "totp", "example.com", []byte("ct-3"), nonce, 1, 50, 0))
	requireStatus(t, resp, http.StatusOK)
	decode(t, resp, &post)
	if post.Results[0].Status != "conflict" || post.Results[0].Version != 2 {
		t.Fatalf("stale 写入应 conflict@2: %+v", post.Results[0])
	}
	conflicts, err := e.st.ConflictsFor(context.Background(), e.user.ID, "item-1")
	if err != nil {
		t.Fatalf("读取冲突失败: %v", err)
	}
	if len(conflicts) != 1 || string(conflicts[0].Ciphertext) != "ct-3" {
		t.Fatalf("落败副本未保存: %+v", conflicts)
	}

	// 分支二：base_version 落后但 updated_at 更新 → applied，旧值进冲突表。
	resp = e.writeItems(dev, itemPayload("item-1", "totp", "example.com", []byte("ct-4"), nonce, 1, 300, 0))
	requireStatus(t, resp, http.StatusOK)
	decode(t, resp, &post)
	if post.Results[0].Status != "applied" || post.Results[0].Version != 3 {
		t.Fatalf("较新写入应 applied@3: %+v", post.Results[0])
	}
	conflicts, err = e.st.ConflictsFor(context.Background(), e.user.ID, "item-1")
	if err != nil {
		t.Fatalf("读取冲突失败: %v", err)
	}
	if len(conflicts) != 2 || string(conflicts[1].Ciphertext) != "ct-2" {
		t.Fatalf("旧值未进冲突表: %+v", conflicts)
	}

	// 分支三：base_version == 当前 version → 无条件应用（无需比较 updated_at）。
	resp = e.writeItems(dev, itemPayload("item-1", "totp", "example.com", []byte("ct-5"), nonce, 3, 10, 0))
	requireStatus(t, resp, http.StatusOK)
	decode(t, resp, &post)
	if post.Results[0].Status != "applied" || post.Results[0].Version != 4 {
		t.Fatalf("base 匹配应 applied@4: %+v", post.Results[0])
	}

	got := e.getItems(dev, 0)
	if len(got.Items) != 1 || got.Items[0].Version != 4 || got.Items[0].CT != "Y3QtNQ" {
		t.Fatalf("最终条目异常: %+v", got.Items)
	}
}

// TestItemsBaseVersionMissing 验证对不存在的条目使用非 0 base_version 时返回 conflict。
func TestItemsBaseVersionMissing(t *testing.T) {
	e := newEnv(t)
	dev := e.enroll("laptop", "linux")

	resp := e.writeItems(dev, itemPayload("ghost", "totp", "example.com", []byte("ct"), make([]byte, 12), 7, 100, 0))
	requireStatus(t, resp, http.StatusOK)
	var post itemsPost
	decode(t, resp, &post)
	if post.Results[0].Status != "conflict" || post.Results[0].Version != 0 {
		t.Fatalf("应返回 conflict@0: %+v", post.Results[0])
	}
}

// TestItemsTooLarge 验证 8 KiB 密文上限。
func TestItemsTooLarge(t *testing.T) {
	e := newEnv(t)
	dev := e.enroll("laptop", "linux")
	nonce := make([]byte, 12)

	resp := e.writeItems(dev, itemPayload("big", "totp", "example.com", make([]byte, 8193), nonce, 0, 100, 0))
	requireStatus(t, resp, http.StatusBadRequest)
	if code := errCode(t, resp); code != "item_too_large" {
		t.Fatalf("错误码应为 item_too_large，实际 %s", code)
	}

	// 恰好 8192 字节应接受。
	resp = e.writeItems(dev, itemPayload("edge", "totp", "example.com", make([]byte, 8192), nonce, 0, 100, 0))
	requireStatus(t, resp, http.StatusOK)
}

// TestItemsValidation 验证结构性非法输入统一 400。
func TestItemsValidation(t *testing.T) {
	e := newEnv(t)
	dev := e.enroll("laptop", "linux")
	nonce := make([]byte, 12)

	cases := []struct {
		name string
		item map[string]any
		code string
	}{
		{"bad_kind", itemPayload("a", "otp", "example.com", []byte("c"), nonce, 0, 1, 0), "invalid_item"},
		{"empty_ct", itemPayload("b", "totp", "example.com", nil, nonce, 0, 1, 0), "invalid_item"},
		{"empty_nonce", itemPayload("c", "totp", "example.com", []byte("c"), nil, 0, 1, 0), "invalid_item"},
		{"empty_rp", itemPayload("d", "totp", "", []byte("c"), nonce, 0, 1, 0), "invalid_item"},
		{"empty_id", itemPayload("", "totp", "example.com", []byte("c"), nonce, 0, 1, 0), "invalid_item"},
		{"negative_base", itemPayload("e", "totp", "example.com", []byte("c"), nonce, -1, 1, 0), "invalid_item"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := e.writeItems(dev, tc.item)
			requireStatus(t, resp, http.StatusBadRequest)
			if code := errCode(t, resp); code != tc.code {
				t.Fatalf("错误码应为 %s，实际 %s", tc.code, code)
			}
		})
	}

	// kind / rp_id 创建后不可改写（语义层拒绝，HTTP 200 + rejected）。
	resp := e.writeItems(dev, itemPayload("fixed", "totp", "example.com", []byte("c"), nonce, 0, 10, 0))
	requireStatus(t, resp, http.StatusOK)
	resp = e.writeItems(dev, itemPayload("fixed", "webauthn", "example.com", []byte("c"), nonce, 1, 20, 0))
	requireStatus(t, resp, http.StatusOK)
	var post itemsPost
	decode(t, resp, &post)
	if post.Results[0].Status != "rejected" || post.Results[0].Reason != "kind_mismatch" {
		t.Fatalf("应 rejected/kind_mismatch: %+v", post.Results[0])
	}
}

// TestItemsTombstone 验证墓碑写入与拉取，以及 health 计数排除墓碑。
func TestItemsTombstone(t *testing.T) {
	e := newEnv(t)
	dev := e.enroll("laptop", "linux")
	nonce := make([]byte, 12)

	resp := e.writeItems(dev, itemPayload("dead", "totp", "example.com", []byte("ct"), nonce, 0, 100, 0))
	requireStatus(t, resp, http.StatusOK)

	resp = e.writeItems(dev, itemPayload("dead", "totp", "example.com", nil, nil, 1, 200, 12345))
	requireStatus(t, resp, http.StatusOK)
	var post itemsPost
	decode(t, resp, &post)
	if post.Results[0].Status != "applied" || post.Results[0].Version != 2 {
		t.Fatalf("墓碑写入应 applied@2: %+v", post.Results[0])
	}

	got := e.getItems(dev, 0)
	if len(got.Items) != 1 || got.Items[0].DeletedAt != 12345 {
		t.Fatalf("墓碑未返回: %+v", got.Items)
	}
	if got.Items[0].CT != "" || got.Items[0].Nonce != "" {
		t.Fatalf("墓碑不应携带密文: %+v", got.Items[0])
	}

	// health 只统计非墓碑条目。
	resp = e.getNoAuth("/api/v1/health")
	requireStatus(t, resp, http.StatusOK)
	var health struct {
		Status  string `json:"status"`
		Version string `json:"version"`
		Items   int64  `json:"items"`
		Devices int64  `json:"devices"`
	}
	decode(t, resp, &health)
	if health.Items != 0 || health.Devices != 1 || health.Status != "ok" {
		t.Fatalf("health 统计异常: %+v", health)
	}
}
