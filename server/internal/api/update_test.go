package api_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"xiaoqiong0v0.cn/vkey/server/internal/store"
)

// testSHA256 是测试用 APK 摘要（64 位小写 hex）。
const testSHA256 = "3f786850e387550fdab836ed7e6dc881de23001b2b0f4d1ad1e0c1e7b6d4b3f0"

// TestUpdateAndroidNotConfigured 验证未配置更新信息时返回 204 且无正文。
func TestUpdateAndroidNotConfigured(t *testing.T) {
	e := newEnv(t)
	resp, header := e.getWithHeader(http.MethodGet, "/api/v1/update/android")
	requireStatus(t, resp, http.StatusNoContent)
	if len(resp.body) != 0 {
		t.Fatalf("204 不应有正文，实际 %q", resp.body)
	}
	if cc := header.Get("Cache-Control"); cc != "public, max-age=300" {
		t.Fatalf("Cache-Control = %q", cc)
	}
}

// TestUpdateAndroidGitHub 验证默认 github 源返回 200 与 Releases 下载地址。
func TestUpdateAndroidGitHub(t *testing.T) {
	e := newEnv(t)
	// 只写 version_code + sha256 即视为已配置，其余取缺省值（github / 默认仓库与产物名）。
	e.setMeta(store.MetaKeyUpdateVersionCode, "30101")
	e.setMeta(store.MetaKeyUpdateVersionName, "0.3.2")
	e.setMeta(store.MetaKeyUpdateSHA256, testSHA256)
	e.setMeta(store.MetaKeyUpdateSize, "8388608")
	e.setMeta(store.MetaKeyUpdateNotes, "首个公开版本")

	resp, header := e.getWithHeader(http.MethodGet, "/api/v1/update/android")
	requireStatus(t, resp, http.StatusOK)
	if cc := header.Get("Cache-Control"); cc != "public, max-age=300" {
		t.Fatalf("Cache-Control = %q", cc)
	}

	var out struct {
		VersionCode int64  `json:"version_code"`
		VersionName string `json:"version_name"`
		URL         string `json:"url"`
		SHA256      string `json:"sha256"`
		Size        int64  `json:"size"`
		Notes       string `json:"notes"`
		Source      string `json:"source"`
		PublishedAt int64  `json:"published_at"`
	}
	decode(t, resp, &out)

	const wantPrefix = "https://github.com/xiaoqiong0v0/vkey/releases/latest/download/"
	if !strings.HasPrefix(out.URL, wantPrefix) {
		t.Fatalf("url = %q，期望前缀 %q", out.URL, wantPrefix)
	}
	if !strings.HasSuffix(out.URL, "/vkey-android.apk") {
		t.Fatalf("url = %q，期望以 /vkey-android.apk 结尾", out.URL)
	}
	if out.VersionCode != 30101 || out.VersionName != "0.3.2" {
		t.Fatalf("版本字段不匹配: %+v", out)
	}
	if out.SHA256 != testSHA256 || out.Size != 8388608 || out.Notes != "首个公开版本" {
		t.Fatalf("产物字段不匹配: %+v", out)
	}
	if out.Source != store.UpdateSourceGitHub {
		t.Fatalf("source = %q", out.Source)
	}
}

// TestUpdateAndroidLocalSource 验证 source=local 时 url 指向本服务 /dl/<asset>。
func TestUpdateAndroidLocalSource(t *testing.T) {
	e := newEnv(t)
	e.setMeta(store.MetaKeyUpdateSource, store.UpdateSourceLocal)
	e.setMeta(store.MetaKeyUpdateVersionCode, "30101")
	e.setMeta(store.MetaKeyUpdateSHA256, testSHA256)

	resp, _ := e.getWithHeader(http.MethodGet, "/api/v1/update/android")
	requireStatus(t, resp, http.StatusOK)
	var out struct {
		URL    string `json:"url"`
		Source string `json:"source"`
	}
	decode(t, resp, &out)

	// testEnv 固定 Domain=https://vkey.test（见 testenv_test.go）。
	if want := "https://vkey.test/dl/vkey-android.apk"; out.URL != want {
		t.Fatalf("url = %q，期望 %q", out.URL, want)
	}
	if out.Source != store.UpdateSourceLocal {
		t.Fatalf("source = %q", out.Source)
	}
}

// TestUpdateAndroidIncompleteConfig 验证缺 version_code 或 sha256 时仍返回 204。
func TestUpdateAndroidIncompleteConfig(t *testing.T) {
	tests := []struct {
		name string
		key  string
		val  string
	}{
		{name: "只配 version_code 缺 sha256", key: store.MetaKeyUpdateVersionCode, val: "30101"},
		{name: "只配 sha256 缺 version_code", key: store.MetaKeyUpdateSHA256, val: testSHA256},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.setMeta(tc.key, tc.val)
			resp, _ := e.getWithHeader(http.MethodGet, "/api/v1/update/android")
			requireStatus(t, resp, http.StatusNoContent)
			if len(resp.body) != 0 {
				t.Fatalf("204 不应有正文，实际 %q", resp.body)
			}
		})
	}
}

// TestUpdateAndroidMethodNotAllowed 验证 POST 返回 405 与 Allow: GET。
func TestUpdateAndroidMethodNotAllowed(t *testing.T) {
	e := newEnv(t)
	resp, header := e.doWithHeader(http.MethodPost, "/api/v1/update/android", strings.NewReader("{}"))
	requireStatus(t, resp, http.StatusMethodNotAllowed)
	if code := errCode(t, resp); code != "method_not_allowed" {
		t.Fatalf("error.code = %q", code)
	}
	if allow := header.Get("Allow"); allow != "GET" {
		t.Fatalf("Allow = %q", allow)
	}
}

// ---------------------------------------------------------------------------
// 测试辅助
// ---------------------------------------------------------------------------

// setMeta 直接写一条 meta 键值（模拟 CLI 配置结果）。
func (e *env) setMeta(key, value string) {
	e.t.Helper()
	if err := e.st.SetMeta(context.Background(), key, value); err != nil {
		e.t.Fatalf("写入 meta %s 失败: %v", key, err)
	}
}

// getWithHeader 发送免鉴权 GET 并返回响应与响应头。
func (e *env) getWithHeader(method, path string) (response, http.Header) {
	e.t.Helper()
	return e.doWithHeader(method, path, nil)
}

// doWithHeader 发送免鉴权请求并返回响应与响应头。
func (e *env) doWithHeader(method, path string, body io.Reader) (response, http.Header) {
	e.t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, body)
	if err != nil {
		e.t.Fatalf("构造请求失败: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatalf("请求 %s 失败: %v", path, err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return response{status: res.StatusCode, body: b}, res.Header
}
