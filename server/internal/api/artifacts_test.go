package api_test

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"xiaoqiong0v0.cn/vkey/server/internal/api"
)

// writeArtifacts 在 dir 下写入产物与 SHA256SUMS（格式同 sha256sum）。
func writeArtifacts(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("创建产物目录失败: %v", err)
	}
	var sums strings.Builder
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("写入产物 %s 失败: %v", name, err)
		}
		sum := sha256.Sum256([]byte(content))
		sums.WriteString(hex.EncodeToString(sum[:]))
		sums.WriteString("  ")
		sums.WriteString(name)
		sums.WriteString("\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums.String()), 0o644); err != nil {
		t.Fatalf("写入 SHA256SUMS 失败: %v", err)
	}
}

// getWithHeaders 发送免鉴权 GET 并返回响应头与 body。
func (e *env) getWithHeaders(path string) (int, http.Header, string) {
	e.t.Helper()
	resp, err := e.srv.Client().Get(e.srv.URL + path)
	if err != nil {
		e.t.Fatalf("请求 %s 失败: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatalf("读取 %s 响应失败: %v", path, err)
	}
	return resp.StatusCode, resp.Header, string(body)
}

// TestArtifactDownload 验证白名单下载、清单与响应头。
func TestArtifactDownload(t *testing.T) {
	dir := t.TempDir()
	content := "fake-tarball-bytes"
	writeArtifacts(t, dir, map[string]string{
		"vkey-hid-linux-x86_64.tar.gz": content,
	})
	e := newEnvOpts(t, func(o *api.Options) { o.ArtifactsDir = dir })

	status, header, body := e.getWithHeaders("/dl/vkey-hid-linux-x86_64.tar.gz")
	if status != http.StatusOK {
		t.Fatalf("下载状态码异常: %d, body=%s", status, body)
	}
	if body != content {
		t.Fatalf("下载内容不匹配: %q", body)
	}
	if ct := header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("Content-Type 异常: %q", ct)
	}
	if cl := header.Get("Content-Length"); cl != strconv.Itoa(len(content)) {
		t.Fatalf("Content-Length 异常: %q", cl)
	}
	if cc := header.Get("Cache-Control"); cc != "no-cache" {
		t.Fatalf("Cache-Control 异常: %q", cc)
	}

	status, header, body = e.getWithHeaders("/dl/SHA256SUMS")
	if status != http.StatusOK {
		t.Fatalf("清单状态码异常: %d", status)
	}
	if ct := header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("清单 Content-Type 异常: %q", ct)
	}
	if !strings.Contains(body, "vkey-hid-linux-x86_64.tar.gz") {
		t.Fatalf("清单缺少产物名: %q", body)
	}

	// 不在 SHA256SUMS 中的文件不可下载。
	if err := os.WriteFile(filepath.Join(dir, "not-listed.bin"), []byte("x"), 0o644); err != nil {
		t.Fatalf("写入非白名单文件失败: %v", err)
	}
	if status, _, _ := e.getWithHeaders("/dl/not-listed.bin"); status != http.StatusNotFound {
		t.Fatalf("非白名单文件应返回 404，实际 %d", status)
	}
}

// TestArtifactTraversal 验证路径穿越被拒绝（编码与非编码形态都必须 404）。
func TestArtifactTraversal(t *testing.T) {
	dir := t.TempDir()
	writeArtifacts(t, dir, map[string]string{"vkey-hid-linux-x86_64.tar.gz": "x"})
	e := newEnvOpts(t, func(o *api.Options) { o.ArtifactsDir = dir })

	paths := []string{
		// 百分号编码的穿越
		"/dl/..%2F..%2Fetc%2Fpasswd",
		"/dl/%2E%2E%2Fetc%2Fpasswd",
		"/dl/..%2FSHA256SUMS",
		"/dl/a%2Fb",
		// 未编码的穿越（不能被 ServeMux 301 成别的路径）
		"/dl/../x",
		"/dl/../../etc/passwd",
		"/dl/a/b",
		// 空名
		"/dl/",
	}
	for _, p := range paths {
		if status, _, body := e.getWithHeaders(p); status != http.StatusNotFound {
			t.Fatalf("%s 应返回 404，实际 %d, body=%s", p, status, body)
		}
	}
}

// TestArtifactMissingDir 验证产物目录缺失时仅 /dl/* 受影响。
func TestArtifactMissingDir(t *testing.T) {
	e := newEnvOpts(t, func(o *api.Options) {
		o.ArtifactsDir = filepath.Join(t.TempDir(), "does-not-exist")
	})

	for _, p := range []string{"/dl/vkey-hid-linux-x86_64.tar.gz", "/dl/SHA256SUMS"} {
		if status, _, _ := e.getWithHeaders(p); status != http.StatusNotFound {
			t.Fatalf("目录缺失时 %s 应返回 404，实际 %d", p, status)
		}
	}
	// 其它接口不受影响。
	if status, _, _ := e.getWithHeaders("/"); status != http.StatusOK {
		t.Fatalf("目录缺失不应影响 /，实际 %d", status)
	}
	if status, _, _ := e.getWithHeaders("/api/v1/policy"); status != http.StatusOK {
		t.Fatalf("目录缺失不应影响 /api/v1/policy，实际 %d", status)
	}
}

// TestArtifactEmptyWhitelist 验证目录存在但无 SHA256SUMS 时返回 404。
func TestArtifactEmptyWhitelist(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "vkey-hid-linux-x86_64.tar.gz"), []byte("x"), 0o644); err != nil {
		t.Fatalf("写入产物失败: %v", err)
	}
	e := newEnvOpts(t, func(o *api.Options) { o.ArtifactsDir = dir })

	for _, p := range []string{"/dl/vkey-hid-linux-x86_64.tar.gz", "/dl/SHA256SUMS"} {
		if status, _, _ := e.getWithHeaders(p); status != http.StatusNotFound {
			t.Fatalf("无清单时 %s 应返回 404，实际 %d", p, status)
		}
	}
}
