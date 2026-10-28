package api_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	qrcode "github.com/skip2/go-qrcode"

	"xiaoqiong0v0.cn/vkey/server/internal/api"
)

// pngMagic 是 PNG 文件头（8 字节签名）。
var pngMagic = []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}

// fetchQR 请求 /pair/qr.png 并返回完整响应（含响应头）。
func fetchQR(t *testing.T, e *env) (*http.Response, []byte) {
	t.Helper()
	resp, err := e.srv.Client().Get(e.srv.URL + "/pair/qr.png")
	if err != nil {
		t.Fatalf("请求 /pair/qr.png 失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取 /pair/qr.png 响应失败: %v", err)
	}
	return resp, body
}

// serveDirect 绕过 http.Client 的 Host 校验，把请求直接交给 handler 处理。
//
// http.Client 会在传输层拒绝含引号/尖括号的 Host，只有直连 handler 才能验证
// sanitizeHost 的白名单过滤。返回状态码、响应头与响应体。
func serveDirect(t *testing.T, e *env, path, host string) (int, http.Header, []byte) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://vkey.test"+path, nil)
	req.Host = host
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	e.srv.Config.Handler.ServeHTTP(rr, req)
	res := rr.Result()
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("读取 %s 响应失败: %v", path, err)
	}
	return res.StatusCode, res.Header, body
}

// expectQR 断言响应是内容为深链的二维码 PNG。
func expectQR(t *testing.T, status int, hdr http.Header, body []byte, deepLink string) {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("二维码状态码异常: got %d want 200", status)
	}
	if ct := hdr.Get("Content-Type"); !strings.HasPrefix(ct, "image/png") {
		t.Fatalf("二维码 Content-Type 异常: %q", ct)
	}
	if cc := hdr.Get("Cache-Control"); cc != "no-cache" {
		t.Fatalf("二维码 Cache-Control 应为 no-cache，实际 %q", cc)
	}
	if len(body) == 0 {
		t.Fatal("二维码响应体为空")
	}
	if !bytes.HasPrefix(body, pngMagic) {
		t.Fatalf("二维码不是合法 PNG（头部 % x）", body[:min(8, len(body))])
	}
	// 与 handlePairQR 的编码参数（Medium / 512px）保持一致，逐字节锁定编码内容：
	// 只有这样才能验证像素里装的确实是深链，而不是任意图片。
	want, err := qrcode.Encode(deepLink, qrcode.Medium, 512)
	if err != nil {
		t.Fatalf("生成对照二维码失败: %v", err)
	}
	if !bytes.Equal(body, want) {
		t.Fatalf("二维码内容与深链不一致（length got=%d want=%d）", len(body), len(want))
	}
}

// TestPairQRPNG 验证 /pair/qr.png 返回编码了深链的 PNG。
func TestPairQRPNG(t *testing.T) {
	e := newEnv(t)

	resp, body := fetchQR(t, e)
	expectQR(t, resp.StatusCode, resp.Header, body, "vkey://config?server=https://vkey.test")
}

// TestPairQRHostInjection 验证带引号/尖括号的 Host 不会进入主页与二维码。
func TestPairQRHostInjection(t *testing.T) {
	// Domain 置空 → 地址由请求 Host + X-Forwarded-Proto 推导（与 /install.sh 同源逻辑）。
	e := newEnvOpts(t, func(o *api.Options) { o.Domain = "" })
	const evilHost = `evil"><script>alert(1)</script>.test`
	const sanitized = "https://evilscriptalert1script.test"

	status, _, pageBody := serveDirect(t, e, "/", evilHost)
	if status != http.StatusOK {
		t.Fatalf("/ 状态码异常: %d", status)
	}
	page := string(pageBody)
	if !strings.Contains(page, "vkey://config?server="+sanitized) {
		t.Fatalf("主页深链未使用过滤后的主机名: %s", sanitized)
	}
	for _, bad := range []string{"<script", `evil"`, "alert("} {
		if strings.Contains(page, bad) {
			t.Fatalf("主页残留未过滤内容 %q", bad)
		}
	}

	qrStatus, qrHdr, qrBody := serveDirect(t, e, "/pair/qr.png", evilHost)
	expectQR(t, qrStatus, qrHdr, qrBody, "vkey://config?server="+sanitized)
}
