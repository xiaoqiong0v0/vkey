package api_test

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"xiaoqiong0v0.cn/vkey/server/internal/api"
	"xiaoqiong0v0.cn/vkey/server/internal/crypto"
	"xiaoqiong0v0.cn/vkey/server/internal/policy"
)

// joinGet 请求 /join* 并返回响应（保留 header 供断言），body 全量读出。
func joinGet(t *testing.T, e *env, path string) (*http.Response, []byte) {
	t.Helper()
	resp, err := e.srv.Client().Get(e.srv.URL + path)
	if err != nil {
		t.Fatalf("请求 %s 失败: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}
	return resp, body
}

// newJoinAdminEnv 构造 admin 模式环境并签发绑定 alice 的开户码，返回环境+明文。
func newJoinAdminEnv(t *testing.T, ttl int64) (*env, string) {
	t.Helper()
	e := newAdminEnv(t, nil)
	plain := issueCode(t, e, "alice", time.Now().Unix(), ttl)
	return e, plain
}

// TestJoinPageValidCode 校验 admin 模式 + 合法未用码 → 200：
// 页面含同源二维码 img、开户深链、明文码与按实际 TTL 的文案，响应头符合契约。
func TestJoinPageValidCode(t *testing.T) {
	e, plain := newJoinAdminEnv(t, policy.EnrollTTLSeconds)
	resp, body := joinGet(t, e, "/join?c="+plain)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d, body=%s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q", ct)
	}
	for h, want := range map[string]string{
		"Cache-Control":          "no-store",
		"Referrer-Policy":        "no-referrer",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := resp.Header.Get(h); got != want {
			t.Fatalf("%s = %q，期望 %q", h, got, want)
		}
	}
	s := string(body)
	for _, want := range []string{
		"<title>vkey 开户</title>",
		`src="/join/qr.png?c=` + plain,
		// href 中 & 由模板转义为 &amp;；vkey:// 自定义 scheme 不得被过滤成 #ZgotmplZ。
		"vkey://enroll?server=https://vkey.test&amp;code=" + plain,
		plain,   // 明文码供手抄
		"30 分钟", // 按实际签发 TTL
		"打开 vkey App",
		"下载二维码",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("页面缺少 %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "#ZgotmplZ") {
		t.Fatalf("深链被 URL 过滤器拦截:\n%s", s)
	}
	// 页面上绝不出现 master_key/token/verifier 的编码值（字段名说明允许）。
	for _, forbid := range []string{
		crypto.Base32Upper(e.masterKey), crypto.B64(e.masterKey), crypto.B64(e.user.Verifier),
	} {
		if strings.Contains(s, forbid) {
			t.Fatal("页面泄露敏感值")
		}
	}
}

// TestJoinPageSingleMode4xx 校验 single 模式下即使码存在也返回 4xx 统一文案。
func TestJoinPageSingleMode4xx(t *testing.T) {
	e := newEnv(t)
	plain := issueCode(t, e, "alice", time.Now().Unix(), 1800)
	resp, body := joinGet(t, e, "/join?c="+plain)
	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		t.Fatalf("single 模式应 4xx，实际 %d", resp.StatusCode)
	}
	if !bytes.Contains(body, []byte("链接无效或已过期")) {
		t.Fatalf("错误文案异常: %s", body)
	}
}

// TestJoinPageBadCodes 校验缺参/不存在/过期/已撤销统一 4xx 且文案一致（防枚举）。
func TestJoinPageBadCodes(t *testing.T) {
	e, _ := newJoinAdminEnv(t, 1800)
	ctx := context.Background()

	expired := issueCode(t, e, "ghost", time.Now().Add(-time.Hour).Unix(), 60)
	rec, revokedPlain, err := e.st.CreateEnrollCode(ctx, "revoked", 1800, time.Now().Unix())
	if err != nil {
		t.Fatalf("CreateEnrollCode: %v", err)
	}
	if err := e.st.RevokeEnrollCode(ctx, rec.ID, time.Now().Unix()); err != nil {
		t.Fatalf("RevokeEnrollCode: %v", err)
	}

	cases := []struct {
		name   string
		path   string
		status int
	}{
		{"缺参数", "/join", http.StatusBadRequest},
		{"空参数", "/join?c=", http.StatusBadRequest},
		{"不存在", "/join?c=ENROLL-ZZZZ-ZZZZ", http.StatusNotFound},
		{"过期", "/join?c=" + expired, http.StatusNotFound},
		{"已撤销", "/join?c=" + revokedPlain, http.StatusNotFound},
	}
	for _, c := range cases {
		resp, body := joinGet(t, e, c.path)
		if resp.StatusCode != c.status {
			t.Fatalf("%s: 状态码 = %d，期望 %d, body=%s", c.name, resp.StatusCode, c.status, body)
		}
		if !bytes.Contains(body, []byte("链接无效或已过期")) {
			t.Fatalf("%s: 错误文案异常: %s", c.name, body)
		}
		// 错误页不得回显任何输入。
		if c.name == "已撤销" && bytes.Contains(body, []byte(revokedPlain)) {
			t.Fatal("错误页不得回显开户码")
		}
	}
}

// TestJoinQRPNG 校验二维码端点返回非空 image/png 且带下载文件名。
func TestJoinQRPNG(t *testing.T) {
	e, plain := newJoinAdminEnv(t, 1800)
	resp, body := joinGet(t, e, "/join/qr.png?c="+plain)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d, body=%s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "image/png" {
		t.Fatalf("Content-Type = %q", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") ||
		!strings.Contains(cd, "vkey-enroll.png") {
		t.Fatalf("Content-Disposition = %q", cd)
	}
	if len(body) < 100 || !bytes.HasPrefix(body, []byte("\x89PNG")) {
		t.Fatalf("PNG 内容异常: len=%d", len(body))
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q", cc)
	}
}

// TestJoinQRBadCode 校验无效码（single 模式）的二维码请求同样 4xx。
func TestJoinQRBadCode(t *testing.T) {
	e := newEnv(t)
	resp, body := joinGet(t, e, "/join/qr.png?c=ENROLL-ZZZZ-ZZZZ")
	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		t.Fatalf("应 4xx，实际 %d, body=%s", resp.StatusCode, body)
	}
}

// TestJoinLogRedacted 校验访问日志对 /join* 只记路径、不记 query（开户码脱敏）。
func TestJoinLogRedacted(t *testing.T) {
	var buf bytes.Buffer
	e := newEnvOpts(t, func(o *api.Options) { o.Logger = log.New(&buf, "", 0) })
	if err := e.st.SetUserMode(context.Background(), policy.UserModeAdmin); err != nil {
		t.Fatal(err)
	}
	plain := issueCode(t, e, "carol", time.Now().Unix(), 1800)

	resp, _ := joinGet(t, e, "/join?c="+plain+"&probe=SECRET-EXTRA")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("合法码应 200，实际 %d", resp.StatusCode)
	}
	resp, _ = joinGet(t, e, "/join/qr.png?c="+plain)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("二维码应 200，实际 %d", resp.StatusCode)
	}

	logs := buf.String()
	for _, forbid := range []string{plain, "SECRET-EXTRA", "c="} {
		if strings.Contains(logs, forbid) {
			t.Fatalf("日志泄露 %q:\n%s", forbid, logs)
		}
	}
	for _, want := range []string{"GET /join -> 200", "GET /join/qr.png -> 200"} {
		if !strings.Contains(logs, want) {
			t.Fatalf("日志缺少 %q:\n%s", want, logs)
		}
	}
}
