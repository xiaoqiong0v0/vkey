package api_test

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
)

// TestPolicy 验证 /policy 返回协议固定 KDF 与账号提示。
func TestPolicy(t *testing.T) {
	e := newEnv(t)

	resp := e.getNoAuth("/api/v1/policy")
	requireStatus(t, resp, http.StatusOK)
	var p struct {
		RequireMasterPW bool `json:"require_master_pw"`
		KDF             struct {
			M int `json:"m"`
			T int `json:"t"`
			P int `json:"p"`
		} `json:"kdf"`
		UsernameHint string `json:"username_hint"`
	}
	decode(t, resp, &p)
	if p.RequireMasterPW {
		t.Fatal("默认策略应为不强制主密码")
	}
	if p.KDF.M != 65536 || p.KDF.T != 3 || p.KDF.P != 1 {
		t.Fatalf("KDF 参数异常: %+v", p.KDF)
	}
	if p.UsernameHint != "default" {
		t.Fatalf("username_hint 异常: %q", p.UsernameHint)
	}

	// 改策略后立即生效（客户端每次启动必查）。
	if err := e.st.SetRequireMasterPW(context.Background(), e.user.ID, true); err != nil {
		t.Fatalf("设置策略失败: %v", err)
	}
	resp = e.getNoAuth("/api/v1/policy")
	requireStatus(t, resp, http.StatusOK)
	decode(t, resp, &p)
	if !p.RequireMasterPW {
		t.Fatal("策略未生效")
	}
}

// TestWebPages 验证主页与引导脚本可访问且注入了 server_url。
func TestWebPages(t *testing.T) {
	e := newEnv(t)
	e.enroll("laptop", "linux")

	checks := []struct {
		path string
		want []string
	}{
		{"/", []string{
			"vkey 服务端自检", "https://vkey.test", "不生成验证码",
			// 主页是唯一入口：手机配置 + Android 下载 + Linux 安装三处链接齐备。
			"手机配置", `src="/pair/qr.png"`, "/dl/vkey-android.apk", "/install.sh",
		}},
		{"/install.sh", []string{`SERVER_URL="https://vkey.test"`, "uname -m", "vkey-hid-linux-${ARCH}.tar.gz"}},
		{"/install.ps1", []string{`$ServerUrl = "https://vkey.test"`, "PROCESSOR_ARCHITECTURE", "/dl/vkey-win-"}},
	}
	for _, c := range checks {
		resp := e.getNoAuth(c.path)
		requireStatus(t, resp, http.StatusOK)
		body := string(resp.body)
		for _, want := range c.want {
			if !strings.Contains(body, want) {
				t.Fatalf("%s 缺少内容 %q", c.path, want)
			}
		}
	}
}

// TestPairRedirectsToIndex 验证旧配对页 /pair 永久重定向到主页。
func TestPairRedirectsToIndex(t *testing.T) {
	e := newEnv(t)

	resp, location := e.getNoRedirect("/pair")
	requireStatus(t, resp, http.StatusMovedPermanently)
	if location != "/" {
		t.Fatalf("/pair 应跳转到 /，实际 %q", location)
	}
}

// TestPairQRStillServed 验证主页引用的 /pair/qr.png 仍然可用。
func TestPairQRStillServed(t *testing.T) {
	e := newEnv(t)

	resp := e.getNoAuth("/pair/qr.png")
	requireStatus(t, resp, http.StatusOK)
	if !bytes.HasPrefix(resp.body, pngMagic) {
		t.Fatal("/pair/qr.png 应返回 PNG")
	}
}

// TestIndexPairSection 验证 `/` 页直接展示同步配置二维码与可复制深链，且不含凭据。
func TestIndexPairSection(t *testing.T) {
	e := newEnv(t)

	resp := e.getNoAuth("/")
	requireStatus(t, resp, http.StatusOK)
	body := string(resp.body)

	deepLink := "vkey://config?server=https://vkey.test"
	for _, want := range []string{
		"手机配置",
		"同步配置二维码",
		"自动填好地址",
		`<img src="/pair/qr.png"`,
		deepLink,
		"readonly",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("/ 缺少内容 %q", want)
		}
	}

	// 深链只带地址：出现且仅出现一次，且不追加任何查询参数。
	if n := strings.Count(body, "vkey://config"); n != 1 {
		t.Fatalf("深链应只出现一次，实际 %d 次", n)
	}
	if strings.Contains(body, deepLink+"&") {
		t.Fatal("深链不应附加额外查询参数")
	}

	// 页面绝不出现服务端不持有的凭据字段名（零知识）。
	for _, bad := range []string{"master_key", "wrapped_key", "pw_salt", "token"} {
		if strings.Contains(body, bad) {
			t.Fatalf("/ 页面不应出现 %q", bad)
		}
	}
}

// TestAPINotFound 验证 /api/ 下的未知路径返回 JSON 错误。
func TestAPINotFound(t *testing.T) {
	e := newEnv(t)
	resp := e.getNoAuth("/api/v1/does-not-exist")
	requireStatus(t, resp, http.StatusNotFound)
	if code := errCode(t, resp); code != "not_found" {
		t.Fatalf("错误码应为 not_found，实际 %s", code)
	}
}
