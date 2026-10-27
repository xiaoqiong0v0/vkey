package api_test

import (
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

// TestWebPages 验证自检页、配对页与引导脚本可访问且注入了 server_url。
func TestWebPages(t *testing.T) {
	e := newEnv(t)
	e.enroll("laptop", "linux")

	checks := []struct {
		path string
		want []string
	}{
		{"/", []string{"vkey 服务端自检", "https://vkey.test", "不生成验证码"}},
		{"/pair", []string{"vkey 设备配对", "https://vkey.test", "/dl/vkey-android.apk"}},
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

// TestAPINotFound 验证 /api/ 下的未知路径返回 JSON 错误。
func TestAPINotFound(t *testing.T) {
	e := newEnv(t)
	resp := e.getNoAuth("/api/v1/does-not-exist")
	requireStatus(t, resp, http.StatusNotFound)
	if code := errCode(t, resp); code != "not_found" {
		t.Fatalf("错误码应为 not_found，实际 %s", code)
	}
}
