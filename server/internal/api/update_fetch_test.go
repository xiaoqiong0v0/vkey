package api

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// TestValidateUpdateURL 验证只放行 https + GitHub 域名（防 SSRF）。
func TestValidateUpdateURL(t *testing.T) {
	ok := []string{
		"https://github.com/xiaoqiong0v0/vkey/releases/latest/download/android.json",
		"https://objects.githubusercontent.com/github-production-release-asset/x",
		"https://release-assets.githubusercontent.com/github-production-release-asset/x",
	}
	for _, raw := range ok {
		if err := validateUpdateURL(raw); err != nil {
			t.Fatalf("%q 应被放行，实际 %v", raw, err)
		}
	}

	bad := []string{
		"http://github.com/x/y",                         // 非 https
		"https://evil.com/x",                            // 非 github 域名
		"https://github.com.evil.com/x",                 // 后缀伪装
		"https://127.0.0.1/x",                           // 内网地址
		"https://169.254.169.254/latest/meta-data",      // 云元数据
		"https://user:pw@github.com/x",                  // 携带用户信息
		"file:///etc/passwd",                            // 非网络 scheme
		"https://githubusercontent.com.evil.com/a.json", // 伪 CDN 后缀
	}
	for _, raw := range bad {
		if err := validateUpdateURL(raw); err == nil {
			t.Fatalf("%q 应被拒绝", raw)
		}
	}
}

// TestHTTPUpdateFetcherRejectsBeforeConnect 验证非法地址在发起连接前就被拒绝。
func TestHTTPUpdateFetcherRejectsBeforeConnect(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		raw  string
		want string
	}{
		{"http://github.com/x/y", "必须是 https"},
		{"https://127.0.0.1:9/android.json", "域名不允许"},
		{"https://evil.example/x", "域名不允许"},
	}
	for _, tc := range cases {
		if _, err := httpUpdateFetcher(ctx, tc.raw); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%q 的错误 = %v，期望包含 %q", tc.raw, err, tc.want)
		}
	}
}

// TestReadUpdateBodyLimit 验证响应体 8 KiB 上限。
func TestReadUpdateBodyLimit(t *testing.T) {
	if _, err := readUpdateBody(bytes.NewReader(make([]byte, updateFetchMaxBytes))); err != nil {
		t.Fatalf("恰好 8 KiB 应通过，实际 %v", err)
	}
	if _, err := readUpdateBody(bytes.NewReader(make([]byte, updateFetchMaxBytes+1))); err == nil {
		t.Fatal("超过 8 KiB 应报错")
	}
}

// TestParseUpdateMetadata 验证 android.json 的解析与字段校验。
func TestParseUpdateMetadata(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	md, err := parseUpdateMetadata([]byte(`{"version_code":30101,"version_name":" 0.3.2 ",
		"sha256":"` + strings.ToUpper(sha) + `","size":34485070,"published_at":1793256000}`))
	if err != nil {
		t.Fatalf("合法响应解析失败: %v", err)
	}
	if md.VersionCode != 30101 || md.VersionName != "0.3.2" || md.SHA256 != sha ||
		md.Size != 34485070 || md.PublishedAt != 1793256000 {
		t.Fatalf("解析结果不匹配: %+v", md)
	}

	bad := map[string]string{
		"非 JSON":         `not json`,
		"缺 version_code": `{"version_name":"0.3.2","sha256":"` + sha + `","size":1}`,
		"缺 sha256":       `{"version_code":30101,"version_name":"0.3.2","size":1}`,
		"sha256 长度错":     `{"version_code":30101,"version_name":"0.3.2","sha256":"abcd","size":1}`,
		"负 size":         `{"version_code":30101,"version_name":"0.3.2","sha256":"` + sha + `","size":-1}`,
		"尾部垃圾":           `{"version_code":30101,"version_name":"0.3.2","sha256":"` + sha + `","size":1} x`,
	}
	for name, body := range bad {
		if _, err := parseUpdateMetadata([]byte(body)); err == nil {
			t.Fatalf("%s 应报错", name)
		}
	}
}

// TestSanitizeUpdateCheckError 验证失败原因被压成单行并截断。
func TestSanitizeUpdateCheckError(t *testing.T) {
	msg := sanitizeUpdateCheckError(errString("第一行\n第二行\r\n" + strings.Repeat("长", 400)))
	if strings.ContainsAny(msg, "\r\n\t") {
		t.Fatalf("失败原因应压成单行: %q", msg)
	}
	if n := len([]rune(msg)); n > updateCheckErrorMaxLen {
		t.Fatalf("失败原因长度 = %d，超过上限 %d", n, updateCheckErrorMaxLen)
	}
}

// errString 是最小 error 实现（避免为单个用例引入额外依赖）。
type errString string

// Error 实现 error。
func (e errString) Error() string { return string(e) }
