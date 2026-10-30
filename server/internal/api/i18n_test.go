package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// errorEnvelope 是错误响应的完整结构（code + 本地化 message）。
type errorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// doWithLang 发送带 Accept-Language 的请求并解析错误响应。
func (e *env) doWithLang(t *testing.T, method, path, acceptLanguage string) (int, errorEnvelope) {
	t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, nil)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	if acceptLanguage != "" {
		req.Header.Set("Accept-Language", acceptLanguage)
	}
	resp := e.do(req)
	var body errorEnvelope
	if err := json.Unmarshal(resp.body, &body); err != nil {
		t.Fatalf("解析错误响应失败: %v, body=%s", err, resp.body)
	}
	return resp.status, body
}

// TestErrorMessagesFollowAcceptLanguage 验证同一错误码在 zh/en 下 message 不同、code 不变。
func TestErrorMessagesFollowAcceptLanguage(t *testing.T) {
	e := newEnv(t)

	cases := []struct {
		name   string
		method string
		path   string
		want   string
		status int
	}{
		{"not_found", http.MethodGet, "/api/v1/does-not-exist", "not_found", http.StatusNotFound},
		{"method_not_allowed", http.MethodPut, "/api/v1/items", "method_not_allowed", http.StatusMethodNotAllowed},
		{"missing_token", http.MethodGet, "/api/v1/items", "missing_token", http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			statusZh, bodyZh := e.doWithLang(t, tc.method, tc.path, "zh-CN")
			statusEn, bodyEn := e.doWithLang(t, tc.method, tc.path, "en-US")

			if statusZh != tc.status || statusEn != tc.status {
				t.Fatalf("状态码不匹配: zh=%d en=%d want %d", statusZh, statusEn, tc.status)
			}
			if bodyZh.Error.Code != tc.want || bodyEn.Error.Code != tc.want {
				t.Fatalf("code 不应随语言变化: zh=%q en=%q want %q",
					bodyZh.Error.Code, bodyEn.Error.Code, tc.want)
			}
			if bodyZh.Error.Message == "" || bodyEn.Error.Message == "" {
				t.Fatalf("message 不应为空: zh=%q en=%q", bodyZh.Error.Message, bodyEn.Error.Message)
			}
			if bodyZh.Error.Message == bodyEn.Error.Message {
				t.Fatalf("zh 与 en 的 message 应不同，实际都为 %q", bodyZh.Error.Message)
			}
		})
	}
}

// TestErrorMessageDefaultsToEnglish 验证缺失或无法解析的 Accept-Language 回落英文。
func TestErrorMessageDefaultsToEnglish(t *testing.T) {
	e := newEnv(t)
	_, en := e.doWithLang(t, http.MethodGet, "/api/v1/does-not-exist", "en")

	for _, header := range []string{"", "de-DE", "de-DE, ja;q=0.8", ";;;", "*"} {
		_, got := e.doWithLang(t, http.MethodGet, "/api/v1/does-not-exist", header)
		if got.Error.Code != "not_found" {
			t.Fatalf("header=%q code 不匹配: %q", header, got.Error.Code)
		}
		if got.Error.Message != en.Error.Message {
			t.Fatalf("header=%q 应回落英文 %q，实际 %q", header, en.Error.Message, got.Error.Message)
		}
	}
}

// TestErrorLanguageHonoursQualityValues 验证按 q 值选择权重更高的受支持语言。
func TestErrorLanguageHonoursQualityValues(t *testing.T) {
	e := newEnv(t)
	_, zh := e.doWithLang(t, http.MethodGet, "/api/v1/does-not-exist", "zh")
	_, en := e.doWithLang(t, http.MethodGet, "/api/v1/does-not-exist", "en")

	_, got := e.doWithLang(t, http.MethodGet, "/api/v1/does-not-exist", "en;q=0.3, zh-CN;q=0.9")
	if got.Error.Message != zh.Error.Message {
		t.Fatalf("q 值更高的 zh 应被选中，实际 message=%q", got.Error.Message)
	}

	_, got = e.doWithLang(t, http.MethodGet, "/api/v1/does-not-exist", "zh;q=0.2, en-GB;q=0.8")
	if got.Error.Message != en.Error.Message {
		t.Fatalf("q 值更高的 en 应被选中，实际 message=%q", got.Error.Message)
	}
}
