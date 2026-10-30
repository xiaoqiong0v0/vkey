package api

import (
	"net/http"
	"strconv"
	"strings"
)

// 支持的响应语言标识。
const (
	langZh = "zh"
	langEn = "en"
)

// defaultLang 是 Accept-Language 缺失或无法解析时的回落语言（默认英文）。
const defaultLang = langEn

// fallbackMessage 是未知错误码的兜底文案（默认英文，与 defaultLang 一致）。
const fallbackMessage = "Request failed"

// langOf 从 Accept-Language 解析客户端首选语言。
//
// 支持 `zh`、`zh-CN`、`en`、`en-US` 及带 q 值的组合；`zh*` 归一为 `zh`，
// `en*` 归一为 `en`。缺失或无法解析时返回 [defaultLang]。
func langOf(r *http.Request) string {
	if r == nil {
		return defaultLang
	}
	return parseLang(r.Header.Get("Accept-Language"))
}

// parseLang 解析 Accept-Language 头，返回 q 值最高且受支持的语言标识。
func parseLang(header string) string {
	best, bestQ := "", -1.0
	for _, part := range strings.Split(header, ",") {
		tag, q := parseLanguageEntry(part)
		if tag == "" || q <= 0 {
			continue
		}
		// 同权重时保留先出现的语言（浏览器按偏好降序发送）。
		if q > bestQ {
			best, bestQ = tag, q
		}
	}
	if best == "" {
		return defaultLang
	}
	return best
}

// parseLanguageEntry 解析单个 `lang;q=0.8` 项，返回归一后的语言与 q 值。
func parseLanguageEntry(entry string) (string, float64) {
	fields := strings.Split(entry, ";")
	tag := strings.TrimSpace(fields[0])
	if tag == "" || tag == "*" {
		return "", 0
	}
	q := 1.0
	for _, f := range fields[1:] {
		kv := strings.SplitN(strings.TrimSpace(f), "=", 2)
		if len(kv) != 2 || !strings.EqualFold(strings.TrimSpace(kv[0]), "q") {
			continue
		}
		if v, err := strconv.ParseFloat(strings.TrimSpace(kv[1]), 64); err == nil {
			q = v
		}
	}
	base := strings.ToLower(strings.SplitN(tag, "-", 2)[0])
	switch base {
	case "zh":
		return langZh, q
	case "en":
		return langEn, q
	default:
		return "", 0
	}
}

// localizedMessage 是一组双语文案。
type localizedMessage struct {
	zh string
	en string
}

// messages 是错误码 → 本地化文案的目录表。
var messages = map[string]localizedMessage{
	"internal":            {"服务端内部错误", "Internal server error"},
	"not_found":           {"资源不存在", "Resource not found"},
	"method_not_allowed":  {"不支持的请求方法", "Method not allowed"},
	"body_too_large":      {"请求体超过 8 MiB", "Request body exceeds 8 MiB"},
	"empty_body":          {"请求体不能为空", "Request body must not be empty"},
	"invalid_json":        {"请求体不是合法的 JSON", "Request body is not valid JSON"},
	"invalid_request":     {"请求参数不合法", "Invalid request"},
	"bad_request":         {"请求不合法", "Bad request"},
	"unauthorized":        {"未授权", "Unauthorized"},
	"rate_limited":        {"请求过于频繁，请稍后重试", "Too many requests, please try again later"},
	"quota_items":         {"超出每用户条目数配额", "Item quota exceeded"},
	"quota_bytes":         {"超出每用户密文字节配额", "Storage quota exceeded"},
	"quota_devices":       {"超出每用户设备数配额", "Device quota exceeded"},
	"missing_token":       {"缺少 Authorization: Bearer <token>", "Missing Authorization: Bearer <token>"},
	"invalid_token":       {"token 无效或设备已吊销", "Invalid token or device revoked"},
	"missing_ts":          {"缺少 X-Vkey-Ts", "Missing X-Vkey-Ts"},
	"invalid_ts":          {"X-Vkey-Ts 必须是 unix 秒", "X-Vkey-Ts must be unix seconds"},
	"ts_skew":             {"请求时间戳超出 ±120 秒", "Request timestamp is outside ±120 seconds"},
	"missing_sig":         {"缺少或非法的 X-Vkey-Sig", "Missing or invalid X-Vkey-Sig"},
	"bad_signature":       {"请求签名校验失败", "Request signature verification failed"},
	"user_disabled":       {"账号已被停用", "Account disabled"},
	"invalid_username":    {"用户名不合法", "Invalid username"},
	"invalid_verifier":    {"凭证校验失败", "Invalid verifier"},
	"invalid_pubkey":      {"公钥不合法", "Invalid public key"},
	"invalid_device":      {"设备信息不合法", "Invalid device"},
	"invalid_credentials": {"用户名或 verifier 不正确", "Incorrect username or verifier"},
	"invalid_pw_salt":     {"主密码盐不合法", "Invalid password salt"},
	"invalid_pw_fields":   {"pw_salt 与 wrapped_key 必须成对提供", "pw_salt and wrapped_key must be provided together"},
	"invalid_wrapped_key": {"主密码包裹数据不合法", "Invalid wrapped key"},
	"invalid_confirm":     {"主密码确认不匹配", "Password confirmation does not match"},
	"device_not_found":    {"设备不存在或已吊销", "Device not found or revoked"},
	"enroll_disabled":     {"服务端未启用开户（single 模式）", "Enrollment is disabled on this server (single mode)"},
	"invalid_code":        {"验证码无效", "Invalid code"},
	"code_expired":        {"验证码已过期", "Code has expired"},
	"code_used":           {"配对码已被使用", "Code already used"},
	"code_not_found":      {"配对码不存在", "Code not found"},
	"code_id_exists":      {"code_id 已存在", "code_id already exists"},
	"invalid_code_id":     {"code_id 不合法", "Invalid code_id"},
	"invalid_blob":        {"配对数据不合法", "Invalid pairing blob"},
	"username_taken":      {"用户名已被占用", "Username already taken"},
	"too_many_items":      {"单次最多提交 500 条", "At most 500 items per request"},
	"item_too_large":      {"单条密文超过 8192 字节", "Item ciphertext exceeds 8192 bytes"},
	"invalid_item":        {"条目数据不合法", "Invalid item"},
	"invalid_since":       {"since 必须是非负整数", "since must be a non-negative integer"},
	"stale_write":         {"版本冲突（写入已过期）", "Stale write (version conflict)"},
	"kind_mismatch":       {"条目类型不匹配", "Item kind mismatch"},
	"not_configured":      {"服务端未配置", "Server not configured"},
	"invalid_response":    {"响应数据不合法", "Invalid response"},
}

// msg 返回错误码在指定语言下的文案；未知错误码回落默认（英文）兜底。
func msg(lang, code string) string {
	m, ok := messages[code]
	if !ok {
		return fallbackMessage
	}
	if lang == langZh {
		return m.zh
	}
	return m.en
}
