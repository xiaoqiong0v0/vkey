package api

import (
	"fmt"
	htmlpkg "html"
	htmltemplate "html/template"
	"net/http"
	"net/url"
	"strings"

	qrcode "github.com/skip2/go-qrcode"

	"xiaoqiong0v0.cn/vkey/server/internal/policy"
	"xiaoqiong0v0.cn/vkey/server/internal/store"
)

// 开户落地页（/join）：管理员把 `vkeyd user add` 打印的链接发给对方，
// 对方在浏览器里看到二维码与开户码，点按钮唤起 App 自动填写。
//
// 零知识边界：页面/QR 里只有服务器地址 + 一次性开户码，绝无 master_key、
// verifier、token；开户码只读校验（store.PeekEnrollCode），打开页面不消费码，
// 消费仍只发生在 POST /api/v1/auth/enroll 事务内。
// 访问日志对 /join* 只记路径不记 query（见 withCommon/safeURI）。

// 开户深链与下载参数。
const (
	// deepLinkEnrollPrefix 是 App「开户」深链前缀：server=<服务器地址>&code=<开户码>。
	deepLinkEnrollPrefix = "vkey://enroll?server="

	// enrollAppPackage 是 Android 客户端包名，用于 intent:// 直达 App。
	enrollAppPackage = "dev.xiaoqiong.vkey"
	// joinPagePath 是开户落地页路径。
	joinPagePath = "/join"
	// joinQRPath 是开户二维码端点路径（页面 img 与下载链接共用）。
	joinQRPath = "/join/qr.png"
	// joinQRFilename 是「下载二维码」的落盘文件名。
	joinQRFilename = "vkey-enroll.png"
	// joinInvalidMessage 是统一失效文案：不区分「码不存在 / 已用 / 过期 / 非 admin 模式」，
	// 避免通过页面差异枚举有效开户码。
	joinInvalidMessage = "链接无效或已过期"
)

// joinView 是开户落地页的渲染数据。
type joinView struct {
	// Code 是开户码明文（形如 ENROLL-XXXX-XXXX，供手抄）。
	Code string
	// QRURL 是二维码图片/下载的相对 URL（带 ?c= 参数）。
	QRURL string
	// DeepLink 是唤起 App 的深链 vkey://enroll?server=…&code=…（QR 编码用原文）。
	DeepLink string
	// MainAnchor 是「打开 vkey App」的完整 <a> 标签：vkey:// 自定义 scheme 会被
	// html/template 的 URL 上下文过滤器拦成 #ZgotmplZ，因此 href 先经
	// html.EscapeString 手工转义、整段以 template.HTML（可信 HTML 上下文）注入。
	// 深链构成全部受控：常量前缀 + sanitizeHost（字符白名单）+
	// QueryEscape(规范化码)（规范化码经 code_hash 精确比对，只会是签发时的
	// 去混淆字母表字符），不含引号/尖括号等可逃逸字符，旁路是安全的。
	MainAnchor htmltemplate.HTML
	// TTLText 是按实际签发 TTL 渲染的有效期文案（如 "30 分钟"）。
	TTLText string
	// QRFilename 是「下载二维码」的落盘文件名。
	QRFilename string
}

// joinPageTemplate 是开户落地页（纯 HTML+CSS、无 JS；系统色适配深浅色）。
var joinPageTemplate = htmltemplate.Must(htmltemplate.New("join").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>vkey 开户</title>
<style>
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{margin:0;padding:2rem 1rem;font:16px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;background:Canvas;color:CanvasText}
main{max-width:26rem;margin:0 auto;text-align:center}
h1{font-size:1.35rem;margin:0 0 .25rem}
p.lead{margin:0 0 1.25rem;color:GrayText}
img.qr{display:block;width:220px;height:220px;margin:0 auto 1rem;padding:8px;background:#fff;border-radius:8px}
p.codeline{margin:.25rem 0 1.25rem}
code.plain{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:1.2rem;letter-spacing:.08em;user-select:all}
a.btn{display:block;text-decoration:none;border-radius:.65rem;padding:.7rem 1rem;margin:.5rem 0;font-size:1rem}
a.main{background:CanvasText;color:Canvas}
a.secondary{border:1px solid CanvasText;color:CanvasText}
ul.notes{margin:1.5rem 0 0;padding:0;list-style:none;color:GrayText;font-size:.88rem;text-align:left}
ul.notes li{margin:.3rem 0}
ul.notes li::before{content:"· "}
</style>
</head>
<body>
<main>
<h1>vkey 开户</h1>
<p class="lead">打开 vkey App 完成绑定：点下方按钮唤起 App 并自动填好，或扫码 / 手抄开户码。</p>
<img class="qr" src="{{.QRURL}}" width="220" height="220" alt="开户二维码">
<p class="codeline">开户码：<code class="plain">{{.Code}}</code></p>
{{.MainAnchor}}
<a class="btn secondary" href="{{.QRURL}}" download="{{.QRFilename}}">下载二维码</a>
<ul class="notes">
<li>开户码有效期 {{.TTLText}}，仅可使用一次，开户成功后立即失效。</li>
<li>master_key 只在本机生成与保存，服务端不会接触到它。</li>
<li>本页与二维码只含服务器地址和一次性开户码，不含任何密钥。</li>
</ul>
</main>
</body>
</html>
`))

// joinErrorTemplate 是统一错误页：文案固定，不回显任何输入。
var joinErrorTemplate = htmltemplate.Must(htmltemplate.New("join-err").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>vkey 开户</title>
<style>
:root{color-scheme:light dark}
body{margin:0;padding:3rem 1.25rem;font:16px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;background:Canvas;color:CanvasText}
main{max-width:26rem;margin:0 auto;text-align:center}
h1{font-size:1.25rem;margin:0 0 .75rem}
p{margin:.35rem 0;color:GrayText}
</style>
</head>
<body>
<main>
<h1>{{.Message}}</h1>
<p>请管理员重新执行 <code>vkeyd user add</code> 签发新链接后打开。</p>
<p>链接只包含一次性开户码，不含任何密钥；过期或被使用后即刻失效。</p>
</main>
</body>
</html>
`))

// joinErrorView 是错误页数据。
type joinErrorView struct {
	Message string
}

// handleJoin 渲染开户落地页（免鉴权；仅 admin 模式 + 有效未用码返回 200）。
func (s *Server) handleJoin(w http.ResponseWriter, r *http.Request) {
	v, ok := s.resolveJoin(w, r)
	if !ok {
		return
	}
	writeJoinHTML(w, http.StatusOK, joinPageTemplate, v)
}

// handleJoinQR 输出开户二维码 PNG（内容与深链一致，带下载文件名）。
func (s *Server) handleJoinQR(w http.ResponseWriter, r *http.Request) {
	v, ok := s.resolveJoin(w, r)
	if !ok {
		return
	}
	png, err := qrcode.Encode(v.DeepLink, qrLevel, qrPNGSize)
	if err != nil {
		s.logErr("生成开户二维码失败", err)
		writeError(w, r, http.StatusInternalServerError, "internal")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Disposition", `attachment; filename="`+joinQRFilename+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(png)
}

// resolveJoin 解析并只读校验 ?c= 开户码：非 admin 模式、不存在/已用/已撤销/
// 过期统一返回同一错误页（404），不泄露「码是否存在」的差异；缺参数给 400。
//
// 返回：成功时 (view, true)；失败时已写出响应，返回 (nil, false)。
func (s *Server) resolveJoin(w http.ResponseWriter, r *http.Request) (*joinView, bool) {
	plain := store.NormalizeEnrollCode(r.URL.Query().Get("c"))
	if plain == "" {
		s.writeJoinError(w, http.StatusBadRequest)
		return nil, false
	}
	mode, err := s.store.UserMode(r.Context())
	if err != nil {
		s.logErr("查询用户模式失败", err)
		writeError(w, r, http.StatusInternalServerError, "internal")
		return nil, false
	}
	if mode != policy.UserModeAdmin {
		s.writeJoinError(w, http.StatusNotFound)
		return nil, false
	}
	state, rec, err := s.store.PeekEnrollCode(r.Context(), plain, s.nowUnix())
	if err != nil {
		s.logErr("查询开户码状态失败", err)
		writeError(w, r, http.StatusInternalServerError, "internal")
		return nil, false
	}
	if state != store.EnrollCodeActive || rec == nil {
		// 过期与不存在/已用/撤销同口径（404 + 同一文案），防枚举。
		s.writeJoinError(w, http.StatusNotFound)
		return nil, false
	}
	serverURL := s.serverURL(r)
	deepLink := deepLinkEnrollPrefix + serverURL + "&code=" + url.QueryEscape(plain)
	// 开户码已绑定用户名：把它一起带给 App，省去手填（老的 App 会忽略未知参数）
	if rec.Username != "" {
		deepLink += "&username=" + url.QueryEscape(rec.Username)
	}
	// 浏览器（尤其 Chrome）对自定义 scheme 有限制：按钮用 intent:// 形式，
	// 手机上没有 App 时回落到本页；二维码仍编码 vkey:// 原文（App 内扫码直接解析）。
	query := strings.TrimPrefix(deepLink, "vkey://enroll?")
	intentURL := "intent://enroll?" + query +
		"#Intent;scheme=vkey;package=" + enrollAppPackage + ";end"
	anchor := `<a class="btn main" href="` + htmlpkg.EscapeString(intentURL) + `">打开 vkey App</a>`
	return &joinView{
		Code:       plain,
		QRURL:      joinQRPath + "?c=" + url.QueryEscape(plain),
		DeepLink:   deepLink,
		MainAnchor: htmltemplate.HTML(anchor),
		TTLText:    ttlText(rec.CreatedAt, rec.ExpiresAt),
		QRFilename: joinQRFilename,
	}, true
}

// writeJoinError 写出统一失效页（HTML，状态码 4xx）。
func (s *Server) writeJoinError(w http.ResponseWriter, status int) {
	writeJoinHTML(w, status, joinErrorTemplate, joinErrorView{Message: joinInvalidMessage})
}

// writeJoinHTML 渲染 join 系列页面并写出安全头（禁缓存；其余通用头由 withCommon 施加）。
func writeJoinHTML(w http.ResponseWriter, status int, t *htmltemplate.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// 页面样式内联、二维码同源；无脚本、无外部资源。
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.WriteHeader(status)
	_ = t.Execute(w, data)
}

// ttlText 把签发时的 TTL（expires_at - created_at）折算成展示文案。
func ttlText(createdAt, expiresAt int64) string {
	secs := expiresAt - createdAt
	if secs <= 0 {
		return "已过期"
	}
	mins := (secs + 59) / 60 // 向上取整，避免短 TTL 显示 0 分钟
	if mins < 60 {
		return fmt.Sprintf("%d 分钟", mins)
	}
	h := mins / 60
	if m := mins % 60; m > 0 {
		return fmt.Sprintf("%d 小时 %d 分钟", h, m)
	}
	return fmt.Sprintf("%d 小时", h)
}

// safeURI 返回访问日志记录的请求标识。
//
// /join 与 /join/* 的开户码在 query（?c=）里，属一次性凭据：
// 日志只记路径，不得出现 query string。
func safeURI(r *http.Request) string {
	if r.URL.Path == "/join" || strings.HasPrefix(r.URL.Path, "/join/") {
		return r.URL.Path
	}
	return r.URL.RequestURI()
}
