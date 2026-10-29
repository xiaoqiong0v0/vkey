// Package api 实现 vkeyd 的 HTTP 接口、鉴权中间件与静态引导页。
package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"xiaoqiong0v0.cn/vkey/server/internal/crypto"
	"xiaoqiong0v0.cn/vkey/server/internal/policy"
	"xiaoqiong0v0.cn/vkey/server/internal/store"
)

// Options 是 API 服务的可选项。
type Options struct {
	// Domain 是配置的域名或 IP（可带 scheme）；为空时由请求的 Host 推导。
	Domain string
	// Version 是 /health 与自检页展示的版本号。
	Version string
	// ArtifactsDir 是 /dl/* 的只读产物目录（白名单来自其中的 SHA256SUMS）。
	// 空值等价于 "./artifacts"。
	ArtifactsDir string
	// Now 是时钟注入点，nil 时使用 time.Now（测试用）。
	Now func() time.Time
	// Logger 是访问日志输出，nil 时使用 log.Default()。
	Logger *log.Logger
}

// Server 是 API 服务实例。
type Server struct {
	store  *store.Store
	opts   Options
	rl     *rateLimiter
	mux    http.Handler
	logger *log.Logger
}

// New 构造 API 服务并完成路由注册。
//
// 参数：st 为已打开的存储；opts 为零值安全的可选项。
// 返回：可直接交给 http.Server 的 Server。
func New(st *store.Store, opts Options) *Server {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Version == "" {
		opts.Version = "dev"
	}
	if opts.ArtifactsDir == "" {
		opts.ArtifactsDir = defaultArtifactsDir
	}
	if opts.Logger == nil {
		opts.Logger = log.Default()
	}
	s := &Server{store: st, opts: opts, rl: newRateLimiter(), logger: opts.Logger}
	s.mux = s.withCommon(s.routes())
	return s
}

// Handler 返回带通用中间件的 http.Handler。
func (s *Server) Handler() http.Handler { return s.mux }

// now 返回当前时间（测试可注入固定时钟）。
func (s *Server) now() time.Time { return s.opts.Now() }

// nowUnix 返回当前 unix 秒。
func (s *Server) nowUnix() int64 { return s.now().Unix() }

// routes 注册全部路由。
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/policy", s.handlePolicy)
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("GET /api/v1/update/android", s.withRateLimit("update", s.handleUpdateAndroid))
	mux.HandleFunc("POST /api/v1/auth/token", s.withRateLimit("auth", s.handleAuthToken))
	mux.HandleFunc("POST /api/v1/auth/enroll", s.withRateLimit("enroll", s.handleEnroll))
	mux.HandleFunc("POST /api/v1/auth/password", s.withAuth(s.handleSetPassword))
	mux.HandleFunc("DELETE /api/v1/auth/password", s.withAuth(s.handleDeletePassword))
	mux.HandleFunc("POST /api/v1/items", s.withAuth(s.handlePostItems))
	mux.HandleFunc("GET /api/v1/items", s.withAuth(s.handleGetItems))
	mux.HandleFunc("GET /api/v1/devices", s.withAuth(s.handleDeviceList))
	mux.HandleFunc("POST /api/v1/devices/register", s.withAuth(s.handleDeviceRegister))
	mux.HandleFunc("POST /api/v1/devices/revoke", s.withAuth(s.handleDeviceRevoke))
	mux.HandleFunc("POST /api/v1/pair/new", s.withAuth(s.handlePairNew))
	mux.HandleFunc("POST /api/v1/pair/claim", s.withRateLimit("claim", s.handlePairClaim))

	// 同一路径的其它方法统一返回 JSON 错误，避免 ServeMux 的纯文本 405。
	for _, p := range []string{
		"/api/v1/policy", "/api/v1/health", "/api/v1/auth/token",
		"/api/v1/auth/enroll",
		"/api/v1/auth/password",
		"/api/v1/update/android",
		"/api/v1/items", "/api/v1/devices", "/api/v1/devices/register", "/api/v1/devices/revoke",
		"/api/v1/pair/new", "/api/v1/pair/claim",
	} {
		mux.HandleFunc(p, s.handleMethodNotAllowed)
	}
	mux.HandleFunc("/api/", s.handleAPINotFound)

	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /pair", s.handlePairRedirect)
	mux.HandleFunc("GET /pair/qr.png", s.handlePairQR)
	mux.HandleFunc("GET "+joinPagePath, s.handleJoin)
	mux.HandleFunc("GET "+joinQRPath, s.handleJoinQR)
	mux.HandleFunc("GET /install.sh", s.handleInstallSH)
	mux.HandleFunc("GET /install.ps1", s.handleInstallPS1)
	mux.HandleFunc("GET /dl/{name}", s.handleArtifact)
	// /dl/ 及其它多段/空名请求（/dl/、/dl/a/b）统一返回 JSON 404。
	mux.HandleFunc("/dl/", s.handleArtifactNotFound)
	return mux
}

// withCommon 施加通用响应头、panic 兜底与访问日志。
func (s *Server) withCommon(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Printf("panic: %v (%s %s)", rec, r.Method, r.URL.Path)
				if !sw.wrote {
					writeErr(sw, http.StatusInternalServerError, "internal", "服务端内部错误")
				}
			}
			s.logger.Printf("%s %s -> %d (%s)", r.Method, safeURI(r), sw.status, time.Since(start).Round(time.Millisecond))
		}()

		sw.Header().Set("X-Content-Type-Options", "nosniff")
		sw.Header().Set("Referrer-Policy", "no-referrer")
		// /join* 的一次性开户码在 query 里：禁缓存 + 日志脱敏（safeURI 只记路径）。
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == joinPagePath ||
			strings.HasPrefix(r.URL.Path, joinPagePath+"/") {
			sw.Header().Set("Cache-Control", "no-store")
		}
		// /dl/* 只接受白名单里的单段文件名：含 "." / ".." 段或反斜杠的路径
		// 在进入 ServeMux 前就返回 404。否则 ServeMux 的 cleanPath 会把
		// /dl/../x 301 重定向到 /x，既不符合契约也会暴露目录结构。
		if strings.HasPrefix(r.URL.Path, "/dl/") && hasDotSegmentOrBackslash(r.URL.Path) {
			writeErr(sw, http.StatusNotFound, "not_found", "文件不存在")
			return
		}
		next.ServeHTTP(sw, r)
	})
}

// statusWriter 记录响应状态码与是否已写出。
type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

// WriteHeader 记录状态码后透传。
func (w *statusWriter) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.status = code
	w.wrote = true
	w.ResponseWriter.WriteHeader(code)
}

// Write 记录已写出后透传。
func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.wrote = true
	}
	return w.ResponseWriter.Write(b)
}

// handleMethodNotAllowed 返回统一的 405 JSON 错误。
func (s *Server) handleMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", allowedMethods(r.URL.Path))
	writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "不支持的请求方法")
}

// handleAPINotFound 返回统一的 404 JSON 错误。
func (s *Server) handleAPINotFound(w http.ResponseWriter, r *http.Request) {
	writeErr(w, http.StatusNotFound, "not_found", "接口不存在")
}

// allowedMethods 返回路径允许的方法列表（用于 405 的 Allow 头）。
func allowedMethods(path string) string {
	if path == "/api/v1/items" {
		return "GET, POST"
	}
	if path == "/api/v1/devices" {
		return "GET"
	}
	if path == "/api/v1/auth/password" {
		return "POST, DELETE"
	}
	if path == "/api/v1/policy" || path == "/api/v1/health" || path == "/api/v1/update/android" {
		return "GET"
	}
	return "POST"
}

// ---------------------------------------------------------------------------
// JSON 读写
// ---------------------------------------------------------------------------

// errorBody 是协议规定的错误响应体。
type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// writeJSON 写出 JSON 响应。
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// writeErr 写出统一错误响应。
func writeErr(w http.ResponseWriter, status int, code, msg string) {
	var body errorBody
	body.Error.Code = code
	body.Error.Message = msg
	writeJSON(w, status, body)
}

// errBodyTooLarge 表示请求体超过上限。
var errBodyTooLarge = errors.New("请求体过大")

// errBodyEmpty 表示请求体为空。
var errBodyEmpty = errors.New("请求体为空")

// readBody 读取请求体（受 policy.MaxRequestBodyBytes 限制）。
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	lr := http.MaxBytesReader(w, r.Body, policy.MaxRequestBodyBytes)
	b, err := io.ReadAll(lr)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, errBodyTooLarge
		}
		return nil, fmt.Errorf("读取请求体失败: %w", err)
	}
	return b, nil
}

// readJSON 读取并解析 JSON 请求体，拒绝空体与尾部多余内容。
func readJSON(w http.ResponseWriter, r *http.Request, v any) error {
	body, err := readBody(w, r)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return errBodyEmpty
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("JSON 解析失败: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON 尾部存在多余内容")
	}
	return nil
}

// writeReadError 把 readJSON 的错误映射为统一响应。
func writeReadError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errBodyTooLarge):
		writeErr(w, http.StatusRequestEntityTooLarge, "body_too_large", "请求体超过 8 MiB")
	case errors.Is(err, errBodyEmpty):
		writeErr(w, http.StatusBadRequest, "empty_body", "请求体不能为空")
	default:
		writeErr(w, http.StatusBadRequest, "invalid_json", err.Error())
	}
}

// ---------------------------------------------------------------------------
// 鉴权
// ---------------------------------------------------------------------------

// authedFunc 是已通过设备鉴权的处理函数。
type authedFunc func(w http.ResponseWriter, r *http.Request, dev *store.Device)

// withAuth 包装需要设备签名鉴权的处理函数。
func (s *Server) withAuth(next authedFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dev, status, code, msg := s.authenticate(w, r)
		if dev == nil {
			writeErr(w, status, code, msg)
			return
		}
		next(w, r, dev)
	}
}

// authenticate 校验 Bearer token、时间戳与 Ed25519 请求签名。
//
// 返回：成功时返回设备与零值状态；失败时返回状态码与错误码。
// 注意：校验通过后请求体会被还原，后续 handler 可再次读取。
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (*store.Device, int, string, string) {
	const prefix = "Bearer "
	authz := r.Header.Get("Authorization")
	if len(authz) <= len(prefix) || !strings.EqualFold(authz[:len(prefix)], prefix) {
		return nil, http.StatusUnauthorized, "missing_token", "缺少 Authorization: Bearer <token>"
	}
	token, err := crypto.ParseB64(strings.TrimSpace(authz[len(prefix):]))
	if err != nil || len(token) != crypto.TokenLen {
		return nil, http.StatusUnauthorized, "invalid_token", "token 编码非法"
	}

	tsStr := strings.TrimSpace(r.Header.Get("X-Vkey-Ts"))
	if tsStr == "" {
		return nil, http.StatusUnauthorized, "missing_ts", "缺少 X-Vkey-Ts"
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return nil, http.StatusUnauthorized, "invalid_ts", "X-Vkey-Ts 必须是 unix 秒"
	}
	if skew := s.nowUnix() - ts; skew > policy.ClockSkewSeconds || skew < -policy.ClockSkewSeconds {
		return nil, http.StatusUnauthorized, "ts_skew", "请求时间戳超出 ±120 秒"
	}

	dev, err := s.store.DeviceByTokenHash(r.Context(), crypto.TokenHash(token))
	if errors.Is(err, store.ErrNotFound) {
		return nil, http.StatusUnauthorized, "invalid_token", "token 无效或设备已吊销"
	}
	if err != nil {
		s.logger.Printf("auth/device 查询失败: %v", err)
		return nil, http.StatusInternalServerError, "internal", "服务端内部错误"
	}

	// 账号被管理员停用（disable）后，该账号全部设备立即 401；数据保留。
	u, err := s.store.UserByID(r.Context(), dev.UserID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, http.StatusUnauthorized, "invalid_token", "token 无效或设备已吊销"
	}
	if err != nil {
		s.logger.Printf("auth/user 查询失败: %v", err)
		return nil, http.StatusInternalServerError, "internal", "服务端内部错误"
	}
	if u.DisabledAt != 0 {
		return nil, http.StatusUnauthorized, "user_disabled", "账号已被停用"
	}

	body, err := readBody(w, r)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			return nil, http.StatusRequestEntityTooLarge, "body_too_large", "请求体超过 8 MiB"
		}
		return nil, http.StatusBadRequest, "bad_request", err.Error()
	}

	sig, err := crypto.ParseB64(strings.TrimSpace(r.Header.Get("X-Vkey-Sig")))
	if err != nil || len(sig) != 64 {
		return nil, http.StatusUnauthorized, "missing_sig", "缺少或非法的 X-Vkey-Sig"
	}
	rawURI := r.RequestURI
	if rawURI == "" {
		rawURI = r.URL.RequestURI()
	}
	if !crypto.Verify(dev.PubKey, r.Method, rawURI, body, ts, sig) {
		return nil, http.StatusUnauthorized, "bad_signature", "请求签名校验失败"
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	if err := s.store.TouchDevice(r.Context(), dev.UserID, dev.ID, s.nowUnix()); err != nil {
		s.logger.Printf("更新设备活跃时间失败: %v", err)
	}
	return dev, 0, "", ""
}

// withRateLimit 对免鉴权端点施加按 IP 的固定窗口限流。
func (s *Server) withRateLimit(name string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := name + "|" + clientIP(r)
		ok, retry := s.rl.allow(key, s.now())
		if !ok {
			w.Header().Set("Retry-After", strconv.FormatInt(retry, 10))
			writeErr(w, http.StatusTooManyRequests, "rate_limited", "请求过于频繁，请稍后重试")
			return
		}
		next(w, r)
	}
}

// clientIP 提取客户端 IP（优先取反向代理写入的 X-Forwarded-For 首项）。
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			xff = xff[:i]
		}
		if ip := strings.TrimSpace(xff); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}
	return "unknown"
}

// ---------------------------------------------------------------------------
// 通用查询
// ---------------------------------------------------------------------------

// firstUser 返回唯一账号；不存在时返回 ErrNotFound。
func (s *Server) firstUser(ctx context.Context) (*store.User, error) {
	return s.store.FirstUser(ctx)
}

// logErr 记录内部错误（不返回给客户端细节）。
func (s *Server) logErr(what string, err error) {
	s.logger.Printf("%s: %v", what, err)
}

// isNoUser 判断错误是否为「尚未 init」。
func isNoUser(err error) bool {
	return errors.Is(err, store.ErrNotFound) || errors.Is(err, sql.ErrNoRows)
}

// b64Ptr 把可空字节切片转为 JSON 可用的 *string（base64url）。
func b64Ptr(b []byte) *string {
	if len(b) == 0 {
		return nil
	}
	s := crypto.B64(b)
	return &s
}

// writeQuotaErr 把配额类存储错误映射为统一的 409 JSON 响应。
//
// 返回：true 表示已写出响应（调用方应直接 return）；false 表示 err 不是配额错误。
func writeQuotaErr(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, store.ErrQuotaItems):
		writeErr(w, http.StatusConflict, "quota_items", "超出每用户条目数配额")
	case errors.Is(err, store.ErrQuotaBytes):
		writeErr(w, http.StatusConflict, "quota_bytes", "超出每用户密文字节配额")
	case errors.Is(err, store.ErrQuotaDevices):
		writeErr(w, http.StatusConflict, "quota_devices", "超出每用户设备数配额")
	default:
		return false
	}
	return true
}
