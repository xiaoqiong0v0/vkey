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
	"sync"
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
	// UpdateFetcher 是更新元数据的网络访问注入点，nil 时使用内置 HTTPS fetcher。
	UpdateFetcher UpdateFetcher
}

// Server 是 API 服务实例。
type Server struct {
	store  *store.Store
	opts   Options
	rl     *rateLimiter
	mux    http.Handler
	logger *log.Logger

	// updateFetch 是拉取 android.json 的实现（测试注入）。
	updateFetch UpdateFetcher
	// updateFetchMu 保证同一时刻只有一个请求在拉取元数据（TryLock，其它请求不阻塞）。
	updateFetchMu sync.Mutex
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
	if opts.UpdateFetcher == nil {
		opts.UpdateFetcher = httpUpdateFetcher
	}
	s := &Server{store: st, opts: opts, rl: newRateLimiter(), logger: opts.Logger, updateFetch: opts.UpdateFetcher}
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
					writeError(sw, r, http.StatusInternalServerError, "internal")
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
			writeError(sw, r, http.StatusNotFound, "not_found")
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
	writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
}

// handleAPINotFound 返回统一的 404 JSON 错误。
func (s *Server) handleAPINotFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusNotFound, "not_found")
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

// writeError 写出统一错误响应。
//
// message 按请求的 Accept-Language 本地化；code 与语言无关，保持稳定。
func writeError(w http.ResponseWriter, r *http.Request, status int, code string) {
	var body errorBody
	body.Error.Code = code
	body.Error.Message = msg(langOf(r), code)
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
func writeReadError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errBodyTooLarge):
		writeError(w, r, http.StatusRequestEntityTooLarge, "body_too_large")
	case errors.Is(err, errBodyEmpty):
		writeError(w, r, http.StatusBadRequest, "empty_body")
	default:
		writeError(w, r, http.StatusBadRequest, "invalid_json")
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
		dev, status, code := s.authenticate(w, r)
		if dev == nil {
			writeError(w, r, status, code)
			return
		}
		next(w, r, dev)
	}
}

// authenticate 校验 Bearer token、时间戳与 Ed25519 请求签名。
//
// 返回：成功时返回设备与零值状态；失败时返回状态码与错误码（文案由调用方本地化）。
// 注意：校验通过后请求体会被还原，后续 handler 可再次读取。
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (*store.Device, int, string) {
	const prefix = "Bearer "
	authz := r.Header.Get("Authorization")
	if len(authz) <= len(prefix) || !strings.EqualFold(authz[:len(prefix)], prefix) {
		return nil, http.StatusUnauthorized, "missing_token"
	}
	token, err := crypto.ParseB64(strings.TrimSpace(authz[len(prefix):]))
	if err != nil || len(token) != crypto.TokenLen {
		return nil, http.StatusUnauthorized, "invalid_token"
	}

	tsStr := strings.TrimSpace(r.Header.Get("X-Vkey-Ts"))
	if tsStr == "" {
		return nil, http.StatusUnauthorized, "missing_ts"
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return nil, http.StatusUnauthorized, "invalid_ts"
	}
	if skew := s.nowUnix() - ts; skew > policy.ClockSkewSeconds || skew < -policy.ClockSkewSeconds {
		return nil, http.StatusUnauthorized, "ts_skew"
	}

	dev, err := s.store.DeviceByTokenHash(r.Context(), crypto.TokenHash(token))
	if errors.Is(err, store.ErrNotFound) {
		return nil, http.StatusUnauthorized, "invalid_token"
	}
	if err != nil {
		s.logger.Printf("auth/device 查询失败: %v", err)
		return nil, http.StatusInternalServerError, "internal"
	}

	// 账号被管理员停用（disable）后，该账号全部设备立即 401；数据保留。
	u, err := s.store.UserByID(r.Context(), dev.UserID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, http.StatusUnauthorized, "invalid_token"
	}
	if err != nil {
		s.logger.Printf("auth/user 查询失败: %v", err)
		return nil, http.StatusInternalServerError, "internal"
	}
	if u.DisabledAt != 0 {
		return nil, http.StatusUnauthorized, "user_disabled"
	}

	body, err := readBody(w, r)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			return nil, http.StatusRequestEntityTooLarge, "body_too_large"
		}
		return nil, http.StatusBadRequest, "bad_request"
	}

	sig, err := crypto.ParseB64(strings.TrimSpace(r.Header.Get("X-Vkey-Sig")))
	if err != nil || len(sig) != 64 {
		return nil, http.StatusUnauthorized, "missing_sig"
	}
	rawURI := r.RequestURI
	if rawURI == "" {
		rawURI = r.URL.RequestURI()
	}
	if !crypto.Verify(dev.PubKey, r.Method, rawURI, body, ts, sig) {
		return nil, http.StatusUnauthorized, "bad_signature"
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	if err := s.store.TouchDevice(r.Context(), dev.UserID, dev.ID, s.nowUnix()); err != nil {
		s.logger.Printf("更新设备活跃时间失败: %v", err)
	}
	return dev, 0, ""
}

// withRateLimit 对免鉴权端点施加按 IP 的固定窗口限流。
func (s *Server) withRateLimit(name string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := name + "|" + clientIP(r)
		ok, retry := s.rl.allow(key, s.now())
		if !ok {
			w.Header().Set("Retry-After", strconv.FormatInt(retry, 10))
			writeError(w, r, http.StatusTooManyRequests, "rate_limited")
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
func writeQuotaErr(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case errors.Is(err, store.ErrQuotaItems):
		writeError(w, r, http.StatusConflict, "quota_items")
	case errors.Is(err, store.ErrQuotaBytes):
		writeError(w, r, http.StatusConflict, "quota_bytes")
	case errors.Is(err, store.ErrQuotaDevices):
		writeError(w, r, http.StatusConflict, "quota_devices")
	default:
		return false
	}
	return true
}
