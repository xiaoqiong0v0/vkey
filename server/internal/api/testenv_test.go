package api_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"xiaoqiong0v0.cn/vkey/server/internal/api"
	"xiaoqiong0v0.cn/vkey/server/internal/crypto"
	"xiaoqiong0v0.cn/vkey/server/internal/store"
)

// env 是每个测试独立的服务端环境（临时 sqlite + httptest）。
type env struct {
	t         *testing.T
	st        *store.Store
	srv       *httptest.Server
	user      *store.User
	masterKey []byte
}

// response 是测试侧记录的 HTTP 响应。
type response struct {
	status int
	body   []byte
}

// testDevice 是测试用设备（Ed25519 密钥对 + token）。
type testDevice struct {
	ID    string
	Token string // base64url 形式，直接放 Authorization 头
	Priv  ed25519.PrivateKey
	Pub   ed25519.PublicKey
}

// newEnv 建库、建用户并启动 httptest 服务（使用真实时钟）。
func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvAt(t, nil)
}

// newEnvAt 与 newEnv 相同，但可注入固定时钟（用于时间窗边界测试）。
func newEnvAt(t *testing.T, now func() time.Time) *env {
	t.Helper()
	return newEnvOpts(t, func(o *api.Options) { o.Now = now })
}

// newEnvOpts 与 newEnv 相同，但允许测试覆盖 Options（如产物目录）。
func newEnvOpts(t *testing.T, mutate func(*api.Options)) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "vkey.db"))
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	masterKey, err := crypto.Random(crypto.KeyLen)
	if err != nil {
		t.Fatalf("生成 master_key 失败: %v", err)
	}
	verifier, err := crypto.Verifier(masterKey, "default")
	if err != nil {
		t.Fatalf("派生 verifier 失败: %v", err)
	}
	if err := st.CreateUser(context.Background(), store.User{Username: "default", Verifier: verifier}); err != nil {
		t.Fatalf("创建用户失败: %v", err)
	}
	user, err := st.FirstUser(context.Background())
	if err != nil {
		t.Fatalf("读取用户失败: %v", err)
	}

	opts := api.Options{
		Domain:  "https://vkey.test",
		Version: "test",
		Logger:  log.New(io.Discard, "", 0),
	}
	if mutate != nil {
		mutate(&opts)
	}
	handler := api.New(st, opts).Handler()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return &env{t: t, st: st, srv: srv, user: user, masterKey: masterKey}
}

// newDevice 生成一对新设备密钥。
func newDevice(t *testing.T) *testDevice {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成设备密钥失败: %v", err)
	}
	return &testDevice{Priv: priv, Pub: pub}
}

// enroll 用 verifier 换取 token（设备 A 的正常上线路径）。
func (e *env) enroll(name, platform string) *testDevice {
	e.t.Helper()
	dev := newDevice(e.t)
	verifier, err := crypto.Verifier(e.masterKey, "default")
	if err != nil {
		e.t.Fatalf("派生 verifier 失败: %v", err)
	}
	body := map[string]any{
		"username": "default",
		"verifier": crypto.B64(verifier),
		"device": map[string]any{
			"name":     name,
			"platform": platform,
			"pubkey":   crypto.B64(dev.Pub),
		},
	}
	resp := e.postJSON("/api/v1/auth/token", body)
	requireStatus(e.t, resp, http.StatusOK)
	var out struct {
		Token    string `json:"token"`
		DeviceID string `json:"device_id"`
	}
	decode(e.t, resp, &out)
	if out.Token == "" || out.DeviceID == "" {
		e.t.Fatalf("认证响应缺字段: %+v", out)
	}
	dev.Token = out.Token
	dev.ID = out.DeviceID
	return dev
}

// postJSON 发送免鉴权 JSON 请求。
func (e *env) postJSON(path string, v any) response {
	e.t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		e.t.Fatalf("序列化请求体失败: %v", err)
	}
	resp, err := e.srv.Client().Post(e.srv.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		e.t.Fatalf("请求 %s 失败: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return response{status: resp.StatusCode, body: body}
}

// signedDo 用当前时间签名并发送请求。
func (e *env) signedDo(dev *testDevice, method, uri string, body []byte) response {
	return e.signedDoTS(dev, method, uri, body, time.Now().Unix())
}

// signedDoTS 用指定时间戳签名并发送请求。
func (e *env) signedDoTS(dev *testDevice, method, uri string, body []byte, ts int64) response {
	e.t.Helper()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, e.srv.URL+uri, rdr)
	if err != nil {
		e.t.Fatalf("构造请求失败: %v", err)
	}
	e.signRequest(req, dev, method, uri, body, ts)
	return e.do(req)
}

// signRequest 给请求加上 Bearer token、时间戳与签名头。
func (e *env) signRequest(req *http.Request, dev *testDevice, method, uri string, body []byte, ts int64) {
	sig := crypto.Sign(dev.Priv, method, uri, body, ts)
	req.Header.Set("Authorization", "Bearer "+dev.Token)
	req.Header.Set("X-Vkey-Ts", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Vkey-Sig", crypto.B64(sig))
	req.Header.Set("Content-Type", "application/json")
}

// postAuthed 发送带签名的 JSON POST 请求。
func (e *env) postAuthed(dev *testDevice, path string, v any) response {
	e.t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		e.t.Fatalf("序列化请求体失败: %v", err)
	}
	return e.signedDo(dev, http.MethodPost, path, b)
}

// getNoAuth 发送免鉴权 GET 请求（页面/策略/健康检查）。
func (e *env) getNoAuth(path string) response {
	e.t.Helper()
	resp, err := e.srv.Client().Get(e.srv.URL + path)
	if err != nil {
		e.t.Fatalf("请求 %s 失败: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return response{status: resp.StatusCode, body: body}
}

// getNoRedirect 发送免鉴权 GET 请求且不跟随重定向，返回响应与 Location 头。
func (e *env) getNoRedirect(path string) (response, string) {
	e.t.Helper()
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Get(e.srv.URL + path)
	if err != nil {
		e.t.Fatalf("请求 %s 失败: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return response{status: resp.StatusCode, body: body}, resp.Header.Get("Location")
}

// do 发送请求并读取响应。
func (e *env) do(req *http.Request) response {
	e.t.Helper()
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatalf("请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return response{status: resp.StatusCode, body: body}
}

// requireStatus 断言 HTTP 状态码。
func requireStatus(t *testing.T, resp response, want int) {
	t.Helper()
	if resp.status != want {
		t.Fatalf("状态码不匹配: got %d want %d, body=%s", resp.status, want, resp.body)
	}
}

// decode 解析响应 JSON。
func decode(t *testing.T, resp response, v any) {
	t.Helper()
	if err := json.Unmarshal(resp.body, v); err != nil {
		t.Fatalf("解析响应失败: %v, body=%s", err, resp.body)
	}
}

// errCode 返回错误响应的 code。
func errCode(t *testing.T, resp response) string {
	t.Helper()
	var eb struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(resp.body, &eb); err != nil {
		t.Fatalf("解析错误响应失败: %v, body=%s", err, resp.body)
	}
	if eb.Error.Code == "" {
		t.Fatalf("错误响应缺少 code: %s", resp.body)
	}
	return eb.Error.Code
}

// itemWire 是条目在 HTTP 上的 JSON 形式。
type itemWire struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	RPID      string `json:"rp_id"`
	CT        string `json:"ct"`
	Nonce     string `json:"nonce"`
	Version   int64  `json:"version"`
	UpdatedAt int64  `json:"updated_at"`
	DeletedAt int64  `json:"deleted_at"`
}

// itemsGet 是 GET /items 的响应。
type itemsGet struct {
	Items []itemWire `json:"items"`
	Next  int64      `json:"next"`
}

// itemResult 是 POST /items 的单条结果。
type itemResult struct {
	ID      string `json:"id"`
	Version int64  `json:"version"`
	Status  string `json:"status"`
	Reason  string `json:"reason"`
}

// itemsPost 是 POST /items 的响应。
type itemsPost struct {
	Results []itemResult `json:"results"`
}

// itemPayload 构造单条写入请求。
func itemPayload(id, kind, rpID string, ct, nonce []byte, baseVersion, updatedAt, deletedAt int64) map[string]any {
	m := map[string]any{
		"id":           id,
		"kind":         kind,
		"rp_id":        rpID,
		"base_version": baseVersion,
		"updated_at":   updatedAt,
	}
	if ct != nil {
		m["ct"] = crypto.B64(ct)
	}
	if nonce != nil {
		m["nonce"] = crypto.B64(nonce)
	}
	if deletedAt != 0 {
		m["deleted_at"] = deletedAt
	}
	return m
}

// writeItems 发送一批条目写入。
func (e *env) writeItems(dev *testDevice, items ...map[string]any) response {
	e.t.Helper()
	b, err := json.Marshal(map[string]any{"items": items})
	if err != nil {
		e.t.Fatalf("序列化条目失败: %v", err)
	}
	return e.signedDo(dev, http.MethodPost, "/api/v1/items", b)
}

// getItems 增量拉取条目。
func (e *env) getItems(dev *testDevice, since int64) itemsGet {
	e.t.Helper()
	resp := e.signedDo(dev, http.MethodGet, "/api/v1/items?since="+strconv.FormatInt(since, 10), nil)
	requireStatus(e.t, resp, http.StatusOK)
	var out itemsGet
	decode(e.t, resp, &out)
	return out
}

// pairNew 登记配对会话。
func (e *env) pairNew(dev *testDevice, codeID string, code, blob, pwSalt []byte) response {
	e.t.Helper()
	body := map[string]any{
		"code_id": codeID,
		"code":    crypto.Base32Upper(code),
		"blob":    crypto.B64(blob),
	}
	if len(pwSalt) > 0 {
		body["pw_salt"] = crypto.B64(pwSalt)
	}
	b, err := json.Marshal(body)
	if err != nil {
		e.t.Fatalf("序列化配对请求失败: %v", err)
	}
	return e.signedDo(dev, http.MethodPost, "/api/v1/pair/new", b)
}

// claimPair 领取配对码（免鉴权）。
func (e *env) claimPair(code, name, platform string, pub ed25519.PublicKey) response {
	e.t.Helper()
	return e.postJSON("/api/v1/pair/claim", map[string]any{
		"code":     code,
		"name":     name,
		"platform": platform,
		"pubkey":   crypto.B64(pub),
	})
}
