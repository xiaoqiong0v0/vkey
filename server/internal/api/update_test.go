package api_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"xiaoqiong0v0.cn/vkey/server/internal/api"
	"xiaoqiong0v0.cn/vkey/server/internal/store"
)

// testSHA256 是测试用 APK 摘要（64 位小写 hex）。
const testSHA256 = "3f786850e387550fdab836ed7e6dc881de23001b2b0f4d1ad1e0c1e7b6d4b3f0"

// TestUpdateAndroidNotConfigured 验证未配置更新信息时返回 204 且无正文。
func TestUpdateAndroidNotConfigured(t *testing.T) {
	e := newEnv(t)
	resp, header := e.getWithHeader(http.MethodGet, "/api/v1/update/android")
	requireStatus(t, resp, http.StatusNoContent)
	if len(resp.body) != 0 {
		t.Fatalf("204 不应有正文，实际 %q", resp.body)
	}
	if cc := header.Get("Cache-Control"); cc != "public, max-age=300" {
		t.Fatalf("Cache-Control = %q", cc)
	}
}

// TestUpdateAndroidGitHub 验证默认 github 源返回 200 与 Releases 下载地址。
func TestUpdateAndroidGitHub(t *testing.T) {
	e := newEnv(t)
	// 只写 version_code + sha256 即视为已配置，其余取缺省值（github / 默认仓库与产物名）。
	e.setMeta(store.MetaKeyUpdateVersionCode, "30101")
	e.setMeta(store.MetaKeyUpdateVersionName, "0.3.2")
	e.setMeta(store.MetaKeyUpdateSHA256, testSHA256)
	e.setMeta(store.MetaKeyUpdateSize, "8388608")
	e.setMeta(store.MetaKeyUpdateNotes, "首个公开版本")

	resp, header := e.getWithHeader(http.MethodGet, "/api/v1/update/android")
	requireStatus(t, resp, http.StatusOK)
	if cc := header.Get("Cache-Control"); cc != "public, max-age=300" {
		t.Fatalf("Cache-Control = %q", cc)
	}

	var out struct {
		VersionCode int64  `json:"version_code"`
		VersionName string `json:"version_name"`
		URL         string `json:"url"`
		SHA256      string `json:"sha256"`
		Size        int64  `json:"size"`
		Notes       string `json:"notes"`
		Source      string `json:"source"`
		PublishedAt int64  `json:"published_at"`
	}
	decode(t, resp, &out)

	const wantPrefix = "https://github.com/xiaoqiong0v0/vkey/releases/latest/download/"
	if !strings.HasPrefix(out.URL, wantPrefix) {
		t.Fatalf("url = %q，期望前缀 %q", out.URL, wantPrefix)
	}
	if !strings.HasSuffix(out.URL, "/vkey-android.apk") {
		t.Fatalf("url = %q，期望以 /vkey-android.apk 结尾", out.URL)
	}
	if out.VersionCode != 30101 || out.VersionName != "0.3.2" {
		t.Fatalf("版本字段不匹配: %+v", out)
	}
	if out.SHA256 != testSHA256 || out.Size != 8388608 || out.Notes != "首个公开版本" {
		t.Fatalf("产物字段不匹配: %+v", out)
	}
	if out.Source != store.UpdateSourceGitHub {
		t.Fatalf("source = %q", out.Source)
	}
}

// TestUpdateAndroidLocalSource 验证 source=local 时 url 指向本服务 /dl/<asset>。
func TestUpdateAndroidLocalSource(t *testing.T) {
	e := newEnv(t)
	e.setMeta(store.MetaKeyUpdateSource, store.UpdateSourceLocal)
	e.setMeta(store.MetaKeyUpdateVersionCode, "30101")
	e.setMeta(store.MetaKeyUpdateSHA256, testSHA256)

	resp, _ := e.getWithHeader(http.MethodGet, "/api/v1/update/android")
	requireStatus(t, resp, http.StatusOK)
	var out struct {
		URL    string `json:"url"`
		Source string `json:"source"`
	}
	decode(t, resp, &out)

	// testEnv 固定 Domain=https://vkey.test（见 testenv_test.go）。
	if want := "https://vkey.test/dl/vkey-android.apk"; out.URL != want {
		t.Fatalf("url = %q，期望 %q", out.URL, want)
	}
	if out.Source != store.UpdateSourceLocal {
		t.Fatalf("source = %q", out.Source)
	}
}

// TestUpdateAndroidIncompleteConfig 验证缺 version_code 或 sha256 时仍返回 204。
func TestUpdateAndroidIncompleteConfig(t *testing.T) {
	tests := []struct {
		name string
		key  string
		val  string
	}{
		{name: "只配 version_code 缺 sha256", key: store.MetaKeyUpdateVersionCode, val: "30101"},
		{name: "只配 sha256 缺 version_code", key: store.MetaKeyUpdateSHA256, val: testSHA256},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.setMeta(tc.key, tc.val)
			resp, _ := e.getWithHeader(http.MethodGet, "/api/v1/update/android")
			requireStatus(t, resp, http.StatusNoContent)
			if len(resp.body) != 0 {
				t.Fatalf("204 不应有正文，实际 %q", resp.body)
			}
		})
	}
}

// TestUpdateAndroidMethodNotAllowed 验证 POST 返回 405 与 Allow: GET。
func TestUpdateAndroidMethodNotAllowed(t *testing.T) {
	e := newEnv(t)
	resp, header := e.doWithHeader(http.MethodPost, "/api/v1/update/android", strings.NewReader("{}"))
	requireStatus(t, resp, http.StatusMethodNotAllowed)
	if code := errCode(t, resp); code != "method_not_allowed" {
		t.Fatalf("error.code = %q", code)
	}
	if allow := header.Get("Allow"); allow != "GET" {
		t.Fatalf("Allow = %q", allow)
	}
}

// ---------------------------------------------------------------------------
// 测试辅助
// ---------------------------------------------------------------------------

// setMeta 直接写一条 meta 键值（模拟 CLI 配置结果）。
func (e *env) setMeta(key, value string) {
	e.t.Helper()
	if err := e.st.SetMeta(context.Background(), key, value); err != nil {
		e.t.Fatalf("写入 meta %s 失败: %v", key, err)
	}
}

// getWithHeader 发送免鉴权 GET 并返回响应与响应头。
func (e *env) getWithHeader(method, path string) (response, http.Header) {
	e.t.Helper()
	return e.doWithHeader(method, path, nil)
}

// doWithHeader 发送免鉴权请求并返回响应与响应头。
func (e *env) doWithHeader(method, path string, body io.Reader) (response, http.Header) {
	e.t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, body)
	if err != nil {
		e.t.Fatalf("构造请求失败: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatalf("请求 %s 失败: %v", path, err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return response{status: res.StatusCode, body: b}, res.Header
}

// ---------------------------------------------------------------------------
// 惰性刷新（auto_check / check_interval / last_checked_at）
// ---------------------------------------------------------------------------

// testSHA256New 是另一个测试用 APK 摘要（64 位小写 hex）。
var testSHA256New = strings.Repeat("ab", 32)

// baseUnix 是惰性刷新用例的固定时间基准。
const baseUnix int64 = 1_700_000_000

// fixedClock 是可手动推进的测试时钟。
type fixedClock struct {
	mu sync.Mutex
	t  time.Time
}

// newFixedClock 以 unix 秒构造测试时钟。
func newFixedClock(sec int64) *fixedClock {
	return &fixedClock{t: time.Unix(sec, 0).UTC()}
}

// Now 返回当前测试时间。
func (c *fixedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Add 推进测试时间。
func (c *fixedClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// countingFetcher 是 UpdateFetcher 的测试替身：统计调用次数并可模拟失败/延迟。
type countingFetcher struct {
	mu      sync.Mutex
	calls   int
	lastURL string
	delay   time.Duration
	body    []byte
	err     error
}

// fetch 实现 api.UpdateFetcher。
func (f *countingFetcher) fetch(ctx context.Context, rawURL string) ([]byte, error) {
	f.mu.Lock()
	f.calls++
	f.lastURL = rawURL
	delay, body, err := f.delay, f.body, f.err
	f.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return body, err
}

// count 返回已发生的拉取次数。
func (f *countingFetcher) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// updateMetadataJSON 构造 android.json 响应体。
func updateMetadataJSON(versionCode int64, versionName, sha string, size, publishedAt int64) []byte {
	return []byte(fmt.Sprintf(
		`{"version_code":%d,"version_name":%q,"sha256":%q,"size":%d,"published_at":%d}`,
		versionCode, versionName, sha, size, publishedAt))
}

// newUpdateEnv 构造注入了时钟与 fetcher 的测试环境（预置已配置的旧版本）。
func newUpdateEnv(t *testing.T, clock *fixedClock, f *countingFetcher) *env {
	t.Helper()
	e := newEnvOpts(t, func(o *api.Options) {
		o.Now = clock.Now
		o.UpdateFetcher = f.fetch
	})
	e.setMeta(store.MetaKeyUpdateVersionCode, "30101")
	e.setMeta(store.MetaKeyUpdateVersionName, "0.3.2")
	e.setMeta(store.MetaKeyUpdateSHA256, testSHA256)
	e.setMeta(store.MetaKeyUpdateSize, "8388608")
	return e
}

// updateVersion 读出当前 meta 中的版本信息（断言刷新结果用）。
func (e *env) updateVersion() *store.UpdateInfo {
	e.t.Helper()
	info, err := e.st.UpdateInfo(context.Background())
	if err != nil {
		e.t.Fatalf("读取更新配置失败: %v", err)
	}
	return info
}

// decodedUpdate 是响应体里断言需要的字段。
type decodedUpdate struct {
	VersionCode int64  `json:"version_code"`
	VersionName string `json:"version_name"`
	SHA256      string `json:"sha256"`
	URL         string `json:"url"`
}

// TestUpdateLazyRefreshTTLNotDue 验证 TTL 未到期时不发起网络请求。
func TestUpdateLazyRefreshTTLNotDue(t *testing.T) {
	clock := newFixedClock(baseUnix)
	f := &countingFetcher{body: updateMetadataJSON(30200, "0.3.3", testSHA256New, 1, baseUnix)}
	e := newUpdateEnv(t, clock, f)
	e.setMeta(store.MetaKeyUpdateLastCheckedAt, fmt.Sprintf("%d", baseUnix-60))

	for i := 0; i < 2; i++ {
		resp, _ := e.getWithHeader(http.MethodGet, "/api/v1/update/android")
		requireStatus(t, resp, http.StatusOK)
		var out decodedUpdate
		decode(t, resp, &out)
		if out.VersionCode != 30101 {
			t.Fatalf("TTL 未到期不应刷新，version_code = %d", out.VersionCode)
		}
	}
	if got := f.count(); got != 0 {
		t.Fatalf("TTL 未到期却拉取了 %d 次", got)
	}
}

// TestUpdateLazyRefreshTTLDue 验证到期时拉取一次并更新 meta，后续请求不再拉取。
func TestUpdateLazyRefreshTTLDue(t *testing.T) {
	clock := newFixedClock(baseUnix)
	f := &countingFetcher{body: updateMetadataJSON(30200, "0.3.3", strings.ToUpper(testSHA256New), 4242, baseUnix-1)}
	e := newUpdateEnv(t, clock, f)

	resp, _ := e.getWithHeader(http.MethodGet, "/api/v1/update/android")
	requireStatus(t, resp, http.StatusOK)
	var out decodedUpdate
	decode(t, resp, &out)
	if out.VersionCode != 30200 || out.VersionName != "0.3.3" {
		t.Fatalf("响应未使用刷新后的版本: %+v", out)
	}
	if out.SHA256 != testSHA256New { // 服务端统一转小写
		t.Fatalf("sha256 = %q，期望 %q", out.SHA256, testSHA256New)
	}
	if got := f.count(); got != 1 {
		t.Fatalf("首次到期应拉取 1 次，实际 %d", got)
	}
	if want := "https://github.com/xiaoqiong0v0/vkey/releases/latest/download/android.json"; f.lastURL != want {
		t.Fatalf("拉取地址 = %q，期望 %q", f.lastURL, want)
	}

	info := e.updateVersion()
	if info.VersionCode != 30200 || info.Size != 4242 || info.PublishedAt != baseUnix-1 {
		t.Fatalf("meta 未按 android.json 更新: %+v", info)
	}
	if info.LastCheckedAt != baseUnix || info.LastCheckError != "" {
		t.Fatalf("检查状态未刷新: last_checked_at=%d last_check_error=%q", info.LastCheckedAt, info.LastCheckError)
	}

	// 第二次请求：TTL 内，不再拉取。
	resp, _ = e.getWithHeader(http.MethodGet, "/api/v1/update/android")
	requireStatus(t, resp, http.StatusOK)
	if got := f.count(); got != 1 {
		t.Fatalf("TTL 内重复拉取: %d 次", got)
	}
}

// TestUpdateLazyRefreshFailureKeepsOld 验证拉取失败保留旧值、写 error、仍返回 200。
func TestUpdateLazyRefreshFailureKeepsOld(t *testing.T) {
	clock := newFixedClock(baseUnix)
	f := &countingFetcher{err: errors.New("更新元数据响应异常: HTTP 500")}
	e := newUpdateEnv(t, clock, f)

	resp, _ := e.getWithHeader(http.MethodGet, "/api/v1/update/android")
	requireStatus(t, resp, http.StatusOK)
	var out decodedUpdate
	decode(t, resp, &out)
	if out.VersionCode != 30101 || out.SHA256 != testSHA256 {
		t.Fatalf("失败时不应改动旧值: %+v", out)
	}

	info := e.updateVersion()
	if info.VersionCode != 30101 || info.SHA256 != testSHA256 {
		t.Fatalf("meta 被失败结果污染: %+v", info)
	}
	if !strings.Contains(info.LastCheckError, "HTTP 500") {
		t.Fatalf("last_check_error = %q", info.LastCheckError)
	}
	if info.LastCheckedAt != baseUnix {
		t.Fatalf("失败也应刷新 last_checked_at，实际 %d", info.LastCheckedAt)
	}

	// 失败同样受 TTL 约束：紧接着的请求不再打网络。
	resp, _ = e.getWithHeader(http.MethodGet, "/api/v1/update/android")
	requireStatus(t, resp, http.StatusOK)
	if got := f.count(); got != 1 {
		t.Fatalf("失败后每个请求都重试了: %d 次", got)
	}
}

// TestUpdateLazyRefreshDisabled 验证 auto_check=false 时永不拉取。
func TestUpdateLazyRefreshDisabled(t *testing.T) {
	clock := newFixedClock(baseUnix)
	f := &countingFetcher{body: updateMetadataJSON(30200, "0.3.3", testSHA256New, 1, baseUnix)}
	e := newUpdateEnv(t, clock, f)
	e.setMeta(store.MetaKeyUpdateAutoCheck, "false")

	for i := 0; i < 2; i++ {
		resp, _ := e.getWithHeader(http.MethodGet, "/api/v1/update/android")
		requireStatus(t, resp, http.StatusOK)
	}
	if got := f.count(); got != 0 {
		t.Fatalf("auto_check=false 仍拉取了 %d 次", got)
	}
	if info := e.updateVersion(); info.LastCheckedAt != 0 {
		t.Fatalf("auto_check=false 不应写 last_checked_at，实际 %d", info.LastCheckedAt)
	}
}

// TestUpdateLazyRefreshIntervalZero 验证 check_interval=0 时每次请求都拉取。
func TestUpdateLazyRefreshIntervalZero(t *testing.T) {
	clock := newFixedClock(baseUnix)
	f := &countingFetcher{body: updateMetadataJSON(30200, "0.3.3", testSHA256New, 1, baseUnix)}
	e := newUpdateEnv(t, clock, f)
	e.setMeta(store.MetaKeyUpdateCheckInterval, "0")

	for i := 1; i <= 2; i++ {
		resp, _ := e.getWithHeader(http.MethodGet, "/api/v1/update/android")
		requireStatus(t, resp, http.StatusOK)
		if got := f.count(); got != i {
			t.Fatalf("第 %d 次请求后拉取次数 = %d，期望 %d", i, got, i)
		}
	}
}

// TestUpdateLazyRefreshConcurrentOnlyOneFetch 验证并发到期请求只触发一次拉取。
func TestUpdateLazyRefreshConcurrentOnlyOneFetch(t *testing.T) {
	clock := newFixedClock(baseUnix)
	f := &countingFetcher{
		delay: 80 * time.Millisecond,
		body:  updateMetadataJSON(30200, "0.3.3", testSHA256New, 1, baseUnix),
	}
	e := newUpdateEnv(t, clock, f)

	const n = 10
	var wg sync.WaitGroup
	statuses := make([]int, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := e.srv.Client().Get(e.srv.URL + "/api/v1/update/android")
			if err != nil {
				errs[i] = err
				return
			}
			defer func() { _ = res.Body.Close() }()
			_, _ = io.Copy(io.Discard, res.Body)
			statuses[i] = res.StatusCode
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("并发请求 %d 失败: %v", i, errs[i])
		}
		if statuses[i] != http.StatusOK {
			t.Fatalf("并发请求 %d 状态码 = %d", i, statuses[i])
		}
	}
	if got := f.count(); got != 1 {
		t.Fatalf("并发到期应只拉取 1 次，实际 %d", got)
	}
}

// TestUpdateLazyRefreshLocalSourceSkipsNetwork 验证 source=local 时不发网络请求。
func TestUpdateLazyRefreshLocalSourceSkipsNetwork(t *testing.T) {
	clock := newFixedClock(baseUnix)
	f := &countingFetcher{body: updateMetadataJSON(30200, "0.3.3", testSHA256New, 1, baseUnix)}
	e := newUpdateEnv(t, clock, f)
	e.setMeta(store.MetaKeyUpdateSource, store.UpdateSourceLocal)

	resp, _ := e.getWithHeader(http.MethodGet, "/api/v1/update/android")
	requireStatus(t, resp, http.StatusOK)
	if got := f.count(); got != 0 {
		t.Fatalf("source=local 不应拉取，实际 %d 次", got)
	}
}

// TestUpdateLazyRefreshBootstrapsUnconfigured 验证未配置时也能靠惰性拉取变为 200。
func TestUpdateLazyRefreshBootstrapsUnconfigured(t *testing.T) {
	clock := newFixedClock(baseUnix)
	f := &countingFetcher{body: updateMetadataJSON(30200, "0.3.3", testSHA256New, 77, baseUnix)}
	e := newEnvOpts(t, func(o *api.Options) {
		o.Now = clock.Now
		o.UpdateFetcher = f.fetch
	})

	resp, _ := e.getWithHeader(http.MethodGet, "/api/v1/update/android")
	requireStatus(t, resp, http.StatusOK)
	var out decodedUpdate
	decode(t, resp, &out)
	if out.VersionCode != 30200 || out.SHA256 != testSHA256New {
		t.Fatalf("未配置时应由 android.json 补齐: %+v", out)
	}
	if info := e.updateVersion(); !info.Configured || info.Size != 77 {
		t.Fatalf("meta 未补齐: %+v", info)
	}
}
