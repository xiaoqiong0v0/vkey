package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"xiaoqiong0v0.cn/vkey/server/internal/store"
)

const (
	// updateMetadataAsset 是 Release 资产里的机器可读更新元数据文件名。
	updateMetadataAsset = "android.json"
	// updateFetchTimeout 是单次惰性拉取的上限（超过即放弃，保留旧值）。
	updateFetchTimeout = 5 * time.Second
	// updateFetchMaxBytes 是响应体上限（8 KiB），超出视为非法响应。
	updateFetchMaxBytes = 8 << 10
	// updateGitHubHost 是唯一允许拉取元数据的域名。
	updateGitHubHost = "github.com"
	// updateAssetHostSuffix 是 GitHub Release 资产实际落地的 CDN 域名后缀。
	updateAssetHostSuffix = ".githubusercontent.com"
	// updateMaxRedirects 是允许跟随的最大重定向次数。
	updateMaxRedirects = 3
	// updateCheckErrorMaxLen 是写入 meta 的失败原因最大长度（单行）。
	updateCheckErrorMaxLen = 200
)

// UpdateFetcher 是更新元数据的网络访问注入点：入参为已校验的 URL，返回响应体。
//
// 生产环境用 httpUpdateFetcher；测试注入假实现即可断言调用次数、模拟失败。
type UpdateFetcher func(ctx context.Context, rawURL string) ([]byte, error)

// updateMetadataURL 按仓库配置拼接 android.json 的下载地址。
func updateMetadataURL(repo string) string {
	return "https://" + updateGitHubHost + "/" + repo + "/releases/latest/download/" + updateMetadataAsset
}

// validateUpdateURL 校验地址只走 https 且只允许 GitHub 域名（防 SSRF）。
//
// 同时用于初始地址与每一跳重定向：GitHub 的 Release 资产会 302 到
// `*.githubusercontent.com`，因此 CDN 域名一并放行。
func validateUpdateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("更新元数据地址无效: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("更新元数据地址必须是 https，实际 %q", u.Scheme)
	}
	if u.User != nil {
		return errors.New("更新元数据地址不允许携带用户信息")
	}
	host := strings.ToLower(u.Hostname())
	if host != updateGitHubHost && !strings.HasSuffix(host, updateAssetHostSuffix) {
		return fmt.Errorf("更新元数据地址域名不允许: %q", host)
	}
	return nil
}

// updateHTTPClient 是惰性拉取专用客户端：5s 超时，重定向逐跳校验域名。
var updateHTTPClient = &http.Client{
	Timeout: updateFetchTimeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= updateMaxRedirects {
			return errors.New("更新元数据重定向次数过多")
		}
		return validateUpdateURL(req.URL.String())
	},
}

// httpUpdateFetcher 是缺省的 UpdateFetcher：限 https/GitHub 域名、响应体 ≤ 8 KiB。
func httpUpdateFetcher(ctx context.Context, rawURL string) ([]byte, error) {
	if err := validateUpdateURL(rawURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("构造更新元数据请求失败: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := updateHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求更新元数据失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("更新元数据响应异常: HTTP %d", resp.StatusCode)
	}
	body, err := readUpdateBody(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// readUpdateBody 读取响应体并施加 8 KiB 上限（超出视为非法响应）。
func readUpdateBody(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, updateFetchMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("读取更新元数据失败: %w", err)
	}
	if len(body) > updateFetchMaxBytes {
		return nil, fmt.Errorf("更新元数据超过 %d 字节上限", updateFetchMaxBytes)
	}
	return body, nil
}

// parseUpdateMetadata 解析并校验 android.json；任一字段非法即报错（调用方保留旧值）。
func parseUpdateMetadata(body []byte) (store.UpdateMetadata, error) {
	var raw struct {
		VersionCode int64  `json:"version_code"`
		VersionName string `json:"version_name"`
		SHA256      string `json:"sha256"`
		Size        int64  `json:"size"`
		PublishedAt int64  `json:"published_at"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return store.UpdateMetadata{}, fmt.Errorf("解析更新元数据失败: %w", err)
	}
	if raw.VersionCode <= 0 {
		return store.UpdateMetadata{}, errors.New("version_code 缺失或非法")
	}
	name := strings.TrimSpace(raw.VersionName)
	if name == "" || len(name) > 64 || strings.ContainsAny(name, "\x00\r\n\t") {
		return store.UpdateMetadata{}, errors.New("version_name 缺失或非法")
	}
	if !store.IsSHA256Hex(raw.SHA256) {
		return store.UpdateMetadata{}, errors.New("sha256 缺失或非法")
	}
	if raw.Size < 0 || raw.PublishedAt < 0 {
		return store.UpdateMetadata{}, errors.New("size/published_at 不能为负")
	}
	return store.UpdateMetadata{
		VersionCode: raw.VersionCode,
		VersionName: name,
		SHA256:      strings.ToLower(raw.SHA256),
		Size:        raw.Size,
		PublishedAt: raw.PublishedAt,
	}, nil
}

// sanitizeUpdateCheckError 把失败原因压成单行并截断，避免写坏 meta 展示。
func sanitizeUpdateCheckError(err error) string {
	msg := strings.Join(strings.Fields(err.Error()), " ")
	if r := []rune(msg); len(r) > updateCheckErrorMaxLen {
		msg = string(r[:updateCheckErrorMaxLen])
	}
	return msg
}
