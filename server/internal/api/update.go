package api

import (
	"context"
	"fmt"
	"net/http"

	"xiaoqiong0v0.cn/vkey/server/internal/store"
)

// updateCacheControl 是更新信息端点的缓存策略（5 分钟）。
const updateCacheControl = "public, max-age=300"

// updateResponse 是 GET /api/v1/update/android 的响应体。
type updateResponse struct {
	VersionCode int64  `json:"version_code"`
	VersionName string `json:"version_name"`
	URL         string `json:"url"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	Notes       string `json:"notes,omitempty"`
	Source      string `json:"source"`
	PublishedAt int64  `json:"published_at"`
}

// handleUpdateAndroid 返回 Android 更新信息（免鉴权）。
//
// 惰性刷新：auto_check 开启且 TTL 到期时，同步拉取一次 Release 资产 android.json
// 后返回；拉取失败保留旧值、仍返回 200/204。并发请求只允许一个真正拉取
// （TryLock 失败的请求直接用缓存返回，不阻塞）。
func (s *Server) handleUpdateAndroid(w http.ResponseWriter, r *http.Request) {
	info, err := s.store.UpdateInfo(r.Context())
	if err != nil {
		s.logErr("查询更新配置失败", err)
		writeErr(w, http.StatusInternalServerError, "internal", "服务端内部错误")
		return
	}
	info = s.refreshUpdateIfDue(r.Context(), info)
	// /api/* 的默认 no-store 在这里被覆盖为可缓存（更新信息变化不频繁）。
	w.Header().Set("Cache-Control", updateCacheControl)
	if !info.Configured {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, updateResponse{
		VersionCode: info.VersionCode,
		VersionName: info.VersionName,
		URL:         s.updateURL(r, info),
		SHA256:      info.SHA256,
		Size:        info.Size,
		Notes:       info.Notes,
		Source:      info.Source,
		PublishedAt: info.PublishedAt,
	})
}

// refreshUpdateIfDue 在 TTL 到期时同步尝试刷新一次元数据，返回最终展示用的信息。
//
// 返回：始终返回可用的信息（刷新失败时为入参本身）；刷新失败不影响响应。
func (s *Server) refreshUpdateIfDue(ctx context.Context, info *store.UpdateInfo) *store.UpdateInfo {
	// source=local 由本服务分发，无需访问网络。
	if !info.AutoCheck || info.Source != store.UpdateSourceGitHub {
		return info
	}
	now := s.nowUnix()
	if !updateDue(now, info.LastCheckedAt, info.CheckInterval) {
		return info
	}
	// 已有请求在拉取：直接用缓存返回，不阻塞（也不排队）。
	if !s.updateFetchMu.TryLock() {
		return info
	}
	defer s.updateFetchMu.Unlock()
	// 等锁期间别人可能已经刷新过：以库中最新状态再判一次 TTL。
	if cur, err := s.store.UpdateInfo(ctx); err == nil {
		info = cur
		if !updateDue(s.nowUnix(), info.LastCheckedAt, info.CheckInterval) {
			return info
		}
	}
	return s.refreshUpdate(ctx, info)
}

// refreshUpdate 真正执行一次拉取 + 落库；失败只记录，不改动旧数据。
func (s *Server) refreshUpdate(ctx context.Context, info *store.UpdateInfo) *store.UpdateInfo {
	// 客户端断开不应丢掉「已尝试过」这件事，否则每个请求都会重试。
	bookCtx := context.WithoutCancel(ctx)
	now := s.nowUnix()

	md, err := s.fetchUpdateMetadata(ctx, info.Repo)
	if err != nil {
		s.logger.Printf("更新元数据拉取失败: %v", err)
		if werr := s.store.RecordUpdateCheckFailure(bookCtx, now, sanitizeUpdateCheckError(err)); werr != nil {
			s.logErr("记录更新检查失败", werr)
		}
		return info
	}
	if werr := s.store.ApplyUpdateMetadata(bookCtx, md, now); werr != nil {
		s.logErr("写入更新元数据失败", werr)
		return info
	}
	latest, lerr := s.store.UpdateInfo(ctx)
	if lerr != nil {
		s.logErr("刷新后读取更新配置失败", lerr)
		return info
	}
	return latest
}

// fetchUpdateMetadata 校验配置并拉取一次 android.json（超时 5s）。
func (s *Server) fetchUpdateMetadata(ctx context.Context, repo string) (store.UpdateMetadata, error) {
	if !store.ValidUpdateRepo(repo) {
		return store.UpdateMetadata{}, fmt.Errorf("仓库配置非法: %q", repo)
	}
	raw := updateMetadataURL(repo)
	if err := validateUpdateURL(raw); err != nil {
		return store.UpdateMetadata{}, err
	}
	fetch := s.updateFetch
	if fetch == nil {
		fetch = httpUpdateFetcher
	}
	fetchCtx, cancel := context.WithTimeout(ctx, updateFetchTimeout)
	defer cancel()
	body, err := fetch(fetchCtx, raw)
	if err != nil {
		return store.UpdateMetadata{}, err
	}
	return parseUpdateMetadata(body)
}

// updateDue 判断距上次检查是否已到 TTL（0 间隔表示每次请求都检查）。
func updateDue(now, lastCheckedAt, interval int64) bool {
	if interval <= 0 {
		return true
	}
	return now-lastCheckedAt >= interval
}

// updateURL 按配置的来源拼接 APK 下载地址。
//
// github：https://github.com/{repo}/releases/latest/download/{asset}
// local ：https://{domain}/dl/{asset}（域名优先取 --domain，其次按请求推导）
func (s *Server) updateURL(r *http.Request, info *store.UpdateInfo) string {
	if info.Source == store.UpdateSourceLocal {
		return s.serverURL(r) + "/dl/" + info.Asset
	}
	return "https://github.com/" + info.Repo + "/releases/latest/download/" + info.Asset
}
