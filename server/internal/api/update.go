package api

import (
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

// handleUpdateAndroid 返回 Android 更新信息（免鉴权，只读配置，不访问网络）。
//
// 配置不完整（缺 version_code 或 sha256）时返回 204，客户端视为「暂无更新」。
func (s *Server) handleUpdateAndroid(w http.ResponseWriter, r *http.Request) {
	info, err := s.store.UpdateInfo(r.Context())
	if err != nil {
		s.logErr("查询更新配置失败", err)
		writeErr(w, http.StatusInternalServerError, "internal", "服务端内部错误")
		return
	}
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
