package store

import (
	"context"
	"strconv"
)

// meta 表中与 Android 更新信息相关的键（均存字符串，整数以十进制表示）。
const (
	// MetaKeyUpdateSource 存更新来源："github"（默认）或 "local"。
	MetaKeyUpdateSource = "update.source"
	// MetaKeyUpdateRepo 存 GitHub 仓库（owner/repo）。
	MetaKeyUpdateRepo = "update.repo"
	// MetaKeyUpdateAsset 存 APK 产物文件名。
	MetaKeyUpdateAsset = "update.asset"
	// MetaKeyUpdateVersionCode 存 Android versionCode（十进制整数）。
	MetaKeyUpdateVersionCode = "update.version_code"
	// MetaKeyUpdateVersionName 存 Android versionName（如 0.3.2）。
	MetaKeyUpdateVersionName = "update.version_name"
	// MetaKeyUpdateSHA256 存 APK 的 sha256（64 位小写 hex）。
	MetaKeyUpdateSHA256 = "update.sha256"
	// MetaKeyUpdateSize 存 APK 字节数（十进制整数）。
	MetaKeyUpdateSize = "update.size"
	// MetaKeyUpdateNotes 存发布说明（可空）。
	MetaKeyUpdateNotes = "update.notes"
	// MetaKeyUpdatePublishedAt 存发布时间（unix 秒，由 CLI 写入时刷新）。
	MetaKeyUpdatePublishedAt = "update.published_at"
)

// 更新信息的缺省值（未写入 meta 时生效）。
const (
	// UpdateSourceGitHub 表示从 GitHub Releases 分发（默认）。
	UpdateSourceGitHub = "github"
	// UpdateSourceLocal 表示由本服务的 /dl/* 分发。
	UpdateSourceLocal = "local"
	// DefaultUpdateRepo 是缺省的 GitHub 仓库（owner/repo）。
	DefaultUpdateRepo = "xiaoqiong0v0/vkey"
	// DefaultUpdateAsset 是缺省的 APK 产物文件名。
	DefaultUpdateAsset = "vkey-android.apk"
)

// UpdateInfo 是 Android 更新信息的服务端配置（只来自 meta 表，不访问网络）。
type UpdateInfo struct {
	Source      string // "github" 或 "local"
	Repo        string // GitHub 仓库 owner/repo
	Asset       string // APK 产物文件名
	VersionCode int64
	VersionName string
	SHA256      string // 64 位小写 hex
	Size        int64  // APK 字节数，0 表示未知
	Notes       string // 发布说明，可空
	PublishedAt int64  // unix 秒，0 表示未知
	// Configured 表示 version_code 与 sha256 都已配置；为 false 时端点返回 204。
	Configured bool
}

// UpdateInfo 读取 Android 更新信息配置；未配置的键取缺省值。
func (s *Store) UpdateInfo(ctx context.Context) (*UpdateInfo, error) {
	info := &UpdateInfo{
		Source: UpdateSourceGitHub,
		Repo:   DefaultUpdateRepo,
		Asset:  DefaultUpdateAsset,
	}
	var err error
	if info.Source, err = s.metaGetString(ctx, MetaKeyUpdateSource, info.Source); err != nil {
		return nil, err
	}
	if info.Repo, err = s.metaGetString(ctx, MetaKeyUpdateRepo, info.Repo); err != nil {
		return nil, err
	}
	if info.Asset, err = s.metaGetString(ctx, MetaKeyUpdateAsset, info.Asset); err != nil {
		return nil, err
	}
	if info.VersionName, err = s.metaGetString(ctx, MetaKeyUpdateVersionName, ""); err != nil {
		return nil, err
	}
	if info.SHA256, err = s.metaGetString(ctx, MetaKeyUpdateSHA256, ""); err != nil {
		return nil, err
	}
	if info.Notes, err = s.metaGetString(ctx, MetaKeyUpdateNotes, ""); err != nil {
		return nil, err
	}
	if info.VersionCode, err = s.metaGetInt(ctx, MetaKeyUpdateVersionCode, 0); err != nil {
		return nil, err
	}
	if info.Size, err = s.metaGetInt(ctx, MetaKeyUpdateSize, 0); err != nil {
		return nil, err
	}
	if info.PublishedAt, err = s.metaGetInt(ctx, MetaKeyUpdatePublishedAt, 0); err != nil {
		return nil, err
	}
	info.Configured = info.VersionCode != 0 && info.SHA256 != ""
	return info, nil
}

// SetUpdatePublishedAt 记录发布时间（unix 秒，CLI 写入新版本时调用）。
func (s *Store) SetUpdatePublishedAt(ctx context.Context, ts int64) error {
	return s.SetMeta(ctx, MetaKeyUpdatePublishedAt, strconv.FormatInt(ts, 10))
}

// metaGetString 读取字符串 meta 键；缺省时返回 def。
func (s *Store) metaGetString(ctx context.Context, key, def string) (string, error) {
	v, ok, err := s.metaGetDB(ctx, key)
	if err != nil || !ok {
		return def, err
	}
	return v, nil
}
