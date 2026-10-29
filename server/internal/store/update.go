package store

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
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
	// MetaKeyUpdateAutoCheck 存是否允许「请求时惰性检查」（"true" / "false"）。
	MetaKeyUpdateAutoCheck = "update.auto_check"
	// MetaKeyUpdateCheckInterval 存惰性检查的最小间隔（秒，0 表示每次请求都检查）。
	MetaKeyUpdateCheckInterval = "update.check_interval"
	// MetaKeyUpdateLastCheckedAt 存最近一次惰性检查的时刻（unix 秒，仅服务端写）。
	MetaKeyUpdateLastCheckedAt = "update.last_checked_at"
	// MetaKeyUpdateLastCheckError 存最近一次检查的失败原因（成功时清空）。
	MetaKeyUpdateLastCheckError = "update.last_check_error"
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
	// DefaultUpdateAutoCheck 是惰性检查的缺省开关。
	DefaultUpdateAutoCheck = true
	// DefaultUpdateCheckInterval 是惰性检查的缺省间隔（秒，86400 = 1 天）。
	DefaultUpdateCheckInterval int64 = 86400
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
	// AutoCheck 表示允许在请求到达时按 TTL 顺带检查一次远端元数据。
	AutoCheck bool
	// CheckInterval 是最小检查间隔（秒）；0 表示每次请求都检查。
	CheckInterval int64
	// LastCheckedAt 是最近一次检查时刻（unix 秒），0 表示从未检查。
	LastCheckedAt int64
	// LastCheckError 是最近一次检查的失败原因，成功时清空。
	LastCheckError string
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
	if info.AutoCheck, err = s.metaGetBool(ctx, MetaKeyUpdateAutoCheck, DefaultUpdateAutoCheck); err != nil {
		return nil, err
	}
	if info.CheckInterval, err = s.metaGetInt(ctx, MetaKeyUpdateCheckInterval, DefaultUpdateCheckInterval); err != nil {
		return nil, err
	}
	if info.CheckInterval < 0 {
		// 库中的负数视为损坏：退回缺省间隔，避免退化成「每个请求都打网络」。
		info.CheckInterval = DefaultUpdateCheckInterval
	}
	if info.LastCheckedAt, err = s.metaGetInt(ctx, MetaKeyUpdateLastCheckedAt, 0); err != nil {
		return nil, err
	}
	if info.LastCheckError, err = s.metaGetString(ctx, MetaKeyUpdateLastCheckError, ""); err != nil {
		return nil, err
	}
	info.Configured = info.VersionCode != 0 && info.SHA256 != ""
	return info, nil
}

// SetUpdatePublishedAt 记录发布时间（unix 秒，CLI 写入新版本时调用）。
func (s *Store) SetUpdatePublishedAt(ctx context.Context, ts int64) error {
	return s.SetMeta(ctx, MetaKeyUpdatePublishedAt, strconv.FormatInt(ts, 10))
}

// UpdateMetadata 是 Release 资产 android.json 的解析结果。
type UpdateMetadata struct {
	VersionCode int64
	VersionName string
	SHA256      string // 64 位小写 hex
	Size        int64  // APK 字节数
	PublishedAt int64  // unix 秒
}

// ApplyUpdateMetadata 用拉取到的元数据覆盖更新信息，刷新检查时刻并清空失败原因。
//
// 单事务写入，避免响应读到「版本已变但摘要未变」的中间态。
func (s *Store) ApplyUpdateMetadata(ctx context.Context, md UpdateMetadata, checkedAt int64) error {
	items := []struct{ key, value string }{
		{MetaKeyUpdateVersionCode, strconv.FormatInt(md.VersionCode, 10)},
		{MetaKeyUpdateVersionName, md.VersionName},
		{MetaKeyUpdateSHA256, md.SHA256},
		{MetaKeyUpdateSize, strconv.FormatInt(md.Size, 10)},
		{MetaKeyUpdatePublishedAt, strconv.FormatInt(md.PublishedAt, 10)},
		{MetaKeyUpdateLastCheckedAt, strconv.FormatInt(checkedAt, 10)},
		{MetaKeyUpdateLastCheckError, ""},
	}
	return s.setMetaBatch(ctx, items)
}

// RecordUpdateCheckFailure 记录一次失败的惰性检查：刷新检查时刻并保存失败原因。
//
// 旧的更新信息保持不变；刷新检查时刻是为了让失败也受 TTL 约束，不每个请求都打网络。
func (s *Store) RecordUpdateCheckFailure(ctx context.Context, checkedAt int64, reason string) error {
	return s.setMetaBatch(ctx, []struct{ key, value string }{
		{MetaKeyUpdateLastCheckedAt, strconv.FormatInt(checkedAt, 10)},
		{MetaKeyUpdateLastCheckError, reason},
	})
}

// ValidUpdateRepo 判断取值能否安全拼进 GitHub 下载地址（owner/repo，仅字母数字与 . _ -）。
func ValidUpdateRepo(repo string) bool {
	parts := strings.Split(repo, "/")
	if len(parts) != 2 {
		return false
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return false
		}
		for _, c := range p {
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
				c == '.', c == '_', c == '-':
			default:
				return false
			}
		}
	}
	return true
}

// IsSHA256Hex 判断取值是否为 64 位十六进制（大小写均可）。
func IsSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// setMetaBatch 在单事务内写入多条 meta 键值。
func (s *Store) setMetaBatch(ctx context.Context, items []struct{ key, value string }) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: 开启事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, it := range items {
		if err := metaSet(ctx, tx, it.key, it.value); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: 提交事务失败: %w", err)
	}
	return nil
}

// metaExecer 是 *sql.DB 与 *sql.Tx 共有的最小写入接口（复用同一条 upsert 语句）。
type metaExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// metaSet 写入（或覆盖）一条 meta 键值。
func metaSet(ctx context.Context, ex metaExecer, key, value string) error {
	_, err := ex.ExecContext(ctx,
		`INSERT INTO meta(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	if err != nil {
		return fmt.Errorf("store: 写入 meta 失败: %w", err)
	}
	return nil
}

// metaGetBool 读取布尔 meta 键；缺省或值损坏时返回 def。
func (s *Store) metaGetBool(ctx context.Context, key string, def bool) (bool, error) {
	v, ok, err := s.metaGetDB(ctx, key)
	if err != nil || !ok {
		return def, err
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def, nil // 值损坏时按默认值处理
	}
	return b, nil
}

// metaGetString 读取字符串 meta 键；缺省时返回 def。
func (s *Store) metaGetString(ctx context.Context, key, def string) (string, error) {
	v, ok, err := s.metaGetDB(ctx, key)
	if err != nil || !ok {
		return def, err
	}
	return v, nil
}
