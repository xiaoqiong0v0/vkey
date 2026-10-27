package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// UpsertDevice 按公钥查找设备：已存在则更新名称/平台/token，否则新建。
//
// 参数：pubkey 为 32 字节 Ed25519 公钥；tokenHash 为设备 token 的 SHA-256。
// 返回：设备 id。已吊销的同公钥设备不会被复用（视为新设备）。
//
// 语义：同一设备的旧 token 会被新 token 覆盖，即重新认证会作废旧 token。
func (s *Store) UpsertDevice(ctx context.Context, userID, name, platform string, pubkey, tokenHash []byte, now int64) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("store: 开启事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var id string
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM devices WHERE user_id = ? AND pubkey = ? AND revoked_at IS NULL
		 ORDER BY created_at ASC LIMIT 1`, userID, pubkey).Scan(&id)
	switch {
	case err == nil:
		if _, err := tx.ExecContext(ctx,
			`UPDATE devices SET name = ?, platform = ?, token_hash = ?, last_seen = ? WHERE id = ?`,
			name, platform, tokenHash, now, id); err != nil {
			return "", fmt.Errorf("store: 更新设备失败: %w", err)
		}
	case errors.Is(err, sql.ErrNoRows):
		id, err = newID()
		if err != nil {
			return "", err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO devices(id, user_id, name, platform, pubkey, token_hash, revoked_at, created_at, last_seen)
			 VALUES(?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
			id, userID, name, platform, pubkey, tokenHash, now, now); err != nil {
			return "", fmt.Errorf("store: 插入设备失败: %w", err)
		}
	default:
		return "", fmt.Errorf("store: 查询设备失败: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("store: 提交事务失败: %w", err)
	}
	return id, nil
}

// CreateDevice 注册一个尚无 token 的设备（POST /devices/register）。
//
// 若同账号下同公钥的未吊销设备已存在，直接返回其 id（幂等）。
func (s *Store) CreateDevice(ctx context.Context, userID, name, platform string, pubkey, tokenHash []byte, now int64) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM devices WHERE user_id = ? AND pubkey = ? AND revoked_at IS NULL
		 ORDER BY created_at ASC LIMIT 1`, userID, pubkey).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("store: 查询设备失败: %w", err)
	}
	id, err = newID()
	if err != nil {
		return "", err
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO devices(id, user_id, name, platform, pubkey, token_hash, revoked_at, created_at, last_seen)
		 VALUES(?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
		id, userID, name, platform, pubkey, tokenHash, now, now); err != nil {
		return "", fmt.Errorf("store: 插入设备失败: %w", err)
	}
	return id, nil
}

// DeviceByTokenHash 按 token 哈希查找未吊销设备，不存在时返回 ErrNotFound。
func (s *Store) DeviceByTokenHash(ctx context.Context, tokenHash []byte) (*Device, error) {
	var (
		d   Device
		rev sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, name, platform, pubkey, token_hash, revoked_at, created_at, last_seen
		 FROM devices WHERE token_hash = ? AND revoked_at IS NULL`, tokenHash).
		Scan(&d.ID, &d.UserID, &d.Name, &d.Platform, &d.PubKey, &d.TokenHash, &rev, &d.CreatedAt, &d.LastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: 读取设备失败: %w", err)
	}
	d.RevokedAt = rev.Int64
	return &d, nil
}

// RevokeDevice 吊销设备并清空其 token；设备不存在或已吊销时返回 ErrNotFound。
func (s *Store) RevokeDevice(ctx context.Context, userID, deviceID string, now int64) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE devices SET revoked_at = ?, token_hash = NULL
		 WHERE user_id = ? AND id = ? AND revoked_at IS NULL`, now, userID, deviceID)
	if err != nil {
		return fmt.Errorf("store: 吊销设备失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchDevice 更新设备最近活跃时间。
func (s *Store) TouchDevice(ctx context.Context, deviceID string, now int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET last_seen = ? WHERE id = ?`, now, deviceID)
	if err != nil {
		return fmt.Errorf("store: 更新设备活跃时间失败: %w", err)
	}
	return nil
}
