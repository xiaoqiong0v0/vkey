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
	q, err := s.Quotas(ctx)
	if err != nil {
		return "", err
	}
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
			`UPDATE devices SET name = ?, platform = ?, token_hash = ?, last_seen = ?
			 WHERE user_id = ? AND id = ?`,
			name, platform, tokenHash, now, userID, id); err != nil {
			return "", fmt.Errorf("store: 更新设备失败: %w", err)
		}
	case errors.Is(err, sql.ErrNoRows):
		if err := checkDeviceSlot(ctx, tx, userID, q); err != nil {
			return "", err
		}
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
// 「查已有 → 配额检查 → 插入」在同一事务内完成，避免并发注册同时越过设备配额。
func (s *Store) CreateDevice(ctx context.Context, userID, name, platform string, pubkey, tokenHash []byte, now int64) (string, error) {
	q, err := s.Quotas(ctx)
	if err != nil {
		return "", err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("store: 开启事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var id string
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM devices WHERE user_id = ? AND pubkey = ? AND revoked_at IS NULL
		 ORDER BY created_at ASC LIMIT 1`, userID, pubkey).Scan(&id)
	if err == nil {
		if err := tx.Commit(); err != nil {
			return "", fmt.Errorf("store: 提交事务失败: %w", err)
		}
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("store: 查询设备失败: %w", err)
	}
	if err := checkDeviceSlot(ctx, tx, userID, q); err != nil {
		return "", err
	}
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
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("store: 提交事务失败: %w", err)
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

// ListDevices 返回账号下全部未吊销设备，按 last_seen 降序（同值按 created_at 升序）。
//
// 只读取列表展示所需的元数据列：公钥与 token 哈希不出库，避免上层误用。
func (s *Store) ListDevices(ctx context.Context, userID string) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, platform, created_at, last_seen
		 FROM devices WHERE user_id = ? AND revoked_at IS NULL
		 ORDER BY last_seen DESC, created_at ASC`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: 查询设备列表失败: %w", err)
	}
	defer func() { _ = rows.Close() }()

	devices := make([]Device, 0, 8)
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.Name, &d.Platform, &d.CreatedAt, &d.LastSeen); err != nil {
			return nil, fmt.Errorf("store: 读取设备列表失败: %w", err)
		}
		d.UserID = userID
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: 读取设备列表失败: %w", err)
	}
	return devices, nil
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
//
// 谓词带 user_id：devices.id 虽为全局生成（不存在跨账号撞 id 的现实路径），
// 但归属校验放在 SQL 层是纵深防御，调用方必须传当前认证账号。
func (s *Store) TouchDevice(ctx context.Context, userID, deviceID string, now int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET last_seen = ? WHERE user_id = ? AND id = ?`, now, userID, deviceID)
	if err != nil {
		return fmt.Errorf("store: 更新设备活跃时间失败: %w", err)
	}
	return nil
}
