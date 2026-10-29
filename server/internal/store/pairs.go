package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// CreatePair 插入一条配对会话记录。code_id 已存在时返回 ErrExists。
func (s *Store) CreatePair(ctx context.Context, p Pair) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO pairs(code_id, user_id, code_hash, blob, pw_salt, expires_at, used_at, created_at)
		 VALUES(?, ?, ?, ?, ?, ?, NULL, ?)`,
		p.CodeID, p.UserID, p.CodeHash, p.Blob, p.PWSalt, p.ExpiresAt, p.CreatedAt)
	if err != nil {
		// 预先检查 code_id，避免把驱动错误文本暴露给调用方。
		var n int
		if qerr := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM pairs WHERE code_id = ?`, p.CodeID).Scan(&n); qerr == nil && n > 0 {
			return ErrExists
		}
		return fmt.Errorf("store: 插入配对码失败: %w", err)
	}
	return nil
}

// ClaimPair 原子地消费一个配对码：校验 → 建设备 → 标记已用。
//
// 参数：codeHash 为 SHA256(配对码原始字节)；pubkey 为设备 Ed25519 公钥；
// tokenHash 为新设备 token 的 SHA-256；now 为当前 unix 秒。
// 返回：领取结果（含 blob 与 pw_salt）。
//
// 并发契约：整个消费过程在同一事务内完成，且用 used_at IS NULL 作为条件更新，
// 保证同一配对码只可能被成功领取一次（见 ASYNC.md）。
func (s *Store) ClaimPair(ctx context.Context, codeHash []byte, name, platform string, pubkey, tokenHash []byte, now int64) (*PairClaim, error) {
	q, err := s.Quotas(ctx)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: 开启事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var (
		codeID     string
		userID     string
		blob       []byte
		pwSalt     []byte
		wrappedKey []byte
		disabledAt sql.NullInt64
		expiresAt  int64
		usedAt     sql.NullInt64
	)
	err = tx.QueryRowContext(ctx,
		`SELECT p.code_id, p.user_id, p.blob, p.pw_salt, u.wrapped_key, u.disabled_at, p.expires_at, p.used_at
		 FROM pairs p JOIN users u ON u.id = p.user_id
		 WHERE p.code_hash = ?`, codeHash).
		Scan(&codeID, &userID, &blob, &pwSalt, &wrappedKey, &disabledAt, &expiresAt, &usedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: 查询配对码失败: %w", err)
	}
	if usedAt.Valid {
		return nil, ErrPairUsed
	}
	if expiresAt <= now {
		return nil, ErrPairExpired
	}
	// 账号已停用：不允许再领取配对码新增设备（错误不区分原因细节）。
	if disabledAt.Int64 != 0 {
		return nil, ErrUserDisabled
	}

	// 配对领取总是新建设备行，先占配额。
	if err := checkDeviceSlot(ctx, tx, userID, q); err != nil {
		return nil, err
	}

	deviceID, err := newID()
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO devices(id, user_id, name, platform, pubkey, token_hash, revoked_at, created_at, last_seen)
		 VALUES(?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
		deviceID, userID, name, platform, pubkey, tokenHash, now, now); err != nil {
		return nil, fmt.Errorf("store: 创建配对设备失败: %w", err)
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE pairs SET used_at = ? WHERE user_id = ? AND code_id = ? AND used_at IS NULL`, now, userID, codeID)
	if err != nil {
		return nil, fmt.Errorf("store: 标记配对码已用失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, ErrPairUsed
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: 提交事务失败: %w", err)
	}
	return &PairClaim{CodeID: codeID, UserID: userID, DeviceID: deviceID, Blob: blob, PWSalt: pwSalt, WrappedKey: wrappedKey}, nil
}
