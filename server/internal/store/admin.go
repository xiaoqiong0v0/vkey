package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"xiaoqiong0v0.cn/vkey/server/internal/policy"
)

// meta 表中与多用户策略相关的键。
const (
	// MetaKeyUserMode 存 "single" 或 "admin"（缺省视为 single）。
	MetaKeyUserMode = "user_mode"
	// MetaKeyMaxItemsPerUser 是每用户条目数配额（十进制整数字符串）。
	MetaKeyMaxItemsPerUser = "quota.max_items_per_user"
	// MetaKeyMaxBytesPerUser 是每用户密文字节配额（十进制整数字符串）。
	MetaKeyMaxBytesPerUser = "quota.max_bytes_per_user"
	// MetaKeyMaxDevicesPerUser 是每用户设备数配额（十进制整数字符串）。
	MetaKeyMaxDevicesPerUser = "quota.max_devices_per_user"
)

// SetMeta 写入/覆盖一个 meta 键（供 CLI 配置用户模式与配额）。
func (s *Store) SetMeta(ctx context.Context, key, value string) error {
	return metaSet(ctx, s.db, key, value)
}

// UserMode 返回配置的用户模式；未设置时为 policy.UserModeSingle。
func (s *Store) UserMode(ctx context.Context) (string, error) {
	v, ok, err := s.metaGetDB(ctx, MetaKeyUserMode)
	if err != nil || !ok {
		return policy.UserModeSingle, err
	}
	return v, nil
}

// SetUserMode 校验并写入用户模式（只接受 single/admin）。
func (s *Store) SetUserMode(ctx context.Context, mode string) error {
	if mode != policy.UserModeSingle && mode != policy.UserModeAdmin {
		return fmt.Errorf("store: 非法用户模式 %q", mode)
	}
	return s.SetMeta(ctx, MetaKeyUserMode, mode)
}

// metaGetDB 在非事务上下文读取 meta 键。
func (s *Store) metaGetDB(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("store: 读取 meta 失败: %w", err)
	}
	return v, true, nil
}

// Quotas 返回每用户配额；缺省取 policy 默认值，显式写入的整数值覆盖默认。
func (s *Store) Quotas(ctx context.Context) (Quota, error) {
	q := Quota{
		MaxItems:   policy.DefaultMaxItemsPerUser,
		MaxBytes:   policy.DefaultMaxBytesPerUser,
		MaxDevices: policy.DefaultMaxDevicesPerUser,
	}
	var err error
	if q.MaxItems, err = s.metaGetInt(ctx, MetaKeyMaxItemsPerUser, q.MaxItems); err != nil {
		return Quota{}, err
	}
	if q.MaxBytes, err = s.metaGetInt(ctx, MetaKeyMaxBytesPerUser, q.MaxBytes); err != nil {
		return Quota{}, err
	}
	if q.MaxDevices, err = s.metaGetInt(ctx, MetaKeyMaxDevicesPerUser, q.MaxDevices); err != nil {
		return Quota{}, err
	}
	return q, nil
}

// SetQuota 写入一项配额（key 取 MetaKeyMax* 之一；负数表示不限制）。
func (s *Store) SetQuota(ctx context.Context, key string, value int64) error {
	switch key {
	case MetaKeyMaxItemsPerUser, MetaKeyMaxBytesPerUser, MetaKeyMaxDevicesPerUser:
		return s.SetMeta(ctx, key, strconv.FormatInt(value, 10))
	default:
		return fmt.Errorf("store: 未知配额键 %q", key)
	}
}

// metaGetInt 读取整型 meta 键；缺省或非法值回退 def。
func (s *Store) metaGetInt(ctx context.Context, key string, def int64) (int64, error) {
	v, ok, err := s.metaGetDB(ctx, key)
	if err != nil || !ok {
		return def, err
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def, nil // 值损坏时按默认值处理，不让存储层卡死
	}
	return n, nil
}

// SetUserDisabled 停用/启用账号：disabledAt>0 记录停用时刻，0 恢复启用。
//
// 返回：账号不存在时返回 ErrNotFound。数据本身不动（条目与设备保留）。
func (s *Store) SetUserDisabled(ctx context.Context, userID string, disabledAt int64) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET disabled_at = ? WHERE id = ?`, nullableInt(disabledAt), userID)
	if err != nil {
		return fmt.Errorf("store: 更新账号状态失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// UserRow 是 `vkeyd user list` 的单行摘要（不含任何敏感字段）。
type UserRow struct {
	ID         string
	Username   string
	CreatedAt  int64
	DisabledAt int64
	Devices    int64 // 未吊销设备数
	Items      int64 // 活跃条目数
}

// ListUsers 返回全部账号摘要，按创建时间升序。
func (s *Store) ListUsers(ctx context.Context) ([]UserRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT u.id, u.username, u.created_at, u.disabled_at,
		        (SELECT COUNT(1) FROM devices d WHERE d.user_id = u.id AND d.revoked_at IS NULL),
		        (SELECT COUNT(1) FROM items i WHERE i.user_id = u.id AND i.deleted_at IS NULL)
		 FROM users u ORDER BY u.created_at ASC, u.id ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: 查询用户列表失败: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]UserRow, 0, 8)
	for rows.Next() {
		var r UserRow
		var disabled sql.NullInt64
		if err := rows.Scan(&r.ID, &r.Username, &r.CreatedAt, &disabled, &r.Devices, &r.Items); err != nil {
			return nil, fmt.Errorf("store: 解析用户列表失败: %w", err)
		}
		r.DisabledAt = disabled.Int64
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: 遍历用户列表失败: %w", err)
	}
	return out, nil
}

// UserUsage 是账号删除前/后的行数统计（dry-run 与级联删除共用结构）。
type UserUsage struct {
	UserID     string
	Username   string
	CreatedAt  int64
	DisabledAt int64
	Items      int64 // items 行数（含墓碑）
	Conflicts  int64 // item_conflicts 行数
	Devices    int64 // devices 行数（含已吊销）
	Pairs      int64 // pairs 行数
	Audits     int64 // audit 行数
	Codes      int64 // 该用户名的开户码行数
}

// resolveUserTarget 按 id 查出账号基本信息（username/created/disabled），不存在返回 ErrNotFound。
func resolveUserTarget(ctx context.Context, tx *sql.Tx, userID string) (*UserUsage, error) {
	var u UserUsage
	var disabled sql.NullInt64
	err := tx.QueryRowContext(ctx,
		`SELECT username, created_at, disabled_at FROM users WHERE id = ?`, userID).
		Scan(&u.Username, &u.CreatedAt, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: 查询账号失败: %w", err)
	}
	u.DisabledAt = disabled.Int64
	u.UserID = userID
	return &u, nil
}

// userTableRef 描述账号在一张关联表里的行数落点与归属键。
//
// table/key 都是编译期常量（不接受外部输入），拼接 SQL 是安全的。
type userTableRef struct {
	dst *int64
	tbl string
	key string // 归属列：user_id 或 username
}

// userTables 是账号删除涉及的关联表清单。
//
// dry-run（计数）与级联删除共用这份清单，保证「打印的行数」与「实际删除的行」
// 使用完全相同的谓词。
func userTables(u *UserUsage) []userTableRef {
	return []userTableRef{
		{&u.Items, "items", "user_id"},
		{&u.Conflicts, "item_conflicts", "user_id"},
		{&u.Devices, "devices", "user_id"},
		{&u.Pairs, "pairs", "user_id"},
		{&u.Audits, "audit", "user_id"},
		{&u.Codes, "enroll_codes", "username"}, // 开户码按用户名归属（此时账号尚未创建）
	}
}

// refArg 返回该表归属键对应的取值。
func (u *UserUsage) refArg(r userTableRef) any {
	if r.key == "username" {
		return u.Username
	}
	return u.UserID
}

// DeleteUserPreview 统计删除该账号将影响的行数，不写库。
//
// 返回：账号不存在时返回 ErrNotFound。
func (s *Store) DeleteUserPreview(ctx context.Context, userID string) (*UserUsage, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: 开启事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	u, err := resolveUserTarget(ctx, tx, userID)
	if err != nil {
		return nil, err
	}
	for _, r := range userTables(u) {
		sqlText := `SELECT COUNT(1) FROM ` + r.tbl + ` WHERE ` + r.key + ` = ?`
		if err := tx.QueryRowContext(ctx, sqlText, u.refArg(r)).Scan(r.dst); err != nil {
			return nil, fmt.Errorf("store: 统计关联行数失败(%s): %w", r.tbl, err)
		}
	}
	return u, nil
}

// DeleteUserCascade 在单事务内级联删除账号的全部关联数据
// （items / item_conflicts / devices / pairs / audit / enroll_codes / seq meta / users 行）。
//
// 返回：实际删除的行数统计；账号不存在时返回 ErrNotFound。
func (s *Store) DeleteUserCascade(ctx context.Context, userID string) (*UserUsage, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: 开启事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	u, err := resolveUserTarget(ctx, tx, userID)
	if err != nil {
		return nil, err
	}
	for _, r := range userTables(u) {
		sqlText := `DELETE FROM ` + r.tbl + ` WHERE ` + r.key + ` = ?`
		res, err := tx.ExecContext(ctx, sqlText, u.refArg(r))
		if err != nil {
			return nil, fmt.Errorf("store: 级联删除失败(%s): %w", r.tbl, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return nil, fmt.Errorf("store: 读取删除行数失败: %w", err)
		}
		*r.dst = n
	}
	// seq 计数在 meta 表里按账号清理（键为 seq:<user_id>）。
	if _, err := tx.ExecContext(ctx, `DELETE FROM meta WHERE key = ?`, seqKey(userID)); err != nil {
		return nil, fmt.Errorf("store: 清理 seq 失败: %w", err)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: 删除账号失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: 提交事务失败: %w", err)
	}
	return u, nil
}
