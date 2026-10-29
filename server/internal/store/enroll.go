package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"xiaoqiong0v0.cn/vkey/server/internal/crypto"
	"xiaoqiong0v0.cn/vkey/server/internal/policy"
)

// 开户码展示与存储规则：
//   - 明文形如 `ENROLL-XXXX-XXXX`，随机段取自去混淆字母表（剔除 I/O/0/1）；
//   - 服务端只存 SHA256(规范化明文字符串的 UTF-8 字节)，明文不落库、不落日志；
//   - 规范化 = 去首尾空白 + 转大写（组内 '-' 保留，属格式一部分）。

// enrollCodeAlphabet 是开户码随机段字母表：大写字母+数字，剔除易混字符 I/O/0/1。
const enrollCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// EnrollCode 是一条开户码记录（不含明文与 hash；0 时间戳表示 NULL）。
type EnrollCode struct {
	ID        string
	Username  string // 绑定的目标用户名；空串表示未绑定（开户时由 enroll 提供）
	CreatedAt int64
	ExpiresAt int64
	UsedAt    int64
	RevokedAt int64
}

// NormalizeEnrollCode 把用户输入的开户码规范化为存储/比较用的形式。
//
// 规则：去空白、转大写。返回空串表示输入为空。
func NormalizeEnrollCode(raw string) string {
	return strings.ToUpper(strings.Join(strings.Fields(raw), ""))
}

// NewEnrollCodePlain 生成一个新的开户码明文（不含 hash）。
func NewEnrollCodePlain() (string, error) {
	total := policy.EnrollCodeGroupSize * policy.EnrollCodeGroups
	b, err := crypto.Random(total)
	if err != nil {
		return "", err
	}
	groups := make([]string, 0, policy.EnrollCodeGroups)
	for i := 0; i < total; i += policy.EnrollCodeGroupSize {
		var sb strings.Builder
		for j := i; j < i+policy.EnrollCodeGroupSize; j++ {
			// 字母表长 32，字节低 5 位取值无偏。
			sb.WriteByte(enrollCodeAlphabet[b[j]&0x1F])
		}
		groups = append(groups, sb.String())
	}
	return policy.EnrollCodePrefix + "-" + strings.Join(groups, "-"), nil
}

// enrollCodeHash 返回开户码的服务端存储形式：SHA256(规范化明文)。
func enrollCodeHash(plain string) []byte {
	return crypto.SHA256([]byte(plain))
}

// CreateEnrollCode 插入一条开户码，返回记录与明文。
//
// 参数：username 为绑定目标（可为空串=未绑定）；ttlSeconds>0；now 为当前 unix 秒。
// 返回：明文只在内存中出现一次，调用方（CLI）打印后不得再持久化。
func (s *Store) CreateEnrollCode(ctx context.Context, username string, ttlSeconds, now int64) (*EnrollCode, string, error) {
	if ttlSeconds <= 0 {
		return nil, "", errors.New("store: 开户码 TTL 必须为正数")
	}
	plain, err := NewEnrollCodePlain()
	if err != nil {
		return nil, "", err
	}
	id, err := newID()
	if err != nil {
		return nil, "", err
	}
	rec := &EnrollCode{ID: id, Username: username, CreatedAt: now, ExpiresAt: now + ttlSeconds}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO enroll_codes(id, username, code_hash, created_at, expires_at, used_at, revoked_at)
		 VALUES(?, ?, ?, ?, ?, NULL, NULL)`,
		id, username, enrollCodeHash(plain), rec.CreatedAt, rec.ExpiresAt)
	if err != nil {
		return nil, "", fmt.Errorf("store: 插入开户码失败: %w", err)
	}
	return rec, plain, nil
}

// ListPendingEnrollCodes 返回未使用且未撤销的开户码摘要，按过期时间升序。
func (s *Store) ListPendingEnrollCodes(ctx context.Context) ([]EnrollCode, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, username, created_at, expires_at FROM enroll_codes
		 WHERE used_at IS NULL AND revoked_at IS NULL ORDER BY expires_at ASC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: 查询开户码失败: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]EnrollCode, 0, 8)
	for rows.Next() {
		var c EnrollCode
		if err := rows.Scan(&c.ID, &c.Username, &c.CreatedAt, &c.ExpiresAt); err != nil {
			return nil, fmt.Errorf("store: 解析开户码失败: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: 遍历开户码失败: %w", err)
	}
	return out, nil
}

// RevokeEnrollCode 撤销一条开户码；不存在/已用/已撤销时返回 ErrNotFound。
func (s *Store) RevokeEnrollCode(ctx context.Context, id string, now int64) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE enroll_codes SET revoked_at = ?
		 WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL`, now, id)
	if err != nil {
		return fmt.Errorf("store: 撤销开户码失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// EnrollCodeState 是开户码的只读检查结论（/join 落地页用；不消费、不写库）。
type EnrollCodeState int

const (
	// EnrollCodeAbsent 表示不存在 / 已使用 / 已撤销（对外统一口径，不区分细节）。
	EnrollCodeAbsent EnrollCodeState = iota
	// EnrollCodeActive 表示有效且未使用。
	EnrollCodeActive
	// EnrollCodeExpired 表示已过期。
	EnrollCodeExpired
)

// PeekEnrollCode 只读检查开户码状态，供 /join 落地页展示；绝不消费或写库。
//
// 参数：raw 为开户码原文（内部按 code_hash 规范化比对）；now 为当前 unix 秒。
// 返回：状态与记录（过期/有效时非 nil，供 TTL 展示；不存在时为 nil）。
// 并发口径：与 Enroll 事务交错时可能读到「刚被消费」→ Absent，属预期行为。
func (s *Store) PeekEnrollCode(ctx context.Context, raw string, now int64) (EnrollCodeState, *EnrollCode, error) {
	plain := NormalizeEnrollCode(raw)
	if plain == "" {
		return EnrollCodeAbsent, nil, nil
	}
	var (
		c         EnrollCode
		usedAt    sql.NullInt64
		revokedAt sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, username, created_at, expires_at, used_at, revoked_at
		 FROM enroll_codes WHERE code_hash = ?`, enrollCodeHash(plain)).
		Scan(&c.ID, &c.Username, &c.CreatedAt, &c.ExpiresAt, &usedAt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return EnrollCodeAbsent, nil, nil
	}
	if err != nil {
		return EnrollCodeAbsent, nil, fmt.Errorf("store: 查询开户码状态失败: %w", err)
	}
	if usedAt.Valid || revokedAt.Valid {
		return EnrollCodeAbsent, nil, nil
	}
	if c.ExpiresAt <= now {
		return EnrollCodeExpired, &c, nil
	}
	return EnrollCodeActive, &c, nil
}

// EnrollInput 是一次开户绑定的全部输入（均已在 API 层完成格式校验）。
type EnrollInput struct {
	Code           string // 开户码明文（原始输入，内部规范化）
	Username       string // 可选：开户码未绑定用户名时必须提供
	Verifier       []byte // 32B：HKDF(master_key, "vkey-verifier", username)
	PWSalt         []byte // 可选 16B
	WrappedKey     []byte // 可选（自包含布局）
	DeviceName     string
	DevicePlatform string
	DevicePubKey   []byte // 32B Ed25519
	TokenHash      []byte // SHA256(新 token)
	Now            int64
}

// EnrollOutcome 是开户成功后的账号与设备信息。
type EnrollOutcome struct {
	UserID   string
	Username string
	DeviceID string
}

// Enroll 在一个事务内完成「校验开户码 → 创建账号 → 创建首个设备 → 消费开户码」。
//
// 并发契约（见 ASYNC.md）：
//   - 消费用 `UPDATE ... WHERE used_at IS NULL AND revoked_at IS NULL` 条件更新，
//     影响行数必须恰好为 1；
//   - code_hash 上有唯一索引；单连接 sqlite 使事务串行，重复/并发提交至多一个成功。
//
// 错误映射：ErrEnrollInvalid（不存在/已用/撤销/未绑定且未提供用户名）、
// ErrEnrollExpired、ErrExists（用户名已被占用）、ErrQuotaDevices。
func (s *Store) Enroll(ctx context.Context, in EnrollInput) (*EnrollOutcome, error) {
	// 配额在事务外预读（单连接下不会与事务内写互锁）。
	q, err := s.Quotas(ctx)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: 开启事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	plain := NormalizeEnrollCode(in.Code)
	if plain == "" {
		return nil, ErrEnrollInvalid
	}
	var (
		codeID    string
		bound     string
		expiresAt int64
		usedAt    sql.NullInt64
		revokedAt sql.NullInt64
	)
	err = tx.QueryRowContext(ctx,
		`SELECT id, username, expires_at, used_at, revoked_at
		 FROM enroll_codes WHERE code_hash = ?`, enrollCodeHash(plain)).
		Scan(&codeID, &bound, &expiresAt, &usedAt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEnrollInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("store: 查询开户码失败: %w", err)
	}
	if usedAt.Valid || revokedAt.Valid {
		return nil, ErrEnrollInvalid
	}
	if expiresAt <= in.Now {
		return nil, ErrEnrollExpired
	}

	username := strings.TrimSpace(in.Username)
	switch {
	case bound != "":
		// 已绑定：请求可省略 username；给出时必须一致。
		if username != "" && username != bound {
			return nil, ErrEnrollInvalid
		}
		username = bound
	case username == "":
		return nil, ErrEnrollInvalid // 未绑定且未提供用户名
	}

	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM users WHERE username = ?`, username).Scan(&n); err != nil {
		return nil, fmt.Errorf("store: 查询用户名失败: %w", err)
	}
	if n > 0 {
		return nil, ErrExists
	}
	// 新账号还没有任何设备；只有「max_devices_per_user=0」这种极端配额会拒绝开户。
	if q.MaxDevices >= 0 && q.MaxDevices < 1 {
		return nil, ErrQuotaDevices
	}

	userID, err := newID()
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO users(id, username, verifier, pw_salt, wrapped_key, require_master_pw, disabled_at, created_at)
		 VALUES(?, ?, ?, ?, ?, 0, NULL, ?)`,
		userID, username, in.Verifier, in.PWSalt, in.WrappedKey, in.Now); err != nil {
		return nil, fmt.Errorf("store: 创建账号失败: %w", err)
	}

	deviceID, err := newID()
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO devices(id, user_id, name, platform, pubkey, token_hash, revoked_at, created_at, last_seen)
		 VALUES(?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
		deviceID, userID, in.DeviceName, in.DevicePlatform, in.DevicePubKey, in.TokenHash, in.Now, in.Now); err != nil {
		return nil, fmt.Errorf("store: 创建首个设备失败: %w", err)
	}

	res, err := tx.ExecContext(ctx,
		`UPDATE enroll_codes SET used_at = ? WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL`,
		in.Now, codeID)
	if err != nil {
		return nil, fmt.Errorf("store: 消费开户码失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, ErrEnrollInvalid
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: 提交事务失败: %w", err)
	}
	return &EnrollOutcome{UserID: userID, Username: username, DeviceID: deviceID}, nil
}
