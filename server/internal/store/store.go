// Package store 实现 vkeyd 的 sqlite 持久层。
//
// 所有 sqlite 访问都经过本包；连接数固定为 1（见 ASYNC.md 的并发契约），
// 因此事务之间天然串行，version 的单调递增由 meta 表中的 seq 计数保证。
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"xiaoqiong0v0.cn/vkey/server/internal/crypto"

	_ "modernc.org/sqlite" // 纯 Go sqlite 驱动
)

// 存储层哨兵错误。
var (
	// ErrNotFound 表示目标记录不存在。
	ErrNotFound = errors.New("store: 记录不存在")
	// ErrExists 表示唯一键冲突（用户名、code_id 等）。
	ErrExists = errors.New("store: 记录已存在")
	// ErrPairUsed 表示配对码已被使用。
	ErrPairUsed = errors.New("store: 配对码已使用")
	// ErrPairExpired 表示配对码已过期。
	ErrPairExpired = errors.New("store: 配对码已过期")
)

// schema 是建库 DDL，与 shared/protocol.md §表结构 逐字段一致。
const schema = `
CREATE TABLE IF NOT EXISTS users (
    id                TEXT PRIMARY KEY,
    username          TEXT NOT NULL UNIQUE,
    verifier          BLOB NOT NULL,
    pw_salt           BLOB,
    wrapped_key       BLOB,
    require_master_pw INTEGER NOT NULL DEFAULT 0,
    created_at        INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    name       TEXT NOT NULL,
    platform   TEXT NOT NULL,
    pubkey     BLOB NOT NULL,
    token_hash BLOB,
    revoked_at INTEGER,
    created_at INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS items (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    kind       TEXT NOT NULL,
    rp_id      TEXT NOT NULL,
    ciphertext BLOB,
    nonce      BLOB,
    version    INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    deleted_at INTEGER,
    UNIQUE (user_id, id)
);
CREATE TABLE IF NOT EXISTS item_conflicts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    TEXT NOT NULL,
    item_id    TEXT NOT NULL,
    ciphertext BLOB,
    nonce      BLOB,
    version    INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pairs (
    code_id    TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    code_hash  BLOB NOT NULL,
    blob       BLOB NOT NULL,
    pw_salt    BLOB,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   TEXT NOT NULL,
    device_id TEXT NOT NULL,
    action    TEXT NOT NULL,
    ts        INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_token ON devices(token_hash) WHERE token_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_devices_user_pub ON devices(user_id, pubkey);
CREATE INDEX IF NOT EXISTS idx_items_version ON items(user_id, version);
CREATE INDEX IF NOT EXISTS idx_conflicts_item ON item_conflicts(user_id, item_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pairs_code_hash ON pairs(code_hash);
CREATE INDEX IF NOT EXISTS idx_pairs_expires ON pairs(expires_at);
`

// User 是账号记录。
type User struct {
	ID              string
	Username        string
	Verifier        []byte
	PWSalt          []byte
	WrappedKey      []byte
	RequireMasterPW bool
	CreatedAt       int64
}

// Device 是设备记录。
type Device struct {
	ID        string
	UserID    string
	Name      string
	Platform  string
	PubKey    []byte
	TokenHash []byte
	RevokedAt int64 // 0 表示未吊销
	CreatedAt int64
	LastSeen  int64
}

// Item 是服务端保存的条目密文（零知识）。
type Item struct {
	ID         string
	UserID     string
	Kind       string
	RPID       string
	Ciphertext []byte
	Nonce      []byte
	Version    int64
	UpdatedAt  int64
	DeletedAt  int64 // 0 表示未删除；非 0 为墓碑
}

// ItemInput 是一次写入请求中的单条条目。
type ItemInput struct {
	ID          string
	Kind        string
	RPID        string
	Ciphertext  []byte
	Nonce       []byte
	BaseVersion int64
	UpdatedAt   int64
	DeletedAt   int64
}

// ItemResult 是单条写入的处理结果。
type ItemResult struct {
	ID      string
	Version int64
	Status  string // applied / conflict / rejected
	Reason  string
}

// Conflict 是 LWW 落败副本。
type Conflict struct {
	ID         int64
	ItemID     string
	Ciphertext []byte
	Nonce      []byte
	Version    int64
	UpdatedAt  int64
}

// Pair 是配对会话记录。
type Pair struct {
	CodeID    string
	UserID    string
	CodeHash  []byte
	Blob      []byte
	PWSalt    []byte
	ExpiresAt int64
	UsedAt    int64
	CreatedAt int64
}

// PairClaim 是领取配对码后的返回数据。
type PairClaim struct {
	CodeID     string
	UserID     string
	DeviceID   string
	Blob       []byte
	PWSalt     []byte
	WrappedKey []byte
}

// Store 是 sqlite 存储句柄。
type Store struct {
	db *sql.DB
}

// Open 打开（必要时创建）数据库并执行迁移。
//
// 参数：path 为数据库文件路径，父目录不存在时自动创建。
// 返回：已就绪的 Store；打开或迁移失败时返回错误。
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("store: 数据库路径不能为空")
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("store: 创建数据库目录失败: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: 打开数据库失败: %w", err)
	}
	// 单连接：sqlite 写锁不需要竞争，事务天然串行（见 ASYNC.md）。
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	pragmas := []string{
		"PRAGMA busy_timeout = 5000",
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA foreign_keys = ON",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("store: 设置 pragma 失败(%s): %w", p, err)
		}
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: 建表失败: %w", err)
	}
	return &Store{db: db}, nil
}

// Close 关闭数据库连接。
func (s *Store) Close() error { return s.db.Close() }

// DB 返回底层连接，仅供同进程内的测试与维护命令使用。
func (s *Store) DB() *sql.DB { return s.db }

// newID 生成 16 字节随机 id 的 base64url 形式（22 字符）。
func newID() (string, error) {
	b, err := crypto.Random(16)
	if err != nil {
		return "", err
	}
	return crypto.B64(b), nil
}

// CreateUser 插入账号。用户名冲突时返回 ErrExists。
//
// 参数：verifier 必须非空；pwSalt/wrappedKey 可为 nil（未启用主密码）。
func (s *Store) CreateUser(ctx context.Context, u User) error {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM users WHERE username = ?`, u.Username).Scan(&n); err != nil {
		return fmt.Errorf("store: 查询用户失败: %w", err)
	}
	if n > 0 {
		return ErrExists
	}
	id := u.ID
	if id == "" {
		var err error
		if id, err = newID(); err != nil {
			return err
		}
	}
	if u.CreatedAt == 0 {
		u.CreatedAt = time.Now().Unix()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users(id, username, verifier, pw_salt, wrapped_key, require_master_pw, created_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?)`,
		id, u.Username, u.Verifier, u.PWSalt, u.WrappedKey, boolToInt(u.RequireMasterPW), u.CreatedAt)
	if err != nil {
		return fmt.Errorf("store: 插入用户失败: %w", err)
	}
	return nil
}

// UserByUsername 按用户名查询账号，不存在时返回 ErrNotFound。
func (s *Store) UserByUsername(ctx context.Context, username string) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, username, verifier, pw_salt, wrapped_key, require_master_pw, created_at
		 FROM users WHERE username = ?`, username)
	return scanUser(row)
}

// FirstUser 返回最早创建的账号（单用户部署即唯一账号），不存在时返回 ErrNotFound。
func (s *Store) FirstUser(ctx context.Context) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, username, verifier, pw_salt, wrapped_key, require_master_pw, created_at
		 FROM users ORDER BY created_at ASC, id ASC LIMIT 1`)
	return scanUser(row)
}

// SetRequireMasterPW 设置指定账号的「强制主密码」策略。
func (s *Store) SetRequireMasterPW(ctx context.Context, userID string, require bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET require_master_pw = ? WHERE id = ?`, boolToInt(require), userID)
	if err != nil {
		return fmt.Errorf("store: 更新策略失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetPasswordWrap 写入主密码包裹（pw_salt + wrapped_key）。
//
// 参数：wrappedKey 为 `nonce(12)||ciphertext||tag` 自包含布局；pwSalt 为 16 字节。
// 返回：账号不存在时返回 ErrNotFound。
func (s *Store) SetPasswordWrap(ctx context.Context, userID string, wrappedKey, pwSalt []byte) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET wrapped_key = ?, pw_salt = ? WHERE id = ?`,
		wrappedKey, pwSalt, userID)
	if err != nil {
		return fmt.Errorf("store: 写入主密码包裹失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ClearPasswordWrap 清空主密码包裹（两列同时置 NULL）。
//
// 返回：账号不存在时返回 ErrNotFound。
func (s *Store) ClearPasswordWrap(ctx context.Context, userID string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET wrapped_key = NULL, pw_salt = NULL WHERE id = ?`, userID)
	if err != nil {
		return fmt.Errorf("store: 清空主密码包裹失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Counts 返回活跃条目数与未吊销设备数（用于 /health 与自检页）。
func (s *Store) Counts(ctx context.Context) (int64, int64, error) {
	var items, devices int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM items WHERE deleted_at IS NULL`).Scan(&items); err != nil {
		return 0, 0, fmt.Errorf("store: 统计条目失败: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM devices WHERE revoked_at IS NULL`).Scan(&devices); err != nil {
		return 0, 0, fmt.Errorf("store: 统计设备失败: %w", err)
	}
	return items, devices, nil
}

// Audit 写入一条审计记录（仅元数据，不含明文）。
func (s *Store) Audit(ctx context.Context, userID, deviceID, action string, ts int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit(user_id, device_id, action, ts) VALUES(?, ?, ?, ?)`,
		userID, deviceID, action, ts)
	if err != nil {
		return fmt.Errorf("store: 写审计失败: %w", err)
	}
	return nil
}

// scanUser 把一行用户记录解析为 User。
func scanUser(row *sql.Row) (*User, error) {
	var (
		u    User
		req  int
		salt []byte
		wrap []byte
	)
	err := row.Scan(&u.ID, &u.Username, &u.Verifier, &salt, &wrap, &req, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: 读取用户失败: %w", err)
	}
	u.PWSalt, u.WrappedKey, u.RequireMasterPW = salt, wrap, req != 0
	return &u, nil
}

// boolToInt 把 bool 转为 sqlite 的 0/1。
func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// seq（per-user 单调递增版本号）
// ---------------------------------------------------------------------------

// seqKey 返回指定账号的 seq 计数在 meta 表中的键名。
func seqKey(userID string) string { return "seq:" + userID }

// seqGet 读取账号当前 seq；不存在时视为 0。
func seqGet(ctx context.Context, tx *sql.Tx, userID string) (int64, error) {
	var v string
	err := tx.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, seqKey(userID)).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("store: 读取 seq 失败: %w", err)
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("store: seq 值非法: %w", err)
	}
	return n, nil
}

// seqPut 写入账号当前 seq。
func seqPut(ctx context.Context, tx *sql.Tx, userID string, v int64) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO meta(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		seqKey(userID), strconv.FormatInt(v, 10))
	if err != nil {
		return fmt.Errorf("store: 写入 seq 失败: %w", err)
	}
	return nil
}

// Seq 返回账号当前 seq（用于 GET /items 的 next 字段）。
func (s *Store) Seq(ctx context.Context, userID string) (int64, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, seqKey(userID)).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("store: 读取 seq 失败: %w", err)
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("store: seq 值非法: %w", err)
	}
	return n, nil
}
