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
	"log"
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
	// ErrEnrollInvalid 表示开户码不存在/已用/已撤销/缺少用户名绑定
	//（对客户端统一表现为 invalid_code，不区分具体原因，防枚举）。
	ErrEnrollInvalid = errors.New("store: 开户码无效")
	// ErrEnrollExpired 表示开户码已过期。
	ErrEnrollExpired = errors.New("store: 开户码已过期")
	// ErrUserDisabled 表示账号已被管理员停用。
	ErrUserDisabled = errors.New("store: 账号已停用")
	// ErrQuotaItems 表示超出每用户条目数配额。
	ErrQuotaItems = errors.New("store: 超出条目数配额")
	// ErrQuotaBytes 表示超出每用户密文字节配额。
	ErrQuotaBytes = errors.New("store: 超出密文字节配额")
	// ErrQuotaDevices 表示超出每用户设备数配额。
	ErrQuotaDevices = errors.New("store: 超出设备数配额")
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
    disabled_at       INTEGER,
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
    id         TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    kind       TEXT NOT NULL,
    rp_id      TEXT NOT NULL,
    ciphertext BLOB,
    nonce      BLOB,
    version    INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    deleted_at INTEGER,
    PRIMARY KEY (user_id, id)
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
CREATE TABLE IF NOT EXISTS enroll_codes (
    id         TEXT PRIMARY KEY,
    username   TEXT NOT NULL DEFAULT '',
    code_hash  BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,
    revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_enroll_code_hash ON enroll_codes(code_hash);
CREATE INDEX IF NOT EXISTS idx_enroll_expires ON enroll_codes(expires_at);
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
	DisabledAt      int64 // 0 表示启用；非 0 为停用时刻（unix 秒）
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
	if err := migrateUsersDisabledAt(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := migrateItemsPK(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// migrateUsersDisabledAt 为旧库补上 users.disabled_at 列（已有则跳过）。
//
// 旧库由 CREATE TABLE IF NOT EXISTS 得到的是不含该列的 users 表，
// 这里用 PRAGMA table_info 检查后执行一次 ALTER TABLE ADD COLUMN，
// 保证旧库打开即可用，不需要外部迁移步骤。
func migrateUsersDisabledAt(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(users)`)
	if err != nil {
		return fmt.Errorf("store: 读取 users 表结构失败: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			cid     int
			name    string
			typ     string
			notnull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return fmt.Errorf("store: 解析 users 表结构失败: %w", err)
		}
		if name == "disabled_at" {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store: 读取 users 表结构失败: %w", err)
	}
	if _, err := db.Exec(`ALTER TABLE users ADD COLUMN disabled_at INTEGER`); err != nil {
		return fmt.Errorf("store: 补 users.disabled_at 列失败: %w", err)
	}
	return nil
}

// migrateItemsPK 把旧库 items 表的全局主键 id 迁移为复合主键 (user_id, id)。
//
// 背景：多用户（user_mode=admin）下不同账号可写同名 item id，旧结构的全局
// `id TEXT PRIMARY KEY` 会触发 PK 冲突（500）；复合主键后 id 仅在账号内唯一。
// 检测：PRAGMA table_info(items) 中 user_id 列不参与主键（pk=0）即为旧结构。
// 迁移：按 SQLite 官方 12 步 ALTER 流程（PRAGMA foreign_keys=OFF → BEGIN
// IMMEDIATE → 建新表 → 整表拷贝 → DROP → RENAME → 重建索引 → foreign_key_check
// → COMMIT → 恢复 foreign_keys）。当前 schema 没有任何外键引用 items
// （item_conflicts 只按 (user_id, item_id) 逻辑关联），无需重建子表；
// 流程仍执行 PRAGMA foreign_key_check 兜底。
// 幂等：已迁移的库（user_id 参与主键）直接返回，不改动数据。
// 日志：迁移前后各记录一条「items 主键迁移：N 行」，不含任何条目内容。
func migrateItemsPK(db *sql.DB) error {
	pkUser, hasID, err := itemsPKInfo(db)
	if err != nil {
		return err
	}
	if !hasID {
		return errors.New("store: items 表缺少 id 列，无法迁移主键")
	}
	if pkUser {
		return nil // 已是复合主键，跳过（幂等）
	}

	var before int64
	if err := db.QueryRow(`SELECT COUNT(1) FROM items`).Scan(&before); err != nil {
		return fmt.Errorf("store: 迁移前统计 items 失败: %w", err)
	}
	log.Printf("store: items 主键迁移开始：%d 行", before)

	// PRAGMA foreign_keys 在事务内是 no-op，必须在 BEGIN 之前设置。
	if _, err := db.Exec(`PRAGMA foreign_keys = OFF`); err != nil {
		return fmt.Errorf("store: 迁移关闭外键约束失败: %w", err)
	}
	restored := false
	defer func() {
		if !restored {
			_, _ = db.Exec(`PRAGMA foreign_keys = ON`)
		}
	}()

	if err := migrateItemsPKTx(db, before); err != nil {
		return err
	}
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		return fmt.Errorf("store: 迁移恢复外键约束失败: %w", err)
	}
	restored = true
	log.Printf("store: items 主键迁移完成：%d 行", before)
	return nil
}

// migrateItemsPKTx 在 BEGIN IMMEDIATE ... COMMIT 内执行表重建，任一步失败即回滚。
func migrateItemsPKTx(db *sql.DB, wantRows int64) error {
	if _, err := db.Exec(`BEGIN IMMEDIATE`); err != nil {
		return fmt.Errorf("store: 迁移开启事务失败: %w", err)
	}
	rollback := func() { _, _ = db.Exec(`ROLLBACK`) }

	// 单连接池（MaxOpenConns=1）保证以下语句与事务落在同一连接上。
	const createNew = `
CREATE TABLE items_new (
    id         TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    kind       TEXT NOT NULL,
    rp_id      TEXT NOT NULL,
    ciphertext BLOB,
    nonce      BLOB,
    version    INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    deleted_at INTEGER,
    PRIMARY KEY (user_id, id)
)`
	if _, err := db.Exec(createNew); err != nil {
		rollback()
		return fmt.Errorf("store: 迁移创建 items_new 失败: %w", err)
	}
	if _, err := db.Exec(
		`INSERT INTO items_new(id, user_id, kind, rp_id, ciphertext, nonce, version, updated_at, deleted_at)
		 SELECT id, user_id, kind, rp_id, ciphertext, nonce, version, updated_at, deleted_at FROM items`); err != nil {
		rollback()
		return fmt.Errorf("store: 迁移拷贝 items 数据失败: %w", err)
	}
	var copied int64
	if err := db.QueryRow(`SELECT COUNT(1) FROM items_new`).Scan(&copied); err != nil {
		rollback()
		return fmt.Errorf("store: 迁移统计 items_new 失败: %w", err)
	}
	if copied != wantRows {
		rollback()
		return fmt.Errorf("store: 迁移行数不一致（items %d → items_new %d），已回滚", wantRows, copied)
	}
	if _, err := db.Exec(`DROP TABLE items`); err != nil {
		rollback()
		return fmt.Errorf("store: 迁移删除旧 items 失败: %w", err)
	}
	if _, err := db.Exec(`ALTER TABLE items_new RENAME TO items`); err != nil {
		rollback()
		return fmt.Errorf("store: 迁移重命名 items_new 失败: %w", err)
	}
	// 旧索引随 DROP TABLE 一起消失，按 schema 原样重建。
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_items_version ON items(user_id, version)`); err != nil {
		rollback()
		return fmt.Errorf("store: 迁移重建索引失败: %w", err)
	}
	// 兜底：确认没有违反外键约束的行（当前 schema 无引用 items 的外键）。
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		rollback()
		return fmt.Errorf("store: 迁移外键检查失败: %w", err)
	}
	var violations int
	for rows.Next() {
		violations++
	}
	closeErr := rows.Err()
	_ = rows.Close()
	if closeErr != nil {
		rollback()
		return fmt.Errorf("store: 迁移外键检查遍历失败: %w", closeErr)
	}
	if violations > 0 {
		rollback()
		return fmt.Errorf("store: 迁移外键检查发现 %d 条违规，已回滚", violations)
	}
	if _, err := db.Exec(`COMMIT`); err != nil {
		rollback()
		return fmt.Errorf("store: 迁移提交失败: %w", err)
	}
	return nil
}

// itemsPKInfo 读取 items 表的主键形态。
//
// 返回：pkUser=user_id 是否参与主键；hasID=id 列是否存在。
func itemsPKInfo(db *sql.DB) (pkUser bool, hasID bool, err error) {
	rows, err := db.Query(`PRAGMA table_info(items)`)
	if err != nil {
		return false, false, fmt.Errorf("store: 读取 items 表结构失败: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			cid     int
			name    string
			typ     string
			notnull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return false, false, fmt.Errorf("store: 解析 items 表结构失败: %w", err)
		}
		switch name {
		case "user_id":
			pkUser = pk > 0
		case "id":
			hasID = true
		}
	}
	if err := rows.Err(); err != nil {
		return false, false, fmt.Errorf("store: 读取 items 表结构失败: %w", err)
	}
	return pkUser, hasID, nil
}

// Close 关闭数据库连接。
func (s *Store) Close() error { return s.db.Close() }

// DB 返回底层连接，仅供同进程内的测试与维护命令使用。
func (s *Store) DB() *sql.DB { return s.db }

// Quota 是每用户配额；值为负数表示不限制，0 表示一项都不允许。
type Quota struct {
	MaxItems   int64 // 活跃条目数上限
	MaxBytes   int64 // 活跃条目密文字节合计上限
	MaxDevices int64 // 未吊销设备数上限
}

// checkDeviceSlot 在新建设备前校验设备数配额（事务内读取，保证与插入同事务串行）。
//
// 返回：超限时返回 ErrQuotaDevices；q.MaxDevices 为负数时不限制。
func checkDeviceSlot(ctx context.Context, tx *sql.Tx, userID string, q Quota) error {
	if q.MaxDevices < 0 {
		return nil
	}
	var n int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM devices WHERE user_id = ? AND revoked_at IS NULL`, userID).Scan(&n); err != nil {
		return fmt.Errorf("store: 统计设备失败: %w", err)
	}
	if n >= q.MaxDevices {
		return ErrQuotaDevices
	}
	return nil
}

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

// userColumns 是账号读取的统一列清单（新增列时只改这里）。
const userColumns = `id, username, verifier, pw_salt, wrapped_key, require_master_pw, disabled_at, created_at`

// UserByUsername 按用户名查询账号，不存在时返回 ErrNotFound。
func (s *Store) UserByUsername(ctx context.Context, username string) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE username = ?`, username)
	return scanUser(row)
}

// UserByID 按 id 查询账号，不存在时返回 ErrNotFound。
func (s *Store) UserByID(ctx context.Context, id string) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = ?`, id)
	return scanUser(row)
}

// FirstUser 返回最早创建的账号（单用户部署即唯一账号），不存在时返回 ErrNotFound。
func (s *Store) FirstUser(ctx context.Context) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users ORDER BY created_at ASC, id ASC LIMIT 1`)
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
		u       User
		req     int
		salt    []byte
		wrap    []byte
		disabled sql.NullInt64
	)
	err := row.Scan(&u.ID, &u.Username, &u.Verifier, &salt, &wrap, &req, &disabled, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: 读取用户失败: %w", err)
	}
	u.PWSalt, u.WrappedKey, u.RequireMasterPW = salt, wrap, req != 0
	u.DisabledAt = disabled.Int64
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
