package store

import (
	"bytes"
	"context"
	"database/sql"
	"log"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// legacyItemsDDL 是迁移前的旧表结构（与提交历史中的 schema 逐字一致）：
// 全局主键 id + UNIQUE(user_id, id)。多用户下不同账号写同名 id 会触发 PK 冲突。
const legacyItemsDDL = `
CREATE TABLE items (
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
CREATE INDEX idx_items_version ON items(user_id, version);
`

// createLegacyDB 用旧结构建库并写入 rows 行数据（两个用户、id 各不相同——
// 旧全局主键本就不允许跨用户同名，迁移测试的起点即为此形态）。
func createLegacyDB(t *testing.T, path string, rows [][2]string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("打开旧库失败: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(legacyItemsDDL); err != nil {
		t.Fatalf("建旧表失败: %v", err)
	}
	for i, r := range rows {
		if _, err := db.Exec(
			`INSERT INTO items(id, user_id, kind, rp_id, ciphertext, nonce, version, updated_at, deleted_at)
			 VALUES(?, ?, 'totp', 'x.example', ?, ?, ?, ?, NULL)`,
			r[0], r[1], []byte{byte(i)}, []byte{byte(i)}, int64(i+1), time.Now().Unix()); err != nil {
			t.Fatalf("写入旧数据失败: %v", err)
		}
	}
}

// sumVersions 返回 items 表 version 合计与行数（用于迁移前后数据一致性比较）。
func sumVersions(t *testing.T, st *Store) (int64, int64) {
	t.Helper()
	var sum, n int64
	err := st.DB().QueryRow(`SELECT COALESCE(SUM(version), 0), COUNT(1) FROM items`).Scan(&sum, &n)
	if err != nil {
		t.Fatalf("统计 items 失败: %v", err)
	}
	return sum, n
}

// TestMigrateItemsCompositePK 验证旧库自动迁移到复合主键 (user_id, id)：
// 行数与数据不变、复合主键生效（跨用户同名 id 可写、同用户重复仍冲突）、
// 索引保留、重复打开幂等、日志只报行数。
func TestMigrateItemsCompositePK(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	rows := [][2]string{
		{"item-a", "u1"},
		{"item-b", "u1"},
		{"item-a-dup", "u2"}, // 旧结构不允许跨用户同名，用近似 id 占位
	}
	createLegacyDB(t, path, rows)

	// 捕获迁移日志（log 是包级默认输出，测试内重定向，Cleanup 恢复）。
	var buf bytes.Buffer
	origOut := log.Writer()
	t.Cleanup(func() { log.SetOutput(origOut) })
	log.SetOutput(&buf)
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open(旧库): %v", err)
	}
	defer func() { _ = st.Close() }()

	out := buf.String()
	if !strings.Contains(out, "items 主键迁移开始：3 行") || !strings.Contains(out, "items 主键迁移完成：3 行") {
		t.Fatalf("迁移日志缺失或行数不对:\n%s", out)
	}
	if strings.Contains(out, "item-a") || strings.Contains(out, "u1") {
		t.Fatalf("迁移日志不得包含条目内容:\n%s", out)
	}

	ctx := context.Background()
	// 结构断言：user_id 已参与主键，索引仍在。
	pkUser, hasID, err := itemsPKInfo(st.DB())
	if err != nil || !hasID || !pkUser {
		t.Fatalf("迁移后主键形态异常: pkUser=%v hasID=%v err=%v", pkUser, hasID, err)
	}
	var idx int
	if err := st.DB().QueryRow(
		`SELECT COUNT(1) FROM sqlite_master WHERE type='index' AND name='idx_items_version'`).Scan(&idx); err != nil || idx != 1 {
		t.Fatalf("idx_items_version 未重建: %d (%v)", idx, err)
	}

	// 数据不变：行数与 version 合计与迁移前一致（迁移前 1+2+3=6）。
	if sum, n := sumVersions(t, st); n != 3 || sum != 6 {
		t.Fatalf("迁移后数据异常: rows=%d sum=%d，期望 3/6", n, sum)
	}

	// 复合主键生效：注册两个账号，写入同名 id 互不冲突。
	if err := st.CreateUser(ctx, User{Username: "alice", Verifier: []byte{1}}); err != nil {
		t.Fatalf("CreateUser(alice): %v", err)
	}
	if err := st.CreateUser(ctx, User{Username: "bob", Verifier: []byte{2}}); err != nil {
		t.Fatalf("CreateUser(bob): %v", err)
	}
	alice, _ := st.UserByUsername(ctx, "alice")
	bob, _ := st.UserByUsername(ctx, "bob")
	for _, u := range []*User{alice, bob} {
		res, err := st.ApplyItems(ctx, u.ID, []ItemInput{
			{ID: "shared", Kind: "totp", RPID: "s.example", Ciphertext: []byte(u.Username), Nonce: bytes.Repeat([]byte{9}, 12), UpdatedAt: time.Now().Unix()},
		})
		if err != nil {
			t.Fatalf("ApplyItems(%s): %v", u.Username, err)
		}
		if res[0].Status != StatusApplied {
			t.Fatalf("%s 写同名 id 应 applied，实际 %+v", u.Username, res[0])
		}
	}
	// 同用户重复「新建」仍是版本冲突语义（不产生第二行、不报 500）。
	res, err := st.ApplyItems(ctx, alice.ID, []ItemInput{
		{ID: "shared", Kind: "totp", RPID: "s.example", Ciphertext: []byte("x"), Nonce: bytes.Repeat([]byte{9}, 12), BaseVersion: 0, UpdatedAt: time.Now().Unix()},
	})
	if err != nil || res[0].Status != StatusConflict {
		t.Fatalf("同用户重复新建应 conflict，实际 %+v err=%v", res, err)
	}
	// 各自只读到自己那份（迁移带入的 u1/u2 行不属于任何注册账号）。
	ca, _, err := st.ItemsSince(ctx, alice.ID, 0, 50)
	if err != nil || len(ca) != 1 || ca[0].ID != "shared" {
		t.Fatalf("alice 条目异常: %v err=%v", ca, err)
	}
	cb, _, err := st.ItemsSince(ctx, bob.ID, 0, 50)
	if err != nil || len(cb) != 1 || cb[0].ID != "shared" {
		t.Fatalf("bob 条目异常: %v err=%v", cb, err)
	}

	// 幂等：再次 Open 不得改动数据、不得重复迁移（日志不再出现新的迁移行）。
	logLinesBefore := strings.Count(buf.String(), "主键迁移")
	st2, err := Open(path)
	if err != nil {
		t.Fatalf("二次 Open: %v", err)
	}
	defer func() { _ = st2.Close() }()
	if got := strings.Count(buf.String(), "主键迁移"); got != logLinesBefore {
		t.Fatalf("二次 Open 重复迁移：日志行数 %d → %d", logLinesBefore, got)
	}
	if sum, n := sumVersions(t, st2); n != 5 || sum == 0 {
		t.Fatalf("二次 Open 后数据异常: rows=%d sum=%d，期望 5 行", n, sum)
	}
	pkUser2, _, err := itemsPKInfo(st2.DB())
	if err != nil || !pkUser2 {
		t.Fatalf("二次 Open 主键形态异常: %v", err)
	}
}

// TestMigrateItemsPKFreshDB 验证新库直接按复合主键建表，不触发迁移日志。
func TestMigrateItemsPKFreshDB(t *testing.T) {
	var buf bytes.Buffer
	origOut := log.Writer()
	t.Cleanup(func() { log.SetOutput(origOut) })
	log.SetOutput(&buf)

	st, err := Open(filepath.Join(t.TempDir(), "fresh.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = st.Close() }()
	if strings.Contains(buf.String(), "主键迁移") {
		t.Fatalf("新库不应触发迁移日志:\n%s", buf.String())
	}
	pkUser, hasID, err := itemsPKInfo(st.DB())
	if err != nil || !hasID || !pkUser {
		t.Fatalf("新库主键形态异常: pkUser=%v hasID=%v err=%v", pkUser, hasID, err)
	}
}
