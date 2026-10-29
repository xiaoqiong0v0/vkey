package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// newPurgeTestStore 建一个临时库并写入指定条目（deletedAt 非 0 即墓碑）。
func newPurgeTestStore(t *testing.T, items []ItemInput) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "purge.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	ctx := context.Background()
	if err := st.CreateUser(ctx, User{Username: "default", Verifier: []byte{1}}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	u, err := st.FirstUser(ctx)
	if err != nil {
		t.Fatalf("FirstUser: %v", err)
	}
	if _, err := st.ApplyItems(ctx, u.ID, items); err != nil {
		t.Fatalf("ApplyItems: %v", err)
	}
	return st
}

// countAll 返回 items 表总行数。
func countAll(t *testing.T, st *Store) int64 {
	t.Helper()
	var n int64
	if err := st.DB().QueryRowContext(context.Background(), `SELECT COUNT(1) FROM items`).Scan(&n); err != nil {
		t.Fatalf("统计条目: %v", err)
	}
	return n
}

// testItems 造 2 条墓碑 + 1 条正常。
func testItems() []ItemInput {
	return []ItemInput{
		{ID: "item-tomb-a", Kind: "totp", RPID: "a.example", UpdatedAt: 100, DeletedAt: 200},
		{ID: "item-tomb-b", Kind: "totp", RPID: "b.example", UpdatedAt: 100, DeletedAt: 300},
		{ID: "item-alive", Kind: "totp", RPID: "c.example", UpdatedAt: 100},
	}
}

// TestPurgePendingReportsOnlyTombstones 验证 dry-run 只报告墓碑且不改库。
func TestPurgePendingReportsOnlyTombstones(t *testing.T) {
	st := newPurgeTestStore(t, testItems())
	ctx := context.Background()

	targets, err := st.PurgePending(ctx)
	if err != nil {
		t.Fatalf("PurgePending: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("待删除条数 = %d，期望 2", len(targets))
	}
	for _, tg := range targets {
		if tg.DeletedAt == 0 {
			t.Fatalf("待删除列表含非墓碑条目 %q", tg.ID)
		}
		if tg.Kind != "totp" || tg.RPID == "" || tg.Version == 0 {
			t.Fatalf("待删除条目字段不完整: %+v", tg)
		}
	}
	if got := countAll(t, st); got != 3 {
		t.Fatalf("dry-run 后条目数 = %d，期望 3（不应写库）", got)
	}
}

// TestPurgeDeletesOnlyTombstones 验证 --yes 只删墓碑，正常条目保留。
func TestPurgeDeletesOnlyTombstones(t *testing.T) {
	st := newPurgeTestStore(t, testItems())
	ctx := context.Background()

	n, err := st.Purge(ctx)
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if n != 2 {
		t.Fatalf("删除条数 = %d，期望 2", n)
	}
	if got := countAll(t, st); got != 1 {
		t.Fatalf("删除后条目数 = %d，期望 1", got)
	}
	var id string
	if err := st.DB().QueryRowContext(ctx, `SELECT id FROM items`).Scan(&id); err != nil {
		t.Fatalf("读取剩余条目: %v", err)
	}
	if id != "item-alive" {
		t.Fatalf("剩余条目 = %q，期望 item-alive", id)
	}
	// 再跑一次应为空操作。
	if n, err := st.Purge(ctx); err != nil || n != 0 {
		t.Fatalf("二次 Purge = (%d, %v)，期望 (0, nil)", n, err)
	}
}

// TestPurgeWithoutTombstones 验证全为正常条目时删 0 条且不报错。
func TestPurgeWithoutTombstones(t *testing.T) {
	st := newPurgeTestStore(t, []ItemInput{
		{ID: "item-1", Kind: "totp", RPID: "a.example", UpdatedAt: 100},
		{ID: "item-2", Kind: "totp", RPID: "b.example", UpdatedAt: 100},
	})
	ctx := context.Background()

	targets, err := st.PurgePending(ctx)
	if err != nil {
		t.Fatalf("PurgePending: %v", err)
	}
	if len(targets) != 0 {
		t.Fatalf("待删除条数 = %d，期望 0", len(targets))
	}
	n, err := st.Purge(ctx)
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if n != 0 {
		t.Fatalf("删除条数 = %d，期望 0", n)
	}
	if got := countAll(t, st); got != 2 {
		t.Fatalf("条目数 = %d，期望 2（不应删除）", got)
	}
}

// TestPurgeSQLGuardsTombstone 断言唯一删除语句仍保留墓碑条件。
func TestPurgeSQLGuardsTombstone(t *testing.T) {
	if !strings.Contains(PurgeItemsSQL, "deleted_at") {
		t.Fatalf("删除语句缺少 deleted_at 条件: %s", PurgeItemsSQL)
	}
	if !strings.Contains(PurgeItemsSQL, "IS NOT NULL") || !strings.Contains(PurgeItemsSQL, "!= 0") {
		t.Fatalf("删除语句条件不完整: %s", PurgeItemsSQL)
	}
}

// TestPurgeIDsDeletesOnlySelected 验证按 (user_id, id) 删除只影响勾选的墓碑。
func TestPurgeIDsDeletesOnlySelected(t *testing.T) {
	st := newPurgeTestStore(t, testItems())
	ctx := context.Background()
	u, err := st.FirstUser(ctx)
	if err != nil {
		t.Fatalf("FirstUser: %v", err)
	}

	n, err := st.PurgeIDs(ctx, []PurgeRef{{UserID: u.ID, ID: "item-tomb-a"}, {UserID: u.ID, ID: "item-tomb-a"}})
	if err != nil {
		t.Fatalf("PurgeIDs: %v", err)
	}
	if n != 1 {
		t.Fatalf("删除条数 = %d，期望 1（重复主键对已去重）", n)
	}
	if got := countAll(t, st); got != 2 {
		t.Fatalf("删除后条目数 = %d，期望 2", got)
	}
	var ids []string
	rows, err := st.DB().QueryContext(ctx, `SELECT id FROM items ORDER BY id`)
	if err != nil {
		t.Fatalf("查询剩余条目: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("扫描剩余条目: %v", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("遍历剩余条目: %v", err)
	}
	if len(ids) != 2 || ids[0] != "item-alive" || ids[1] != "item-tomb-b" {
		t.Fatalf("剩余条目 = %v，期望 [item-alive item-tomb-b]", ids)
	}
	// 空 ids 为无操作。
	if n, err := st.PurgeIDs(ctx, nil); err != nil || n != 0 {
		t.Fatalf("空 ids PurgeIDs = (%d, %v)，期望 (0, nil)", n, err)
	}
}

// TestPurgeIDsGuardsNonTombstone 验证勾选了非墓碑主键对时回滚并返回 ErrPurgeGuard。
func TestPurgeIDsGuardsNonTombstone(t *testing.T) {
	st := newPurgeTestStore(t, testItems())
	ctx := context.Background()
	u, err := st.FirstUser(ctx)
	if err != nil {
		t.Fatalf("FirstUser: %v", err)
	}

	refs := []PurgeRef{{UserID: u.ID, ID: "item-tomb-a"}, {UserID: u.ID, ID: "item-alive"}}
	if _, err := st.PurgeIDs(ctx, refs); !errors.Is(err, ErrPurgeGuard) {
		t.Fatalf("PurgeIDs 错误 = %v，期望 ErrPurgeGuard", err)
	}
	if got := countAll(t, st); got != 3 {
		t.Fatalf("回滚后条目数 = %d，期望 3", got)
	}
}

// TestPurgeIDsRespectsUserScope 验证复合主键后跨用户同名 id 的墓碑互不影响：
// 删除 bob 的同名墓碑不得波及 alice。
func TestPurgeIDsRespectsUserScope(t *testing.T) {
	st := newPurgeTestStore(t, testItems())
	ctx := context.Background()
	alice, err := st.FirstUser(ctx)
	if err != nil {
		t.Fatalf("FirstUser: %v", err)
	}
	if err := st.CreateUser(ctx, User{Username: "bob", Verifier: []byte{2}}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	bob, err := st.UserByUsername(ctx, "bob")
	if err != nil {
		t.Fatalf("UserByUsername: %v", err)
	}
	// bob 写一条与 alice 同名（item-tomb-a）的墓碑。
	if _, err := st.ApplyItems(ctx, bob.ID, []ItemInput{
		{ID: "item-tomb-a", Kind: "totp", RPID: "z.example", UpdatedAt: 100, DeletedAt: 400},
	}); err != nil {
		t.Fatalf("ApplyItems(bob): %v", err)
	}

	// 只删 bob 的主键对。
	n, err := st.PurgeIDs(ctx, []PurgeRef{{UserID: bob.ID, ID: "item-tomb-a"}})
	if err != nil || n != 1 {
		t.Fatalf("PurgeIDs = (%d, %v)，期望 (1, nil)", n, err)
	}
	// alice 的同名墓碑仍在。
	targets, err := st.PurgePending(ctx)
	if err != nil {
		t.Fatalf("PurgePending: %v", err)
	}
	var aliceTomb int
	for _, tg := range targets {
		if tg.ID == "item-tomb-a" && tg.UserID == alice.ID {
			aliceTomb++
		}
	}
	if aliceTomb != 1 {
		t.Fatalf("alice 的同名墓碑应保留，实际 %d 条（共 %d 条待删）", aliceTomb, len(targets))
	}
}
