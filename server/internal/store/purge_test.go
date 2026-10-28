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

// TestPurgeIDsDeletesOnlySelected 验证按 id 删除只影响勾选的墓碑。
func TestPurgeIDsDeletesOnlySelected(t *testing.T) {
	st := newPurgeTestStore(t, testItems())
	ctx := context.Background()

	n, err := st.PurgeIDs(ctx, []string{"item-tomb-a", "item-tomb-a"})
	if err != nil {
		t.Fatalf("PurgeIDs: %v", err)
	}
	if n != 1 {
		t.Fatalf("删除条数 = %d，期望 1（重复 id 已去重）", n)
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

// TestPurgeIDsGuardsNonTombstone 验证勾选了非墓碑 id 时回滚并返回 ErrPurgeGuard。
func TestPurgeIDsGuardsNonTombstone(t *testing.T) {
	st := newPurgeTestStore(t, testItems())
	ctx := context.Background()

	if _, err := st.PurgeIDs(ctx, []string{"item-tomb-a", "item-alive"}); !errors.Is(err, ErrPurgeGuard) {
		t.Fatalf("PurgeIDs 错误 = %v，期望 ErrPurgeGuard", err)
	}
	if got := countAll(t, st); got != 3 {
		t.Fatalf("回滚后条目数 = %d，期望 3", got)
	}
}
