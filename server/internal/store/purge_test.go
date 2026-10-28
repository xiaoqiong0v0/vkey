package store

import (
	"context"
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
