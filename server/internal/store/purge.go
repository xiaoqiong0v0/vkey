package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// 物理删除（purge）的唯一入口。
//
// 策略：只有已逻辑删除的墓碑（deleted_at 非空且非 0）可以被物理删除；
// 该操作仅由运维在控制台执行 `vkeyd purge`（交互勾选）或 `vkeyd purge --yes`，
// 不暴露任何 HTTP 接口。

// PurgeItemsSQL 是唯一允许的物理删除语句。
//
// 请勿修改 WHERE 子句：Purge 在事务内会做一致性断言，
// 一旦删除影响到非墓碑行就会回滚并返回 ErrPurgeGuard。
const PurgeItemsSQL = `DELETE FROM items WHERE deleted_at IS NOT NULL AND deleted_at != 0`

// tombstonePredicate 是「已逻辑删除」的行判定条件，必须与 PurgeItemsSQL 的 WHERE 一致。
const tombstonePredicate = `deleted_at IS NOT NULL AND deleted_at != 0`

// ErrPurgeGuard 表示物理删除的一致性断言失败（疑似删除条件被放宽），事务已回滚。
var ErrPurgeGuard = fmt.Errorf("store: 物理删除断言失败：非墓碑条目受影响，已回滚")

// PurgeTarget 是一条待物理删除的墓碑条目摘要（不含密文）。
type PurgeTarget struct {
	ID        string
	Kind      string
	RPID      string
	DeletedAt int64
	Version   int64
}

// PurgePending 列出待物理删除的墓碑条目，按 id 升序。
//
// 只读操作，供 `vkeyd purge` 的 dry-run 使用；不会修改数据库。
func (s *Store) PurgePending(ctx context.Context) ([]PurgeTarget, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, kind, rp_id, deleted_at, version FROM items
		 WHERE `+tombstonePredicate+` ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: 查询待删除墓碑失败: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]PurgeTarget, 0, 16)
	for rows.Next() {
		var t PurgeTarget
		if err := rows.Scan(&t.ID, &t.Kind, &t.RPID, &t.DeletedAt, &t.Version); err != nil {
			return nil, fmt.Errorf("store: 解析待删除墓碑失败: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: 遍历待删除墓碑失败: %w", err)
	}
	return out, nil
}

// Purge 在单个事务内物理删除所有墓碑条目。
//
// 返回：实际删除的条数（无可删条目时为 0）。
// 防御断言（任一不满足即回滚并返回 ErrPurgeGuard）：
//   - 实际影响行数必须等于事务内统计到的墓碑行数；
//   - 删除前后「非墓碑行数」必须完全一致（防止 WHERE 被放宽导致误删）。
func (s *Store) Purge(ctx context.Context) (int64, error) {
	return s.purgeInTx(ctx, func(ctx context.Context, tx *sql.Tx) (int64, int64, error) {
		tombstones, err := countTombstones(ctx, tx)
		if err != nil {
			return 0, 0, err
		}
		if tombstones == 0 {
			return 0, 0, nil
		}
		res, err := tx.ExecContext(ctx, PurgeItemsSQL)
		if err != nil {
			return 0, 0, fmt.Errorf("store: 物理删除墓碑失败: %w", err)
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return 0, 0, fmt.Errorf("store: 读取删除条数失败: %w", err)
		}
		return affected, tombstones, nil
	})
}

// PurgeIDs 在单个事务内物理删除指定 id 的墓碑条目（交互式勾选后使用）。
//
// 参数：ids 为待删除条目的 id（通常来自 PurgePending）；重复 id 会被去重。
// 返回：实际删除的条数（ids 为空时为 0）。
// 防御断言与 Purge 一致，且额外要求「实际影响行数 == 去重后的 id 数」——
// 若某个 id 在删除时已不是墓碑（状态被并发改动），事务回滚并返回 ErrPurgeGuard。
func (s *Store) PurgeIDs(ctx context.Context, ids []string) (int64, error) {
	uniq := dedupeIDs(ids)
	if len(uniq) == 0 {
		return 0, nil
	}
	return s.purgeInTx(ctx, func(ctx context.Context, tx *sql.Tx) (int64, int64, error) {
		args := make([]any, len(uniq))
		for i, id := range uniq {
			args[i] = id
		}
		sqlText := `DELETE FROM items WHERE id IN (` +
			strings.TrimSuffix(strings.Repeat("?,", len(uniq)), ",") + `) AND ` + tombstonePredicate
		res, err := tx.ExecContext(ctx, sqlText, args...)
		if err != nil {
			return 0, 0, fmt.Errorf("store: 物理删除墓碑失败: %w", err)
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return 0, 0, fmt.Errorf("store: 读取删除条数失败: %w", err)
		}
		return affected, int64(len(uniq)), nil
	})
}

// purgeExec 在事务内执行一次物理删除。
//
// 返回：affected 为实际影响行数；expected 为预期影响行数（0 表示无需删除）。
type purgeExec func(ctx context.Context, tx *sql.Tx) (affected, expected int64, err error)

// purgeInTx 在单事务内执行物理删除并做一致性断言。
//
// expected 为 0 时视为空操作（不提交任何删除），返回 0。
// 断言（任一不满足即回滚并返回 ErrPurgeGuard）：
//   - 实际影响行数必须等于预期行数；
//   - 删除前后「非墓碑行数」必须完全一致（防止 WHERE 被放宽导致误删）。
func (s *Store) purgeInTx(ctx context.Context, exec purgeExec) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: 开启事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	aliveBefore, err := countNonTombstones(ctx, tx)
	if err != nil {
		return 0, err
	}
	affected, expected, err := exec(ctx, tx)
	if err != nil {
		return 0, err
	}
	if expected == 0 {
		return 0, nil
	}
	if affected != expected {
		return 0, fmt.Errorf("%w（预期 %d 条，实际影响 %d 条）", ErrPurgeGuard, expected, affected)
	}

	aliveAfter, err := countNonTombstones(ctx, tx)
	if err != nil {
		return 0, err
	}
	if aliveAfter != aliveBefore {
		return 0, fmt.Errorf("%w（非墓碑行数 删除前 %d → 删除后 %d）", ErrPurgeGuard, aliveBefore, aliveAfter)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: 提交事务失败: %w", err)
	}
	return affected, nil
}

// dedupeIDs 按首次出现顺序去重，并丢弃空字符串。
func dedupeIDs(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

// countTombstones 统计已逻辑删除的行数。
func countTombstones(ctx context.Context, tx *sql.Tx) (int64, error) {
	var n int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM items WHERE `+tombstonePredicate).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: 统计墓碑失败: %w", err)
	}
	return n, nil
}

// countNonTombstones 统计未被逻辑删除的行数（正常条目）。
func countNonTombstones(ctx context.Context, tx *sql.Tx) (int64, error) {
	var n int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM items WHERE NOT (`+tombstonePredicate+`)`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: 统计非墓碑失败: %w", err)
	}
	return n, nil
}
