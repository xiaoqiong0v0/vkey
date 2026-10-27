package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// 条目写入结果状态。
const (
	// StatusApplied 表示写入已生效。
	StatusApplied = "applied"
	// StatusConflict 表示 LWW 落败，未生效。
	StatusConflict = "conflict"
	// StatusRejected 表示语义非法（如 kind/rp_id 被改写），未生效。
	StatusRejected = "rejected"
)

// ApplyItems 在一个事务内按 LWW 规则应用一批条目写入。
//
// 参数：userID 为账号；in 已由 API 层完成结构校验（base64、长度、kind 等）。
// 返回：与入参顺序一一对应的结果；事务失败时返回错误。
//
// 并发契约：version 的读取与递增都在同一事务内完成（见 ASYNC.md）。
func (s *Store) ApplyItems(ctx context.Context, userID string, in []ItemInput) ([]ItemResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: 开启事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	seq, err := seqGet(ctx, tx, userID)
	if err != nil {
		return nil, err
	}
	results := make([]ItemResult, 0, len(in))
	for _, it := range in {
		res, next, err := applyOne(ctx, tx, userID, it, seq)
		if err != nil {
			return nil, err
		}
		seq = next
		results = append(results, res)
	}
	if err := seqPut(ctx, tx, userID, seq); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: 提交事务失败: %w", err)
	}
	return results, nil
}

// applyOne 处理单条条目并返回结果与更新后的 seq。
func applyOne(ctx context.Context, tx *sql.Tx, userID string, it ItemInput, seq int64) (ItemResult, int64, error) {
	var (
		curKind    string
		curRPID    string
		curCT      []byte
		curNonce   []byte
		curVersion int64
		curUpdated int64
		curDeleted sql.NullInt64
	)
	err := tx.QueryRowContext(ctx,
		`SELECT kind, rp_id, ciphertext, nonce, version, updated_at, deleted_at
		 FROM items WHERE user_id = ? AND id = ?`, userID, it.ID).
		Scan(&curKind, &curRPID, &curCT, &curNonce, &curVersion, &curUpdated, &curDeleted)
	if errors.Is(err, sql.ErrNoRows) {
		// 服务端没有该条目：只有 base_version == 0 的「新建」才接受。
		if it.BaseVersion != 0 {
			return ItemResult{ID: it.ID, Version: 0, Status: StatusConflict, Reason: "base_version_mismatch"}, seq, nil
		}
		seq++
		if err := insertItem(ctx, tx, userID, it, seq); err != nil {
			return ItemResult{}, seq, err
		}
		return ItemResult{ID: it.ID, Version: seq, Status: StatusApplied}, seq, nil
	}
	if err != nil {
		return ItemResult{}, seq, fmt.Errorf("store: 读取条目失败: %w", err)
	}

	// 条目的 kind / rp_id 创建后不可变，防止调包。
	if it.Kind != curKind {
		return ItemResult{ID: it.ID, Version: curVersion, Status: StatusRejected, Reason: "kind_mismatch"}, seq, nil
	}
	if it.RPID != curRPID {
		return ItemResult{ID: it.ID, Version: curVersion, Status: StatusRejected, Reason: "rp_id_mismatch"}, seq, nil
	}

	current := Item{
		ID: it.ID, UserID: userID, Kind: curKind, RPID: curRPID,
		Ciphertext: curCT, Nonce: curNonce, Version: curVersion,
		UpdatedAt: curUpdated, DeletedAt: curDeleted.Int64,
	}

	if it.BaseVersion == curVersion {
		seq++
		if err := updateItem(ctx, tx, userID, it, seq); err != nil {
			return ItemResult{}, seq, err
		}
		return ItemResult{ID: it.ID, Version: seq, Status: StatusApplied}, seq, nil
	}

	if it.UpdatedAt > curUpdated {
		// 服务端版本落后：保留旧值为冲突副本，然后应用新值。
		if err := insertConflict(ctx, tx, userID, current); err != nil {
			return ItemResult{}, seq, err
		}
		seq++
		if err := updateItem(ctx, tx, userID, it, seq); err != nil {
			return ItemResult{}, seq, err
		}
		return ItemResult{ID: it.ID, Version: seq, Status: StatusApplied}, seq, nil
	}

	// 服务端版本更新（或 updated_at 相同）：本次写入落败，保留本次为冲突副本。
	incoming := Item{
		ID: it.ID, UserID: userID, Kind: it.Kind, RPID: it.RPID,
		Ciphertext: it.Ciphertext, Nonce: it.Nonce, Version: it.BaseVersion,
		UpdatedAt: it.UpdatedAt, DeletedAt: it.DeletedAt,
	}
	if err := insertConflict(ctx, tx, userID, incoming); err != nil {
		return ItemResult{}, seq, err
	}
	return ItemResult{ID: it.ID, Version: curVersion, Status: StatusConflict, Reason: "stale_write"}, seq, nil
}

// insertItem 插入新条目。
func insertItem(ctx context.Context, tx *sql.Tx, userID string, it ItemInput, version int64) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO items(id, user_id, kind, rp_id, ciphertext, nonce, version, updated_at, deleted_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		it.ID, userID, it.Kind, it.RPID, it.Ciphertext, it.Nonce, version, it.UpdatedAt, nullableInt(it.DeletedAt))
	if err != nil {
		return fmt.Errorf("store: 插入条目失败: %w", err)
	}
	return nil
}

// updateItem 覆盖已有条目。
func updateItem(ctx context.Context, tx *sql.Tx, userID string, it ItemInput, version int64) error {
	res, err := tx.ExecContext(ctx,
		`UPDATE items SET ciphertext = ?, nonce = ?, version = ?, updated_at = ?, deleted_at = ?
		 WHERE user_id = ? AND id = ?`,
		it.Ciphertext, it.Nonce, version, it.UpdatedAt, nullableInt(it.DeletedAt), userID, it.ID)
	if err != nil {
		return fmt.Errorf("store: 更新条目失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// insertConflict 保存 LWW 落败副本。
func insertConflict(ctx context.Context, tx *sql.Tx, userID string, it Item) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO item_conflicts(user_id, item_id, ciphertext, nonce, version, updated_at)
		 VALUES(?, ?, ?, ?, ?, ?)`,
		userID, it.ID, it.Ciphertext, it.Nonce, it.Version, it.UpdatedAt)
	if err != nil {
		return fmt.Errorf("store: 写入冲突副本失败: %w", err)
	}
	return nil
}

// ItemsSince 返回 version > since 的条目（含墓碑），按 version 升序。
//
// 返回的 next 为账号当前 seq。若 next < since，说明服务端回滚过，客户端应全量重拉。
func (s *Store) ItemsSince(ctx context.Context, userID string, since int64, limit int) ([]Item, int64, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, kind, rp_id, ciphertext, nonce, version, updated_at, deleted_at
		 FROM items WHERE user_id = ? AND version > ? ORDER BY version ASC LIMIT ?`,
		userID, since, limit)
	if err != nil {
		return nil, 0, fmt.Errorf("store: 查询条目失败: %w", err)
	}
	defer func() { _ = rows.Close() }()

	items := make([]Item, 0, 16)
	for rows.Next() {
		var (
			it      Item
			deleted sql.NullInt64
		)
		if err := rows.Scan(&it.ID, &it.UserID, &it.Kind, &it.RPID, &it.Ciphertext,
			&it.Nonce, &it.Version, &it.UpdatedAt, &deleted); err != nil {
			return nil, 0, fmt.Errorf("store: 解析条目失败: %w", err)
		}
		it.DeletedAt = deleted.Int64
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("store: 遍历条目失败: %w", err)
	}
	// 显式关闭，确保单连接在查询 seq 前被释放。
	_ = rows.Close()
	next, err := s.Seq(ctx, userID)
	if err != nil {
		return nil, 0, err
	}
	return items, next, nil
}

// ConflictsFor 返回指定条目的冲突副本（按写入顺序）。用于运维与测试。
func (s *Store) ConflictsFor(ctx context.Context, userID, itemID string) ([]Conflict, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, item_id, ciphertext, nonce, version, updated_at
		 FROM item_conflicts WHERE user_id = ? AND item_id = ? ORDER BY id ASC`, userID, itemID)
	if err != nil {
		return nil, fmt.Errorf("store: 查询冲突副本失败: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]Conflict, 0, 4)
	for rows.Next() {
		var c Conflict
		if err := rows.Scan(&c.ID, &c.ItemID, &c.Ciphertext, &c.Nonce, &c.Version, &c.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: 解析冲突副本失败: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: 遍历冲突副本失败: %w", err)
	}
	return out, nil
}

// nullableInt 把 0 值转为 SQL NULL。
func nullableInt(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}
