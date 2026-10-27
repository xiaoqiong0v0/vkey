package api

import (
	"net/http"
	"strconv"

	"xiaoqiong0v0.cn/vkey/server/internal/crypto"
	"xiaoqiong0v0.cn/vkey/server/internal/policy"
	"xiaoqiong0v0.cn/vkey/server/internal/store"
)

// 条目 kind 允许值。
const (
	kindTOTP     = "totp"
	kindWebAuthn = "webauthn"
)

// itemsPostItem 是 POST /api/v1/items 中的单条条目。
//
// deleted_at 是对 shared/protocol.md 中 API 列表的扩展（见 protocol.md「偏差记录」）：
// 客户端用非 0 的 deleted_at 表达墓碑删除。
type itemsPostItem struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	RPID        string `json:"rp_id"`
	CT          string `json:"ct"`
	Nonce       string `json:"nonce"`
	BaseVersion int64  `json:"base_version"`
	UpdatedAt   int64  `json:"updated_at"`
	DeletedAt   int64  `json:"deleted_at"`
}

// itemsPostRequest 是 POST /api/v1/items 的请求体。
type itemsPostRequest struct {
	Items []itemsPostItem `json:"items"`
}

// itemsPostResult 是单条写入结果。
type itemsPostResult struct {
	ID      string `json:"id"`
	Version int64  `json:"version"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
}

// itemsPostResponse 是 POST /api/v1/items 的响应体。
type itemsPostResponse struct {
	Results []itemsPostResult `json:"results"`
}

// itemJSON 是 GET /api/v1/items 中单条条目的线上形式。
type itemJSON struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	RPID      string `json:"rp_id"`
	CT        string `json:"ct"`
	Nonce     string `json:"nonce"`
	Version   int64  `json:"version"`
	UpdatedAt int64  `json:"updated_at"`
	DeletedAt int64  `json:"deleted_at"`
}

// itemsGetResponse 是 GET /api/v1/items 的响应体。
type itemsGetResponse struct {
	Items []itemJSON `json:"items"`
	Next  int64      `json:"next"`
}

// handlePostItems 按 LWW 规则批量写入条目（需鉴权）。
//
// 结构非法（base64、长度、kind 等）整单拒绝并返回 400；语义冲突通过
// results[].status 表达，HTTP 状态仍为 200。
func (s *Server) handlePostItems(w http.ResponseWriter, r *http.Request, dev *store.Device) {
	var req itemsPostRequest
	if err := readJSON(w, r, &req); err != nil {
		writeReadError(w, err)
		return
	}
	if len(req.Items) > policy.MaxItemsPerRequest {
		writeErr(w, http.StatusBadRequest, "too_many_items", "单次最多提交 500 条")
		return
	}

	now := s.nowUnix()
	inputs := make([]store.ItemInput, 0, len(req.Items))
	for i, it := range req.Items {
		in, code, msg := normalizeItemInput(it, now)
		if code != "" {
			writeErr(w, http.StatusBadRequest, code, "items["+strconv.Itoa(i)+"]: "+msg)
			return
		}
		inputs = append(inputs, in)
	}

	results, err := s.store.ApplyItems(r.Context(), dev.UserID, inputs)
	if err != nil {
		s.logErr("应用条目失败", err)
		writeErr(w, http.StatusInternalServerError, "internal", "服务端内部错误")
		return
	}
	if err := s.store.Audit(r.Context(), dev.UserID, dev.ID, "items.apply", now); err != nil {
		s.logErr("写审计失败", err)
	}

	resp := itemsPostResponse{Results: make([]itemsPostResult, 0, len(results))}
	for _, res := range results {
		resp.Results = append(resp.Results, itemsPostResult{
			ID: res.ID, Version: res.Version, Status: res.Status, Reason: res.Reason,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

// normalizeItemInput 校验并转换单条条目；返回空错误码表示通过。
func normalizeItemInput(it itemsPostItem, now int64) (store.ItemInput, string, string) {
	var in store.ItemInput
	if it.ID == "" || len(it.ID) > policy.MaxItemIDBytes {
		return in, "invalid_item", "id 必须为 1..128 字节"
	}
	if it.Kind != kindTOTP && it.Kind != kindWebAuthn {
		return in, "invalid_item", "kind 必须是 totp 或 webauthn"
	}
	if it.RPID == "" || len(it.RPID) > policy.MaxRPIDBytes {
		return in, "invalid_item", "rp_id 必须为 1..255 字节"
	}
	if it.BaseVersion < 0 || it.UpdatedAt < 0 || it.DeletedAt < 0 {
		return in, "invalid_item", "base_version/updated_at/deleted_at 不能为负"
	}

	ct := []byte(nil)
	if it.CT != "" {
		var err error
		ct, err = crypto.ParseB64(it.CT)
		if err != nil {
			return in, "invalid_item", "ct 不是合法的 base64url"
		}
		if len(ct) > policy.MaxItemCiphertextBytes {
			return in, "item_too_large", "ct 解码后超过 8192 字节"
		}
	} else if it.DeletedAt == 0 {
		return in, "invalid_item", "非墓碑条目的 ct 不能为空"
	}

	nonce := []byte(nil)
	if it.Nonce != "" {
		var err error
		nonce, err = crypto.ParseB64(it.Nonce)
		if err != nil {
			return in, "invalid_item", "nonce 不是合法的 base64url"
		}
		if len(nonce) != crypto.NonceLen {
			return in, "invalid_item", "nonce 必须为 12 字节"
		}
	} else if it.DeletedAt == 0 {
		return in, "invalid_item", "非墓碑条目的 nonce 不能为空"
	}

	updated := it.UpdatedAt
	if updated == 0 {
		updated = now
	}
	in = store.ItemInput{
		ID:          it.ID,
		Kind:        it.Kind,
		RPID:        it.RPID,
		Ciphertext:  ct,
		Nonce:       nonce,
		BaseVersion: it.BaseVersion,
		UpdatedAt:   updated,
		DeletedAt:   it.DeletedAt,
	}
	return in, "", ""
}

// handleGetItems 增量拉取条目（需鉴权）。
//
// 查询参数 since 表示「只返回 version > since 的条目」。返回值 next 为本页
// 最后一条的 version（还有下一页时）或服务端当前 seq；若 next < since，
// 说明服务端版本回滚，客户端应全量重拉。
func (s *Server) handleGetItems(w http.ResponseWriter, r *http.Request, dev *store.Device) {
	var since int64
	if v := r.URL.Query().Get("since"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			writeErr(w, http.StatusBadRequest, "invalid_since", "since 必须是非负整数")
			return
		}
		since = n
	}
	items, next, err := s.store.ItemsSince(r.Context(), dev.UserID, since, policy.MaxItemsPage)
	if err != nil {
		s.logErr("拉取条目失败", err)
		writeErr(w, http.StatusInternalServerError, "internal", "服务端内部错误")
		return
	}
	resp := itemsGetResponse{Items: make([]itemJSON, 0, len(items)), Next: next}
	for _, it := range items {
		resp.Items = append(resp.Items, itemJSON{
			ID: it.ID, Kind: it.Kind, RPID: it.RPID,
			CT: crypto.B64(it.Ciphertext), Nonce: crypto.B64(it.Nonce),
			Version: it.Version, UpdatedAt: it.UpdatedAt, DeletedAt: it.DeletedAt,
		})
	}
	if len(items) == policy.MaxItemsPage && len(items) > 0 {
		resp.Next = items[len(items)-1].Version
	}
	writeJSON(w, http.StatusOK, resp)
}
