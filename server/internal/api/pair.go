package api

import (
	"errors"
	"net/http"
	"regexp"

	"xiaoqiong0v0.cn/vkey/server/internal/crypto"
	"xiaoqiong0v0.cn/vkey/server/internal/pair"
	"xiaoqiong0v0.cn/vkey/server/internal/policy"
	"xiaoqiong0v0.cn/vkey/server/internal/store"
)

// codeIDPattern 限定 code_id 的字符集（它会作为 HKDF info 使用）。
var codeIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// pairNewRequest 是 POST /api/v1/pair/new 的请求体。
//
// 注意：`code` 是对 shared/protocol.md 原始 API 列表的补充字段（原因见
// protocol.md「偏差记录」：服务端需要 code 才能算出 code_hash）。
type pairNewRequest struct {
	CodeID string `json:"code_id"`
	Code   string `json:"code"`
	Blob   string `json:"blob"`
	PWSalt string `json:"pw_salt"`
}

// pairNewResponse 是 POST /api/v1/pair/new 的响应体。
type pairNewResponse struct {
	CodeID    string `json:"code_id"`
	Code      string `json:"code"`
	ExpiresAt int64  `json:"expires_at"`
}

// pairClaimRequest 是 POST /api/v1/pair/claim 的请求体。
type pairClaimRequest struct {
	Code     string `json:"code"`
	Name     string `json:"name"`
	Platform string `json:"platform"`
	PubKey   string `json:"pubkey"`
}

// pairClaimResponse 是 POST /api/v1/pair/claim 的响应体。
type pairClaimResponse struct {
	Token      string  `json:"token"`
	DeviceID   string  `json:"device_id"`
	Blob       string  `json:"blob"`
	PWSalt     *string `json:"pw_salt,omitempty"`
	WrappedKey *string `json:"wrapped_key,omitempty"`
	CodeID     string  `json:"code_id"`
}

// handlePairNew 登记一个配对会话（需鉴权）。
//
// 流程：客户端生成 32B code，用 PairKEK 把 master_key 封装为 blob，
// 然后把 {code_id, code, blob} 上传；服务端只存 SHA256(code) 与 blob。
func (s *Server) handlePairNew(w http.ResponseWriter, r *http.Request, dev *store.Device) {
	var req pairNewRequest
	if err := readJSON(w, r, &req); err != nil {
		writeReadError(w, r, err)
		return
	}
	if !codeIDPattern.MatchString(req.CodeID) {
		writeError(w, r, http.StatusBadRequest, "invalid_code_id")
		return
	}
	code, canonical, err := pair.Normalize(req.Code)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_code")
		return
	}
	blob, err := crypto.ParseB64(req.Blob)
	if err != nil || len(blob) <= crypto.NonceLen+16 || len(blob) > policy.MaxPairBlobBytes {
		writeError(w, r, http.StatusBadRequest, "invalid_blob")
		return
	}
	var pwSalt []byte
	if req.PWSalt != "" {
		pwSalt, err = parseFixedB64("pw_salt", req.PWSalt, crypto.PWSaltLen)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_pw_salt")
			return
		}
	}

	now := s.nowUnix()
	expires := now + int64(policy.PairTTLSeconds)
	p := store.Pair{
		CodeID:    req.CodeID,
		UserID:    dev.UserID,
		CodeHash:  pair.Hash(code),
		Blob:      blob,
		PWSalt:    pwSalt,
		ExpiresAt: expires,
		CreatedAt: now,
	}
	if err := s.store.CreatePair(r.Context(), p); err != nil {
		if errors.Is(err, store.ErrExists) {
			writeError(w, r, http.StatusConflict, "code_id_exists")
			return
		}
		s.logErr("创建配对会话失败", err)
		writeError(w, r, http.StatusInternalServerError, "internal")
		return
	}
	if err := s.store.Audit(r.Context(), dev.UserID, dev.ID, "pair.new", now); err != nil {
		s.logErr("写审计失败", err)
	}
	writeJSON(w, http.StatusOK, pairNewResponse{CodeID: req.CodeID, Code: canonical, ExpiresAt: expires})
}

// handlePairClaim 领取配对码并创建设备（免鉴权，单次可用）。
func (s *Server) handlePairClaim(w http.ResponseWriter, r *http.Request) {
	var req pairClaimRequest
	if err := readJSON(w, r, &req); err != nil {
		writeReadError(w, r, err)
		return
	}
	code, _, err := pair.Normalize(req.Code)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_code")
		return
	}
	pubkey, err := parseFixedB64("pubkey", req.PubKey, 32)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_pubkey")
		return
	}
	if err := validateText("name", req.Name, policy.MaxDeviceNameBytes); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_device")
		return
	}
	if err := validateText("platform", req.Platform, policy.MaxPlatformBytes); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_device")
		return
	}

	token, err := crypto.NewToken()
	if err != nil {
		s.logErr("生成 token 失败", err)
		writeError(w, r, http.StatusInternalServerError, "internal")
		return
	}
	claim, err := s.store.ClaimPair(r.Context(), pair.Hash(code), req.Name, req.Platform,
		pubkey, crypto.TokenHash(token), s.nowUnix())
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "code_not_found")
		return
	case errors.Is(err, store.ErrPairUsed):
		writeError(w, r, http.StatusConflict, "code_used")
		return
	case errors.Is(err, store.ErrPairExpired):
		writeError(w, r, http.StatusGone, "code_expired")
		return
	case errors.Is(err, store.ErrUserDisabled):
		writeError(w, r, http.StatusUnauthorized, "user_disabled")
		return
	case writeQuotaErr(w, r, err):
		return
	case err != nil:
		s.logErr("领取配对码失败", err)
		writeError(w, r, http.StatusInternalServerError, "internal")
		return
	}
	if err := s.store.Audit(r.Context(), claim.UserID, claim.DeviceID, "pair.claim", s.nowUnix()); err != nil {
		s.logErr("写审计失败", err)
	}
	writeJSON(w, http.StatusOK, pairClaimResponse{
		Token:      crypto.B64(token),
		DeviceID:   claim.DeviceID,
		Blob:       crypto.B64(claim.Blob),
		PWSalt:     b64Ptr(claim.PWSalt),
		WrappedKey: b64Ptr(claim.WrappedKey),
		CodeID:     claim.CodeID,
	})
}
