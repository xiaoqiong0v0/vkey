package api

import (
	"errors"
	"net/http"

	"xiaoqiong0v0.cn/vkey/server/internal/crypto"
	"xiaoqiong0v0.cn/vkey/server/internal/policy"
	"xiaoqiong0v0.cn/vkey/server/internal/store"
)

// 开户（enroll）：admin 模式下客户端凭管理员 CLI 签发的一次性开户码绑定账号。
//
// 零知识边界：master_key 全程只在客户端生成；服务端只收到 verifier
// （HKDF 派生值，不可反推 master_key）、可选的 pw_salt/wrapped_key 与设备公钥。
// 日志与错误信息不得出现 code / verifier / token 原文。

// enrollRequest 是 POST /api/v1/auth/enroll 的请求体。
type enrollRequest struct {
	Code       string     `json:"code"`
	Username   string     `json:"username"` // 可选：开户码已绑定用户名时可省略
	Verifier   string     `json:"verifier"`
	PWSalt     string     `json:"pw_salt"`     // 可选
	WrappedKey string     `json:"wrapped_key"` // 可选
	Device     authDevice `json:"device"`
}

// enrollResponse 是 POST /api/v1/auth/enroll 的响应体。
type enrollResponse struct {
	DeviceID string `json:"device_id"`
	Token    string `json:"token"`
	UserID   string `json:"user_id"`
	Username string `json:"username"`
}

// handleEnroll 用一次性开户码创建账号 + 首个设备并签发 token（免鉴权，限流 60/min/IP）。
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	mode, err := s.store.UserMode(r.Context())
	if err != nil {
		s.logErr("查询用户模式失败", err)
		writeErr(w, http.StatusInternalServerError, "internal", "服务端内部错误")
		return
	}
	if mode != policy.UserModeAdmin {
		writeErr(w, http.StatusForbidden, "enroll_disabled", "服务端未启用开户（single 模式）")
		return
	}

	var req enrollRequest
	if err := readJSON(w, r, &req); err != nil {
		writeReadError(w, err)
		return
	}
	if store.NormalizeEnrollCode(req.Code) == "" {
		writeErr(w, http.StatusBadRequest, "invalid_code", "code 不能为空")
		return
	}
	verifier, err := parseFixedB64("verifier", req.Verifier, crypto.KeyLen)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_verifier", err.Error())
		return
	}
	// username 可选：开户码已绑定时省略；长度校验与 /auth/token 同规则。
	if req.Username != "" {
		if err := validateText("username", req.Username, policy.MaxUsernameBytes); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_username", err.Error())
			return
		}
	}
	pubkey, err := parseFixedB64("device.pubkey", req.Device.PubKey, 32)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_pubkey", err.Error())
		return
	}
	if err := validateText("device.name", req.Device.Name, policy.MaxDeviceNameBytes); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_device", err.Error())
		return
	}
	if err := validateText("device.platform", req.Device.Platform, policy.MaxPlatformBytes); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_device", err.Error())
		return
	}
	pwSalt, wrappedKey, code, msg := parsePasswordFields(req.PWSalt, req.WrappedKey)
	if code != "" {
		writeErr(w, http.StatusBadRequest, code, msg)
		return
	}

	token, err := crypto.NewToken()
	if err != nil {
		s.logErr("生成 token 失败", err)
		writeErr(w, http.StatusInternalServerError, "internal", "服务端内部错误")
		return
	}
	out, err := s.store.Enroll(r.Context(), store.EnrollInput{
		Code:           req.Code,
		Username:       req.Username,
		Verifier:       verifier,
		PWSalt:         pwSalt,
		WrappedKey:     wrappedKey,
		DeviceName:     req.Device.Name,
		DevicePlatform: req.Device.Platform,
		DevicePubKey:   pubkey,
		TokenHash:      crypto.TokenHash(token),
		Now:            s.nowUnix(),
	})
	switch {
	case err == nil:
	case errors.Is(err, store.ErrEnrollExpired):
		writeErr(w, http.StatusGone, "code_expired", "开户码已过期")
		return
	case errors.Is(err, store.ErrEnrollInvalid), errors.Is(err, store.ErrNotFound):
		// 不存在/已用/已撤销/未绑定用户名统一答复，不区分细节。
		writeErr(w, http.StatusBadRequest, "invalid_code", "开户码无效")
		return
	case errors.Is(err, store.ErrExists):
		writeErr(w, http.StatusConflict, "username_taken", "用户名已被占用")
		return
	case writeQuotaErr(w, err):
		return
	default:
		s.logErr("开户失败", err)
		writeErr(w, http.StatusInternalServerError, "internal", "服务端内部错误")
		return
	}

	if err := s.store.Audit(r.Context(), out.UserID, out.DeviceID, "auth.enroll", s.nowUnix()); err != nil {
		s.logErr("写审计失败", err)
	}
	// 只记标识与结果，绝不记 code/verifier/token。
	s.logger.Printf("enroll ok: user_id=%s username=%s", out.UserID, out.Username)
	writeJSON(w, http.StatusOK, enrollResponse{
		DeviceID: out.DeviceID,
		Token:    crypto.B64(token),
		UserID:   out.UserID,
		Username: out.Username,
	})
}

// parsePasswordFields 校验可选的主密码包裹字段。
//
// 规则与 POST /auth/password 一致：pw_salt 16B、wrapped_key 为自包含布局且 ≤ 80B；
// 两者要么都不给，要么都给出（只给其一视为非法）。
// 返回：(pwSalt, wrappedKey, 错误码, 错误消息)；错误码为空表示通过。
func parsePasswordFields(pwSaltB64, wrappedB64 string) ([]byte, []byte, string, string) {
	if pwSaltB64 == "" && wrappedB64 == "" {
		return nil, nil, "", ""
	}
	if pwSaltB64 == "" || wrappedB64 == "" {
		return nil, nil, "invalid_pw_fields", "pw_salt 与 wrapped_key 必须成对提供"
	}
	pwSalt, err := parseFixedB64("pw_salt", pwSaltB64, crypto.PWSaltLen)
	if err != nil {
		return nil, nil, "invalid_pw_salt", err.Error()
	}
	wrappedKey, err := crypto.ParseB64(wrappedB64)
	if err != nil {
		return nil, nil, "invalid_wrapped_key", "wrapped_key 不是合法的 base64url"
	}
	if len(wrappedKey) <= crypto.NonceLen+crypto.TagLen || len(wrappedKey) > policy.MaxWrappedKeyBytes {
		return nil, nil, "invalid_wrapped_key",
			"wrapped_key 必须是 nonce(12)||ct||tag 自包含布局，长度 ≤ 80 字节"
	}
	return pwSalt, wrappedKey, "", ""
}
