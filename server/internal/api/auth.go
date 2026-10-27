package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"xiaoqiong0v0.cn/vkey/server/internal/crypto"
	"xiaoqiong0v0.cn/vkey/server/internal/policy"
	"xiaoqiong0v0.cn/vkey/server/internal/store"
)

// policyResponse 是 GET /api/v1/policy 的响应体。
type policyResponse struct {
	RequireMasterPW bool `json:"require_master_pw"`
	// RequireMasterPWEnforced 表示「策略要求主密码」且「服务端确实存有包裹」，
	// 客户端只有在这种情况下才能用密码解包；否则必须报错而不是静默放行。
	RequireMasterPWEnforced bool       `json:"require_master_pw_enforced"`
	KDF                     policy.KDF `json:"kdf"`
	UsernameHint            string     `json:"username_hint"`
}

// healthResponse 是 GET /api/v1/health 的响应体。
type healthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
	Items   int64  `json:"items"`
	Devices int64  `json:"devices"`
}

// authDevice 是认证请求中的设备描述。
type authDevice struct {
	Name     string `json:"name"`
	Platform string `json:"platform"`
	PubKey   string `json:"pubkey"`
}

// authTokenRequest 是 POST /api/v1/auth/token 的请求体。
type authTokenRequest struct {
	Username string     `json:"username"`
	Verifier string     `json:"verifier"`
	Device   authDevice `json:"device"`
}

// authTokenResponse 是 POST /api/v1/auth/token 的响应体。
type authTokenResponse struct {
	Token      string  `json:"token"`
	DeviceID   string  `json:"device_id"`
	PWSalt     *string `json:"pw_salt,omitempty"`
	WrappedKey *string `json:"wrapped_key,omitempty"`
}

// passwordRequest 是 POST /api/v1/auth/password 的请求体。
type passwordRequest struct {
	WrappedKey string `json:"wrapped_key"`
	PWSalt     string `json:"pw_salt"`
}

// passwordDeleteRequest 是 DELETE /api/v1/auth/password 的请求体。
//
// 必须显式确认，避免误删导致所有设备都无法再解出 master_key。
type passwordDeleteRequest struct {
	Confirm string `json:"confirm"`
}

// removePasswordConfirm 是删除主密码包裹时必须回传的确认串。
const removePasswordConfirm = "remove-master-password"

// okResponse 是只表示成功的响应体。
type okResponse struct {
	OK bool `json:"ok"`
}

// handlePolicy 返回服务端策略（免鉴权）。
func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	resp := policyResponse{KDF: policy.KDFParams()}
	u, err := s.firstUser(r.Context())
	switch {
	case err == nil:
		resp.RequireMasterPW = u.RequireMasterPW
		resp.RequireMasterPWEnforced = u.RequireMasterPW && len(u.WrappedKey) > 0
		// username 是 verifier 的 HKDF info，客户端必须拿到精确值才能算 verifier，
		// 因此这里返回原文而非掩码。
		resp.UsernameHint = u.Username
	case isNoUser(err):
		// 尚未 init：返回默认策略。
	default:
		s.logErr("查询策略失败", err)
		writeErr(w, http.StatusInternalServerError, "internal", "服务端内部错误")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleHealth 返回服务状态与计数（免鉴权）。
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	items, devices, err := s.store.Counts(r.Context())
	if err != nil {
		s.logErr("统计失败", err)
		writeErr(w, http.StatusInternalServerError, "internal", "服务端内部错误")
		return
	}
	writeJSON(w, http.StatusOK, healthResponse{
		Status:  "ok",
		Version: s.opts.Version,
		Items:   items,
		Devices: devices,
	})
}

// handleAuthToken 用 verifier 换取设备 token，并 upsert 设备。
//
// 语义：同一设备公钥再次认证会覆盖旧 token（旧 token 立即失效）。
func (s *Server) handleAuthToken(w http.ResponseWriter, r *http.Request) {
	var req authTokenRequest
	if err := readJSON(w, r, &req); err != nil {
		writeReadError(w, err)
		return
	}
	if err := validateText("username", req.Username, policy.MaxUsernameBytes); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_username", err.Error())
		return
	}
	verifier, err := parseFixedB64("verifier", req.Verifier, crypto.KeyLen)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_verifier", err.Error())
		return
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

	u, err := s.store.UserByUsername(r.Context(), req.Username)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusUnauthorized, "invalid_credentials", "用户名或 verifier 不正确")
		return
	}
	if err != nil {
		s.logErr("查询用户失败", err)
		writeErr(w, http.StatusInternalServerError, "internal", "服务端内部错误")
		return
	}
	// 常量时间比较，避免按字节提前返回。
	if !crypto.Equal(u.Verifier, verifier) {
		writeErr(w, http.StatusUnauthorized, "invalid_credentials", "用户名或 verifier 不正确")
		return
	}

	token, err := crypto.NewToken()
	if err != nil {
		s.logErr("生成 token 失败", err)
		writeErr(w, http.StatusInternalServerError, "internal", "服务端内部错误")
		return
	}
	deviceID, err := s.store.UpsertDevice(r.Context(), u.ID, req.Device.Name, req.Device.Platform,
		pubkey, crypto.TokenHash(token), s.nowUnix())
	if err != nil {
		s.logErr("upsert 设备失败", err)
		writeErr(w, http.StatusInternalServerError, "internal", "服务端内部错误")
		return
	}
	if err := s.store.Audit(r.Context(), u.ID, deviceID, "auth.token", s.nowUnix()); err != nil {
		s.logErr("写审计失败", err)
	}

	resp := authTokenResponse{Token: crypto.B64(token), DeviceID: deviceID}
	resp.PWSalt = b64Ptr(u.PWSalt)
	resp.WrappedKey = b64Ptr(u.WrappedKey)
	writeJSON(w, http.StatusOK, resp)
}

// handleSetPassword 写入主密码包裹（需鉴权）。
//
// 校验：pw_salt 解码后必须 16B；wrapped_key 必须是自包含布局，长度 ≤ 80B。
// 服务端只存密文，无法解出 master_key。
func (s *Server) handleSetPassword(w http.ResponseWriter, r *http.Request, dev *store.Device) {
	var req passwordRequest
	if err := readJSON(w, r, &req); err != nil {
		writeReadError(w, err)
		return
	}
	pwSalt, err := parseFixedB64("pw_salt", req.PWSalt, crypto.PWSaltLen)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_pw_salt", err.Error())
		return
	}
	wrappedKey, err := crypto.ParseB64(req.WrappedKey)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_wrapped_key", "wrapped_key 不是合法的 base64url")
		return
	}
	if len(wrappedKey) <= crypto.NonceLen+crypto.TagLen || len(wrappedKey) > policy.MaxWrappedKeyBytes {
		writeErr(w, http.StatusBadRequest, "invalid_wrapped_key",
			"wrapped_key 必须是 nonce(12)||ct||tag 自包含布局，长度 ≤ 80 字节")
		return
	}
	if err := s.store.SetPasswordWrap(r.Context(), dev.UserID, wrappedKey, pwSalt); err != nil {
		s.logErr("写入主密码包裹失败", err)
		writeErr(w, http.StatusInternalServerError, "internal", "服务端内部错误")
		return
	}
	if err := s.store.Audit(r.Context(), dev.UserID, dev.ID, "auth.password.set", s.nowUnix()); err != nil {
		s.logErr("写审计失败", err)
	}
	writeJSON(w, http.StatusOK, okResponse{OK: true})
}

// handleDeletePassword 清空主密码包裹（需鉴权，必须显式确认）。
func (s *Server) handleDeletePassword(w http.ResponseWriter, r *http.Request, dev *store.Device) {
	var req passwordDeleteRequest
	if err := readJSON(w, r, &req); err != nil {
		writeReadError(w, err)
		return
	}
	if req.Confirm != removePasswordConfirm {
		writeErr(w, http.StatusBadRequest, "invalid_confirm",
			"必须回传 {\"confirm\":\"remove-master-password\"} 才能删除主密码包裹")
		return
	}
	if err := s.store.ClearPasswordWrap(r.Context(), dev.UserID); err != nil {
		s.logErr("清空主密码包裹失败", err)
		writeErr(w, http.StatusInternalServerError, "internal", "服务端内部错误")
		return
	}
	if err := s.store.Audit(r.Context(), dev.UserID, dev.ID, "auth.password.clear", s.nowUnix()); err != nil {
		s.logErr("写审计失败", err)
	}
	writeJSON(w, http.StatusOK, okResponse{OK: true})
}

// validateText 校验必填文本字段的长度。
func validateText(field, v string, maxBytes int) error {
	if strings.TrimSpace(v) == "" {
		return fmt.Errorf("%s 不能为空", field)
	}
	if len(v) > maxBytes {
		return fmt.Errorf("%s 超过 %d 字节", field, maxBytes)
	}
	return nil
}

// parseFixedB64 解析 base64url 并校验解码后的固定长度。
func parseFixedB64(field, v string, n int) ([]byte, error) {
	b, err := crypto.ParseB64(v)
	if err != nil {
		return nil, fmt.Errorf("%s 不是合法的 base64url", field)
	}
	if len(b) != n {
		return nil, fmt.Errorf("%s 必须解码为 %d 字节", field, n)
	}
	return b, nil
}
