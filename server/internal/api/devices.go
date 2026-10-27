package api

import (
	"errors"
	"net/http"

	"xiaoqiong0v0.cn/vkey/server/internal/policy"
	"xiaoqiong0v0.cn/vkey/server/internal/store"
)

// deviceRegisterRequest 是 POST /api/v1/devices/register 的请求体。
type deviceRegisterRequest struct {
	Name     string `json:"name"`
	Platform string `json:"platform"`
	PubKey   string `json:"pubkey"`
}

// deviceRegisterResponse 是 POST /api/v1/devices/register 的响应体。
type deviceRegisterResponse struct {
	DeviceID string `json:"device_id"`
}

// deviceRevokeRequest 是 POST /api/v1/devices/revoke 的请求体。
type deviceRevokeRequest struct {
	DeviceID string `json:"device_id"`
}

// handleDeviceRegister 预注册设备公钥（需鉴权）。
//
// 说明：该端点只登记公钥，不签发 token；新设备仍需用 verifier 调用
// POST /api/v1/auth/token 才能拿到 token（见 shared/protocol.md）。
func (s *Server) handleDeviceRegister(w http.ResponseWriter, r *http.Request, dev *store.Device) {
	var req deviceRegisterRequest
	if err := readJSON(w, r, &req); err != nil {
		writeReadError(w, err)
		return
	}
	pubkey, err := parseFixedB64("pubkey", req.PubKey, 32)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_pubkey", err.Error())
		return
	}
	if err := validateText("name", req.Name, policy.MaxDeviceNameBytes); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_device", err.Error())
		return
	}
	if err := validateText("platform", req.Platform, policy.MaxPlatformBytes); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_device", err.Error())
		return
	}
	deviceID, err := s.store.CreateDevice(r.Context(), dev.UserID, req.Name, req.Platform, pubkey, nil, s.nowUnix())
	if err != nil {
		s.logErr("注册设备失败", err)
		writeErr(w, http.StatusInternalServerError, "internal", "服务端内部错误")
		return
	}
	if err := s.store.Audit(r.Context(), dev.UserID, dev.ID, "device.register", s.nowUnix()); err != nil {
		s.logErr("写审计失败", err)
	}
	writeJSON(w, http.StatusOK, deviceRegisterResponse{DeviceID: deviceID})
}

// handleDeviceRevoke 吊销设备并清空其 token（需鉴权）。
func (s *Server) handleDeviceRevoke(w http.ResponseWriter, r *http.Request, dev *store.Device) {
	var req deviceRevokeRequest
	if err := readJSON(w, r, &req); err != nil {
		writeReadError(w, err)
		return
	}
	if err := validateText("device_id", req.DeviceID, 128); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_device", err.Error())
		return
	}
	err := s.store.RevokeDevice(r.Context(), dev.UserID, req.DeviceID, s.nowUnix())
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "device_not_found", "设备不存在或已吊销")
		return
	}
	if err != nil {
		s.logErr("吊销设备失败", err)
		writeErr(w, http.StatusInternalServerError, "internal", "服务端内部错误")
		return
	}
	if err := s.store.Audit(r.Context(), dev.UserID, dev.ID, "device.revoke", s.nowUnix()); err != nil {
		s.logErr("写审计失败", err)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
