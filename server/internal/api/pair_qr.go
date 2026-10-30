package api

import (
	"net/http"

	qrcode "github.com/skip2/go-qrcode"
)

// 同步配置深链与二维码参数。
const (
	// deepLinkConfigPrefix 是 App「同步配置」深链前缀：后面只拼服务器地址，
	// 绝不附加任何配对码、master_key 或 token。
	deepLinkConfigPrefix = "vkey://config?server="
	// qrPNGSize 是二维码 PNG 的边长（像素）。
	qrPNGSize = 512
)

// qrLevel 是二维码纠错等级（M 级兼顾容错与密度）。
const qrLevel = qrcode.Medium

// pairDeepLink 由服务器地址构造同步配置深链。
//
// 参数：serverURL 为 serverURL(r) 的结果，已经过 sanitizeHost 字符白名单过滤，
// 只含字母/数字/`.`/`-`/`:`/`[`/`]` 与 scheme，不含 `&`、`=`、`#`、空格等会改变
// 查询语义的字符。
// 返回：形如 `vkey://config?server=https://example.com` 的深链；内容仅地址，
// 页面展示的可复制文本与二维码内容完全一致，便于手动输入。
func pairDeepLink(serverURL string) string {
	return deepLinkConfigPrefix + serverURL
}

// handlePairQR 输出同步配置深链的二维码 PNG（零知识：只编码服务器地址）。
func (s *Server) handlePairQR(w http.ResponseWriter, r *http.Request) {
	png, err := qrcode.Encode(pairDeepLink(s.serverURL(r)), qrLevel, qrPNGSize)
	if err != nil {
		s.logErr("生成同步配置二维码失败", err)
		writeError(w, r, http.StatusInternalServerError, "internal")
		return
	}
	// 地址随 Host/--domain 变化，禁止缓存，避免换域名后仍扫到旧地址。
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(png)
}
