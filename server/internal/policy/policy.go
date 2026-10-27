// Package policy 集中定义协议层面的固定参数与服务端策略视图。
//
// 服务端策略只有一项可变值（是否强制主密码），其余参数（KDF 参数、超时、
// 上限）都是协议常量，编译期固定，客户端不得依赖服务端下发以外的取值。
package policy

import (
	"xiaoqiong0v0.cn/vkey/server/internal/crypto"
)

// 协议常量。
const (
	// PairTTLSeconds 是配对码有效期（10 分钟）。
	PairTTLSeconds = 600
	// ClockSkewSeconds 是请求时间戳允许的最大偏移（±120 秒）。
	ClockSkewSeconds = 120
	// MaxItemCiphertextBytes 是单条密文上限（8 KiB，解码后字节数）。
	MaxItemCiphertextBytes = 8192
	// MaxItemsPerRequest 是单次 POST /items 的条目上限。
	MaxItemsPerRequest = 500
	// MaxItemsPage 是单次 GET /items 的返回上限。
	MaxItemsPage = 1000
	// MaxRequestBodyBytes 是任意 API 请求体上限（8 MiB）。
	MaxRequestBodyBytes = 8 << 20
	// MaxItemIDBytes 是条目 id 的长度上限。
	MaxItemIDBytes = 128
	// MaxRPIDBytes 是 rp_id 的长度上限。
	MaxRPIDBytes = 255
	// MaxPairBlobBytes 是配对 blob 的长度上限。
	MaxPairBlobBytes = 4096
	// MaxWrappedKeyBytes 是主密码包裹 master_key 的长度上限（nonce||ct||tag）。
	MaxWrappedKeyBytes = 80
	// MaxDeviceNameBytes 是设备名长度上限。
	MaxDeviceNameBytes = 128
	// MaxPlatformBytes 是平台标识长度上限。
	MaxPlatformBytes = 32
	// MaxUsernameBytes 是账号名长度上限。
	MaxUsernameBytes = 128
)

// KDF 是下发给客户端的 Argon2id 参数。
type KDF struct {
	M int `json:"m"` // 内存开销，KiB
	T int `json:"t"` // 迭代次数
	P int `json:"p"` // 并行度
}

// KDFParams 返回协议固定的 Argon2id 参数。
func KDFParams() KDF {
	return KDF{M: crypto.Argon2MemoryKiB, T: crypto.Argon2Time, P: crypto.Argon2Threads}
}
