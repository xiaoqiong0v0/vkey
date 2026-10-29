// Package policy 集中定义协议层面的固定参数与服务端策略视图。
//
// 可变策略为：是否强制主密码、用户模式（single/admin）与每用户配额
// （三项配额都有默认值，可由 `vkeyd policy set` 覆盖）；其余参数（KDF 参数、
// 超时、上限）是协议常量，编译期固定，客户端不得依赖服务端下发以外的取值。
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

	// EnrollTTLSeconds 是开户码默认有效期（30 分钟）。
	EnrollTTLSeconds = 1800
	// DefaultMaxItemsPerUser 是每用户活跃条目数默认配额。
	DefaultMaxItemsPerUser = 1000
	// DefaultMaxBytesPerUser 是每用户密文字节合计默认配额（20 MiB）。
	DefaultMaxBytesPerUser = 20 << 20
	// DefaultMaxDevicesPerUser 是每用户未吊销设备数默认配额。
	DefaultMaxDevicesPerUser = 10
)

// 用户模式取值（存于 meta 表，见 store.UserMode）。
const (
	// UserModeSingle 是单账号模式：无自助注册，行为与 M1 完全一致（默认）。
	UserModeSingle = "single"
	// UserModeAdmin 是多用户模式：只能由管理员用 CLI 开户（一次性开户码）。
	UserModeAdmin = "admin"
)

// 开户码展示格式常量：`ENROLL-XXXX-XXXX`，XXXX 取自去混淆字母表
//（剔除易混字符 I/O/0/1），共 32 个字符、8 位随机。
const (
	// EnrollCodePrefix 是开户码固定前缀。
	EnrollCodePrefix = "ENROLL"
	// EnrollCodeGroupSize 是开户码随机段的分组大小与组数（2 组）。
	EnrollCodeGroupSize = 4
	// EnrollCodeGroups 是开户码随机段组数。
	EnrollCodeGroups = 2
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
