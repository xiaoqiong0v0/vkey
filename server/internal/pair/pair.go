// Package pair 实现配对码的生成、规范化、哈希与参考 blob 封装。
//
// 配对码是 32 字节随机值：线上传输用 base32 大写无填充，人工输入/展示时按
// 每 4 字符用 '-' 分组。服务端只保存 SHA256(配对码原始字节)。
package pair

import (
	"errors"
	"fmt"

	"xiaoqiong0v0.cn/vkey/server/internal/crypto"
)

// ErrBadCode 表示配对码无法解析或长度不符。
var ErrBadCode = errors.New("pair: 配对码非法")

// NewCode 生成新的配对码，返回原始字节与规范化（base32 无填充）字符串。
//
// 客户端与服务端共用该实现；正常流程由客户端生成后连同 blob 上传。
func NewCode() ([]byte, string, error) {
	code, err := crypto.NewPairCode()
	if err != nil {
		return nil, "", err
	}
	return code, crypto.Base32Upper(code), nil
}

// Normalize 解析用户或客户端提交的配对码，返回原始字节与规范字符串。
//
// 容忍小写、'-'、空格与 '=' 填充；长度必须是 32 字节。
func Normalize(raw string) ([]byte, string, error) {
	code, err := crypto.ParsePairCode(raw)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrBadCode, err)
	}
	return code, crypto.Base32Upper(code), nil
}

// Display 返回人类可读的配对码（每 4 字符以 '-' 分隔）。
func Display(code []byte) string { return crypto.FormatPairCode(code) }

// Hash 返回服务端保存的 code_hash = SHA256(配对码原始 32 字节)。
func Hash(code []byte) []byte { return crypto.PairCodeHash(code) }

// SealBlob 用配对码派生的 KEK 封装 master_key（随机 nonce）。
//
// 线上布局：blob = nonce(12B) || AES-256-GCM(密文||tag)，无 AAD。
func SealBlob(code []byte, codeID string, masterKey []byte) ([]byte, error) {
	kek, err := crypto.PairKEK(code, codeID)
	if err != nil {
		return nil, err
	}
	return crypto.SealSelfContained(kek, masterKey, nil)
}

// SealBlobWithNonce 与 SealBlob 相同，但使用调用方指定的 nonce（测试向量用）。
func SealBlobWithNonce(code []byte, codeID string, masterKey, nonce []byte) ([]byte, error) {
	kek, err := crypto.PairKEK(code, codeID)
	if err != nil {
		return nil, err
	}
	return crypto.SealSelfContainedWithNonce(kek, nonce, masterKey, nil)
}

// OpenBlob 用配对码解出 master_key。
//
// 参数：blob 必须是 nonce(12B) || 密文||tag 的自包含布局。
func OpenBlob(code []byte, codeID string, blob []byte) ([]byte, error) {
	kek, err := crypto.PairKEK(code, codeID)
	if err != nil {
		return nil, err
	}
	return crypto.OpenSelfContained(kek, blob, nil)
}
