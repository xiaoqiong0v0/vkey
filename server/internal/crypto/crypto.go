// Package crypto 实现 vkey 协议中的全部密码学原语与编码规则。
//
// 本包是 shared/protocol.md 的 Go 参考实现：客户端（Rust/Android）与服务端必须
// 逐字节一致。所有导出函数均给出明确的输入输出编码说明。
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	// KeyLen 是对称密钥（master_key / verifier / item_key / KEK）的字节长度。
	KeyLen = 32
	// NonceLen 是 AES-256-GCM 的 nonce 字节长度。
	NonceLen = 12
	// TagLen 是 AES-256-GCM 认证标签的字节长度。
	TagLen = 16
	// TokenLen 是设备 token 的随机字节长度。
	TokenLen = 32
	// PairCodeLen 是配对码的随机字节长度。
	PairCodeLen = 32
	// PW盐长度。
	PWSaltLen = 16

	// Argon2MemoryKiB 是主密码 KEK 的 Argon2id 内存开销（KiB）。
	Argon2MemoryKiB = 65536
	// Argon2Time 是 Argon2id 迭代次数。
	Argon2Time = 3
	// Argon2Threads 是 Argon2id 并行度。
	Argon2Threads = 1

	// SaltVerifier 是 verifier 的 HKDF salt（UTF-8 字节）。
	SaltVerifier = "vkey-verifier"
	// SaltItem 是 item_key 的 HKDF salt（UTF-8 字节）。
	SaltItem = "vkey-item"
	// SaltPair 是配对 KEK 的 HKDF salt（UTF-8 字节）。
	SaltPair = "vkey-pair"
	// AADItemPrefix 是条目 AEAD 的 AAD 前缀，其后直接拼接 item_id。
	AADItemPrefix = "vkey-item|"
)

// b64 是协议规定的二进制字段编码：base64url 无填充。
var b64 = base64.RawURLEncoding

// b32 是协议规定的展示编码：base32 大写、无填充。
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// ErrBadLength 表示某个定长输入的字节数不符合协议。
var ErrBadLength = errors.New("crypto: 输入长度不符合协议")

// errDecode 表示编码解析失败；对外统一包装为 ErrBadEncoding。
var errDecode = errors.New("crypto: 编码解析失败")

// ErrBadEncoding 表示 base64url / base32 解析失败。
var ErrBadEncoding = errors.New("crypto: 编码非法")

// ---------------------------------------------------------------------------
// 派生
// ---------------------------------------------------------------------------

// hkdfKey 用 HKDF-SHA256 派生 n 字节密钥。
//
// 参数：ikm 为输入密钥材料；saltUTF8 为 HKDF salt 的 UTF-8 字节；info 为 info
// 的 UTF-8 字节（调用方已转义）；n 为输出长度。
// 返回：派生结果；长度非法或读取失败时返回错误。
func hkdfKey(ikm, saltUTF8 []byte, info string, n int) ([]byte, error) {
	if n <= 0 {
		return nil, ErrBadLength
	}
	out := make([]byte, n)
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, saltUTF8, []byte(info)), out); err != nil {
		return nil, fmt.Errorf("crypto: hkdf 派生失败: %w", err)
	}
	return out, nil
}

// Verifier 计算登录校验值：HKDF-SHA256(ikm=masterKey, salt=UTF8("vkey-verifier"),
// info=UTF8(username), len=32)。
//
// 参数：masterKey 必须是 32 字节；username 为账号名（原样 UTF-8）。
// 返回：32 字节 verifier；masterKey 长度非法时返回错误。
func Verifier(masterKey []byte, username string) ([]byte, error) {
	if len(masterKey) != KeyLen {
		return nil, fmt.Errorf("%w: master_key 必须 32 字节", ErrBadLength)
	}
	return hkdfKey(masterKey, []byte(SaltVerifier), username, KeyLen)
}

// ItemKey 计算条目密钥：HKDF-SHA256(ikm=masterKey, salt=UTF8("vkey-item"),
// info=UTF8(itemID), len=32)。
//
// 参数：masterKey 必须是 32 字节；itemID 为条目 id（原样 UTF-8）。
// 返回：32 字节 item_key；长度非法时返回错误。
func ItemKey(masterKey []byte, itemID string) ([]byte, error) {
	if len(masterKey) != KeyLen {
		return nil, fmt.Errorf("%w: master_key 必须 32 字节", ErrBadLength)
	}
	if itemID == "" {
		return nil, fmt.Errorf("%w: item_id 不能为空", ErrBadLength)
	}
	return hkdfKey(masterKey, []byte(SaltItem), itemID, KeyLen)
}

// PairKEK 计算配对密钥：HKDF-SHA256(ikm=codeBytes, salt=UTF8("vkey-pair"),
// info=UTF8(codeID), len=32)。
//
// 参数：codeBytes 是配对码原始 32 字节；codeID 为客户端生成的配对会话 id。
// 返回：32 字节 KEK；长度非法时返回错误。
func PairKEK(codeBytes []byte, codeID string) ([]byte, error) {
	if len(codeBytes) != PairCodeLen {
		return nil, fmt.Errorf("%w: 配对码必须 32 字节", ErrBadLength)
	}
	if codeID == "" {
		return nil, fmt.Errorf("%w: code_id 不能为空", ErrBadLength)
	}
	return hkdfKey(codeBytes, []byte(SaltPair), codeID, KeyLen)
}

// DeriveKEK 用 Argon2id 从主密码派生 KEK。
//
// 参数：password 为主密码原样 UTF-8；salt 必须是 16 字节随机值。
// 返回：32 字节 KEK；salt 长度非法时 panic（调用方必须先行校验）。
func DeriveKEK(password string, salt []byte) []byte {
	if len(salt) != PWSaltLen {
		panic(fmt.Sprintf("crypto: Argon2 salt 必须 %d 字节", PWSaltLen))
	}
	return argon2.IDKey([]byte(password), salt, Argon2Time, Argon2MemoryKiB, Argon2Threads, KeyLen)
}

// ---------------------------------------------------------------------------
// AEAD
// ---------------------------------------------------------------------------

// Seal 用 AES-256-GCM 加密，返回「密文 ‖ 16 字节 tag」（与 Go 标准库语义一致）。
//
// 参数：key 必须 32 字节；nonce 必须 12 字节；aad 为附加认证数据（可为 nil）。
func Seal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	aead, err := newGCM(key, nonce)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// Open 解密由 Seal 产生的密文（含 tag），校验失败返回错误。
//
// 参数：key 必须 32 字节；nonce 必须 12 字节；aad 必须与加密时一致。
func Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := newGCM(key, nonce)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("crypto: AEAD 解密失败: %w", err)
	}
	return pt, nil
}

// newGCM 构造 AES-256-GCM，并校验密钥与 nonce 长度。
func newGCM(key, nonce []byte) (cipher.AEAD, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("%w: key 必须 32 字节", ErrBadLength)
	}
	if len(nonce) != NonceLen {
		return nil, fmt.Errorf("%w: nonce 必须 12 字节", ErrBadLength)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: 构造 AES 失败: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: 构造 GCM 失败: %w", err)
	}
	return aead, nil
}

// SealSelfContained 用随机 nonce 加密，返回 nonce(12B) || 密文||tag 的自包含布局。
//
// wrapped_key 与配对 blob 使用该布局（协议中这两项没有独立的 nonce 字段）。
func SealSelfContained(key, plaintext, aad []byte) ([]byte, error) {
	nonce, err := NewNonce()
	if err != nil {
		return nil, err
	}
	return SealSelfContainedWithNonce(key, nonce, plaintext, aad)
}

// SealSelfContainedWithNonce 与 SealSelfContained 相同，但使用调用方指定的 nonce。
func SealSelfContainedWithNonce(key, nonce, plaintext, aad []byte) ([]byte, error) {
	ct, err := Seal(key, nonce, plaintext, aad)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// OpenSelfContained 解密 nonce(12B) || 密文||tag 的自包含布局。
func OpenSelfContained(key, blob, aad []byte) ([]byte, error) {
	if len(blob) < NonceLen+16 {
		return nil, fmt.Errorf("%w: 自包含密文过短", ErrBadLength)
	}
	return Open(key, blob[:NonceLen], blob[NonceLen:], aad)
}

// ItemAAD 返回条目 AEAD 的附加认证数据：UTF8("vkey-item|"+itemID)。
func ItemAAD(itemID string) []byte { return []byte(AADItemPrefix + itemID) }

// SealItem 用 master_key 派生 item_key 后加密条目明文。
//
// 参数：nonce 必须 12 字节；返回 base64url 前的原始密文字节。
func SealItem(masterKey []byte, itemID string, plaintext, nonce []byte) ([]byte, error) {
	key, err := ItemKey(masterKey, itemID)
	if err != nil {
		return nil, err
	}
	return Seal(key, nonce, plaintext, ItemAAD(itemID))
}

// OpenItem 用 master_key 派生 item_key 后解密条目密文。
func OpenItem(masterKey []byte, itemID string, ciphertext, nonce []byte) ([]byte, error) {
	key, err := ItemKey(masterKey, itemID)
	if err != nil {
		return nil, err
	}
	return Open(key, nonce, ciphertext, ItemAAD(itemID))
}

// ---------------------------------------------------------------------------
// 签名串 / 设备签名
// ---------------------------------------------------------------------------

// SigningString 构造请求签名串，精确格式为：
//
//	METHOD + "\n" + RequestURI + "\n" + hex(sha256(body)) + "\n" + ts
//
// 参数：requestURI 必须是原始 RequestURI（含 query，不含 scheme/host）；
// body 为原始请求体（GET 空 body 传 nil，等价 sha256("")）。
func SigningString(method, requestURI string, body []byte, ts int64) string {
	sum := sha256.Sum256(body)
	return method + "\n" + requestURI + "\n" + hex.EncodeToString(sum[:]) + "\n" + strconv.FormatInt(ts, 10)
}

// Sign 用设备 Ed25519 私钥对签名串签名，返回 64 字节原始签名。
func Sign(priv ed25519.PrivateKey, method, requestURI string, body []byte, ts int64) []byte {
	return ed25519.Sign(priv, []byte(SigningString(method, requestURI, body, ts)))
}

// Verify 校验设备 Ed25519 签名。
func Verify(pub ed25519.PublicKey, method, requestURI string, body []byte, ts int64, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, []byte(SigningString(method, requestURI, body, ts)), sig)
}

// ---------------------------------------------------------------------------
// 哈希 / 定长比较
// ---------------------------------------------------------------------------

// SHA256 返回输入数据的 SHA-256 摘要。
func SHA256(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// TokenHash 返回设备 token 的服务端存储形式（SHA-256）。
func TokenHash(token []byte) []byte { return SHA256(token) }

// PairCodeHash 返回配对码原始字节的服务端存储形式（SHA-256）。
func PairCodeHash(codeBytes []byte) []byte { return SHA256(codeBytes) }

// Equal 做常量时间比较：先各自 SHA-256 再比较，避免长度差异带来的时序泄漏。
func Equal(a, b []byte) bool {
	ha, hb := sha256.Sum256(a), sha256.Sum256(b)
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

// ---------------------------------------------------------------------------
// 随机数
// ---------------------------------------------------------------------------

// Random 返回 n 字节密码学随机数。
func Random(n int) ([]byte, error) {
	if n <= 0 {
		return nil, ErrBadLength
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("crypto: 读取随机数失败: %w", err)
	}
	return b, nil
}

// NewToken 生成 32 字节设备 token。
func NewToken() ([]byte, error) { return Random(TokenLen) }

// NewPairCode 生成 32 字节配对码原始值。
func NewPairCode() ([]byte, error) { return Random(PairCodeLen) }

// NewNonce 生成 12 字节 AEAD nonce。
func NewNonce() ([]byte, error) { return Random(NonceLen) }

// ---------------------------------------------------------------------------
// 编码
// ---------------------------------------------------------------------------

// B64 编码为 base64url 无填充（协议中所有二进制字段的线上形式）。
func B64(b []byte) string { return b64.EncodeToString(b) }

// ParseB64 解析 base64url（必须无填充；容忍首尾空白）。
func ParseB64(s string) ([]byte, error) {
	b, err := b64.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadEncoding, err)
	}
	return b, nil
}

// Base32Upper 编码为 base32 大写无填充（master_key / 配对码的展示形式）。
func Base32Upper(b []byte) string { return b32.EncodeToString(b) }

// ParseBase32 解析 base32，容忍小写、'-'、空格与 '=' 填充。
//
// 该函数用于用户手工输入的 master_key 与配对码。
func ParseBase32(s string) ([]byte, error) {
	clean := strings.ToUpper(strings.TrimSpace(s))
	clean = strings.NewReplacer("-", "", " ", "", "\t", "", "\n", "", "\r", "", "=", "").Replace(clean)
	if clean == "" {
		return nil, fmt.Errorf("%w: 输入为空", ErrBadEncoding)
	}
	b, err := b32.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadEncoding, err)
	}
	return b, nil
}

// FormatPairCode 把 32 字节配对码格式化为人类可读形式：base32 大写无填充，
// 每 4 个字符用 '-' 连接。
func FormatPairCode(code []byte) string {
	s := Base32Upper(code)
	var sb strings.Builder
	for i := 0; i < len(s); i += 4 {
		if i > 0 {
			sb.WriteByte('-')
		}
		end := i + 4
		if end > len(s) {
			end = len(s)
		}
		sb.WriteString(s[i:end])
	}
	return sb.String()
}

// ParsePairCode 解析人工输入的配对码，返回 32 字节原始值。
//
// 容忍 FormatPairCode 的分组形式，也容忍纯 base32 形式。
func ParsePairCode(s string) ([]byte, error) {
	b, err := ParseBase32(s)
	if err != nil {
		return nil, err
	}
	if len(b) != PairCodeLen {
		return nil, fmt.Errorf("%w: 配对码必须 32 字节", ErrBadLength)
	}
	return b, nil
}

// ParseMasterKey 解析 base32 形式的 master_key，必须是 32 字节。
func ParseMasterKey(s string) ([]byte, error) {
	b, err := ParseBase32(s)
	if err != nil {
		return nil, err
	}
	if len(b) != KeyLen {
		return nil, fmt.Errorf("%w: master_key 必须 32 字节", ErrBadLength)
	}
	return b, nil
}

// Hex 返回小写十六进制编码。
func Hex(b []byte) string { return hex.EncodeToString(b) }

// ParseHex 解析十六进制串（仅用于测试向量与调试输出）。
func ParseHex(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadEncoding, err)
	}
	return b, nil
}
