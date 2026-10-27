// Command genvectors 生成 shared/vectors/ 下的协议测试向量。
//
// 用法（在 server/ 目录下）：
//
//	go run ./cmd/genvectors                 # 写入 ../shared/vectors
//	go run ./cmd/genvectors -out <dir>      # 写入指定目录
//
// 生成器的全部输入都是固定字节，输出可复现；任何一端实现都必须逐字节匹配。
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"xiaoqiong0v0.cn/vkey/server/internal/crypto"
	"xiaoqiong0v0.cn/vkey/server/internal/pair"
)

// 固定测试输入。
var (
	masterKey = func() []byte { return seq(0x00, 32) }()
	pwSalt    = func() []byte { return repeat(0x10, 16) }()
	itemNonce = func() []byte { return seq(0x20, 12) }()
	wrapNonce = func() []byte { return seq(0x30, 12) }()
	pairNonce = func() []byte { return seq(0x60, 12) }()
	pairCode  = func() []byte { return seq(0x40, 32) }()
	keySeed   = func() []byte { return seq(0x70, 32) }()
)

const (
	username     = "default"
	itemID       = "01J9Z6Q3R8T5V7X9Y2B4C6D8E0"
	codeID       = "pair-20261026-demo"
	password     = "correct horse battery staple"
	itemPlain    = `{"kind":"totp","label":"demo@example.com","issuer":"Example","secret":"JBSWY3DPEHPK3PXP","algorithm":"SHA1","digits":6,"period":30}`
	itemsBody    = `{"items":[]}`
	pairBody     = `{"code":"ABCD-EFGH","name":"phone","platform":"android","pubkey":"AAAA"}`
	fixedTS      = int64(1761436800)
	fixedTSLater = int64(1761436900)
)

// vector 是单条测试向量。
type vector struct {
	Name     string         `json:"name"`
	Inputs   map[string]any `json:"inputs"`
	Expected map[string]any `json:"expected"`
}

// vectorFile 是单个向量文件的顶层结构。
type vectorFile struct {
	GeneratedBy string   `json:"generated_by"`
	Vectors     []vector `json:"vectors"`
}

// main 生成功三组向量文件。
func main() {
	out := flag.String("out", filepath.Join("..", "shared", "vectors"), "输出目录")
	flag.Parse()

	if err := os.MkdirAll(*out, 0o755); err != nil {
		fail("创建输出目录失败: %v", err)
	}
	writeJSON(filepath.Join(*out, "kdf.json"), kdfVectors())
	writeJSON(filepath.Join(*out, "aead.json"), aeadVectors())
	writeJSON(filepath.Join(*out, "signing.json"), signingVectors())
	writeJSON(filepath.Join(*out, "encoding.json"), encodingVectors())
	fmt.Fprintf(os.Stderr, "已生成 4 个向量文件到 %s\n", *out)
}

// kdfVectors 生成 KDF 派生向量。
func kdfVectors() vectorFile {
	verifier, err := crypto.Verifier(masterKey, username)
	check(err)
	itemKey, err := crypto.ItemKey(masterKey, itemID)
	check(err)
	kek, err := crypto.PairKEK(pairCode, codeID)
	check(err)
	argonKEK := crypto.DeriveKEK(password, pwSalt)

	return vectorFile{
		GeneratedBy: "server/cmd/genvectors",
		Vectors: []vector{
			{
				Name:     "verifier",
				Inputs:   map[string]any{"master_key_hex": crypto.Hex(masterKey), "username": username},
				Expected: map[string]any{"verifier_b64url": crypto.B64(verifier)},
			},
			{
				Name:     "item_key",
				Inputs:   map[string]any{"master_key_hex": crypto.Hex(masterKey), "item_id": itemID},
				Expected: map[string]any{"item_key_b64url": crypto.B64(itemKey)},
			},
			{
				Name:     "pair_kek",
				Inputs:   map[string]any{"code_hex": crypto.Hex(pairCode), "code_id": codeID},
				Expected: map[string]any{"kek_b64url": crypto.B64(kek)},
			},
			{
				Name: "argon2id_kek",
				Inputs: map[string]any{
					"password": password, "pw_salt_hex": crypto.Hex(pwSalt),
					"m": crypto.Argon2MemoryKiB, "t": crypto.Argon2Time, "p": crypto.Argon2Threads,
				},
				Expected: map[string]any{"kek_b64url": crypto.B64(argonKEK)},
			},
		},
	}
}

// aeadVectors 生成 AEAD 封装向量。
func aeadVectors() vectorFile {
	itemCT, err := crypto.SealItem(masterKey, itemID, []byte(itemPlain), itemNonce)
	check(err)
	argonKEK := crypto.DeriveKEK(password, pwSalt)
	wrapped, err := crypto.SealSelfContainedWithNonce(argonKEK, wrapNonce, masterKey, nil)
	check(err)
	blob, err := pair.SealBlobWithNonce(pairCode, codeID, masterKey, pairNonce)
	check(err)

	return vectorFile{
		GeneratedBy: "server/cmd/genvectors",
		Vectors: []vector{
			{
				Name: "item_ciphertext",
				Inputs: map[string]any{
					"master_key_hex": crypto.Hex(masterKey),
					"item_id":        itemID,
					"nonce_hex":      crypto.Hex(itemNonce),
					"plaintext_utf8": itemPlain,
					"aad_utf8":       string(crypto.ItemAAD(itemID)),
				},
				Expected: map[string]any{"ciphertext_b64url": crypto.B64(itemCT)},
			},
			{
				Name: "wrapped_key",
				Inputs: map[string]any{
					"password": password, "pw_salt_hex": crypto.Hex(pwSalt),
					"master_key_hex": crypto.Hex(masterKey),
					"nonce_hex":      crypto.Hex(wrapNonce),
					"layout":         "nonce(12) || ciphertext || tag",
				},
				Expected: map[string]any{"wrapped_key_b64url": crypto.B64(wrapped)},
			},
			{
				Name: "pair_blob",
				Inputs: map[string]any{
					"code_hex":       crypto.Hex(pairCode),
					"code_id":        codeID,
					"master_key_hex": crypto.Hex(masterKey),
					"nonce_hex":      crypto.Hex(pairNonce),
					"layout":         "nonce(12) || ciphertext || tag",
				},
				Expected: map[string]any{"blob_b64url": crypto.B64(blob)},
			},
		},
	}
}

// signingVectors 生成签名串与 Ed25519 签名向量。
func signingVectors() vectorFile {
	priv := ed25519.NewKeyFromSeed(keySeed)
	pub := priv.Public().(ed25519.PublicKey)

	cases := []struct {
		name   string
		method string
		uri    string
		body   string
		ts     int64
	}{
		{"get_items_since", "GET", "/api/v1/items?since=42", "", fixedTS},
		{"post_items", "POST", "/api/v1/items", itemsBody, fixedTS},
		{"post_pair_claim", "POST", "/api/v1/pair/claim", pairBody, fixedTSLater},
	}

	vectors := make([]vector, 0, len(cases))
	for _, c := range cases {
		sig := crypto.Sign(priv, c.method, c.uri, []byte(c.body), c.ts)
		vectors = append(vectors, vector{
			Name: c.name,
			Inputs: map[string]any{
				"method":              c.method,
				"request_uri":         c.uri,
				"body_utf8":           c.body,
				"ts":                  c.ts,
				"device_key_seed_hex": crypto.Hex(keySeed),
			},
			Expected: map[string]any{
				"body_sha256_hex":      crypto.Hex(crypto.SHA256([]byte(c.body))),
				"signing_string_utf8":  crypto.SigningString(c.method, c.uri, []byte(c.body), c.ts),
				"signature_b64url":     crypto.B64(sig),
				"device_pubkey_b64url": crypto.B64(pub),
			},
		})
	}
	return vectorFile{GeneratedBy: "server/cmd/genvectors", Vectors: vectors}
}

// encodingVectors 生成编码向量（base32 / base64url / 展示分组）。
func encodingVectors() vectorFile {
	return vectorFile{
		GeneratedBy: "server/cmd/genvectors",
		Vectors: []vector{
			{
				Name:     "master_key_encoding",
				Inputs:   map[string]any{"master_key_hex": crypto.Hex(masterKey)},
				Expected: map[string]any{"b32_nopad_upper": crypto.Base32Upper(masterKey), "b64url": crypto.B64(masterKey)},
			},
			{
				Name:   "pair_code_encoding",
				Inputs: map[string]any{"code_hex": crypto.Hex(pairCode)},
				Expected: map[string]any{
					"code_b32_nopad_upper": crypto.Base32Upper(pairCode),
					"code_display":         pair.Display(pairCode),
					"code_hash_hex":        crypto.Hex(pair.Hash(pairCode)),
				},
			},
		},
	}
}

// writeJSON 以固定缩进写出向量文件。
func writeJSON(path string, v vectorFile) {
	b, err := json.MarshalIndent(v, "", "  ")
	check(err)
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o644); err != nil {
		fail("写入 %s 失败: %v", path, err)
	}
}

// seq 生成从 start 开始的 n 个连续字节。
func seq(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

// repeat 生成 n 个相同字节。
func repeat(v byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}

// check 在错误时终止生成器。
func check(err error) {
	if err != nil {
		fail("%v", err)
	}
}

// fail 打印错误并以非 0 退出。
func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "genvectors: "+format+"\n", args...)
	os.Exit(1)
}
