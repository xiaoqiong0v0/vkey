package crypto_test

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xiaoqiong0v0.cn/vkey/server/internal/crypto"
)

// rawVector 是向量文件中的一条记录。
type rawVector struct {
	Name     string          `json:"name"`
	Inputs   json.RawMessage `json:"inputs"`
	Expected json.RawMessage `json:"expected"`
}

// vectorFile 是向量文件的顶层结构。
type vectorFile struct {
	GeneratedBy string      `json:"generated_by"`
	Vectors     []rawVector `json:"vectors"`
}

// vectorsDir 从当前包目录向上查找 shared/vectors。
func vectorsDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("获取工作目录失败: %v", err)
	}
	for i := 0; i < 8; i++ {
		cand := filepath.Join(dir, "shared", "vectors")
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			return cand
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("找不到 shared/vectors（从 %s 向上）", dir)
	return ""
}

// loadVectors 读取指定向量文件并按 name 建索引。
func loadVectors(t *testing.T, name string) map[string]rawVector {
	t.Helper()
	path := filepath.Join(vectorsDir(t), name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", path, err)
	}
	var vf vectorFile
	if err := json.Unmarshal(b, &vf); err != nil {
		t.Fatalf("解析 %s 失败: %v", path, err)
	}
	if vf.GeneratedBy == "" || len(vf.Vectors) == 0 {
		t.Fatalf("%s 缺少 generated_by 或 vectors", path)
	}
	out := make(map[string]rawVector, len(vf.Vectors))
	for _, v := range vf.Vectors {
		if _, dup := out[v.Name]; dup {
			t.Fatalf("%s 中向量名重复: %s", path, v.Name)
		}
		out[v.Name] = v
	}
	return out
}

// mustVec 取出指定向量，缺失即失败。
func mustVec(t *testing.T, vars map[string]rawVector, name string) rawVector {
	t.Helper()
	v, ok := vars[name]
	if !ok {
		t.Fatalf("缺少向量 %q", name)
	}
	return v
}

// TestKDFVectors 比对 shared/vectors/kdf.json 的全部派生结果。
func TestKDFVectors(t *testing.T) {
	vars := loadVectors(t, "kdf.json")

	t.Run("verifier", func(t *testing.T) {
		v := mustVec(t, vars, "verifier")
		var in struct {
			MasterKeyHex string `json:"master_key_hex"`
			Username     string `json:"username"`
		}
		var want struct {
			VerifierB64 string `json:"verifier_b64url"`
		}
		decodeBoth(t, v, &in, &want)
		mk, err := crypto.ParseHex(in.MasterKeyHex)
		if err != nil {
			t.Fatal(err)
		}
		got, err := crypto.Verifier(mk, in.Username)
		if err != nil {
			t.Fatalf("Verifier: %v", err)
		}
		if crypto.B64(got) != want.VerifierB64 {
			t.Fatalf("verifier 不匹配:\n got %s\nwant %s", crypto.B64(got), want.VerifierB64)
		}
	})

	t.Run("item_key", func(t *testing.T) {
		v := mustVec(t, vars, "item_key")
		var in struct {
			MasterKeyHex string `json:"master_key_hex"`
			ItemID       string `json:"item_id"`
		}
		var want struct {
			ItemKeyB64 string `json:"item_key_b64url"`
		}
		decodeBoth(t, v, &in, &want)
		mk, err := crypto.ParseHex(in.MasterKeyHex)
		if err != nil {
			t.Fatal(err)
		}
		got, err := crypto.ItemKey(mk, in.ItemID)
		if err != nil {
			t.Fatalf("ItemKey: %v", err)
		}
		if crypto.B64(got) != want.ItemKeyB64 {
			t.Fatalf("item_key 不匹配:\n got %s\nwant %s", crypto.B64(got), want.ItemKeyB64)
		}
	})

	t.Run("pair_kek", func(t *testing.T) {
		v := mustVec(t, vars, "pair_kek")
		var in struct {
			CodeHex string `json:"code_hex"`
			CodeID  string `json:"code_id"`
		}
		var want struct {
			KEKB64 string `json:"kek_b64url"`
		}
		decodeBoth(t, v, &in, &want)
		code, err := crypto.ParseHex(in.CodeHex)
		if err != nil {
			t.Fatal(err)
		}
		got, err := crypto.PairKEK(code, in.CodeID)
		if err != nil {
			t.Fatalf("PairKEK: %v", err)
		}
		if crypto.B64(got) != want.KEKB64 {
			t.Fatalf("pair KEK 不匹配:\n got %s\nwant %s", crypto.B64(got), want.KEKB64)
		}
	})

	t.Run("argon2id_kek", func(t *testing.T) {
		v := mustVec(t, vars, "argon2id_kek")
		var in struct {
			Password  string `json:"password"`
			PWSaltHex string `json:"pw_salt_hex"`
			M         uint32 `json:"m"`
			T         uint32 `json:"t"`
			P         uint8  `json:"p"`
		}
		var want struct {
			KEKB64 string `json:"kek_b64url"`
		}
		decodeBoth(t, v, &in, &want)
		if in.M != crypto.Argon2MemoryKiB || in.T != crypto.Argon2Time || in.P != crypto.Argon2Threads {
			t.Fatalf("向量中的 Argon2 参数 (%d,%d,%d) 与实现 (%d,%d,%d) 不一致",
				in.M, in.T, in.P, crypto.Argon2MemoryKiB, crypto.Argon2Time, crypto.Argon2Threads)
		}
		salt, err := crypto.ParseHex(in.PWSaltHex)
		if err != nil {
			t.Fatal(err)
		}
		got := crypto.DeriveKEK(in.Password, salt)
		if crypto.B64(got) != want.KEKB64 {
			t.Fatalf("argon2id KEK 不匹配:\n got %s\nwant %s", crypto.B64(got), want.KEKB64)
		}
	})
}

// TestAEADVectors 比对 shared/vectors/aead.json 的全部封装结果。
func TestAEADVectors(t *testing.T) {
	vars := loadVectors(t, "aead.json")

	t.Run("item_ciphertext", func(t *testing.T) {
		v := mustVec(t, vars, "item_ciphertext")
		var in struct {
			MasterKeyHex string `json:"master_key_hex"`
			ItemID       string `json:"item_id"`
			NonceHex     string `json:"nonce_hex"`
			Plaintext    string `json:"plaintext_utf8"`
			AAD          string `json:"aad_utf8"`
		}
		var want struct {
			CiphertextB64 string `json:"ciphertext_b64url"`
		}
		decodeBoth(t, v, &in, &want)
		mk, err := crypto.ParseHex(in.MasterKeyHex)
		if err != nil {
			t.Fatal(err)
		}
		nonce, err := crypto.ParseHex(in.NonceHex)
		if err != nil {
			t.Fatal(err)
		}
		if in.AAD != string(crypto.ItemAAD(in.ItemID)) {
			t.Fatalf("AAD 不匹配: got %q want %q", in.AAD, crypto.ItemAAD(in.ItemID))
		}
		ct, err := crypto.SealItem(mk, in.ItemID, []byte(in.Plaintext), nonce)
		if err != nil {
			t.Fatalf("SealItem: %v", err)
		}
		if crypto.B64(ct) != want.CiphertextB64 {
			t.Fatalf("item 密文不匹配:\n got %s\nwant %s", crypto.B64(ct), want.CiphertextB64)
		}
		pt, err := crypto.OpenItem(mk, in.ItemID, ct, nonce)
		if err != nil {
			t.Fatalf("OpenItem: %v", err)
		}
		if string(pt) != in.Plaintext {
			t.Fatalf("解密结果不一致")
		}
		// AAD 交叉校验：换 item_id 必须失败。
		if _, err := crypto.OpenItem(mk, in.ItemID+"x", ct, nonce); err == nil {
			t.Fatal("AAD 不符时 OpenItem 本应失败")
		}
	})

	t.Run("wrapped_key", func(t *testing.T) {
		v := mustVec(t, vars, "wrapped_key")
		var in struct {
			Password     string `json:"password"`
			PWSaltHex    string `json:"pw_salt_hex"`
			MasterKeyHex string `json:"master_key_hex"`
			NonceHex     string `json:"nonce_hex"`
		}
		var want struct {
			WrappedB64 string `json:"wrapped_key_b64url"`
		}
		decodeBoth(t, v, &in, &want)
		salt, err := crypto.ParseHex(in.PWSaltHex)
		if err != nil {
			t.Fatal(err)
		}
		mk, err := crypto.ParseHex(in.MasterKeyHex)
		if err != nil {
			t.Fatal(err)
		}
		nonce, err := crypto.ParseHex(in.NonceHex)
		if err != nil {
			t.Fatal(err)
		}
		kek := crypto.DeriveKEK(in.Password, salt)
		wrapped, err := crypto.SealSelfContainedWithNonce(kek, nonce, mk, nil)
		if err != nil {
			t.Fatalf("SealSelfContainedWithNonce: %v", err)
		}
		if crypto.B64(wrapped) != want.WrappedB64 {
			t.Fatalf("wrapped_key 不匹配:\n got %s\nwant %s", crypto.B64(wrapped), want.WrappedB64)
		}
		got, err := crypto.OpenSelfContained(kek, wrapped, nil)
		if err != nil {
			t.Fatalf("OpenSelfContained: %v", err)
		}
		if crypto.B64(got) != crypto.B64(mk) {
			t.Fatal("解出的 master_key 不一致")
		}
	})

	t.Run("pair_blob", func(t *testing.T) {
		v := mustVec(t, vars, "pair_blob")
		var in struct {
			CodeHex      string `json:"code_hex"`
			CodeID       string `json:"code_id"`
			MasterKeyHex string `json:"master_key_hex"`
			NonceHex     string `json:"nonce_hex"`
		}
		var want struct {
			BlobB64 string `json:"blob_b64url"`
		}
		decodeBoth(t, v, &in, &want)
		code, err := crypto.ParseHex(in.CodeHex)
		if err != nil {
			t.Fatal(err)
		}
		mk, err := crypto.ParseHex(in.MasterKeyHex)
		if err != nil {
			t.Fatal(err)
		}
		nonce, err := crypto.ParseHex(in.NonceHex)
		if err != nil {
			t.Fatal(err)
		}
		kek, err := crypto.PairKEK(code, in.CodeID)
		if err != nil {
			t.Fatal(err)
		}
		blob, err := crypto.SealSelfContainedWithNonce(kek, nonce, mk, nil)
		if err != nil {
			t.Fatal(err)
		}
		if crypto.B64(blob) != want.BlobB64 {
			t.Fatalf("pair blob 不匹配:\n got %s\nwant %s", crypto.B64(blob), want.BlobB64)
		}
	})
}

// TestSigningVectors 比对签名串与 Ed25519 签名。
func TestSigningVectors(t *testing.T) {
	vars := loadVectors(t, "signing.json")
	for name, raw := range vars {
		raw := raw
		t.Run(name, func(t *testing.T) {
			var in struct {
				Method    string `json:"method"`
				RequestUR string `json:"request_uri"`
				Body      string `json:"body_utf8"`
				TS        int64  `json:"ts"`
				SeedHex   string `json:"device_key_seed_hex"`
			}
			var want struct {
				BodySHA256Hex string `json:"body_sha256_hex"`
				SigningString string `json:"signing_string_utf8"`
				SignatureB64  string `json:"signature_b64url"`
				DevicePubkey  string `json:"device_pubkey_b64url"`
			}
			decodeBoth(t, raw, &in, &want)

			body := []byte(in.Body)
			if got := crypto.Hex(crypto.SHA256(body)); got != want.BodySHA256Hex {
				t.Fatalf("body sha256 不匹配: got %s want %s", got, want.BodySHA256Hex)
			}
			if got := crypto.SigningString(in.Method, in.RequestUR, body, in.TS); got != want.SigningString {
				t.Fatalf("签名串不匹配:\n got %q\nwant %q", got, want.SigningString)
			}
			seed, err := crypto.ParseHex(in.SeedHex)
			if err != nil {
				t.Fatal(err)
			}
			priv := ed25519.NewKeyFromSeed(seed)
			pub := priv.Public().(ed25519.PublicKey)
			if crypto.B64(pub) != want.DevicePubkey {
				t.Fatalf("公钥不匹配: got %s want %s", crypto.B64(pub), want.DevicePubkey)
			}
			sig := crypto.Sign(priv, in.Method, in.RequestUR, body, in.TS)
			if crypto.B64(sig) != want.SignatureB64 {
				t.Fatalf("签名不匹配:\n got %s\nwant %s", crypto.B64(sig), want.SignatureB64)
			}
			if !crypto.Verify(pub, in.Method, in.RequestUR, body, in.TS, sig) {
				t.Fatal("Verify 应通过")
			}
			if crypto.Verify(pub, in.Method, in.RequestUR, body, in.TS+1, sig) {
				t.Fatal("时间戳变化后 Verify 不应通过")
			}
			if crypto.Verify(pub, in.Method, in.RequestUR, append(body, ' '), in.TS, sig) {
				t.Fatal("body 变化后 Verify 不应通过")
			}
		})
	}
}

// TestEncodingVectors 比对编码规则（base32/base64url/展示分组/哈希）。
func TestEncodingVectors(t *testing.T) {
	vars := loadVectors(t, "encoding.json")

	t.Run("master_key_encoding", func(t *testing.T) {
		v := mustVec(t, vars, "master_key_encoding")
		var in struct {
			MasterKeyHex string `json:"master_key_hex"`
		}
		var want struct {
			B32 string `json:"b32_nopad_upper"`
			B64 string `json:"b64url"`
		}
		decodeBoth(t, v, &in, &want)
		mk, err := crypto.ParseHex(in.MasterKeyHex)
		if err != nil {
			t.Fatal(err)
		}
		if got := crypto.Base32Upper(mk); got != want.B32 {
			t.Fatalf("base32 不匹配: got %s want %s", got, want.B32)
		}
		if got := crypto.B64(mk); got != want.B64 {
			t.Fatalf("base64url 不匹配: got %s want %s", got, want.B64)
		}
		// 容忍小写、'-'、'=' 的输入。
		parsed, err := crypto.ParseMasterKey(" " + want.B32 + "= ")
		if err != nil {
			t.Fatalf("ParseMasterKey 失败: %v", err)
		}
		if crypto.Hex(parsed) != in.MasterKeyHex {
			t.Fatal("ParseMasterKey 结果不一致")
		}
	})

	t.Run("pair_code_encoding", func(t *testing.T) {
		v := mustVec(t, vars, "pair_code_encoding")
		var in struct {
			CodeHex string `json:"code_hex"`
		}
		var want struct {
			B32     string `json:"code_b32_nopad_upper"`
			Display string `json:"code_display"`
			HashHex string `json:"code_hash_hex"`
		}
		decodeBoth(t, v, &in, &want)
		code, err := crypto.ParseHex(in.CodeHex)
		if err != nil {
			t.Fatal(err)
		}
		if got := crypto.Base32Upper(code); got != want.B32 {
			t.Fatalf("code base32 不匹配: got %s want %s", got, want.B32)
		}
		if got := crypto.FormatPairCode(code); got != want.Display {
			t.Fatalf("展示格式不匹配: got %s want %s", got, want.Display)
		}
		if got := crypto.Hex(crypto.PairCodeHash(code)); got != want.HashHex {
			t.Fatalf("code_hash 不匹配: got %s want %s", got, want.HashHex)
		}
		// 人工输入的两组形式都必须能解析回原始字节。
		for _, form := range []string{want.B32, want.Display, " " + strings.ToLower(want.Display) + " "} {
			parsed, err := crypto.ParsePairCode(form)
			if err != nil {
				t.Fatalf("ParsePairCode(%q) 失败: %v", form, err)
			}
			if crypto.Hex(parsed) != in.CodeHex {
				t.Fatalf("ParsePairCode(%q) 结果不一致", form)
			}
		}
	})
}

// TestCryptoSelfContained 覆盖自包含封装与通用错误路径。
func TestCryptoSelfContained(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	pt := []byte("secret")
	blob, err := crypto.SealSelfContained(key, pt, []byte("aad"))
	if err != nil {
		t.Fatalf("SealSelfContained: %v", err)
	}
	got, err := crypto.OpenSelfContained(key, blob, []byte("aad"))
	if err != nil || string(got) != string(pt) {
		t.Fatalf("OpenSelfContained 失败: %v", err)
	}
	if _, err := crypto.OpenSelfContained(key, blob, []byte("bad")); err == nil {
		t.Fatal("AAD 不符时不应解密成功")
	}
	if _, err := crypto.OpenSelfContained(key, blob[:10], nil); err == nil {
		t.Fatal("过短输入应失败")
	}
	if _, err := crypto.ItemKey(key[:16], "x"); err == nil {
		t.Fatal("master_key 长度错误应失败")
	}
	if _, err := crypto.ItemKey(key, ""); err == nil {
		t.Fatal("空 item_id 应失败")
	}
	if _, err := crypto.ParseB64("!!!"); err == nil {
		t.Fatal("非法 base64url 应失败")
	}
	if !crypto.Equal([]byte("a"), []byte("a")) || crypto.Equal([]byte("a"), []byte("b")) {
		t.Fatal("Equal 语义错误")
	}
	if crypto.SigningString("GET", "/x", nil, 1) != crypto.SigningString("GET", "/x", []byte{}, 1) {
		t.Fatal("空 body 与非 nil 空 body 的签名串应一致")
	}
}

// decodeBoth 同时解析 inputs 与 expected。
func decodeBoth(t *testing.T, v rawVector, inputs, expected any) {
	t.Helper()
	if err := json.Unmarshal(v.Inputs, inputs); err != nil {
		t.Fatalf("%s.inputs 解析失败: %v", v.Name, err)
	}
	if err := json.Unmarshal(v.Expected, expected); err != nil {
		t.Fatalf("%s.expected 解析失败: %v", v.Name, err)
	}
}
