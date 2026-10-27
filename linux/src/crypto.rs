//! vkey 协议密码学原语与编码规则。
//!
//! 本模块与 `shared/protocol.md` §1 及 `shared/vectors/*.json` 逐字节对齐；
//! Go 参考实现见 `server/internal/crypto/crypto.go`。

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// 对称密钥长度（master_key / verifier / item_key / KEK）。
pub const KEY_LEN: usize = 32;
/// AES-256-GCM nonce 长度。
pub const NONCE_LEN: usize = 12;
/// GCM tag 长度。
pub const TAG_LEN: usize = 16;
/// 设备 token 长度。
pub const TOKEN_LEN: usize = 32;
/// 配对码原始长度。
pub const PAIR_CODE_LEN: usize = 32;
/// 主密码 salt 长度。
pub const PW_SALT_LEN: usize = 16;
/// Ed25519 种子 / 公钥 / 签名长度。
pub const ED25519_SEED_LEN: usize = 32;
pub const ED25519_PUB_LEN: usize = 32;
pub const ED25519_SIG_LEN: usize = 64;

/// verifier 的 HKDF salt。
pub const SALT_VERIFIER: &[u8] = b"vkey-verifier";
/// item_key 的 HKDF salt。
pub const SALT_ITEM: &[u8] = b"vkey-item";
/// 配对 KEK 的 HKDF salt。
pub const SALT_PAIR: &[u8] = b"vkey-pair";
/// 条目 AEAD 的 AAD 前缀。
pub const AAD_ITEM_PREFIX: &str = "vkey-item|";
/// 本地包裹 master_key 的 HKDF salt（仅本机使用，不属于线上协议）。
pub const SALT_LOCAL: &[u8] = b"vkey-local";
/// 本地包裹 master_key 的 HKDF info（仅本机使用）。
pub const INFO_LOCAL_WRAP: &str = "vkey-wrap-master";

/// Argon2id 默认参数（KiB / 迭代 / 并行度），与协议固定值一致。
pub const ARGON2_M_KIB: u32 = 65536;
pub const ARGON2_T: u32 = 3;
pub const ARGON2_P: u32 = 1;

const ALPHABET_B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// 生成 n 字节密码学随机数。
pub fn random_bytes(n: usize) -> Result<Vec<u8>> {
    if n == 0 {
        bail!("随机数长度必须大于 0");
    }
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    Ok(buf)
}

/// SHA-256 摘要。
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

/// 设备 token 的服务端存储形式。
pub fn token_hash(token: &[u8]) -> [u8; 32] {
    sha256(token)
}

/// 配对码的服务端存储形式（对原始 32B 求哈希，不是展示字符串）。
pub fn pair_code_hash(code: &[u8]) -> [u8; 32] {
    sha256(code)
}

/// HKDF-SHA256 派生 32 字节密钥。
///
/// 参数：`ikm` 为输入密钥材料；`salt` / `info` 为 UTF-8 原始字节；
/// 返回：32 字节 OKM。对应协议 §1.1 的 `PRK = HMAC-SHA256(salt, ikm)`。
pub fn hkdf32(ikm: &[u8], salt: &[u8], info: &str) -> Result<Zeroizing<Vec<u8>>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = Zeroizing::new(vec![0u8; KEY_LEN]);
    hk.expand(info.as_bytes(), okm.as_mut())
        .map_err(|e| anyhow!("HKDF 派生失败: {e}"))?;
    Ok(okm)
}

/// 计算 verifier：HKDF-SHA256(master_key, "vkey-verifier", username)。
pub fn verifier(master_key: &[u8], username: &str) -> Result<Zeroizing<Vec<u8>>> {
    require_len(master_key, KEY_LEN, "master_key")?;
    hkdf32(master_key, SALT_VERIFIER, username)
}

/// 计算 item_key：HKDF-SHA256(master_key, "vkey-item", item_id)。
pub fn item_key(master_key: &[u8], item_id: &str) -> Result<Zeroizing<Vec<u8>>> {
    require_len(master_key, KEY_LEN, "master_key")?;
    if item_id.is_empty() {
        bail!("item_id 不能为空");
    }
    hkdf32(master_key, SALT_ITEM, item_id)
}

/// 计算配对 KEK：HKDF-SHA256(code_bytes, "vkey-pair", code_id)。
pub fn pair_kek(code_bytes: &[u8], code_id: &str) -> Result<Zeroizing<Vec<u8>>> {
    require_len(code_bytes, PAIR_CODE_LEN, "配对码")?;
    if code_id.is_empty() {
        bail!("code_id 不能为空");
    }
    hkdf32(code_bytes, SALT_PAIR, code_id)
}

/// 计算本地包裹 KEK：HKDF-SHA256(local_key, "vkey-local", "vkey-wrap-master")。
pub fn local_wrap_kek(local_key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    require_len(local_key, KEY_LEN, "local.key")?;
    hkdf32(local_key, SALT_LOCAL, INFO_LOCAL_WRAP)
}

/// 用 Argon2id 从主密码派生 32 字节 KEK。
///
/// 参数：`m_kib` / `t` / `p` 来自服务端策略（协议固定 65536/3/1）；
/// `salt` 必须 16 字节。
pub fn argon2id_kek(
    password: &str,
    salt: &[u8],
    m_kib: u32,
    t: u32,
    p: u32,
) -> Result<Zeroizing<Vec<u8>>> {
    require_len(salt, PW_SALT_LEN, "pw_salt")?;
    let params =
        Params::new(m_kib, t, p, Some(KEY_LEN)).map_err(|e| anyhow!("Argon2 参数非法: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut okm = Zeroizing::new(vec![0u8; KEY_LEN]);
    argon
        .hash_password_into(password.as_bytes(), salt, okm.as_mut())
        .map_err(|e| anyhow!("Argon2id 派生失败: {e}"))?;
    Ok(okm)
}

/// 条目 AEAD 的 AAD：UTF8("vkey-item|" + item_id)。
pub fn item_aad(item_id: &str) -> Vec<u8> {
    format!("{AAD_ITEM_PREFIX}{item_id}").into_bytes()
}

/// AES-256-GCM 加密，输出 `ciphertext || tag`。
#[allow(deprecated)]
pub fn seal(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = new_cipher(key, nonce)?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("AES-256-GCM 加密失败"))
}

/// AES-256-GCM 解密（输入为 `ciphertext || tag`）。
#[allow(deprecated)]
pub fn open(key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = new_cipher(key, nonce)?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("AES-256-GCM 解密失败（密钥、nonce 或 AAD 不匹配）"))
}

/// 用随机 nonce 加密，输出 `nonce(12B) || ciphertext || tag` 自包含布局。
pub fn seal_self_contained(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let nonce = random_bytes(NONCE_LEN)?;
    seal_self_contained_with_nonce(key, &nonce, plaintext, aad)
}

/// 用指定 nonce 做自包含加密（测试向量复现用）。
pub fn seal_self_contained_with_nonce(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let ct = seal(key, nonce, plaintext, aad)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// 解密 `nonce(12B) || ciphertext || tag` 自包含布局。
pub fn open_self_contained(key: &[u8], blob: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        bail!("自包含密文过短（{} 字节）", blob.len());
    }
    open(key, &blob[..NONCE_LEN], &blob[NONCE_LEN..], aad)
}

/// 用随机 nonce 加密条目，返回 `(ciphertext, nonce)`（ct 含 tag）。
pub fn seal_item_random(
    master_key: &[u8],
    item_id: &str,
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let key = item_key(master_key, item_id)?;
    let nonce = random_bytes(NONCE_LEN)?;
    let ct = seal(&key, &nonce, plaintext, &item_aad(item_id))?;
    Ok((ct, nonce))
}

/// 用指定 nonce 加密条目（测试向量复现用）。
pub fn seal_item_with_nonce(
    master_key: &[u8],
    item_id: &str,
    plaintext: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>> {
    let key = item_key(master_key, item_id)?;
    seal(&key, nonce, plaintext, &item_aad(item_id))
}

/// 解密条目密文。
pub fn open_item(
    master_key: &[u8],
    item_id: &str,
    ciphertext: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>> {
    let key = item_key(master_key, item_id)?;
    open(&key, nonce, ciphertext, &item_aad(item_id))
}

/// 构造设备签名串：
/// `METHOD + "\n" + RequestURI + "\n" + hex(sha256(body)) + "\n" + ts`。
pub fn signing_string(method: &str, request_uri: &str, body: &[u8], ts: i64) -> String {
    let digest = sha256(body);
    format!(
        "{}\n{}\n{}\n{}",
        method,
        request_uri,
        hex::encode(digest),
        ts
    )
}

/// 从 32B 种子构造 Ed25519 签名密钥。
pub fn device_signing_key(seed: &[u8]) -> Result<SigningKey> {
    let arr: [u8; ED25519_SEED_LEN] = seed
        .try_into()
        .map_err(|_| anyhow!("Ed25519 种子必须 {ED25519_SEED_LEN} 字节"))?;
    Ok(SigningKey::from_bytes(&arr))
}

/// 从 32B 种子导出 32B 原始公钥。
pub fn device_public_key(seed: &[u8]) -> Result<[u8; ED25519_PUB_LEN]> {
    Ok(device_signing_key(seed)?.verifying_key().to_bytes())
}

/// 用设备私钥签署请求，返回 64B 原始签名。
pub fn sign_request(
    seed: &[u8],
    method: &str,
    request_uri: &str,
    body: &[u8],
    ts: i64,
) -> Result<[u8; ED25519_SIG_LEN]> {
    let key = device_signing_key(seed)?;
    let msg = signing_string(method, request_uri, body, ts);
    Ok(key.sign(msg.as_bytes()).to_bytes())
}

/// 校验设备请求签名。
pub fn verify_request(
    public_key: &[u8],
    method: &str,
    request_uri: &str,
    body: &[u8],
    ts: i64,
    signature: &[u8],
) -> Result<bool> {
    let pk: [u8; ED25519_PUB_LEN] = public_key
        .try_into()
        .map_err(|_| anyhow!("Ed25519 公钥必须 {ED25519_PUB_LEN} 字节"))?;
    let sig: [u8; ED25519_SIG_LEN] = signature
        .try_into()
        .map_err(|_| anyhow!("Ed25519 签名必须 {ED25519_SIG_LEN} 字节"))?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|e| anyhow!("Ed25519 公钥非法: {e}"))?;
    let sig = Ed25519Signature::from_bytes(&sig);
    let msg = signing_string(method, request_uri, body, ts);
    Ok(vk.verify_strict(msg.as_bytes(), &sig).is_ok())
}

/// 常量时间比较（先各自 SHA-256，避免长度差异时序泄漏）。
pub fn equal_ct(a: &[u8], b: &[u8]) -> bool {
    let ha = sha256(a);
    let hb = sha256(b);
    ha.ct_eq(&hb).into()
}

/// base64url 无填充编码。
pub fn b64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// base64url 解码（容忍首尾空白与尾随 `=`）。
pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    let trimmed = s.trim().trim_end_matches('=');
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(trimmed)
        .map_err(|e| anyhow!("base64url 解码失败: {e}"))
}

/// base32 大写无填充编码（RFC 4648 标准字母表）。
pub fn b32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            let idx = ((buffer >> (bits - 5)) & 0x1f) as usize;
            out.push(ALPHABET_B32[idx] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET_B32[idx] as char);
    }
    out
}

/// base32 解码，容忍小写、`-`、空白、制表/换行与 `=` 填充。
pub fn b32_decode(input: &str) -> Result<Vec<u8>> {
    let cleaned: String = input
        .chars()
        .filter(|c| !matches!(c, '-' | ' ' | '\t' | '\n' | '\r' | '='))
        .collect::<String>()
        .to_ascii_uppercase();
    if cleaned.is_empty() {
        bail!("base32 输入为空");
    }
    let mut out = Vec::with_capacity(cleaned.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for ch in cleaned.bytes() {
        let val = b32_value(ch).ok_or_else(|| anyhow!("base32 含非法字符: {}", ch as char))?;
        buffer = (buffer << 5) | u32::from(val);
        bits += 5;
        if bits >= 8 {
            out.push((buffer >> (bits - 8)) as u8);
            bits -= 8;
        }
    }
    if bits > 0 && (buffer & ((1 << bits) - 1)) != 0 {
        bail!("base32 尾部包含非零填充位");
    }
    Ok(out)
}

/// 把 32B 配对码格式化为 4 字符一组的展示形式。
pub fn format_pair_code(code: &[u8]) -> String {
    let s = b32_encode(code);
    let mut out = String::with_capacity(s.len() + s.len() / 4);
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        out.push(ch);
    }
    out
}

/// 解析配对码（容忍展示形式 / 小写 / 空格），必须得到 32B。
pub fn parse_pair_code(input: &str) -> Result<Vec<u8>> {
    let bytes = b32_decode(input).context("配对码解析失败")?;
    require_len(&bytes, PAIR_CODE_LEN, "配对码")?;
    Ok(bytes)
}

/// 解析 master_key 的 base32 形式，必须得到 32B。
pub fn parse_master_key(input: &str) -> Result<Vec<u8>> {
    let bytes = b32_decode(input).context("master_key 解析失败")?;
    require_len(&bytes, KEY_LEN, "master_key")?;
    Ok(bytes)
}

/// 小写十六进制编码。
pub fn hex_encode(data: &[u8]) -> String {
    hex::encode(data)
}

/// 解析十六进制串（测试向量与调试输出）。
pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let cleaned = s.trim();
    hex::decode(cleaned).map_err(|e| anyhow!("十六进制解码失败: {e}"))
}

fn new_cipher(key: &[u8], nonce: &[u8]) -> Result<Aes256Gcm> {
    require_len(key, KEY_LEN, "AES 密钥")?;
    require_len(nonce, NONCE_LEN, "AES nonce")?;
    Aes256Gcm::new_from_slice(key).map_err(|_| anyhow!("AES-256 密钥长度非法"))
}

fn require_len(data: &[u8], expected: usize, what: &str) -> Result<()> {
    if data.len() != expected {
        bail!("{what} 必须 {expected} 字节，实际 {}", data.len());
    }
    Ok(())
}

fn b32_value(ch: u8) -> Option<u8> {
    match ch {
        b'A'..=b'Z' => Some(ch - b'A'),
        b'2'..=b'7' => Some(ch - b'2' + 26),
        _ => None,
    }
}
