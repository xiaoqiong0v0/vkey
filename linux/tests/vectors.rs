//! 与 `shared/vectors/*.json` 逐项比对。
//!
//! 路径通过 `include_str!` 编译期嵌入，保证 cargo test 在 Windows / Linux 上
//! 都能找到仓库根下的 shared/（linux/tests/../../shared）。

use anyhow::{anyhow, bail, Result};
use serde::Deserialize;
use serde_json::Value;
use vkey_hid::crypto;

#[derive(Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    inputs: Value,
    expected: Value,
}

const KDF: &str = include_str!("../../shared/vectors/kdf.json");
const AEAD: &str = include_str!("../../shared/vectors/aead.json");
const ENCODING: &str = include_str!("../../shared/vectors/encoding.json");
const SIGNING: &str = include_str!("../../shared/vectors/signing.json");

fn load(raw: &str) -> Result<Vec<Vector>> {
    let file: VectorFile = serde_json::from_str(raw)?;
    Ok(file.vectors)
}

fn find<'a>(vectors: &'a [Vector], name: &str) -> Result<&'a Vector> {
    vectors
        .iter()
        .find(|v| v.name == name)
        .ok_or_else(|| anyhow!("缺少向量 {name}"))
}

fn hex(inputs: &Value, key: &str) -> Result<Vec<u8>> {
    crypto::hex_decode(
        inputs
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("缺少 {key}"))?,
    )
}

fn text<'a>(inputs: &'a Value, key: &str) -> Result<&'a str> {
    inputs
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("缺少 {key}"))
}

fn b64(expected: &Value, key: &str) -> Result<Vec<u8>> {
    crypto::b64_decode(
        expected
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("缺少 {key}"))?,
    )
}

fn u32_of(inputs: &Value, key: &str) -> Result<u32> {
    inputs
        .get(key)
        .and_then(Value::as_u64)
        .map(|v| v as u32)
        .ok_or_else(|| anyhow!("缺少 {key}"))
}

#[test]
fn kdf_vectors_match() -> Result<()> {
    let vectors = load(KDF)?;

    let v = find(&vectors, "verifier")?;
    let master = hex(&v.inputs, "master_key_hex")?;
    let username = text(&v.inputs, "username")?;
    let got = crypto::verifier(&master, username)?;
    assert_eq!(
        got.as_slice(),
        b64(&v.expected, "verifier_b64url")?.as_slice()
    );

    let v = find(&vectors, "item_key")?;
    let master = hex(&v.inputs, "master_key_hex")?;
    let item_id = text(&v.inputs, "item_id")?;
    let got = crypto::item_key(&master, item_id)?;
    assert_eq!(
        got.as_slice(),
        b64(&v.expected, "item_key_b64url")?.as_slice()
    );

    let v = find(&vectors, "pair_kek")?;
    let code = hex(&v.inputs, "code_hex")?;
    let code_id = text(&v.inputs, "code_id")?;
    let got = crypto::pair_kek(&code, code_id)?;
    assert_eq!(got.as_slice(), b64(&v.expected, "kek_b64url")?.as_slice());

    let v = find(&vectors, "argon2id_kek")?;
    let salt = hex(&v.inputs, "pw_salt_hex")?;
    let password = text(&v.inputs, "password")?;
    let got = crypto::argon2id_kek(
        password,
        &salt,
        u32_of(&v.inputs, "m")?,
        u32_of(&v.inputs, "t")?,
        u32_of(&v.inputs, "p")?,
    )?;
    assert_eq!(got.as_slice(), b64(&v.expected, "kek_b64url")?.as_slice());
    Ok(())
}

#[test]
fn aead_vectors_match() -> Result<()> {
    let vectors = load(AEAD)?;

    let v = find(&vectors, "item_ciphertext")?;
    let master = hex(&v.inputs, "master_key_hex")?;
    let item_id = text(&v.inputs, "item_id")?;
    let nonce = hex(&v.inputs, "nonce_hex")?;
    let plaintext = text(&v.inputs, "plaintext_utf8")?;
    let aad = text(&v.inputs, "aad_utf8")?;
    assert_eq!(crypto::item_aad(item_id), aad.as_bytes());
    let ct = crypto::seal_item_with_nonce(&master, item_id, plaintext.as_bytes(), &nonce)?;
    assert_eq!(
        crypto::b64_encode(&ct),
        v.expected
            .get("ciphertext_b64url")
            .and_then(Value::as_str)
            .unwrap()
    );
    let opened = crypto::open_item(&master, item_id, &ct, &nonce)?;
    assert_eq!(opened, plaintext.as_bytes());

    let v = find(&vectors, "wrapped_key")?;
    let master = hex(&v.inputs, "master_key_hex")?;
    let salt = hex(&v.inputs, "pw_salt_hex")?;
    let nonce = hex(&v.inputs, "nonce_hex")?;
    let password = text(&v.inputs, "password")?;
    let kek = crypto::argon2id_kek(password, &salt, 65536, 3, 1)?;
    let wrapped = crypto::seal_self_contained_with_nonce(&kek, &nonce, &master, b"")?;
    assert_eq!(
        crypto::b64_encode(&wrapped),
        v.expected
            .get("wrapped_key_b64url")
            .and_then(Value::as_str)
            .unwrap()
    );
    assert_eq!(crypto::open_self_contained(&kek, &wrapped, b"")?, master);

    let v = find(&vectors, "pair_blob")?;
    let master = hex(&v.inputs, "master_key_hex")?;
    let code = hex(&v.inputs, "code_hex")?;
    let code_id = text(&v.inputs, "code_id")?;
    let nonce = hex(&v.inputs, "nonce_hex")?;
    let kek = crypto::pair_kek(&code, code_id)?;
    let blob = crypto::seal_self_contained_with_nonce(&kek, &nonce, &master, b"")?;
    assert_eq!(
        crypto::b64_encode(&blob),
        v.expected
            .get("blob_b64url")
            .and_then(Value::as_str)
            .unwrap()
    );
    assert_eq!(crypto::open_self_contained(&kek, &blob, b"")?, master);
    Ok(())
}

#[test]
fn encoding_vectors_match() -> Result<()> {
    let vectors = load(ENCODING)?;

    let v = find(&vectors, "master_key_encoding")?;
    let master = hex(&v.inputs, "master_key_hex")?;
    assert_eq!(
        crypto::b32_encode(&master),
        v.expected
            .get("b32_nopad_upper")
            .and_then(Value::as_str)
            .unwrap()
    );
    assert_eq!(
        crypto::b64_encode(&master),
        v.expected.get("b64url").and_then(Value::as_str).unwrap()
    );
    // 解析回环（容忍小写/分组/填充）。
    assert_eq!(
        crypto::parse_master_key(&crypto::b32_encode(&master))?,
        master
    );

    let v = find(&vectors, "pair_code_encoding")?;
    let code = hex(&v.inputs, "code_hex")?;
    assert_eq!(
        crypto::b32_encode(&code),
        v.expected
            .get("code_b32_nopad_upper")
            .and_then(Value::as_str)
            .unwrap()
    );
    assert_eq!(
        crypto::format_pair_code(&code),
        v.expected
            .get("code_display")
            .and_then(Value::as_str)
            .unwrap()
    );
    assert_eq!(
        crypto::hex_encode(&crypto::pair_code_hash(&code)),
        v.expected
            .get("code_hash_hex")
            .and_then(Value::as_str)
            .unwrap()
    );
    let display = v
        .expected
        .get("code_display")
        .and_then(Value::as_str)
        .unwrap()
        .to_ascii_lowercase();
    assert_eq!(crypto::parse_pair_code(&display)?, code);
    Ok(())
}

#[test]
fn signing_vectors_match() -> Result<()> {
    let vectors = load(SIGNING)?;
    if vectors.is_empty() {
        bail!("signing 向量为空");
    }
    for v in &vectors {
        let seed = hex(&v.inputs, "device_key_seed_hex")?;
        let method = text(&v.inputs, "method")?;
        let uri = text(&v.inputs, "request_uri")?;
        let body = text(&v.inputs, "body_utf8")?;
        let ts = v
            .inputs
            .get("ts")
            .and_then(Value::as_i64)
            .ok_or_else(|| anyhow!("缺少 ts"))?;

        let expected_string = v
            .expected
            .get("signing_string_utf8")
            .and_then(Value::as_str)
            .unwrap();
        assert_eq!(
            crypto::signing_string(method, uri, body.as_bytes(), ts),
            expected_string,
            "{} signing string",
            v.name
        );

        let pubkey = crypto::device_public_key(&seed)?;
        assert_eq!(
            crypto::b64_encode(&pubkey),
            v.expected
                .get("device_pubkey_b64url")
                .and_then(Value::as_str)
                .unwrap(),
            "{} pubkey",
            v.name
        );

        let sig = crypto::sign_request(&seed, method, uri, body.as_bytes(), ts)?;
        assert_eq!(
            crypto::b64_encode(&sig),
            v.expected
                .get("signature_b64url")
                .and_then(Value::as_str)
                .unwrap(),
            "{} signature",
            v.name
        );
        assert!(crypto::verify_request(
            &pubkey,
            method,
            uri,
            body.as_bytes(),
            ts,
            &sig
        )?);
    }
    Ok(())
}
