//! 最小 CBOR 编解码器（CTAP2 子集）。
//!
//! 与 `spike/uhid_fido.py` 一致：
//! - `true` / `false` 编码为 `0xF5` / `0xF4`（不是整数 21/20）
//! - map 按 canonical CBOR 排序（编码后长度升序，再按字节序）
//! - 不支持 indefinite length / float；tag 忽略后返回内层值
//!
//! 只覆盖 CTAP2 需要的类型：uint / nint / bytes / text / array / map / bool / null。

use anyhow::{anyhow, bail, Result};

const MAJOR_UINT: u8 = 0;
const MAJOR_NINT: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_TAG: u8 = 6;
const MAJOR_SIMPLE: u8 = 7;

const SIMPLE_FALSE: u8 = 20;
const SIMPLE_TRUE: u8 = 21;
const SIMPLE_NULL: u8 = 22;
const SIMPLE_UNDEFINED: u8 = 23;
const INDEFINITE: u8 = 31;

const MAX_DEPTH: usize = 64;

/// CBOR 值。map 用有序 `Vec` 保存，编码时按 canonical 顺序排序。
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    UInt(u64),
    NInt(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

impl Value {
    /// 用整数 key 取 map 值。
    pub fn get_int(&self, key: i64) -> Option<&Value> {
        match self {
            Value::Map(entries) => entries.iter().find_map(|(k, v)| match (k, key) {
                (Value::UInt(n), k) if *n == k as u64 && k >= 0 => Some(v),
                (Value::NInt(n), k) if *n == k => Some(v),
                _ => None,
            }),
            _ => None,
        }
    }

    /// 用文本 key 取 map 值。
    pub fn get_text(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(entries) => entries.iter().find_map(|(k, v)| match k {
                Value::Text(s) if s == key => Some(v),
                _ => None,
            }),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::UInt(n) => i64::try_from(*n).ok(),
            Value::NInt(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

/// 编码一个 CBOR 值。
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

/// 解码一个 CBOR 值，返回 `(value, consumed)`。
pub fn decode(data: &[u8]) -> Result<(Value, usize)> {
    decode_at(data, 0, 0)
}

fn encode_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::UInt(n) => head(MAJOR_UINT, *n, out),
        Value::NInt(n) => {
            debug_assert!(*n < 0, "NInt 必须为负数");
            head(MAJOR_NINT, (-1 - *n) as u64, out);
        }
        Value::Bytes(b) => {
            head(MAJOR_BYTES, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            head(MAJOR_TEXT, s.len() as u64, out);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            head(MAJOR_ARRAY, items.len() as u64, out);
            for item in items {
                encode_into(item, out);
            }
        }
        Value::Map(entries) => {
            head(MAJOR_MAP, entries.len() as u64, out);
            let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = entries
                .iter()
                .map(|(k, v)| {
                    let mut kb = Vec::new();
                    encode_into(k, &mut kb);
                    let mut vb = Vec::new();
                    encode_into(v, &mut vb);
                    (kb, vb)
                })
                .collect();
            // canonical CBOR：先按编码后长度，再按字节序。
            encoded.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
            for (k, v) in encoded {
                out.extend_from_slice(&k);
                out.extend_from_slice(&v);
            }
        }
        Value::Bool(true) => out.push(0xF5),
        Value::Bool(false) => out.push(0xF4),
        Value::Null => out.push(0xF6),
    }
}

fn head(major: u8, value: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    if value < 24 {
        out.push(m | value as u8);
    } else if value <= u8::MAX as u64 {
        out.push(m | 24);
        out.push(value as u8);
    } else if value <= u16::MAX as u64 {
        out.push(m | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u32::MAX as u64 {
        out.push(m | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

fn decode_at(data: &[u8], offset: usize, depth: usize) -> Result<(Value, usize)> {
    if depth > MAX_DEPTH {
        bail!("CBOR 嵌套过深");
    }
    let first = *data
        .get(offset)
        .ok_or_else(|| anyhow!("CBOR 数据意外结束"))?;
    let major = first >> 5;
    let info = first & 0x1f;
    let mut pos = offset + 1;

    if major == MAJOR_SIMPLE {
        return match info {
            SIMPLE_FALSE => Ok((Value::Bool(false), pos)),
            SIMPLE_TRUE => Ok((Value::Bool(true), pos)),
            SIMPLE_NULL | SIMPLE_UNDEFINED => Ok((Value::Null, pos)),
            other => Err(anyhow!("不支持的 CBOR simple value {other}")),
        };
    }

    let (arg, next) = decode_arg(data, pos, info)?;
    pos = next;

    match major {
        MAJOR_TAG => {
            // 忽略语义 tag，返回内层值（容错）。
            decode_at(data, pos, depth + 1)
        }
        MAJOR_UINT => Ok((Value::UInt(arg), pos)),
        MAJOR_NINT => Ok((Value::NInt(-1 - arg as i64), pos)),
        MAJOR_BYTES => {
            let end = pos
                .checked_add(arg as usize)
                .ok_or_else(|| anyhow!("CBOR 长度溢出"))?;
            if end > data.len() {
                bail!("CBOR bytes 截断");
            }
            Ok((Value::Bytes(data[pos..end].to_vec()), end))
        }
        MAJOR_TEXT => {
            let end = pos
                .checked_add(arg as usize)
                .ok_or_else(|| anyhow!("CBOR 长度溢出"))?;
            if end > data.len() {
                bail!("CBOR text 截断");
            }
            let s = std::str::from_utf8(&data[pos..end])
                .map_err(|e| anyhow!("CBOR text 不是合法 UTF-8: {e}"))?;
            Ok((Value::Text(s.to_string()), end))
        }
        MAJOR_ARRAY => {
            let count = arg as usize;
            let mut items = Vec::with_capacity(count.min(64));
            for _ in 0..count {
                let (item, next) = decode_at(data, pos, depth + 1)?;
                items.push(item);
                pos = next;
            }
            Ok((Value::Array(items), pos))
        }
        MAJOR_MAP => {
            let count = arg as usize;
            let mut entries = Vec::with_capacity(count.min(64));
            for _ in 0..count {
                let (k, next) = decode_at(data, pos, depth + 1)?;
                pos = next;
                let (v, next) = decode_at(data, pos, depth + 1)?;
                pos = next;
                entries.push((k, v));
            }
            Ok((Value::Map(entries), pos))
        }
        other => Err(anyhow!("不支持的 CBOR major type {other}")),
    }
}

fn decode_arg(data: &[u8], offset: usize, info: u8) -> Result<(u64, usize)> {
    if info < 24 {
        return Ok((u64::from(info), offset));
    }
    if info == INDEFINITE {
        bail!("不支持 indefinite length CBOR");
    }
    let size = match info {
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        other => bail!("CBOR 保留附加信息 {other}"),
    };
    let end = offset
        .checked_add(size)
        .ok_or_else(|| anyhow!("CBOR 偏移溢出"))?;
    if end > data.len() {
        bail!("CBOR 参数截断");
    }
    let mut buf = [0u8; 8];
    buf[8 - size..].copy_from_slice(&data[offset..end]);
    Ok((u64::from_be_bytes(buf), end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bool_encoding_is_f5_f4() {
        assert_eq!(encode(&Value::Bool(true)), vec![0xF5]);
        assert_eq!(encode(&Value::Bool(false)), vec![0xF4]);
        assert_ne!(encode(&Value::Bool(true)), vec![0x15]);
        assert_ne!(encode(&Value::Bool(false)), vec![0x14]);
    }

    #[test]
    fn negative_integers() {
        for (v, bytes) in [
            (-1i64, vec![0x20]),
            (-7, vec![0x26]),
            (-24, vec![0x37]),
            (-25, vec![0x38, 0x18]),
            (-1000, vec![0x39, 0x03, 0xE7]),
        ] {
            let encoded = encode(&Value::NInt(v));
            assert_eq!(encoded, bytes, "value {v}");
            let (decoded, used) = decode(&encoded).unwrap();
            assert_eq!(decoded, Value::NInt(v));
            assert_eq!(used, encoded.len());
        }
    }

    #[test]
    fn nested_map_array_roundtrip() {
        let value = Value::Map(vec![
            (
                Value::UInt(1),
                Value::Array(vec![
                    Value::Text("FIDO_2_0".into()),
                    Value::Text("FIDO_2_1".into()),
                ]),
            ),
            (
                Value::UInt(4),
                Value::Map(vec![
                    (Value::Text("up".into()), Value::Bool(true)),
                    (Value::Text("plat".into()), Value::Bool(false)),
                ]),
            ),
            (
                Value::UInt(10),
                Value::Array(vec![Value::Map(vec![
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                    (Value::Text("alg".into()), Value::NInt(-7)),
                ])]),
            ),
        ]);
        let encoded = encode(&value);
        let (decoded, used) = decode(&encoded).unwrap();
        assert_eq!(used, encoded.len());
        // map 编码时会 canonical 排序，因此按字段比较而不是整体相等。
        assert_eq!(
            decoded
                .get_int(1)
                .and_then(Value::as_array)
                .map(|a| a.len()),
            Some(2)
        );
        assert_eq!(
            decoded
                .get_int(4)
                .and_then(|m| m.get_text("up"))
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            decoded
                .get_int(10)
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(|m| m.get_text("alg"))
                .and_then(Value::as_i64),
            Some(-7)
        );
        assert_eq!(encode(&decoded), encoded, "重新编码应稳定");
    }

    #[test]
    fn canonical_map_order() {
        let value = Value::Map(vec![
            (Value::Text("plat".into()), Value::Bool(false)),
            (Value::Text("up".into()), Value::Bool(true)),
        ]);
        let encoded = encode(&value);
        // canonical CBOR：先按编码后长度升序，所以 "up"(3 字节 key) 在 "plat"(5 字节 key) 前。
        assert_eq!(encoded[0] & 0xE0, 0xA0);
        assert_eq!(&encoded[1..4], b"\x62up");
    }

    #[test]
    fn authenticator_selection_request_shape() {
        let request = Value::Map(vec![
            (Value::UInt(1), Value::Text("example.com".into())),
            (Value::UInt(2), Value::Bytes(vec![0x42; 32])),
            (
                Value::UInt(3),
                Value::Map(vec![(Value::UInt(1), Value::Bool(true))]),
            ),
        ]);
        let encoded = encode(&request);
        let (decoded, _) = decode(&encoded).unwrap();
        assert_eq!(
            decoded.get_int(1).and_then(Value::as_text),
            Some("example.com")
        );
        assert_eq!(
            decoded
                .get_int(2)
                .and_then(Value::as_bytes)
                .map(|b| b.len()),
            Some(32)
        );
        assert!(decoded
            .get_int(3)
            .and_then(|m| m.get_int(1))
            .and_then(Value::as_bool)
            .unwrap());
    }

    #[test]
    fn rejects_truncated() {
        assert!(decode(&[0x1A, 0x00]).is_err());
        assert!(decode(&[0x82, 0x01]).is_err());
    }
}
