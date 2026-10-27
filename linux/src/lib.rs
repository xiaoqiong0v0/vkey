//! vkey Linux 客户端核心库。
//!
//! 模块划分与 `shared/protocol.md` 对应：
//! - [`crypto`]：KDF / AEAD / Ed25519 / 签名串 / 编码（与 shared/vectors 对齐）
//! - [`api`]：vkeyd HTTP 客户端（policy/auth/items/pair）
//! - [`store`]：本地身份、条目密文缓存与本地包裹
//! - [`sync`]：增量拉取/推送与 LWW 冲突处理
//! - [`policy`]：服务端策略与「不可降级」规则
//! - [`ctap2`]：CBOR / CTAPHID / CTAP2 authenticator / uhid

pub mod api;
pub mod config;
pub mod crypto;
pub mod ctap2;
pub mod policy;
pub mod store;
pub mod sync;
