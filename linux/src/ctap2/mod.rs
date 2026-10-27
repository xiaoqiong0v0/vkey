//! CTAP2 / CTAPHID 实现。

pub mod authenticator;
pub mod cbor;
pub mod hid;

#[cfg(target_os = "linux")]
pub mod uhid;
