//! CTAP2 / CTAPHID 实现。

pub mod authenticator;
pub mod cbor;
pub mod hid;

#[cfg(target_os = "linux")]
pub mod uhid;

use std::sync::OnceLock;

/// 读取调试开关环境变量：值为 `"1"` 时开启。
///
/// 每个进程只读一次环境变量（`OnceLock` 缓存），未设置时调用方不产生任何输出。
///
/// - `cache`：调用方持有的静态缓存槽；
/// - `var`：环境变量名。
pub(crate) fn debug_flag(cache: &'static OnceLock<bool>, var: &str) -> bool {
    *cache.get_or_init(|| {
        std::env::var_os(var)
            .as_deref()
            .and_then(std::ffi::OsStr::to_str)
            == Some("1")
    })
}
