//! 本地路径、文件权限（0600/0700）与配置读写。
//!
//! 数据目录优先级：`VKEY_DATA_DIR` → `$XDG_DATA_HOME/vkey` →
//! `~/.local/share/vkey`。Windows 下退化为 `%LOCALAPPDATA%\vkey`。

use anyhow::{anyhow, Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// 返回 vkey 数据目录（不存在时创建，Unix 权限 0700）。
pub fn data_dir() -> Result<PathBuf> {
    let dir = if let Some(v) = env::var_os("VKEY_DATA_DIR") {
        PathBuf::from(v)
    } else if let Some(v) = env::var_os("XDG_DATA_HOME") {
        PathBuf::from(v).join("vkey")
    } else if cfg!(windows) {
        env::var_os("LOCALAPPDATA")
            .map(|v| PathBuf::from(v).join("vkey"))
            .ok_or_else(|| anyhow!("无法确定 LOCALAPPDATA，请设置 VKEY_DATA_DIR"))?
    } else {
        let home = env::var_os("HOME").ok_or_else(|| anyhow!("HOME 未设置"))?;
        PathBuf::from(home).join(".local/share/vkey")
    };
    ensure_dir(&dir)?;
    Ok(dir)
}

/// 创建目录并收紧权限（Unix 0700）。
pub fn ensure_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("创建目录失败: {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(dir)?.permissions();
        perm.set_mode(0o700);
        fs::set_permissions(dir, perm)?;
    }
    Ok(())
}

/// 读取可选文件；不存在返回 None。
pub fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(data) => {
            ensure_private_file(path)?;
            Ok(Some(data))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("读取文件失败: {}", path.display())),
    }
}

/// 读取必需文件。
pub fn read_required(path: &Path) -> Result<Vec<u8>> {
    read_optional(path)?.ok_or_else(|| anyhow!("文件不存在: {}", path.display()))
}

/// 原子写入私有文件（Unix 0600）。
///
/// 实现：写同目录临时文件 → fsync → rename。Windows 下 rename 不能覆盖
/// 已存在文件，因此先删除目标（失败回滚窗口极小，配置写入不是高频操作）。
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    let tmp = path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        chrono_like_counter()
    ));
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .with_context(|| format!("创建临时文件失败: {}", tmp.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = file.metadata()?.permissions();
            perm.set_mode(0o600);
            file.set_permissions(perm)?;
        }
        file.write_all(data)?;
        file.sync_all()?;
    }
    #[cfg(windows)]
    {
        if path.exists() {
            fs::remove_file(path).with_context(|| format!("覆盖前删除失败: {}", path.display()))?;
        }
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("重命名失败: {} -> {}", tmp.display(), path.display()))?;
    ensure_private_file(path)?;
    Ok(())
}

/// 写 JSON 私有文件。
pub fn write_json_private<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let data = serde_json::to_vec_pretty(value).context("序列化 JSON 失败")?;
    write_private(path, &data)
}

/// 读 JSON 文件。
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let data = read_required(path)?;
    serde_json::from_slice(&data).with_context(|| format!("解析 JSON 失败: {}", path.display()))
}

/// 读可选 JSON 文件。
pub fn read_json_optional<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match read_optional(path)? {
        Some(data) => {
            Ok(Some(serde_json::from_slice(&data).with_context(|| {
                format!("解析 JSON 失败: {}", path.display())
            })?))
        }
        None => Ok(None),
    }
}

/// 把已存在文件的权限收紧为 0600（Unix）。
pub fn ensure_private_file(path: &Path) -> Result<()> {
    #[cfg(not(unix))]
    let _ = path;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(path)?.permissions();
        if perm.mode() & 0o777 != 0o600 {
            perm.set_mode(0o600);
            fs::set_permissions(path, perm)?;
        }
    }
    Ok(())
}

/// 当前 unix 秒。
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 默认设备名：`VKEY_DEVICE_NAME` → 主机名 → `vkey-device`。
pub fn default_device_name() -> String {
    if let Ok(v) = env::var("VKEY_DEVICE_NAME") {
        if !v.trim().is_empty() {
            return v;
        }
    }
    for key in ["HOSTNAME", "COMPUTERNAME"] {
        if let Ok(v) = env::var(key) {
            if !v.trim().is_empty() {
                return v;
            }
        }
    }
    "vkey-device".to_string()
}

/// 读取主密码。
///
/// Linux 优先 `systemd-ask-password --timeout=0`（systemd user service 场景），
/// 失败或不可用时退回 `rpassword`。
pub fn read_password(prompt: &str) -> Result<Zeroizing<String>> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(out) = std::process::Command::new("systemd-ask-password")
            .arg("--timeout=0")
            .arg(prompt)
            .output()
        {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout).trim_end().to_string();
                if !text.is_empty() {
                    return Ok(Zeroizing::new(text));
                }
            }
        }
    }
    let pw = rpassword::prompt_password(prompt).context("读取主密码失败")?;
    if pw.is_empty() {
        return Err(anyhow!("主密码不能为空"));
    }
    Ok(Zeroizing::new(pw))
}

/// 读取需要二次确认的主密码（仅在首次设置时使用）。
pub fn read_new_password(prompt: &str) -> Result<Zeroizing<String>> {
    let first = read_password(prompt)?;
    let second = read_password("再次输入以确认: ")?;
    if *first != *second {
        return Err(anyhow!("两次输入的主密码不一致"));
    }
    Ok(first)
}

/// 读取 master_key（隐藏输入）。
pub fn read_master_key(prompt: &str) -> Result<Zeroizing<String>> {
    let value = rpassword::prompt_password(prompt).context("读取 master_key 失败")?;
    if value.trim().is_empty() {
        return Err(anyhow!("master_key 不能为空"));
    }
    Ok(Zeroizing::new(value))
}

/// 移除主密码前的两次确认（必须两次都输入 `yes`）。
///
/// 删除服务端包裹会让未持有 local.key 的设备永久无法解出 master_key，
/// 因此要求显式、重复确认，而不是单次回车。
pub fn confirm_remove_password() -> Result<()> {
    let first = read_password("确认移除主密码（输入 yes）: ")?;
    if first.trim() != "yes" {
        return Err(anyhow!("未输入 yes，已取消"));
    }
    let second = read_password("再次确认移除主密码（输入 yes）: ")?;
    if second.trim() != "yes" {
        return Err(anyhow!("两次确认不一致，已取消"));
    }
    Ok(())
}

fn chrono_like_counter() -> u128 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    nanos ^ u128::from(n)
}
