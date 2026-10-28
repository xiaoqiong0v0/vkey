package dev.xiaoqiong.vkey.vault

import kotlinx.serialization.Serializable

/** 单条 TOTP 条目（与 shared/protocol.md 的条目明文结构对齐，本轮只用 totp）。 */
@Serializable
data class TotpItem(
    val id: String,
    val kind: String = "totp",
    val issuer: String,
    val account: String,
    /** Base32 编码的共享密钥（明文仅存在于解密后的内存与加密后的磁盘） */
    val secret: String,
    val algorithm: String = "SHA1",
    val digits: Int = 6,
    val period: Int = 30,
    val created_at: Long = 0L,
)

/** 解密后的库内容。 */
@Serializable
data class VaultData(
    /** 账号级 32B 主密钥，Base32 无填充（52 字符） */
    val master_key: String,
    val items: List<TotpItem> = emptyList(),
    /** 同步设备材料；null 表示本机尚未完成同步配置（未登录）。 */
    val device: DeviceConfig? = null,
)

/** 磁盘上的密封结构：`nonce` 为 12B IV 的 base64，`ct` 为 AES-256-GCM 密文 base64。 */
@Serializable
data class SealedVault(
    val v: Int = 1,
    val nonce: String,
    val ct: String,
)
