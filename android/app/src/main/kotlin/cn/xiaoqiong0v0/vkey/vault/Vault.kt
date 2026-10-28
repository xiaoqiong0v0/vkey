package cn.xiaoqiong0v0.vkey.vault

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.util.UUID

/**
 * 功能：单条 TOTP 条目（明文模型，只存在于内存或加密后的 vault.json 密文中）。
 * 注意：`secret` 为 Base32 文本，禁止写日志、禁止出现在磁盘明文中。
 */
@Serializable
data class VaultItem(
    /** 条目唯一 id（UUID 字符串） */
    val id: String,
    /** 条目类型，M3.1 只有 "totp" */
    val kind: String = KIND_TOTP,
    /** 发行方（如 GitHub） */
    val issuer: String = "",
    /** 账号（如 user@example.com） */
    val account: String = "",
    /** Base32 编码的共享密钥 */
    val secret: String,
    /** HMAC 算法：SHA1 / SHA256 / SHA512 */
    val algorithm: String = "SHA1",
    /** 验证码位数 */
    val digits: Int = 6,
    /** 时间步长（秒） */
    val period: Int = 30,
    /** 创建时间（Unix 秒） */
    @SerialName("created_at")
    val createdAt: Long = 0L,
) {
    companion object {
        /** 条目类型：TOTP */
        const val KIND_TOTP: String = "totp"

        /**
         * 功能：用用户输入构造一条新条目。
         * @param issuer 发行方
         * @param account 账号
         * @param secretBase32 规范化后的 Base32 密钥
         * @return 新条目（id 与创建时间自动生成）
         */
        fun create(issuer: String, account: String, secretBase32: String): VaultItem = VaultItem(
            id = UUID.randomUUID().toString(),
            kind = KIND_TOTP,
            issuer = issuer.trim(),
            account = account.trim(),
            secret = secretBase32,
            createdAt = System.currentTimeMillis() / 1000L,
        )
    }
}

/**
 * 功能：vault 明文模型（落盘前整体加密）。
 * @property masterKey Base32 主密钥（52 字符），也是用户恢复码的来源
 * @property items 条目列表
 */
@Serializable
data class Vault(
    @SerialName("master_key")
    val masterKey: String,
    val items: List<VaultItem> = emptyList(),
)

/**
 * 功能：vault.json 的外层封装（磁盘上只有这些字段）。
 * @property v 格式版本
 * @property nonce AES-GCM 的随机 IV（Base64）
 * @property ct 密文 + GCM tag（Base64）
 */
@Serializable
data class VaultEnvelope(
    val v: Int = CURRENT_VERSION,
    val nonce: String,
    val ct: String,
) {
    companion object {
        /** 当前落盘格式版本 */
        const val CURRENT_VERSION: Int = 1
    }
}
