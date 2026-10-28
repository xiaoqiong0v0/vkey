package dev.xiaoqiong.vkey.vault

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** WebAuthn 条目的 `kind`（与 `sync.ItemJson.KIND_WEBAUTHN` 一致；vault 层不反向依赖 sync 包）。 */
private const val KIND_WEBAUTHN: String = "webauthn"

/**
 * 单条 TOTP 条目（与 shared/protocol.md 的条目明文结构对齐，本轮只用 totp）。
 *
 * 同步字段（M3.2）说明：
 * - [version] 是**服务端**版本号，0 表示服务端还没有这条（需要新建）；
 * - [updatedAt] 是本机写入时间（unix 秒），作为 LWW 的 `updated_at`；
 * - [syncedUpdatedAt] 是上一次推送成功时的 [updatedAt]，用于判断「自上次同步后有没有改过」；
 * - [deleted] 是墓碑标记：本地隐藏，条目保留，下次同步推送 `deleted_at`。
 *
 * 旧 vault 没有这些字段，靠默认值兼容（`version=0` 的条目会在首次同步时按新建推送）。
 */
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
    /** 服务端版本号；0 = 服务端尚无此条目。 */
    val version: Long = 0L,
    /** 本机最后写入时间（unix 秒）；0 = 未知，推送时用当前时间补。 */
    val updatedAt: Long = 0L,
    /** 上次推送成功时的 [updatedAt]；`updatedAt > syncedUpdatedAt` 表示有本地改动待推。 */
    val syncedUpdatedAt: Long = 0L,
    /** 墓碑标记：true 时 UI 不显示，同步时推送 `deleted_at`。 */
    val deleted: Boolean = false,
    /**
     * 条目明文里未识别的 JSON 字段（协议 §5 要求客户端往返保留未知字段）。
     * 推送时原样回填，不被本地模型丢弃。
     */
    val extras: JsonObject? = null,
)

/**
 * 单条 WebAuthn 凭据（对应 `shared/examples/item-webauthn.json`）。
 *
 * 手机端**只读 + 可吊销**：不新增、不修改，明文里只保留用于展示的
 * `rp_id` / `username` / `display_name` / `label` / `user_handle` / `created_at`，
 * 私钥、`credential_id` 等字段不落本地模型。
 *
 * 同步字段与 [TotpItem] 同义：
 * - [version] 服务端版本号；
 * - [updatedAt] 本机最后写入时间（吊销时写入）；
 * - [syncedUpdatedAt] 上次吊销推送成功的时间；
 * - [deleted] 墓碑：用户显式吊销后置 true，下一次同步推送删除；UI 不展示。
 *
 * 旧 vault 没有该列表，靠 [VaultData.webAuthn] 的默认空列表兼容。
 */
@Serializable
data class WebAuthnItem(
    val id: String,
    val kind: String = KIND_WEBAUTHN,
    /** 依赖方标识（站点域名），明文里的 `rp_id`。 */
    val rpId: String = "",
    /** 账号名，明文里的 `username`。 */
    val username: String = "",
    /** 展示名，明文里的 `display_name`。 */
    val displayName: String = "",
    /** 列表主标题，明文里的 `label`（WebAuthn 为用户名或 RP）。 */
    val label: String = "",
    /** WebAuthn `user.id` 原始字节的 base64url，明文里的 `user_handle`（仅展示/区分，不含私钥）。 */
    val userHandle: String = "",
    /** 凭据创建时间（unix 秒），明文里的 `created_at`。 */
    val createdAt: Long = 0L,
    /** 服务端版本号；0 = 服务端尚无此条目。 */
    val version: Long = 0L,
    /** 本机最后写入时间（unix 秒）；吊销时更新。 */
    val updatedAt: Long = 0L,
    /** 上次吊销推送成功时的 [updatedAt]。 */
    val syncedUpdatedAt: Long = 0L,
    /** 墓碑标记：true 时 UI 不显示，同步时推送 `deleted_at`。 */
    val deleted: Boolean = false,
)

/** 解密后的库内容。 */
@Serializable
data class VaultData(
    /** 账号级 32B 主密钥，Base32 无填充（52 字符） */
    val master_key: String,
    val items: List<TotpItem> = emptyList(),
    /** WebAuthn 凭据（桌面端虚拟密钥），手机只读/可吊销。 */
    val webAuthn: List<WebAuthnItem> = emptyList(),
    /** 同步设备材料；null 表示本机尚未完成同步配置（未登录）。 */
    val device: DeviceConfig? = null,
    /** 已同步到的服务端 version（`GET /items?since=` 的游标）。 */
    val seq: Long = 0L,
    /** 最近一次同步完成时间（unix 秒）；0 = 从未同步。 */
    val lastSyncAt: Long = 0L,
)

/**
 * 把旧版本误并入 [VaultData.items] 的 WebAuthn 条目迁移到独立的 [VaultData.webAuthn]。
 *
 * 旧版同步不区分 `kind`，把服务端的 webauthn 凭据当 TOTP 存进 `items`；这些条目再次
 * 推送会触发 `kind_mismatch` 冲突，也会在「2FA」页里显示成没有密钥的空条目。
 * 展示字段从旧条目保留的 [TotpItem.extras]（明文里未识别的字段）里取回。
 *
 * @return 迁移后的库；没有旧数据时原样返回
 */
fun VaultData.withLegacyWebAuthnMigrated(): VaultData {
    if (items.none { it.kind == KIND_WEBAUTHN }) return this
    val moved = items.filter { it.kind == KIND_WEBAUTHN }.map { it.toWebAuthnItem() }
    val retained = items.filter { it.kind != KIND_WEBAUTHN }
    val existingIds = webAuthn.mapTo(HashSet()) { it.id }
    return copy(
        items = retained,
        webAuthn = webAuthn + moved.filterNot { it.id in existingIds },
    )
}

/** 旧 TOTP 模型里的 webauthn 条目转成只读模型。 */
private fun TotpItem.toWebAuthnItem(): WebAuthnItem = WebAuthnItem(
    id = id,
    rpId = extras?.string("rp_id").orEmpty(),
    username = extras?.string("username").orEmpty(),
    displayName = extras?.string("display_name").orEmpty(),
    createdAt = created_at,
    version = version,
    updatedAt = updatedAt,
    syncedUpdatedAt = syncedUpdatedAt,
    deleted = deleted,
)

/** 读取 extras 里的字符串字段；缺失或类型不符返回 null。 */
private fun JsonObject.string(key: String): String? =
    (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

/** 磁盘上的密封结构：`nonce` 为 12B IV 的 base64，`ct` 为 AES-256-GCM 密文 base64。 */
@Serializable
data class SealedVault(
    val v: Int = 1,
    val nonce: String,
    val ct: String,
)
