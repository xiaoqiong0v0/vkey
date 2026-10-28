package dev.xiaoqiong.vkey.sync

import dev.xiaoqiong.vkey.vault.TotpItem
import dev.xiaoqiong.vkey.vault.WebAuthnItem
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put

/**
 * 条目明文 JSON 的编解码（`shared/protocol.md` §5.1 /
 * `shared/examples/item-totp.json` / `shared/examples/item-webauthn.json`）。
 *
 * TOTP 字段名严格照示例：`kind / label / issuer / secret / algorithm / digits / period /
 * notes / created_at / updated_at`。本地模型里叫 `account` 的字段对应明文里的 `label`；
 * 其余未识别的字段（如 `notes`）收进 [TotpItem.extras]，推送时原样回填，
 * 满足协议「客户端必须保留未知字段」的要求。
 *
 * WebAuthn 条目本机只读（不新增/不修改），因此只需要从明文里取出展示字段：
 * `rp_id / username / display_name / created_at`。
 */
object ItemJson {

    /** TOTP 条目的 `kind` 取值。 */
    const val KIND_TOTP: String = "totp"

    /** WebAuthn 条目的 `kind` 取值。 */
    const val KIND_WEBAUTHN: String = "webauthn"

    private const val KEY_KIND = "kind"
    private const val KEY_RP_ID = "rp_id"
    private const val KEY_USERNAME = "username"
    private const val KEY_DISPLAY_NAME = "display_name"
    private const val KEY_LABEL = "label"
    private const val KEY_ISSUER = "issuer"
    private const val KEY_SECRET = "secret"
    private const val KEY_ALGORITHM = "algorithm"
    private const val KEY_DIGITS = "digits"
    private const val KEY_PERIOD = "period"
    private const val KEY_CREATED_AT = "created_at"
    private const val KEY_UPDATED_AT = "updated_at"

    private const val DEFAULT_ALGORITHM = "SHA1"
    private const val DEFAULT_DIGITS = 6
    private const val DEFAULT_PERIOD = 30

    /** 已识别的键集合；不在其中的键一律进 [TotpItem.extras]。 */
    private val KNOWN_KEYS: Set<String> = setOf(
        KEY_KIND, KEY_LABEL, KEY_ISSUER, KEY_SECRET, KEY_ALGORITHM,
        KEY_DIGITS, KEY_PERIOD, KEY_CREATED_AT, KEY_UPDATED_AT,
    )

    /**
     * 把本地条目序列化为条目明文 JSON。
     *
     * @param item 待序列化的条目
     * @return UTF-8 JSON 文本（字段顺序：未知字段 → 已知字段）
     */
    fun encode(item: TotpItem): String {
        val obj = buildJsonObject {
            item.extras?.forEach { (key, value) ->
                if (key !in KNOWN_KEYS) put(key, value)
            }
            put(KEY_KIND, item.kind)
            put(KEY_LABEL, item.account)
            put(KEY_ISSUER, item.issuer)
            put(KEY_SECRET, item.secret)
            put(KEY_ALGORITHM, item.algorithm)
            put(KEY_DIGITS, item.digits)
            put(KEY_PERIOD, item.period)
            if (item.created_at > 0L) put(KEY_CREATED_AT, item.created_at)
            if (item.updatedAt > 0L) put(KEY_UPDATED_AT, item.updatedAt)
        }
        return obj.toString()
    }

    /**
     * 解析条目明文 JSON，并套上外层同步字段。
     *
     * @param plaintext `ct` 解密后的 UTF-8 JSON
     * @param id 外层条目 id（明文里没有 id）
     * @param version 外层 `version`
     * @param updatedAt 外层 `updated_at`（同步时钟）
     * @param deleted 外层是否墓碑
     * @return 本地条目；缺省字段按协议默认值补齐
     * @throws IllegalArgumentException 明文不是合法 JSON 对象时
     */
    fun decode(
        plaintext: String,
        id: String,
        version: Long,
        updatedAt: Long,
        deleted: Boolean = false,
    ): TotpItem {
        val obj = Json.parseToJsonElement(plaintext).jsonObject
        val extras = obj.filterKeys { it !in KNOWN_KEYS }
            .takeIf { it.isNotEmpty() }
            ?.let { JsonObject(it) }
        return TotpItem(
            id = id,
            kind = obj.string(KEY_KIND) ?: KIND_TOTP,
            issuer = obj.string(KEY_ISSUER).orEmpty(),
            account = obj.string(KEY_LABEL).orEmpty(),
            secret = obj.string(KEY_SECRET).orEmpty(),
            algorithm = obj.string(KEY_ALGORITHM) ?: DEFAULT_ALGORITHM,
            digits = obj.int(KEY_DIGITS) ?: DEFAULT_DIGITS,
            period = obj.int(KEY_PERIOD) ?: DEFAULT_PERIOD,
            created_at = obj.long(KEY_CREATED_AT) ?: 0L,
            version = version,
            updatedAt = updatedAt,
            syncedUpdatedAt = updatedAt,
            deleted = deleted,
            extras = extras,
        )
    }

    /**
     * 只读取条目明文里的 `kind`，不解码整个条目。
     *
     * @param plaintext `ct` 解密后的 UTF-8 JSON
     * @return `kind` 字符串；不是合法 JSON 对象或缺少 `kind` 时返回 null
     */
    fun kindOf(plaintext: String): String? = runCatching {
        Json.parseToJsonElement(plaintext).jsonObject.string(KEY_KIND)
    }.getOrNull()

    /**
     * 解析 WebAuthn 条目明文，并套上外层同步字段。
     *
     * 手机端只读展示，因此丢弃 `credential_id` / `private_key` 等凭据敏感字段，
     * 不写入本地模型，也不参与推送。
     *
     * @param plaintext `ct` 解密后的 UTF-8 JSON
     * @param id 外层条目 id
     * @param version 外层 `version`
     * @param updatedAt 外层 `updated_at`
     * @param deleted 外层是否墓碑
     * @return 本地只读条目；缺省字段按空值补齐
     * @throws IllegalArgumentException 明文不是合法 JSON 对象时
     */
    fun decodeWebAuthn(
        plaintext: String,
        id: String,
        version: Long,
        updatedAt: Long,
        deleted: Boolean = false,
    ): WebAuthnItem {
        val obj = Json.parseToJsonElement(plaintext).jsonObject
        return WebAuthnItem(
            id = id,
            kind = obj.string(KEY_KIND) ?: KIND_WEBAUTHN,
            rpId = obj.string(KEY_RP_ID).orEmpty(),
            username = obj.string(KEY_USERNAME).orEmpty(),
            displayName = obj.string(KEY_DISPLAY_NAME).orEmpty(),
            createdAt = obj.long(KEY_CREATED_AT) ?: 0L,
            version = version,
            updatedAt = updatedAt,
            syncedUpdatedAt = updatedAt,
            deleted = deleted,
        )
    }

    /** 取字符串字段；类型不符或缺失返回 null。 */
    private fun JsonObject.string(key: String): String? =
        (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

    /** 取整数字段（兼容 `30` 与 `30.0` 之外的非法值）；缺失返回 null。 */
    private fun JsonObject.long(key: String): Long? =
        (this[key] as? JsonPrimitive)?.takeIf { !it.isString }?.content?.toLongOrNull()

    /** 取 int 字段。 */
    private fun JsonObject.int(key: String): Int? = long(key)?.toInt()
}
