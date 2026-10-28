package dev.xiaoqiong.vkey.vault

import java.net.URLDecoder
import java.util.UUID

/** `otpauth://` 解析结果（只保留 TOTP 需要的字段）。 */
data class OtpauthEntry(
    val issuer: String,
    val account: String,
    val item: TotpItem,
)

/**
 * 解析 `otpauth://totp/...` URI（RFC 标准格式，Google Authenticator 兼容）。
 *
 * 支持：
 * `otpauth://totp/Issuer:account?secret=BASE32&issuer=Issuer&algorithm=SHA1&digits=6&period=30`
 *
 * @return 解析结果；不是 TOTP 或缺少 secret 时返回 null
 */
object Otpauth {

    fun parse(raw: String): OtpauthEntry? {
        val text = raw.trim()
        if (!text.startsWith("otpauth://", ignoreCase = true)) return null

        val uri = try {
            java.net.URI(text)
        } catch (e: Exception) {
            return null
        }
        val type = uri.host?.lowercase() ?: return null
        if (type != "totp") return null

        val label = uri.path?.trimStart('/')?.let { URLDecoder.decode(it, "UTF-8") } ?: ""
        val query = parseQuery(uri.rawQuery)
        val secret = query["secret"]?.trim()?.uppercase()?.replace(" ", "")
        if (secret.isNullOrEmpty()) return null
        // 校验 Base32 合法性（失败说明二维码内容损坏）
        if (Base32.decode(secret) == null) return null

        val labelIssuer = if (label.contains(':')) label.substringBefore(':').trim() else ""
        val labelAccount = if (label.contains(':')) label.substringAfter(':').trim() else label.trim()
        val issuer = query["issuer"]?.let { URLDecoder.decode(it, "UTF-8") }.orEmpty().ifBlank { labelIssuer }

        val algorithm = (query["algorithm"] ?: "SHA1").uppercase().let {
            if (it in setOf("SHA1", "SHA256", "SHA512")) it else "SHA1"
        }
        val digits = (query["digits"]?.toIntOrNull() ?: 6).coerceIn(6, 8)
        val period = (query["period"]?.toIntOrNull() ?: 30).coerceIn(1, 300)

        val item = TotpItem(
            id = UUID.randomUUID().toString(),
            issuer = issuer,
            account = labelAccount,
            secret = secret,
            algorithm = algorithm,
            digits = digits,
            period = period,
            created_at = System.currentTimeMillis() / 1000,
        )
        return OtpauthEntry(issuer = issuer, account = labelAccount, item = item)
    }

    private fun parseQuery(rawQuery: String?): Map<String, String> {
        if (rawQuery.isNullOrBlank()) return emptyMap()
        return rawQuery.split('&').mapNotNull { pair ->
            val idx = pair.indexOf('=')
            if (idx <= 0) null else pair.substring(0, idx).lowercase() to pair.substring(idx + 1)
        }.toMap()
    }
}
