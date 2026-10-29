package dev.xiaoqiong.vkey.sync

import dev.xiaoqiong.vkey.vault.Base32
import java.net.URLDecoder

/**
 * 扫码 / 深链识别结果。
 *
 * - [ServerConfig]：服务端 `/pair` 页或主页给出的同步配置二维码（`vkey://config?server=…`），
 *   内容只有服务器地址，不含任何凭据。
 * - [PairCode]：另一台设备生成的配对码（`vkey://pair?code=…` 或裸 52 位 base32）。
 */
sealed interface ScanLink {
    /** 同步配置深链：只带服务器地址。 */
    data class ServerConfig(val serverUrl: String) : ScanLink

    /** 配对码链接或裸配对码。 */
    data class PairCode(val code: String) : ScanLink

    /** 开户码文本（`ENROLL-XXXX-XXXX`，服务端管理员签发）。 */
    data class EnrollCode(val code: String) : ScanLink
}

/**
 * 深链与配对码文本解析（纯 JVM，便于单元测试）。
 *
 * 服务端生成的深链形如 `vkey://config?server=https://example.com`，
 * `server` 参数**不做** percent-encode（含 `://`），因此这里按原文取值，
 * 只在遇到 `%` 时才尝试解码一次。
 */
object Links {

    /** 同步配置深链前缀（与服务端 `pair_qr.go` 的 `deepLinkConfigPrefix` 一致）。 */
    const val CONFIG_PREFIX: String = "vkey://config"

    /** 配对码深链前缀。 */
    const val PAIR_PREFIX: String = "vkey://pair"

    /** 配对码 / master_key 均为 32B，base32 无填充后固定 52 字符。 */
    private const val KEY_BYTES = 32
    private const val KEY_CHARS = 52

    /**
     * 开户码格式（与服务端 `policy.EnrollCodePrefix/GroupSize/Groups` 一致）：
     * `ENROLL-` 前缀 + 2 组各 4 位字母数字；`-` 属格式一部分，比较前只去空白、转大写。
     */
    private val ENROLL_CODE_PATTERN = Regex("^ENROLL-[A-Z0-9]{4}-[A-Z0-9]{4}$")

    private const val PARAM_SERVER = "server"
    private const val PARAM_CODE = "code"

    /**
     * 解析同步配置深链里的服务器地址。
     *
     * @param raw 扫码内容或 intent data 原文
     * @return 合法的 `http(s)://` 地址；不是配置深链或地址非法时返回 null
     */
    fun parseServerConfig(raw: String): String? {
        val text = raw.trim()
        if (!text.startsWith(CONFIG_PREFIX, ignoreCase = true)) return null
        val rest = text.substring(CONFIG_PREFIX.length)
        // 允许 `vkey://config?…`、`vkey://config/?…` 与无参数形式
        if (rest.isNotEmpty() && rest[0] != '?' && rest[0] != '/' && rest[0] != '#') return null
        val query = rest.substringAfter('?', "")
        val server = queryParam(query, PARAM_SERVER)?.let(::decodeQueryValue)?.trim()
        if (server.isNullOrEmpty()) return null
        val lower = server.lowercase()
        if (!lower.startsWith("http://") && !lower.startsWith("https://")) return null
        return server
    }

    /**
     * 解析配对码深链 `vkey://pair?code=…`。
     *
     * @param raw 扫码内容原文
     * @return 规范化前的坐标（可能带 `-` 分组）；非配对深链或码非法时返回 null
     */
    fun parsePairCodeLink(raw: String): String? {
        val text = raw.trim()
        if (!text.startsWith(PAIR_PREFIX, ignoreCase = true)) return null
        val rest = text.substring(PAIR_PREFIX.length)
        if (rest.isNotEmpty() && rest[0] != '?' && rest[0] != '/' && rest[0] != '#') return null
        val code = queryParam(rest.substringAfter('?', ""), PARAM_CODE)?.let(::decodeQueryValue)?.trim()
        return code?.takeIf(::isPairCodeText)
    }

    /**
     * 识别裸配对码（用户从别的设备抄下来、直接贴过来的 52 位 base32）。
     *
     * @param raw 文本原文（可含空格 / `-` / 小写 / `=` 填充）
     * @return 原文（交给服务端与 [dev.xiaoqiong.vkey.crypto.Crypto.parsePairCode] 再规范化）；
     *         不是 32B 配对码时返回 null
     */
    fun parseBarePairCode(raw: String): String? {
        val text = raw.trim()
        if (text.isEmpty()) return null
        if (text.contains("://")) return null
        return text.takeIf(::isPairCodeText)
    }

    /**
     * 解析开户码文本（`ENROLL-XXXX-XXXX`）。
     *
     * 与服务端 `NormalizeEnrollCode` 同规则：去空白、转大写（组内 `-` 保留）。
     * 容忍用户粘贴带空格或小写的码。
     *
     * @param raw 用户输入或扫码原文
     * @return 规范形式 `ENROLL-XXXX-XXXX`；格式不符时返回 null
     */
    fun parseEnrollCode(raw: String): String? {
        val text = raw.trim()
        if (text.isEmpty() || text.contains("://")) return null
        val normalized = text.filterNot { it.isWhitespace() }.uppercase()
        return normalized.takeIf { ENROLL_CODE_PATTERN.matches(it) }
    }

    /**
     * 按「配置深链 → 配对码深链 → 开户码 → 裸配对码」的顺序识别扫码内容。
     *
     * @param raw 扫码内容原文
     * @return 识别结果；都不是时返回 null（调用方再尝试 `otpauth://`）
     */
    fun classify(raw: String): ScanLink? {
        parseServerConfig(raw)?.let { return ScanLink.ServerConfig(it) }
        parsePairCodeLink(raw)?.let { return ScanLink.PairCode(it) }
        parseEnrollCode(raw)?.let { return ScanLink.EnrollCode(it) }
        parseBarePairCode(raw)?.let { return ScanLink.PairCode(it) }
        return null
    }

    // ------------------------------------------------------------------
    // 私有实现
    // ------------------------------------------------------------------

    /** 判断文本是否恰好是 32B 的 base32（容忍分组符/空白/填充/小写）。 */
    private fun isPairCodeText(text: String): Boolean {
        val cleaned = text.filterNot { it.isWhitespace() || it == '-' || it == '=' }
        if (cleaned.length != KEY_CHARS) return false
        return Base32.decode(cleaned)?.size == KEY_BYTES
    }

    /** 从查询串里取第一个同名参数的值（未解码，可能为空串）。 */
    private fun queryParam(query: String, name: String): String? {
        if (query.isEmpty()) return null
        for (part in query.split('&')) {
            if (part.isEmpty()) continue
            val key = part.substringBefore('=')
            if (key != name) continue
            return part.substringAfter('=', "")
        }
        return null
    }

    /** 只在出现 `%` 时按 URL 规则解码，避免把 `+` 误当空格。 */
    private fun decodeQueryValue(value: String): String {
        if (!value.contains('%')) return value
        return try {
            URLDecoder.decode(value, "UTF-8")
        } catch (e: IllegalArgumentException) {
            value
        }
    }
}
