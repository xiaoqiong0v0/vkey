package dev.xiaoqiong.vkey.ui

import dev.xiaoqiong.vkey.vault.TotpItem
import java.net.URLEncoder

/** otpauth URI 前缀：只导出 TOTP（与 `Otpauth.parse` 的解析范围一致）。 */
private const val OTPAUTH_PREFIX = "otpauth://totp/"

/** issuer 与 label 在 URI 路径里的分隔符（分隔符本身不参与编码）。 */
private const val LABEL_SEPARATOR = ":"

/** 缺省算法（条目字段为空时按 RFC 默认值补）。 */
private const val DEFAULT_ALGORITHM = "SHA1"

/** UTF-8 编码名（`URLEncoder` 的必需参数，Java 保证可用）。 */
private const val CHARSET_UTF8 = "UTF-8"

/**
 * 把一条 TOTP 条目编码成 `otpauth://totp/...` URI（其它验证器可识别的导出格式）。
 *
 * 输出形如：
 * `otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30`
 *
 * 规则：
 * - 路径为 `issuer:label`，两段分别做 URL 编码（空格编码成 `%20`，冒号分隔符保留）；
 * - issuer 为空时路径只放 label，且不输出 `issuer` 查询参数；
 * - label 为空时用 issuer 顶替；
 * - secret 原样输出（仅去空白、转大写、去掉 base32 填充 `=`），不做二次编码（Base32 字符集本身就是 URL 安全的）；
 * - algorithm 统一大写；digits / period 按条目原值。
 *
 * @param item 待导出的条目（只读，不修改）
 * @return 可直接导入其它验证器的 otpauth URI
 */
fun buildOtpauthUri(item: TotpItem): String {
    val issuer = item.issuer.trim()
    val label = item.account.trim().ifBlank { issuer }
    val path = if (issuer.isEmpty()) {
        encodeComponent(label)
    } else {
        encodeComponent(issuer) + LABEL_SEPARATOR + encodeComponent(label)
    }

    val params = buildList {
        add("secret=${normalizeSecret(item.secret)}")
        // issuer 为空时不输出该参数，避免导入端把空串当 issuer
        if (issuer.isNotEmpty()) add("issuer=${encodeComponent(issuer)}")
        add("algorithm=${item.algorithm.trim().ifBlank { DEFAULT_ALGORITHM }.uppercase()}")
        add("digits=${item.digits}")
        add("period=${item.period}")
    }
    return OTPAUTH_PREFIX + path + "?" + params.joinToString("&")
}

/**
 * 编码 URI 组件：`URLEncoder` 按 `application/x-www-form-urlencoded` 把空格转成 `+`，
 * 这里换回 RFC 3986 的 `%20`（多数验证器只认百分号编码）。
 *
 * @param value 原始文本（可为空串）
 * @return 编码后的组件
 */
private fun encodeComponent(value: String): String =
    URLEncoder.encode(value, CHARSET_UTF8).replace("+", "%20")

/**
 * 规范化 Base32 密钥：去掉空白、转大写、去掉尾部填充。
 *
 * @param secret 条目里保存的密钥
 * @return 大写无填充的 Base32（原字符不变）
 */
private fun normalizeSecret(secret: String): String =
    secret.filterNot { it.isWhitespace() }.uppercase().trimEnd('=')
