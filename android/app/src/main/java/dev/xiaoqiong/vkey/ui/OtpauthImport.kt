package dev.xiaoqiong.vkey.ui

import dev.xiaoqiong.vkey.sync.ItemJson
import dev.xiaoqiong.vkey.vault.Otpauth
import dev.xiaoqiong.vkey.vault.TotpItem

/** 注释行前缀：`#` 开头（trim 之后判断）的行整行跳过，不计数。 */
private const val COMMENT_PREFIX = "#"

/** 不支持的类型：`otpauth://hotp/…` 明确跳过并单独计数（HOTP 是计数器型，本应用只存 TOTP）。 */
private const val HOTP_PREFIX = "otpauth://hotp/"

/** UTF-8 BOM：部分导出工具会带上，必须剥掉，否则第一行会被判成「无法识别」。 */
private const val BOM = '\uFEFF'

/** 单行最大长度：超长行按「无法识别」处理（正常 otpauth URI 远小于此，防止异常输入拖慢解析）。 */
internal const val MAX_IMPORT_LINE_LENGTH = 4096

/**
 * 一次导入解析的统计结果。
 *
 * @property items 可导入的条目（已排除重复与不支持的类型）
 * @property duplicates 与库中（或同批前面已接受的行）重复的条数
 * @property hotpSkipped `otpauth://hotp/…` 被明确跳过的条数
 * @property invalid 无法识别（不是 TOTP otpauth URI / 超长行）的行数
 */
data class ImportResult(
    val items: List<TotpItem> = emptyList(),
    val duplicates: Int = 0,
    val hotpSkipped: Int = 0,
    val invalid: Int = 0,
) {
    /** 共识别 = 可导入 + 重复 + 不支持 HOTP（无法识别的行不计入「识别」）。 */
    val recognized: Int get() = items.size + duplicates + hotpSkipped
}

/**
 * 解析导入文本（纯函数，便于单测；不做任何 IO / 日志）。
 *
 * 规则：
 * - 按行处理（兼容 `\n` / `\r\n` / `\r`），逐行 trim；
 * - 空行与 `#` 注释行跳过，不计入任何统计；
 * - `otpauth://hotp/…` 明确跳过，计入 [ImportResult.hotpSkipped]；
 * - 其余行交给 [Otpauth.parse]；解析失败（含超长行）计入 [ImportResult.invalid]，不影响其它行；
 * - 重复判定：issuer + account（即 URI 里的 label）+ secret 三者忽略大小写相同即视为重复。
 *   比较对象为库中**未删除的 TOTP 条目**；同一批文本里先出现的行同样参与判定，
 *   避免同一份文件里的重复行被导入两次。
 *
 * 注意：解析结果的 secret 是明文，调用方不得写日志 / 缓存文件。
 *
 * @param text 待解析文本（文件内容或粘贴内容）
 * @param existing 现有库条目（用于重复判定）
 * @return 解析与去重后的统计结果
 */
fun parseOtpauthImport(text: String, existing: List<TotpItem> = emptyList()): ImportResult {
    val seen = existing.asSequence()
        .filter { it.kind == ItemJson.KIND_TOTP && !it.deleted }
        .mapTo(HashSet()) { DuplicateKey.of(it.issuer, it.account, it.secret) }

    val items = mutableListOf<TotpItem>()
    var duplicates = 0
    var hotpSkipped = 0
    var invalid = 0

    for (rawLine in text.removePrefix(BOM.toString()).lineSequence()) {
        val line = rawLine.trim()
        if (line.isEmpty() || line.startsWith(COMMENT_PREFIX)) continue
        if (line.length > MAX_IMPORT_LINE_LENGTH) {
            invalid++
            continue
        }
        if (line.startsWith(HOTP_PREFIX, ignoreCase = true)) {
            hotpSkipped++
            continue
        }
        val entry = Otpauth.parse(line)
        if (entry == null) {
            invalid++
            continue
        }
        val key = DuplicateKey.of(entry.issuer, entry.account, entry.item.secret)
        if (!seen.add(key)) {
            duplicates++
        } else {
            items += entry.item
        }
    }
    return ImportResult(
        items = items,
        duplicates = duplicates,
        hotpSkipped = hotpSkipped,
        invalid = invalid,
    )
}

/** 重复判定键：三个字段都 trim + 转小写后比较。 */
private data class DuplicateKey(val issuer: String, val account: String, val secret: String) {
    companion object {
        fun of(issuer: String, account: String, secret: String): DuplicateKey = DuplicateKey(
            issuer = issuer.trim().lowercase(),
            account = account.trim().lowercase(),
            secret = secret.trim().lowercase(),
        )
    }
}
