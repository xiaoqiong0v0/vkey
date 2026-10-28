package cn.xiaoqiong0v0.vkey.vault

/**
 * 功能：RFC 4648 Base32 编解码（无填充字符，大小写不敏感）。
 * 说明：TOTP secret 与恢复码都以 Base32 表示；32 字节密钥编码后正好 52 个字符。
 */
object Base32 {

    /** Base32 字母表（RFC 4648，无 0/1/8/9，避免手抄歧义） */
    private const val ALPHABET: String = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    /** 合法编码长度对 8 取模的余数集合（无填充时只可能是这几种） */
    private val VALID_REMAINDERS: Set<Int> = setOf(0, 2, 4, 5, 7)

    /**
     * 功能：把字节数组编码为 Base32 字符串（大写、无 `=` 填充）。
     * @param data 待编码字节
     * @return Base32 字符串
     */
    fun encode(data: ByteArray): String {
        val out = StringBuilder((data.size * 8 + 4) / 5)
        var buffer = 0
        var bitsLeft = 0
        for (byte in data) {
            buffer = (buffer shl 8) or (byte.toInt() and 0xFF)
            bitsLeft += 8
            while (bitsLeft >= 5) {
                out.append(ALPHABET[(buffer shr (bitsLeft - 5)) and 0x1F])
                bitsLeft -= 5
            }
        }
        // 末尾不足 5 位的部分左对齐补齐
        if (bitsLeft > 0) {
            out.append(ALPHABET[(buffer shl (5 - bitsLeft)) and 0x1F])
        }
        return out.toString()
    }

    /**
     * 功能：把 Base32 字符串解码为字节数组。
     * 说明：忽略空白、`-` 与 `=`，大小写不敏感；非法字符将抛出 IllegalArgumentException。
     * @param input 用户输入或磁盘读出的 Base32 文本
     * @return 解码后的字节
     * @throws IllegalArgumentException 输入含非法字符或长度不合法
     */
    fun decode(input: String): ByteArray {
        val cleaned = input.filter { ch ->
            !ch.isWhitespace() && ch != '-' && ch != '='
        }.uppercase()
        require(cleaned.isNotEmpty()) { "Base32 输入为空" }
        require(cleaned.length % 8 in VALID_REMAINDERS) { "Base32 长度不合法：${cleaned.length}" }

        val out = ByteArray(cleaned.length * 5 / 8)
        var buffer = 0
        var bitsLeft = 0
        var index = 0
        for (ch in cleaned) {
            val value = ALPHABET.indexOf(ch)
            require(value >= 0) { "非法 Base32 字符：$ch" }
            buffer = (buffer shl 5) or value
            bitsLeft += 5
            if (bitsLeft >= 8) {
                out[index++] = ((buffer shr (bitsLeft - 8)) and 0xFF).toByte()
                bitsLeft -= 8
            }
            // 丢弃已经无用的高位，避免 Int 溢出
            if (bitsLeft < 32) {
                buffer = buffer and ((1 shl bitsLeft) - 1)
            }
        }
        return out
    }

    /**
     * 功能：把 Base32 文本按固定字符数分组（便于用户抄写与核对）。
     * @param text 原始 Base32 文本
     * @param groupSize 每组字符数
     * @return 以空格分隔的分组文本
     */
    fun group(text: String, groupSize: Int = 4): String =
        text.chunked(groupSize).joinToString(" ")
}
