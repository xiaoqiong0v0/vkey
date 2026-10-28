package dev.xiaoqiong.vkey.vault

/**
 * RFC 4648 Base32（无填充、大小写不敏感）编解码。
 *
 * vkey 约定：`master_key`（32B）的恢复码是它的 Base32 大写无填充形式，长度固定 52 字符。
 */
object Base32 {

    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    /** 把字节数组编码为 Base32 字符串（无 `=` 填充，大写）。 */
    fun encode(data: ByteArray): String {
        val sb = StringBuilder((data.size * 8 + 4) / 5)
        var buffer = 0
        var bits = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                bits -= 5
                sb.append(ALPHABET[(buffer shr bits) and 0x1F])
            }
        }
        if (bits > 0) {
            sb.append(ALPHABET[(buffer shl (5 - bits)) and 0x1F])
        }
        return sb.toString()
    }

    /**
     * 解码 Base32 字符串。
     *
     * 容错：忽略空格、`-`、`=` 与换行；小写自动转大写。
     *
     * @return 解码后的字节数组；出现非法字符时返回 null
     */
    fun decode(input: String): ByteArray? {
        val cleaned = input.filterNot { it.isWhitespace() || it == '-' || it == '=' }.uppercase()
        if (cleaned.isEmpty()) return null
        val out = ArrayList<Byte>(cleaned.length * 5 / 8 + 1)
        var buffer = 0
        var bits = 0
        for (ch in cleaned) {
            val v = ALPHABET.indexOf(ch)
            if (v < 0) return null
            buffer = (buffer shl 5) or v
            bits += 5
            if (bits >= 8) {
                bits -= 8
                out.add(((buffer shr bits) and 0xFF).toByte())
            }
        }
        return out.toByteArray()
    }
}
