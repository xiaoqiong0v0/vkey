package cn.xiaoqiong0v0.vkey.totp

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * 功能：RFC 6238 TOTP 生成（配合 RFC 4226 HOTP 动态截断）。
 * 说明：只用 JCA 的 HmacSHA1/SHA256/SHA512，不引入 BouncyCastle。
 */
object Totp {

    /** 默认时间步长（秒） */
    const val DEFAULT_PERIOD: Int = 30

    /** 默认验证码位数 */
    const val DEFAULT_DIGITS: Int = 6

    /**
     * 功能：生成当前时间步的验证码。
     * @param secret 已解码的密钥字节
     * @param epochMillis 当前时间（毫秒）
     * @param digits 位数（6 或 8）
     * @param period 时间步长（秒）
     * @param algorithm 算法名（SHA1 / SHA256 / SHA512）
     * @return 定长数字字符串（左侧补 0）
     */
    fun generate(
        secret: ByteArray,
        epochMillis: Long,
        digits: Int = DEFAULT_DIGITS,
        period: Int = DEFAULT_PERIOD,
        algorithm: String = "SHA1",
    ): String {
        val counter = counterFor(epochMillis, period)
        return hotp(secret, counter, digits, algorithm)
    }

    /**
     * 功能：把毫秒时间换算为时间步计数器。
     * @param epochMillis 当前时间（毫秒）
     * @param period 时间步长（秒）
     * @return 计数器（自 epoch 起的步数）
     */
    fun counterFor(epochMillis: Long, period: Int = DEFAULT_PERIOD): Long =
        epochMillis / 1000L / period

    /**
     * 功能：当前步剩余秒数（1..period）。
     * @param epochMillis 当前时间（毫秒）
     * @param period 时间步长（秒）
     * @return 剩余秒数
     */
    fun remainingSeconds(epochMillis: Long, period: Int = DEFAULT_PERIOD): Int {
        val elapsed = (epochMillis / 1000L) % period
        return (period - elapsed).toInt()
    }

    /**
     * 功能：计算 HOTP 值（RFC 4226）。
     * @param secret 密钥字节
     * @param counter 计数器
     * @param digits 位数
     * @param algorithm 算法名
     * @return 定长数字字符串
     */
    fun hotp(secret: ByteArray, counter: Long, digits: Int, algorithm: String): String {
        val macName: String = when (algorithm.uppercase()) {
            "SHA1" -> "HmacSHA1"
            "SHA256" -> "HmacSHA256"
            "SHA512" -> "HmacSHA512"
            else -> throw IllegalArgumentException("不支持的算法：$algorithm")
        }
        val mac = Mac.getInstance(macName)
        mac.init(SecretKeySpec(secret, macName))

        // 计数器按大端序写成 8 字节
        val message = ByteArray(8)
        var value = counter
        for (i in 7 downTo 0) {
            message[i] = (value and 0xFF).toByte()
            value = value ushr 8
        }

        val hash = mac.doFinal(message)
        val offset = hash[hash.size - 1].toInt() and 0x0F
        val binary = ((hash[offset].toInt() and 0x7F) shl 24) or
            ((hash[offset + 1].toInt() and 0xFF) shl 16) or
            ((hash[offset + 2].toInt() and 0xFF) shl 8) or
            (hash[offset + 3].toInt() and 0xFF)
        val modulus = MODULUS[digits] ?: pow10(digits)
        return (binary % modulus).toString().padStart(digits, '0')
    }

    /** 常用位数对应的 10^n 查表 */
    private val MODULUS: Map<Int, Int> = mapOf(
        1 to 10,
        2 to 100,
        3 to 1_000,
        4 to 10_000,
        5 to 100_000,
        6 to 1_000_000,
        7 to 10_000_000,
        8 to 100_000_000,
    )

    /** 功能：计算 10 的 n 次方（兜底非常用位数）。 */
    private fun pow10(n: Int): Int {
        var result = 1
        repeat(n) { result *= 10 }
        return result
    }
}
