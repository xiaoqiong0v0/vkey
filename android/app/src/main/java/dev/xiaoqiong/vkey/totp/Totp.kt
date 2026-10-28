package dev.xiaoqiong.vkey.totp

import dev.xiaoqiong.vkey.vault.Base32
import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** RFC 6238 TOTP 计算（HOTP 部分按 RFC 4226）。 */
object Totp {

    /**
     * 计算指定时刻的验证码。
     *
     * @param secretBase32 Base32 编码的共享密钥
     * @param timestampSeconds 当前时间（unix 秒）
     * @param digits 位数（6/7/8）
     * @param period 步长秒数（默认 30）
     * @param algorithm HMAC 算法：SHA1 / SHA256 / SHA512
     * @return 验证码字符串；参数非法时返回 null
     */
    fun code(
        secretBase32: String,
        timestampSeconds: Long,
        digits: Int = 6,
        period: Int = 30,
        algorithm: String = "SHA1",
    ): String? {
        val key = Base32.decode(secretBase32) ?: return null
        if (key.isEmpty() || period <= 0 || digits <= 0) return null
        val counter = timestampSeconds / period
        val macName = when (algorithm.uppercase()) {
            "SHA1" -> "HmacSHA1"
            "SHA256" -> "HmacSHA256"
            "SHA512" -> "HmacSHA512"
            else -> return null
        }
        val mac = Mac.getInstance(macName)
        mac.init(SecretKeySpec(key, macName))
        val hash = mac.doFinal(ByteBuffer.allocate(8).putLong(counter).array())

        // 动态截断（RFC 4226 §5.3）
        val offset = hash[hash.size - 1].toInt() and 0x0F
        val binary = ((hash[offset].toInt() and 0x7F) shl 24) or
            ((hash[offset + 1].toInt() and 0xFF) shl 16) or
            ((hash[offset + 2].toInt() and 0xFF) shl 8) or
            (hash[offset + 3].toInt() and 0xFF)
        val mod = intPow10(digits)
        return (binary % mod).toString().padStart(digits, '0')
    }

    /** 当前步长内剩余秒数。 */
    fun remainingSeconds(timestampSeconds: Long, period: Int = 30): Int {
        if (period <= 0) return 0
        val rem = (timestampSeconds % period).toInt()
        return period - rem
    }

    private fun intPow10(n: Int): Int {
        var v = 1
        repeat(n) { v *= 10 }
        return v
    }
}
