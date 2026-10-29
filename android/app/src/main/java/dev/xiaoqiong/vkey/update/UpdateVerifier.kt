package dev.xiaoqiong.vkey.update

import java.io.File
import java.security.MessageDigest

/**
 * 更新包的纯 JVM 校验逻辑（版本比较 / SHA-256 / 证书指纹），便于单元测试。
 *
 * 不依赖 Android API；APK 签名证书的提取见 [ApkVerifier]。
 */
object UpdateVerifier {

    /** 允许安装的 APK 签名证书 SHA-256 指纹（64 位小写 hex）。 */
    const val TRUSTED_CERT_SHA256: String =
        "192d42bd1f1a26d6f79db047d2e2ec44ee752d9981b90d505d92d7a4c887e87c"

    private const val HEX_PAD = 2
    private const val BUFFER_BYTES = 64 * 1024

    /**
     * 远端版本是否比本地新（严格大于才算更新）。
     *
     * @param remote 服务端 versionCode
     * @param current 本地 `BuildConfig.VERSION_CODE`
     * @return 更高时返回 true；相等或更低返回 false
     */
    fun isNewer(remote: Long, current: Long): Boolean = remote > current

    /** 字节数组的 SHA-256，输出小写 hex。 */
    fun sha256Hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return hex(digest)
    }

    /**
     * 文件的 SHA-256（流式计算，适合几十 MB 的 APK）。
     *
     * @param file 目标文件
     * @return 64 位小写 hex
     */
    fun fileSha256Hex(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(BUFFER_BYTES)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        return hex(digest.digest())
    }

    /**
     * 比较两个 SHA-256 文本（大小写不敏感，忽略首尾空白）。
     *
     * 期望值必须是 64 位 hex，否则直接判失败（防止服务端给空串时被误判为匹配）。
     *
     * @param expected 服务端下发的值
     * @param actual 本地计算结果
     * @return 均为 64 位 hex 且内容一致时返回 true
     */
    fun matchesSha256(expected: String, actual: String): Boolean {
        val normalizedExpected = expected.trim()
        if (normalizedExpected.length != SHA256_HEX_LEN) return false
        return normalizedExpected.equals(actual.trim(), ignoreCase = true)
    }

    /** 字节 → 小写 hex。 */
    private fun hex(bytes: ByteArray): String {
        val out = StringBuilder(bytes.size * HEX_PAD)
        for (byte in bytes) {
            val value = byte.toInt() and 0xFF
            out.append(HEX_DIGITS[value ushr 4])
            out.append(HEX_DIGITS[value and 0x0F])
        }
        return out.toString()
    }

    private const val SHA256_HEX_LEN = 64
    private const val HEX_DIGITS = "0123456789abcdef"
}
