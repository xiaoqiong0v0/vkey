package dev.xiaoqiong.vkey.update

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 更新校验的纯逻辑单测：SHA-256（匹配 / 不匹配）、版本比较（更高 / 相等 / 更低）。
 */
class UpdateVerifierTest {

    /** `"abc"` 的标准 SHA-256 向量，同时验证 hex 编码本身。 */
    @Test
    fun sha256HexMatchesKnownVector() {
        val expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

        assertEquals(expected, UpdateVerifier.sha256Hex("abc".toByteArray()))
    }

    @Test
    fun fileSha256MatchesIgnoringCase() {
        val file = File.createTempFile("vkey-update", ".apk")
        try {
            file.writeBytes("vkey-update-payload".toByteArray())
            val actual = UpdateVerifier.fileSha256Hex(file)

            assertEquals(64, actual.length)
            assertTrue(UpdateVerifier.matchesSha256(actual.uppercase(), actual))
            assertTrue(UpdateVerifier.matchesSha256(actual, actual))
        } finally {
            file.delete()
        }
    }

    @Test
    fun sha256MismatchRejected() {
        val file = File.createTempFile("vkey-update", ".apk")
        try {
            file.writeBytes("vkey-update-payload".toByteArray())
            val actual = UpdateVerifier.fileSha256Hex(file)

            // 64 个 0（服务端联调用的假 sha256）必须被判为不匹配
            assertFalse(UpdateVerifier.matchesSha256("0".repeat(64), actual))
            // 长度不对的期望值直接拒绝，避免空串被误判为匹配
            assertFalse(UpdateVerifier.matchesSha256("", actual))
        } finally {
            file.delete()
        }
    }

    @Test
    fun higherVersionIsUpdate() {
        assertTrue(UpdateVerifier.isNewer(40000, 30100))
        assertTrue(UpdateVerifier.isNewer(30101, 30100))
    }

    @Test
    fun sameVersionIsNotUpdate() {
        assertFalse(UpdateVerifier.isNewer(30100, 30100))
    }

    @Test
    fun lowerVersionIsNotUpdate() {
        assertFalse(UpdateVerifier.isNewer(30099, 30100))
    }
}
