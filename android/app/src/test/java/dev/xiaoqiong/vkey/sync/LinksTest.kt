package dev.xiaoqiong.vkey.sync

import dev.xiaoqiong.vkey.crypto.Crypto
import dev.xiaoqiong.vkey.vault.Base32
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** 深链 / 配对码文本解析的单元测试（纯 JVM，不依赖 Android）。 */
class LinksTest {

    // ------------------------------------------------------------------
    // vkey://config?server=…
    // ------------------------------------------------------------------

    @Test
    fun `parseServerConfig 读取 https 地址`() {
        assertEquals(
            "https://vkey.example.com",
            Links.parseServerConfig("vkey://config?server=https://vkey.example.com"),
        )
    }

    @Test
    fun `parseServerConfig 支持端口与尾部斜杠`() {
        assertEquals(
            "http://127.0.0.1:8080",
            Links.parseServerConfig("vkey://config?server=http://127.0.0.1:8080"),
        )
    }

    @Test
    fun `parseServerConfig 容忍 percent-encoded 值`() {
        assertEquals(
            "https://vkey.example.com",
            Links.parseServerConfig("vkey://config?server=https%3A%2F%2Fvkey.example.com"),
        )
    }

    @Test
    fun `parseServerConfig 忽略前面的其它参数`() {
        assertEquals(
            "https://a.b",
            Links.parseServerConfig("vkey://config?from=qr&server=https://a.b&x=1"),
        )
    }

    @Test
    fun `parseServerConfig 拒绝缺少 server 或非 http 协议`() {
        assertNull(Links.parseServerConfig("vkey://config"))
        assertNull(Links.parseServerConfig("vkey://config?server="))
        assertNull(Links.parseServerConfig("vkey://config?server=ftp://a.b"))
        assertNull(Links.parseServerConfig("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP"))
    }

    @Test
    fun `parseServerConfig 拒绝前缀相似的主机`() {
        assertNull(Links.parseServerConfig("vkey://configuration?server=https://a.b"))
    }

    // ------------------------------------------------------------------
    // 配对码
    // ------------------------------------------------------------------

    @Test
    fun `parsePairCodeLink 支持分组小写`() {
        val code = ByteArray(32) { (it * 7).toByte() }
        val formatted = Crypto.formatPairCode(code).lowercase()
        val parsed = Links.parsePairCodeLink("vkey://pair?code=$formatted")
        assertEquals(formatted, parsed)
        assertEquals(code.toList(), Crypto.parsePairCode(parsed!!).toList())
    }

    @Test
    fun `parseBarePairCode 接受 52 位裸码`() {
        val code = ByteArray(32) { it.toByte() }
        val formatted = Crypto.formatPairCode(code)
        val parsed = Links.parseBarePairCode(formatted)
        assertEquals(formatted, parsed)
    }

    @Test
    fun `parseBarePairCode 拒绝长度不符与非法字符`() {
        assertNull(Links.parseBarePairCode("JBSWY3DPEHPK3PXP"))
        assertNull(Links.parseBarePairCode("1".repeat(52)))
        assertNull(Links.parseBarePairCode("otpauth://totp/a?secret=" + Base32.encode(ByteArray(32))))
    }

    @Test
    fun `classify 先配置后配对码`() {
        val config = Links.classify("vkey://config?server=https://a.b")
        assertTrue(config is ScanLink.ServerConfig)
        assertEquals("https://a.b", (config as ScanLink.ServerConfig).serverUrl)

        val pair = Links.classify(Crypto.formatPairCode(ByteArray(32) { 1 }))
        assertTrue(pair is ScanLink.PairCode)

        assertNull(Links.classify("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP"))
    }

    // ------------------------------------------------------------------
    // SyncManager 的纯函数
    // ------------------------------------------------------------------

    @Test
    fun `code_id 与 Linux 客户端格式一致`() {
        assertEquals("pair-1700000000-deadbeef", SyncManager.buildCodeId(1_700_000_000L, "deadbeef"))
        assertTrue(SyncManager.isValidCodeId(SyncManager.newCodeId()))
        assertFalse(SyncManager.isValidCodeId("pair 1 deadbeef"))
    }

    @Test
    fun `设备名规范化`() {
        assertEquals("android", SyncManager.sanitizeDeviceName("   "))
        assertEquals("Pixel 8", SyncManager.sanitizeDeviceName("  Pixel   8 "))
        val long = SyncManager.sanitizeDeviceName("设".repeat(200))
        assertTrue(long.toByteArray(Charsets.UTF_8).size <= 128)
        assertTrue(long.isNotEmpty())
    }

    @Test
    fun `master_key 解析要求 32 字节`() {
        val key = ByteArray(32) { (it * 3).toByte() }
        val text = Base32.encode(key)
        assertEquals(52, text.length)
        assertEquals(key.toList(), SyncManager.parseMasterKey(text.lowercase()).toList())
        assertTrue(SyncManager.looksLikeKey(text))
        assertFalse(SyncManager.looksLikeKey(Base32.encode(ByteArray(16))))
    }
}
