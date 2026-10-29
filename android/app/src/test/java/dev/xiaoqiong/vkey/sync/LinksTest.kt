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

    // ------------------------------------------------------------------
    // 开户码 ENROLL-XXXX-XXXX
    // ------------------------------------------------------------------

    @Test
    fun `parseEnrollCode 接受规范形式`() {
        assertEquals("ENROLL-AB12-CD34", Links.parseEnrollCode("ENROLL-AB12-CD34"))
    }

    @Test
    fun `parseEnrollCode 大小写不敏感`() {
        assertEquals("ENROLL-AB12-CD34", Links.parseEnrollCode("enroll-ab12-cd34"))
    }

    @Test
    fun `parseEnrollCode 容忍空格与换行（粘贴场景）`() {
        assertEquals("ENROLL-AB12-CD34", Links.parseEnrollCode("  ENROLL-AB12 - CD34 \n"))
        assertEquals("ENROLL-AB12-CD34", Links.parseEnrollCode("ENROLL - AB12 - CD34"))
    }

    @Test
    fun `parseEnrollCode 拒绝丢失分组连字符的码`() {
        // 服务端规范化只去空白、转大写（`-` 属格式一部分、参与哈希）；
        // 无连字符的粘贴串对不上服务端哈希，本地必须提前拒掉。
        assertNull(Links.parseEnrollCode("ENROLL AB12 CD34"))
        assertNull(Links.parseEnrollCode("ENROLLAB12CD34"))
    }

    @Test
    fun `parseEnrollCode 前缀错误返回 null`() {
        assertNull(Links.parseEnrollCode("PAIR-AB12-CD34"))
        assertNull(Links.parseEnrollCode("ENROLLX-AB12-CD34"))
    }

    @Test
    fun `parseEnrollCode 分组长度或组数不对返回 null`() {
        assertNull(Links.parseEnrollCode("ENROLL-AB1-CD34"))
        assertNull(Links.parseEnrollCode("ENROLL-AB123-CD34"))
        assertNull(Links.parseEnrollCode("ENROLL-AB12-CD34-EF56"))
        assertNull(Links.parseEnrollCode("ENROLL-AB12"))
        assertNull(Links.parseEnrollCode(""))
    }

    @Test
    fun `parseEnrollCode 拒绝链接与其它码`() {
        assertNull(Links.parseEnrollCode("vkey://config?server=https://x"))
        assertNull(Links.parseEnrollCode(Base32.encode(ByteArray(32))))
    }

    @Test
    fun `classify 识别开户码文本`() {
        assertEquals(ScanLink.EnrollCode("ENROLL-AB12-CD34"), Links.classify("enroll-ab12-cd34"))
    }

    @Test
    fun `classify 不误伤配对码与配置深链`() {
        val key = Base32.encode(ByteArray(32) { (it % 7).toByte() })
        assertEquals(ScanLink.PairCode(key), Links.classify(key))
        assertTrue(Links.classify("vkey://config?server=https://x") is ScanLink.ServerConfig)
    }

    // ------------------------------------------------------------------
    // 开户深链 vkey://enroll?server=…&code=…[&username=…]
    // ------------------------------------------------------------------

    @Test
    fun `parseEnrollLink 正常解析 server 与 code`() {
        assertEquals(
            EnrollDeepLink("http://10.0.2.2:3150", "ENROLL-ABCD-1234", null),
            Links.parseEnrollLink("vkey://enroll?server=http://10.0.2.2:3150&code=ENROLL-ABCD-1234"),
        )
    }

    @Test
    fun `parseEnrollLink 解析 username`() {
        assertEquals(
            EnrollDeepLink("https://vkey.example.com", "ENROLL-ABCD-1234", "dl1"),
            Links.parseEnrollLink(
                "vkey://enroll?server=https://vkey.example.com&code=ENROLL-ABCD-1234&username=dl1",
            ),
        )
    }

    @Test
    fun `parseEnrollLink 参数顺序无关且忽略其它参数`() {
        assertEquals(
            EnrollDeepLink("https://a.b", "ENROLL-AB12-CD34", "u2"),
            Links.parseEnrollLink("vkey://enroll?from=join&username=u2&code=ENROLL-AB12-CD34&server=https://a.b"),
        )
    }

    @Test
    fun `parseEnrollLink 缺 code 或缺 server 返回 null`() {
        assertNull(Links.parseEnrollLink("vkey://enroll?server=https://a.b"))
        assertNull(Links.parseEnrollLink("vkey://enroll?code=ENROLL-AB12-CD34"))
        assertNull(Links.parseEnrollLink("vkey://enroll"))
        assertNull(Links.parseEnrollLink("vkey://enroll?server=&code=ENROLL-AB12-CD34"))
        assertNull(Links.parseEnrollLink("vkey://enroll?server=https://a.b&code="))
    }

    @Test
    fun `parseEnrollLink 非法 code 返回 null`() {
        assertNull(Links.parseEnrollLink("vkey://enroll?server=https://a.b&code=BAD"))
        assertNull(Links.parseEnrollLink("vkey://enroll?server=https://a.b&code=ENROLL-AB1-CD34"))
        // 裸配对码不是开户码
        assertNull(
            Links.parseEnrollLink(
                "vkey://enroll?server=https://a.b&code=" + Base32.encode(ByteArray(32)),
            ),
        )
    }

    @Test
    fun `parseEnrollLink 非 http(s) 协议返回 null`() {
        assertNull(Links.parseEnrollLink("vkey://enroll?server=ftp://a.b&code=ENROLL-AB12-CD34"))
        assertNull(Links.parseEnrollLink("vkey://enroll?server=a.b&code=ENROLL-AB12-CD34"))
    }

    @Test
    fun `parseEnrollLink 大小写与空格容忍`() {
        // 前缀大小写不限、码规范化同 parseEnrollCode（转大写、去内部空格）
        assertEquals(
            EnrollDeepLink("https://a.b", "ENROLL-AB12-CD34", null),
            Links.parseEnrollLink("  VKEY://ENROLL?server=https://a.b&code=enroll-ab12-cd34 "),
        )
    }

    @Test
    fun `parseEnrollLink 容忍 percent-encoded 值`() {
        assertEquals(
            EnrollDeepLink("https://a.b", "ENROLL-AB12-CD34", "u 1"),
            Links.parseEnrollLink(
                "vkey://enroll?server=https%3A%2F%2Fa.b&code=ENROLL-AB12-CD34&username=u%201",
            ),
        )
    }

    @Test
    fun `parseEnrollLink 空白 username 归一为 null`() {
        assertEquals(
            EnrollDeepLink("https://a.b", "ENROLL-AB12-CD34", null),
            Links.parseEnrollLink("vkey://enroll?server=https://a.b&code=ENROLL-AB12-CD34&username=%20"),
        )
    }

    @Test
    fun `parseEnrollLink 拒绝前缀相似的主机与其它深链`() {
        assertNull(Links.parseEnrollLink("vkey://enrollment?server=https://a.b&code=ENROLL-AB12-CD34"))
        assertNull(Links.parseEnrollLink("vkey://config?server=https://a.b"))
        assertNull(Links.parseEnrollLink("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP"))
    }

    // ------------------------------------------------------------------
    // 开户落地页 http(s)://<host>/join?c=…
    // ------------------------------------------------------------------

    @Test
    fun `parseJoinUrl 正常解析 code 与 host`() {
        assertEquals(
            EnrollTarget("ENROLL-GMGH-ZYKF", "http://10.0.2.2:3150", null),
            Links.parseJoinUrl("http://10.0.2.2:3150/join?c=ENROLL-GMGH-ZYKF"),
        )
    }

    @Test
    fun `parseJoinUrl 支持 http 与 https`() {
        assertEquals(
            EnrollTarget("ENROLL-AB12-CD34", "https://vkey.example.com", null),
            Links.parseJoinUrl("https://vkey.example.com/join?c=ENROLL-AB12-CD34"),
        )
        assertEquals(
            EnrollTarget("ENROLL-AB12-CD34", "http://vkey.example.com", null),
            Links.parseJoinUrl("http://vkey.example.com/join?c=ENROLL-AB12-CD34"),
        )
    }

    @Test
    fun `parseJoinUrl 忽略其它参数与参数顺序`() {
        assertEquals(
            EnrollTarget("ENROLL-AB12-CD34", "https://a.b", "dl1"),
            Links.parseJoinUrl("https://a.b/join?from=qr&username=dl1&c=ENROLL-AB12-CD34&x=1"),
        )
    }

    @Test
    fun `parseJoinUrl 忽略 fragment`() {
        assertEquals(
            EnrollTarget("ENROLL-AB12-CD34", "https://a.b:8443", null),
            Links.parseJoinUrl("https://a.b:8443/join?c=ENROLL-AB12-CD34#step-2"),
        )
    }

    @Test
    fun `parseJoinUrl 容忍尾部斜杠大小写与空格`() {
        assertEquals(
            EnrollTarget("ENROLL-AB12-CD34", "https://A.b", null),
            Links.parseJoinUrl("  HTTPS://A.b/Join/?c=enroll-ab12-cd34 \n"),
        )
    }

    @Test
    fun `parseJoinUrl 缺 c 返回 null`() {
        assertNull(Links.parseJoinUrl("https://a.b/join"))
        assertNull(Links.parseJoinUrl("https://a.b/join?c="))
        assertNull(Links.parseJoinUrl("https://a.b/join?from=qr"))
    }

    @Test
    fun `parseJoinUrl 非法 code 返回 null`() {
        assertNull(Links.parseJoinUrl("https://a.b/join?c=BAD"))
        assertNull(Links.parseJoinUrl("https://a.b/join?c=ENROLL-AB1-CD34"))
        // 裸配对码不是开户码
        assertNull(Links.parseJoinUrl("https://a.b/join?c=" + Base32.encode(ByteArray(32))))
    }

    @Test
    fun `parseJoinUrl 拒绝非 join 路径与非 http 协议`() {
        assertNull(Links.parseJoinUrl("https://a.b/pair?c=ENROLL-AB12-CD34"))
        assertNull(Links.parseJoinUrl("https://a.b/join/deep?c=ENROLL-AB12-CD34"))
        assertNull(Links.parseJoinUrl("https://a.b/?c=ENROLL-AB12-CD34"))
        assertNull(Links.parseJoinUrl("ftp://a.b/join?c=ENROLL-AB12-CD34"))
        assertNull(Links.parseJoinUrl("vkey://enroll?server=https://a.b&code=ENROLL-AB12-CD34"))
        assertNull(Links.parseJoinUrl("https:///join?c=ENROLL-AB12-CD34"))
    }

    @Test
    fun `parseJoinUrl 容忍 percent-encoded 值`() {
        assertEquals(
            EnrollTarget("ENROLL-AB12-CD34", "https://a.b", "u 1"),
            Links.parseJoinUrl("https://a.b/join?c=ENROLL-AB12-CD34&username=u%201"),
        )
    }

    @Test
    fun `classify 识别开户深链与 join 链接并带出地址`() {
        assertEquals(
            ScanLink.EnrollCode("ENROLL-AB12-CD34", "https://a.b", "u2"),
            Links.classify("vkey://enroll?server=https://a.b&code=ENROLL-AB12-CD34&username=u2"),
        )
        assertEquals(
            ScanLink.EnrollCode("ENROLL-GMGH-ZYKF", "http://10.0.2.2:3150", null),
            Links.classify("http://10.0.2.2:3150/join?c=ENROLL-GMGH-ZYKF"),
        )
    }

    @Test
    fun `classify 裸开户码不带地址`() {
        assertEquals(
            ScanLink.EnrollCode("ENROLL-AB12-CD34", null, null),
            Links.classify("  enroll-ab12-cd34 "),
        )
    }
}
