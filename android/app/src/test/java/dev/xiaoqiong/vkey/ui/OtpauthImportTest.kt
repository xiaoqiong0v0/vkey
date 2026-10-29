package dev.xiaoqiong.vkey.ui

import dev.xiaoqiong.vkey.vault.TotpItem
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [parseOtpauthImport] 的解析 / 去重测试（纯函数，无需 Android 环境）。
 *
 * 覆盖：单行 / 多行混合 / HOTP 跳过 / 空行与注释 / 空文本 / CRLF / BOM 与前后空白 /
 * 超长行 / 与库中条目重复（忽略大小写）/ 同批重复 / 墓碑不算重复 / 与导出往返一致。
 */
class OtpauthImportTest {

    /** 构造条目：只关心参与解析 / 去重的字段，其余用默认值。 */
    private fun item(
        issuer: String = "GitHub",
        account: String = "alice@example.com",
        secret: String = "JBSWY3DPEHPK3PXP",
        algorithm: String = "SHA1",
        digits: Int = 6,
        period: Int = 30,
        deleted: Boolean = false,
    ): TotpItem = TotpItem(
        id = "existing-id",
        issuer = issuer,
        account = account,
        secret = secret,
        algorithm = algorithm,
        digits = digits,
        period = period,
        deleted = deleted,
    )

    @Test
    fun `单行合法 URI 解析为一条可导入条目`() {
        val result = parseOtpauthImport(
            "otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
        )
        assertEquals(1, result.items.size)
        assertEquals(0, result.duplicates)
        assertEquals(0, result.hotpSkipped)
        assertEquals(0, result.invalid)
        assertEquals(1, result.recognized)
        val parsed = result.items.single()
        assertEquals("GitHub", parsed.issuer)
        assertEquals("alice@example.com", parsed.account)
        assertEquals("JBSWY3DPEHPK3PXP", parsed.secret)
        assertTrue("id 必须新生成", parsed.id.isNotBlank())
        assertEquals(0L, parsed.version)
        assertEquals(0L, parsed.updatedAt)
        assertFalse(parsed.deleted)
    }

    @Test
    fun `多行混合 注释与空行跳过 非法行不影响其它行`() {
        val text = """
            # 这是注释
            otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub

            not-an-uri
            otpauth://totp/Bank:bob?issuer=Bank
            otpauth://totp/Mail:carol?secret=GEZDGNBVGY3TQOJQ&issuer=Mail
        """.trimIndent()
        val result = parseOtpauthImport(text)
        assertEquals(2, result.items.size)
        assertEquals(listOf("GitHub", "Mail"), result.items.map { it.issuer })
        assertEquals(0, result.duplicates)
        assertEquals(0, result.hotpSkipped)
        assertEquals("两条非法行：非 otpauth 与缺 secret", 2, result.invalid)
    }

    @Test
    fun `HOTP 行明确跳过并单独计数`() {
        val text = """
            otpauth://hotp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&counter=1
            OTPAUTH://HOTP/Bank:bob?secret=GEZDGNBVGY3TQOJQ&counter=2
            otpauth://totp/Mail:carol?secret=KRSXG5DSN5UXG43T&issuer=Mail
        """.trimIndent()
        val result = parseOtpauthImport(text)
        assertEquals(1, result.items.size)
        assertEquals("Mail", result.items.single().issuer)
        assertEquals(2, result.hotpSkipped)
        assertEquals(0, result.invalid)
        assertEquals(3, result.recognized)
    }

    @Test
    fun `与库中条目重复的不导入 issuer label secret 忽略大小写`() {
        val existing = listOf(item(issuer = "GitHub", account = "alice@example.com", secret = "JBSWY3DPEHPK3PXP"))
        val text = "otpauth://totp/github:ALICE@EXAMPLE.COM?secret=jbswy3dpehpk3pxp&issuer=GITHUB"
        val result = parseOtpauthImport(text, existing)
        assertEquals(0, result.items.size)
        assertEquals(1, result.duplicates)
        assertEquals(1, result.recognized)
    }

    @Test
    fun `密钥不同不算重复`() {
        val existing = listOf(item(issuer = "GitHub", account = "alice@example.com", secret = "JBSWY3DPEHPK3PXP"))
        val text = "otpauth://totp/GitHub:alice@example.com?secret=GEZDGNBVGY3TQOJQ&issuer=GitHub"
        val result = parseOtpauthImport(text, existing)
        assertEquals(1, result.items.size)
        assertEquals(0, result.duplicates)
    }

    @Test
    fun `已删除的墓碑条目不算重复`() {
        val existing = listOf(
            item(issuer = "GitHub", account = "alice@example.com", secret = "JBSWY3DPEHPK3PXP", deleted = true),
        )
        val result = parseOtpauthImport(
            "otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
            existing,
        )
        assertEquals(1, result.items.size)
        assertEquals(0, result.duplicates)
    }

    @Test
    fun `同一批文本内的重复行只导入一次`() {
        val line = "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
        val result = parseOtpauthImport("$line\n$line")
        assertEquals(1, result.items.size)
        assertEquals(1, result.duplicates)
        assertEquals(2, result.recognized)
    }

    @Test
    fun `空文本返回全零`() {
        val result = parseOtpauthImport("")
        assertEquals(0, result.items.size)
        assertEquals(0, result.duplicates)
        assertEquals(0, result.hotpSkipped)
        assertEquals(0, result.invalid)
        assertEquals(0, result.recognized)
    }

    @Test
    fun `CRLF 换行也能解析`() {
        val text = "otpauth://totp/A:a?secret=JBSWY3DPEHPK3PXP&issuer=A\r\n" +
            "otpauth://totp/B:b?secret=GEZDGNBVGY3TQOJQ&issuer=B\r\n"
        val result = parseOtpauthImport(text)
        assertEquals(2, result.items.size)
        assertEquals(0, result.invalid)
    }

    @Test
    fun `BOM 与首尾空白被剥离`() {
        val text = "\uFEFF  \n  otpauth://totp/A:a?secret=JBSWY3DPEHPK3PXP&issuer=A  \n\t\n"
        val result = parseOtpauthImport(text)
        assertEquals(1, result.items.size)
        assertEquals("A", result.items.single().issuer)
        assertEquals(0, result.invalid)
    }

    @Test
    fun `超长行计入无法识别`() {
        val long = "otpauth://totp/A:a?secret=JBSWY3DPEHPK3PXP&issuer=A&pad=" +
            "x".repeat(MAX_IMPORT_LINE_LENGTH)
        val result = parseOtpauthImport(long)
        assertEquals(0, result.items.size)
        assertEquals(1, result.invalid)
        assertEquals(0, result.recognized)
    }

    @Test
    fun `导出 3 条再导入字段一致`() {
        val sources = listOf(
            item("GitHub", "alice@example.com", "JBSWY3DPEHPK3PXP"),
            item("我的银行", "张三", "GEZDGNBVGY3TQOJQ", algorithm = "SHA256", digits = 8, period = 60),
            item("Mail", "bob", "KRSXG5DSN5UXG43T", algorithm = "SHA512", digits = 7, period = 45),
        )
        val text = sources.map { buildOtpauthUri(it) }.joinToString("\n")
        val result = parseOtpauthImport(text)
        assertEquals(3, result.items.size)
        assertEquals(0, result.invalid)
        sources.zip(result.items).forEach { (expected, actual) ->
            assertEquals(expected.issuer, actual.issuer)
            assertEquals(expected.account, actual.account)
            assertEquals(expected.secret, actual.secret)
            assertEquals(expected.algorithm, actual.algorithm)
            assertEquals(expected.digits, actual.digits)
            assertEquals(expected.period, actual.period)
        }
    }
}
