package dev.xiaoqiong.vkey.ui

import dev.xiaoqiong.vkey.vault.Otpauth
import dev.xiaoqiong.vkey.vault.TotpItem
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.URI
import java.net.URLDecoder

/**
 * [buildOtpauthUri] 的导出格式测试（纯函数，无需 Android 环境）。
 *
 * 覆盖：普通条目 / issuer 为空 / label 为空 / 空格与中文与特殊字符编码 /
 * SHA256 + 8 位 + 60 秒 / secret 原样（大小写与填充）/ 与 [Otpauth.parse] 往返一致。
 */
class OtpauthUriTest {

    /** 构造条目：只关心导出字段，其余用默认值。 */
    private fun item(
        issuer: String = "GitHub",
        account: String = "alice@example.com",
        secret: String = "JBSWY3DPEHPK3PXP",
        algorithm: String = "SHA1",
        digits: Int = 6,
        period: Int = 30,
    ): TotpItem = TotpItem(
        id = "test-id",
        issuer = issuer,
        account = account,
        secret = secret,
        algorithm = algorithm,
        digits = digits,
        period = period,
    )

    @Test
    fun `普通条目按标准顺序输出全部参数`() {
        assertEquals(
            "otpauth://totp/GitHub:alice%40example.com" +
                "?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30",
            buildOtpauthUri(item()),
        )
    }

    @Test
    fun `issuer 为空时路径只放 label 且不输出 issuer 参数`() {
        val uri = buildOtpauthUri(item(issuer = "", account = "alice"))
        assertEquals("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30", uri)
        assertFalse("issuer 为空时不应输出 issuer 参数", uri.contains("issuer="))
        assertFalse("issuer 为空时路径不应出现分隔符", uri.removePrefix("otpauth://totp/").substringBefore('?').contains(':'))
    }

    @Test
    fun `label 为空时用 issuer 顶替`() {
        assertEquals(
            "otpauth://totp/GitHub:GitHub?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30",
            buildOtpauthUri(item(account = "")),
        )
    }

    @Test
    fun `空格与特殊字符按百分号编码 冒号保留为分隔符`() {
        val uri = buildOtpauthUri(item(issuer = "My Bank", account = "a b/c&d?e=f"))
        assertEquals(
            "otpauth://totp/My%20Bank:a%20b%2Fc%26d%3Fe%3Df" +
                "?secret=JBSWY3DPEHPK3PXP&issuer=My%20Bank&algorithm=SHA1&digits=6&period=30",
            uri,
        )
        assertFalse("空格必须编码成 %20 而不是 +", uri.contains('+'))
    }

    @Test
    fun `中文按 UTF-8 百分号编码且可解码回原文`() {
        val uri = buildOtpauthUri(item(issuer = "我的银行", account = "张三"))
        val rawPath = URI(uri).rawPath.removePrefix("/")
        assertEquals("我的银行:张三", URLDecoder.decode(rawPath, "UTF-8"))
        assertTrue("中文必须被编码", uri.contains("%E6%88%91"))
        assertTrue(uri.startsWith("otpauth://totp/"))
    }

    @Test
    fun `SHA256 八位六十秒按条目输出`() {
        assertEquals(
            "otpauth://totp/Bank:user?secret=JBSWY3DPEHPK3PXP&issuer=Bank&algorithm=SHA256&digits=8&period=60",
            buildOtpauthUri(item(issuer = "Bank", account = "user", algorithm = "sha256", digits = 8, period = 60)),
        )
    }

    @Test
    fun `secret 转大写去填充并原样保留 base32 字符`() {
        assertEquals(
            "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30",
            buildOtpauthUri(item(account = "alice", secret = " jbswy3dpehpk3pxp== ")),
        )
    }

    @Test
    fun `导出结果可被 Otpauth 解析回同一条目`() {
        val source = item(issuer = "我的银行", account = "张三", algorithm = "SHA512", digits = 8, period = 60)
        val parsed = Otpauth.parse(buildOtpauthUri(source))
        requireNotNull(parsed) { "导出的 URI 必须可被 Otpauth.parse 解析" }
        assertEquals(source.issuer, parsed.issuer)
        assertEquals(source.account, parsed.account)
        assertEquals(source.secret, parsed.item.secret)
        assertEquals(source.algorithm, parsed.item.algorithm)
        assertEquals(source.digits, parsed.item.digits)
        assertEquals(source.period, parsed.item.period)
    }
}
