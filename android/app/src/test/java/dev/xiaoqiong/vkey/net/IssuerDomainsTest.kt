package dev.xiaoqiong.vkey.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** [IssuerDomains] 的解析规则测试（纯 JVM，无网络）。 */
class IssuerDomainsTest {

    @Test
    fun domainLiteralIsUsedDirectly() {
        assertEquals("example.com", IssuerDomains.domainFor("example.com"))
        assertEquals("sub.example.co", IssuerDomains.domainFor("sub.example.co"))
    }

    @Test
    fun domainLiteralIsLowercased() {
        assertEquals("github.com", IssuerDomains.domainFor("GitHub.Com"))
        assertEquals("example.com", IssuerDomains.domainFor("  EXAMPLE.COM  "))
    }

    @Test
    fun builtinMappingHits() {
        assertEquals("github.com", IssuerDomains.domainFor("github"))
        assertEquals("google.com", IssuerDomains.domainFor("gmail"))
        assertEquals("microsoft.com", IssuerDomains.domainFor("office365"))
        assertEquals("amazon.com", IssuerDomains.domainFor("aws"))
        assertEquals("npmjs.com", IssuerDomains.domainFor("npm"))
        assertEquals("x.com", IssuerDomains.domainFor("twitter"))
        assertEquals("weixin.qq.com", IssuerDomains.domainFor("wechat"))
        assertEquals("163.com", IssuerDomains.domainFor("netease"))
        assertEquals("steampowered.com", IssuerDomains.domainFor("steam"))
        assertEquals("godaddy.com", IssuerDomains.domainFor("godaddy"))
    }

    @Test
    fun suffixedIssuerUsesFirstWord() {
        assertEquals("github.com", IssuerDomains.domainFor("GitHub Inc."))
        assertEquals("github.com", IssuerDomains.domainFor("GitHub, Inc."))
        assertEquals("google.com", IssuerDomains.domainFor("Google LLC"))
        assertEquals("github.com", IssuerDomains.domainFor("  github (work)  "))
    }

    @Test
    fun unknownIssuerReturnsNull() {
        assertNull(IssuerDomains.domainFor("Acme Widgets"))
        assertNull(IssuerDomains.domainFor(""))
        assertNull(IssuerDomains.domainFor("   "))
        assertNull(IssuerDomains.domainFor("."))
    }

    @Test
    fun mappingIsCaseInsensitive() {
        assertEquals("github.com", IssuerDomains.domainFor("GITHUB"))
        assertEquals("github.com", IssuerDomains.domainFor("GitHub"))
        assertEquals("github.com", IssuerDomains.domainFor("gitHub Inc"))
    }
}
