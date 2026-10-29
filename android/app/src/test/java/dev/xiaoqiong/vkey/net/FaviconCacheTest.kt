package dev.xiaoqiong.vkey.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [FaviconCache] 的逻辑实现 [FaviconMemoryCache] 测试（纯 JVM，无网络/无 IO）。
 *
 * 时钟注入假时钟，验证失败静默期不依赖 sleep。
 */
class FaviconCacheTest {

    /** 可手动推进的假时钟（毫秒）。 */
    private var now: Long = 0L

    /** 与生产同配置（64 条 / 6 小时），只是时钟可控。 */
    private fun newCache(maxEntries: Int = 64): FaviconMemoryCache<String> =
        FaviconMemoryCache(maxEntries = maxEntries, clock = { now })

    @Test
    fun peekMissReturnsNull() {
        val cache = newCache()
        assertNull(cache.peek("github.com"))
        assertNull(cache.peek(""))
    }

    @Test
    fun peekHitReturnsStoredValue() {
        val cache = newCache()
        cache.put("github.com", "icon")
        assertEquals("icon", cache.peek("github.com"))
    }

    @Test
    fun domainKeyIsCaseAndWhitespaceInsensitive() {
        val cache = newCache()
        cache.put("  GitHub.COM  ", "icon")
        assertEquals("icon", cache.peek("github.com"))
    }

    @Test
    fun markFailedMakesIsFailedTrue() {
        val cache = newCache()
        assertFalse(cache.isFailed("github.com"))
        cache.markFailed("github.com")
        assertTrue(cache.isFailed("github.com"))
        assertFalse(cache.isFailed("google.com"))
    }

    @Test
    fun failureExpiresAfterTtl() {
        val cache = newCache()
        cache.markFailed("github.com")

        now = FaviconMemoryCache.DEFAULT_FAILURE_TTL_MS - 1
        assertTrue(cache.isFailed("github.com"))

        now = FaviconMemoryCache.DEFAULT_FAILURE_TTL_MS
        assertFalse(cache.isFailed("github.com"))
    }

    @Test
    fun failureTtlIsFiveMinutes() {
        assertEquals(5L * 60 * 1000, FaviconMemoryCache.DEFAULT_FAILURE_TTL_MS)
    }

    @Test
    fun successClearsFailureRecord() {
        val cache = newCache()
        cache.markFailed("github.com")
        cache.put("github.com", "icon")
        assertFalse(cache.isFailed("github.com"))
    }

    @Test
    fun lruEvictsLeastRecentlyUsedEntry() {
        val cache = newCache(maxEntries = 2)
        cache.put("a.com", "a")
        cache.put("b.com", "b")
        // 访问 a.com，使其成为最近使用；再插入 c.com 淘汰 b.com
        assertEquals("a", cache.peek("a.com"))
        cache.put("c.com", "c")

        assertEquals("a", cache.peek("a.com"))
        assertNull(cache.peek("b.com"))
        assertEquals("c", cache.peek("c.com"))
    }
}
