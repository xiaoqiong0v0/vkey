package dev.xiaoqiong.vkey.net

import android.graphics.Bitmap

/**
 * 图标进程内缓存 + 失败负缓存（纯 JVM 逻辑，时钟可注入，便于单测）。
 *
 * 主线程只做同步 [peek]/[isFailed]（纯内存、无 IO），IO 线程负责
 * [put]/[markFailed]；所有方法串行化在同一把锁上，读写不会看到半成品状态。
 *
 * @param V 缓存值类型（生产为 [Bitmap]，单测可用字符串）
 * @param maxEntries 内存条目上限（LRU 淘汰）
 * @param failureTtlMs 失败记录有效期（毫秒）
 * @param clock 当前时间来源（毫秒），测试注入假时钟避免 sleep
 */
internal class FaviconMemoryCache<V : Any>(
    private val maxEntries: Int = DEFAULT_MAX_ENTRIES,
    private val failureTtlMs: Long = DEFAULT_FAILURE_TTL_MS,
    private val clock: () -> Long = System::currentTimeMillis,
) {

    /** 按访问顺序淘汰的 LRU 容器。 */
    private val values: LinkedHashMap<String, V> =
        object : LinkedHashMap<String, V>(maxEntries, LOAD_FACTOR, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, V>): Boolean =
                size > maxEntries
        }

    /** 域名 → 失败记录过期时刻（毫秒）。 */
    private val failures: MutableMap<String, Long> = HashMap()

    /**
     * 同步查内存缓存，不做任何 IO。
     *
     * @param domain 站点域名（大小写/空白不敏感）
     * @return 命中的图标；未命中或 domain 为空时返回 null
     */
    @Synchronized
    fun peek(domain: String): V? {
        val key = keyOf(domain)
        if (key.isEmpty()) return null
        return values[key]
    }

    /** 写入内存缓存，并清除该域名的失败记录。 */
    @Synchronized
    fun put(domain: String, value: V) {
        val key = keyOf(domain)
        if (key.isEmpty()) return
        values[key] = value
        failures.remove(key)
    }

    /**
     * 是否处于失败静默期（失败后 [DEFAULT_FAILURE_TTL_MS] 内不再请求网络）。
     *
     * 过期记录在查询时顺带清理。
     */
    @Synchronized
    fun isFailed(domain: String): Boolean {
        val key = keyOf(domain)
        if (key.isEmpty()) return false
        val expiresAt = failures[key] ?: return false
        if (clock() >= expiresAt) {
            failures.remove(key)
            return false
        }
        return true
    }

    /** 记录一次抓取失败（从现在起 [failureTtlMs] 内不再请求网络）。 */
    @Synchronized
    fun markFailed(domain: String) {
        val key = keyOf(domain)
        if (key.isEmpty()) return
        failures[key] = clock() + failureTtlMs
    }

    /** 统一键：去空白 + 小写（域名本身大小写不敏感）。 */
    private fun keyOf(domain: String): String = domain.trim().lowercase()

    internal companion object {

        /** 内存条目上限（列表通常几十条）。 */
        internal const val DEFAULT_MAX_ENTRIES: Int = 64

        /** 失败记录有效期：6 小时。 */
        internal const val DEFAULT_FAILURE_TTL_MS: Long = 6L * 60 * 60 * 1000

        /** 负载因子。 */
        private const val LOAD_FACTOR: Float = 0.75f
    }
}

/**
 * 生产单例：2FA 列表首帧同步查询图标用的内存缓存。
 *
 * 只暴露 [Bitmap] API；逻辑在 [FaviconMemoryCache]，单测直接测它。
 */
object FaviconCache {

    private val cache: FaviconMemoryCache<Bitmap> = FaviconMemoryCache()

    /**
     * 同步查内存图标，不做 IO。
     *
     * @param domain 站点域名
     * @return 命中的图标；未命中返回 null（调用方据此决定画占位还是字母）
     */
    fun peek(domain: String): Bitmap? = cache.peek(domain)

    /** 加载成功后写入内存缓存。 */
    fun put(domain: String, bitmap: Bitmap) {
        cache.put(domain, bitmap)
    }

    /** 该域名是否处于失败静默期。 */
    fun isFailed(domain: String): Boolean = cache.isFailed(domain)

    /** 标记该域名抓取失败。 */
    fun markFailed(domain: String) {
        cache.markFailed(domain)
    }
}
