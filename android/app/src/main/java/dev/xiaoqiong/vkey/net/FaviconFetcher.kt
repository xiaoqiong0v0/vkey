package dev.xiaoqiong.vkey.net

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * 站点图标抓取：只直连 `https://<domain>/...` 取官方 favicon，失败返回 null。
 *
 * 不依赖任何第三方 favicon 服务；磁盘缓存 7 天，内存缓存进程内有效
 * （见 [FaviconCache]），抓取失败的域名 6 小时内不再请求网络。
 * 所有网络/解码异常都静默跳过（不写日志，避免把条目信息带进 logcat）。
 */
object FaviconFetcher {

    /** 磁盘缓存有效期：7 天。 */
    const val CACHE_TTL_MS: Long = 7L * 24 * 60 * 60 * 1000

    /** 单请求超时（秒）。 */
    private const val TIMEOUT_SECONDS: Long = 5L

    /** 响应体上限：200KB。 */
    private const val MAX_BODY_BYTES: Int = 200 * 1024

    /** 读流时的分块大小。 */
    private const val READ_CHUNK_BYTES: Int = 8 * 1024

    /** 缓存目录名（位于 `context.cacheDir` 下）。 */
    private const val CACHE_DIR_NAME: String = "icons"

    /** 按命中率排序的候选路径。 */
    private val CANDIDATE_PATHS: List<String> = listOf(
        "/apple-touch-icon.png",
        "/favicon.png",
        "/favicon.ico",
    )

    /** 只接受简单主机名，避免把用户输入拼成任意 URL。 */
    private val HOST_PATTERN: Regex = Regex("^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")

    /** 部分站点会按 UA 返回不同内容，固定一个浏览器 UA 提高命中率。 */
    private const val USER_AGENT: String = "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36"

    private const val HASH_ALGORITHM: String = "SHA-1"
    private const val HEX_RADIX: Int = 16

    /** 5s 超时；拦截器强制 https（含重定向，遇到 http 直接失败）。 */
    private val client: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .callTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .retryOnConnectionFailure(false)
            .addInterceptor { chain ->
                if (!chain.request().url.isHttps) throw IOException("only https allowed")
                chain.proceed(chain.request())
            }
            .build()
    }

    /**
     * 取站点图标。
     *
     * @param context 任意 Context（内部只用 `cacheDir`）
     * @param domain 站点域名（如 `github.com`，不含 scheme/路径）
     * @return 解码后的图标；缓存命中、网络失败或内容无法解码时返回 null
     */
    suspend fun load(context: Context, domain: String): Bitmap? = withContext(Dispatchers.IO) {
        val host = normalizeHost(domain) ?: return@withContext null

        FaviconCache.peek(host)?.let { return@withContext it }

        val cacheFile = cacheFile(context, host)
        readCached(cacheFile)?.let { bitmap ->
            FaviconCache.put(host, bitmap)
            return@withContext bitmap
        }

        if (FaviconCache.isFailed(host)) return@withContext null

        for (path in CANDIDATE_PATHS) {
            val bytes = fetchBytes("https://$host$path") ?: continue
            val bitmap = decode(bytes) ?: continue
            writeCache(cacheFile, bytes)
            FaviconCache.put(host, bitmap)
            return@withContext bitmap
        }
        FaviconCache.markFailed(host)
        null
    }

    /**
     * 是否存在**有效期内**的磁盘缓存（同步，仅做 stat，可在组合期调用）。
     *
     * 用途：列表首帧判断该画透明占位还是字母徽标，避免「字母 → 图标」闪动。
     *
     * @param context 任意 Context（内部只用 `cacheDir`）
     * @param domain 站点域名
     * @return 域名非法、文件不存在或已过期时返回 false
     */
    fun hasCached(context: Context, domain: String): Boolean {
        val host = normalizeHost(domain) ?: return false
        return isFreshCacheFile(cacheFile(context, host))
    }

    // ------------------------------------------------------------------
    // 内部实现
    // ------------------------------------------------------------------

    /** 只允许简单主机名（拒绝路径、端口、scheme 等注入）。 */
    private fun isSafeHost(host: String): Boolean =
        host.isNotEmpty() && host.contains('.') && HOST_PATTERN.matches(host)

    /** 规范化域名并校验；非法（会拼成任意 URL）时返回 null。 */
    private fun normalizeHost(domain: String): String? {
        val host = domain.trim().lowercase()
        return if (isSafeHost(host)) host else null
    }

    /** 缓存文件新鲜度：存在且未超 [CACHE_TTL_MS]（只做 stat）。 */
    private fun isFreshCacheFile(file: File): Boolean {
        if (!file.isFile) return false
        val age = System.currentTimeMillis() - file.lastModified()
        return age in 0..CACHE_TTL_MS
    }

    /** 缓存文件：`cacheDir/icons/<sha1(domain)>.png`。 */
    private fun cacheFile(context: Context, domain: String): File =
        File(File(context.cacheDir, CACHE_DIR_NAME), "${sha1(domain)}.png")

    /** 域名 → 十六进制 SHA-1（只用于文件名，不涉及条目明文）。 */
    private fun sha1(value: String): String {
        val digest = MessageDigest.getInstance(HASH_ALGORITHM).digest(value.toByteArray())
        return digest.joinToString(separator = "") { "%02x".format(it) }
    }

    /** 读磁盘缓存；过期或无法解码时删除并返回 null。 */
    private fun readCached(file: File): Bitmap? {
        if (!file.isFile) return null
        if (!isFreshCacheFile(file)) {
            file.delete()
            return null
        }
        val bytes = runCatching { file.readBytes() }.getOrNull()
        val bitmap = bytes?.let { decode(it) }
        if (bitmap == null) file.delete()
        return bitmap
    }

    /** 写缓存；失败不影响返回结果。 */
    private fun writeCache(file: File, bytes: ByteArray) {
        runCatching {
            file.parentFile?.mkdirs()
            file.writeBytes(bytes)
        }
    }

    /** 单次 GET；非 2xx、超限、异常一律返回 null（静默）。 */
    private fun fetchBytes(url: String): ByteArray? = try {
        val request = Request.Builder()
            .url(url)
            .header("User-Agent", USER_AGENT)
            .build()
        client.newCall(request).execute().use { response ->
            val body = response.body
            when {
                !response.isSuccessful || body == null -> null
                body.contentLength() > MAX_BODY_BYTES -> null
                else -> body.byteStream().use { readLimited(it, MAX_BODY_BYTES) }
            }
        }
    } catch (_: Exception) {
        null
    }

    /** 读取至多 [limit] 字节；超出上限视为不合格（返回 null）。 */
    private fun readLimited(input: InputStream, limit: Int): ByteArray? {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(READ_CHUNK_BYTES)
        var total = 0
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            total += read
            if (total > limit) return null
            out.write(buffer, 0, read)
        }
        val bytes = out.toByteArray()
        return if (bytes.isEmpty()) null else bytes
    }

    /**
     * 解码：先按常规图片解码；失败且内容是 ICO 时，解析 ICO 目录取出内嵌 PNG 再解码。
     *
     * 很多站点把 PNG 直接塞进 `favicon.ico`，少了这一步基本抓不到图标。
     */
    private fun decode(bytes: ByteArray): Bitmap? {
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size)?.let { return it }
        val png = IcoParser.extractLargestPng(bytes) ?: return null
        return BitmapFactory.decodeByteArray(png, 0, png.size)
    }
}

/**
 * ICO 目录解析（纯字节操作，无 Android 依赖，可单测）。
 *
 * 只做一件事：找出目录里「面积最大」的条目，若其数据以 PNG 魔数开头就返回该 PNG 负载。
 */
internal object IcoParser {

    /** ICONDIR 头长度：reserved(2) + type(2) + count(2)。 */
    private const val HEADER_BYTES: Int = 6

    /** ICONDIRENTRY 长度。 */
    private const val ENTRY_BYTES: Int = 16

    /** ICO 里尺寸字段为 0 表示 256 像素。 */
    private const val SIZE_FIELD_256: Int = 256

    /** PNG 文件头四字节。 */
    private val PNG_MAGIC: ByteArray = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47)

    /** 判断字节是否 ICO：`00 00 01 00`。 */
    fun isIco(bytes: ByteArray): Boolean =
        bytes.size >= HEADER_BYTES &&
            bytes[0] == 0x00.toByte() && bytes[1] == 0x00.toByte() &&
            bytes[2] == 0x01.toByte() && bytes[3] == 0x00.toByte()

    /**
     * 取出面积最大条目里的 PNG 负载。
     *
     * @param bytes 完整 ICO 文件内容
     * @return PNG 字节；非 ICO、目录越界、最大条目不是 PNG 时返回 null
     */
    fun extractLargestPng(bytes: ByteArray): ByteArray? {
        if (!isIco(bytes)) return null
        val count = readU16(bytes, 4)
        if (count <= 0 || bytes.size < HEADER_BYTES + count * ENTRY_BYTES) return null

        var bestOffset = -1
        var bestLength = 0
        var bestArea = -1L
        for (index in 0 until count) {
            val entry = HEADER_BYTES + index * ENTRY_BYTES
            val widthRaw = bytes[entry].toInt() and 0xFF
            val heightRaw = bytes[entry + 1].toInt() and 0xFF
            val width = if (widthRaw == 0) SIZE_FIELD_256 else widthRaw
            val height = if (heightRaw == 0) SIZE_FIELD_256 else heightRaw
            val length = readU32(bytes, entry + 8)
            val offset = readU32(bytes, entry + 12)
            if (length <= 0 || offset < 0) continue
            if (offset.toLong() + length > bytes.size) continue
            val area = width.toLong() * height
            if (area > bestArea || (area == bestArea && length > bestLength)) {
                bestArea = area
                bestOffset = offset
                bestLength = length
            }
        }
        if (bestOffset < 0) return null

        val payload = bytes.copyOfRange(bestOffset, bestOffset + bestLength)
        if (payload.size < PNG_MAGIC.size) return null
        for (index in PNG_MAGIC.indices) {
            if (payload[index] != PNG_MAGIC[index]) return null
        }
        return payload
    }

    /** 小端读取 2 字节无符号整数（越界返回 0）。 */
    private fun readU16(bytes: ByteArray, offset: Int): Int {
        if (offset < 0 || offset + 2 > bytes.size) return 0
        return (bytes[offset].toInt() and 0xFF) or ((bytes[offset + 1].toInt() and 0xFF) shl 8)
    }

    /** 小端读取 4 字节无符号整数（越界或超 Int 范围返回 -1）。 */
    private fun readU32(bytes: ByteArray, offset: Int): Int {
        if (offset < 0 || offset + 4 > bytes.size) return -1
        val value = (bytes[offset].toLong() and 0xFF) or
            ((bytes[offset + 1].toLong() and 0xFF) shl 8) or
            ((bytes[offset + 2].toLong() and 0xFF) shl 16) or
            ((bytes[offset + 3].toLong() and 0xFF) shl 24)
        return if (value > Int.MAX_VALUE) -1 else value.toInt()
    }
}
