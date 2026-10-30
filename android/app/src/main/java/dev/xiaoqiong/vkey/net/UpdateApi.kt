package dev.xiaoqiong.vkey.net

import android.util.Log
import dev.xiaoqiong.vkey.i18n.ACCEPT_LANGUAGE_HEADER
import dev.xiaoqiong.vkey.i18n.ACCEPT_LANGUAGE_ZH
import java.io.File
import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.job
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request

/** Android 更新信息（`GET /api/v1/update/android`，免鉴权）。 */
@Serializable
data class UpdateInfo(
    /** 服务端产物的 versionCode（与本地 `BuildConfig.VERSION_CODE` 比较）。 */
    @SerialName("version_code") val versionCode: Long,
    /** 展示用版本名，如 `0.3.2`。 */
    @SerialName("version_name") val versionName: String,
    /** APK 下载地址（github release 或自托管 `/dl/…`）。 */
    val url: String,
    /** APK 的 SHA-256（64 位 hex，服务端统一小写）。 */
    val sha256: String,
    /** APK 字节数；0 表示服务端未提供（下载时按响应头判断进度）。 */
    val size: Long = 0L,
    /** 发布说明（可能为空）。 */
    val notes: String = "",
    /** 来源：`github` / `local`（仅日志与排查用）。 */
    val source: String = "",
    /** 发布时间（unix 秒）。 */
    @SerialName("published_at") val publishedAt: Long = 0L,
)

/**
 * 更新接口错误。
 *
 * @property status HTTP 状态码；0 表示网络/URL 错误（没有拿到响应）
 */
class UpdateException(
    val status: Int,
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)

/**
 * Android 更新检查与 APK 下载客户端。
 *
 * - [check]：`GET {serverUrl}/api/v1/update/android`，204 视为「暂无更新」，
 *   非 2xx 抛 [UpdateException]（带状态码）；
 * - [download]：流式下载到目标文件，回调进度，支持协程取消（取消时中断 OkHttp 调用）。
 *
 * @param client 可注入的 OkHttp 客户端（单测用）；默认 10 秒超时
 */
class UpdateApi(
    private val client: OkHttpClient = defaultClient(),
    /** 请求头 `Accept-Language` 取值（决定服务端错误文案语言）。 */
    private val acceptLanguage: String = ACCEPT_LANGUAGE_ZH,
) {

    /**
     * 查询服务端的最新 Android 版本信息。
     *
     * @param serverUrl 同步服务地址（尾部斜杠可有可无）
     * @return 更新信息；服务端返回 204（未配置）时为 null
     * @throws UpdateException 非 2xx、响应体为空/非法 JSON、网络失败
     */
    suspend fun check(serverUrl: String): UpdateInfo? = withContext(Dispatchers.IO) {
        val root = serverUrl.trim().trimEnd('/')
        val url = (root + CHECK_PATH).toHttpUrlOrNull()
            ?: throw UpdateException(0, "invalid server url: ${redact(root)}")
        val request = Request.Builder()
            .url(url)
            .header(ACCEPT_LANGUAGE_HEADER, acceptLanguage)
            .get()
            .build()
        val response = try {
            client.newCall(request).execute()
        } catch (e: IOException) {
            Log.w(TAG, "GET $CHECK_PATH -> 0 code=network_error msg=${e.message}")
            throw UpdateException(0, e.message ?: "network request failed", e)
        }
        response.use {
            if (it.code == HTTP_NO_CONTENT) return@withContext null
            if (!it.isSuccessful) {
                Log.w(TAG, "GET $CHECK_PATH -> ${it.code}")
                throw UpdateException(it.code, "update endpoint returned HTTP ${it.code}")
            }
            val text = it.body?.string().orEmpty()
            if (text.isBlank()) throw UpdateException(it.code, "empty update response")
            try {
                json.decodeFromString<UpdateInfo>(text)
            } catch (e: SerializationException) {
                throw UpdateException(it.code, "invalid update response: ${e.message}", e)
            }
        }
    }

    /**
     * 把 APK 下载到 [dest]（覆盖写入）。
     *
     * 进度回调在 IO 线程触发；协程被取消时中断底层 HTTP 调用并抛出 CancellationException。
     *
     * @param url 下载地址
     * @param dest 目标文件（父目录需已存在或由本方法创建）
     * @param expectedSize 服务端声明的字节数；响应头没有 Content-Length 时用它算进度
     * @param onProgress 已下载字节数与总字节数（总数为 0 表示未知）
     * @throws UpdateException 非 2xx 或网络失败
     */
    suspend fun download(
        url: String,
        dest: File,
        expectedSize: Long = 0L,
        onProgress: (downloaded: Long, total: Long) -> Unit = { _, _ -> },
    ) = withContext(Dispatchers.IO) {
        val target = url.trim().toHttpUrlOrNull()
            ?: throw UpdateException(0, "invalid download url: ${redact(url)}")
        dest.parentFile?.mkdirs()
        val request = Request.Builder()
            .url(target)
            .header(ACCEPT_LANGUAGE_HEADER, acceptLanguage)
            .get()
            .build()
        val call = client.newCall(request)
        // 协程取消 → 取消 OkHttp 调用，避免阻塞读把取消拖到超时
        val handle = currentCoroutineContext().job.invokeOnCompletion { cause ->
            if (cause != null) call.cancel()
        }
        try {
            val response = try {
                call.execute()
            } catch (e: IOException) {
                throw UpdateException(0, e.message ?: "download failed", e)
            }
            response.use {
                if (!it.isSuccessful) {
                    Log.w(TAG, "GET $DOWNLOAD_PATH_LABEL -> ${it.code}")
                    throw UpdateException(it.code, "download returned HTTP ${it.code}")
                }
                val body = it.body ?: throw UpdateException(it.code, "empty download body")
                val total = body.contentLength().takeIf { length -> length > 0L } ?: expectedSize
                body.byteStream().use { input ->
                    dest.outputStream().use { output ->
                        val buffer = ByteArray(BUFFER_BYTES)
                        var downloaded = 0L
                        while (true) {
                            currentCoroutineContext().ensureActive()
                            val read = input.read(buffer)
                            if (read < 0) break
                            output.write(buffer, 0, read)
                            downloaded += read
                            onProgress(downloaded, total)
                        }
                    }
                }
            }
        } finally {
            handle.dispose()
        }
    }

    private companion object {
        /** 日志 tag（`adb logcat -s vkey-update`），只打路径/状态码与校验结果。 */
        const val TAG = "vkey-update"

        const val CHECK_PATH = "/api/v1/update/android"

        /** 下载 URL 可能含签名参数：日志里只记路径，不记完整地址。 */
        const val DOWNLOAD_PATH_LABEL = "/download"

        const val HTTP_NO_CONTENT = 204
        const val TIMEOUT_SECONDS = 10L
        const val BUFFER_BYTES = 64 * 1024

        private val json = Json { ignoreUnknownKeys = true }

        /** 默认客户端：10 秒连接/读/写超时，不重试。 */
        private fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .writeTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .retryOnConnectionFailure(false)
            .build()

        /** 只保留 scheme+host，避免把查询参数/凭据写进日志。 */
        private fun redact(url: String): String =
            url.toHttpUrlOrNull()?.let { "${it.scheme}://${it.host}" } ?: "<invalid>"
    }
}
