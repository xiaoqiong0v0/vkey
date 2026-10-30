package dev.xiaoqiong.vkey.ui

import android.content.Context
import dev.xiaoqiong.vkey.R
import dev.xiaoqiong.vkey.i18n.ACCEPT_LANGUAGE_HEADER
import dev.xiaoqiong.vkey.i18n.ACCEPT_LANGUAGE_ZH
import java.io.IOException
import java.io.InterruptedIOException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request

/** 保存服务器地址前探测的免鉴权端点（只要 2xx 即说明地址可用）。 */
internal const val POLICY_PROBE_PATH = "/api/v1/policy"

/** 探测超时（秒）：地址对话框里最长等这么久。 */
internal const val PROBE_TIMEOUT_SECONDS = 5L

/**
 * 服务端地址连通性探测结果。
 *
 * 成功只认 2xx：地址写错了（反代 404、Service Worker 页面等）必须拦在保存之前。
 */
internal sealed interface ServerProbe {

    /** 端点返回 2xx：地址可用。 */
    data object Reachable : ServerProbe

    /**
     * 探测失败（地址未保存）。
     *
     * @property reason 失败原因，决定展示给用户的文案
     * @property status HTTP 状态码（仅 [Reason.HTTP_STATUS] 有意义）
     * @property detail 底层异常摘要（用于补充「网络不通」类提示）
     */
    data class Unreachable(
        val reason: Reason,
        val status: Int? = null,
        val detail: String? = null,
    ) : ServerProbe {

        /** 失败分类：非法地址 / 超时 / DNS / 非 2xx / 其它网络错误。 */
        enum class Reason { INVALID_URL, TIMEOUT, DNS, HTTP_STATUS, NETWORK }
    }
}

/**
 * 把服务器基址拼成探测 URL。
 *
 * 地址必须通过 [isValidServerUrl] 且能被 OkHttp 解析（`http://` 这类空 host 会被拒），
 * 否则返回 null，调用方按「非法地址」处理。
 *
 * @param baseUrl 用户填写的服务器地址（可带首尾空白与尾部斜杠）
 * @return 探测 URL；非法时为 null
 */
internal fun policyProbeUrl(baseUrl: String): HttpUrl? {
    val base = normalizeServerUrl(baseUrl)
    if (!isValidServerUrl(base)) return null
    return try {
        (base + POLICY_PROBE_PATH).toHttpUrl()
    } catch (e: IllegalArgumentException) {
        null
    }
}

/**
 * HTTP 状态码 → 探测结果（纯函数）。
 *
 * @param status 响应状态码
 * @return 2xx 视为可用，其余为 [ServerProbe.Unreachable.Reason.HTTP_STATUS]
 */
internal fun probeResultOfStatus(status: Int): ServerProbe =
    if (status in 200..299) {
        ServerProbe.Reachable
    } else {
        ServerProbe.Unreachable(ServerProbe.Unreachable.Reason.HTTP_STATUS, status = status)
    }

/**
 * 探测时抛出的异常 → 失败原因（纯函数）。
 *
 * 顺序有意义：[SocketTimeoutException] / [InterruptedIOException] 先于泛化的 [IOException]，
 * [UnknownHostException] 先于 [IOException]（它继承自 IOException）。
 *
 * @param t 捕获到的异常
 * @return 对应用户可见分类
 */
internal fun probeFailureOf(t: Throwable): ServerProbe.Unreachable.Reason = when (t) {
    is SocketTimeoutException, is InterruptedIOException -> ServerProbe.Unreachable.Reason.TIMEOUT
    is UnknownHostException -> ServerProbe.Unreachable.Reason.DNS
    is IllegalArgumentException -> ServerProbe.Unreachable.Reason.INVALID_URL
    is IOException -> ServerProbe.Unreachable.Reason.NETWORK
    else -> ServerProbe.Unreachable.Reason.NETWORK
}

/** 去掉首尾空白与尾部斜杠，用于地址比较与拼端点。 */
internal fun normalizeServerUrl(url: String): String = url.trim().trimEnd('/')

/**
 * 扫码得到的服务端地址与「地址」字段现值合并（纯函数）。
 *
 * 扫码结果非空（去空白后）则规范化后覆盖字段值 —— 扫码是用户的明确动作，
 * 宁可覆盖手输值也不拼接；结果为空 / 只有空白（例如取消扫码）时保留原值。
 *
 * @param current 地址字段当前值
 * @param scanned 扫码识别到的服务端地址；null 表示没有结果
 * @return 合并后的地址字段值（已规范化）
 */
internal fun mergeScannedAddress(current: String, scanned: String?): String {
    val next = normalizeServerUrl(scanned.orEmpty())
    return next.ifEmpty { normalizeServerUrl(current) }
}

/**
 * 保存新地址后是否需要清除本机设备绑定（纯函数）。
 *
 * token 属于旧服务器：已配置且地址确实变了才需要重新登录 / 重新配对；
 * 未配置（`deviceServerUrl == null`）只保存地址，不动其它状态。
 *
 * @param deviceServerUrl 当前已绑定的服务器地址；null 表示未配置
 * @param newUrl 即将保存的地址
 * @return true 表示需要清绑定
 */
internal fun requiresDeviceRebind(deviceServerUrl: String?, newUrl: String): Boolean =
    deviceServerUrl != null && normalizeServerUrl(deviceServerUrl) != normalizeServerUrl(newUrl)

/**
 * 探测服务器地址是否可用：`GET {url}/api/v1/policy`，5s 内返回 2xx 即通过。
 *
 * 只读、免鉴权；不涉及同步 / 加密逻辑。
 *
 * @param baseUrl 用户填写的服务器地址
 * @param acceptLanguage 请求头 `Accept-Language` 取值
 * @return 探测结果（不会抛异常）
 */
internal suspend fun probeServerAddress(
    baseUrl: String,
    acceptLanguage: String = ACCEPT_LANGUAGE_ZH,
): ServerProbe = withContext(Dispatchers.IO) {
    val url = policyProbeUrl(baseUrl)
        ?: return@withContext ServerProbe.Unreachable(ServerProbe.Unreachable.Reason.INVALID_URL)
    val request = Request.Builder()
        .url(url)
        .header(ACCEPT_LANGUAGE_HEADER, acceptLanguage)
        .get()
        .build()
    try {
        probeClient.newCall(request).execute().use { response ->
            probeResultOfStatus(response.code)
        }
    } catch (t: IOException) {
        ServerProbe.Unreachable(probeFailureOf(t), detail = t.message)
    }
}

/** 把探测失败翻译成用户可见文案。 */
internal fun describeProbeFailure(context: Context, failure: ServerProbe.Unreachable): String =
    when (failure.reason) {
        ServerProbe.Unreachable.Reason.INVALID_URL -> context.getString(R.string.err_server_url_scheme)
        ServerProbe.Unreachable.Reason.TIMEOUT -> context.getString(R.string.err_server_unreachable_timeout)
        ServerProbe.Unreachable.Reason.DNS -> context.getString(R.string.err_server_unreachable_dns)
        ServerProbe.Unreachable.Reason.HTTP_STATUS ->
            context.getString(R.string.err_server_unreachable_status, failure.status ?: 0)
        ServerProbe.Unreachable.Reason.NETWORK ->
            context.getString(R.string.err_server_unreachable_network, failure.detail.orEmpty())
    }

/**
 * 探测专用客户端：5s 总超时（含 DNS / 连接 / 读），不重试。
 *
 * 与业务客户端（20s）分开，避免用户为了确认地址在对话框里等太久。
 */
private val probeClient: OkHttpClient by lazy {
    OkHttpClient.Builder()
        .callTimeout(PROBE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .connectTimeout(PROBE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .readTimeout(PROBE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .retryOnConnectionFailure(false)
        .build()
}
