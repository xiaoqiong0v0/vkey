package dev.xiaoqiong.vkey.net

import android.util.Log
import dev.xiaoqiong.vkey.crypto.Crypto
import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response

/** 服务端策略（`GET /api/v1/policy`）。 */
@Serializable
data class Policy(
    /** 服务端策略：是否要求客户端启用主密码包裹层。 */
    @SerialName("require_master_pw") val requireMasterPw: Boolean,
    /** 实际可执行性：`require_master_pw && wrapped_key 非空`。为 true 时必须用主密码解包。 */
    @SerialName("require_master_pw_enforced") val requireMasterPwEnforced: Boolean,
    /** Argon2id 参数。 */
    val kdf: KdfParams,
    /** 唯一账号的原始用户名；verifier 的 HKDF info 就是它。 */
    @SerialName("username_hint") val usernameHint: String,
)

/** Argon2id 参数（KiB / 迭代 / 并行度）。 */
@Serializable
data class KdfParams(val m: Int, val t: Int, val p: Int)

/** `POST /api/v1/auth/token` 响应。 */
@Serializable
data class AuthTokenResponse(
    /** base64url(32B) 设备 token。 */
    val token: String,
    /** base64url(16B) 设备 id。 */
    @SerialName("device_id") val deviceId: String,
    /** 可选：base64url(16B) 主密码盐。 */
    @SerialName("pw_salt") val pwSalt: String? = null,
    /** 可选：base64url(nonce||ct||tag) 主密码包裹。 */
    @SerialName("wrapped_key") val wrappedKey: String? = null,
)

/** 服务端条目（`GET /api/v1/items`）。 */
@Serializable
data class SyncedItem(
    val id: String,
    val kind: String,
    @SerialName("rp_id") val rpId: String,
    /** base64url(ciphertext||tag)；墓碑为空串。 */
    val ct: String,
    /** base64url(12B)；墓碑为空串。 */
    val nonce: String,
    val version: Long,
    @SerialName("updated_at") val updatedAt: Long,
    /** 0 = 未删除；非 0 = 墓碑。 */
    @SerialName("deleted_at") val deletedAt: Long,
)

/** `GET /api/v1/items` 响应。 */
@Serializable
data class ItemsPage(
    val items: List<SyncedItem>,
    /** 下一页起点；`next < since` 表示服务端版本回滚，应全量重拉。 */
    val next: Long,
)

/** 待写入的条目（`POST /api/v1/items`）。 */
@Serializable
data class ItemWrite(
    val id: String,
    val kind: String,
    @SerialName("rp_id") val rpId: String,
    /** base64url(ciphertext||tag)；墓碑为空串。 */
    val ct: String,
    /** base64url(12B)；墓碑为空串。 */
    val nonce: String,
    /** 客户端认为的服务端当前版本，0 表示新建。 */
    @SerialName("base_version") val baseVersion: Long,
    /** 客户端写入时间（unix 秒），0 表示由服务端填 now。 */
    @SerialName("updated_at") val updatedAt: Long,
    /** 0 = 未删除；非 0 = 墓碑。 */
    @SerialName("deleted_at") val deletedAt: Long = 0,
)

/** 单条写入结果。 */
@Serializable
data class PushResult(
    val id: String,
    /** 应用后的版本；conflict 时为服务端当前版本（新建冲突为 0）。 */
    val version: Long,
    /** `applied` / `conflict` / `rejected`。 */
    val status: String,
    /** 失败原因，如 `stale_write` / `kind_mismatch`。 */
    val reason: String? = null,
)

/** `POST /api/v1/items` 响应；`results` 与请求顺序一一对应。 */
@Serializable
data class PushResponse(val results: List<PushResult>)

/** `POST /api/v1/pair/new` 响应。 */
@Serializable
data class PairNewResponse(
    @SerialName("code_id") val codeId: String,
    /** 服务端回显的规范形式 base32（无分组）。 */
    val code: String,
    @SerialName("expires_at") val expiresAt: Long,
)

/** `POST /api/v1/pair/claim` 响应。 */
@Serializable
data class PairClaimResponse(
    val token: String,
    @SerialName("device_id") val deviceId: String,
    /** base64url(nonce||ct||tag)，用配对 KEK 解出 master_key。 */
    val blob: String,
    @SerialName("pw_salt") val pwSalt: String? = null,
    @SerialName("wrapped_key") val wrappedKey: String? = null,
    @SerialName("code_id") val codeId: String,
)

/** 设备列表项（`GET /api/v1/devices`）。 */
@Serializable
data class DeviceInfo(
    val id: String,
    val name: String,
    val platform: String,
    @SerialName("created_at") val createdAt: Long,
    @SerialName("last_seen") val lastSeen: Long,
    /** 是否为发起本次请求的设备。 */
    val current: Boolean,
)

/** `GET /api/v1/devices` 响应。 */
@Serializable
data class DevicesResponse(val devices: List<DeviceInfo>)

/**
 * 服务端统一错误（`{"error":{"code","message"}}`）。
 *
 * @property code 机器可读错误码，如 `invalid_token` / `ts_skew` / `code_used`
 * @property message 人类可读说明
 * @property status HTTP 状态码
 */
class ApiException(
    val code: String,
    message: String,
    val status: Int,
) : Exception("$code: $message (HTTP $status)")

/**
 * vkey 同步服务 HTTP 客户端。
 *
 * 鉴权请求自动携带 `Authorization: Bearer <token>`、`X-Vkey-Ts`、`X-Vkey-Sig`。
 * 签名串里的 RequestURI 直接取自即将发送的 [HttpUrl]（含 query 原文顺序），
 * 因此与实际请求行逐字节一致。
 *
 * 使用方式：先用 [authToken] 或 [pairClaim] 拿到 token，再设置 [deviceSeed]；
 * 之后所有需要签名的调用自动签名。
 */
class VkeyApi(
    baseUrl: String,
    client: OkHttpClient = defaultClient(),
) {

    /** 服务基址（不含尾部斜杠）。 */
    val baseUrl: HttpUrl = baseUrl.trimEnd('/').toHttpUrl()

    /** 当前会话的 base64url(32B) token；[authToken]/[pairClaim] 成功后自动写入。 */
    var token: String? = null

    /** 设备 Ed25519 私钥种子（32B）；签名前必须设置。用完后由调用方自行清零。 */
    var deviceSeed: ByteArray? = null

    private val root: String = this.baseUrl.toString().trimEnd('/')
    private val signingClient: OkHttpClient = client.newBuilder().addInterceptor(::signRequest).build()

    // ------------------------------------------------------------------
    // 免鉴权端点
    // ------------------------------------------------------------------

    /**
     * 查询服务端策略（免鉴权）。客户端每次启动都必须重新查询。
     *
     * @return 当前策略
     */
    fun policy(): Policy = execute(get("/api/v1/policy"))

    /**
     * 用 verifier 换取设备 token（免鉴权，限流 60 次/分钟/IP）。
     *
     * 成功后把返回的 token 写入 [token]。
     *
     * @param username 账号名原文
     * @param verifier 32B verifier（[Crypto.verifier] 的结果）
     * @param deviceName 设备名（1..128 字节）
     * @param platform 平台标识，如 `android`
     * @param pubkey 32B Ed25519 原始公钥
     * @return 服务端响应
     */
    fun authToken(
        username: String,
        verifier: ByteArray,
        deviceName: String,
        platform: String,
        pubkey: ByteArray,
    ): AuthTokenResponse {
        val body = AuthTokenRequest(
            username = username,
            verifier = Crypto.b64urlEncode(verifier),
            device = DevicePayload(name = deviceName, platform = platform, pubkey = Crypto.b64urlEncode(pubkey)),
        )
        val response = execute<AuthTokenResponse>(post("/api/v1/auth/token", body))
        token = response.token
        return response
    }

    /**
     * 领取配对码（免鉴权，限流 60 次/分钟/IP）。
     *
     * 成功后把返回的 token 写入 [token]。
     *
     * @param code 配对码（容忍小写、`-`、空白与填充）
     * @param name 新设备名
     * @param platform 平台标识
     * @param pubkey 32B Ed25519 原始公钥
     * @return 服务端响应（含用配对 KEK 解密的 blob）
     */
    fun pairClaim(code: String, name: String, platform: String, pubkey: ByteArray): PairClaimResponse {
        val body = PairClaimRequest(
            code = code,
            name = name,
            platform = platform,
            pubkey = Crypto.b64urlEncode(pubkey),
        )
        val response = execute<PairClaimResponse>(post("/api/v1/pair/claim", body))
        token = response.token
        return response
    }

    // ------------------------------------------------------------------
    // 签名端点
    // ------------------------------------------------------------------

    /**
     * 增量拉取条目（签名）。
     *
     * @param since 只返回 `version > since` 的条目，缺省 0
     * @return 本页条目与 next 游标（含墓碑）
     */
    fun listItems(since: Long = 0L): ItemsPage {
        require(since >= 0) { "since must be non-negative" }
        return execute(get("/api/v1/items?since=$since"))
    }

    /**
     * 批量写入条目（签名）。
     *
     * @param items 待写入条目，最多 500 条
     * @return 与 [items] 顺序一一对应的写入结果
     */
    fun pushItems(items: List<ItemWrite>): PushResponse {
        require(items.size <= MAX_ITEMS_PER_PUSH) { "at most $MAX_ITEMS_PER_PUSH items per push" }
        return execute(post("/api/v1/items", ItemPushRequest(items)))
    }

    /**
     * 登记配对码（签名）。
     *
     * @param codeId 配对会话 id（1..64 字节，`[A-Za-z0-9._-]`）
     * @param code 32B 配对码原始值
     * @param blob 自包含配对 blob（nonce||ct||tag）
     * @return 服务端回显的规范配对码与过期时间
     */
    fun pairNew(codeId: String, code: ByteArray, blob: ByteArray): PairNewResponse {
        val body = PairNewRequest(
            codeId = codeId,
            code = Crypto.base32Encode(code),
            blob = Crypto.b64urlEncode(blob),
        )
        return execute(post("/api/v1/pair/new", body))
    }

    /**
     * 查询本账号未吊销设备（签名）。
     *
     * @return 设备列表，按 last_seen 降序
     */
    fun devices(): DevicesResponse = execute(get("/api/v1/devices"))

    // ------------------------------------------------------------------
    // 请求构造与响应解析
    // ------------------------------------------------------------------

    /** 给已登录请求加签名头；未设置 token 或种子时原样放行。 */
    private fun signRequest(chain: okhttp3.Interceptor.Chain): Response {
        val original = chain.request()
        val token = this.token
        val seed = this.deviceSeed
        if (token == null || seed == null) return chain.proceed(original)

        val bodyBytes = original.body?.let { body ->
            val buffer = okio.Buffer()
            body.writeTo(buffer)
            buffer.readByteArray()
        } ?: ByteArray(0)
        val requestUri = requestUriOf(original.url)
        val ts = System.currentTimeMillis() / 1000
        val message = Crypto.signingString(original.method, requestUri, bodyBytes, ts)
        val signature = Crypto.ed25519Sign(seed, message.toByteArray(Charsets.UTF_8))

        val signed = original.newBuilder()
            .header("Authorization", "Bearer $token")
            .header("X-Vkey-Ts", ts.toString())
            .header("X-Vkey-Sig", Crypto.b64urlEncode(signature))
            .build()
        return chain.proceed(signed)
    }

    /** 构造 GET 请求。 */
    private fun get(pathWithQuery: String): Request =
        Request.Builder().url(urlOf(pathWithQuery)).get().build()

    /** 构造 JSON POST 请求。 */
    private inline fun <reified T> post(path: String, payload: T): Request =
        Request.Builder()
            .url(urlOf(path))
            .post(json.encodeToString(payload).toRequestBody(JSON_MEDIA_TYPE))
            .build()

    /** 把相对路径拼到服务基址上。 */
    private fun urlOf(pathWithQuery: String): HttpUrl = (root + pathWithQuery).toHttpUrl()

    /** 执行请求并把非 2xx 响应解析为 [ApiException]。 */
    private inline fun <reified T> execute(request: Request): T {
        val response = try {
            signingClient.newCall(request).execute()
        } catch (e: IOException) {
            // 只打方法/路径与异常摘要，绝不打 token、密文或明文
            Log.w(HTTP_TAG, "${request.method} ${request.url.encodedPath} -> 0 " +
                "code=network_error msg=${e.message}")
            throw ApiException("network_error", e.message ?: "network request failed", 0)
        }
        response.use {
            val text = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                val error = parseError(response.code, text)
                Log.w(HTTP_TAG, "${request.method} ${request.url.encodedPath} -> ${response.code} " +
                    "code=${error.code} msg=${error.message}")
                throw error
            }
            if (text.isBlank()) throw ApiException("empty_body", "server returned an empty body", response.code)
            return try {
                json.decodeFromString<T>(text)
            } catch (e: SerializationException) {
                throw ApiException("invalid_response", e.message ?: "response is not valid JSON", response.code)
            }
        }
    }

    /** 从响应体解析统一错误结构；结构不符时退化为原始摘要。 */
    private fun parseError(status: Int, body: String): ApiException {
        val envelope = try {
            json.decodeFromString<ErrorEnvelope>(body)
        } catch (e: SerializationException) {
            null
        }
        return if (envelope != null) {
            ApiException(envelope.error.code, envelope.error.message, status)
        } else {
            ApiException("http_$status", body.take(ERROR_SNIPPET_LEN), status)
        }
    }

    companion object {
        /** HTTP 失败日志 tag（`adb logcat -s vkey-http`）。 */
        private const val HTTP_TAG = "vkey-http"

        private const val MAX_ITEMS_PER_PUSH = 500
        private const val ERROR_SNIPPET_LEN = 200
        private const val TIMEOUT_SECONDS = 20L

        private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()

        /** 协议自带的 JSON 配置：忽略未知字段（向前兼容），始终输出默认值。 */
        private val json = Json {
            ignoreUnknownKeys = true
            encodeDefaults = true
        }

        /** 默认 OkHttp 客户端：20s 超时，不重试连接失败。 */
        private fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .writeTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .retryOnConnectionFailure(false)
            .build()
    }
}

/** 返回请求行里的原始 target：`path?query`，不含 scheme/host。 */
internal fun requestUriOf(url: HttpUrl): String {
    val query = url.encodedQuery
    return if (query == null) url.encodedPath else url.encodedPath + "?" + query
}

@Serializable
private data class DevicePayload(val name: String, val platform: String, val pubkey: String)

@Serializable
private data class AuthTokenRequest(val username: String, val verifier: String, val device: DevicePayload)

@Serializable
private data class ItemPushRequest(val items: List<ItemWrite>)

@Serializable
private data class PairNewRequest(
    @SerialName("code_id") val codeId: String,
    val code: String,
    val blob: String,
)

@Serializable
private data class PairClaimRequest(val code: String, val name: String, val platform: String, val pubkey: String)

@Serializable
private data class ErrorEnvelope(val error: ErrorBody)

@Serializable
private data class ErrorBody(val code: String, val message: String)
