package dev.xiaoqiong.vkey.sync

import dev.xiaoqiong.vkey.crypto.Crypto
import dev.xiaoqiong.vkey.i18n.ACCEPT_LANGUAGE_ZH
import dev.xiaoqiong.vkey.net.VkeyApi
import dev.xiaoqiong.vkey.vault.DeviceConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** 一次同步配置（用 master_key 登录 / 用配对码领取）的结果。 */
data class SyncResult(
    /** 可落盘的设备材料。 */
    val config: DeviceConfig,
    /** 本次确认的 master_key（Base32 52 字符），用于校正本地库。 */
    val masterKeyBase32: String,
)

/** 用开户码接入（多用户实例注册）的结果。 */
data class EnrollResult(
    /** 可落盘的设备材料。 */
    val config: DeviceConfig,
    /** 本地新生成的 master_key（Base32 52 字符），即恢复码。 */
    val masterKeyBase32: String,
)

/** 生成好的配对码（给新设备用）。 */
data class GeneratedPairCode(
    /** 人类可读形式：base32 大写，每 4 字符用 `-` 分组。 */
    val codeText: String,
    /** 服务端配对会话 id。 */
    val codeId: String,
    /** 过期时间（unix 秒）。 */
    val expiresAt: Long,
)

/**
 * 同步配置与设备配对（M3.2 前半）。
 *
 * 除 [enroll] 外都是阻塞调用（内部走 OkHttp 同步接口），调用方必须放到
 * `Dispatchers.IO` 上执行；[enroll] 已自带 IO 切换。
 *
 * 与 Linux 客户端保持逐字节一致：
 * - 登录：`verifier = HKDF(master_key, "vkey-verifier", username)`；
 * - 配对：`KEK = HKDF(code, "vkey-pair", code_id)`，`blob = nonce||ct||tag`；
 * - 配对码：32B 随机、base32 展示，`code_id = pair-<unix秒>-<8位hex随机>`。
 */
object SyncManager {

    /** 平台标识（服务端 `platform` 字段）。 */
    const val PLATFORM: String = "android"

    /** 配对码有效期（与服务端 `policy.PairTTLSeconds` 一致，仅用于本地倒计时兜底）。 */
    const val PAIR_TTL_SECONDS: Long = 600L

    /** 设备名字节上限（服务端 `policy.MaxDeviceNameBytes`）。 */
    private const val DEVICE_NAME_MAX = 128

    /** master_key 原始字节长度。 */
    private const val MASTER_KEY_BYTES = 32

    /** 未配置账号名时的默认值（与 Linux 客户端一致）。 */
    private const val DEFAULT_USERNAME = "default"

    private const val CODE_ID_PREFIX = "pair"
    private const val CODE_ID_RANDOM_BYTES = 4
    private const val HEX_DIGITS = "0123456789abcdef"

    /**
     * 用 master_key 登录并登记本机设备。
     *
     * 流程：拉策略 → 取 `username_hint` → 复用/生成 Ed25519 种子 → verifier → `POST /auth/token`。
     *
     * @param serverUrl 服务地址（`https://host[:port]`）
     * @param masterKeyBase32 恢复码 / master_key 的 base32 形式（52 字符）
     * @param deviceName 设备名（超长会截断，空白会退化为 `android`）
     * @param existingSeedB64 已有种子（base64url）；复用可避免旧 token 失效
     * @param acceptLanguage 请求头 `Accept-Language` 取值
     * @return 设备材料与本次确认的 master_key
     * @throws dev.xiaoqiong.vkey.net.ApiException 网络或服务端错误
     */
    fun login(
        serverUrl: String,
        masterKeyBase32: String,
        deviceName: String,
        existingSeedB64: String? = null,
        acceptLanguage: String = ACCEPT_LANGUAGE_ZH,
        usernameOverride: String? = null,
    ): SyncResult {
        val masterKey = parseMasterKey(masterKeyBase32)
        val api = VkeyApi(serverUrl, acceptLanguage = acceptLanguage)
        val policy = api.policy()
        // 多用户实例（user_mode=admin）没法靠 username_hint 判断该登哪个账号：
        // 调用方显式给的用户名优先，其次用服务端提示，最后回落 default。
        val username = usernameOverride?.trim()?.takeIf { it.isNotEmpty() }
            ?: policy.usernameHint.ifBlank { DEFAULT_USERNAME }
        val name = sanitizeDeviceName(deviceName)
        val seed = existingSeedB64?.let(::decodeSeed) ?: Crypto.random(Crypto.ED25519_SEED_LEN)

        val verifier = Crypto.verifier(masterKey, username)
        val response = api.authToken(
            username = username,
            verifier = verifier,
            deviceName = name,
            platform = PLATFORM,
            pubkey = Crypto.ed25519PublicKey(seed),
        )
        return SyncResult(
            config = DeviceConfig(
                server_url = api.baseUrl.toString().trimEnd('/'),
                device_id = response.deviceId,
                device_name = name,
                username = username,
                seed = Crypto.b64urlEncode(seed),
                token = response.token,
            ),
            masterKeyBase32 = Crypto.base32Encode(masterKey),
        )
    }

    /**
     * 用一次性配对码领取 master_key 并登记本机设备。
     *
     * 流程：拉策略（取账号名） → 生成/复用种子 → `POST /pair/claim` →
     * `KEK = pairKek(code, claim.code_id)` → 解 blob 得 master_key。
     *
     * @param serverUrl 服务地址
     * @param code 配对码（容忍 `-`/空白/小写）
     * @param deviceName 设备名
     * @param existingSeedB64 已有种子（base64url）；复用可避免重复登记新设备
     * @param acceptLanguage 请求头 `Accept-Language` 取值
     * @return 设备材料与解出的 master_key
     * @throws dev.xiaoqiong.vkey.net.ApiException 配对码不存在/已用/过期等
     * @throws IllegalArgumentException 配对码或 blob 非法
     */
    fun pair(
        serverUrl: String,
        code: String,
        deviceName: String,
        existingSeedB64: String? = null,
        acceptLanguage: String = ACCEPT_LANGUAGE_ZH,
    ): SyncResult {
        val codeBytes = Crypto.parsePairCode(code)
        val api = VkeyApi(serverUrl, acceptLanguage = acceptLanguage)
        val policy = api.policy()
        val username = policy.usernameHint.ifBlank { DEFAULT_USERNAME }
        val name = sanitizeDeviceName(deviceName)
        val seed = existingSeedB64?.let(::decodeSeed) ?: Crypto.random(Crypto.ED25519_SEED_LEN)

        val claim = api.pairClaim(
            code = code,
            name = name,
            platform = PLATFORM,
            pubkey = Crypto.ed25519PublicKey(seed),
        )
        // code_id 必须取响应里的值：新设备不知道生成方的 code_id
        val kek = Crypto.pairKek(codeBytes, claim.codeId)
        val masterKey = Crypto.openPairBlob(kek, Crypto.b64urlDecode(claim.blob))

        return SyncResult(
            config = DeviceConfig(
                server_url = api.baseUrl.toString().trimEnd('/'),
                device_id = claim.deviceId,
                device_name = name,
                username = username,
                seed = Crypto.b64urlEncode(seed),
                token = claim.token,
            ),
            masterKeyBase32 = Crypto.base32Encode(masterKey),
        )
    }

    /**
     * 用一次性开户码接入新账号（`POST /api/v1/auth/enroll`）。
     *
     * 零知识边界：master_key 在本地 `SecureRandom` 生成，服务端只收到
     * `verifier = HKDF(master_key, "vkey-verifier", username)`；成功后本机
     * 以该 master_key 作为账号密钥。
     *
     * @param serverUrl 服务地址
     * @param code 开户码（容忍空格与小写，须为 `ENROLL-XXXX-XXXX`）
     * @param username 用户名（必须与管理员开户时绑定的用户名一致）
     * @param deviceName 设备名（超长截断，空白退化为 `android`）
     * @param existingSeedB64 已有 Ed25519 种子（base64url）；复用可避免重复登记新设备
     * @param acceptLanguage 请求头 `Accept-Language` 取值
     * @return 设备材料与本地新生成的 master_key
     * @throws dev.xiaoqiong.vkey.net.ApiException 开户码无效/过期、用户名占用、设备配额满等
     * @throws IllegalArgumentException 开户码格式非法或用户名为空
     */
    suspend fun enroll(
        serverUrl: String,
        code: String,
        username: String,
        deviceName: String,
        existingSeedB64: String? = null,
        acceptLanguage: String = ACCEPT_LANGUAGE_ZH,
    ): EnrollResult = withContext(Dispatchers.IO) {
        val canonical = Links.parseEnrollCode(code)
            ?: throw IllegalArgumentException("illegal enroll code format (expected ENROLL-XXXX-XXXX)")
        val account = username.trim()
        require(account.isNotEmpty()) { "username must not be blank" }
        val api = VkeyApi(serverUrl, acceptLanguage = acceptLanguage)
        val name = sanitizeDeviceName(deviceName)
        val seed = existingSeedB64?.let(::decodeSeed) ?: Crypto.random(Crypto.ED25519_SEED_LEN)
        val masterKey = Crypto.random(Crypto.KEY_LEN)

        val response = api.enroll(
            code = canonical,
            username = account,
            verifier = Crypto.verifier(masterKey, account),
            deviceName = name,
            platform = PLATFORM,
            pubkey = Crypto.ed25519PublicKey(seed),
        )
        EnrollResult(
            config = DeviceConfig(
                server_url = api.baseUrl.toString().trimEnd('/'),
                device_id = response.deviceId,
                device_name = name,
                // 服务端回显的绑定用户名与本地一致才可能成功；缺失时退化成本地输入
                username = response.username.ifBlank { account },
                seed = Crypto.b64urlEncode(seed),
                token = response.token,
            ),
            masterKeyBase32 = Crypto.base32Encode(masterKey),
        )
    }

    /**
     * 生成一次性配对码（本机作为已有设备，给新设备用）。
     *
     * 前提：本机已登录（[config] 非空）且已解锁（能拿到 master_key）。
     *
     * @param config 本机设备材料（提供服务器地址、token、种子）
     * @param masterKeyBase32 本机 master_key（base32）
     * @param acceptLanguage 请求头 `Accept-Language` 取值
     * @return 展示用配对码、code_id 与服务端过期时间
     * @throws dev.xiaoqiong.vkey.net.ApiException 未登录态/签名失败等
     */
    fun generatePairCode(
        config: DeviceConfig,
        masterKeyBase32: String,
        acceptLanguage: String = ACCEPT_LANGUAGE_ZH,
    ): GeneratedPairCode {
        val masterKey = parseMasterKey(masterKeyBase32)
        val code = Crypto.random(Crypto.PAIR_CODE_LEN)
        val codeId = newCodeId()
        val kek = Crypto.pairKek(code, codeId)
        val blob = Crypto.sealPairBlob(kek, masterKey, Crypto.random(Crypto.NONCE_LEN))

        val api = authorizedApi(config, acceptLanguage)
        val response = api.pairNew(codeId, code, blob)
        return GeneratedPairCode(
            codeText = Crypto.formatPairCode(code),
            codeId = response.codeId,
            expiresAt = response.expiresAt,
        )
    }

    /**
     * 解析 master_key（恢复码）文本。
     *
     * @param text base32 文本（容忍空格 / `-` / 小写）
     * @return 32B 原始 master_key
     * @throws IllegalArgumentException 不是合法 base32 或长度不为 32B
     */
    fun parseMasterKey(text: String): ByteArray {
        val bytes = Crypto.base32Decode(text)
        require(bytes.size == MASTER_KEY_BYTES) { "master_key must be 32 bytes (52 base32 characters)" }
        return bytes
    }

    /**
     * 判断文本是否像 master_key / 配对码（52 位 base32）。
     *
     * @param text 待检查文本
     * @return 解码后恰好 32B 时为 true
     */
    fun looksLikeKey(text: String): Boolean = runCatching { parseMasterKey(text) }.isSuccess

    /**
     * 规范化设备名：合并空白、截断到字节上限。
     *
     * @param raw 用户输入（可为空）
     * @return 1..128 字节的设备名；全空白时返回 `android`
     */
    fun sanitizeDeviceName(raw: String): String {
        val collapsed = raw.trim().replace(WHITESPACE, " ").ifBlank { "android" }
        // 按字符逐个裁剪，保证不超过服务端字节上限且不切断 UTF-8 序列
        val sb = StringBuilder()
        var bytes = 0
        for (ch in collapsed) {
            val len = ch.toString().toByteArray(Charsets.UTF_8).size
            if (bytes + len > DEVICE_NAME_MAX) break
            sb.append(ch)
            bytes += len
        }
        return sb.toString().ifBlank { "android" }
    }

    /**
     * 构造配对码会话 id：`pair-<unix秒>-<8位hex随机>`（与 Linux 客户端一致）。
     *
     * @param nowUnix unix 秒
     * @param randomHex 8 位十六进制随机串
     * @return `code_id`
     */
    fun buildCodeId(nowUnix: Long, randomHex: String): String =
        "$CODE_ID_PREFIX-$nowUnix-$randomHex"

    /** 生成新的 `code_id`（用安全随机数的 4B 十六进制）。 */
    fun newCodeId(): String = buildCodeId(System.currentTimeMillis() / 1000, randomHex(CODE_ID_RANDOM_BYTES))

    /** 校验 `code_id` 是否满足服务端 `[A-Za-z0-9._-]{1,64}`。 */
    fun isValidCodeId(codeId: String): Boolean = CODE_ID_PATTERN.matches(codeId)

    // ------------------------------------------------------------------
    // 私有实现
    // ------------------------------------------------------------------

    private val WHITESPACE = Regex("\\s+")
    private val CODE_ID_PATTERN = Regex("^[A-Za-z0-9._-]{1,64}$")

    /** 用已存设备材料构造带签名能力的客户端。 */
    internal fun authorizedApi(config: DeviceConfig, acceptLanguage: String = ACCEPT_LANGUAGE_ZH): VkeyApi {
        val api = VkeyApi(config.server_url, acceptLanguage = acceptLanguage)
        api.token = config.token
        api.deviceSeed = decodeSeed(config.seed)
        return api
    }

    /** 解码已落盘的 Ed25519 种子并校验长度。 */
    private fun decodeSeed(seedB64: String): ByteArray {
        val seed = Crypto.b64urlDecode(seedB64)
        require(seed.size == Crypto.ED25519_SEED_LEN) { "illegal device seed length: ${seed.size}" }
        return seed
    }

    /** 生成 n 字节随机数的小写十六进制。 */
    private fun randomHex(n: Int): String {
        val sb = StringBuilder(n * 2)
        for (b in Crypto.random(n)) {
            val v = b.toInt() and 0xFF
            sb.append(HEX_DIGITS[v ushr 4]).append(HEX_DIGITS[v and 0x0F])
        }
        return sb.toString()
    }
}
