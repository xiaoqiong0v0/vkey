package dev.xiaoqiong.vkey.sync

import dev.xiaoqiong.vkey.crypto.Crypto
import dev.xiaoqiong.vkey.net.ApiException
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * 开户码接入（[SyncManager.enroll]）的单元测试（纯 JVM + MockWebServer）。
 *
 * 关注点：请求体 JSON 字段名与取值（服务端契约）、master_key 本地生成、
 * 设备材料组装、错误透传与输入校验。
 */
class SyncManagerEnrollTest {

    private lateinit var server: MockWebServer

    private val successBody =
        """{"device_id":"d1","token":"tok-1","user_id":"u1","username":"alice"}"""

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun `enroll 发送契约字段并组装设备材料`() {
        server.enqueue(MockResponse().setBody(successBody))

        val result = runBlocking {
            // 小写 + 内部空格：验证规范化后发送；用户名带空白：验证 trim
            SyncManager.enroll(baseUrl(), "enroll-ab12 - cd34", "  alice  ", "Pixel 8")
        }

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/api/v1/auth/enroll", recorded.path)
        // 免鉴权端点：不应带签名头
        assertNull(recorded.getHeader("Authorization"))
        assertNull(recorded.getHeader("X-Vkey-Sig"))

        val body = Json.parseToJsonElement(recorded.body.readUtf8()).jsonObject
        assertEquals("ENROLL-AB12-CD34", body.string("code"))
        assertEquals("alice", body.string("username"))
        assertEquals(43, body.string("verifier").length) // base64url(32B) 无填充
        val device = body["device"] as JsonObject
        assertEquals("Pixel 8", device.string("name"))
        assertEquals("android", device.string("platform"))
        assertEquals(43, device.string("pubkey").length)

        // 本地 master_key：52 位 base32，且 verifier 与之一致（零知识：服务端只见派生值）
        val masterKey = SyncManager.parseMasterKey(result.masterKeyBase32)
        assertEquals(52, result.masterKeyBase32.length)
        assertEquals(Crypto.b64urlEncode(Crypto.verifier(masterKey, "alice")), body.string("verifier"))

        // 设备材料
        assertEquals(baseUrl().trimEnd('/'), result.config.server_url)
        assertEquals("d1", result.config.device_id)
        assertEquals("tok-1", result.config.token)
        assertEquals("alice", result.config.username)
        assertEquals("Pixel 8", result.config.device_name)
        val seed = Crypto.b64urlDecode(result.config.seed)
        assertEquals(32, seed.size)
        assertEquals(Crypto.b64urlEncode(Crypto.ed25519PublicKey(seed)), device.string("pubkey"))
    }

    @Test
    fun `enroll 复用已有设备种子`() {
        server.enqueue(MockResponse().setBody(successBody))
        val seed = Crypto.random(Crypto.ED25519_SEED_LEN)
        val seedB64 = Crypto.b64urlEncode(seed)

        val result = runBlocking { SyncManager.enroll(baseUrl(), "ENROLL-AB12-CD34", "alice", "P", seedB64) }

        assertEquals(seedB64, result.config.seed)
        val body = Json.parseToJsonElement(server.takeRequest().body.readUtf8()).jsonObject
        assertEquals(
            Crypto.b64urlEncode(Crypto.ed25519PublicKey(seed)),
            (body["device"] as JsonObject).string("pubkey"),
        )
    }

    @Test
    fun `enroll 服务端未回用户名时退化成本地输入`() {
        server.enqueue(MockResponse().setBody("""{"device_id":"d1","token":"tok-1","user_id":"u1","username":""}"""))

        val result = runBlocking { SyncManager.enroll(baseUrl(), "ENROLL-AB12-CD34", "alice", "P") }

        assertEquals("alice", result.config.username)
        // 请求里带的是 trim 后的用户名（verifier 的 HKDF info 与之一致）
        val body = Json.parseToJsonElement(server.takeRequest().body.readUtf8()).jsonObject
        assertEquals("alice", body.string("username"))
    }

    @Test
    fun `enroll 拒绝非法开户码格式`() {
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking { SyncManager.enroll(baseUrl(), "PAIR-AB12-CD34", "alice", "P") }
        }
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking { SyncManager.enroll(baseUrl(), "ENROLL-AB1", "alice", "P") }
        }
    }

    @Test
    fun `enroll 拒绝空白用户名`() {
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking { SyncManager.enroll(baseUrl(), "ENROLL-AB12-CD34", "   ", "P") }
        }
    }

    @Test
    fun `enroll 透传服务端错误码`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(409)
                .setBody("""{"error":{"code":"username_taken","message":"用户名已被占用"}}"""),
        )

        val error = assertThrows(ApiException::class.java) {
            runBlocking { SyncManager.enroll(baseUrl(), "ENROLL-AB12-CD34", "alice", "P") }
        }
        assertEquals("username_taken", error.code)
        assertEquals(409, error.status)
    }

    /** MockWebServer 基址。 */
    private fun baseUrl(): String = server.url("/").toString()

    /** 取 JsonObject 里字符串字段（缺失时 NPE 让测试直接失败）。 */
    private fun JsonObject.string(key: String): String = checkNotNull(this[key]?.jsonPrimitive?.content) { key }
}
