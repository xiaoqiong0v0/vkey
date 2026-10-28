package dev.xiaoqiong.vkey.net

import dev.xiaoqiong.vkey.crypto.Crypto
import okhttp3.HttpUrl.Companion.toHttpUrl
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
 * 验证 [VkeyApi] 的签名头与错误解析。
 *
 * 关键不变量：签名串里的 RequestURI 必须与实际请求行逐字节一致（含 query 原文顺序）。
 */
class VkeyApiTest {

    private lateinit var server: MockWebServer
    private lateinit var api: VkeyApi

    private val seed = hex("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
    private val token = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
        api = VkeyApi(server.url("/").toString())
        api.token = token
        api.deviceSeed = seed
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun requestUriKeepsQueryOrderVerbatim() {
        val url = "https://vkey.example/api/v1/items?b=2&a=1".toHttpUrl()

        assertEquals("/api/v1/items?b=2&a=1", requestUriOf(url))
        assertEquals("/api/v1/policy", requestUriOf("https://vkey.example/api/v1/policy".toHttpUrl()))
    }

    @Test
    fun signedGetCarriesHeadersOverTheExactSentUri() {
        server.enqueue(MockResponse().setBody("""{"items":[],"next":7}"""))

        val page = api.listItems(42)

        assertEquals(7L, page.next)
        assertTrue(page.items.isEmpty())

        val recorded = server.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/api/v1/items?since=42", recorded.path)
        assertEquals("Bearer $token", recorded.getHeader("Authorization"))

        val ts = requireNotNull(recorded.getHeader("X-Vkey-Ts")).toLong()
        val body = recorded.body.readByteArray()
        val expectedMessage = Crypto.signingString("GET", "/api/v1/items?since=42", body, ts)
        val expectedSignature = Crypto.ed25519Sign(seed, expectedMessage.toByteArray(Charsets.UTF_8))
        assertEquals(Crypto.b64urlEncode(expectedSignature), recorded.getHeader("X-Vkey-Sig"))
    }

    @Test
    fun signedPostSignsTheExactSentBodyBytes() {
        server.enqueue(MockResponse().setBody("""{"results":[{"id":"a1","version":3,"status":"applied"}]}"""))

        val response = api.pushItems(
            listOf(
                ItemWrite(
                    id = "a1",
                    kind = "totp",
                    rpId = "totp",
                    ct = "AAAA",
                    nonce = "AAAAAAAAAAAAAAAA",
                    baseVersion = 2,
                    updatedAt = 1761436800,
                ),
            ),
        )

        assertEquals(1, response.results.size)
        assertEquals("applied", response.results[0].status)

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/api/v1/items", recorded.path)
        assertEquals("application/json; charset=utf-8", recorded.getHeader("Content-Type"))

        val body = recorded.body.readByteArray()
        val ts = requireNotNull(recorded.getHeader("X-Vkey-Ts")).toLong()
        val expectedMessage = Crypto.signingString("POST", "/api/v1/items", body, ts)
        val expectedSignature = Crypto.ed25519Sign(seed, expectedMessage.toByteArray(Charsets.UTF_8))
        assertEquals(Crypto.b64urlEncode(expectedSignature), recorded.getHeader("X-Vkey-Sig"))

        // 服务端按收到的那串字节验签，元素字段名必须是 snake_case。
        val sent = String(body, Charsets.UTF_8)
        assertTrue(sent, sent.contains("\"base_version\":2"))
        assertTrue(sent, sent.contains("\"rp_id\":\"totp\""))
        assertTrue(sent, sent.contains("\"deleted_at\":0"))
    }

    @Test
    fun errorEnvelopeBecomesApiException() {
        server.enqueue(
            MockResponse()
                .setResponseCode(401)
                .setBody("""{"error":{"code":"invalid_token","message":"token 无效或设备已吊销"}}"""),
        )

        val error = assertThrows(ApiException::class.java) { api.listItems(0) }

        assertEquals("invalid_token", error.code)
        assertEquals(401, error.status)
        assertTrue(error.message.orEmpty().contains("token 无效"))
    }

    @Test
    fun unauthenticatedPolicyCallIsNotSigned() {
        server.enqueue(
            MockResponse().setBody(
                """{"require_master_pw":false,"require_master_pw_enforced":false,
                   "kdf":{"m":65536,"t":3,"p":1},"username_hint":"default","extra_field":1}""",
            ),
        )
        api.token = null
        api.deviceSeed = null

        val policy = api.policy()

        assertEquals("default", policy.usernameHint)
        assertEquals(65536, policy.kdf.m)
        assertEquals(3, policy.kdf.t)
        assertEquals(1, policy.kdf.p)

        val recorded = server.takeRequest()
        assertEquals("/api/v1/policy", recorded.path)
        assertNull(recorded.getHeader("Authorization"))
        assertNull(recorded.getHeader("X-Vkey-Sig"))
    }

    @Test
    fun authTokenEncodesVerifierAndInstallsToken() {
        server.enqueue(
            MockResponse().setBody("""{"token":"$token","device_id":"AAAA","pw_salt":null}"""),
        )
        api.token = null

        val verifier = Crypto.verifier(hex("00".repeat(32)), "default")
        val response = api.authToken(
            username = "default",
            verifier = verifier,
            deviceName = "phone",
            platform = "android",
            pubkey = Crypto.ed25519PublicKey(seed),
        )

        assertEquals(token, response.token)
        assertEquals(token, api.token)

        val recorded = server.takeRequest()
        val sent = String(recorded.body.readByteArray(), Charsets.UTF_8)
        assertTrue(sent, sent.contains("\"verifier\":\"${Crypto.b64urlEncode(verifier)}\""))
        assertTrue(sent, sent.contains("\"platform\":\"android\""))
        assertNull(recorded.getHeader("Authorization"))
    }

    /** 十六进制转字节。 */
    private fun hex(text: String): ByteArray {
        require(text.length % 2 == 0) { "非法十六进制: $text" }
        return ByteArray(text.length / 2) { index ->
            text.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }
}
