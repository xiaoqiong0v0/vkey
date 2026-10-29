package dev.xiaoqiong.vkey.net

import dev.xiaoqiong.vkey.crypto.Crypto
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

/** 验证 [VkeyApi.enroll] 的响应解析、token 安装与免鉴权语义。 */
class VkeyApiEnrollTest {

    private lateinit var server: MockWebServer
    private lateinit var api: VkeyApi

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
        api = VkeyApi(server.url("/").toString())
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun enrollDecodesResponseAndInstallsToken() {
        server.enqueue(
            MockResponse().setBody("""{"device_id":"d1","token":"tok-1","user_id":"u1","username":"alice"}"""),
        )

        val response = api.enroll(
            code = "ENROLL-AB12-CD34",
            username = "alice",
            verifier = Crypto.random(Crypto.KEY_LEN),
            deviceName = "phone",
            platform = "android",
            pubkey = Crypto.ed25519PublicKey(Crypto.random(Crypto.ED25519_SEED_LEN)),
        )

        assertEquals("d1", response.deviceId)
        assertEquals("u1", response.userId)
        assertEquals("alice", response.username)
        assertEquals("tok-1", response.token)
        // 与 authToken 同风格：成功后 token 写入实例，供后续签名请求使用
        assertEquals("tok-1", api.token)

        val recorded = server.takeRequest()
        assertEquals("/api/v1/auth/enroll", recorded.path)
        assertNull(recorded.getHeader("Authorization"))
    }

    @Test
    fun enrollMapsInvalidCodeErrorToApiException() {
        server.enqueue(
            MockResponse()
                .setResponseCode(400)
                .setBody("""{"error":{"code":"invalid_code","message":"开户码无效"}}"""),
        )

        val error = assertThrows(ApiException::class.java) {
            api.enroll(
                code = "ENROLL-ZZZZ-ZZZZ",
                username = "ghost",
                verifier = Crypto.random(Crypto.KEY_LEN),
                deviceName = "phone",
                platform = "android",
                pubkey = Crypto.random(Crypto.ED25519_PUBLIC_KEY_LEN),
            )
        }
        assertEquals("invalid_code", error.code)
        assertEquals(400, error.status)
    }
}
