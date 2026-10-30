package dev.xiaoqiong.vkey.net

import dev.xiaoqiong.vkey.crypto.Crypto
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

/**
 * 验证 [VkeyApi] 会按构造参数带上 `Accept-Language`（服务端据此本地化错误文案）。
 *
 * 覆盖免鉴权与签名两条请求路径：签名拦截器不得丢掉语言头。
 */
class VkeyApiLanguageTest {

    private lateinit var server: MockWebServer

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
    fun chineseLanguageHeaderSurvivesSigning() {
        server.enqueue(MockResponse().setBody("""{"items":[],"next":0}"""))
        val api = VkeyApi(server.url("/").toString(), acceptLanguage = "zh-CN").apply {
            token = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
            deviceSeed = ByteArray(Crypto.ED25519_SEED_LEN) { it.toByte() }
        }

        api.listItems()

        assertEquals("zh-CN", server.takeRequest().getHeader("Accept-Language"))
    }

    @Test
    fun englishLanguageHeaderOnUnauthenticatedRequest() {
        server.enqueue(
            MockResponse().setBody(
                """{"require_master_pw":false,"require_master_pw_enforced":false,""" +
                    """"kdf":{"m":1,"t":1,"p":1},"username_hint":"default"}""",
            ),
        )
        val api = VkeyApi(server.url("/").toString(), acceptLanguage = "en")

        api.policy()

        assertEquals("en", server.takeRequest().getHeader("Accept-Language"))
    }
}
