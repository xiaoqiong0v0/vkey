package dev.xiaoqiong.vkey.net

import kotlinx.coroutines.runBlocking
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
 * 验证 [UpdateApi.check] 与服务端的契约：
 * 204 → null、非 2xx 抛带状态码的异常、2xx 正确解析字段。
 */
class UpdateApiTest {

    private lateinit var server: MockWebServer
    private lateinit var api: UpdateApi

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
        api = UpdateApi()
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun noContentMeansNoUpdate() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(204))

        val info = api.check(server.url("/").toString())

        assertNull(info)
        assertEquals("/api/v1/update/android", server.takeRequest().path)
    }

    @Test
    fun nonSuccessThrowsWithStatus() {
        server.enqueue(
            MockResponse()
                .setResponseCode(503)
                .setBody("""{"error":{"code":"internal","message":"boom"}}"""),
        )

        val error = assertThrows(UpdateException::class.java) {
            runBlocking { api.check(server.url("/").toString()) }
        }

        assertEquals(503, error.status)
        assertTrue(error.message.orEmpty().contains("503"))
    }

    @Test
    fun parsesUpdatePayload() = runBlocking {
        val sha = "0123456789abcdef".repeat(4)
        server.enqueue(
            MockResponse().setBody(
                """{"version_code":40000,"version_name":"0.4.0",
                   "url":"https://example.test/vkey-android.apk","sha256":"$sha",
                   "size":34485070,"notes":"fix","source":"local","published_at":1793256000}""",
            ),
        )

        val info = api.check(server.url("/").toString())

        requireNotNull(info)
        assertEquals(40000L, info.versionCode)
        assertEquals("0.4.0", info.versionName)
        assertEquals(sha, info.sha256)
        assertEquals(34485070L, info.size)
        assertEquals("fix", info.notes)
        assertEquals("local", info.source)
        assertEquals(1793256000L, info.publishedAt)
        assertEquals("/api/v1/update/android", server.takeRequest().path)
    }

    @Test
    fun trailingSlashInServerUrlStillHitsContractPath() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(204))

        api.check(server.url("/").toString().trimEnd('/'))

        assertEquals("/api/v1/update/android", server.takeRequest().path)
    }
}
