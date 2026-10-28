package dev.xiaoqiong.vkey.sync

import dev.xiaoqiong.vkey.crypto.Crypto
import dev.xiaoqiong.vkey.net.ApiException
import dev.xiaoqiong.vkey.net.VkeyApi
import dev.xiaoqiong.vkey.vault.DeviceConfig
import dev.xiaoqiong.vkey.vault.TotpItem
import dev.xiaoqiong.vkey.vault.VaultData
import dev.xiaoqiong.vkey.vault.WebAuthnItem
import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * 验证 [ItemsSync] 的推送/拉取语义（纯 JVM，MockWebServer 充当服务端）。
 *
 * 覆盖：明文 JSON 与 `shared/examples/item-totp.json` 一致、密文可被 `openItem` 解回、
 * LWW 合并（服务端版本更大覆盖 / 墓碑隐藏）、`since` 递增、conflict 归零重推、墓碑推送、
 * TOTP/WebAuthn 分通道（webauthn 只拉不推、仅显式吊销才推墓碑、未知 kind 只 skip）。
 */
class ItemsSyncTest {

    private lateinit var server: MockWebServer

    private val mac = ByteArray(32) { it.toByte() }
    private val macB32 = Crypto.base32Encode(mac)
    private val seed = hex("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    // ------------------------------------------------------------------
    // 用例
    // ------------------------------------------------------------------

    @Test
    fun plaintextJsonMatchesSharedExample() {
        val example = File(requireNotNull(System.getProperty("vkey.vectorsDir")) { "缺少 vkey.vectorsDir" })
            .parentFile!!.resolve("examples/item-totp.json")
        assertTrue("示例文件缺失：$example", example.exists())
        val text = example.readText()

        val item = ItemJson.decode(text, id = ID, version = 3L, updatedAt = NOW)

        // 示例里的 label 对应本地的 account；其余字段一一同名
        assertEquals("alice@example.com", item.account)
        assertEquals("Example", item.issuer)
        assertEquals("JBSWY3DPEHPK3PXP", item.secret)
        assertEquals("SHA1", item.algorithm)
        assertEquals(6, item.digits)
        assertEquals(30, item.period)
        assertEquals(NOW, item.created_at)
        // 未知字段（notes）必须保留在 extras 里
        assertEquals(JsonPrimitive("示例条目（明文，非密文）"), item.extras?.get("notes"))

        val encoded = Json.parseToJsonElement(ItemJson.encode(item)).jsonObject
        val expected = Json.parseToJsonElement(text).jsonObject
        expected.forEach { (key, value) ->
            assertEquals("字段 $key 与示例不一致", value, encoded[key])
        }
        // 只允许额外多出同步时钟 updated_at
        assertEquals(setOf("updated_at"), encoded.keys - expected.keys)
    }

    @Test
    fun pushedCiphertextDecryptsWithItemKey() {
        server.enqueue(applied(ID, version = 7L))
        server.enqueue(page(next = 7L))

        val outcome = ItemsSync.syncBlocking(vaultOf(localItem()), now = NOW)

        val push = server.takeRequest()
        assertEquals("/api/v1/items", push.path)
        val element = firstWrite(push.body.readUtf8())
        assertEquals("totp", element.str("kind"))
        assertEquals("totp", element.str("rp_id"))
        assertEquals(0L, element.long("base_version"))
        assertEquals(0L, element.long("deleted_at"))
        assertEquals(NOW, element.long("updated_at"))

        val plain = Crypto.openItem(
            masterKey = mac,
            itemId = ID,
            ciphertext = Crypto.b64urlDecode(element.str("ct")),
            nonce = Crypto.b64urlDecode(element.str("nonce")),
        )
        val decoded = Json.parseToJsonElement(String(plain, Charsets.UTF_8)).jsonObject
        assertEquals("JBSWY3DPEHPK3PXP", decoded.str("secret"))
        assertEquals("alice@example.com", decoded.str("label"))

        // 响应里的服务端版本被回填
        assertEquals(7L, outcome.vault.items.single().version)
        assertEquals(1, outcome.stats.pushed)
        assertEquals(0, outcome.stats.conflicts)
    }

    @Test
    fun conflictResetsVersionSoNextSyncRetries() {
        server.enqueue(conflict(ID, version = 3L))
        server.enqueue(page(next = 3L))

        val outcome = ItemsSync.syncBlocking(
            vaultOf(localItem(version = 5L, updatedAt = NOW - 10, dirty = true)),
            now = NOW,
        )

        val item = outcome.vault.items.single()
        assertEquals(0L, item.version)
        assertEquals(0L, item.syncedUpdatedAt)
        assertEquals(1, outcome.stats.conflicts)
        assertEquals(0, outcome.stats.pushed)
    }

    @Test
    fun pullOverwritesLocalWhenServerVersionIsNewer() {
        val local = localItem(version = 1L, updatedAt = NOW - 100)
        val remote = local.copy(secret = "NEWSECRET234567", updatedAt = NOW - 5)
        server.enqueue(page(remoteJson(remote, version = 5L, updatedAt = NOW - 5), next = 5L))

        val outcome = ItemsSync.syncBlocking(vaultOf(local), now = NOW)

        val merged = outcome.vault.items.single()
        assertEquals("NEWSECRET234567", merged.secret)
        assertEquals(5L, merged.version)
        assertEquals(5L, outcome.vault.seq)
        assertEquals(1, outcome.stats.pulled)
        // 拉取后不再算脏条目
        assertEquals(merged.updatedAt, merged.syncedUpdatedAt)
    }

    @Test
    fun tombstoneFromServerHidesItem() {
        val local = localItem(version = 4L, updatedAt = NOW - 100)
        server.enqueue(
            page(remoteJson(local, version = 9L, updatedAt = NOW - 5, deletedAt = NOW - 5), next = 9L),
        )

        val outcome = ItemsSync.syncBlocking(vaultOf(local), now = NOW)

        val merged = outcome.vault.items.single()
        assertTrue(merged.deleted)
        // UI 侧过滤规则：墓碑不展示
        assertTrue(outcome.vault.items.filterNot { it.deleted }.isEmpty())
        assertEquals(9L, outcome.vault.seq)
    }

    @Test
    fun nextSyncUsesAdvancedSinceAndSkipsCleanPush() {
        val local = localItem(version = 1L, updatedAt = NOW - 100)
        server.enqueue(page(remoteJson(local, version = 5L, updatedAt = NOW - 5), next = 5L))
        val first = ItemsSync.syncBlocking(vaultOf(local), now = NOW)
        assertEquals(5L, first.vault.seq)

        server.enqueue(page(next = 5L))
        val second = ItemsSync.syncBlocking(first.vault, now = NOW + 60)

        assertEquals(2, server.requestCount)
        assertEquals("/api/v1/items?since=0", server.takeRequest().path)
        // 第二次没有脏条目 → 只有一次 GET，且 since 用新游标
        assertEquals("/api/v1/items?since=5", server.takeRequest().path)
        assertEquals(0, second.stats.pushed)
        assertEquals(5L, second.vault.seq)
    }

    @Test
    fun deletedLocalItemPushesTombstone() {
        val tomb = localItem(version = 2L, updatedAt = NOW, dirty = true).copy(deleted = true)
        server.enqueue(applied(ID, version = 3L))
        server.enqueue(page(next = 3L))

        ItemsSync.syncBlocking(vaultOf(tomb), now = NOW)

        val element = firstWrite(server.takeRequest().body.readUtf8())
        assertEquals("", element.str("ct"))
        assertEquals("", element.str("nonce"))
        assertEquals(2L, element.long("base_version"))
        assertEquals(NOW, element.long("deleted_at"))
    }

    @Test
    fun webauthnPlaintextMatchesSharedExample() {
        val example = File(requireNotNull(System.getProperty("vkey.vectorsDir")) { "缺少 vkey.vectorsDir" })
            .parentFile!!.resolve("examples/item-webauthn.json")
        assertTrue("示例文件缺失：$example", example.exists())

        val item = ItemJson.decodeWebAuthn(example.readText(), id = WA_ID, version = 2L, updatedAt = NOW)

        assertEquals("webauthn", ItemJson.kindOf(example.readText()))
        assertEquals("example.com", item.rpId)
        assertEquals("alice", item.username)
        assertEquals("Alice", item.displayName)
        assertEquals(NOW, item.createdAt)
        assertEquals(2L, item.version)
        assertFalse(item.deleted)
    }

    @Test
    fun webauthnIsPulledButNeverPushed() {
        server.enqueue(page(remoteWebAuthnJson(version = 5L, updatedAt = NOW - 5), next = 5L))

        val outcome = ItemsSync.syncBlocking(vaultOf(), now = NOW)

        // 只有一次 GET，没有任何 POST：正常 webauthn 条目绝不回推
        assertEquals(1, server.requestCount)
        assertEquals("/api/v1/items?since=0", server.takeRequest().path)
        assertEquals(0, outcome.stats.pushed)
        assertEquals(0, outcome.stats.revoked)
        assertEquals(1, outcome.stats.pulled)
        assertEquals(0, outcome.stats.conflicts)
        assertEquals(0, outcome.stats.skipped)

        val item = outcome.vault.webAuthn.single()
        assertEquals(WA_ID, item.id)
        assertEquals("example.com", item.rpId)
        assertEquals("alice", item.username)
        assertEquals(NOW, item.createdAt)
        assertEquals(5L, item.version)
        assertFalse(item.deleted)
        // 分通道：webauthn 不能落进 TOTP 列表
        assertTrue(outcome.vault.items.isEmpty())
    }

    @Test
    fun webauthnTombstonePushedOnlyOnExplicitDelete() {
        val clean = WebAuthnItem(
            id = WA_ID,
            rpId = "example.com",
            username = "alice",
            createdAt = NOW,
            version = 5L,
            // 即使本机时间更新，只要没吊销就不该推送
            updatedAt = NOW,
            syncedUpdatedAt = NOW - 100,
        )

        server.enqueue(page(next = 5L))
        val first = ItemsSync.syncBlocking(vaultOf(webAuthn = listOf(clean)), now = NOW)
        assertEquals(1, server.requestCount)
        assertEquals("/api/v1/items?since=0", server.takeRequest().path)
        assertEquals(0, first.stats.revoked)

        // 用户显式吊销 → 只推墓碑
        server.enqueue(applied(WA_ID, version = 6L))
        server.enqueue(page(next = 6L))
        val revoked = clean.copy(deleted = true)
        val second = ItemsSync.syncBlocking(vaultOf(webAuthn = listOf(revoked)), now = NOW)

        val element = firstWrite(server.takeRequest().body.readUtf8())
        assertEquals("webauthn", element.str("kind"))
        assertEquals("example.com", element.str("rp_id"))
        assertEquals("", element.str("ct"))
        assertEquals("", element.str("nonce"))
        assertEquals(5L, element.long("base_version"))
        assertEquals(NOW, element.long("updated_at"))
        assertEquals(NOW, element.long("deleted_at"))

        assertEquals(1, second.stats.revoked)
        assertEquals(0, second.stats.pushed)
        assertEquals(6L, second.vault.webAuthn.single().version)
        assertEquals(NOW, second.vault.webAuthn.single().syncedUpdatedAt)

        // 已推成功 → 后续同步不再重推
        server.enqueue(page(next = 6L))
        val third = ItemsSync.syncBlocking(second.vault, now = NOW + 60)
        assertEquals(4, server.requestCount)
        assertEquals(0, third.stats.revoked)
    }

    @Test
    fun unknownKindIsSkippedAndNeverPushed() {
        val payload = """{"id":"$UNKNOWN_ID","kind":"passkey","rp_id":"x","ct":"AAAA","nonce":"AAAA",""" +
            """"version":5,"updated_at":$NOW,"deleted_at":0}"""
        server.enqueue(page(payload, next = 5L))

        val outcome = ItemsSync.syncBlocking(vaultOf(), now = NOW)

        assertEquals(1, server.requestCount)
        assertEquals(1, outcome.stats.skipped)
        assertEquals(0, outcome.stats.pushed)
        assertEquals(0, outcome.stats.conflicts)
        assertTrue(outcome.vault.items.isEmpty())
        assertTrue(outcome.vault.webAuthn.isEmpty())
        // 跳过也要推进游标，避免同步卡死
        assertEquals(5L, outcome.vault.seq)
    }

    @Test
    fun legacyWebAuthnInItemsIsMigratedAndNotPushed() {
        // 旧版本把 webauthn 当 TOTP 存进 items（kind 与展示字段留在 extras 里）
        val legacy = TotpItem(
            id = WA_ID,
            kind = "webauthn",
            issuer = "",
            account = "",
            secret = "",
            created_at = NOW,
            version = 5L,
            updatedAt = NOW,
            syncedUpdatedAt = NOW,
            extras = JsonObject(
                mapOf(
                    "rp_id" to JsonPrimitive("example.com"),
                    "username" to JsonPrimitive("alice"),
                ),
            ),
        )
        server.enqueue(page(next = 5L))

        val outcome = ItemsSync.syncBlocking(vaultOf(legacy), now = NOW)

        // 迁移后不再出现在 items，也不会被回推
        assertEquals(1, server.requestCount)
        assertEquals(0, outcome.stats.pushed)
        assertTrue(outcome.vault.items.isEmpty())
        val item = outcome.vault.webAuthn.single()
        assertEquals("example.com", item.rpId)
        assertEquals("alice", item.username)
        assertEquals(NOW, item.createdAt)
        assertEquals(5L, item.version)
        assertFalse(item.deleted)
    }

    // ------------------------------------------------------------------
    // 密钥页实时查询 / 吊销（不落本地）
    // ------------------------------------------------------------------

    @Test
    fun liveQueryFiltersTombstonesAndUnknownKindsThenSkipsBrokenCiphertext() {
        // 密文/密钥对不上（用别人的 master_key 加密）→ 应跳过而不是抛错
        val broken = """{"id":"$BROKEN_ID","kind":"webauthn","rp_id":"bad.example","ct":"AAAA",""" +
            """"nonce":"AAAA","version":3,"updated_at":${NOW - 5},"deleted_at":0}"""
        val unknown = """{"id":"$UNKNOWN_ID","kind":"passkey","rp_id":"x","ct":"AAAA","nonce":"AAAA",""" +
            """"version":4,"updated_at":${NOW - 4},"deleted_at":0}"""
        server.enqueue(
            page(
                remoteWebAuthnJson(version = 2L, updatedAt = NOW - 10),
                remoteWebAuthnJson(version = 3L, updatedAt = NOW - 5, deletedAt = NOW - 5),
                unknown,
                broken,
                next = 9L,
            ),
        )
        // 末页：next 与服务端 seq 相同 → 停止翻页
        server.enqueue(page(next = 9L))

        val live = ItemsSync.fetchWebAuthnLiveDetailed(liveApi(), mac)

        assertEquals(1, live.items.size)
        val item = live.items.single()
        assertEquals(WA_ID, item.id)
        assertEquals("example.com", item.rpId)
        assertEquals("alice", item.username)
        assertEquals("alice", item.label)
        assertEquals("Alice", item.displayName)
        assertEquals("YWxpY2UtMDAx", item.userHandle)
        assertEquals(NOW, item.createdAt)
        // 只有密文坏掉的那条计入 skipped（墓碑与未知 kind 属于过滤，不算跳过）
        assertEquals(1, live.skipped)
        // 明文里的私钥字段不落模型：模型上根本没有该字段，无法被误用
        assertEquals(2, server.requestCount)
        assertEquals("/api/v1/items?since=0", server.takeRequest().path)
        assertEquals("/api/v1/items?since=9", server.takeRequest().path)
    }

    @Test
    fun liveQueryFollowsNextCursorUntilNoNewItems() {
        server.enqueue(page(remoteWebAuthnJson(version = 5L, updatedAt = NOW - 10), next = 5L))
        server.enqueue(page(remoteWebAuthnJson(version = 9L, updatedAt = NOW - 5, id = WA_ID_2), next = 9L))
        server.enqueue(page(next = 9L))

        val items = ItemsSync.fetchWebAuthnLive(liveApi(), mac)

        assertEquals(3, server.requestCount)
        assertEquals("/api/v1/items?since=0", server.takeRequest().path)
        assertEquals("/api/v1/items?since=5", server.takeRequest().path)
        assertEquals("/api/v1/items?since=9", server.takeRequest().path)
        assertEquals(listOf(WA_ID, WA_ID_2), items.map { it.id })
    }

    @Test
    fun revokeWebAuthnPushesMinimalTombstoneWithCurrentVersion() {
        server.enqueue(applied(WA_ID, version = 7L))
        val item = WebAuthnItem(
            id = WA_ID,
            rpId = "example.com",
            username = "alice",
            version = 6L,
            updatedAt = NOW - 10,
            syncedUpdatedAt = NOW - 10,
        )

        ItemsSync.revokeWebAuthn(liveApi(), item, now = NOW)

        val request = server.takeRequest()
        assertEquals("/api/v1/items", request.path)
        val element = firstWrite(request.body.readUtf8())
        assertEquals(WA_ID, element.str("id"))
        assertEquals("webauthn", element.str("kind"))
        assertEquals("example.com", element.str("rp_id"))
        assertEquals("", element.str("ct"))
        assertEquals("", element.str("nonce"))
        assertEquals(6L, element.long("base_version"))
        assertEquals(NOW, element.long("updated_at"))
        assertEquals(NOW, element.long("deleted_at"))
    }

    @Test
    fun revokeWebAuthnSurfacesServerReasonAsApiException() {
        server.enqueue(conflict(WA_ID, version = 9L))
        val item = WebAuthnItem(id = WA_ID, rpId = "example.com", version = 6L)

        val error = runCatching { ItemsSync.revokeWebAuthn(liveApi(), item, now = NOW) }.exceptionOrNull()

        assertTrue("应抛 ApiException，实际 $error", error is ApiException)
        assertEquals("stale_write", (error as ApiException).code)
        // 本地语义失败（未被应用）：没有 HTTP 状态码
        assertEquals(0, error.status)
    }

    // ------------------------------------------------------------------
    // 夹具
    // ------------------------------------------------------------------

    private fun vaultOf(
        vararg items: TotpItem,
        webAuthn: List<WebAuthnItem> = emptyList(),
    ): VaultData = VaultData(
        master_key = macB32,
        items = items.toList(),
        webAuthn = webAuthn,
        device = DeviceConfig(
            server_url = server.url("/").toString().trimEnd('/'),
            device_id = "AAAA",
            device_name = "unit-test",
            username = "default",
            seed = Crypto.b64urlEncode(seed),
            token = TOKEN,
        ),
    )

    private fun localItem(
        version: Long = 0L,
        updatedAt: Long = 0L,
        dirty: Boolean = false,
    ): TotpItem = TotpItem(
        id = ID,
        issuer = "Example",
        account = "alice@example.com",
        secret = "JBSWY3DPEHPK3PXP",
        version = version,
        updatedAt = updatedAt,
        // 已同步条目的「上次推送时间」等于 updatedAt；dirty=true 用来模拟本地新改动
        syncedUpdatedAt = if (dirty) 0L else updatedAt,
    )

    /** 构造一条服务端条目（用同一 master_key 加密，模拟其它设备的写入）。 */
    private fun remoteJson(
        item: TotpItem,
        version: Long,
        updatedAt: Long,
        deletedAt: Long = 0L,
    ): String {
        if (deletedAt != 0L) {
            return """{"id":"${item.id}","kind":"totp","rp_id":"totp","ct":"","nonce":"",""" +
                """"version":$version,"updated_at":$updatedAt,"deleted_at":$deletedAt}"""
        }
        val nonce = ByteArray(Crypto.NONCE_LEN) { 7 }
        val ct = Crypto.sealItem(mac, item.id, ItemJson.encode(item).toByteArray(Charsets.UTF_8), nonce)
        return """{"id":"${item.id}","kind":"totp","rp_id":"totp",""" +
            """"ct":"${Crypto.b64urlEncode(ct)}","nonce":"${Crypto.b64urlEncode(nonce)}",""" +
            """"version":$version,"updated_at":$updatedAt,"deleted_at":0}"""
    }

    /**
     * 构造一条服务端 WebAuthn 条目（用同一 master_key 加密，模拟 Fedora 端的写入）。
     *
     * @param id 条目 id（默认 [WA_ID]，多页用例里区分两条）
     * @param deletedAt 非 0 时生成墓碑（无密文）
     */
    private fun remoteWebAuthnJson(
        version: Long,
        updatedAt: Long,
        deletedAt: Long = 0L,
        id: String = WA_ID,
    ): String {
        if (deletedAt != 0L) {
            return """{"id":"$id","kind":"webauthn","rp_id":"example.com","ct":"","nonce":"",""" +
                """"version":$version,"updated_at":$updatedAt,"deleted_at":$deletedAt}"""
        }
        val plain = """{"kind":"webauthn","rp_id":"example.com","rp_name":"Example",""" +
            """"user_handle":"YWxpY2UtMDAx","username":"alice","label":"alice","display_name":"Alice",""" +
            """"credential_id":"M9HCCwug9BJ6tdhNArxdUw","alg":-7,""" +
            """"private_key":"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg","created_at":$NOW}"""
        val nonce = ByteArray(Crypto.NONCE_LEN) { 9 }
        val ct = Crypto.sealItem(mac, id, plain.toByteArray(Charsets.UTF_8), nonce)
        return """{"id":"$id","kind":"webauthn","rp_id":"example.com",""" +
            """"ct":"${Crypto.b64urlEncode(ct)}","nonce":"${Crypto.b64urlEncode(nonce)}",""" +
            """"version":$version,"updated_at":$updatedAt,"deleted_at":0}"""
    }

    /** 直接构造带签名材料、指向 MockWebServer 的客户端（密钥页实时查询/吊销用）。 */
    private fun liveApi(): VkeyApi = VkeyApi(server.url("/").toString().trimEnd('/')).apply {
        token = TOKEN
        deviceSeed = seed
    }

    private fun page(vararg items: String, next: Long): MockResponse =
        MockResponse().setBody("""{"items":[${items.joinToString(",")}],"next":$next}""")

    private fun applied(id: String, version: Long): MockResponse =
        MockResponse().setBody("""{"results":[{"id":"$id","version":$version,"status":"applied"}]}""")

    private fun conflict(id: String, version: Long): MockResponse =
        MockResponse().setBody(
            """{"results":[{"id":"$id","version":$version,"status":"conflict","reason":"stale_write"}]}""",
        )

    /** 取出 `POST /items` 请求体里的第一条写入项。 */
    private fun firstWrite(body: String): JsonObject =
        Json.parseToJsonElement(body).jsonObject.getValue("items").jsonArray.first().jsonObject

    /** 十六进制转字节。 */
    private fun hex(text: String): ByteArray {
        require(text.length % 2 == 0) { "非法十六进制: $text" }
        return ByteArray(text.length / 2) { index ->
            text.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    companion object {
        private const val ID = "01J9Z6Q3R8T5V7X9Y2B4C6D8E0"
        private const val WA_ID = "01J9Z6Q3R8T5V7X9Y2B4C6D8E1"
        private const val WA_ID_2 = "01J9Z6Q3R8T5V7X9Y2B4C6D8E3"
        private const val UNKNOWN_ID = "01J9Z6Q3R8T5V7X9Y2B4C6D8E2"
        private const val BROKEN_ID = "01J9Z6Q3R8T5V7X9Y2B4C6D8E4"
        private const val TOKEN = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        private const val NOW = 1_761_436_800L
    }
}

/** 取 JSON 字符串字段。 */
private fun JsonObject.str(key: String): String = getValue(key).jsonPrimitive.content

/** 取 JSON 数字字段。 */
private fun JsonObject.long(key: String): Long = getValue(key).jsonPrimitive.long
