package dev.xiaoqiong.vkey.sync

import android.util.Log
import dev.xiaoqiong.vkey.crypto.Crypto
import dev.xiaoqiong.vkey.i18n.ACCEPT_LANGUAGE_ZH
import dev.xiaoqiong.vkey.net.ApiException
import dev.xiaoqiong.vkey.net.ItemWrite
import dev.xiaoqiong.vkey.net.SyncedItem
import dev.xiaoqiong.vkey.net.VkeyApi
import dev.xiaoqiong.vkey.vault.TotpItem
import dev.xiaoqiong.vkey.vault.VaultData
import dev.xiaoqiong.vkey.vault.WebAuthnItem
import dev.xiaoqiong.vkey.vault.withLegacyWebAuthnMigrated
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * 一次同步的统计。
 *
 * @property pushed 服务端确认应用（`applied`）的 **TOTP** 推送条数
 * @property revoked 服务端确认应用的 **WebAuthn 吊销墓碑** 条数
 * @property pulled 真正合并进本地的拉取条数（TOTP / WebAuthn 的新建、覆盖、墓碑均计入）
 * @property conflicts 推送被判 conflict/rejected 的条数（已重置 `version=0` 待重推）
 * @property skipped 拉取时解密或解析失败、`kind` 未知/不匹配而跳过的条数（游标照常前进以免同步卡死）
 * @property at 本次同步的 unix 秒
 */
data class SyncStats(
    val pushed: Int = 0,
    val revoked: Int = 0,
    val pulled: Int = 0,
    val conflicts: Int = 0,
    val skipped: Int = 0,
    val at: Long = 0L,
)

/**
 * 一次同步的产物。
 *
 * @property vault 合并后的库内容（游标 [VaultData.seq]、[VaultData.lastSyncAt] 已更新）
 * @property stats 统计
 */
data class SyncOutcome(val vault: VaultData, val stats: SyncStats)

/**
 * 实时查询「密钥」页的结果。
 *
 * @property items 解密成功的 WebAuthn 条目（已按 id 去重、已过滤墓碑）
 * @property skipped 解密或明文解析失败而跳过的条数（不抛错，仅计数）
 */
data class WebAuthnLive(
    val items: List<WebAuthnItem> = emptyList(),
    val skipped: Int = 0,
)

/**
 * 条目同步引擎（TOTP + WebAuthn 两条独立通道）。
 *
 * 流程（[syncBlocking]）：先 push（TOTP 脏条目 + WebAuthn 吊销墓碑，`POST /items`），
 * 再 pull（`GET /items?since=seq`，逐条解密后按 LWW 合并到各自的列表）。
 *
 * 语义要点（对齐 `shared/protocol.md` §4.6 / §4.7）：
 * - 加密：`item_key = HKDF(master_key, "vkey-item", id)`，AAD = `vkey-item|<id>`，nonce 12B 随机；
 * - 外层 `rp_id`：TOTP 固定为 `totp`，WebAuthn 取条目自身的 `rpId`；
 * - **TOTP 双向**：本地改动按 `base_version` 推送；
 * - **WebAuthn 只拉 + 显式吊销**：正常条目绝不回推（避免用手机的旧数据覆盖电脑端凭据），
 *   只有用户手动「吊销」（`deleted=true`）产生的墓碑才推送；
 * - 拉取严格按外层 `kind` 路由：`totp` → [VaultData.items]，`webauthn` → [VaultData.webAuthn]；
 *   未知 `kind`、解密失败、明文 `kind` 不匹配一律计入 `skipped`，**绝不回推**；
 * - `conflict` → 计入统计并把该条 `version` 归零，下次同步以「新建」重推；
 * - 拉取按 `version > seq` 增量进行，`next < since` 视为服务端回滚 → 全量重拉一次（服务端为准）；
 * - 墓碑（`deleted_at != 0`）在本地标记 `deleted=true`，UI 不显示。
 *
 * 所有方法都是阻塞调用（内部走 OkHttp 同步接口）；[sync] 已切到 `Dispatchers.IO`，
 * 直接调用 [syncBlocking] 时调用方必须自己保证在 IO 线程上执行。
 */
object ItemsSync {

    /** 同步链路日志 tag（`adb logcat -s vkey-sync`）。 */
    private const val TAG = "vkey-sync"

    /** TOTP 条目的外层 `rp_id`（协议 §5.1 固定值，不随 issuer 变化）。 */
    const val RP_ID_TOTP: String = "totp"

    /** 服务端单次写入上限（协议 §8）。 */
    private const val MAX_ITEMS_PER_PUSH = 500

    /** 单次同步最多翻的页数（防御性上限，正常 1~2 页）。 */
    private const val MAX_PULL_PAGES = 200

    /** 服务端单页上限（协议 §4.7）；未满页即最后一页。 */
    private const val PULL_PAGE_LIMIT = 1000

    private const val STATUS_APPLIED = "applied"

    /** 跳过原因：密文为空或 AEAD 打开失败（密钥不对/密文损坏）。 */
    private const val REASON_OPEN_FAILED = "open-failed"

    /** 跳过原因：明文 kind 不符或 JSON 解析失败。 */
    private const val REASON_PARSE_FAILED = "parse-failed"

    /** 服务端写入失败原因：`base_version` 不是当前版本。 */
    private const val REASON_STALE_WRITE = "stale_write"

    /** 当前 unix 秒。 */
    fun nowSeconds(): Long = System.currentTimeMillis() / 1000

    /**
     * 同步一次（IO 版本）。
     *
     * @param vault 当前库内容（必须已配置 [VaultData.device]）
     * @param now 本次同步的 unix 秒（测试可注入）
     * @param acceptLanguage 请求头 `Accept-Language` 取值
     * @return 合并后的库内容与统计
     * @throws ApiException 网络或服务端错误（UI 直接展示 `code/message`）
     */
    suspend fun sync(
        vault: VaultData,
        now: Long = nowSeconds(),
        acceptLanguage: String = ACCEPT_LANGUAGE_ZH,
    ): SyncOutcome = withContext(Dispatchers.IO) { syncBlocking(vault, now, acceptLanguage) }

    /**
     * 同步一次（阻塞版本，调用方负责切 IO）。
     *
     * @param vault 当前库内容（必须已配置 [VaultData.device]）
     * @param now 本次同步的 unix 秒
     * @param acceptLanguage 请求头 `Accept-Language` 取值
     * @return 合并后的库内容与统计
     * @throws ApiException 网络或服务端错误
     */
    fun syncBlocking(
        vault: VaultData,
        now: Long = nowSeconds(),
        acceptLanguage: String = ACCEPT_LANGUAGE_ZH,
    ): SyncOutcome {
        // 兼容旧 vault：先把历史误并入 items 的 webauthn 条目搬到独立列表
        val source = vault.withLegacyWebAuthnMigrated()
        val config = source.device
            ?: throw ApiException("not_configured", "sync is not configured on this device", 0)
        val masterKey = SyncManager.parseMasterKey(source.master_key)
        val api = SyncManager.authorizedApi(config, acceptLanguage)

        Log.d(TAG, "push start")
        val afterTotpPush = pushTotp(api, masterKey, source.items, now)
        val afterRevokePush = pushWebAuthnTombstones(api, masterKey, source.webAuthn, now)
        Log.d(
            TAG,
            "push done totp=${afterTotpPush.pushed} revoked=${afterRevokePush.revoked} " +
                "conflicts=${afterTotpPush.conflicts + afterRevokePush.conflicts}",
        )
        val afterPull = pull(
            api = api,
            masterKey = masterKey,
            items = afterTotpPush.items,
            webAuthn = afterRevokePush.items,
            since = source.seq,
        )
        Log.d(
            TAG,
            "pull done pulled=${afterPull.pulled} skipped=${afterPull.skipped} seq=${afterPull.seq}",
        )

        val stats = SyncStats(
            pushed = afterTotpPush.pushed,
            revoked = afterRevokePush.revoked,
            pulled = afterPull.pulled,
            conflicts = afterTotpPush.conflicts + afterRevokePush.conflicts,
            skipped = afterPull.skipped,
            at = now,
        )
        return SyncOutcome(
            vault = source.copy(
                items = afterPull.items,
                webAuthn = afterPull.webAuthn,
                seq = afterPull.seq,
                lastSyncAt = now,
            ),
            stats = stats,
        )
    }

    // ------------------------------------------------------------------
    // 实时查询 / 吊销：WebAuthn（不走本地同步）
    // ------------------------------------------------------------------

    /**
     * 实时拉取全部 WebAuthn 凭据（`GET /items?since=0`，翻页到结束）。
     *
     * 「密钥」页不做本地同步：手机不持有凭据，只实时查看/吊销，所以每次都从 0 开始全量扫描，
     * 逐个 `next` 推进到没有新条目为止，并过滤外层 `kind == "webauthn"` 且 `deleted_at == 0`。
     *
     * @param api 已带签名的客户端
     * @param masterKey 32B master_key
     * @return 解密成功的只读条目（解密/解析失败的条目被跳过）
     * @throws ApiException 网络或服务端错误
     */
    fun fetchWebAuthnLive(api: VkeyApi, masterKey: ByteArray): List<WebAuthnItem> =
        fetchWebAuthnLiveDetailed(api, masterKey).items

    /**
     * 同 [fetchWebAuthnLive]，额外返回被跳过的条数（便于 UI/日志区分「真的没有」与「解不开」）。
     *
     * @param api 已带签名的客户端
     * @param masterKey 32B master_key
     * @return 条目与被跳过的条数
     * @throws ApiException 网络或服务端错误
     */
    fun fetchWebAuthnLiveDetailed(api: VkeyApi, masterKey: ByteArray): WebAuthnLive {
        val byId = LinkedHashMap<String, WebAuthnItem>()
        var total = 0
        var skipped = 0
        var cursor = 0L
        var pages = 0

        Log.d(TAG, "webauthn fetch start since=0")
        while (pages < MAX_PULL_PAGES) {
            pages++
            val page = api.listItems(cursor)
            Log.d(TAG, "page items=${page.items.size} next=${page.next}")
            for (remote in page.items) {
                if (remote.kind != ItemJson.KIND_WEBAUTHN) continue
                if (remote.deletedAt != 0L) continue
                total++
                val decoded = decodeLiveWebAuthn(remote, masterKey)
                val item = decoded.item
                if (item == null) {
                    skipped++
                    // 只打 id / kind / 原因，绝不打密文或明文
                    Log.w(TAG, "skip id=${remote.id} kind=${remote.kind} reason=${decoded.reason}")
                    continue
                }
                byId[item.id] = item
            }
            val next = page.next
            // 用响应 next 推进：next 没有前进 = 没有更新条目（末页的 next 即服务端 seq）
            if (next <= cursor) break
            cursor = next
        }
        Log.d(TAG, "webauthn fetch done total=$total ok=${byId.size} skipped=$skipped")
        return WebAuthnLive(items = byId.values.toList(), skipped = skipped)
    }

    /**
     * 吊销一条 WebAuthn 凭据：推 `deleted_at = now` 的墓碑。
     *
     * 以条目当前的服务端 `version` 作为 `base_version`；墓碑不带密文
     * （协议 §4.7：墓碑的 `ct`/`nonce` 可为空串），是最简合法形式。
     *
     * @param api 已带签名的客户端
     * @param item 待吊销条目（必须带服务端 `version`）
     * @param now 墓碑时间（unix 秒，测试可注入）
     * @throws ApiException 网络/服务端错误，或写入未被应用（`code` 取服务端 `reason`）
     */
    fun revokeWebAuthn(api: VkeyApi, item: WebAuthnItem, now: Long = nowSeconds()) {
        val write = ItemWrite(
            id = item.id,
            kind = ItemJson.KIND_WEBAUTHN,
            rpId = item.rpId,
            ct = "",
            nonce = "",
            baseVersion = item.version,
            updatedAt = now,
            deletedAt = now,
        )
        val result = api.pushItems(listOf(write)).results.firstOrNull()
            ?: throw ApiException("invalid_response", "server returned no write result", 0)
        if (result.status != STATUS_APPLIED) {
            val code = result.reason ?: result.status
            val message = when (code) {
                REASON_STALE_WRITE -> "credential changed on another device"
                else -> "server rejected the write ($code)"
            }
            throw ApiException(code, message, 0)
        }
    }

    // ------------------------------------------------------------------
    // 推送：TOTP 脏条目
    // ------------------------------------------------------------------

    /**
     * 推送本地脏 TOTP 条目，并按响应回填服务端版本。
     *
     * @param api 已带签名的客户端
     * @param masterKey 32B master_key
     * @param items 当前 TOTP 条目
     * @param now 本次同步的 unix 秒
     * @return 回填后的条目与统计
     */
    private fun pushTotp(
        api: VkeyApi,
        masterKey: ByteArray,
        items: List<TotpItem>,
        now: Long,
    ): TotpPushOutcome {
        // 保持原顺序替换：先建 id -> item 映射，再按 id 写回
        val updated = LinkedHashMap<String, TotpItem>(items.size)
        items.forEach { updated[it.id] = it }

        val dirty = items.filter { it.kind == ItemJson.KIND_TOTP && it.needsPush() }
        var pushed = 0
        var conflicts = 0

        for (chunk in dirty.chunked(MAX_ITEMS_PER_PUSH)) {
            val writes = chunk.map { toTotpWrite(it, masterKey, now) }
            val results = api.pushItems(writes).results
            chunk.forEachIndexed { index, item ->
                val result = results.getOrNull(index) ?: return@forEachIndexed
                if (result.status == STATUS_APPLIED) {
                    val ts = effectiveTimestamp(item.updatedAt, now)
                    updated[item.id] = item.copy(
                        version = result.version,
                        updatedAt = ts,
                        syncedUpdatedAt = ts,
                    )
                    pushed++
                } else {
                    // conflict / rejected：归零后下次以「新建」重推（协议 §4.6 的恢复路径）
                    updated[item.id] = item.copy(version = 0L, syncedUpdatedAt = 0L)
                    conflicts++
                }
            }
        }
        return TotpPushOutcome(updated.values.toList(), pushed, conflicts)
    }

    // ------------------------------------------------------------------
    // 推送：WebAuthn 吊销墓碑
    // ------------------------------------------------------------------

    /**
     * 推送用户显式吊销产生的 WebAuthn 墓碑，并按响应回填服务端版本。
     *
     * 正常（未吊销）的 WebAuthn 条目**永不推送**——手机没有新增/修改凭据的入口，
     * 回推只可能用过期数据覆盖电脑端。
     *
     * @param api 已带签名的客户端
     * @param masterKey 32B master_key（墓碑不带密文，保留参数以对齐其它写入路径）
     * @param webAuthn 当前 WebAuthn 条目
     * @param now 本次同步的 unix 秒
     * @return 回填后的条目与统计
     */
    private fun pushWebAuthnTombstones(
        api: VkeyApi,
        masterKey: ByteArray,
        webAuthn: List<WebAuthnItem>,
        now: Long,
    ): WebAuthnPushOutcome {
        val updated = LinkedHashMap<String, WebAuthnItem>(webAuthn.size)
        webAuthn.forEach { updated[it.id] = it }

        val revoked = webAuthn.filter { it.deleted && it.needsRevokePush() }
        var revokedCount = 0
        var conflicts = 0

        for (chunk in revoked.chunked(MAX_ITEMS_PER_PUSH)) {
            val writes = chunk.map { toWebAuthnTombstone(it, now) }
            val results = api.pushItems(writes).results
            chunk.forEachIndexed { index, item ->
                val result = results.getOrNull(index) ?: return@forEachIndexed
                if (result.status == STATUS_APPLIED) {
                    val ts = effectiveTimestamp(item.updatedAt, now)
                    updated[item.id] = item.copy(
                        version = result.version,
                        updatedAt = ts,
                        syncedUpdatedAt = ts,
                    )
                    revokedCount++
                } else {
                    updated[item.id] = item.copy(version = 0L, syncedUpdatedAt = 0L)
                    conflicts++
                }
            }
        }
        return WebAuthnPushOutcome(updated.values.toList(), revokedCount, conflicts)
    }

    // ------------------------------------------------------------------
    // 拉取
    // ------------------------------------------------------------------

    /**
     * 增量拉取，并按外层 `kind` 分流合并。
     *
     * @param api 已带签名的客户端
     * @param masterKey 32B master_key
     * @param items 推送后的 TOTP 条目
     * @param webAuthn 推送后的 WebAuthn 条目
     * @param since 起始游标（[VaultData.seq]）
     * @return 合并后的两个列表、新游标与统计
     */
    private fun pull(
        api: VkeyApi,
        masterKey: ByteArray,
        items: List<TotpItem>,
        webAuthn: List<WebAuthnItem>,
        since: Long,
    ): PullOutcome {
        val totpById = LinkedHashMap<String, TotpItem>(items.size)
        items.forEach { totpById[it.id] = it }
        val webAuthnById = LinkedHashMap<String, WebAuthnItem>(webAuthn.size)
        webAuthn.forEach { webAuthnById[it.id] = it }

        var cursor = since
        var pulled = 0
        var skipped = 0
        var forceRemote = false
        var pages = 0

        Log.d(TAG, "pull start since=$since")
        while (pages < MAX_PULL_PAGES) {
            pages++
            val page = api.listItems(cursor)

            for (remote in page.items) {
                val result = when (remote.kind) {
                    ItemJson.KIND_TOTP -> pullTotp(remote, totpById, masterKey, forceRemote)
                    ItemJson.KIND_WEBAUTHN -> pullWebAuthn(remote, webAuthnById, masterKey, forceRemote)
                    // 未知 kind：计入 skipped 并原样忽略，绝不回推
                    else -> MergeResult.SKIPPED
                }
                when (result) {
                    MergeResult.MERGED -> pulled++
                    MergeResult.SKIPPED -> skipped++
                    MergeResult.IGNORED -> Unit
                }
            }

            val next = page.next
            if (next < cursor) {
                // 服务端版本回滚（如从备份恢复）：全量重拉一次，且以服务端为准
                if (forceRemote) break
                forceRemote = true
                cursor = 0L
                continue
            }
            val previous = cursor
            cursor = next
            // 未满页 = 最后一页（协议 §4.7）；满页但游标没前进则防死循环
            if (page.items.size < PULL_PAGE_LIMIT) break
            if (next <= previous) break
        }
        return PullOutcome(
            items = totpById.values.toList(),
            webAuthn = webAuthnById.values.toList(),
            seq = cursor,
            pulled = pulled,
            skipped = skipped,
        )
    }

    /**
     * 合并一条服务端 TOTP 条目。
     *
     * @param remote 服务端条目（外层 `kind == totp`）
     * @param byId 本地 TOTP 索引（原地更新）
     * @param masterKey 32B master_key
     * @param forceRemote 服务端回滚后的全量重拉，忽略本地版本比较
     * @return 合并结果（合并 / 跳过 / 忽略）
     */
    private fun pullTotp(
        remote: SyncedItem,
        byId: MutableMap<String, TotpItem>,
        masterKey: ByteArray,
        forceRemote: Boolean,
    ): MergeResult {
        val local = byId[remote.id]
        // 服务端版本不比本地新时保留本地（服务端回滚后的全量重拉除外）
        if (!forceRemote && local != null && remote.version <= local.version) return MergeResult.IGNORED

        if (remote.deletedAt != 0L) {
            if (local == null) return MergeResult.IGNORED
            byId[remote.id] = local.copy(
                deleted = true,
                version = remote.version,
                updatedAt = remote.updatedAt,
                syncedUpdatedAt = remote.updatedAt,
            )
            return MergeResult.MERGED
        }

        val plain = decrypt(masterKey, remote.id, remote.ct, remote.nonce)
            ?: return MergeResult.SKIPPED
        // 明文 kind 与外层不符/未知：跳过，绝不回推
        val plainKind = ItemJson.kindOf(plain)
        if (plainKind != null && plainKind != ItemJson.KIND_TOTP) return MergeResult.SKIPPED
        val item = runCatching {
            ItemJson.decode(plain, remote.id, remote.version, remote.updatedAt)
        }.getOrNull() ?: return MergeResult.SKIPPED
        byId[remote.id] = item
        return MergeResult.MERGED
    }

    /**
     * 合并一条服务端 WebAuthn 条目（只读；墓碑则标记本地条目）。
     *
     * @param remote 服务端条目（外层 `kind == webauthn`）
     * @param byId 本地 WebAuthn 索引（原地更新）
     * @param masterKey 32B master_key
     * @param forceRemote 服务端回滚后的全量重拉，忽略本地版本比较
     * @return 合并结果（合并 / 跳过 / 忽略）
     */
    private fun pullWebAuthn(
        remote: SyncedItem,
        byId: MutableMap<String, WebAuthnItem>,
        masterKey: ByteArray,
        forceRemote: Boolean,
    ): MergeResult {
        val local = byId[remote.id]
        if (!forceRemote && local != null && remote.version <= local.version) return MergeResult.IGNORED

        if (remote.deletedAt != 0L) {
            if (local == null) return MergeResult.IGNORED
            byId[remote.id] = local.copy(
                deleted = true,
                version = remote.version,
                updatedAt = remote.updatedAt,
                syncedUpdatedAt = remote.updatedAt,
            )
            return MergeResult.MERGED
        }

        val plain = decrypt(masterKey, remote.id, remote.ct, remote.nonce)
            ?: return MergeResult.SKIPPED
        val plainKind = ItemJson.kindOf(plain)
        if (plainKind != null && plainKind != ItemJson.KIND_WEBAUTHN) return MergeResult.SKIPPED
        val item = runCatching {
            ItemJson.decodeWebAuthn(plain, remote.id, remote.version, remote.updatedAt)
        }.getOrNull() ?: return MergeResult.SKIPPED
        byId[remote.id] = item
        return MergeResult.MERGED
    }

    /**
     * 解密一条服务端 WebAuthn 条目并转成只读模型（实时查询用，不落库）。
     *
     * @param remote 外层 `kind == webauthn` 且非墓碑的条目
     * @param masterKey 32B master_key
     * @return 解码结果：成功给条目，失败给原因
     */
    private fun decodeLiveWebAuthn(remote: SyncedItem, masterKey: ByteArray): LiveDecode {
        val plain = decrypt(masterKey, remote.id, remote.ct, remote.nonce)
            ?: return LiveDecode(reason = REASON_OPEN_FAILED)
        val plainKind = ItemJson.kindOf(plain)
        if (plainKind != null && plainKind != ItemJson.KIND_WEBAUTHN) {
            return LiveDecode(reason = REASON_PARSE_FAILED)
        }
        val item = runCatching {
            ItemJson.decodeWebAuthn(plain, remote.id, remote.version, remote.updatedAt)
        }.getOrNull() ?: return LiveDecode(reason = REASON_PARSE_FAILED)
        return LiveDecode(item = item)
    }

    /**
     * 解密条目密文。
     *
     * @return 明文 JSON；密文为空、编码非法或 AEAD 校验失败时返回 null
     */
    private fun decrypt(masterKey: ByteArray, id: String, ct: String, nonce: String): String? {
        if (ct.isEmpty() || nonce.isEmpty()) return null
        return runCatching {
            val plain = Crypto.openItem(
                masterKey = masterKey,
                itemId = id,
                ciphertext = Crypto.b64urlDecode(ct),
                nonce = Crypto.b64urlDecode(nonce),
            )
            String(plain, Charsets.UTF_8)
        }.getOrNull()
    }

    // ------------------------------------------------------------------
    // 映射
    // ------------------------------------------------------------------

    /** 本地 TOTP 条目是否需要在本次同步推送。 */
    private fun TotpItem.needsPush(): Boolean = version == 0L || updatedAt > syncedUpdatedAt

    /** 本地 WebAuthn 墓碑是否需要在本次同步推送（只有用户显式吊销且尚未推成功的）。 */
    private fun WebAuthnItem.needsRevokePush(): Boolean =
        deleted && (version == 0L || updatedAt > syncedUpdatedAt)

    /** 推送时间戳：`updated_at` 缺失（旧 vault）时用本次同步时间补。 */
    private fun effectiveTimestamp(updatedAt: Long, now: Long): Long =
        if (updatedAt > 0L) updatedAt else now

    /**
     * 把本地 TOTP 条目转换为 `POST /items` 的写入项。
     *
     * 墓碑不带密文（`ct`/`nonce` 为空串），`deleted_at` 与 `updated_at` 取同一时间戳。
     */
    private fun toTotpWrite(item: TotpItem, masterKey: ByteArray, now: Long): ItemWrite {
        val ts = effectiveTimestamp(item.updatedAt, now)
        if (item.deleted) {
            return ItemWrite(
                id = item.id,
                kind = ItemJson.KIND_TOTP,
                rpId = RP_ID_TOTP,
                ct = "",
                nonce = "",
                baseVersion = item.version,
                updatedAt = ts,
                deletedAt = ts,
            )
        }
        val nonce = Crypto.random(Crypto.NONCE_LEN)
        val plain = ItemJson.encode(item).toByteArray(Charsets.UTF_8)
        val ct = Crypto.sealItem(masterKey, item.id, plain, nonce)
        return ItemWrite(
            id = item.id,
            kind = ItemJson.KIND_TOTP,
            rpId = RP_ID_TOTP,
            ct = Crypto.b64urlEncode(ct),
            nonce = Crypto.b64urlEncode(nonce),
            baseVersion = item.version,
            updatedAt = ts,
            deletedAt = 0L,
        )
    }

    /**
     * 把本地 WebAuthn 条目转换为**吊销墓碑**写入项。
     *
     * 只有墓碑走这里：`kind=webauthn`、`rp_id` 取条目自身、密文为空。
     */
    private fun toWebAuthnTombstone(item: WebAuthnItem, now: Long): ItemWrite {
        val ts = effectiveTimestamp(item.updatedAt, now)
        return ItemWrite(
            id = item.id,
            kind = ItemJson.KIND_WEBAUTHN,
            rpId = item.rpId,
            ct = "",
            nonce = "",
            baseVersion = item.version,
            updatedAt = ts,
            deletedAt = ts,
        )
    }

    private data class TotpPushOutcome(val items: List<TotpItem>, val pushed: Int, val conflicts: Int)

    private data class WebAuthnPushOutcome(
        val items: List<WebAuthnItem>,
        val revoked: Int,
        val conflicts: Int,
    )

    private data class PullOutcome(
        val items: List<TotpItem>,
        val webAuthn: List<WebAuthnItem>,
        val seq: Long,
        val pulled: Int,
        val skipped: Int,
    )

    /** 单条拉取条目的处理结果。 */
    private enum class MergeResult { MERGED, SKIPPED, IGNORED }

    /**
     * 实时查询单条的解码结果。
     *
     * @property item 解析成功的条目
     * @property reason 失败原因（`open-failed` / `parse-failed`），成功时为 null
     */
    private data class LiveDecode(val item: WebAuthnItem? = null, val reason: String? = null)
}
