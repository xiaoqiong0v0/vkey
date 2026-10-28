package dev.xiaoqiong.vkey

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.FloatingActionButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.core.content.ContextCompat
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.xiaoqiong.vkey.sync.ItemJson
import dev.xiaoqiong.vkey.sync.ItemsSync
import dev.xiaoqiong.vkey.sync.Links
import dev.xiaoqiong.vkey.sync.SyncStats
import dev.xiaoqiong.vkey.totp.Totp
import dev.xiaoqiong.vkey.ui.clearClipboard
import dev.xiaoqiong.vkey.ui.copyToClipboard
import dev.xiaoqiong.vkey.ui.describeFailure
import dev.xiaoqiong.vkey.ui.formatSyncTime
import dev.xiaoqiong.vkey.vault.Base32
import dev.xiaoqiong.vkey.vault.DeviceConfig
import dev.xiaoqiong.vkey.vault.TotpItem
import dev.xiaoqiong.vkey.vault.VaultData
import dev.xiaoqiong.vkey.vault.VaultStore
import dev.xiaoqiong.vkey.vault.WebAuthnItem
import dev.xiaoqiong.vkey.vault.withLegacyWebAuthnMigrated
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

/** 列表页的页签索引：2FA / 密钥（与 HorizontalPager 的页序一致）。 */
private const val PAGE_2FA = 0
private const val PAGE_WEBAUTHN = 1
private const val PAGE_COUNT = 2

/** 密钥凭据创建时间的展示格式。 */
private const val CREATED_AT_PATTERN = "yyyy-MM-dd HH:mm"

/** 应用入口：持有库状态与「自动锁定」逻辑，UI 全部在 Compose 里。 */
class MainActivity : androidx.fragment.app.FragmentActivity() {

    private lateinit var store: VaultStore
    private lateinit var settings: dev.xiaoqiong.vkey.vault.AppSettings

    private val vault = mutableStateOf<VaultData?>(null)
    private val locked = mutableStateOf(false)
    private val lockMessage = mutableStateOf("正在验证…")
    private val canRetry = mutableStateOf(false)

    /** 深链带来的服务器地址（非空表示要打开「同步配置」页）。 */
    private val pendingSyncServer = mutableStateOf<String?>(null)

    /** 深链带来的配对码（预填到同步配置页）。 */
    private val pendingPairCode = mutableStateOf<String?>(null)

    /** 系统验证进行中，避免重复拉起。 */
    private var authInFlight = false

    /** 验证弹窗关闭会触发一次 onResume，用它跳过循环触发。 */
    private var skipNextResume = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 防截屏（验证码属于敏感信息）
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)

        store = VaultStore(filesDir)
        settings = dev.xiaoqiong.vkey.vault.AppSettings(this)
        val loaded = store.read()
        // 旧版本把 webauthn 误并入 items：升级后一次性迁移到「密钥」列表并落盘
        val migrated = loaded?.withLegacyWebAuthnMigrated()
        if (migrated != null && migrated != loaded) store.write(migrated)
        vault.value = migrated
        locked.value = vault.value != null
        handleDeepLink(intent)

        setContent {
            MaterialTheme {
                VkeyApp(
                    vault = vault.value,
                    locked = locked.value,
                    lockMessage = lockMessage.value,
                    canRetry = canRetry.value,
                    onRetryLock = { showSystemAuth() },
                    onCreate = { data ->
                        vault.value = data
                        locked.value = false
                    },
                    onUnlock = { locked.value = false },
                    onLock = { locked.value = true },
                    onPersist = { data ->
                        vault.value = data
                        store.write(data)
                    },
                    autoLockOnResume = settings.autoLockOnResume,
                    onAutoLockChange = { settings.autoLockOnResume = it },
                    serverUrl = settings.serverUrl,
                    onServerUrlChange = { settings.serverUrl = it },
                    pendingSyncServer = pendingSyncServer.value,
                    pendingPairCode = pendingPairCode.value,
                    onPendingHandled = {
                        pendingSyncServer.value = null
                        pendingPairCode.value = null
                    },
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleDeepLink(intent)
    }

    /**
     * 处理 `vkey://config?server=…` 与 `vkey://pair?code=…` 深链。
     *
     * - 配置深链：只写服务器地址，并打开「同步配置」页让用户输入配对码 / master_key；
     * - 配对深链：预填配对码（免鉴权领取，无需先登录）。
     *
     * @param intent 启动或复用的 Intent（非 VIEW 或没有 data 时直接返回）
     */
    private fun handleDeepLink(intent: Intent?) {
        if (intent?.action != Intent.ACTION_VIEW) return
        val data = intent.dataString ?: return

        val server = Links.parseServerConfig(data)
        if (server != null) {
            settings.serverUrl = server
            pendingPairCode.value = null
            pendingSyncServer.value = server
            Toast.makeText(this, "服务器地址已设置：$server", Toast.LENGTH_LONG).show()
            return
        }

        val code = Links.parsePairCodeLink(data)
        if (code != null) {
            pendingPairCode.value = code
            pendingSyncServer.value = settings.serverUrl
            Toast.makeText(this, "已识别配对码，请在「同步配置」里领取", Toast.LENGTH_LONG).show()
        }
    }

    override fun onStop() {
        // 默认不锁：用户已在系统层解锁过；需要在设置里打开「回前台重新解锁」
        if (vault.value != null && settings.autoLockOnResume) {
            locked.value = true
        }
        super.onStop()
    }

    override fun onResume() {
        super.onResume()
        if (skipNextResume) {
            skipNextResume = false
            return
        }
        if (vault.value != null && locked.value) {
            showSystemAuth()
        }
    }

    /**
     * 拉起系统验证（指纹 / 面容 / 锁屏密码）。
     *
     * 说明：`BiometricPrompt` 关闭后会触发一次 onResume，用 `skipNextResume`
     * 避免「取消 → 立刻重弹」的循环；需要用户主动点击才能再次验证。
     */
    private fun showSystemAuth() {
        if (authInFlight) return
        val allowed = androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG or
            androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
        val km = getSystemService(KEYGUARD_SERVICE) as android.app.KeyguardManager
        if (!km.isDeviceSecure) {
            lockMessage.value = "请先在系统设置里设置锁屏密码或录入指纹"
            canRetry.value = false
            return
        }
        authInFlight = true
        canRetry.value = false
        lockMessage.value = "正在验证…"
        val prompt = androidx.biometric.BiometricPrompt(
            this,
            androidx.core.content.ContextCompat.getMainExecutor(this),
            object : androidx.biometric.BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    result: androidx.biometric.BiometricPrompt.AuthenticationResult,
                ) {
                    authInFlight = false
                    locked.value = false
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    authInFlight = false
                    skipNextResume = true
                    lockMessage.value = "验证未通过：$errString"
                    canRetry.value = true
                }

                override fun onAuthenticationFailed() {
                    lockMessage.value = "未识别，请重试"
                }
            },
        )
        val info = androidx.biometric.BiometricPrompt.PromptInfo.Builder()
            .setTitle("解锁 vkey")
            .setSubtitle("使用指纹 / 面容 / 锁屏密码")
            .setAllowedAuthenticators(allowed)
            .build()
        runCatching { prompt.authenticate(info) }
            .onFailure {
                authInFlight = false
                skipNextResume = true
                lockMessage.value = "无法启动系统验证：${it.message}"
                canRetry.value = true
            }
    }
}

@Composable
private fun VkeyApp(
    vault: VaultData?,
    locked: Boolean,
    lockMessage: String,
    canRetry: Boolean,
    onRetryLock: () -> Unit,
    onCreate: (VaultData) -> Unit,
    onUnlock: () -> Unit,
    onLock: () -> Unit,
    onPersist: (VaultData) -> Unit,
    autoLockOnResume: Boolean,
    onAutoLockChange: (Boolean) -> Unit,
    serverUrl: String,
    onServerUrlChange: (String) -> Unit,
    pendingSyncServer: String?,
    pendingPairCode: String?,
    onPendingHandled: () -> Unit,
) {
    when {
        vault == null -> SetupScreen(onCreate = onCreate)
        locked -> LockScreen(message = lockMessage, canRetry = canRetry, onRetry = onRetryLock)
        else -> VaultScreen(
            vault = vault,
            onLock = onLock,
            onPersist = onPersist,
            autoLockOnResume = autoLockOnResume,
            onAutoLockChange = onAutoLockChange,
            serverUrl = serverUrl,
            onServerUrlChange = onServerUrlChange,
            pendingSyncServer = pendingSyncServer,
            pendingPairCode = pendingPairCode,
            onPendingHandled = onPendingHandled,
        )
    }
}

/** 首次引导：生成主密钥 → 强制展示并确认已保存恢复码。 */
@Composable
private fun SetupScreen(onCreate: (VaultData) -> Unit) {
    val context = LocalContext.current
    val store = remember { VaultStore(context.filesDir) }
    val recoveryCode = remember { store.generateMasterKey() }
    var saved by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Text("创建 vkey 库", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(8.dp))
        Text(
            "这是你的恢复码（52 位）。它等价于你的主密钥：丢失后任何设备都无法解开你的数据。",
            style = MaterialTheme.typography.bodyMedium,
        )
        Spacer(Modifier.height(16.dp))
        Card(Modifier.fillMaxWidth()) {
            Text(
                text = recoveryCode.chunked(4).joinToString(" "),
                modifier = Modifier.padding(16.dp),
                fontFamily = FontFamily.Monospace,
                fontSize = 16.sp,
                fontWeight = FontWeight.Medium,
            )
        }
        Spacer(Modifier.height(8.dp))
        TextButton(onClick = { copyToClipboard(context, recoveryCode, sensitive = true) }) {
            Text("复制恢复码")
        }
        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = saved, onCheckedChange = { saved = it })
            Text("我已把恢复码保存到安全的地方")
        }
        Spacer(Modifier.height(16.dp))
        Button(
            onClick = { onCreate(store.create(recoveryCode)) },
            enabled = saved,
            modifier = Modifier.fillMaxWidth(),
        ) { Text("进入") }
    }
}

/**
 * 解锁页（纯展示）：真正的验证由 Activity 在 `onResume` 里拉起，
 * 这里只负责显示状态与「点一下重试」。
 */
@Composable
private fun LockScreen(message: String, canRetry: Boolean, onRetry: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp)
            .clickable(
                interactionSource = remember { MutableInteractionSource() },
                indication = null,
            ) { if (canRetry) onRetry() },
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("vkey 已锁定", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(12.dp))
        Text(message, style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center)
        if (canRetry) {
            Spacer(Modifier.height(8.dp))
            Text(
                "点屏幕重试",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.primary,
            )
        }
    }
}
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun VaultScreen(
    vault: VaultData,
    onLock: () -> Unit,
    onPersist: (VaultData) -> Unit,
    autoLockOnResume: Boolean,
    onAutoLockChange: (Boolean) -> Unit,
    serverUrl: String,
    onServerUrlChange: (String) -> Unit,
    pendingSyncServer: String?,
    pendingPairCode: String?,
    onPendingHandled: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var showAdd by remember { mutableStateOf(false) }
    var showScan by remember { mutableStateOf(false) }
    var fabExpanded by remember { mutableStateOf(false) }
    var showSync by remember { mutableStateOf(false) }
    // 待确认的删除 / 吊销目标：null = 没有弹窗（所有删除都必须二次确认）
    var pendingDelete by remember { mutableStateOf<TotpItem?>(null) }
    var pendingRevoke by remember { mutableStateOf<WebAuthnItem?>(null) }
    // 2FA / 密钥两个页签，支持左右滑动；页签与滑动双向同步
    val pagerState = rememberPagerState(pageCount = { PAGE_COUNT })
    // 深链带来的配对码：先固定下来再清除 pending，避免 SyncScreen 首帧读到 null
    var syncPrefill by remember { mutableStateOf("") }
    // 主页：连按两次返回才退出（第一次给出提示）
    val activity = LocalContext.current as? android.app.Activity
    var lastBackAt by remember { mutableLongStateOf(0L) }
    androidx.activity.compose.BackHandler {
        val now = System.currentTimeMillis()
        if (now - lastBackAt < 2000L) {
            activity?.finish()
        } else {
            lastBackAt = now
            android.widget.Toast
                .makeText(context, "再按一次返回退出", android.widget.Toast.LENGTH_SHORT)
                .show()
        }
    }

    // 逐帧时间源：进度条按真实时间连续推进（不再 500ms 一跳）
    var nowMillis by remember { mutableLongStateOf(System.currentTimeMillis()) }
    // 同步串行化：自动同步与「立即同步」可能同时发生，避免两次合并互相覆盖
    val syncMutex = remember { Mutex() }
    // 最近一次自动/手动同步的失败原因（不打扰用户，只在设置页状态里展示）
    var lastSyncError by remember { mutableStateOf<String?>(null) }
    // 同步回调里要用最新的库内容，避免闭包捕获旧快照
    val latestVault by rememberUpdatedState(vault)

    /**
     * 执行一次条目同步：IO 上跑 [ItemsSync.sync]，把结果合并回最新库并落盘。
     *
     * 合并策略：以同步结果为准，但保留同步期间新增（结果里不存在）的本地条目。
     *
     * @return 本次同步统计
     */
    val doSync: suspend () -> SyncStats = {
        syncMutex.withLock {
            val before = latestVault
            try {
                val outcome = ItemsSync.sync(before)
                val synced = outcome.vault
                val syncedIds = synced.items.mapTo(HashSet()) { it.id }
                val syncedWebAuthnIds = synced.webAuthn.mapTo(HashSet()) { it.id }
                val merged = synced.copy(
                    items = synced.items + before.items.filterNot { it.id in syncedIds },
                    // 拉取期间本地新增的密钥条目（理论上没有，防御性保留）同样不能丢
                    webAuthn = synced.webAuthn +
                        before.webAuthn.filterNot { it.id in syncedWebAuthnIds },
                )
                onPersist(merged)
                lastSyncError = null
                outcome.stats
            } catch (t: Throwable) {
                lastSyncError = describeFailure(t)
                throw t
            }
        }
    }

    // 进入列表页且已配置时自动同步一次：失败不打扰用户，只记录状态
    LaunchedEffect(Unit) {
        if (latestVault.device != null) {
            runCatching { doSync() }
        }
    }

    LaunchedEffect(pendingSyncServer, pendingPairCode) {
        if (pendingSyncServer != null || pendingPairCode != null) {
            syncPrefill = pendingPairCode.orEmpty()
            showSync = true
            onPendingHandled()
        }
    }

    // 0 = 收起，1 = 完全展开；驱动按钮的位移与透明度
    val expandProgress by animateFloatAsState(
        targetValue = if (fabExpanded) 1f else 0f,
        animationSpec = tween(durationMillis = 180),
        label = "fab-expand",
    )

    LaunchedEffect(Unit) {
        while (true) {
            androidx.compose.runtime.withFrameNanos { nowMillis = System.currentTimeMillis() }
        }
    }

    // 切到「密钥」页时收起「+」菜单（FAB 只在 2FA 页出现）
    LaunchedEffect(pagerState.currentPage) {
        if (pagerState.currentPage != PAGE_2FA) fabExpanded = false
    }

    Box(Modifier.fillMaxSize()) {
        // 墓碑条目仍在库里（等下次同步推送），但 UI 不显示；非 totp 条目不属于 2FA 页
        val visibleTotp = vault.items.filter { it.kind == ItemJson.KIND_TOTP && !it.deleted }
        val visibleWebAuthn = vault.webAuthn.filterNot { it.deleted }
        Scaffold(
            topBar = {
                TopAppBar(
                    title = {
                        Text(
                            "vkey · 2FA ${visibleTotp.size} · 密钥 ${visibleWebAuthn.size}",
                            style = MaterialTheme.typography.titleMedium,
                        )
                    },
                    actions = {
                        TextButton(onClick = { syncPrefill = ""; showSync = true }) { Text("设置") }
                        TextButton(onClick = onLock) { Text("锁定") }
                    },
                )
            },
        ) { padding ->
            Column(Modifier.fillMaxSize().padding(padding)) {
                TabRow(selectedTabIndex = pagerState.currentPage) {
                    Tab(
                        selected = pagerState.currentPage == PAGE_2FA,
                        onClick = { scope.launch { pagerState.animateScrollToPage(PAGE_2FA) } },
                        text = { Text("2FA") },
                    )
                    Tab(
                        selected = pagerState.currentPage == PAGE_WEBAUTHN,
                        onClick = { scope.launch { pagerState.animateScrollToPage(PAGE_WEBAUTHN) } },
                        text = { Text("密钥") },
                    )
                }
                HorizontalPager(state = pagerState, modifier = Modifier.fillMaxSize()) { page ->
                    when (page) {
                        PAGE_2FA -> TotpList(
                            entries = visibleTotp,
                            nowMillis = nowMillis,
                            onCopy = { code ->
                                copyToClipboard(context, code, sensitive = true)
                                scope.launch {
                                    delay(30_000)
                                    clearClipboard(context)
                                }
                            },
                            onDelete = { pendingDelete = it },
                        )
                        else -> WebAuthnList(
                            entries = visibleWebAuthn,
                            onRevoke = { pendingRevoke = it },
                        )
                    }
                }
            }
        }

        // 遮罩：展开时铺满全屏接管点击，点空白处收起；画在内容之上、按钮之下
        if (fabExpanded && pagerState.currentPage == PAGE_2FA) {
            Box(
                Modifier
                    .fillMaxSize()
                    .clickable(
                        interactionSource = remember { MutableInteractionSource() },
                        indication = null,
                    ) { fabExpanded = false },
            )
        }

        // 悬浮按钮组：只在 2FA 页出现（密钥页只读/可吊销，不提供新增）
        if (pagerState.currentPage == PAGE_2FA) {
            Column(
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .padding(end = 16.dp, bottom = 24.dp),
                horizontalAlignment = Alignment.End,
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                if (expandProgress > 0.01f) {
                    Column(
                        horizontalAlignment = Alignment.End,
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                        // 先叠在 FAB 上方再向上分开：只做位移（0 → 12dp），不做透明度/尺寸动画
                        modifier = Modifier
                            .offset(y = ((1f - expandProgress) * 12).dp),
                    ) {
                        ActionButton(
                            label = "扫描二维码",
                            onClick = {
                                fabExpanded = false
                                showScan = true
                            },
                        )
                        ActionButton(
                            label = "手动输入",
                            onClick = {
                                fabExpanded = false
                                showAdd = true
                            },
                        )
                    }
                    Spacer(Modifier.height(4.dp))
                }

                val plusRotation by animateFloatAsState(
                    targetValue = if (fabExpanded) 45f else 0f,
                    animationSpec = tween(durationMillis = 180),
                    label = "fab-plus-rotation",
                )
                FloatingActionButton(onClick = { fabExpanded = !fabExpanded }) {
                    Text(
                        text = "+",
                        fontSize = 28.sp,
                        modifier = Modifier.rotate(plusRotation),
                    )
                }
            }
        }
    }


    if (showSync) {
        dev.xiaoqiong.vkey.ui.SyncScreen(
            masterKey = vault.master_key,
            device = vault.device,
            serverUrl = serverUrl,
            lastSyncAt = vault.lastSyncAt,
            onSyncNow = doSync,
            initialPairCode = syncPrefill.takeIf { it.isNotBlank() },
            onSaved = { config, newMasterKey ->
                // 配对拿到的 master_key 才是账号密钥：以它为准（本地条目保留）
                onPersist(
                    vault.copy(
                        master_key = newMasterKey ?: vault.master_key,
                        device = config,
                    ),
                )
            },
            onServerUrlChange = onServerUrlChange,
            autoLockOnResume = autoLockOnResume,
            onAutoLockChange = onAutoLockChange,
            onClearDevice = { onPersist(vault.copy(device = null)) },
            onClose = { showSync = false },
        )
    }

    if (showScan) {
        dev.xiaoqiong.vkey.ui.ScanScreen(
            onResult = { item ->
                onPersist(vault.copy(items = vault.items + item))
                showScan = false
            },
            onCancel = { showScan = false },
        )
    }

    if (showAdd) {
        AddDialog(
            onDismiss = { showAdd = false },
            onAdd = { issuer, account, secret ->
                val item = TotpItem(
                    id = UUID.randomUUID().toString(),
                    issuer = issuer,
                    account = account,
                    secret = secret,
                    created_at = System.currentTimeMillis() / 1000,
                )
                onPersist(vault.copy(items = vault.items + item))
                showAdd = false
            },
        )
    }

    // 删除 2FA 条目：二次确认后才打墓碑（下次同步把删除推到服务端）
    pendingDelete?.let { item ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            title = { Text("删除 2FA 条目") },
            text = { Text("删除后无法恢复（服务端也会删除）。") },
            confirmButton = {
                TextButton(onClick = {
                    val now = System.currentTimeMillis() / 1000
                    onPersist(
                        vault.copy(
                            items = vault.items.map { old ->
                                if (old.id == item.id) old.copy(deleted = true, updatedAt = now) else old
                            },
                        ),
                    )
                    pendingDelete = null
                }) { Text("删除") }
            },
            dismissButton = { TextButton(onClick = { pendingDelete = null }) { Text("取消") } },
        )
    }

    // 吊销 WebAuthn 凭据：二次确认后才打墓碑（唯一会推送的密钥操作）
    pendingRevoke?.let { item ->
        AlertDialog(
            onDismissRequest = { pendingRevoke = null },
            title = { Text("吊销密钥凭据") },
            text = { Text("吊销后所有设备（含电脑）将无法再用该站点凭据。") },
            confirmButton = {
                TextButton(onClick = {
                    val now = System.currentTimeMillis() / 1000
                    onPersist(
                        vault.copy(
                            webAuthn = vault.webAuthn.map { old ->
                                if (old.id == item.id) old.copy(deleted = true, updatedAt = now) else old
                            },
                        ),
                    )
                    pendingRevoke = null
                }) { Text("吊销") }
            },
            dismissButton = { TextButton(onClick = { pendingRevoke = null }) { Text("取消") } },
        )
    }
}

@Composable
private fun ActionButton(label: String, onClick: () -> Unit) {
    ExtendedFloatingActionButton(
        onClick = onClick,
        icon = {},
        text = { Text(label) },
    )
}

/**
 * 2FA 页：TOTP 卡片列表（空态给出添加入口提示）。
 *
 * @param entries 可见条目（已过滤墓碑）
 * @param nowMillis 当前时间，用于推进验证码进度
 * @param onCopy 复制验证码
 * @param onDelete 请求删除（需二次确认后才打墓碑）
 */
@Composable
private fun TotpList(
    entries: List<TotpItem>,
    nowMillis: Long,
    onCopy: (String) -> Unit,
    onDelete: (TotpItem) -> Unit,
) {
    if (entries.isEmpty()) {
        EmptyState("还没有 2FA 条目", "点右下角「+」，可扫描二维码或手动输入 Base32 密钥")
        return
    }
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        items(entries, key = { it.id }) { item ->
            TotpCard(
                item = item,
                nowMillis = nowMillis,
                onCopy = onCopy,
                onDelete = { onDelete(item) },
            )
        }
    }
}

/**
 * 密钥页：WebAuthn 凭据列表（只读 + 吊销；不提供新增）。
 *
 * @param entries 可见条目（已过滤墓碑）
 * @param onRevoke 请求吊销（需二次确认后才打墓碑）
 */
@Composable
private fun WebAuthnList(entries: List<WebAuthnItem>, onRevoke: (WebAuthnItem) -> Unit) {
    if (entries.isEmpty()) {
        EmptyState(
            "没有密钥凭据",
            "这些是桌面端的虚拟密钥凭据，手机只读/可吊销（不能在这里新增）。",
        )
        return
    }
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        items(entries, key = { it.id }) { item ->
            WebAuthnCard(item = item, onRevoke = { onRevoke(item) })
        }
    }
}

/** 统一空态：标题 + 说明，居中展示。 */
@Composable
private fun EmptyState(title: String, description: String) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(title, style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(8.dp))
        Text(
            description,
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
        )
    }
}

/** 单条 WebAuthn 凭据：站点、账号、创建时间 + 「吊销」。 */
@Composable
private fun WebAuthnCard(item: WebAuthnItem, onRevoke: () -> Unit) {
    val createdAt = remember(item.createdAt) { formatCreatedAt(item.createdAt) }
    Card(Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.Top,
        ) {
            Column(Modifier.weight(1f)) {
                Text(item.rpId.ifBlank { "(未知站点)" }, style = MaterialTheme.typography.titleMedium)
                Text(
                    item.username.ifBlank { item.displayName }.ifBlank { "(未命名账号)" },
                    style = MaterialTheme.typography.bodySmall,
                )
                if (createdAt != null) {
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "创建于 $createdAt",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            TextButton(onClick = onRevoke) { Text("吊销") }
        }
    }
}

/**
 * 把 unix 秒格式化为本地时间。
 *
 * @param epochSeconds unix 秒
 * @return 本地 `yyyy-MM-dd HH:mm`；未知（<=0）返回 null
 */
private fun formatCreatedAt(epochSeconds: Long): String? {
    if (epochSeconds <= 0L) return null
    return SimpleDateFormat(CREATED_AT_PATTERN, Locale.getDefault())
        .format(Date(epochSeconds * 1000L))
}

@Composable
private fun TotpCard(
    item: TotpItem,
    nowMillis: Long,
    onCopy: (String) -> Unit,
    onDelete: () -> Unit,
) {
    val nowSeconds = nowMillis / 1000
    // 验证码每 30s 才变：按窗口记忆，避免逐帧重算 HMAC
    val code = remember(nowSeconds / item.period) {
        Totp.code(item.secret, nowSeconds, item.digits, item.period, item.algorithm)
    } ?: "------"
    val periodMs = item.period * 1000L
    val remainMillis = periodMs - (nowMillis % periodMs)
    val remainProgress = (remainMillis.toDouble() / periodMs).toFloat()
    val remain = kotlin.math.ceil(remainMillis / 1000.0).toInt().coerceAtLeast(0)

    Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors()) {
        Column(Modifier.padding(16.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Column {
                    Text(item.issuer.ifBlank { "(未命名)" }, style = MaterialTheme.typography.titleMedium)
                    Text(item.account, style = MaterialTheme.typography.bodySmall)
                }
                TextButton(onClick = onDelete) { Text("删除") }
            }
            Spacer(Modifier.height(8.dp))
            Text(
                text = code.chunked(3).joinToString(" "),
                fontFamily = FontFamily.Monospace,
                fontSize = 28.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.fillMaxWidth(),
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(8.dp))
            LinearProgressIndicator(
                progress = { remainProgress },
                modifier = Modifier.fillMaxWidth(),
                // 关掉 Material3 默认的「stop indicator」小圆点
                drawStopIndicator = {},
            )
            Spacer(Modifier.height(8.dp))
            Button(onClick = { onCopy(code) }, modifier = Modifier.fillMaxWidth()) {
                Text("复制（${remain}s）")
            }
        }
        HorizontalDivider()
    }
}

@Composable
private fun AddDialog(onDismiss: () -> Unit, onAdd: (String, String, String) -> Unit) {
    var issuer by remember { mutableStateOf("") }
    var account by remember { mutableStateOf("") }
    var secret by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("添加 TOTP") },
        text = {
            Column {
                OutlinedTextField(
                    value = issuer,
                    onValueChange = { issuer = it },
                    label = { Text("issuer（如 GitHub）") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = account,
                    onValueChange = { account = it },
                    label = { Text("账号") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = secret,
                    onValueChange = { secret = it },
                    label = { Text("Base32 密钥") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
                    modifier = Modifier.fillMaxWidth(),
                )
                error?.let {
                    Spacer(Modifier.height(8.dp))
                    Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val key = secret.trim()
                val decoded = Base32.decode(key)
                when {
                    decoded == null -> error = "密钥不是合法的 Base32"
                    decoded.size < 10 -> error = "解码后长度过短（${decoded.size}B），疑似不完整"
                    else -> onAdd(issuer.trim(), account.trim(), key.uppercase())
                }
            }) { Text("保存") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } },
    )
}
