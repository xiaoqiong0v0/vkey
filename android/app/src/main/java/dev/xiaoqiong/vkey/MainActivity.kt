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
import dev.xiaoqiong.vkey.sync.Links
import dev.xiaoqiong.vkey.totp.Totp
import dev.xiaoqiong.vkey.ui.clearClipboard
import dev.xiaoqiong.vkey.ui.copyToClipboard
import dev.xiaoqiong.vkey.vault.Base32
import dev.xiaoqiong.vkey.vault.DeviceConfig
import dev.xiaoqiong.vkey.vault.TotpItem
import dev.xiaoqiong.vkey.vault.VaultData
import dev.xiaoqiong.vkey.vault.VaultStore
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.UUID

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
        vault.value = store.read()
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
    var showSettings by remember { mutableStateOf(false) }
    var showSync by remember { mutableStateOf(false) }
    // 深链带来的配对码：先固定下来再清除 pending，避免 SyncScreen 首帧读到 null
    var syncPrefill by remember { mutableStateOf("") }
    // 逐帧时间源：进度条按真实时间连续推进（不再 500ms 一跳）
    var nowMillis by remember { mutableLongStateOf(System.currentTimeMillis()) }

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

    Box(Modifier.fillMaxSize()) {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text("vkey · ${vault.items.size} 条") },
                    actions = {
                        TextButton(onClick = { showSettings = true }) { Text("设置") }
                        TextButton(onClick = onLock) { Text("锁定") }
                    },
                )
            },
        ) { padding ->
            if (vault.items.isEmpty()) {
                Column(
                    modifier = Modifier.fillMaxSize().padding(padding).padding(24.dp),
                    verticalArrangement = Arrangement.Center,
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Text("还没有条目", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "点右下角「+」，可扫描二维码或手动输入 Base32 密钥",
                        style = MaterialTheme.typography.bodyMedium,
                        textAlign = TextAlign.Center,
                    )
                }
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize().padding(padding),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    items(vault.items, key = { it.id }) { item ->
                        TotpCard(
                            item = item,
                            nowMillis = nowMillis,
                            onCopy = { code ->
                                copyToClipboard(context, code, sensitive = true)
                                scope.launch {
                                    delay(30_000)
                                    clearClipboard(context)
                                }
                            },
                            onDelete = {
                                onPersist(vault.copy(items = vault.items.filterNot { it.id == item.id }))
                            },
                        )
                    }
                }
            }
        }

        // 遮罩：展开时铺满全屏接管点击，点空白处收起；画在内容之上、按钮之下
        if (fabExpanded) {
            Box(
                Modifier
                    .fillMaxSize()
                    .clickable(
                        interactionSource = remember { MutableInteractionSource() },
                        indication = null,
                    ) { fabExpanded = false },
            )
        }

        // 悬浮按钮组：绝对定位在右下角，动作按钮向上展开（不参与布局，故不会被裁剪）
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

    if (showSettings) {
        SettingsDialog(
            autoLockOnResume = autoLockOnResume,
            onAutoLockChange = onAutoLockChange,
            serverUrl = serverUrl,
            device = vault.device,
            onOpenSync = {
                showSettings = false
                syncPrefill = ""
                showSync = true
            },
            onDismiss = { showSettings = false },
        )
    }

    if (showSync) {
        dev.xiaoqiong.vkey.ui.SyncScreen(
            masterKey = vault.master_key,
            device = vault.device,
            serverUrl = serverUrl,
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
}

/** 设置：回前台是否重新解锁、同步配置入口（含当前配对状态）。 */
@Composable
private fun SettingsDialog(
    autoLockOnResume: Boolean,
    onAutoLockChange: (Boolean) -> Unit,
    serverUrl: String,
    device: DeviceConfig?,
    onOpenSync: () -> Unit,
    onDismiss: () -> Unit,
) {
    var autoLock by remember { mutableStateOf(autoLockOnResume) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("设置") },
        text = {
            Column {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Checkbox(checked = autoLock, onCheckedChange = { autoLock = it })
                    Text("回到前台时重新解锁")
                }
                Spacer(Modifier.height(12.dp))
                Text("同步", style = MaterialTheme.typography.titleSmall)
                Text(
                    "服务器：${device?.server_url ?: serverUrl.ifBlank { "（未设置）" }}",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(top = 4.dp),
                )
                Text(
                    "状态：" + if (device == null) {
                        "未配置"
                    } else {
                        "已登录（${device.device_name}）"
                    },
                    style = MaterialTheme.typography.bodySmall,
                )
                TextButton(onClick = {
                    onAutoLockChange(autoLock)
                    onOpenSync()
                }) { Text("同步配置 / 配对") }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                onAutoLockChange(autoLock)
                onDismiss()
            }) { Text("保存") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } },
    )
}

/**
 * 展开出来的动作按钮。
 *
 * 刻意不做透明度 / 尺寸 / 颜色动画：
 * - `graphicsLayer { alpha }` 会生成离屏图层，按按钮矩形裁掉外扩阴影；
 * - 容器色 alpha 会与背景混合导致动画过程中偏色；
 * - 尺寸动画会被布局边界裁剪。
 * 因此展开动画只由父级 `offset` 位移承担，按钮自身始终是「不透明、原色、固定尺寸」。
 */
@Composable
private fun ActionButton(label: String, onClick: () -> Unit) {
    ExtendedFloatingActionButton(
        onClick = onClick,
        icon = {},
        text = { Text(label) },
    )
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
