package cn.xiaoqiong0v0.vkey

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.darkColorScheme
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import cn.xiaoqiong0v0.vkey.totp.Totp
import cn.xiaoqiong0v0.vkey.vault.Base32
import cn.xiaoqiong0v0.vkey.vault.Vault
import cn.xiaoqiong0v0.vkey.vault.VaultItem
import cn.xiaoqiong0v0.vkey.vault.VaultStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** 后台停留多久（毫秒）后回来需要重新解锁（M3.1 写死 5 分钟） */
private const val LOCK_TIMEOUT_MS: Long = 5 * 60 * 1000L

/** 列表刷新间隔（毫秒）：兼顾进度条平滑与耗电 */
private const val TICK_INTERVAL_MS: Long = 200L

/** 复制验证码后多少毫秒清空剪贴板 */
private const val CLIPBOARD_CLEAR_DELAY_MS: Long = 30 * 1000L

/** 复制提示文案里展示的秒数（与上面的常量保持一致） */
private const val CLIPBOARD_CLEAR_SECONDS: Int = 30

/** 剪贴板标签（不含敏感信息） */
private const val CLIP_LABEL: String = "vkey-totp"

/** 允许的 secret 解码长度下限（字节） */
private const val MIN_SECRET_BYTES: Int = 10

/** 允许的 secret 解码长度上限（字节） */
private const val MAX_SECRET_BYTES: Int = 64

/** 主题配色（深色，TOTP 类应用常用低亮度） */
private val VkeyColorScheme = darkColorScheme(
    primary = Color(0xFF6FD3A8),
    onPrimary = Color(0xFF06281C),
    secondary = Color(0xFF9CC7B6),
    background = Color(0xFF101114),
    onBackground = Color(0xFFE6E8E6),
    surface = Color(0xFF191B1F),
    onSurface = Color(0xFFE6E8E6),
    surfaceVariant = Color(0xFF23262B),
    onSurfaceVariant = Color(0xFFB4B9B6),
    error = Color(0xFFFFB4AB),
)

/**
 * 功能：单 Activity 入口；设置 FLAG_SECURE 并驱动 Compose UI。
 */
class MainActivity : ComponentActivity() {

    /** 每次自增表示「需要立刻锁定」（后台超时返回时触发） */
    private var lockSignal: Int by mutableStateOf(0)

    /** 上次 onStop 的时间戳（0 表示没有记录） */
    private var stoppedAtMillis: Long = 0L

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 防截屏 / 防最近任务预览（方案 §8 强制项）
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
        setContent {
            MaterialTheme(colorScheme = VkeyColorScheme) {
                Surface(modifier = Modifier.fillMaxSize()) {
                    VkeyApp(lockSignal = lockSignal)
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        val leftAt = stoppedAtMillis
        stoppedAtMillis = 0L
        if (leftAt > 0L && System.currentTimeMillis() - leftAt >= LOCK_TIMEOUT_MS) {
            lockSignal += 1
        }
    }

    override fun onStop() {
        super.onStop()
        // 配置变更（旋转等）不算「退到后台」
        if (!isChangingConfigurations) {
            stoppedAtMillis = System.currentTimeMillis()
        }
    }
}

/** 界面阶段状态机 */
private sealed interface Phase {
    /** 首次读取磁盘中 */
    data object Loading : Phase

    /** 强制确认恢复码（未确认不得进入主界面） */
    data class Onboarding(val recoveryCode: String) : Phase

    /** 已锁定（内存中没有明文 vault） */
    data object Locked : Phase

    /** 已解锁 */
    data object Unlocked : Phase

    /** 不可恢复的错误（密钥失效 / 文件损坏） */
    data class Failure(val message: String) : Phase
}

/** 首次加载结果 */
private data class LoadedVault(
    val vault: Vault,
    val recoveryCode: String,
    val needsRecoveryConfirm: Boolean,
)

/**
 * 功能：vault 状态与业务动作（M3.1 用手写容器，不引入 ViewModel/Hilt）。
 * @param context 应用 Context（只用 filesDir 与 Keystore）
 * @param scope 组合作用域，用于异步落盘
 */
private class VaultController(
    context: Context,
    private val scope: CoroutineScope,
) {
    private val store: VaultStore = VaultStore(context)

    /** 当前阶段 */
    var phase: Phase by mutableStateOf(Phase.Loading)
        private set

    /** 明文 vault（仅解锁期间存在于内存） */
    var vault: Vault? by mutableStateOf(null)
        private set

    /** 是否正在做 IO（避免重复点击） */
    var busy: Boolean by mutableStateOf(false)
        private set

    /** 一次性提示（Snackbar 用） */
    var notice: String? by mutableStateOf(null)
        private set

    init {
        reload()
    }

    /** 功能：重新读取本地 vault（首次进入 / 失败后重试）。 */
    fun reload() {
        scope.launch {
            busy = true
            val result = runCatching { withContext(Dispatchers.IO) { bootstrap() } }
            busy = false
            result
                .onSuccess { loaded ->
                    vault = loaded.vault
                    phase = if (loaded.needsRecoveryConfirm) {
                        Phase.Onboarding(loaded.recoveryCode)
                    } else {
                        Phase.Unlocked
                    }
                }
                .onFailure { error ->
                    phase = Phase.Failure(error.message ?: "无法读取本地保管库")
                }
        }
    }

    /** 功能：用户确认已保存恢复码后进入主界面。 */
    fun confirmRecovery() {
        store.markRecoveryConfirmed()
        vault?.let { if (it.items.isEmpty()) notice = "还没有条目，点右下角「添加」" }
        phase = Phase.Unlocked
    }

    /** 功能：立即锁定（清掉内存明文）。 */
    fun lock() {
        if (vault == null) return
        vault = null
        phase = Phase.Locked
    }

    /** 功能：点击解锁（M3.1 只需确认；生物识别留 M3.3）。 */
    fun unlock() {
        if (busy) return
        scope.launch {
            busy = true
            val result = runCatching { withContext(Dispatchers.IO) { store.load() } }
            busy = false
            result
                .onSuccess { loaded ->
                    if (loaded == null) {
                        phase = Phase.Failure("本地保管库丢失，请重新安装或恢复")
                    } else {
                        vault = loaded
                        phase = Phase.Unlocked
                    }
                }
                .onFailure { error ->
                    phase = Phase.Failure(error.message ?: "解锁失败")
                }
        }
    }

    /**
     * 功能：新增一条 TOTP 条目（校验通过后落盘）。
     * @return null 表示成功；否则返回给用户看的错误文案
     */
    fun addItem(issuer: String, account: String, secretInput: String): String? {
        val current = vault ?: return "当前未解锁"
        if (issuer.isBlank() && account.isBlank()) return "issuer / account 至少填写一项"
        if (secretInput.isBlank()) return "密钥不能为空"

        val normalized = secretInput.filter { !it.isWhitespace() && it != '-' && it != '=' }.uppercase()
        val bytes = runCatching { Base32.decode(normalized) }.getOrElse { error ->
            return "不是合法的 Base32：${error.message ?: "解析失败"}"
        }
        if (bytes.size < MIN_SECRET_BYTES) {
            return "密钥太短：解码后仅 ${bytes.size} 字节（至少 $MIN_SECRET_BYTES）"
        }
        if (bytes.size > MAX_SECRET_BYTES) {
            return "密钥太长：解码后 ${bytes.size} 字节（最多 $MAX_SECRET_BYTES）"
        }

        val updated = current.copy(
            items = current.items + VaultItem.create(issuer, account, Base32.encode(bytes)),
        )
        vault = updated
        persist(updated)
        notice = "已添加"
        return null
    }

    /**
     * 功能：删除指定条目并落盘。
     * @param id 条目 id
     */
    fun deleteItem(id: String) {
        val current = vault ?: return
        val updated = current.copy(items = current.items.filterNot { it.id == id })
        vault = updated
        persist(updated)
        notice = "已删除"
    }

    /** 功能：消费一次性提示。 */
    fun consumeNotice() {
        notice = null
    }

    /**
     * 功能：投递一次性提示（界面用 Snackbar 展示）。
     * @param text 提示文案
     */
    fun addNotice(text: String) {
        notice = text
    }

    /**
     * 功能：异步加密落盘。
     * @param value 要保存的 vault
     */
    private fun persist(value: Vault) {
        scope.launch {
            runCatching { withContext(Dispatchers.IO) { store.save(value) } }
                .onFailure { notice = "保存失败：${it.message ?: it.javaClass.simpleName}" }
        }
    }

    /**
     * 功能：首次进入时创建 vault，或读取已有 vault。
     * @return 明文 vault + 恢复码 + 是否需要补做恢复码确认
     */
    private fun bootstrap(): LoadedVault {
        val existing = store.load()
        if (existing != null) {
            // 恢复码就是 master_key 的 Base32 表示，直接由内存值重新编码得到
            val recovery = Base32.encode(Base32.decode(existing.masterKey))
            return LoadedVault(existing, recovery, !store.isRecoveryConfirmed())
        }
        val recovery = Base32.encode(store.newMasterKey())
        val fresh = Vault(masterKey = recovery)
        store.save(fresh)
        return LoadedVault(fresh, recovery, needsRecoveryConfirm = true)
    }
}

/**
 * 功能：根 Composable，按阶段切换界面。
 * @param lockSignal 自增表示需要锁定
 */
@Composable
private fun VkeyApp(lockSignal: Int) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val controller = remember { VaultController(context.applicationContext, scope) }

    LaunchedEffect(lockSignal) {
        if (lockSignal > 0) controller.lock()
    }

    when (val phase = controller.phase) {
        Phase.Loading -> LoadingScreen()

        is Phase.Onboarding -> OnboardingScreen(
            recoveryCode = phase.recoveryCode,
            onConfirm = controller::confirmRecovery,
        )

        Phase.Locked -> LockedScreen(
            busy = controller.busy,
            message = controller.notice,
            onUnlock = controller::unlock,
        )

        Phase.Unlocked -> {
            val vault = controller.vault
            if (vault == null) {
                LoadingScreen()
            } else {
                HomeScreen(
                    items = vault.items,
                    notice = controller.notice,
                    onNoticeConsumed = controller::consumeNotice,
                    onCopy = { code ->
                        copyTotpCode(context, code, scope)
                        controller.addNotice("已复制，$CLIPBOARD_CLEAR_SECONDS 秒后自动清空剪贴板")
                    },
                    onAdd = controller::addItem,
                    onDelete = controller::deleteItem,
                    onLock = controller::lock,
                )
            }
        }

        is Phase.Failure -> FailureScreen(
            message = phase.message,
            onRetry = controller::reload,
        )
    }
}

/** 功能：加载中占位。 */
@Composable
private fun LoadingScreen() {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        CircularProgressIndicator()
    }
}

/**
 * 功能：强制恢复码页（勾选「已保存」才能进入）。
 * @param recoveryCode 52 位 Base32 恢复码
 * @param onConfirm 用户确认后的回调
 */
@Composable
private fun OnboardingScreen(recoveryCode: String, onConfirm: () -> Unit) {
    var saved by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 32.dp),
    ) {
        Text(
            text = "备份你的恢复码",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
        )
        Spacer(Modifier.height(12.dp))
        Text(
            text = "恢复码是解密全部数据的唯一钥匙。手机丢失、换机、或系统密钥失效时，只能靠它恢复。",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(20.dp))
        Surface(
            shape = RoundedCornerShape(12.dp),
            color = MaterialTheme.colorScheme.surfaceVariant,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                text = Base32.group(recoveryCode, groupSize = 4),
                fontFamily = FontFamily.Monospace,
                fontSize = 18.sp,
                letterSpacing = 1.sp,
                lineHeight = 28.sp,
                modifier = Modifier.padding(16.dp),
            )
        }
        Spacer(Modifier.height(10.dp))
        Text(
            text = "共 ${recoveryCode.length} 位，建议抄在纸上或存进密码管理器。",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(28.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = saved, onCheckedChange = { saved = it })
            Spacer(Modifier.width(4.dp))
            Text(text = "我已妥善保存这 ${recoveryCode.length} 位恢复码")
        }
        Spacer(Modifier.height(8.dp))
        Text(
            text = "未保存且密钥失效 = 永久无法解密，没有任何后门。",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
        )
        Spacer(Modifier.height(28.dp))
        Button(
            onClick = onConfirm,
            enabled = saved,
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp),
        ) {
            Text("进入 vkey")
        }
    }
}

/**
 * 功能：锁定页（M3.1 为点击确认解锁）。
 * @param busy 是否正在读取
 * @param message 错误或提示文案
 * @param onUnlock 解锁回调
 */
@Composable
private fun LockedScreen(busy: Boolean, message: String?, onUnlock: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = "vkey 已锁定",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
        )
        Spacer(Modifier.height(10.dp))
        Text(
            text = "应用在后台超过 5 分钟，需要重新解锁。生物识别解锁将在 M3.3 提供。",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(28.dp))
        Button(
            onClick = onUnlock,
            enabled = !busy,
            modifier = Modifier.height(48.dp),
        ) {
            Text(if (busy) "解锁中…" else "解锁")
        }
        if (message != null) {
            Spacer(Modifier.height(16.dp))
            Text(
                text = message,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
                textAlign = TextAlign.Center,
            )
        }
    }
}

/**
 * 功能：致命错误页。
 * @param message 错误描述
 * @param onRetry 重试回调
 */
@Composable
private fun FailureScreen(message: String, onRetry: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = "无法打开保管库",
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.error,
        )
        Spacer(Modifier.height(12.dp))
        Text(
            text = message,
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(24.dp))
        Button(onClick = onRetry) { Text("重试") }
    }
}

/**
 * 功能：主界面（列表 + 添加 + 删除 + 锁定）。
 * @param items 条目列表
 * @param notice 一次性提示
 * @param onNoticeConsumed 提示消费回调
 * @param onCopy 复制验证码
 * @param onAdd 添加条目（返回错误文案或 null）
 * @param onDelete 删除条目
 * @param onLock 手动锁定
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun HomeScreen(
    items: List<VaultItem>,
    notice: String?,
    onNoticeConsumed: () -> Unit,
    onCopy: (String) -> Unit,
    onAdd: (String, String, String) -> String?,
    onDelete: (String) -> Unit,
    onLock: () -> Unit,
) {
    val snackbarHostState = remember { SnackbarHostState() }
    var showAddDialog by remember { mutableStateOf(false) }
    var pendingDelete by remember { mutableStateOf<VaultItem?>(null) }

    var nowMillis by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(Unit) {
        while (true) {
            nowMillis = System.currentTimeMillis()
            delay(TICK_INTERVAL_MS)
        }
    }

    LaunchedEffect(notice) {
        if (notice != null) {
            snackbarHostState.showSnackbar(notice)
            onNoticeConsumed()
        }
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text("vkey", fontWeight = FontWeight.SemiBold) },
                actions = {
                    TextButton(onClick = onLock) { Text("锁定") }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                ),
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { showAddDialog = true }) {
                Text(text = "添加", fontWeight = FontWeight.Medium)
            }
        },
        containerColor = MaterialTheme.colorScheme.background,
    ) { innerPadding ->
        if (items.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
                    .padding(32.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text = "还没有条目。\n点右下角「添加」，输入 Base32 密钥即可。",
                    textAlign = TextAlign.Center,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
                contentPadding = PaddingValues(
                    start = 16.dp,
                    end = 16.dp,
                    top = 8.dp,
                    bottom = 96.dp,
                ),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                items(items = items, key = { it.id }) { item ->
                    TotpItemCard(
                        item = item,
                        nowMillis = nowMillis,
                        onClick = { code -> onCopy(code) },
                        onLongClick = { pendingDelete = item },
                    )
                }
            }
        }
    }

    if (showAddDialog) {
        AddItemDialog(
            onDismiss = { showAddDialog = false },
            onConfirm = { issuer, account, secret ->
                val error = onAdd(issuer, account, secret)
                if (error == null) {
                    showAddDialog = false
                }
                error
            },
        )
    }

    pendingDelete?.let { target ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            title = { Text("删除条目？") },
            text = { Text("将删除「${target.displayLabel()}」，此操作不可撤销。") },
            confirmButton = {
                TextButton(onClick = {
                    onDelete(target.id)
                    pendingDelete = null
                }) {
                    Text("删除", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingDelete = null }) { Text("取消") }
            },
        )
    }
}

/**
 * 功能：单条验证码卡片（点击复制，长按删除）。
 * @param item 条目
 * @param nowMillis 当前时间（驱动刷新）
 * @param onClick 点击（复制验证码）回调
 * @param onLongClick 长按（删除）回调
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun TotpItemCard(
    item: VaultItem,
    nowMillis: Long,
    onClick: (String) -> Unit,
    onLongClick: () -> Unit,
) {
    val secretBytes = remember(item.secret) {
        runCatching { Base32.decode(item.secret) }.getOrNull()
    }
    val code: String = secretBytes?.let {
        runCatching {
            Totp.generate(
                secret = it,
                epochMillis = nowMillis,
                digits = item.digits,
                period = item.period,
                algorithm = item.algorithm,
            )
        }.getOrNull()
    } ?: "------"
    val remaining = Totp.remainingSeconds(nowMillis, item.period)
    val progress = remaining.coerceIn(0, item.period).toFloat() / item.period.toFloat()

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .combinedClickable(
                onClick = { onClick(code) },
                onLongClick = onLongClick,
            ),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = item.displayLabel(),
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    text = "${remaining}s",
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (item.issuer.isNotBlank() && item.account.isNotBlank()) {
                Text(
                    text = item.account,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Spacer(Modifier.height(10.dp))
            Text(
                text = code.chunked(3).joinToString(" "),
                fontFamily = FontFamily.Monospace,
                fontSize = 30.sp,
                letterSpacing = 2.sp,
                fontWeight = FontWeight.Medium,
                color = MaterialTheme.colorScheme.primary,
            )
            Spacer(Modifier.height(12.dp))
            LinearProgressIndicator(
                progress = { progress },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(4.dp),
            )
        }
    }
}

/**
 * 功能：添加条目对话框。
 * @param onDismiss 关闭回调
 * @param onConfirm 保存回调，返回 null 表示成功，否则为错误文案
 */
@Composable
private fun AddItemDialog(
    onDismiss: () -> Unit,
    onConfirm: (String, String, String) -> String?,
) {
    var issuer by remember { mutableStateOf("") }
    var account by remember { mutableStateOf("") }
    var secret by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("添加 TOTP") },
        text = {
            Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                OutlinedTextField(
                    value = issuer,
                    onValueChange = { issuer = it },
                    label = { Text("发行方（如 GitHub）") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = account,
                    onValueChange = { account = it },
                    label = { Text("账号（可选）") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = secret,
                    onValueChange = { secret = it },
                    label = { Text("密钥（Base32）") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
                    modifier = Modifier.fillMaxWidth(),
                )
                if (error != null) {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = error.orEmpty(),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                error = onConfirm(issuer, account, secret)
            }) {
                Text("保存")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("取消") }
        },
    )
}

/** 功能：条目展示名（issuer 优先，其次 account，都为空的兜底）。 */
private fun VaultItem.displayLabel(): String = when {
    issuer.isNotBlank() -> issuer
    account.isNotBlank() -> account
    else -> "未命名"
}

/**
 * 功能：复制验证码到剪贴板，并在 30 秒后（内容未被覆盖时）清空。
 * @param context 用于取 ClipboardManager
 * @param code 验证码
 * @param scope 用于延迟清空
 */
@Suppress("DEPRECATION")
private fun copyTotpCode(context: Context, code: String, scope: CoroutineScope) {
    val manager = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
    val clip = ClipData.newPlainText(CLIP_LABEL, code)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        // API 33+：标记为敏感内容，避免出现在剪贴板预览里
        clip.description.extras = PersistableBundle().apply {
            putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
        }
    }
    manager.setPrimaryClip(clip)

    scope.launch {
        delay(CLIPBOARD_CLEAR_DELAY_MS)
        val current = manager.primaryClip
            ?.takeIf { it.itemCount > 0 }
            ?.getItemAt(0)
            ?.text
            ?.toString()
        if (current == code) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                manager.clearPrimaryClip()
            } else {
                manager.setPrimaryClip(ClipData.newPlainText("", ""))
            }
        }
    }
}
