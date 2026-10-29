package dev.xiaoqiong.vkey.ui

import android.content.Context
import android.os.Build
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.layout.Arrangement
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.addPathNodes
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.DialogProperties
import dev.xiaoqiong.vkey.R
import dev.xiaoqiong.vkey.net.ApiException
import dev.xiaoqiong.vkey.sync.EnrollResult
import dev.xiaoqiong.vkey.sync.GeneratedPairCode
import dev.xiaoqiong.vkey.sync.Links
import dev.xiaoqiong.vkey.sync.SyncManager
import dev.xiaoqiong.vkey.sync.SyncStats
import dev.xiaoqiong.vkey.vault.DeviceConfig
import dev.xiaoqiong.vkey.vault.LanguageMode
import dev.xiaoqiong.vkey.vault.ThemeMode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** 需要二次确认的破坏性操作。 */
private enum class ConfirmKind { NONE, CLEAR_DEVICE, ENROLL }

/**
 * 同步配置页（M3.2 前半）：未配置 → 已登录 的单一状态机。
 *
 * 入口：
 * - 设置 → 同步配置；
 * - `vkey://config?server=…` 深链 / 扫码（自动填地址）；
 * - `vkey://pair?code=…` 深链 / 扫码（自动填配对码）；
 * - `vkey://enroll?server=…&code=…[&username=…]` 深链（服务端 `/join` 页）：
 *   自动展开「用开户码接入」卡片并预填 code/username（地址由上层先行覆盖）。
 *
 * 所有网络与密码学操作都在 IO 线程执行，结果通过 [onSaved] 落盘。
 *
 * 区块可见性按「是否已配置」切换：`device == null` 才显示「服务端地址」「用开户码接入」两张卡片，
 * 已配置时隐藏（换服务器 / 换账号请先解除绑定），解除绑定后随状态变化立即恢复。
 *
 * @param masterKey 当前库的 master_key（base32），用于生成配对码与校正账号密钥
 * @param device 已保存的设备材料；null 表示未配置
 * @param hasLocalItems 本地是否已有未删除的条目（开户码接入前需要二次确认）
 * @param serverUrl 当前设置的同步服务地址
 * @param lastSyncAt 最近一次同步完成时间（unix 秒）；0 = 从未同步
 * @param onSyncNow 执行一次条目同步（由上层持库状态，内部切 IO 并落盘）；返回统计
 * @param initialPairCode 从扫码/深链带进来的配对码（可为 null）
 * @param initialEnrollCode 开户深链（`vkey://enroll`）带进来的规范化开户码（可为 null）；
 *   非 null 时「用开户码接入」卡片默认展开并预填
 * @param initialEnrollUsername 开户深链附带的用户名（可为 null）
 * @param onSaved 配置成功回调：新设备材料 + 需要替换的 master_key（null 表示与本地一致）；
 *   **同步落盘并读回校验**，返回 null = 已持久化，非 null = 错误文案（未落盘，可重试）
 * @param onServerUrlChange 服务器地址变化（持久化到 AppSettings）
 * @param onClearDevice 断开配对（清除设备材料）
 * @param onOpenAbout 打开「关于」页
 * @param onClose 关闭本页
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SyncScreen(
    masterKey: String,
    device: DeviceConfig?,
    hasLocalItems: Boolean,
    serverUrl: String,
    lastSyncAt: Long,
    onSyncNow: suspend () -> SyncStats,
    initialPairCode: String?,
    initialEnrollCode: String?,
    initialEnrollUsername: String?,
    onSaved: (DeviceConfig, String?) -> String?,
    onServerUrlChange: (String) -> Unit,
    onClearDevice: () -> Unit,
    autoLockOnResume: Boolean,
    onAutoLockChange: (Boolean) -> Unit,
    themeMode: ThemeMode,
    onThemeModeChange: (ThemeMode) -> Unit,
    language: LanguageMode,
    onLanguageChange: (LanguageMode) -> Unit,
    onOpenAbout: () -> Unit,
    onClose: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    // 系统返回键：回到列表页，而不是退出应用
    BackHandler { onClose() }

    var url by remember { mutableStateOf(serverUrl) }
    var deviceName by remember { mutableStateOf(device?.device_name ?: defaultDeviceName()) }
    var masterKeyInput by remember { mutableStateOf("") }
    var pairCodeInput by remember { mutableStateOf(initialPairCode.orEmpty()) }
    // 开户深链（vkey://enroll）带来的预填值；无深链时为空、行为不变
    var enrollCodeInput by remember { mutableStateOf(initialEnrollCode.orEmpty()) }
    var enrollUsernameInput by remember { mutableStateOf(initialEnrollUsername.orEmpty()) }
    // 开户成功后的待发材料：非 null 时展示恢复码确认弹窗（勾选后才落盘）
    var enrollPending by remember { mutableStateOf<EnrollResult?>(null) }
    var enrollAck by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var info by remember { mutableStateOf<String?>(null) }
    var showScan by remember { mutableStateOf(false) }
    // 进入扫码页前的语义：每个入口设定自己要接受的码类型（标题/提示/错误文案随 mode 变）
    var scanMode by remember { mutableStateOf(ScanMode.AUTO) }
    var generated by remember { mutableStateOf<GeneratedPairCode?>(null) }
    var remainingSeconds by remember { mutableLongStateOf(0L) }
    var confirm by remember { mutableStateOf(ConfirmKind.NONE) }
    var syncStats by remember { mutableStateOf<SyncStats?>(null) }
    // 两张卡片的折叠状态：只存内存（离开本页即恢复默认），不做持久化。
    // 默认收起；服务端从未配置（serverUrl 为空）时地址卡默认展开，否则新用户找不到入口；
    // 开户深链带码进来时开户卡默认展开（用户点开就该看到已填好的码）。
    var serverCardExpanded by remember { mutableStateOf(serverUrl.isBlank()) }
    var enrollCardExpanded by remember { mutableStateOf(initialEnrollCode != null) }

    /** 统一的任务执行：置忙、清错误、切 IO。 */
    val runTask: (String, suspend () -> Unit) -> Unit = { label, task ->
        if (busy == null) {
            error = null
            info = null
            busy = label
            scope.launch {
                try {
                    task()
                } catch (t: Throwable) {
                    error = describeFailure(context, t)
                } finally {
                    busy = null
                }
            }
        }
    }

    /** 校验服务器地址：空 → 「未配置」；协议头不对 → scheme 错误。通过返回 true。 */
    val requireValidAddress: () -> Boolean = {
        val address = url.trim()
        when {
            address.isEmpty() -> {
                error = context.getString(R.string.err_enter_server_url)
                false
            }
            !isValidServerUrl(address) -> {
                error = context.getString(R.string.err_server_url_scheme)
                false
            }
            else -> true
        }
    }

    /** 用 master_key 登录。 */
    val doLogin: () -> Unit = {
        val mk = masterKeyInput.trim()
        val address = url.trim()
        when {
            busy != null -> Unit
            !requireValidAddress() -> Unit
            !SyncManager.looksLikeKey(mk) ->
                error = context.getString(R.string.err_master_key_format)
            else -> runTask(context.getString(R.string.busy_logging_in)) {
                val result = withContext(Dispatchers.IO) {
                    SyncManager.login(address, mk, deviceName, device?.seed)
                }
                onServerUrlChange(result.config.server_url)
                // 落盘校验失败：保留输入、显式报错，不谎称「已登录」
                val failure = onSaved(result.config, result.masterKeyBase32.takeIf { it != masterKey })
                if (failure != null) {
                    error = failure
                } else {
                    masterKeyInput = ""
                    info = context.getString(R.string.info_logged_in, result.config.device_name)
                }
            }
        }
    }

    /** 用配对码领取 master_key。 */
    val doPair: () -> Unit = {
        val code = pairCodeInput.trim()
        val address = url.trim()
        when {
            busy != null -> Unit
            !requireValidAddress() -> Unit
            !SyncManager.looksLikeKey(code) ->
                error = context.getString(R.string.err_pair_code_format)
            else -> runTask(context.getString(R.string.busy_claiming_pair_code)) {
                val result = withContext(Dispatchers.IO) {
                    SyncManager.pair(address, code, deviceName, device?.seed)
                }
                onServerUrlChange(result.config.server_url)
                val failure = onSaved(result.config, result.masterKeyBase32.takeIf { it != masterKey })
                if (failure != null) {
                    error = failure
                } else {
                    pairCodeInput = ""
                    info = context.getString(R.string.info_paired, result.config.device_name)
                }
            }
        }
    }

    /** 执行开户码接入（已过校验与二次确认）。 */
    val runEnroll: (address: String, code: String, username: String) -> Unit = { address, code, username ->
        runTask(context.getString(R.string.busy_enrolling)) {
            val result = try {
                SyncManager.enroll(address, code, username, deviceName, device?.seed)
            } catch (e: ApiException) {
                // 开户类错误码换成开户语境文案；其余交回 describeFailure 统一处理
                val resId = enrollErrorRes(e.code)
                if (resId != 0) {
                    error = context.getString(resId)
                    null
                } else {
                    throw e
                }
            }
            if (result != null) {
                enrollAck = false
                enrollPending = result
                enrollCodeInput = ""
                enrollUsernameInput = ""
            }
        }
    }

    /** 用开户码接入：校验 → （必要时）二次确认 → 请求。 */
    val doEnroll: () -> Unit = {
        val canonical = Links.parseEnrollCode(enrollCodeInput)
        val address = url.trim()
        val username = enrollUsernameInput.trim()
        when {
            busy != null -> Unit
            !requireValidAddress() -> Unit
            canonical == null -> error = context.getString(R.string.err_enroll_code_format)
            username.isEmpty() -> error = context.getString(R.string.err_enroll_username_empty)
            // 已有配置或本地条目：接入新账号是破坏性动作，先二次确认
            device != null || hasLocalItems -> confirm = ConfirmKind.ENROLL
            else -> runEnroll(address, canonical, username)
        }
    }

    /** 立即同步：先推后拉，把结果统计留在页面上。 */
    val doSync: () -> Unit = {
        when {
            busy != null || device == null -> Unit
            else -> runTask(context.getString(R.string.busy_syncing_items)) {
                val stats = onSyncNow()
                syncStats = stats
                info = context.getString(R.string.info_sync_done)
            }
        }
    }

    /** 生成配对码（需要已登录 + 已解锁）。 */
    val doGenerate: () -> Unit = {
        val cfg = device
        when {
            busy != null || cfg == null -> Unit
            else -> runTask(context.getString(R.string.busy_generating_pair_code)) {
                val pairCode = withContext(Dispatchers.IO) {
                    SyncManager.generatePairCode(cfg, masterKey)
                }
                generated = pairCode
                remainingSeconds = (pairCode.expiresAt - System.currentTimeMillis() / 1000).coerceAtLeast(0)
            }
        }
    }

    // 配对码有效期倒计时：以服务端 expires_at 为准，逐秒刷新
    LaunchedEffect(generated) {
        val expiresAt = generated?.expiresAt ?: return@LaunchedEffect
        while (true) {
            remainingSeconds = (expiresAt - System.currentTimeMillis() / 1000).coerceAtLeast(0)
            if (remainingSeconds <= 0L) break
            delay(1_000)
        }
    }

    val pairedServer = device?.server_url
    val serverChanged = pairedServer != null && normalizeUrl(url) != normalizeUrl(pairedServer)

    // 页面级切换（表单 ↔ 扫码）：与顶层页面共用同一套转场，进入扫码走前进方向，关闭走返回方向
    AnimatedContent(
        targetState = showScan,
        modifier = Modifier.fillMaxSize(),
        transitionSpec = {
            vkeyPageTransition(
                forward = targetState,
                animated = !vkeyPageAnimationsDisabled(context),
            )
        },
        label = "vkey-sync-scan",
    ) { scanning ->
        if (scanning) {
            ScanScreen(
                mode = scanMode,
                onResult = null,
                onConfigLink = { server ->
                    url = server
                    onServerUrlChange(server)
                    showScan = false
                    info = context.getString(R.string.info_server_set, server)
                },
                onPairCode = { code ->
                    pairCodeInput = code
                    showScan = false
                    info = context.getString(R.string.info_pair_code_detected)
                },
                onEnrollCode = { code ->
                    enrollCodeInput = code
                    showScan = false
                    info = context.getString(R.string.info_enroll_code_detected)
                },
                onCancel = { showScan = false },
            )
        } else {
            Scaffold(
                topBar = {
                    TopAppBar(
                        title = { Text(stringResource(R.string.title_settings)) },
                        navigationIcon = {
                            TextButton(onClick = onClose) {
                                Text(stringResource(R.string.action_back))
                            }
                        },
                    )
                },
            ) { padding ->
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding)
                        .verticalScroll(rememberScrollState())
                        .padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    // ---------------- 外观：主题 + 语言（点击即生效，无需保存） ----------------
                    Card(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp)) {
                            Text(
                                stringResource(R.string.section_appearance),
                                style = MaterialTheme.typography.titleMedium,
                            )
                            Spacer(Modifier.height(4.dp))
                            ThemeMode.entries.forEach { option ->
                                ChoiceRow(
                                    label = stringResource(option.labelRes()),
                                    selected = themeMode == option,
                                    onSelect = { onThemeModeChange(option) },
                                )
                            }
                            Spacer(Modifier.height(12.dp))
                            HorizontalDivider()
                            Spacer(Modifier.height(12.dp))
                            Text(
                                stringResource(R.string.section_language),
                                style = MaterialTheme.typography.titleMedium,
                            )
                            Spacer(Modifier.height(4.dp))
                            LanguageMode.entries.forEach { option ->
                                ChoiceRow(
                                    label = stringResource(option.labelRes()),
                                    selected = language == option,
                                    onSelect = { onLanguageChange(option) },
                                )
                            }
                        }
                    }

                    // ---------------- 安全 ----------------
                    Card(Modifier.fillMaxWidth()) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 16.dp, vertical = 8.dp),
                        ) {
                            Column(Modifier.weight(1f)) {
                                Text(stringResource(R.string.settings_auto_lock_title), style = MaterialTheme.typography.bodyLarge)
                                Text(
                                    stringResource(R.string.settings_auto_lock_desc),
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                            androidx.compose.material3.Switch(
                                checked = autoLockOnResume,
                                onCheckedChange = onAutoLockChange,
                            )
                        }
                    }

                    // ---------------- 状态 ----------------
                    Card(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp)) {
                            Text(
                                text = if (device == null) {
                                    stringResource(R.string.status_not_configured)
                                } else {
                                    // 顶部状态直接带上账号名：接入完成后一眼可确认「已登录：xxx」
                                    stringResource(R.string.status_logged_in, device.username)
                                },
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Medium,
                            )
                            if (device == null) {
                                Text(
                                    stringResource(R.string.sync_configure_hint),
                                    style = MaterialTheme.typography.bodySmall,
                                    modifier = Modifier.padding(top = 4.dp),
                                )
                            } else {
                                Text(
                                    stringResource(R.string.label_device, device.device_name),
                                    style = MaterialTheme.typography.bodySmall,
                                )
                                Text(
                                    stringResource(R.string.label_server, device.server_url),
                                    style = MaterialTheme.typography.bodySmall,
                                )
                                Text(
                                    stringResource(R.string.label_account_line, device.username),
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                        }
                    }

                    if (busy != null) {
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                        Text(busy.orEmpty(), style = MaterialTheme.typography.bodySmall)
                    }
                    info?.let {
                        Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
                    }
                    error?.let {
                        Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    }

                    // ---------------- 未配置专属入口：服务端地址 + 本机设备名 + 开户码接入 ----------------
                    // 这两个入口只在「尚未配对/登录」时有意义；已配置后换服务器或换账号请先解除绑定，
                    // 解除绑定（device 变 null）后立即恢复显示，无需重启。展开/收起转场沿用现有动画且不裁剪。
                    AnimatedVisibility(
                        visible = device == null,
                        enter = expandVertically(
                            animationSpec = tween(durationMillis = PAGE_TRANSITION_MS),
                            clip = false,
                        ) + fadeIn(tween(durationMillis = PAGE_TRANSITION_MS)),
                        exit = shrinkVertically(
                            animationSpec = tween(durationMillis = PAGE_TRANSITION_MS),
                            clip = false,
                        ) + fadeOut(tween(durationMillis = PAGE_TRANSITION_MS)),
                    ) {
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            // ---------- 服务器地址（可折叠卡片） ----------
                            // 折叠态摘要：地址为空显示「未配置」（过长中间省略），否则显示地址本身
                            val addressText = url.trim()
                            val serverSummary = if (addressText.isEmpty()) {
                                stringResource(R.string.status_not_configured)
                            } else {
                                middleEllipsis(addressText)
                            }
                            CollapsibleCard(
                                title = stringResource(R.string.section_server_address),
                                summary = serverSummary,
                                expanded = serverCardExpanded,
                                onToggle = { serverCardExpanded = !serverCardExpanded },
                            ) {
                                OutlinedTextField(
                                    value = url,
                                    onValueChange = { url = it },
                                    label = { Text(stringResource(R.string.label_sync_server_url)) },
                                    // 未配置时只给占位示例，不预填任何真实域名
                                    placeholder = {
                                        if (url.isEmpty()) {
                                            Text(stringResource(R.string.placeholder_server_url))
                                        }
                                    },
                                    singleLine = true,
                                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Button(
                                        onClick = {
                                            if (requireValidAddress()) {
                                                onServerUrlChange(url.trim())
                                                info = context.getString(R.string.info_server_saved)
                                            }
                                        },
                                        enabled = busy == null && url.trim().isNotEmpty(),
                                        modifier = Modifier.weight(1f),
                                    ) { Text(stringResource(R.string.action_save_address)) }
                                    Button(
                                        onClick = {
                                            scanMode = ScanMode.CONFIG_LINK
                                            showScan = true
                                        },
                                        enabled = busy == null,
                                        modifier = Modifier.weight(1f),
                                    ) { Text(stringResource(R.string.action_scan)) }
                                }
                                Text(
                                    stringResource(R.string.sync_scan_hint),
                                    style = MaterialTheme.typography.bodySmall,
                                    modifier = Modifier.padding(top = 4.dp),
                                )
                            }

                            // ---------- 本机设备名（全局唯一输入入口） ----------
                            // 设备名只在这里编辑：登录 / 配对 / 开户各入口共用同一个 deviceName 状态。
                            // 仅在未配置时显示（已配置后状态卡里会展示「设备：xxx」），解除绑定后自动恢复。
                            Card(Modifier.fillMaxWidth()) {
                                Column(Modifier.padding(16.dp)) {
                                    Text(
                                        stringResource(R.string.section_device_name),
                                        style = MaterialTheme.typography.titleMedium,
                                    )
                                    Spacer(Modifier.height(4.dp))
                                    OutlinedTextField(
                                        value = deviceName,
                                        onValueChange = { deviceName = it },
                                        label = { Text(stringResource(R.string.label_device_name)) },
                                        singleLine = true,
                                        modifier = Modifier.fillMaxWidth(),
                                    )
                                    Text(
                                        stringResource(R.string.device_name_desc),
                                        style = MaterialTheme.typography.bodySmall,
                                        modifier = Modifier.padding(top = 4.dp),
                                    )
                                }
                            }

                            // ---------- 用开户码接入（多用户实例注册入口，可折叠卡片） ----------
                            CollapsibleCard(
                                title = stringResource(R.string.section_enroll),
                                summary = stringResource(R.string.enroll_card_new_account),
                                expanded = enrollCardExpanded,
                                onToggle = { enrollCardExpanded = !enrollCardExpanded },
                            ) {
                                Text(
                                    stringResource(R.string.enroll_desc),
                                    style = MaterialTheme.typography.bodySmall,
                                )
                                Spacer(Modifier.height(8.dp))
                                OutlinedTextField(
                                    value = enrollCodeInput,
                                    onValueChange = { enrollCodeInput = it },
                                    label = { Text(stringResource(R.string.label_enroll_code)) },
                                    singleLine = true,
                                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                Spacer(Modifier.height(8.dp))
                                OutlinedTextField(
                                    value = enrollUsernameInput,
                                    onValueChange = { enrollUsernameInput = it },
                                    label = { Text(stringResource(R.string.label_enroll_username)) },
                                    singleLine = true,
                                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                Spacer(Modifier.height(8.dp))
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Button(
                                        onClick = doEnroll,
                                        enabled = busy == null,
                                        modifier = Modifier.weight(1f),
                                    ) { Text(stringResource(R.string.action_enroll)) }
                                    Button(
                                        onClick = {
                                            scanMode = ScanMode.ENROLL
                                            showScan = true
                                        },
                                        enabled = busy == null,
                                        modifier = Modifier.weight(1f),
                                    ) { Text(stringResource(R.string.action_scan_input)) }
                                }
                            }
                        }
                    }

                    if (device != null) {
                        // ---------------- 已登录：条目同步 ----------------
                        Card(Modifier.fillMaxWidth()) {
                            Column(Modifier.padding(16.dp)) {
                                Text(stringResource(R.string.section_item_sync), style = MaterialTheme.typography.titleMedium)
                                Text(
                                    stringResource(R.string.item_sync_desc),
                                    style = MaterialTheme.typography.bodySmall,
                                    modifier = Modifier.padding(top = 4.dp),
                                )
                                Spacer(Modifier.height(8.dp))
                                Button(
                                    onClick = doSync,
                                    enabled = busy == null,
                                    modifier = Modifier.fillMaxWidth(),
                                ) { Text(stringResource(R.string.action_sync_now)) }
                                val stats = syncStats
                                if (stats != null) {
                                    Text(
                                        stringResource(
                                            R.string.sync_stats,
                                            stats.pushed,
                                            stats.revoked,
                                            stats.pulled,
                                            stats.skipped,
                                            stats.conflicts,
                                        ),
                                        style = MaterialTheme.typography.bodySmall,
                                        modifier = Modifier.padding(top = 8.dp),
                                    )
                                }
                                Text(
                                    stringResource(
                                        R.string.label_last_sync,
                                        formatSyncTime(context, lastSyncAt),
                                    ),
                                    style = MaterialTheme.typography.bodySmall,
                                    modifier = Modifier.padding(top = 4.dp),
                                )
                            }
                        }

                        // ---------------- 已登录：生成配对码 ----------------
                        Card(Modifier.fillMaxWidth()) {
                            Column(Modifier.padding(16.dp)) {
                                Text(stringResource(R.string.section_pair_new_device), style = MaterialTheme.typography.titleMedium)
                                Text(
                                    stringResource(R.string.pair_new_device_desc),
                                    style = MaterialTheme.typography.bodySmall,
                                    modifier = Modifier.padding(top = 4.dp),
                                )
                                Spacer(Modifier.height(8.dp))
                                Button(
                                    onClick = doGenerate,
                                    enabled = busy == null,
                                    modifier = Modifier.fillMaxWidth(),
                                ) {
                                    Text(
                                        if (generated == null) {
                                            stringResource(R.string.action_generate_pair_code)
                                        } else {
                                            stringResource(R.string.action_regenerate)
                                        },
                                    )
                                }

                                val pairCode = generated
                                if (pairCode != null) {
                                    Spacer(Modifier.height(12.dp))
                                    // 直接给二维码：另一台设备扫码即可带走 master_key（不用手抄）
                                    Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                                        QrCodeImage(
                                            content = "vkey://pair?code=${pairCode.codeText}" +
                                                "&server=${normalizeUrl(url).ifBlank { device.server_url }}",
                                            size = 220.dp,
                                        )
                                    }
                                    Spacer(Modifier.height(8.dp))
                                    Text(
                                        text = pairCode.codeText,
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 17.sp,
                                        fontWeight = FontWeight.Medium,
                                    )
                                    Text(
                                        text = if (remainingSeconds > 0) {
                                            stringResource(
                                                R.string.pair_code_remaining,
                                                formatCountdown(remainingSeconds),
                                            )
                                        } else {
                                            stringResource(R.string.pair_code_expired)
                                        },
                                        style = MaterialTheme.typography.bodySmall,
                                        color = if (remainingSeconds > 0) {
                                            MaterialTheme.colorScheme.primary
                                        } else {
                                            MaterialTheme.colorScheme.error
                                        },
                                        modifier = Modifier.padding(top = 4.dp),
                                    )
                                    Spacer(Modifier.height(4.dp))
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        Button(
                                            onClick = {
                                                copyToClipboard(context, pairCode.codeText, sensitive = false)
                                                info = context.getString(R.string.info_pair_code_copied)
                                            },
                                            enabled = remainingSeconds > 0,
                                        ) { Text(stringResource(R.string.action_copy_pair_code)) }
                                        TextButton(onClick = {
                                            scanMode = ScanMode.PAIR
                                            showScan = true
                                        }) {
                                            Text(stringResource(R.string.action_scan_other_code))
                                        }
                                    }
                                }
                            }
                        }

                        HorizontalDivider()

                        // ---------------- 切服务器 / 断开 ----------------
                        Card(Modifier.fillMaxWidth()) {
                            Column(Modifier.padding(16.dp)) {
                                Text(stringResource(R.string.section_device_management), style = MaterialTheme.typography.titleMedium)
                                if (serverChanged) {
                                    Text(
                                        stringResource(R.string.warn_server_changed),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.error,
                                        modifier = Modifier.padding(top = 4.dp),
                                    )
                                }
                                TextButton(
                                    onClick = { confirm = ConfirmKind.CLEAR_DEVICE },
                                    enabled = busy == null,
                                ) { Text(stringResource(R.string.action_clear_pairing)) }
                            }
                        }
                    } else {
                        // ---------------- 未配置：两条配置路径 ----------------
                        Card(Modifier.fillMaxWidth()) {
                            Column(Modifier.padding(16.dp)) {
                                Text(stringResource(R.string.section_login_master_key), style = MaterialTheme.typography.titleMedium)
                                Text(
                                    stringResource(R.string.login_master_key_desc),
                                    style = MaterialTheme.typography.bodySmall,
                                    modifier = Modifier.padding(top = 4.dp),
                                )
                                Spacer(Modifier.height(8.dp))
                                OutlinedTextField(
                                    value = masterKeyInput,
                                    onValueChange = { masterKeyInput = it },
                                    label = { Text("master_key") },
                                    singleLine = true,
                                    visualTransformation = PasswordVisualTransformation(),
                                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                Spacer(Modifier.height(8.dp))
                                Button(
                                    onClick = doLogin,
                                    enabled = busy == null,
                                    modifier = Modifier.fillMaxWidth(),
                                ) { Text(stringResource(R.string.action_login_with_master_key)) }
                            }
                        }

                        Card(Modifier.fillMaxWidth()) {
                            Column(Modifier.padding(16.dp)) {
                                Text(stringResource(R.string.section_pair_with_code), style = MaterialTheme.typography.titleMedium)
                                Text(
                                    stringResource(R.string.pair_with_code_desc),
                                    style = MaterialTheme.typography.bodySmall,
                                    modifier = Modifier.padding(top = 4.dp),
                                )
                                Spacer(Modifier.height(8.dp))
                                OutlinedTextField(
                                    value = pairCodeInput,
                                    onValueChange = { pairCodeInput = it },
                                    label = { Text(stringResource(R.string.label_pair_code_input)) },
                                    singleLine = true,
                                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                Spacer(Modifier.height(8.dp))
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Button(
                                        onClick = doPair,
                                        enabled = busy == null,
                                        modifier = Modifier.weight(1f),
                                    ) { Text(stringResource(R.string.action_claim_and_configure)) }
                                    Button(
                                        onClick = {
                                            scanMode = ScanMode.PAIR
                                            showScan = true
                                        },
                                        enabled = busy == null,
                                        modifier = Modifier.weight(1f),
                                    ) { Text(stringResource(R.string.action_scan_input)) }
                                }
                            }
                        }
                    }

                    // ---------------- 关于（页面最底部） ----------------
                    Card(Modifier.fillMaxWidth()) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable(onClick = onOpenAbout)
                                .padding(horizontal = 16.dp, vertical = 16.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                stringResource(R.string.about_title),
                                style = MaterialTheme.typography.bodyLarge,
                                modifier = Modifier.weight(1f),
                            )
                            Icon(
                                imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }
    }

    if (confirm == ConfirmKind.CLEAR_DEVICE) {
        AlertDialog(
            onDismissRequest = { confirm = ConfirmKind.NONE },
            title = { Text(stringResource(R.string.dialog_disconnect_title)) },
            text = {
                Text(stringResource(R.string.dialog_disconnect_text))
            },
            confirmButton = {
                TextButton(onClick = {
                    confirm = ConfirmKind.NONE
                    generated = null
                    onClearDevice()
                    onServerUrlChange(url)
                    info = context.getString(R.string.info_disconnected)
                }) { Text(stringResource(R.string.action_disconnect)) }
            },
            dismissButton = {
                TextButton(onClick = { confirm = ConfirmKind.NONE }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }

    // 接入新账号前的二次确认（已有配对或已有条目时）
    if (confirm == ConfirmKind.ENROLL) {
        AlertDialog(
            onDismissRequest = { confirm = ConfirmKind.NONE },
            title = { Text(stringResource(R.string.dialog_enroll_overwrite_title)) },
            text = { Text(stringResource(R.string.dialog_enroll_overwrite_text)) },
            confirmButton = {
                TextButton(onClick = {
                    confirm = ConfirmKind.NONE
                    val canonical = Links.parseEnrollCode(enrollCodeInput)
                    val username = enrollUsernameInput.trim()
                    val address = url.trim()
                    when {
                        address.isEmpty() -> error = context.getString(R.string.err_enter_server_url)
                        !isValidServerUrl(address) ->
                            error = context.getString(R.string.err_server_url_scheme)
                        canonical != null && username.isNotEmpty() -> runEnroll(address, canonical, username)
                    }
                }) { Text(stringResource(R.string.action_enroll)) }
            },
            dismissButton = {
                TextButton(onClick = { confirm = ConfirmKind.NONE }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }

    // 开户成功：必须先抄写恢复码（勾选确认）才能落盘；取消/返回则不保存并提示可重试
    enrollPending?.let { result ->
        AlertDialog(
            onDismissRequest = {
                // 「直接返回」= 放弃本次接入：丢弃待发材料、不落盘、提示可重新输入开户码
                enrollPending = null
                enrollAck = false
                info = context.getString(R.string.info_enroll_abandoned)
            },
            properties = DialogProperties(dismissOnBackPress = true, dismissOnClickOutside = false),
            title = { Text(stringResource(R.string.enroll_recovery_title)) },
            text = {
                Column {
                    Text(
                        stringResource(R.string.enroll_recovery_hint),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Spacer(Modifier.height(8.dp))
                    Card(Modifier.fillMaxWidth()) {
                        Text(
                            text = result.masterKeyBase32.chunked(4).joinToString(" "),
                            modifier = Modifier.padding(12.dp),
                            fontFamily = FontFamily.Monospace,
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Medium,
                        )
                    }
                    Spacer(Modifier.height(4.dp))
                    TextButton(onClick = {
                        copyToClipboard(context, result.masterKeyBase32, sensitive = true)
                    }) { Text(stringResource(R.string.setup_copy_recovery)) }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = enrollAck, onCheckedChange = { enrollAck = it })
                        Text(stringResource(R.string.enroll_saved_check))
                    }
                    // 落盘失败在弹窗内直接可见（弹窗保持打开，可重试「完成」）
                    error?.let {
                        Text(
                            text = it,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                            modifier = Modifier.padding(top = 4.dp),
                        )
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        // 勾选确认后才落盘：先写服务器地址，再写 DeviceConfig + master_key；
                        // onSaved 内部「写盘 + 读回比对 device_id」，成功才关闭弹窗
                        onServerUrlChange(result.config.server_url)
                        val failure = onSaved(result.config, result.masterKeyBase32)
                        if (failure == null) {
                            enrollPending = null
                            enrollAck = false
                            info = context.getString(R.string.info_enrolled, result.config.username)
                        } else {
                            error = failure
                        }
                    },
                    enabled = enrollAck,
                ) { Text(stringResource(R.string.action_enroll_done)) }
            },
            dismissButton = {
                TextButton(onClick = {
                    enrollPending = null
                    enrollAck = false
                    info = context.getString(R.string.info_enroll_abandoned)
                }) { Text(stringResource(R.string.action_enroll_cancel)) }
            },
        )
    }
}

/**
 * 校验服务器地址：仅接受 `http://` 或 `https://` 前缀（大小写不限、已去首尾空白）。
 *
 * 默认服务地址为空串（不内置生产域名），因此所有发起请求前的入口都必须先过这里。
 *
 * @param raw 去空白后的地址文本
 * @return 合法时为 true
 */
internal fun isValidServerUrl(raw: String): Boolean {
    val lower = raw.lowercase()
    return lower.startsWith("http://") || lower.startsWith("https://")
}

/**
 * 可折叠卡片：头部一行（标题 + 折叠态状态摘要 + 展开箭头），展开区做垂直展开动画。
 *
 * - 头部整行可点（高度 ≥48dp），折叠时也能看到关键信息（摘要）；
 * - 折叠时内容完全不进入组合（不是 alpha=0 占位）；
 * - 展开/收起动画不裁剪内容（`clip = false`），避免输入框描边被切；
 * - 时长与页面转场一致（[PAGE_TRANSITION_MS]）。
 *
 * @param title 卡片标题
 * @param summary 折叠态状态摘要（单行，过长由调用方做中间省略）
 * @param expanded 是否展开
 * @param onToggle 点击头部时切换展开状态
 * @param content 展开后显示的内容（已带好内边距）
 */
@Composable
private fun CollapsibleCard(
    title: String,
    summary: String,
    expanded: Boolean,
    onToggle: () -> Unit,
    content: @Composable ColumnScope.() -> Unit,
) {
    val arrowRotation by animateFloatAsState(
        targetValue = if (expanded) 180f else 0f,
        animationSpec = tween(durationMillis = PAGE_TRANSITION_MS),
        label = "collapsible-card-arrow",
    )
    val stateLabel = stringResource(
        if (expanded) R.string.state_expanded else R.string.state_collapsed,
    )
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.fillMaxWidth()) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .clickable(onClick = onToggle)
                    .semantics {
                        role = Role.Button
                        stateDescription = stateLabel
                    }
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.width(12.dp))
                Text(
                    text = summary,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.End,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                Spacer(Modifier.width(8.dp))
                Icon(
                    imageVector = ExpandMoreIcon,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.rotate(arrowRotation),
                )
            }
            AnimatedVisibility(
                visible = expanded,
                enter = expandVertically(
                    animationSpec = tween(durationMillis = PAGE_TRANSITION_MS),
                    clip = false,
                ) + fadeIn(tween(durationMillis = PAGE_TRANSITION_MS)),
                exit = shrinkVertically(
                    animationSpec = tween(durationMillis = PAGE_TRANSITION_MS),
                    clip = false,
                ) + fadeOut(tween(durationMillis = PAGE_TRANSITION_MS)),
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
                    content = content,
                )
            }
        }
    }
}

/**
 * 单选项一行（整行可点，RadioButton 只做视觉指示）。
 *
 * @param label 选项文案
 * @param selected 是否选中
 * @param onSelect 点击回调（立即保存并应用）
 */
@Composable
private fun ChoiceRow(label: String, selected: Boolean, onSelect: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .selectable(selected = selected, role = Role.RadioButton, onClick = onSelect)
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = null)
        Spacer(Modifier.width(8.dp))
        Text(label, style = MaterialTheme.typography.bodyLarge)
    }
}

/** 主题模式 → 文案资源。 */
private fun ThemeMode.labelRes(): Int = when (this) {
    ThemeMode.SYSTEM -> R.string.theme_system
    ThemeMode.LIGHT -> R.string.theme_light
    ThemeMode.DARK -> R.string.theme_dark
}

/** 界面语言 → 文案资源。 */
private fun LanguageMode.labelRes(): Int = when (this) {
    LanguageMode.SYSTEM -> R.string.language_system
    LanguageMode.CHINESE -> R.string.language_chinese
    LanguageMode.ENGLISH -> R.string.language_english
}

/** 默认设备名：`Android <型号>`（型号可能为空，退化为 `android`）。 */
private fun defaultDeviceName(): String {
    val model = Build.MODEL.orEmpty().trim()
    return SyncManager.sanitizeDeviceName(if (model.isEmpty()) "android" else "Android $model")
}

/** 去掉尾部斜杠用于比较服务器地址。 */
private fun normalizeUrl(url: String): String = url.trim().trimEnd('/')

/** 把剩余秒数格式化为 `mm:ss`。 */
private fun formatCountdown(seconds: Long): String {
    val safe = seconds.coerceAtLeast(0)
    return "%02d:%02d".format(safe / 60, safe % 60)
}

/**
 * 把 unix 秒格式化为本地时间；0 表示从未同步。
 *
 * @param unixSeconds 同步完成时间（unix 秒）
 * @return 形如 `2026-10-28 09:15:03`，或 `从未同步`
 */
internal fun formatSyncTime(context: Context, unixSeconds: Long): String {
    if (unixSeconds <= 0L) return context.getString(R.string.sync_never)
    val format = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
    return format.format(Date(unixSeconds * 1000L))
}

/**
 * 把开户码接入（`POST /auth/enroll`）的服务端错误码映射成开户语境文案。
 *
 * `invalid_code` / `code_expired` 在配对语境已有文案，开户语境含义不同，
 * 这里覆盖；其余错误码返回 0，交回 [describeFailure] 统一处理。
 *
 * @param code [ApiException.code]
 * @return strings 资源 id；0 表示无专属映射
 */
internal fun enrollErrorRes(code: String): Int = when (code) {
    "invalid_code" -> R.string.err_enroll_invalid_code
    "code_expired" -> R.string.err_enroll_code_expired
    "username_taken" -> R.string.err_enroll_username_taken
    "invalid_verifier" -> R.string.err_enroll_invalid_verifier
    "quota_devices" -> R.string.err_enroll_quota_devices
    "enroll_disabled" -> R.string.err_enroll_disabled
    else -> 0
}

/**
 * 把底层异常翻译成用户能看懂的一句话。
 *
 * 服务端错误保留 `code` 与 `message`（[ApiException] 的 `message` 已是 `code: message (HTTP n)`），
 * 便于用户/日志定位。
 *
 * @param t 捕获到的异常
 * @return 中文说明（保留服务端错误码便于排查）
 */
internal fun describeFailure(context: Context, t: Throwable): String {
    if (t is ApiException) {
        return when (t.code) {
            "network_error" -> context.getString(R.string.err_network, t.message.orEmpty())
            "code_not_found" -> context.getString(R.string.err_code_not_found)
            "code_used" -> context.getString(R.string.err_code_used)
            "code_expired" -> context.getString(R.string.err_code_expired)
            "invalid_code" -> context.getString(R.string.err_invalid_code)
            "invalid_token" -> context.getString(R.string.err_invalid_token)
            "ts_skew" -> context.getString(R.string.err_ts_skew)
            "empty_body", "invalid_response" -> context.getString(R.string.err_bad_response)
            "not_configured" -> context.getString(R.string.err_not_configured)
            "stale_write" -> context.getString(R.string.err_stale_write)
            else -> t.message ?: t.code
        }
    }
    if (t is IllegalArgumentException) return t.message ?: context.getString(R.string.err_invalid_input)
    return t.message ?: t.javaClass.simpleName
}

/** 状态摘要最长字符数：超出时保留首尾、中间用省略号（卡片头部单行显示，中段才是可省信息）。 */
private const val SUMMARY_MAX_CHARS = 32

/**
 * 中间省略：过长文本保留开头与结尾，中间用 `…` 替代。
 *
 * Compose 的 [TextOverflow.Ellipsis] 只能尾部省略，而服务器地址的关键信息在两端
 * （scheme + 域名 / 路径尾段），因此这里先按字符数做中间省略，再由 [TextOverflow.Ellipsis] 兜底。
 *
 * @param text 原始文本
 * @param maxChars 允许的最大字符数（含省略号）
 * @return 未超长时原样返回
 */
private fun middleEllipsis(text: String, maxChars: Int = SUMMARY_MAX_CHARS): String {
    if (text.length <= maxChars) return text
    val head = (maxChars + 1) / 2
    val tail = maxChars - head
    return text.take(head) + "…" + text.takeLast(tail)
}

/**
 * `Icons.Filled.ExpandMore` 的本地等价实现（Material 图标 `expand_more`）。
 *
 * 项目只依赖 material-icons-core，扩展图标库（material-icons-extended）不是现有依赖，
 * 为不引入新依赖，这里内联同一份官方路径数据。
 */
private val ExpandMoreIcon: ImageVector by lazy {
    ImageVector.Builder(
        name = "ExpandMore",
        defaultWidth = 24.dp,
        defaultHeight = 24.dp,
        viewportWidth = 24f,
        viewportHeight = 24f,
    ).apply {
        addPath(
            pathData = addPathNodes("M16.59 8.59L12 13.17 7.41 8.59 6 10l6 6 6-6z"),
            fill = SolidColor(Color.Black),
        )
    }.build()
}
