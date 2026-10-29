package dev.xiaoqiong.vkey.ui

import android.content.Context
import android.os.Build
import androidx.compose.animation.AnimatedContent
import androidx.compose.foundation.layout.Arrangement
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.xiaoqiong.vkey.R
import dev.xiaoqiong.vkey.net.ApiException
import dev.xiaoqiong.vkey.sync.GeneratedPairCode
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
private enum class ConfirmKind { NONE, CLEAR_DEVICE }

/**
 * 同步配置页（M3.2 前半）：未配置 → 已登录 的单一状态机。
 *
 * 入口：
 * - 设置 → 同步配置；
 * - `vkey://config?server=…` 深链 / 扫码（自动填地址）；
 * - `vkey://pair?code=…` 深链 / 扫码（自动填配对码）。
 *
 * 所有网络与密码学操作都在 IO 线程执行，结果通过 [onSaved] 落盘。
 *
 * @param masterKey 当前库的 master_key（base32），用于生成配对码与校正账号密钥
 * @param device 已保存的设备材料；null 表示未配置
 * @param serverUrl 当前设置的同步服务地址
 * @param lastSyncAt 最近一次同步完成时间（unix 秒）；0 = 从未同步
 * @param onSyncNow 执行一次条目同步（由上层持库状态，内部切 IO 并落盘）；返回统计
 * @param initialPairCode 从扫码/深链带进来的配对码（可为 null）
 * @param onSaved 配置成功回调：新设备材料 + 需要替换的 master_key（null 表示与本地一致）
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
    serverUrl: String,
    lastSyncAt: Long,
    onSyncNow: suspend () -> SyncStats,
    initialPairCode: String?,
    onSaved: (DeviceConfig, String?) -> Unit,
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
    var busy by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var info by remember { mutableStateOf<String?>(null) }
    var showScan by remember { mutableStateOf(false) }
    var generated by remember { mutableStateOf<GeneratedPairCode?>(null) }
    var remainingSeconds by remember { mutableLongStateOf(0L) }
    var confirm by remember { mutableStateOf(ConfirmKind.NONE) }
    var syncStats by remember { mutableStateOf<SyncStats?>(null) }

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

    /** 用 master_key 登录。 */
    val doLogin: () -> Unit = {
        val mk = masterKeyInput.trim()
        val address = url.trim()
        when {
            busy != null -> Unit
            address.isEmpty() -> error = context.getString(R.string.err_enter_server_url)
            !SyncManager.looksLikeKey(mk) ->
                error = context.getString(R.string.err_master_key_format)
            else -> runTask(context.getString(R.string.busy_logging_in)) {
                val result = withContext(Dispatchers.IO) {
                    SyncManager.login(address, mk, deviceName, device?.seed)
                }
                onServerUrlChange(result.config.server_url)
                onSaved(result.config, result.masterKeyBase32.takeIf { it != masterKey })
                masterKeyInput = ""
                info = context.getString(R.string.info_logged_in, result.config.device_name)
            }
        }
    }

    /** 用配对码领取 master_key。 */
    val doPair: () -> Unit = {
        val code = pairCodeInput.trim()
        val address = url.trim()
        when {
            busy != null -> Unit
            address.isEmpty() -> error = context.getString(R.string.err_enter_server_url)
            !SyncManager.looksLikeKey(code) ->
                error = context.getString(R.string.err_pair_code_format)
            else -> runTask(context.getString(R.string.busy_claiming_pair_code)) {
                val result = withContext(Dispatchers.IO) {
                    SyncManager.pair(address, code, deviceName, device?.seed)
                }
                onServerUrlChange(result.config.server_url)
                onSaved(result.config, result.masterKeyBase32.takeIf { it != masterKey })
                pairCodeInput = ""
                info = context.getString(R.string.info_paired, result.config.device_name)
            }
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
                                    stringResource(R.string.status_logged_in)
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

                    // ---------------- 服务器地址 ----------------
                    Card(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp)) {
                            OutlinedTextField(
                                value = url,
                                onValueChange = { url = it },
                                label = { Text(stringResource(R.string.label_sync_server_url)) },
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
                                        onServerUrlChange(url)
                                        info = context.getString(R.string.info_server_saved)
                                    },
                                    enabled = busy == null && url.trim().isNotEmpty(),
                                    modifier = Modifier.weight(1f),
                                ) { Text(stringResource(R.string.action_save_address)) }
                                Button(
                                    onClick = { showScan = true },
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
                                            content = "vkey://pair?code=${pairCode.codeText}&server=${normalizeUrl(url)}",
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
                                        TextButton(onClick = { showScan = true }) {
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
                                Spacer(Modifier.height(8.dp))
                                OutlinedTextField(
                                    value = deviceName,
                                    onValueChange = { deviceName = it },
                                    label = { Text(stringResource(R.string.label_device_name_for_repair)) },
                                    singleLine = true,
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                Spacer(Modifier.height(8.dp))
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
                                        onClick = { showScan = true },
                                        enabled = busy == null,
                                        modifier = Modifier.weight(1f),
                                    ) { Text(stringResource(R.string.action_scan_input)) }
                                }
                            }
                        }

                        OutlinedTextField(
                            value = deviceName,
                            onValueChange = { deviceName = it },
                            label = { Text(stringResource(R.string.label_device_name)) },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
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
