package dev.xiaoqiong.vkey.ui

import android.content.Context
import android.os.Build
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
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
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Card
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
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
 * 设置页的分类（分组导航）：顺序即 tab 顺序，每个 tab 只显示该组的项。
 *
 * 选中项由 Activity 持有（`settingsTabState`），因此跳页/切换后仍记得上次停留的分类
 * （进程内有效，进程被杀后回到 [ACCOUNT]）。
 */
enum class SettingsTab {
    /** 账号：服务端地址行（两种状态都有）+ 未配置时的接入方式下拉框（只渲染当前方式的表单）/ 已配置时的状态卡、同步、配对、设备管理。 */
    ACCOUNT,

    /** 设置：本机设备名、回到前台时重新解锁、明暗模式、语言、导入 / 导出 2FA 配置。 */
    SETTINGS,

    /** 关于：版本、检查更新、开源许可、仓库链接、零知识说明（内嵌渲染，不整页跳转）。 */
    ABOUT,
}

/**
 * 设置页（M3.2 前半）：未配置 → 已登录 的单一状态机，按分类分组导航。
 *
 * 分组（见 [SettingsTab]）：账号 / 设置 / 关于，选中某类后只显示该类的项；
 * 分类切换沿用页面转场（[PAGE_TRANSITION_MS]、不裁剪）。
 *
 * 入口：
 * - 主页「设置」按钮、首启选择「我已有 master_key / 配对码」（进本页并选中「账号」）；
 * - `vkey://config?server=…` 深链 / 扫码（自动填地址）；
 * - `vkey://pair?code=…` 深链 / 扫码（自动切到「配对码」并预填）；
 * - `vkey://enroll?server=…&code=…[&username=…]` 深链（服务端 `/join` 页）：
 *   自动切到「开户码」并预填 code/username（地址由上层先行覆盖）。
 *
 * 所有网络与密码学操作都在 IO 线程执行，结果通过 [onSaved] 落盘。
 *
 * 账号分类内「服务端地址」是一行紧凑条目（点击 / 「修改」进编辑对话框），两种状态都显示：
 * 保存前必须探测 `GET {url}/api/v1/policy`（5s / 2xx），失败不落盘；
 * 已配置且地址确实变了则清除本机设备绑定（token 属于旧服务器），本地条目与 master_key 保留。
 *
 * 未配置（`device == null`）时其下是「接入方式」下拉框（master_key / 配对码 / 开户码 三选一，
 * 只渲染当前方式的表单）；已配置时该块隐藏，解除绑定后随状态变化立即恢复。
 *
 * @param masterKey 当前库的 master_key（base32），用于生成配对码与校正账号密钥
 * @param device 已保存的设备材料；null 表示未配置
 * @param hasLocalItems 本地是否已有未删除的条目（开户码接入前需要二次确认）
 * @param serverUrl 当前设置的同步服务地址
 * @param lastSyncAt 最近一次同步完成时间（unix 秒）；0 = 从未同步
 * @param onSyncNow 执行一次条目同步（由上层持库状态，内部切 IO 并落盘）；返回统计
 * @param initialPairCode 从扫码/深链带进来的配对码（可为 null）
 * @param initialEnrollCode 开户深链（`vkey://enroll`）带进来的规范化开户码（可为 null）；
 *   非 null 时自动切到「开户码」方式并预填
 * @param initialEnrollUsername 开户深链附带的用户名（可为 null）
 * @param onSaved 配置成功回调：新设备材料 + 需要替换的 master_key（null 表示与本地一致）；
 *   **同步落盘并读回校验**，返回 null = 已持久化，非 null = 错误文案（未落盘，可重试）
 * @param onServerUrlChange 服务器地址变化（持久化到 AppSettings）
 * @param onClearDevice 断开配对（清除设备材料）
 * @param onClose 关闭本页
 * @param canExportTotp 是否存在可导出的 2FA 条目（false 时「导出 2FA 配置」入口不显示）
 * @param onExportTotp 点击「导出 2FA 配置」（验证与分享由 Activity 负责）
 * @param currentVersionName 当前版本名（如 `0.3.1`）
 * @param currentVersionCode 当前 versionCode（如 `30100`）
 * @param updateStatus 最近一次手动检查更新的结果文案；null = 尚未检查
 * @param updateChecking 是否正在检查更新
 * @param onCheckUpdate 点击「检查更新」（关于 tab）；参数为设置页当前填写的服务端地址
 * @param settingsTabState 当前分类（由 Activity 持有，进程内记住上次停留的分类）
 * @param onOpenImport 点击「导入 2FA 配置」（打开导入页）
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
    onClose: () -> Unit,
    canExportTotp: Boolean,
    onExportTotp: () -> Unit,
    currentVersionName: String,
    currentVersionCode: Int,
    updateStatus: String?,
    updateChecking: Boolean,
    onCheckUpdate: (String) -> Unit,
    settingsTabState: MutableState<SettingsTab>,
    onOpenImport: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    // 系统返回键：回到列表页，而不是退出应用
    BackHandler { onClose() }

    var url by remember { mutableStateOf(serverUrl) }
    var deviceName by remember { mutableStateOf(device?.device_name ?: defaultDeviceName()) }
    // 接入方式 + 各方式表单输入（互斥）：切换方式清空输入，深链/扫码只预填对应方式
    var form by remember {
        mutableStateOf(ConnectFormState.fromPrefill(initialPairCode, initialEnrollCode, initialEnrollUsername))
    }
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
    // 服务端地址编辑对话框：草稿值 / 探测中 / 错误文案。成功探测后才落盘，失败行值不变
    var showAddressDialog by remember { mutableStateOf(false) }
    var addressDraft by remember { mutableStateOf("") }
    var addressBusy by remember { mutableStateOf(false) }
    var addressError by remember { mutableStateOf<String?>(null) }
    // 「扫码」是否从地址对话框发起：回来后重新打开对话框并填入结果
    var scanForAddress by remember { mutableStateOf(false) }

    // 深链/预填可能在页面已打开时到达（热启动 onNewIntent，或扫码回调）：
    // 参数变化时重新应用一次，保证「方式自动切到对应项并预填」；
    // 无预填时按默认状态比较，不覆盖用户手动切换的方式与输入。
    LaunchedEffect(initialPairCode, initialEnrollCode, initialEnrollUsername) {
        val next = ConnectFormState.fromPrefill(initialPairCode, initialEnrollCode, initialEnrollUsername)
        if (next != ConnectFormState()) form = next
    }
    // 深链可能在上层写入新地址后到达：地址变化时同步到输入框（页面开着也能直接看到）
    LaunchedEffect(serverUrl) {
        if (serverUrl.isNotBlank() && serverUrl != url) url = serverUrl
    }

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
        val mk = form.masterKey.trim()
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
                    form = form.copy(masterKey = "")
                    info = context.getString(R.string.info_logged_in, result.config.device_name)
                }
            }
        }
    }

    /** 用配对码领取 master_key。 */
    val doPair: () -> Unit = {
        val code = form.pairCode.trim()
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
                    form = form.copy(pairCode = "")
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
                form = form.copy(enrollCode = "", enrollUsername = "")
            }
        }
    }

    /** 用开户码接入：校验 → （必要时）二次确认 → 请求。 */
    val doEnroll: () -> Unit = {
        val canonical = Links.parseEnrollCode(form.enrollCode)
        val address = url.trim()
        val username = form.enrollUsername.trim()
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

    /**
     * 保存服务端地址（对话框内）：格式校验 → 连通性探测（5s / 2xx）→ 成功才落盘。
     *
     * 失败时只更新对话框内的错误文案，行值与 AppSettings 都保持原值；
     * 已配置且地址确实变了则清本机设备绑定，提示重新登录 / 重新配对。
     */
    val doSaveAddress: () -> Unit = {
        val address = addressDraft.trim()
        when {
            addressBusy -> Unit
            address.isEmpty() -> addressError = context.getString(R.string.err_enter_server_url)
            !isValidServerUrl(address) -> addressError = context.getString(R.string.err_server_url_scheme)
            else -> {
                addressError = null
                addressBusy = true
                scope.launch {
                    try {
                        when (val probe = probeServerAddress(address)) {
                            ServerProbe.Reachable -> {
                                val rebind = requiresDeviceRebind(device?.server_url, address)
                                url = address
                                onServerUrlChange(address)
                                showAddressDialog = false
                                addressDraft = ""
                                if (rebind) {
                                    // token 属于旧服务器：清绑定（本地条目与 master_key 保留）
                                    generated = null
                                    onClearDevice()
                                    form = ConnectFormState()
                                    info = context.getString(R.string.info_server_updated_relogin)
                                } else {
                                    info = context.getString(R.string.info_server_saved)
                                }
                            }
                            is ServerProbe.Unreachable -> addressError = describeProbeFailure(context, probe)
                        }
                    } finally {
                        addressBusy = false
                    }
                }
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
    val serverChanged = pairedServer != null && normalizeServerUrl(url) != normalizeServerUrl(pairedServer)

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
                    // 扫码只填值、不落盘：地址必须在「保存」时探测连通性；
                    // 从地址对话框进来的扫码回到对话框，从表单进来的直接打开对话框确认保存
                    url = server
                    addressDraft = server
                    addressError = null
                    scanForAddress = false
                    showScan = false
                    showAddressDialog = true
                },
                onPairCode = { code ->
                    form = form.withPairCode(code)
                    showScan = false
                    scanForAddress = false
                    info = context.getString(R.string.info_pair_code_detected)
                },
                onEnrollCode = { target ->
                    form = form.withEnrollCode(target.code, target.username)
                    // 开户码 / `/join` 链接自带服务端地址时同步到地址行；落盘留到接入成功
                    // （接入请求本身就是连通性验证；裸码则保持现有地址）
                    target.serverUrl?.let { server -> url = server }
                    showScan = false
                    scanForAddress = false
                    info = context.getString(R.string.info_enroll_code_detected)
                },
                onCancel = {
                    showScan = false
                    // 从地址对话框扫码后取消：回到对话框继续编辑原值
                    if (scanForAddress) {
                        scanForAddress = false
                        showAddressDialog = true
                    }
                },
            )
        } else {
            // ---------------- 分类导航：先选类型，再列该类型的项 ----------------
            // TabRow 固定在顶部，内容随分类切换走同一套转场（260ms、不裁剪）；
            // 「检查更新」「关于」固定在页面底部：关于是导航入口而非设置项，放页脚后任何分类都能点到。
            var tab by settingsTabState
            val contentScroll = rememberScrollState()
            // 换分类回到顶部：避免上一分类的滚动位置把新分类顶到半截
            LaunchedEffect(tab) { contentScroll.scrollTo(0) }

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
                Column(Modifier.fillMaxSize().padding(padding)) {
                    TabRow(selectedTabIndex = tab.ordinal) {
                        SettingsTab.entries.forEach { entry ->
                            Tab(
                                selected = tab == entry,
                                onClick = { tab = entry },
                                text = {
                                    Text(
                                        text = stringResource(entry.labelRes()),
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                },
                            )
                        }
                    }

                    // 任务状态（进行中 / 成功 / 失败）：跨分类常驻，切分类不会看不到刚发生的结果
                    if (busy != null || info != null || error != null) {
                        Column(
                            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                        ) {
                            if (busy != null) {
                                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                                Text(busy.orEmpty(), style = MaterialTheme.typography.bodySmall)
                            }
                            info?.let {
                                Text(
                                    it,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.primary,
                                )
                            }
                            error?.let {
                                Text(
                                    it,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.error,
                                )
                            }
                        }
                    }

                    AnimatedContent(
                        targetState = tab,
                        modifier = Modifier.weight(1f).fillMaxWidth(),
                        transitionSpec = {
                            vkeyPageTransition(
                                forward = targetState.ordinal > initialState.ordinal,
                                animated = !vkeyPageAnimationsDisabled(context),
                            )
                        },
                        label = "vkey-settings-tab",
                    ) { group ->
                        Column(
                            modifier = Modifier
                                .fillMaxSize()
                                .verticalScroll(contentScroll)
                                .padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            when (group) {
                                // ---------------- 账号 ----------------
                                SettingsTab.ACCOUNT -> {
                                    // ---------- 服务端地址（两种状态都显示，点击进编辑对话框） ----------
                                    ServerAddressRow(
                                        url = url,
                                        enabled = busy == null && !addressBusy,
                                        onEdit = {
                                            addressDraft = url.trim()
                                            addressError = null
                                            showAddressDialog = true
                                        },
                                    )

                                    if (device != null) {
                                        // ---------- 已配置：状态卡 ----------
                                        Card(Modifier.fillMaxWidth()) {
                                            Column(Modifier.padding(16.dp)) {
                                                Text(
                                                    // 顶部状态直接带上账号名：接入完成后一眼可确认「已登录：xxx」
                                                    text = stringResource(R.string.status_logged_in, device.username),
                                                    style = MaterialTheme.typography.titleMedium,
                                                    fontWeight = FontWeight.Medium,
                                                )
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

                                        // ---------- 已配置：条目同步 ----------
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

                                        // ---------- 已配置：生成配对码 ----------
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
                                                                "&server=${normalizeServerUrl(url).ifBlank { device.server_url }}",
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

                                        // ---------- 已配置：设备管理（解除绑定） ----------
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
                                    }

                                    // ---------- 未配置：接入方式下拉框 + 当前方式的表单 ----------
                                    // 地址行在上面（已配置时也可改）；这里只放互斥的接入方式，
                                    // 切换后只渲染该方式的表单。已配置后整块隐藏，解除绑定后随状态立即恢复。
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
                                            // ---------- 接入方式（下拉框，三选一） ----------
                                            Card(Modifier.fillMaxWidth()) {
                                                Column(Modifier.padding(16.dp)) {
                                                    ConnectModeDropdown(
                                                        mode = form.mode,
                                                        onSelect = { option ->
                                                            if (form.mode != option) {
                                                                form = form.select(option)
                                                                info = context.getString(
                                                                    R.string.info_connect_mode_switched,
                                                                    context.getString(option.titleRes()),
                                                                )
                                                            }
                                                        },
                                                    )
                                                }
                                            }
                                            // ---------- 当前方式的表单（一次只渲染一个） ----------
                                            when (form.mode) {
                                                ConnectMode.MASTER_KEY -> Card(Modifier.fillMaxWidth()) {
                                                    Column(Modifier.padding(16.dp)) {
                                                        Text(stringResource(R.string.section_login_master_key), style = MaterialTheme.typography.titleMedium)
                                                        Text(
                                                            stringResource(R.string.login_master_key_desc),
                                                            style = MaterialTheme.typography.bodySmall,
                                                            modifier = Modifier.padding(top = 4.dp),
                                                        )
                                                        Spacer(Modifier.height(8.dp))
                                                        OutlinedTextField(
                                                            value = form.masterKey,
                                                            onValueChange = { form = form.copy(masterKey = it) },
                                                            label = { Text("master_key") },
                                                            singleLine = true,
                                                            visualTransformation = PasswordVisualTransformation(),
                                                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                                                            modifier = Modifier.fillMaxWidth(),
                                                        )
                                                        Spacer(Modifier.height(8.dp))
                                                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                                            Button(
                                                                onClick = doLogin,
                                                                enabled = busy == null,
                                                                modifier = Modifier.weight(1f),
                                                            ) { Text(stringResource(R.string.action_login_with_master_key)) }
                                                            Button(
                                                                onClick = {
                                                                    scanMode = form.mode.scanMode()
                                                                    showScan = true
                                                                },
                                                                enabled = busy == null,
                                                                modifier = Modifier.weight(1f),
                                                            ) { Text(stringResource(R.string.action_scan_input)) }
                                                        }
                                                    }
                                                }

                                                ConnectMode.PAIR -> Card(Modifier.fillMaxWidth()) {
                                                    Column(Modifier.padding(16.dp)) {
                                                        Text(stringResource(R.string.section_pair_with_code), style = MaterialTheme.typography.titleMedium)
                                                        Text(
                                                            stringResource(R.string.pair_with_code_desc),
                                                            style = MaterialTheme.typography.bodySmall,
                                                            modifier = Modifier.padding(top = 4.dp),
                                                        )
                                                        Spacer(Modifier.height(8.dp))
                                                        OutlinedTextField(
                                                            value = form.pairCode,
                                                            onValueChange = { form = form.copy(pairCode = it) },
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
                                                                    scanMode = form.mode.scanMode()
                                                                    showScan = true
                                                                },
                                                                enabled = busy == null,
                                                                modifier = Modifier.weight(1f),
                                                            ) { Text(stringResource(R.string.action_scan_input)) }
                                                        }
                                                    }
                                                }

                                                ConnectMode.ENROLL -> Card(Modifier.fillMaxWidth()) {
                                                    Column(Modifier.padding(16.dp)) {
                                                        Text(stringResource(R.string.section_enroll), style = MaterialTheme.typography.titleMedium)
                                                        Text(
                                                            stringResource(R.string.enroll_desc),
                                                            style = MaterialTheme.typography.bodySmall,
                                                            modifier = Modifier.padding(top = 4.dp),
                                                        )
                                                        Spacer(Modifier.height(8.dp))
                                                        OutlinedTextField(
                                                            value = form.enrollCode,
                                                            onValueChange = { form = form.copy(enrollCode = it) },
                                                            label = { Text(stringResource(R.string.label_enroll_code)) },
                                                            singleLine = true,
                                                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
                                                            modifier = Modifier.fillMaxWidth(),
                                                        )
                                                        Spacer(Modifier.height(8.dp))
                                                        OutlinedTextField(
                                                            value = form.enrollUsername,
                                                            onValueChange = { form = form.copy(enrollUsername = it) },
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
                                                                    scanMode = form.mode.scanMode()
                                                                    showScan = true
                                                                },
                                                                enabled = busy == null,
                                                                modifier = Modifier.weight(1f),
                                                            ) { Text(stringResource(R.string.action_scan_input)) }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                // ---------------- 设置（本机 / 外观 / 数据） ----------------
                                SettingsTab.SETTINGS -> {
                                    LocalSettings(
                                        showDeviceName = device == null,
                                        deviceName = deviceName,
                                        onDeviceNameChange = { deviceName = it },
                                        autoLockOnResume = autoLockOnResume,
                                        onAutoLockChange = onAutoLockChange,
                                    )
                                    AppearanceSettings(
                                        themeMode = themeMode,
                                        onThemeModeChange = onThemeModeChange,
                                        language = language,
                                        onLanguageChange = onLanguageChange,
                                    )
                                    DataSettings(
                                        canExportTotp = canExportTotp,
                                        onOpenImport = onOpenImport,
                                        onExportTotp = onExportTotp,
                                    )
                                }

                                // ---------------- 关于（内嵌渲染，不整页跳转） ----------------
                                SettingsTab.ABOUT -> AboutContent(
                                    currentVersionName = currentVersionName,
                                    currentVersionCode = currentVersionCode,
                                    updateStatus = updateStatus,
                                    updateChecking = updateChecking,
                                    onCheckUpdate = { onCheckUpdate(url.trim()) },
                                )
                            }
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
                    // 回到「先选方式」：方式与输入都恢复默认，避免解除绑定后仍停在旧方式的半截表单
                    form = ConnectFormState()
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
                    val canonical = Links.parseEnrollCode(form.enrollCode)
                    val username = form.enrollUsername.trim()
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

    // 服务端地址编辑：保存前必须探测 `GET {url}/api/v1/policy`（5s / 2xx），失败不落盘
    if (showAddressDialog) {
        /** 关闭对话框（探测中不允许关闭，避免结果回来时无处展示）。 */
        val closeAddressDialog: () -> Unit = {
            if (!addressBusy) {
                showAddressDialog = false
                addressError = null
            }
        }
        AlertDialog(
            onDismissRequest = closeAddressDialog,
            title = { Text(stringResource(R.string.section_server_address)) },
            text = {
                Column {
                    OutlinedTextField(
                        value = addressDraft,
                        onValueChange = {
                            addressDraft = it
                            addressError = null
                        },
                        label = { Text(stringResource(R.string.label_sync_server_url)) },
                        placeholder = {
                            if (addressDraft.isEmpty()) {
                                Text(stringResource(R.string.placeholder_server_url))
                            }
                        },
                        singleLine = true,
                        enabled = !addressBusy,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    addressError?.let {
                        Text(
                            text = it,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                            modifier = Modifier.padding(top = 4.dp),
                        )
                    }
                    if (addressBusy) {
                        Spacer(Modifier.height(8.dp))
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                        Text(
                            stringResource(R.string.busy_connecting_server),
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.padding(top = 4.dp),
                        )
                    } else {
                        Text(
                            stringResource(R.string.sync_scan_hint),
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.padding(top = 4.dp),
                        )
                        TextButton(onClick = {
                            // 关对话框去扫码（扫码页会覆盖整页），结果回来再打开并填值
                            scanForAddress = true
                            scanMode = ScanMode.CONFIG_LINK
                            addressError = null
                            showAddressDialog = false
                            showScan = true
                        }) { Text(stringResource(R.string.action_scan)) }
                    }
                }
            },
            confirmButton = {
                Button(onClick = doSaveAddress, enabled = !addressBusy) {
                    Text(stringResource(R.string.action_save_address))
                }
            },
            dismissButton = {
                TextButton(onClick = closeAddressDialog, enabled = !addressBusy) {
                    Text(stringResource(R.string.action_cancel))
                }
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
 * 接入方式下拉框：收起时一行显示当前选择（标题 + 说明），展开后每项带一行短说明。
 *
 * @param mode 当前选中的接入方式
 * @param onSelect 选择回调（切换方式并清空输入由调用方负责）
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ConnectModeDropdown(mode: ConnectMode, onSelect: (ConnectMode) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it },
    ) {
        OutlinedTextField(
            value = stringResource(mode.titleRes()),
            onValueChange = {},
            readOnly = true,
            singleLine = true,
            label = { Text(stringResource(R.string.connect_section_title)) },
            supportingText = { Text(stringResource(mode.descRes())) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor(MenuAnchorType.PrimaryNotEditable),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            ConnectMode.entries.forEach { option ->
                DropdownMenuItem(
                    text = {
                        Column {
                            Text(stringResource(option.titleRes()), style = MaterialTheme.typography.bodyLarge)
                            Text(
                                stringResource(option.descRes()),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    },
                    onClick = {
                        expanded = false
                        onSelect(option)
                    },
                )
            }
        }
    }
}

/**
 * 服务端地址行：一行显示当前地址（未设置为占位），整行可点 / 右侧「修改」进编辑对话框。
 *
 * @param url 当前地址（空串 = 未配置）
 * @param enabled false 时不可点（其它任务进行中）
 * @param onEdit 进入编辑对话框
 */
@Composable
private fun ServerAddressRow(url: String, enabled: Boolean, onEdit: () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(enabled = enabled, onClick = onEdit)
                .padding(start = 16.dp, end = 8.dp, top = 12.dp, bottom = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    stringResource(R.string.server_address_label),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    text = url.trim().ifEmpty { stringResource(R.string.server_url_not_set) },
                    style = MaterialTheme.typography.bodyLarge,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            TextButton(onClick = onEdit, enabled = enabled) {
                Text(stringResource(R.string.action_modify_address))
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

/** 设置分类 → tab 文案资源。 */
private fun SettingsTab.labelRes(): Int = when (this) {
    SettingsTab.ACCOUNT -> R.string.settings_tab_account
    SettingsTab.SETTINGS -> R.string.settings_tab_settings
    SettingsTab.ABOUT -> R.string.settings_tab_about
}

/**
 * 「本机」分类：本机设备名 + 回到前台时重新解锁。
 *
 * 设备名是登录 / 配对 / 开户共用的唯一定义处，因此仅未配置时显示
 * （已配置后状态卡里展示「设备：xxx」，改名需要重新登录，不在此处改）。
 *
 * @param showDeviceName 是否显示设备名输入（未配置时为 true）
 * @param deviceName 设备名当前值
 * @param onDeviceNameChange 设备名变化
 * @param autoLockOnResume 回前台是否重新解锁
 * @param onAutoLockChange 切换「回前台重新解锁」
 */
@Composable
private fun LocalSettings(
    showDeviceName: Boolean,
    deviceName: String,
    onDeviceNameChange: (String) -> Unit,
    autoLockOnResume: Boolean,
    onAutoLockChange: (Boolean) -> Unit,
) {
    if (showDeviceName) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp)) {
                Text(
                    stringResource(R.string.section_device_name),
                    style = MaterialTheme.typography.titleMedium,
                )
                Spacer(Modifier.height(4.dp))
                OutlinedTextField(
                    value = deviceName,
                    onValueChange = onDeviceNameChange,
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
    }

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
            Switch(
                checked = autoLockOnResume,
                onCheckedChange = onAutoLockChange,
            )
        }
    }
}

/**
 * 「外观」分类：明暗模式 + 界面语言（点击即生效，无需保存）。
 *
 * @param themeMode 当前明暗模式
 * @param onThemeModeChange 切换明暗模式
 * @param language 当前界面语言
 * @param onLanguageChange 切换界面语言（由上层落盘并重建 Activity）
 */
@Composable
private fun AppearanceSettings(
    themeMode: ThemeMode,
    onThemeModeChange: (ThemeMode) -> Unit,
    language: LanguageMode,
    onLanguageChange: (LanguageMode) -> Unit,
) {
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
}

/**
 * 「数据」分类：导入 / 导出 2FA 配置。
 *
 * 导入走主页 FAB 同一个导入页；导出仍需系统验证 + 红色警告（由上层负责），
 * 没有可导出条目时入口不显示。
 *
 * @param canExportTotp 是否存在可导出的 2FA 条目
 * @param onOpenImport 打开导入页
 * @param onExportTotp 点击导出（先验证后弹红色警告）
 */
@Composable
private fun DataSettings(
    canExportTotp: Boolean,
    onOpenImport: () -> Unit,
    onExportTotp: () -> Unit,
) {
    Card(Modifier.fillMaxWidth()) {
        SettingsRow(
            title = stringResource(R.string.import_title),
            subtitle = stringResource(R.string.import_subtitle),
            onClick = onOpenImport,
        )
    }
    if (canExportTotp) {
        Card(Modifier.fillMaxWidth()) {
            SettingsRow(
                title = stringResource(R.string.export_totp_title),
                subtitle = stringResource(R.string.export_totp_subtitle),
                onClick = onExportTotp,
            )
        }
    }
}

/**
 * 设置条目行：标题 + 可选说明 + 可选状态行 + 右侧箭头，整行可点。
 *
 * 设置页与「关于」tab（[AboutContent]）共用，因此是 `internal` 而非 `private`。
 *
 * @param title 主标题
 * @param onClick 点击回调
 * @param subtitle 说明文案（正文字号下方，可为 null）
 * @param status 状态行（如更新的检查结果，可为 null）
 * @param enabled false 时不可点（如更新检查进行中）
 */
@Composable
internal fun SettingsRow(
    title: String,
    onClick: () -> Unit,
    subtitle: String? = null,
    status: String? = null,
    enabled: Boolean = true,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(enabled = enabled, onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            subtitle?.let {
                Text(it, style = MaterialTheme.typography.bodySmall)
            }
            status?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
        }
        Icon(
            imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/** 默认设备名：`Android <型号>`（型号可能为空，退化为 `android`）。 */
private fun defaultDeviceName(): String {
    val model = Build.MODEL.orEmpty().trim()
    return SyncManager.sanitizeDeviceName(if (model.isEmpty()) "android" else "Android $model")
}

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

