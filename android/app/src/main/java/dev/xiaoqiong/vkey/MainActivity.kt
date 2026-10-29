package dev.xiaoqiong.vkey

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.compose.animation.AnimatedContent
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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
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
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
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
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.core.content.ContextCompat
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.xiaoqiong.vkey.i18n.LocaleSupport
import dev.xiaoqiong.vkey.net.UpdateApi
import dev.xiaoqiong.vkey.net.UpdateInfo
import dev.xiaoqiong.vkey.sync.EnrollDeepLink
import dev.xiaoqiong.vkey.sync.ItemJson
import dev.xiaoqiong.vkey.sync.ItemsSync
import dev.xiaoqiong.vkey.sync.Links
import dev.xiaoqiong.vkey.sync.SyncManager
import dev.xiaoqiong.vkey.sync.SyncStats
import dev.xiaoqiong.vkey.totp.Totp
import dev.xiaoqiong.vkey.ui.IssuerIcon
import dev.xiaoqiong.vkey.ui.OnboardingState
import dev.xiaoqiong.vkey.ui.ScanMode
import dev.xiaoqiong.vkey.ui.SettingsTab
import dev.xiaoqiong.vkey.ui.UpdateBanner
import dev.xiaoqiong.vkey.ui.UpdateDialog
import dev.xiaoqiong.vkey.ui.buildOtpauthUri
import dev.xiaoqiong.vkey.ui.clearClipboard
import dev.xiaoqiong.vkey.ui.copyToClipboard
import dev.xiaoqiong.vkey.ui.describeFailure
import dev.xiaoqiong.vkey.ui.onboardingState
import dev.xiaoqiong.vkey.ui.theme.VkeyTheme
import dev.xiaoqiong.vkey.ui.vkeyPageAnimationsDisabled
import dev.xiaoqiong.vkey.ui.vkeyPageTransition
import dev.xiaoqiong.vkey.update.ApkVerifier
import dev.xiaoqiong.vkey.update.UpdateInstaller
import dev.xiaoqiong.vkey.update.UpdateVerifier
import dev.xiaoqiong.vkey.vault.AppSettings
import dev.xiaoqiong.vkey.vault.Base32
import dev.xiaoqiong.vkey.vault.DeviceConfig
import dev.xiaoqiong.vkey.vault.LanguageMode
import dev.xiaoqiong.vkey.vault.ThemeMode
import dev.xiaoqiong.vkey.vault.TotpItem
import dev.xiaoqiong.vkey.vault.VaultData
import dev.xiaoqiong.vkey.vault.VaultStore
import dev.xiaoqiong.vkey.vault.WebAuthnItem
import dev.xiaoqiong.vkey.vault.withLegacyWebAuthnMigrated
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
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

/** 深链取证日志标签（`adb logcat -s vkey-deeplink`）。 */
private const val DEEP_LINK_LOG_TAG = "vkey-deeplink"

/** 导出 2FA 时的免验证窗口（毫秒）：刚通过系统验证就跳过，避免连续弹窗。 */
private const val EXPORT_AUTH_GRACE_MS = 30_000L

/** 导出内容的 MIME 类型（纯文本，交给系统分享面板，不上传任何地方）。 */
private const val EXPORT_MIME_TYPE = "text/plain"

/** 启动静默检查更新的最小间隔：24 小时（手动检查不受此限制）。 */
private const val UPDATE_CHECK_INTERVAL_MS = 24L * 60L * 60L * 1000L

/** 更新 APK 的缓存子目录（必须与 `res/xml/file_paths.xml` 的 cache-path 一致）。 */
private const val UPDATE_CACHE_DIR = "updates"

/** 更新流程日志 tag（`adb logcat -s vkey-update`）：只打版本号与校验结果。 */
private const val UPDATE_LOG_TAG = "vkey-update"

/** 首启流程日志 tag（`adb logcat -s vkey-onboarding`）：只打状态名，不含任何密钥。 */
private const val ONBOARDING_LOG_TAG = "vkey-onboarding"

/**
 * 库内的顶层页面。
 *
 * [depth] 是层级序号：数字变大 = 进入更深一层（前进），变小 = 返回。
 * 转场方向只由它判定，不靠调用点各自猜。
 *
 * @property depth 层级序号（主页为 0）
 */
private enum class VkeyPage(val depth: Int) {
    HOME(0),
    SYNC(1),
    SCAN(1),
    /** 导入页可从主页 FAB 或设置·设置进入，退回到来时的那一页，层级因此比设置页深一层。 */
    IMPORT(2),
}

/** 应用入口：持有库状态与「自动锁定」逻辑，UI 全部在 Compose 里。 */
class MainActivity : androidx.fragment.app.FragmentActivity() {

    private lateinit var store: VaultStore
    private lateinit var settings: AppSettings

    private val vault = mutableStateOf<VaultData?>(null)
    private val locked = mutableStateOf(false)

    /** 解锁页状态文案；真实文案在 onCreate 里按当前语言取，避免构造期访问资源。 */
    private val lockMessage = mutableStateOf("")
    private val canRetry = mutableStateOf(false)

    /** 深链带来的服务器地址（非空表示要打开「同步配置」页）。 */
    private val pendingSyncServer = mutableStateOf<String?>(null)

    /** 深链带来的配对码（预填到同步配置页）。 */
    private val pendingPairCode = mutableStateOf<String?>(null)

    /** 深链带来的开户请求（`vkey://enroll?server=…&code=…`）；null 表示无。 */
    private val pendingEnroll = mutableStateOf<EnrollDeepLink?>(null)

    /**
     * 库内当前顶层页面。
     *
     * 由 Activity 持有而不是组合内 `remember`：深链在 [handleDeepLink] 里直接改它即可跳转，
     * 不依赖组合副作用（热启动时 `LaunchedEffect` 曾未触发导致停在主页）。
     */
    private val topPageState = mutableStateOf(VkeyPage.HOME)

    /** 开户深链预填（预填开户卡并展开）；由 Activity 直接写入，组合层只读。 */
    private val enrollPrefillState = mutableStateOf<EnrollDeepLink?>(null)

    /** 配对码预填（深链带来的配对码，进「设置」页时填进输入框）。 */
    private val syncPrefillState = mutableStateOf("")

    /**
     * 本次运行是否点了首启的「我已有 master_key / 配对码」。
     *
     * 只影响本次运行：跳过**不建库**，因此主页用 [guestVault] 兜空态；
     * 下次冷启动若仍未配置，二选一页会照常出现（见 `ui.onboardingState`）。
     */
    private val onboardingSkippedThisRun = mutableStateOf(false)

    /** 从设置返回首启二选一页（访客态下按返回键时置位，进入主界面后再清掉）。 */
    private val returnToSetupChoice = mutableStateOf(false)

    /**
     * 访客态占位库：首启选了「已有配置」但还没接入时给主页用的空库。
     *
     * **只在内存里**：`master_key` 为空串，任何写入都会被 [persistable] 拦下，绝不落盘。
     */
    private val guestVault = VaultData(master_key = "")

    /**
     * 设置页当前分类。
     *
     * 由 Activity 持有而不是组合内 `remember`：切页面（设置 ↔ 主页 / 导入）后仍记得
     * 上次停留的分类，进程内有效。首启跳过时由 [onSkipOnboarding] 置为「账号」。
     */
    private val settingsTabState = mutableStateOf(SettingsTab.ACCOUNT)

    /** 系统验证进行中，避免重复拉起。 */
    private var authInFlight = false

    /** 最近一次系统验证成功的时间（毫秒），用于导出 2FA 时 30 秒内免重复验证。 */
    private var lastAuthAt = 0L

    /** 「导出 2FA 配置」红色警告弹窗是否可见（验证通过后才置 true）。 */
    private val exportDialogVisible = mutableStateOf(false)

    /** 验证弹窗关闭会触发一次 onResume，用它跳过循环触发。 */
    private var skipNextResume = false

    /**
     * 应用设置里的语言偏好：在 Activity 创建前包装 base context，
     * 使 `resources`（`getString` / `stringResource`）按选定语言取值。
     * 「跟随系统」时原样返回，不改写系统配置。
     */
    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(LocaleSupport.wrap(newBase, AppSettings(newBase).language))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 防截屏（验证码属于敏感信息）
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)

        store = VaultStore(filesDir)
        settings = AppSettings(this)
        lockMessage.value = getString(R.string.lock_verifying)
        val loaded = store.read()
        // 旧版本把 webauthn 误并入 items：升级后一次性迁移到「密钥」列表并落盘
        val migrated = loaded?.withLegacyWebAuthnMigrated()
        if (migrated != null && migrated != loaded) store.write(migrated)
        vault.value = migrated
        locked.value = vault.value != null
        // 首启页面决策：未配置（无库）时永远是「创建 / 我已配置」二选一；跳过不建库，故下次仍会再问
        val startupState = onboardingState(
            vaultLoaded = vault.value != null,
            onboardingSkipped = settings.onboardingSkipped,
        )
        Log.i(
            ONBOARDING_LOG_TAG,
            "startup state=${startupState.name} showChoice=${startupState.needsSetupChoice} " +
                "vault=${vault.value != null} skipped=${settings.onboardingSkipped}",
        )
        handleDeepLink(intent)

        setContent {
            // 主题模式只影响 Compose 配色：改设置即重组，无需重建 Activity
            var themeMode by remember { mutableStateOf(settings.themeMode) }
            var language by remember { mutableStateOf(settings.language) }
            VkeyTheme(mode = themeMode) {
                VkeyApp(
                    // 访客态（首启跳过且还没接入）用空库兜主页；不落盘、不生成任何密钥
                    // 访客态按返回键时回到首启二选一页（此时仍不建库）
                    vault = vault.value
                        ?: guestVault.takeIf { onboardingSkippedThisRun.value && !returnToSetupChoice.value },
                    locked = locked.value,
                    lockMessage = lockMessage.value,
                    canRetry = canRetry.value,
                    onRetryLock = { showSystemAuth() },
                    onboardingSkipped = startupState == OnboardingState.SKIPPED_UNCONFIGURED,
                    onSkipOnboarding = { skipOnboarding() },
                    onGuestBackToSetup = { returnToSetupChoice.value = true },
                    onCreate = { data ->
                        returnToSetupChoice.value = false
                        vault.value = data
                        locked.value = false
                    },
                    onUnlock = { locked.value = false },
                    onLock = { locked.value = true },
                    onPersist = { data ->
                        if (!persistable(data)) {
                            Toast.makeText(this, getString(R.string.err_vault_not_configured), Toast.LENGTH_LONG)
                                .show()
                        } else {
                            vault.value = data
                            store.write(data)
                        }
                    },
                    onPersistVerified = { data ->
                        if (!persistable(data)) {
                            getString(R.string.err_vault_not_configured)
                        } else {
                            // 配置类写入专用：落盘 + 读回比对 device_id，校验通过才提交内存状态；
                            // 失败返回错误文案（由 UI 显式展示，绝不静默）
                            runCatching { store.writeAndVerify(data) }
                                .onSuccess { vault.value = data }
                                .fold(
                                    onSuccess = { null },
                                    onFailure = {
                                        getString(R.string.err_vault_save_failed, describeFailure(this, it))
                                    },
                                )
                        }
                    },
                    autoLockOnResume = settings.autoLockOnResume,
                    onAutoLockChange = { settings.autoLockOnResume = it },
                    serverUrl = settings.serverUrl,
                    onServerUrlChange = { settings.serverUrl = it },
                    themeMode = themeMode,
                    onThemeModeChange = { mode ->
                        themeMode = mode
                        settings.themeMode = mode
                    },
                    language = language,
                    onLanguageChange = { mode ->
                        language = mode
                        // 语言在 attachBaseContext 里应用：先落盘再重建，冷启动同样生效
                        settings.language = mode
                        recreate()
                    },
                    pendingSyncServer = pendingSyncServer.value,
                    pendingPairCode = pendingPairCode.value,
                    pendingEnroll = pendingEnroll.value,
                    onApplyEnrollLink = { link -> applyEnrollLink(link, fromOnNewIntent = false) },
                    topPageState = topPageState,
                    settingsTabState = settingsTabState,
                    enrollPrefillState = enrollPrefillState,
                    syncPrefillState = syncPrefillState,
                    onPendingHandled = {
                        pendingSyncServer.value = null
                        pendingPairCode.value = null
                        pendingEnroll.value = null
                    },
                    exportDialogVisible = exportDialogVisible.value,
                    onRequestExport = { requestTotpExport() },
                    onConfirmExport = { shareTotpExport() },
                    onDismissExport = { exportDialogVisible.value = false },
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleDeepLink(intent, fromOnNewIntent = true)
    }

    /**
     * 处理 `vkey://config?server=…`、`vkey://pair?code=…` 与 `vkey://enroll?server=…&code=…` 深链。
     *
     * - 配置深链：只写服务器地址，并打开「同步配置」页让用户输入配对码 / master_key；
     * - 配对深链：预填配对码（免鉴权领取，无需先登录）；
     * - 开户深链：已登录（`vault.device != null`）时**完全不响应**（不跳转、不改地址、不弹窗），
     *   只提示「当前已登录 X，无需开户」；未登录时由 [applyEnrollLink] 直接应用
     *   （覆盖地址、预填开户卡、打开「设置」页），冷启动与热启动走同一条路径；
     *   server/code 缺失或格式不符只提示「链接无效或已过期」，绝不改动现有配置。
     *
     * @param intent 启动或复用的 Intent（非 VIEW 或没有 data 时直接返回）
     * @param fromOnNewIntent 是否来自 [onNewIntent]（只用于日志取证）
     */
    private fun handleDeepLink(intent: Intent?, fromOnNewIntent: Boolean = false) {
        if (intent?.action != Intent.ACTION_VIEW) return
        val data = intent.dataString ?: return

        val server = Links.parseServerConfig(data)
        if (server != null) {
            settings.serverUrl = server
            pendingPairCode.value = null
            pendingEnroll.value = null
            pendingSyncServer.value = server
            Toast.makeText(this, getString(R.string.toast_server_set, server), Toast.LENGTH_LONG).show()
            return
        }

        val code = Links.parsePairCodeLink(data)
        if (code != null) {
            pendingPairCode.value = code
            pendingEnroll.value = null
            pendingSyncServer.value = settings.serverUrl
            Toast.makeText(this, getString(R.string.toast_pair_code_detected), Toast.LENGTH_LONG).show()
            return
        }

        if (data.trim().startsWith(Links.ENROLL_PREFIX, ignoreCase = true)) {
            // 已登录：开户码没有意义（同一设备只能绑一个账号），整条深链不响应，
            // 不跳转、不改服务端地址、不弹确认，只提示当前账号
            val device = vault.value?.device
            if (device != null) {
                Toast.makeText(
                    this,
                    getString(R.string.toast_enroll_already_logged_in, device.username),
                    Toast.LENGTH_LONG,
                ).show()
                return
            }
            val link = Links.parseEnrollLink(data)
            if (link == null) {
                // 非法/缺参：只提示，不落任何状态、不动服务器地址
                Toast.makeText(this, getString(R.string.err_deep_link_invalid), Toast.LENGTH_LONG).show()
            } else {
                pendingPairCode.value = null
                pendingSyncServer.value = null
                // 直接应用（不依赖组合副作用）；pendingEnroll 仍保留，组合层作兜底
                applyEnrollLink(link, fromOnNewIntent = fromOnNewIntent)
                pendingEnroll.value = link
            }
        }
    }

    /**
     * 应用一条开户深链：覆盖服务器地址 → 预填开户卡 → 打开「设置」页。
     *
     * 全部写入 Activity 持有的状态（[settings] / [enrollPrefillState] / [topPageState]），
     * 因此冷启动（[onCreate]）与热启动（[onNewIntent]）都能直接生效，
     * 不依赖组合里的 `LaunchedEffect`（热启动曾因此停在主页）。
     *
     * @param link 已校验的开户深链
     * @param fromOnNewIntent 是否来自 [onNewIntent]（仅用于日志取证）
     */
    private fun applyEnrollLink(link: EnrollDeepLink, fromOnNewIntent: Boolean) {
        settings.serverUrl = link.serverUrl
        syncPrefillState.value = ""
        enrollPrefillState.value = link
        topPageState.value = VkeyPage.SYNC
        // 只记码长，不落开户码明文
        Log.i(
            DEEP_LINK_LOG_TAG,
            "enroll link applied (fromOnNewIntent=$fromOnNewIntent, codeLength=${link.code.length})",
        )
    }

    /**
     * 首启选「我已有 master_key / 配对码」：**不建库**，进主页空态并打开设置·账号。
     *
     * 只写偏好 `onboarding_skipped`（记录用；下次未配置时仍会再次询问），
     * 主密钥 / 设备材料一律不生成、不落盘。
     */
    private fun skipOnboarding() {
        settings.onboardingSkipped = true
        onboardingSkippedThisRun.value = true
        returnToSetupChoice.value = false
        settingsTabState.value = SettingsTab.ACCOUNT
        syncPrefillState.value = ""
        enrollPrefillState.value = null
        topPageState.value = VkeyPage.SYNC
        Log.i(ONBOARDING_LOG_TAG, "skipped: no vault created, opening settings/account")
    }

    /**
     * 是否允许把 [data] 落盘。
     *
     * 拦截访客态（首启跳过、未接入账号）产生的写入：空主密钥的库一旦落盘就再也解不开，
     * 也绝不该凭空生成密钥。正常建库 / 登录 / 配对 / 开户拿到的 master_key 都不为空，因此不受影响。
     *
     * @param data 待写入的库内容
     * @return true 表示可以落盘
     */
    private fun persistable(data: VaultData): Boolean = data.master_key.isNotBlank()

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
        authenticate(onSuccess = { locked.value = false })
    }

    /**
     * 拉起系统验证，成功后执行 [onSuccess]（解锁页与导出前验证共用同一段实现）。
     *
     * 验证成功会记录时间戳，供 [requestTotpExport] 的 30 秒免重复验证使用。
     *
     * @param onSuccess 验证通过后的动作
     * @param onError 验证出错时的额外回调（错误码 + 系统文案）；null 时只更新解锁页状态
     */
    private fun authenticate(
        onSuccess: () -> Unit,
        onError: ((Int, CharSequence) -> Unit)? = null,
    ) {
        if (authInFlight) return
        val allowed = androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG or
            androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
        val km = getSystemService(KEYGUARD_SERVICE) as android.app.KeyguardManager
        if (!km.isDeviceSecure) {
            lockMessage.value = getString(R.string.lock_need_device_credential)
            canRetry.value = false
            return
        }
        authInFlight = true
        canRetry.value = false
        lockMessage.value = getString(R.string.lock_verifying)
        val prompt = androidx.biometric.BiometricPrompt(
            this,
            androidx.core.content.ContextCompat.getMainExecutor(this),
            object : androidx.biometric.BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    result: androidx.biometric.BiometricPrompt.AuthenticationResult,
                ) {
                    authInFlight = false
                    lastAuthAt = System.currentTimeMillis()
                    onSuccess()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    authInFlight = false
                    skipNextResume = true
                    lockMessage.value = getString(R.string.lock_failed, errString)
                    canRetry.value = true
                    onError?.invoke(errorCode, errString)
                }

                override fun onAuthenticationFailed() {
                    lockMessage.value = getString(R.string.lock_not_recognized)
                }
            },
        )
        val info = androidx.biometric.BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.biometric_title))
            .setSubtitle(getString(R.string.biometric_subtitle))
            .setAllowedAuthenticators(allowed)
            .build()
        runCatching { prompt.authenticate(info) }
            .onFailure {
                authInFlight = false
                skipNextResume = true
                lockMessage.value = getString(R.string.lock_unavailable, it.message.orEmpty())
                canRetry.value = true
            }
    }

    /** 可导出的 2FA 条目：排除墓碑与非 totp 条目（与列表页可见条目的口径一致）。 */
    private fun exportableTotpItems(): List<TotpItem> =
        vault.value?.items.orEmpty().filter { it.kind == ItemJson.KIND_TOTP && !it.deleted }

    /**
     * 点击「导出 2FA 配置」：先验证（30 秒内刚验证过则跳过），通过后才弹红色警告。
     *
     * 未设置锁屏密码或验证被取消/失败时**不导出**（弹窗也不会出现）。
     */
    private fun requestTotpExport() {
        // 防御：没有条目时入口不显示，这里再挡一次（不触发验证、不弹窗）
        if (exportableTotpItems().isEmpty()) return
        if (System.currentTimeMillis() - lastAuthAt <= EXPORT_AUTH_GRACE_MS) {
            exportDialogVisible.value = true
            return
        }
        val km = getSystemService(KEYGUARD_SERVICE) as android.app.KeyguardManager
        if (!km.isDeviceSecure) {
            Toast.makeText(this, getString(R.string.export_totp_need_unlock), Toast.LENGTH_LONG).show()
            return
        }
        authenticate(
            onSuccess = { exportDialogVisible.value = true },
            onError = { errorCode, _ ->
                // 用户主动取消不算失败，不打扰
                val cancelled = errorCode == androidx.biometric.BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                    errorCode == androidx.biometric.BiometricPrompt.ERROR_USER_CANCELED ||
                    errorCode == androidx.biometric.BiometricPrompt.ERROR_CANCELED
                if (!cancelled) {
                    Toast.makeText(this, getString(R.string.export_totp_auth_failed), Toast.LENGTH_SHORT)
                        .show()
                }
            },
        )
    }

    /**
     * 用户确认导出：把全部未删除的 2FA 条目拼成 otpauth 文本，交给系统分享面板。
     *
     * 明文只存在于本次 Intent 载荷里：不写日志、不落文件、不上传；条目为空时直接返回。
     */
    private fun shareTotpExport() {
        exportDialogVisible.value = false
        val items = exportableTotpItems()
        if (items.isEmpty()) return
        val payload = items.joinToString("\n") { buildOtpauthUri(it) }
        // 用 createChooser 由系统决定渠道（微信 / 邮件 / 云盘…），本应用不接触任何网络
        val send = Intent(Intent.ACTION_SEND)
            .setType(EXPORT_MIME_TYPE)
            .putExtra(Intent.EXTRA_TEXT, payload)
        startActivity(Intent.createChooser(send, getString(R.string.export_totp_chooser_title)))
    }
}

/**
 * 应用根组合：首启二选一 → 解锁页 → 主页（库内页面）。
 *
 * @param vault 当前库；null = 本机还没有库（首启二选一页）
 * @param onboardingSkipped 上次是否选过「我已有 master_key / 配对码」（只影响首启页提示文案）
 * @param onSkipOnboarding 首启选「我已有 master_key / 配对码」（不建库，进主页空态 + 设置·账号）
 * @param settingsTabState 设置页分类（Activity 持有，进程内记住）
 */
@Composable
private fun VkeyApp(
    vault: VaultData?,
    locked: Boolean,
    lockMessage: String,
    canRetry: Boolean,
    onRetryLock: () -> Unit,
    onboardingSkipped: Boolean,
    onSkipOnboarding: () -> Unit,
    onGuestBackToSetup: () -> Unit,
    onCreate: (VaultData) -> Unit,
    onUnlock: () -> Unit,
    onLock: () -> Unit,
    onPersist: (VaultData) -> Unit,
    onPersistVerified: (VaultData) -> String?,
    autoLockOnResume: Boolean,
    onAutoLockChange: (Boolean) -> Unit,
    serverUrl: String,
    onServerUrlChange: (String) -> Unit,
    themeMode: ThemeMode,
    onThemeModeChange: (ThemeMode) -> Unit,
    language: LanguageMode,
    onLanguageChange: (LanguageMode) -> Unit,
    pendingSyncServer: String?,
    pendingPairCode: String?,
    pendingEnroll: EnrollDeepLink?,
    onApplyEnrollLink: (EnrollDeepLink) -> Unit,
    topPageState: MutableState<VkeyPage>,
    settingsTabState: MutableState<SettingsTab>,
    enrollPrefillState: MutableState<EnrollDeepLink?>,
    syncPrefillState: MutableState<String>,
    onPendingHandled: () -> Unit,
    exportDialogVisible: Boolean,
    onRequestExport: () -> Unit,
    onConfirmExport: () -> Unit,
    onDismissExport: () -> Unit,
) {
    when {
        vault == null -> SetupScreen(
            onboardingSkipped = onboardingSkipped,
            onCreate = onCreate,
            onSkip = onSkipOnboarding,
        )
        locked -> LockScreen(message = lockMessage, canRetry = canRetry, onRetry = onRetryLock)
        else -> VaultScreen(
            vault = vault,
            onGuestBackToSetup = onGuestBackToSetup,
            onLock = onLock,
            onPersist = onPersist,
            onPersistVerified = onPersistVerified,
            autoLockOnResume = autoLockOnResume,
            onAutoLockChange = onAutoLockChange,
            serverUrl = serverUrl,
            onServerUrlChange = onServerUrlChange,
            themeMode = themeMode,
            onThemeModeChange = onThemeModeChange,
            language = language,
            onLanguageChange = onLanguageChange,
            pendingSyncServer = pendingSyncServer,
            pendingPairCode = pendingPairCode,
            pendingEnroll = pendingEnroll,
            onApplyEnrollLink = onApplyEnrollLink,
            topPageState = topPageState,
            settingsTabState = settingsTabState,
            enrollPrefillState = enrollPrefillState,
            syncPrefillState = syncPrefillState,
            onPendingHandled = onPendingHandled,
            exportDialogVisible = exportDialogVisible,
            onRequestExport = onRequestExport,
            onConfirmExport = onConfirmExport,
            onDismissExport = onDismissExport,
        )
    }
}

/**
 * 首次引导：二选一 —— 创建新的恢复码（走原建库流程）或「我已有 master_key / 配对码」（不建库）。
 *
 * 未配置前每次启动都会回到这里：跳过既不生成主密钥也不写库，所以 `onboardingSkipped`
 * 只影响提示文案，不抑制本页（判定见 `ui.onboardingState`）。
 *
 * @param onboardingSkipped 上次是否选过跳过（用于追加一行「上次已跳过」提示）
 * @param onCreate 建库成功回调（携带新库）
 * @param onSkip 选择「我已有…」：由 Activity 记偏好并跳到设置·账号
 */
@Composable
private fun SetupScreen(
    onboardingSkipped: Boolean,
    onCreate: (VaultData) -> Unit,
    onSkip: () -> Unit,
) {
    val context = LocalContext.current
    // false = 二选一页；true = 建库表单（生成恢复码 → 确认已保存）
    var creating by remember { mutableStateOf(false) }
    AnimatedContent(
        targetState = creating,
        modifier = Modifier.fillMaxSize(),
        transitionSpec = {
            vkeyPageTransition(
                forward = targetState,
                animated = !vkeyPageAnimationsDisabled(context),
            )
        },
        label = "vkey-setup",
    ) { inCreation ->
        if (inCreation) {
            CreateVaultForm(onCreate = onCreate, onCancel = { creating = false })
        } else {
            SetupChoice(
                onboardingSkipped = onboardingSkipped,
                onStartCreate = { creating = true },
                onSkip = onSkip,
            )
        }
    }
}

/**
 * 首启二选一页：主按钮创建新恢复码，次按钮「我已有 master_key / 配对码」（不建库）。
 *
 * @param onboardingSkipped 上次是否选过跳过（true 时追加提示）
 * @param onStartCreate 点击「创建新的恢复码」
 * @param onSkip 点击「我已有 master_key / 配对码」
 */
@Composable
private fun SetupChoice(
    onboardingSkipped: Boolean,
    onStartCreate: () -> Unit,
    onSkip: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Text(stringResource(R.string.setup_choice_title), style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(8.dp))
        Text(
            stringResource(R.string.setup_choice_desc),
            style = MaterialTheme.typography.bodyMedium,
        )
        if (onboardingSkipped) {
            Spacer(Modifier.height(8.dp))
            Text(
                stringResource(R.string.setup_choice_prev_skipped),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(Modifier.height(24.dp))
        Button(
            onClick = onStartCreate,
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.setup_choice_create)) }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(
            onClick = onSkip,
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.setup_choice_skip)) }
    }
}

/**
 * 建库表单：生成主密钥 → 展示并确认已保存恢复码 → 建库。
 *
 * @param onCreate 建库成功回调（携带新库）
 * @param onCancel 返回二选一页（未写任何内容）
 */
@Composable
private fun CreateVaultForm(onCreate: (VaultData) -> Unit, onCancel: () -> Unit) {
    val context = LocalContext.current
    val store = remember { VaultStore(context.filesDir) }
    val recoveryCode = remember { store.generateMasterKey() }
    var saved by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Text(stringResource(R.string.setup_title), style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(8.dp))
        Text(
            stringResource(R.string.setup_recovery_hint),
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
        TextButton(onClick = {
            copyToClipboard(context, recoveryCode, sensitive = true)
            Toast.makeText(context, context.getString(R.string.toast_recovery_copied), Toast.LENGTH_SHORT).show()
        }) {
            Text(stringResource(R.string.setup_copy_recovery))
        }
        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = saved, onCheckedChange = { saved = it })
            Text(stringResource(R.string.setup_saved_check))
        }
        Spacer(Modifier.height(16.dp))
        Button(
            onClick = { onCreate(store.create(recoveryCode)) },
            enabled = saved,
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.action_continue)) }
        TextButton(onClick = onCancel, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.action_back))
        }
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
        Text(stringResource(R.string.lock_title), style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(12.dp))
        Text(message, style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center)
        if (canRetry) {
            Spacer(Modifier.height(8.dp))
            Text(
                stringResource(R.string.lock_tap_retry),
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
    onGuestBackToSetup: () -> Unit,
    onLock: () -> Unit,
    onPersist: (VaultData) -> Unit,
    onPersistVerified: (VaultData) -> String?,
    autoLockOnResume: Boolean,
    onAutoLockChange: (Boolean) -> Unit,
    serverUrl: String,
    onServerUrlChange: (String) -> Unit,
    themeMode: ThemeMode,
    onThemeModeChange: (ThemeMode) -> Unit,
    language: LanguageMode,
    onLanguageChange: (LanguageMode) -> Unit,
    pendingSyncServer: String?,
    pendingPairCode: String?,
    pendingEnroll: EnrollDeepLink?,
    onApplyEnrollLink: (EnrollDeepLink) -> Unit,
    topPageState: MutableState<VkeyPage>,
    settingsTabState: MutableState<SettingsTab>,
    enrollPrefillState: MutableState<EnrollDeepLink?>,
    syncPrefillState: MutableState<String>,
    onPendingHandled: () -> Unit,
    exportDialogVisible: Boolean,
    onRequestExport: () -> Unit,
    onConfirmExport: () -> Unit,
    onDismissExport: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var showAdd by remember { mutableStateOf(false) }
    var fabExpanded by remember { mutableStateOf(false) }
    // 当前顶层页面：状态由 Activity 持有（深链在组合外直接跳转），转场方向按 VkeyPage.depth 判定
    var topPage by topPageState
    // 导入页的「返回目标」：主页 FAB 进 → 回主页；设置·数据进 → 回设置
    var importBackTarget by remember { mutableStateOf(VkeyPage.HOME) }
    // 待确认的删除 / 吊销目标：null = 没有弹窗（所有删除都必须二次确认）
    var pendingDelete by remember { mutableStateOf<TotpItem?>(null) }
    var pendingRevoke by remember { mutableStateOf<WebAuthnItem?>(null) }
    // 2FA / 密钥两个页签，支持左右滑动；页签与滑动双向同步
    val pagerState = rememberPagerState(pageCount = { PAGE_COUNT })
    // 深链带来的配对码：状态由 Activity 持有，进「设置」页时预填
    var syncPrefill by syncPrefillState
    // 深链带来的开户请求：进「设置」页时展开开户卡并预填 code/username；离开本页即清除
    var enrollPrefill by enrollPrefillState
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
                .makeText(context, context.getString(R.string.toast_press_back_again), android.widget.Toast.LENGTH_SHORT)
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

    // ---------------- 应用内更新（检查 → 下载 → 校验 → 安装） ----------------
    val updateSettings = remember { AppSettings(context) }
    // 已发现的新版本（驱动主页提示条）；null = 暂无更新
    var availableUpdate by remember { mutableStateOf<UpdateInfo?>(null) }
    // 对话框展示的更新信息；null = 对话框关闭
    var updateDialogInfo by remember { mutableStateOf<UpdateInfo?>(null) }
    // 提示条是否已被用户关闭（仅本次会话）
    var updateBannerDismissed by remember { mutableStateOf(false) }
    var updateChecking by remember { mutableStateOf(false) }
    // 设置页「检查更新」的结果文案（已是最新 / 发现新版本 / 检查失败）
    var updateCheckStatus by remember { mutableStateOf<String?>(null) }
    // 下载 / 校验 / 安装错误，就地显示在更新对话框里
    var updateError by remember { mutableStateOf<String?>(null) }
    var downloadProgress by remember { mutableStateOf<Float?>(null) }
    var downloadJob by remember { mutableStateOf<Job?>(null) }

    /** 当前版本（来自构建产物，不硬编码）。 */
    val currentVersionName = BuildConfig.VERSION_NAME
    val currentVersionCode = BuildConfig.VERSION_CODE
    val currentVersionText = stringResource(
        R.string.update_current_version,
        currentVersionName,
        currentVersionCode,
    )

    /** 更新检查的目标地址：已配对优先用配对时记录的地址，否则用设置里的地址。 */
    val updateTargetAddress: () -> String = {
        (latestVault.device?.server_url ?: serverUrl).trim()
    }

    /**
     * 执行一次更新检查。
     *
     * @param address 手动检查时传入的地址（设置页当前输入）；空串回退到已保存地址
     * @param manual true = 手动检查（写结果文案、发现新版本时弹对话框）；
     *   false = 启动静默检查（失败不打扰用户）
     */
    val runUpdateCheck: (String, Boolean) -> Unit = { address, manual ->
        val target = address.trim().ifBlank { updateTargetAddress() }
        if (updateChecking) {
            Unit
        } else if (target.isBlank()) {
            if (manual) {
                updateCheckStatus = context.getString(
                    R.string.update_check_failed,
                    context.getString(R.string.err_enter_server_url),
                )
            }
        } else if (manual) {
            updateChecking = true
            updateCheckStatus = context.getString(R.string.update_checking)
            scope.launch {
                try {
                    val info = UpdateApi().check(target)
                    updateSettings.lastUpdateCheckAt = System.currentTimeMillis()
                    val newer = info?.takeIf {
                        UpdateVerifier.isNewer(it.versionCode, currentVersionCode.toLong())
                    }
                    availableUpdate = newer
                    updateBannerDismissed = false
                    if (newer != null) {
                        updateCheckStatus = context.getString(R.string.update_found, newer.versionName)
                        updateError = null
                        updateDialogInfo = newer
                    } else {
                        updateCheckStatus = context.getString(R.string.update_up_to_date)
                    }
                    Log.i(UPDATE_LOG_TAG, "check -> ${newer?.versionCode ?: "up_to_date"}")
                } catch (t: Throwable) {
                    val reason = describeFailure(context, t)
                    updateCheckStatus = context.getString(R.string.update_check_failed, reason)
                    Log.w(UPDATE_LOG_TAG, "check failed: $reason")
                } finally {
                    updateChecking = false
                }
            }
        } else {
            // 静默检查：不写页面状态，失败直接忽略
            scope.launch {
                runCatching { UpdateApi().check(target) }
                    .onSuccess { info ->
                        if (info != null &&
                            UpdateVerifier.isNewer(info.versionCode, currentVersionCode.toLong())
                        ) {
                            availableUpdate = info
                            updateBannerDismissed = false
                            Log.i(UPDATE_LOG_TAG, "silent check -> ${info.versionCode}")
                        }
                    }
                updateSettings.lastUpdateCheckAt = System.currentTimeMillis()
            }
        }
    }

    // 启动静默检查：距上次检查不足 24 小时则跳过（手动检查不受限）
    LaunchedEffect(Unit) {
        val elapsed = System.currentTimeMillis() - updateSettings.lastUpdateCheckAt
        if (updateTargetAddress().isNotEmpty() && elapsed >= UPDATE_CHECK_INTERVAL_MS) {
            runUpdateCheck("", false)
        }
    }

    /**
     * 下载并校验更新包：SHA-256 / 大小 / 签名全部通过才允许安装。
     *
     * 任一步失败都会删除文件、把原因留在对话框里，绝不弹出安装。
     */
    val startDownload: (UpdateInfo) -> Unit = { info ->
        if (downloadJob?.isActive == true) {
            Unit
        } else {
            updateError = null
            downloadProgress = 0f
            downloadJob = scope.launch {
                val dir = File(context.cacheDir, UPDATE_CACHE_DIR)
                val apk = File(dir, "${info.versionCode}.apk")
                try {
                    dir.mkdirs()
                    // 已有完整文件（例如刚授权「安装未知应用」后重试）：跳过重复下载
                    val cached = withContext(Dispatchers.IO) {
                        apk.isFile && UpdateVerifier.matchesSha256(
                            info.sha256,
                            UpdateVerifier.fileSha256Hex(apk),
                        )
                    }
                    if (cached) {
                        downloadProgress = 1f
                    } else {
                        if (apk.exists()) apk.delete()
                        UpdateApi().download(info.url, apk, info.size) { done, total ->
                            if (total > 0L) {
                                val fraction = (done.toFloat() / total.toFloat()).coerceIn(0f, 1f)
                                // 按 1% 粒度刷新，避免每 64KB 都触发重组
                                val shown = downloadProgress ?: 0f
                                if (fraction >= 1f || fraction - shown >= 0.01f) {
                                    downloadProgress = fraction
                                }
                            }
                        }
                    }
                    val actualSha = withContext(Dispatchers.IO) { UpdateVerifier.fileSha256Hex(apk) }
                    when {
                        !UpdateVerifier.matchesSha256(info.sha256, actualSha) -> {
                            apk.delete()
                            updateError = context.getString(R.string.update_verify_sha_failed)
                            Log.w(UPDATE_LOG_TAG, "verify ${info.versionCode}: sha256 mismatch")
                        }
                        info.size > 0L && apk.length() != info.size -> {
                            apk.delete()
                            updateError = context.getString(R.string.update_verify_size_failed)
                            Log.w(UPDATE_LOG_TAG, "verify ${info.versionCode}: size mismatch")
                        }
                        !withContext(Dispatchers.IO) {
                            ApkVerifier.hasTrustedSignature(context, apk)
                        } -> {
                            apk.delete()
                            updateError = context.getString(R.string.update_verify_signature_failed)
                            Log.w(UPDATE_LOG_TAG, "verify ${info.versionCode}: signature mismatch")
                        }
                        !UpdateInstaller.canRequestPackageInstall(context) -> {
                            updateError = context.getString(R.string.update_need_install_permission)
                            UpdateInstaller.openUnknownSourcesSettings(context)
                        }
                        else -> {
                            Log.i(UPDATE_LOG_TAG, "verify ${info.versionCode}: sha256 ok, signature ok")
                            runCatching { UpdateInstaller.install(context, apk) }
                                .onSuccess {
                                    updateDialogInfo = null
                                    updateCheckStatus = null
                                }
                                .onFailure {
                                    updateError = context.getString(
                                        R.string.update_install_failed,
                                        describeFailure(context, it),
                                    )
                                }
                        }
                    }
                } catch (e: CancellationException) {
                    // 取消下载：删掉半成品，把控制权交回调用方（不会被下面的 catch 吞掉）
                    apk.delete()
                    throw e
                } catch (t: Throwable) {
                    apk.delete()
                    // 取消下载时 OkHttp 的中断会以 IOException 形式出现：原样抛出取消，不当作失败
                    currentCoroutineContext().ensureActive()
                    val reason = describeFailure(context, t)
                    updateError = context.getString(R.string.update_download_failed, reason)
                    Log.w(UPDATE_LOG_TAG, "download failed: $reason")
                } finally {
                    downloadProgress = null
                    downloadJob = null
                }
            }
        }
    }

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
                // 同步可能带来新条目：清掉图标的失败静默期，让新条目的 favicon 立刻可重试
                dev.xiaoqiong.vkey.net.FaviconCache.clearFailures()
                outcome.stats
            } catch (t: Throwable) {
                lastSyncError = describeFailure(context, t)
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

    // ---- 密钥页：实时查询服务端（手机不持有凭据，不做本地同步）----
    // 展示源只来自这里的实时结果，不再读 vault.webAuthn
    var liveWebAuthn by remember { mutableStateOf<List<WebAuthnItem>>(emptyList()) }
    // 上次实时拉取被跳过的条数（解密/解析失败），与列表一起展示便于定位「真的没有」还是「解不开」
    var webAuthnSkipped by remember { mutableStateOf(0) }
    var webAuthnLoading by remember { mutableStateOf(false) }
    var webAuthnLoadError by remember { mutableStateOf<String?>(null) }
    var webAuthnActionError by remember { mutableStateOf<String?>(null) }

    /**
     * 实时拉取密钥列表（`GET /items?since=0` 翻页到结束）。
     *
     * 未配对（无 device）时清空数据并交给页面显示引导。
     */
    val loadWebAuthn: suspend () -> Unit = {
        val config = latestVault.device
        if (config == null) {
            liveWebAuthn = emptyList()
            webAuthnSkipped = 0
            webAuthnLoadError = null
            webAuthnLoading = false
        } else {
            webAuthnLoading = true
            webAuthnLoadError = null
            webAuthnActionError = null
            try {
                val masterKey = SyncManager.parseMasterKey(latestVault.master_key)
                val api = SyncManager.authorizedApi(config)
                val live = withContext(Dispatchers.IO) {
                    ItemsSync.fetchWebAuthnLiveDetailed(api, masterKey)
                }
                liveWebAuthn = live.items
                webAuthnSkipped = live.skipped
            } catch (t: Throwable) {
                webAuthnLoadError = describeFailure(context, t)
            } finally {
                webAuthnLoading = false
            }
        }
    }

    /** 吊销：服务端推墓碑，成功后重新实时拉取；失败把 code/message 留在列表上方。 */
    val revokeWebAuthn: (WebAuthnItem) -> Unit = { item ->
        scope.launch {
            val config = latestVault.device
            if (config == null) {
                webAuthnActionError = context.getString(R.string.err_sync_not_configured)
            } else {
                webAuthnActionError = null
                try {
                    val api = SyncManager.authorizedApi(config)
                    withContext(Dispatchers.IO) { ItemsSync.revokeWebAuthn(api, item) }
                    loadWebAuthn()
                } catch (t: Throwable) {
                    webAuthnActionError = describeFailure(context, t)
                }
            }
        }
    }

    // 滑动/切到「密钥」页时自动实时加载（settledPage 避免拖动过程中反复请求）
    LaunchedEffect(pagerState.settledPage, vault.device) {
        if (pagerState.settledPage == PAGE_WEBAUTHN) loadWebAuthn()
    }

    LaunchedEffect(pendingSyncServer, pendingPairCode) {
        if (pendingSyncServer != null || pendingPairCode != null) {
            syncPrefill = pendingPairCode.orEmpty()
            topPage = VkeyPage.SYNC
            onPendingHandled()
        }
    }

    // 开户深链兜底：主路径在 Activity 的 onNewIntent/onCreate 里已直接应用（写同一份状态）；
    // 这里只在尚未应用过时补一次，保证「pendingEnroll 有值但页面没跳」不会发生。
    LaunchedEffect(pendingEnroll) {
        val link = pendingEnroll ?: return@LaunchedEffect
        if (enrollPrefill != link) onApplyEnrollLink(link)
        onPendingHandled()
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

    // 顶层页面转场：前进时新页从右滑入、返回时从左滑入，方向只由 VkeyPage.depth 判定
    AnimatedContent(
        targetState = topPage,
        modifier = Modifier.fillMaxSize(),
        transitionSpec = {
            vkeyPageTransition(
                forward = targetState.depth > initialState.depth,
                animated = !vkeyPageAnimationsDisabled(context),
            )
        },
        label = "vkey-page",
    ) { target ->
        when (target) {
            // 主页：页签 / FAB / 遮罩一起参与转场
            VkeyPage.HOME -> Box(Modifier.fillMaxSize()) {
                // 墓碑条目仍在库里（等下次同步推送），但 UI 不显示；非 totp 条目不属于 2FA 页
                val visibleTotp = vault.items.filter { it.kind == ItemJson.KIND_TOTP && !it.deleted }
                Scaffold(
                    topBar = {
                        TopAppBar(
                            title = {
                                Text(
                                    stringResource(
                                        R.string.home_title,
                                        visibleTotp.size,
                                        liveWebAuthn.size,
                                    ),
                                    style = MaterialTheme.typography.titleMedium,
                                )
                            },
                            actions = {
                                TextButton(onClick = { syncPrefill = ""; enrollPrefill = null; topPage = VkeyPage.SYNC }) { Text(stringResource(R.string.action_settings)) }
                                TextButton(onClick = onLock) { Text(stringResource(R.string.action_lock)) }
                            },
                        )
                    },
                ) { padding ->
                    Column(Modifier.fillMaxSize().padding(padding)) {
                        // 发现新版本：主页顶部提示条（可关闭，不弹窗打断）
                        val bannerUpdate = availableUpdate?.takeIf {
                            !updateBannerDismissed &&
                                UpdateVerifier.isNewer(it.versionCode, currentVersionCode.toLong())
                        }
                        if (bannerUpdate != null) {
                            UpdateBanner(
                                versionName = bannerUpdate.versionName,
                                onView = {
                                    updateError = null
                                    updateDialogInfo = bannerUpdate
                                },
                                onDismiss = { updateBannerDismissed = true },
                            )
                        }
                        TabRow(selectedTabIndex = pagerState.currentPage) {
                            Tab(
                                selected = pagerState.currentPage == PAGE_2FA,
                                onClick = { scope.launch { pagerState.animateScrollToPage(PAGE_2FA) } },
                                text = { Text("2FA") },
                            )
                            Tab(
                                selected = pagerState.currentPage == PAGE_WEBAUTHN,
                                onClick = { scope.launch { pagerState.animateScrollToPage(PAGE_WEBAUTHN) } },
                                text = { Text(stringResource(R.string.tab_webauthn)) },
                            )
                        }
                        HorizontalPager(state = pagerState, modifier = Modifier.fillMaxSize()) { page ->
                            when (page) {
                                PAGE_2FA -> TotpList(
                                    entries = visibleTotp,
                                    nowMillis = nowMillis,
                                    onCopy = { code ->
                                        copyToClipboard(context, code, sensitive = true)
                                        Toast.makeText(
                                            context,
                                            context.getString(R.string.toast_code_copied),
                                            Toast.LENGTH_SHORT,
                                        ).show()
                                        scope.launch {
                                            delay(30_000)
                                            clearClipboard(context)
                                        }
                                    },
                                    onDelete = { pendingDelete = it },
                                )
                                else -> WebAuthnLivePage(
                                    configured = vault.device != null,
                                    loading = webAuthnLoading,
                                    error = webAuthnLoadError,
                                    actionError = webAuthnActionError,
                                    entries = liveWebAuthn,
                                    skipped = webAuthnSkipped,
                                    onRefresh = { scope.launch { loadWebAuthn() } },
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
                                    label = stringResource(R.string.fab_scan_qr),
                                    onClick = {
                                        fabExpanded = false
                                        topPage = VkeyPage.SCAN
                                    },
                                )
                                ActionButton(
                                    label = stringResource(R.string.fab_manual_input),
                                    onClick = {
                                        fabExpanded = false
                                        showAdd = true
                                    },
                                )
                                ActionButton(
                                    label = stringResource(R.string.fab_import_config),
                                    onClick = {
                                        fabExpanded = false
                                        importBackTarget = VkeyPage.HOME
                                        topPage = VkeyPage.IMPORT
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

            VkeyPage.SYNC -> dev.xiaoqiong.vkey.ui.SyncScreen(
                masterKey = vault.master_key,
                device = vault.device,
                hasLocalItems = vault.items.any { !it.deleted },
                // 开户深链带来的地址优先：settings 的写入未必在本次组合里可见
                serverUrl = enrollPrefill?.serverUrl ?: serverUrl,
                lastSyncAt = vault.lastSyncAt,
                onSyncNow = doSync,
                initialPairCode = syncPrefill.takeIf { it.isNotBlank() },
                initialEnrollCode = enrollPrefill?.code,
                initialEnrollUsername = enrollPrefill?.username,
                onSaved = { config, newMasterKey ->
                    // 配对/开户拿到的 master_key 才是账号密钥：以它为准（本地条目保留）。
                    // 走 latestVault 而非闭包捕获的 vault，避免陈旧快照覆盖并发写入；
                    // 落盘并读回校验成功后才提交内存状态，失败回传错误文案（null = 成功）
                    val base = latestVault
                    onPersistVerified(
                        base.copy(
                            master_key = newMasterKey ?: base.master_key,
                            device = config,
                        ),
                    )
                },
                onServerUrlChange = onServerUrlChange,
                autoLockOnResume = autoLockOnResume,
                onAutoLockChange = onAutoLockChange,
                themeMode = themeMode,
                onThemeModeChange = onThemeModeChange,
                language = language,
                onLanguageChange = onLanguageChange,
                onClearDevice = { onPersist(vault.copy(device = null)) },
                onClose = {
                    enrollPrefill = null
                    // 访客态（首启跳过、仍未接入）从设置返回时回到首启二选一页，而不是空主页
                    if (vault.device == null && vault.master_key.isEmpty()) {
                        onGuestBackToSetup()
                    }
                    topPage = VkeyPage.HOME
                },
                // 与列表页可见条目同口径：至少一条未删除的 totp 条目才显示导出入口
                canExportTotp = vault.items.any { it.kind == ItemJson.KIND_TOTP && !it.deleted },
                onExportTotp = onRequestExport,
                currentVersionName = currentVersionName,
                currentVersionCode = currentVersionCode,
                updateStatus = updateCheckStatus,
                updateChecking = updateChecking,
                onCheckUpdate = { address -> runUpdateCheck(address, true) },
                settingsTabState = settingsTabState,
                // 设置·数据 → 导入页；关闭时回到设置（保留上次停留的分类）
                onOpenImport = {
                    importBackTarget = VkeyPage.SYNC
                    topPage = VkeyPage.IMPORT
                },
            )

            // 主页 FAB / 设置·设置：从 otpauth 文本（选文件 / 粘贴）批量导入 2FA 条目。
            // 落盘走 writeAndVerify：失败回传文案在页内展示，成功才 Toast + 回到来源页。
            VkeyPage.IMPORT -> dev.xiaoqiong.vkey.ui.ImportScreen(
                existing = vault.items,
                onImport = { items ->
                    // 用 latestVault 而非闭包快照，避免覆盖导入期间发生的并发写入
                    val base = latestVault
                    onPersistVerified(base.copy(items = base.items + items))
                },
                onClose = { topPage = importBackTarget },
            )

            // 主页 FAB：添加 2FA 条目的入口，只接受 otpauth:// 二维码
            VkeyPage.SCAN -> dev.xiaoqiong.vkey.ui.ScanScreen(
                mode = ScanMode.TOTP,
                onResult = { item ->
                    onPersist(vault.copy(items = vault.items + item))
                    topPage = VkeyPage.HOME
                },
                onCancel = { topPage = VkeyPage.HOME },
            )
        }
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
            title = { Text(stringResource(R.string.dialog_delete_totp_title)) },
            text = { Text(stringResource(R.string.dialog_delete_totp_text)) },
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
                }) { Text(stringResource(R.string.action_delete)) }
            },
            dismissButton = {
                TextButton(onClick = { pendingDelete = null }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }

    // 吊销 WebAuthn 凭据：二次确认后直接向服务端推墓碑（手机不持有凭据，不落本地）
    pendingRevoke?.let { item ->
        AlertDialog(
            onDismissRequest = { pendingRevoke = null },
            title = { Text(stringResource(R.string.dialog_revoke_title)) },
            text = { Text(stringResource(R.string.dialog_revoke_text)) },
            confirmButton = {
                TextButton(onClick = {
                    pendingRevoke = null
                    revokeWebAuthn(item)
                }) { Text(stringResource(R.string.action_revoke)) }
            },
            dismissButton = {
                TextButton(onClick = { pendingRevoke = null }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }

    // 导出 2FA：验证通过后才出现；红色强调「明文密钥」风险，确认后才生成并分享
    if (exportDialogVisible) {
        AlertDialog(
            onDismissRequest = onDismissExport,
            title = { Text(stringResource(R.string.export_totp_title)) },
            text = {
                Text(
                    text = stringResource(R.string.export_totp_warning),
                    color = MaterialTheme.colorScheme.error,
                    fontWeight = FontWeight.Medium,
                )
            },
            confirmButton = {
                TextButton(
                    onClick = onConfirmExport,
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
                ) { Text(stringResource(R.string.export_totp_confirm)) }
            },
            dismissButton = {
                TextButton(onClick = onDismissExport) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }

    // 更新对话框：版本 / 大小 / 说明 / 当前版本 + 下载进度与校验错误
    updateDialogInfo?.let { info ->
        UpdateDialog(
            info = info,
            currentVersion = currentVersionText,
            progress = downloadProgress,
            error = updateError,
            onDownload = { startDownload(info) },
            onCancelDownload = { downloadJob?.cancel() },
            onDismiss = {
                // 下载中不允许关闭（避免误触后任务无法观察）
                if (downloadJob?.isActive != true) {
                    updateDialogInfo = null
                    updateError = null
                }
            },
        )
    }
}

@Composable
private fun ActionButton(label: String, onClick: () -> Unit) {
    // 直接用 content 槽（不传空 icon）：空 icon 会让 uiautomator / 无障碍服务读不到按钮文字
    ExtendedFloatingActionButton(onClick = onClick) {
        Text(label)
    }
}

/**
 * 列表展示顺序：`updatedAt` 倒序（最新在最上面）。
 *
 * 时间字段缺失（`updatedAt == 0`，旧数据）时退化为 `version` 倒序；
 * 仍相同则按 `id` 升序兜底，保证同一份数据每次渲染顺序一致（刷新时不抖动）。
 *
 * @param id 条目 id（最后一级 tie-break，升序）
 * @param updatedAt 条目最后写入时间（unix 秒，0 表示缺失）
 * @param version 服务端版本号（`updatedAt` 缺失时的备用排序键）
 * @return 排序后的新列表（不修改入参）
 */
private fun <T> List<T>.sortedForDisplay(
    id: (T) -> String,
    updatedAt: (T) -> Long,
    version: (T) -> Long,
): List<T> = sortedWith(
    compareByDescending<T> { updatedAt(it) }
        .thenByDescending { version(it) }
        .thenBy { id(it) },
)

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
        EmptyState(
            title = stringResource(R.string.empty_totp_title),
            description = stringResource(R.string.empty_totp_desc),
        )
        return
    }
    // 展示顺序由 UI 决定（同步层保持服务端顺序）：按更新时间倒序
    val ordered = remember(entries) {
        entries.sortedForDisplay(
            id = { it.id },
            updatedAt = { it.updatedAt },
            version = { it.version },
        )
    }
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        items(ordered, key = { it.id }) { item ->
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
 * 密钥页：**实时查询服务端**（不落本地），三态 + 手动「刷新」。
 *
 * 手机不持有凭据，因此这里不做本地同步：每次进入页面 / 点刷新都重新拉取，
 * 展示 `rp_id`、账号与创建时间，并允许吊销（服务端墓碑）。
 *
 * @param configured 是否已配对（无 device 时提示先完成同步配置）
 * @param loading 是否正在加载
 * @param error 上次加载失败的原因（非 null 时展示错误态 + 重试）
 * @param actionError 吊销失败原因（展示在列表上方，不覆盖已有列表）
 * @param entries 实时查到的条目（已过滤墓碑）
 * @param skipped 上次拉取被跳过的条数（解密/解析失败），用于诊断汇总
 * @param onRefresh 重新拉取
 * @param onRevoke 请求吊销（需二次确认）
 */
@Composable
private fun WebAuthnLivePage(
    configured: Boolean,
    loading: Boolean,
    error: String?,
    actionError: String?,
    entries: List<WebAuthnItem>,
    skipped: Int,
    onRefresh: () -> Unit,
    onRevoke: (WebAuthnItem) -> Unit,
) {
    if (!configured) {
        EmptyState(
            title = stringResource(R.string.empty_webauthn_unconfigured_title),
            description = stringResource(R.string.empty_webauthn_unconfigured_desc),
        )
        return
    }
    Column(Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                text = if (loading) {
                    stringResource(R.string.webauthn_loading)
                } else {
                    stringResource(R.string.webauthn_counts, entries.size, skipped)
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            TextButton(onClick = onRefresh, enabled = !loading) {
                Text(stringResource(R.string.action_refresh))
            }
        }
        actionError?.let { message ->
            Text(
                text = message,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
        Box(Modifier.weight(1f)) {
            when {
                loading && entries.isEmpty() -> LinearProgressIndicator(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 48.dp).align(Alignment.Center),
                )
                error != null -> WebAuthnErrorState(error = error, onRetry = onRefresh)
                entries.isEmpty() -> EmptyState(
                    title = stringResource(R.string.empty_webauthn_title),
                    description = stringResource(R.string.empty_webauthn_desc),
                )
                else -> WebAuthnList(entries = entries, onRevoke = onRevoke)
            }
        }
    }
}

/** 密钥页加载失败态：错误原因 + 重试。 */
@Composable
private fun WebAuthnErrorState(error: String, onRetry: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(stringResource(R.string.webauthn_load_failed), style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(8.dp))
        Text(
            text = error,
            style = MaterialTheme.typography.bodySmall,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(12.dp))
        Button(onClick = onRetry) { Text(stringResource(R.string.action_retry)) }
    }
}

/**
 * 密钥页：WebAuthn 凭据列表（只读 + 吊销；不提供新增）。
 *
 * @param entries 实时查到的条目（已过滤墓碑）
 * @param onRevoke 请求吊销（需二次确认）
 */
@Composable
private fun WebAuthnList(entries: List<WebAuthnItem>, onRevoke: (WebAuthnItem) -> Unit) {
    if (entries.isEmpty()) {
        EmptyState(
            title = stringResource(R.string.empty_webauthn_title),
            description = stringResource(R.string.empty_webauthn_list_desc),
        )
        return
    }
    // 展示顺序由 UI 决定：按更新时间倒序（最新在最上面）
    val ordered = remember(entries) {
        entries.sortedForDisplay(
            id = { it.id },
            updatedAt = { it.updatedAt },
            version = { it.version },
        )
    }
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        items(ordered, key = { it.id }) { item ->
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
                Text(
                    item.rpId.ifBlank { stringResource(R.string.unknown_site) },
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    item.username.ifBlank { item.displayName }.ifBlank { item.label }
                        .ifBlank { stringResource(R.string.unnamed_account) },
                    style = MaterialTheme.typography.bodySmall,
                )
                if (createdAt != null) {
                    Spacer(Modifier.height(4.dp))
                    Text(
                        stringResource(R.string.webauthn_created_at, createdAt),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            TextButton(onClick = onRevoke) { Text(stringResource(R.string.action_revoke)) }
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
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                // 站点图标：先字母徽标，抓到 favicon 后覆盖（尺寸固定，行高不跳）
                IssuerIcon(issuer = item.issuer, label = item.account)
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        item.issuer.ifBlank { stringResource(R.string.unnamed_issuer) },
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Text(item.account, style = MaterialTheme.typography.bodySmall)
                }
                TextButton(onClick = onDelete) { Text(stringResource(R.string.action_delete)) }
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
                Text(stringResource(R.string.totp_copy_countdown, remain))
            }
        }
        HorizontalDivider()
    }
}

@Composable
private fun AddDialog(onDismiss: () -> Unit, onAdd: (String, String, String) -> Unit) {
    val context = LocalContext.current
    var issuer by remember { mutableStateOf("") }
    var account by remember { mutableStateOf("") }
    var secret by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.dialog_add_totp_title)) },
        text = {
            Column {
                OutlinedTextField(
                    value = issuer,
                    onValueChange = { issuer = it },
                    label = { Text(stringResource(R.string.label_issuer)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = account,
                    onValueChange = { account = it },
                    label = { Text(stringResource(R.string.label_account)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = secret,
                    onValueChange = { secret = it },
                    label = { Text(stringResource(R.string.label_base32_secret)) },
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
                    decoded == null -> error = context.getString(R.string.err_secret_not_base32)
                    decoded.size < 10 ->
                        error = context.getString(R.string.err_secret_too_short, decoded.size)
                    else -> onAdd(issuer.trim(), account.trim(), key.uppercase())
                }
            }) { Text(stringResource(R.string.action_save)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) }
        },
    )
}
