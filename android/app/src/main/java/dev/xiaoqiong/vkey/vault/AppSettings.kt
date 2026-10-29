package dev.xiaoqiong.vkey.vault

import android.content.Context
import java.util.Locale

/**
 * 主题模式：跟随系统 / 浅色 / 深色。
 *
 * @property storageValue 持久化到 SharedPreferences 的取值（`theme_mode`）
 */
enum class ThemeMode(val storageValue: String) {
    SYSTEM("system"),
    LIGHT("light"),
    DARK("dark"),
    ;

    companion object {
        /**
         * 把持久化取值解析成枚举，非法/缺失一律回退「跟随系统」。
         *
         * @param raw SharedPreferences 里的原始字符串
         * @return 对应枚举；无法识别时返回 [SYSTEM]
         */
        fun fromStorage(raw: String?): ThemeMode =
            entries.firstOrNull { it.storageValue == raw } ?: SYSTEM
    }
}

/**
 * 界面语言：跟随系统 / 中文 / English。
 *
 * @property storageValue 持久化到 SharedPreferences 的取值（`language`）
 */
enum class LanguageMode(val storageValue: String) {
    SYSTEM("system"),
    CHINESE("zh"),
    ENGLISH("en"),
    ;

    /** 覆盖用的 locale；null 表示不覆盖（跟随系统）。 */
    val locale: Locale?
        get() = when (this) {
            SYSTEM -> null
            CHINESE -> Locale.SIMPLIFIED_CHINESE
            ENGLISH -> Locale.ENGLISH
        }

    companion object {
        /**
         * 把持久化取值解析成枚举，非法/缺失一律回退「跟随系统」。
         *
         * @param raw SharedPreferences 里的原始字符串
         * @return 对应枚举；无法识别时返回 [SYSTEM]
         */
        fun fromStorage(raw: String?): LanguageMode =
            entries.firstOrNull { it.storageValue == raw } ?: SYSTEM
    }
}

/**
 * 应用设置（SharedPreferences 持久化）。
 *
 * 目前包含：回前台是否重新解锁、同步服务地址、主题模式、界面语言。
 * 后两项在冷启动时读取：[ThemeMode] 决定 Compose 配色，[LanguageMode] 在
 * `MainActivity.attachBaseContext` 里包装 locale。
 */
class AppSettings(context: Context) {

    private val sp = context.getSharedPreferences("vkey_settings", Context.MODE_PRIVATE)

    /** 从后台回到前台时是否重新要求解锁（默认关闭：用户已在系统层解锁过）。 */
    var autoLockOnResume: Boolean
        get() = sp.getBoolean(KEY_AUTO_LOCK, false)
        set(value) = sp.edit().putBoolean(KEY_AUTO_LOCK, value).apply()

    /**
     * 同步服务地址（如 `https://vkey.example.com`）。
     *
     * **默认为空串 = 未配置**：开源发行版不内置任何生产域名，
     * 调用方必须自行处理空值（提示「未配置服务端」，不得据此发起请求）。
     */
    var serverUrl: String
        get() = sp.getString(KEY_SERVER_URL, DEFAULT_SERVER_URL) ?: DEFAULT_SERVER_URL
        set(value) = sp.edit().putString(KEY_SERVER_URL, value.trim()).apply()

    /** 主题模式（默认跟随系统）。 */
    var themeMode: ThemeMode
        get() = ThemeMode.fromStorage(sp.getString(KEY_THEME_MODE, null))
        set(value) = sp.edit().putString(KEY_THEME_MODE, value.storageValue).apply()

    /** 界面语言（默认跟随系统）。 */
    var language: LanguageMode
        get() = LanguageMode.fromStorage(sp.getString(KEY_LANGUAGE, null))
        set(value) = sp.edit().putString(KEY_LANGUAGE, value.storageValue).apply()

    /**
     * 首启二选一页是否选过「我已有 master_key / 配对码」（持久化记录）。
     *
     * 跳过**不会**创建库、也不会生成主密钥：因此下次启动只要仍未配置
     * （没有 vault / master_key），二选一页依旧会出现。该标记只用于提示与取证。
     */
    var onboardingSkipped: Boolean
        get() = sp.getBoolean(KEY_ONBOARDING_SKIPPED, false)
        set(value) = sp.edit().putBoolean(KEY_ONBOARDING_SKIPPED, value).apply()

    /**
     * 最近一次更新检查的时间（毫秒时间戳，0 = 从未检查）。
     *
     * 用于启动静默检查的频率限制：距上次检查不足 24 小时则跳过。
     * 手动检查同样写入，避免随后启动再查一次。
     */
    var lastUpdateCheckAt: Long
        get() = sp.getLong(KEY_LAST_UPDATE_CHECK_AT, 0L)
        set(value) = sp.edit().putLong(KEY_LAST_UPDATE_CHECK_AT, value).apply()

    private companion object {
        const val KEY_AUTO_LOCK = "auto_lock_on_resume"
        const val KEY_SERVER_URL = "server_url"
        const val KEY_THEME_MODE = "theme_mode"
        const val KEY_LANGUAGE = "language"
        const val KEY_LAST_UPDATE_CHECK_AT = "last_update_check_at"
        const val KEY_ONBOARDING_SKIPPED = "onboarding_skipped"
        /** 默认服务地址：空串（未配置）。发行版不内置任何生产域名。 */
        const val DEFAULT_SERVER_URL = ""
    }
}
