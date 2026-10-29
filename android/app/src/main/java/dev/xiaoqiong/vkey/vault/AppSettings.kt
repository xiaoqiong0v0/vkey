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

    /** 同步服务地址（如 `https://vkey.xiaoqiong0v0.cn`）。 */
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

    private companion object {
        const val KEY_AUTO_LOCK = "auto_lock_on_resume"
        const val KEY_SERVER_URL = "server_url"
        const val KEY_THEME_MODE = "theme_mode"
        const val KEY_LANGUAGE = "language"
        const val DEFAULT_SERVER_URL = "https://vkey.xiaoqiong0v0.cn"
    }
}
