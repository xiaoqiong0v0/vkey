package dev.xiaoqiong.vkey.i18n

import android.content.Context
import android.content.res.Configuration
import android.os.LocaleList
import dev.xiaoqiong.vkey.vault.AppSettings
import dev.xiaoqiong.vkey.vault.LanguageMode
import java.util.Locale

/** `Accept-Language` 请求头名。 */
const val ACCEPT_LANGUAGE_HEADER: String = "Accept-Language"

/** 中文（简体）语言标识。 */
const val ACCEPT_LANGUAGE_ZH: String = "zh-CN"

/** 英文语言标识。 */
const val ACCEPT_LANGUAGE_EN: String = "en"

/**
 * 返回当前 App 语言对应的 `Accept-Language` 取值。
 *
 * 显式选中语言时用该语言；跟随系统时用 [Locale.getDefault]（`MainActivity`
 * 在跟随系统时已把它复位为系统 locale）。非英文的系统语言按中文处理，
 * 与资源目录（`values/` 为中文、`values-en/` 为英文）的回落一致。
 *
 * @param context 任意 context
 * @return `zh-CN` 或 `en`
 */
fun headerLanguage(context: Context): String {
    val locale = AppSettings(context).language.locale ?: Locale.getDefault()
    return if (locale.language.equals("en", ignoreCase = true)) ACCEPT_LANGUAGE_EN else ACCEPT_LANGUAGE_ZH
}

/**
 * 语言切换支持（不依赖 appcompat）。
 *
 * 做法：`MainActivity.attachBaseContext` 里按偏好包装 Context 的 configuration，
 * 使 `resources`（进而 `stringResource` / `getString`）按选定 locale 取值。
 * 「跟随系统」= 不覆盖，并把进程默认 locale 复位成系统值（否则切回跟随系统后
 * 模块级 `Locale.getDefault()` 仍停留在上一次的覆盖值）。
 */
object LocaleSupport {

    /**
     * 按 [mode] 包装 base context。
     *
     * @param base Activity 的原始 base context（此时其 configuration 仍是系统配置）
     * @param mode 语言偏好
     * @return 覆盖了 locale 的 Context；[LanguageMode.SYSTEM] 时原样返回
     */
    fun wrap(base: Context, mode: LanguageMode): Context {
        val locale = mode.locale
        if (locale == null) {
            // 跟随系统：清掉历史上设置过的进程默认 locale
            Locale.setDefault(systemLocale(base))
            return base
        }
        Locale.setDefault(locale)
        val config = Configuration(base.resources.configuration).apply {
            setLocales(LocaleList(locale))
            setLayoutDirection(locale)
        }
        return base.createConfigurationContext(config)
    }

    /**
     * 读取系统当前 locale（不受本应用覆盖影响）。
     *
     * @param context 任意 context
     * @return 系统首选 locale；取不到时回退 [Locale.getDefault]
     */
    private fun systemLocale(context: Context): Locale =
        context.resources.configuration.locales.get(0) ?: Locale.getDefault()
}
