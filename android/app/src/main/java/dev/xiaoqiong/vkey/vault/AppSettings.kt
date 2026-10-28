package dev.xiaoqiong.vkey.vault

import android.content.Context

/**
 * 应用设置（SharedPreferences 持久化）。
 *
 * 目前只有两项：回前台是否重新解锁、同步服务地址。后者在 M3.2 接入同步后才会真正使用。
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

    private companion object {
        const val KEY_AUTO_LOCK = "auto_lock_on_resume"
        const val KEY_SERVER_URL = "server_url"
        const val DEFAULT_SERVER_URL = "https://vkey.xiaoqiong0v0.cn"
    }
}
