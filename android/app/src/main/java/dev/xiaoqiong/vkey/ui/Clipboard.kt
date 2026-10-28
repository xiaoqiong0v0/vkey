package dev.xiaoqiong.vkey.ui

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle

/** 敏感内容的剪贴板标签；[clearClipboard] 只清理自己写入的内容。 */
private const val SENSITIVE_LABEL = "vkey code"

/** 普通内容（服务器地址、配对码等不涉密文本）的剪贴板标签。 */
private const val PLAIN_LABEL = "vkey"

/**
 * 复制到剪贴板。
 *
 * @param context 上下文
 * @param text 待复制文本
 * @param sensitive 是否敏感（验证码 / 恢复码）；API 33+ 会标记为 sensitive，
 *   避免出现在剪贴板预览与系统智能建议里
 */
fun copyToClipboard(context: Context, text: String, sensitive: Boolean) {
    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    val clip = ClipData.newPlainText(if (sensitive) SENSITIVE_LABEL else PLAIN_LABEL, text)
    if (sensitive && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        clip.description.extras = PersistableBundle().apply {
            putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
        }
    }
    cm.setPrimaryClip(clip)
}

/**
 * 清空剪贴板（仅当当前内容仍是本应用写入的验证码时才清，避免误删用户其它复制）。
 *
 * @param context 上下文
 */
fun clearClipboard(context: Context) {
    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    if (cm.primaryClipDescription?.label?.toString() == SENSITIVE_LABEL) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            cm.clearPrimaryClip()
        }
    }
}
