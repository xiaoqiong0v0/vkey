package dev.xiaoqiong.vkey.update

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.core.content.FileProvider
import java.io.File

/**
 * APK 安装入口：FileProvider 暴露缓存文件，交给系统安装器。
 *
 * Android 8+ 安装未知来源应用需要用户显式授权，未授权时先引导到系统设置。
 */
object UpdateInstaller {

    /** FileProvider authority，与 Manifest 里的 `${applicationId}.updates` 一致。 */
    private fun authority(context: Context): String = "${context.packageName}.updates"

    /** 当前是否已允许本应用安装未知来源应用（API 26+ 恒可调用）。 */
    fun canRequestPackageInstall(context: Context): Boolean =
        context.packageManager.canRequestPackageInstalls()

    /**
     * 打开「安装未知应用」授权页（针对本应用）。
     *
     * @param context 任意 Context（内部会加 NEW_TASK）
     */
    fun openUnknownSourcesSettings(context: Context) {
        val intent = Intent(
            Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
            Uri.parse("package:${context.packageName}"),
        ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(intent)
    }

    /**
     * 拉起系统安装器。
     *
     * @param context 任意 Context（内部会加 NEW_TASK）
     * @param apk 已通过 SHA-256 与签名校验的 APK
     * @throws android.content.ActivityNotFoundException 系统没有可处理的应用
     */
    fun install(context: Context, apk: File) {
        val uri = FileProvider.getUriForFile(context, authority(context), apk)
        val intent = Intent(Intent.ACTION_VIEW)
            .setDataAndType(uri, APK_MIME_TYPE)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(intent)
    }

    /** APK 的 MIME 类型。 */
    private const val APK_MIME_TYPE = "application/vnd.android.package-archive"
}
