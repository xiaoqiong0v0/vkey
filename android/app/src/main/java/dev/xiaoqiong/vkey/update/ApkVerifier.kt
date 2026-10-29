package dev.xiaoqiong.vkey.update

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File

/**
 * APK 签名证书校验：只允许与 [UpdateVerifier.TRUSTED_CERT_SHA256] 一致的包被安装。
 *
 * 用 [PackageManager.getPackageArchiveInfo] 解析**下载下来的文件**（不安装），
 * 取签名证书原始字节算 SHA-256。Android 9（API 28）起用
 * `GET_SIGNING_CERTIFICATES`，更早版本退化为已废弃的 `GET_SIGNATURES`。
 */
object ApkVerifier {

    /**
     * 判断 APK 是否由受信任证书签名。
     *
     * @param context 用于访问 PackageManager
     * @param apk 已下载的 APK 文件
     * @return 任一会话签名证书指纹匹配时返回 true；无法解析/无签名/不匹配返回 false
     */
    fun hasTrustedSignature(context: Context, apk: File): Boolean {
        val certificates = signatureCertificates(context, apk)
        return certificates.any {
            UpdateVerifier.sha256Hex(it).equals(UpdateVerifier.TRUSTED_CERT_SHA256, ignoreCase = true)
        }
    }

    /** 提取 APK 的签名证书原始字节；无法解析时返回空列表。 */
    private fun signatureCertificates(context: Context, apk: File): List<ByteArray> {
        val pm = context.packageManager
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = pm.getPackageArchiveInfo(apk.absolutePath, PackageManager.GET_SIGNING_CERTIFICATES)
            info?.signingInfo?.apkContentsSigners?.map { it.toByteArray() }.orEmpty()
        } else {
            @Suppress("DEPRECATION")
            val info = pm.getPackageArchiveInfo(apk.absolutePath, PackageManager.GET_SIGNATURES)
            @Suppress("DEPRECATION")
            info?.signatures?.map { it.toByteArray() }.orEmpty()
        }
    }
}
