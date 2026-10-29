package dev.xiaoqiong.vkey.ui

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import dev.xiaoqiong.vkey.R
import dev.xiaoqiong.vkey.vault.AppSettings

/** 项目主页地址（点击用浏览器打开）。 */

/** 项目源码地址（点击用浏览器打开）。 */
private const val ABOUT_REPOSITORY_URL = "https://github.com/xiaoqiong0v0/vkey"

/** 关于页声明读取的资产文件名（仓库根 LICENSE 若打进 assets 才会显示）。 */
private const val ABOUT_LICENSE_ASSET = "LICENSE"

/**
 * 关于页：应用图标 / 名称 / 版本 + 包名、服务端、开源许可 + 外链。
 *
 * 版本号取自 PackageManager（不硬编码），随 `versionName` / `versionCode` 自动变化。
 *
 * @param onClose 返回设置页（系统返回键与左上角「返回」同义）
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AboutScreen(onClose: () -> Unit) {
    val context = LocalContext.current
    // 系统返回键：回到设置页，而不是退出应用
    BackHandler { onClose() }

    val version = remember(context) { appVersion(context) }
    val serverUrl = remember(context) { AppSettings(context).serverUrl.trim() }
    val license = remember(context) { readLicenseFirstLine(context) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.about_title)) },
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
            // ---------------- 应用标识 ----------------
            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Image(
                    painter = painterResource(R.mipmap.ic_launcher),
                    contentDescription = stringResource(R.string.app_name),
                    modifier = Modifier.size(72.dp),
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    stringResource(R.string.app_name),
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Medium,
                )
                Text(
                    stringResource(R.string.about_version, version.first, version.second),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            // ---------------- 信息 ----------------
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    InfoRow(
                        label = stringResource(R.string.about_label_package),
                        value = context.packageName,
                    )
                    InfoRow(
                        label = stringResource(R.string.about_label_server),
                        value = serverUrl.ifBlank { stringResource(R.string.about_server_unset) },
                    )
                    InfoRow(
                        label = stringResource(R.string.about_label_license),
                        value = license ?: stringResource(R.string.about_license_missing),
                    )
                }
            }

            // ---------------- 外链 ----------------
            Card(Modifier.fillMaxWidth()) {
                Column {
                    LinkRow(
                        label = stringResource(R.string.about_link_repo),
                        url = ABOUT_REPOSITORY_URL,
                    )
                }
            }

            Text(
                stringResource(R.string.about_footer),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
            )
        }
    }
}

/** 信息行：左标签、右取值（取值可换行）。 */
@Composable
private fun InfoRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(16.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.End,
            modifier = Modifier.weight(1f),
        )
    }
}

/** 外链行：整行可点，右侧箭头；打开失败静默（例如无浏览器）。 */
@Composable
private fun LinkRow(label: String, url: String) {
    val context = LocalContext.current
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { openUrl(context, url) }
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.bodyLarge)
            Text(
                text = url,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Icon(
            imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/**
 * 用浏览器打开链接；没有可处理的应用时静默忽略。
 *
 * @param context 用于启动 Activity
 * @param url 目标地址（http/https）
 */
private fun openUrl(context: Context, url: String) {
    runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
}

/**
 * 读取应用版本名与版本号（来自构建产物，不硬编码）。
 *
 * @param context 用于访问 PackageManager
 * @return 版本名（如 `0.3.1`）与版本号（如 `30100`）
 */
private fun appVersion(context: Context): Pair<String, Long> {
    val pm = context.packageManager
    val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        pm.getPackageInfo(context.packageName, PackageManager.PackageInfoFlags.of(0L))
    } else {
        @Suppress("DEPRECATION")
        pm.getPackageInfo(context.packageName, 0)
    }
    val name = info.versionName.orEmpty()
    val code = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        info.longVersionCode
    } else {
        @Suppress("DEPRECATION")
        info.versionCode.toLong()
    }
    return name to code
}

/**
 * 读取许可声明：取 assets 内 [ABOUT_LICENSE_ASSET] 的第一个非空行。
 *
 * Apache-2.0 文本首行是空行、第二行才是 "Apache License"，因此不能只取 `readLine()`。
 * 命中 Apache 家族时统一显示为 "Apache License 2.0"（用户可读的短名）。
 *
 * @param context 用于打开 assets
 * @return 许可短名；资产缺失或为空时返回 null（由调用方显示「未声明」）
 */
private fun readLicenseFirstLine(context: Context): String? = runCatching {
    context.assets.open(ABOUT_LICENSE_ASSET).bufferedReader().useLines { lines ->
        lines.map { it.trim() }.firstOrNull { it.isNotEmpty() }
    }
}.getOrNull()?.let { line ->
    if (line.startsWith("Apache License", ignoreCase = true)) "Apache License 2.0" else line
}
