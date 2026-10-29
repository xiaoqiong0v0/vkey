package dev.xiaoqiong.vkey.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import dev.xiaoqiong.vkey.R
import dev.xiaoqiong.vkey.net.UpdateInfo
import java.util.Locale

/** 发布说明滚动区的最大高度（超出后内部滚动，避免弹窗撑满屏幕）。 */
private val NOTES_MAX_HEIGHT = 200.dp

/** 字节 → MB 展示精度：保留一位小数。 */
private const val MB_FORMAT = "%.1f"

/**
 * 主页顶部的更新提示条（不打断操作，可关闭）。
 *
 * @param versionName 新版本号（如 `0.3.2`）
 * @param onView 点击「查看」打开更新对话框
 * @param onDismiss 关闭提示条（仅本次会话隐藏）
 */
@Composable
fun UpdateBanner(versionName: String, onView: () -> Unit, onDismiss: () -> Unit) {
    Surface(
        color = MaterialTheme.colorScheme.primaryContainer,
        contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 16.dp, end = 4.dp, top = 4.dp, bottom = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(R.string.update_banner_title, versionName),
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = onView) {
                Text(stringResource(R.string.action_view))
            }
            IconButton(onClick = onDismiss) {
                Icon(
                    imageVector = Icons.Filled.Close,
                    contentDescription = stringResource(R.string.action_close),
                )
            }
        }
    }
}

/**
 * 更新对话框：版本号 / 大小 / 发布说明 / 当前版本，下载进度与校验错误就地展示。
 *
 * @param info 服务端下发的更新信息
 * @param currentVersion 已格式化的当前版本（如 `当前版本 0.3.1 (30100)`）
 * @param progress 下载进度 0f..1f；null 表示不在下载中
 * @param error 下载/校验/安装错误文案；null 表示无错误
 * @param onDownload 点击「下载并安装」
 * @param onCancelDownload 取消下载
 * @param onDismiss 关闭对话框（下载中不可关闭）
 */
@Composable
fun UpdateDialog(
    info: UpdateInfo,
    currentVersion: String,
    progress: Float?,
    error: String?,
    onDownload: () -> Unit,
    onCancelDownload: () -> Unit,
    onDismiss: () -> Unit,
) {
    val downloading = progress != null
    AlertDialog(
        onDismissRequest = { if (!downloading) onDismiss() },
        properties = DialogProperties(
            dismissOnBackPress = !downloading,
            dismissOnClickOutside = !downloading,
        ),
        title = { Text(stringResource(R.string.update_dialog_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(
                    text = stringResource(R.string.update_dialog_version, info.versionName),
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    text = currentVersion,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (info.size > 0L) {
                    Text(
                        text = stringResource(R.string.update_dialog_size, formatMegabytes(info.size)),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Spacer(Modifier.height(4.dp))
                Text(
                    text = stringResource(R.string.update_dialog_notes),
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                )
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = NOTES_MAX_HEIGHT)
                        .verticalScroll(rememberScrollState()),
                ) {
                    Text(
                        text = info.notes.ifBlank { stringResource(R.string.update_dialog_notes_empty) },
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                error?.let {
                    Text(
                        text = it,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
                if (progress != null) {
                    Spacer(Modifier.height(4.dp))
                    LinearProgressIndicator(
                        progress = { progress.coerceIn(0f, 1f) },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Text(
                        text = stringResource(
                            R.string.update_downloading,
                            (progress.coerceIn(0f, 1f) * 100).toInt(),
                        ),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        },
        confirmButton = {
            if (downloading) {
                TextButton(onClick = onCancelDownload) {
                    Text(stringResource(R.string.action_cancel_download))
                }
            } else {
                Button(onClick = onDownload) {
                    Text(stringResource(R.string.action_download_install))
                }
            }
        },
        dismissButton = {
            if (!downloading) {
                TextButton(onClick = onDismiss) {
                    Text(stringResource(R.string.action_later))
                }
            }
        },
    )
}

/** 字节数 → MB（保留一位小数，如 `32.9`）。 */
private fun formatMegabytes(bytes: Long): String =
    String.format(Locale.US, MB_FORMAT, bytes / (1024.0 * 1024.0))
