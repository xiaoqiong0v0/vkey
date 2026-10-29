package dev.xiaoqiong.vkey.ui

import android.content.ContentResolver
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.xiaoqiong.vkey.R
import dev.xiaoqiong.vkey.vault.TotpItem
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException

/** 文件选择器的首选 MIME：otpauth 文本。 */
private const val IMPORT_MIME_TEXT = "text/plain"

/** 兜底 MIME：部分文件的 MIME 识别不出 text/plain（云盘导出的 .txt 常见）。 */
private const val IMPORT_MIME_ANY = "*/*"

/** 导入文件大小上限（1 MiB）：纯 otpauth 文本远小于此，超出即拒绝，避免读爆内存。 */
private const val MAX_IMPORT_BYTES = 1 shl 20

/** 预览最多展示多少条可导入条目（其余只显示数量）。 */
private const val PREVIEW_LIMIT = 20

/** 粘贴框最小行数（多行文本框观感）。 */
private const val PASTE_MIN_LINES = 6

/** 粘贴框最大行数（超出内部滚动）。 */
private const val PASTE_MAX_LINES = 12

/**
 * 导入 2FA 配置页：选文件 / 粘贴文本 → 解析预览 → 确认写入。
 *
 * 安全约定：内容只存在于本页的内存状态与库的加密文件中，**不写日志、不写缓存文件**；
 * 不额外要求生物识别（用户主动选文件 / 粘贴即视为授权）。
 *
 * @param existing 现有库条目（用于重复判定）
 * @param onImport 提交可导入条目；返回错误文案（null = 成功，已落盘）
 * @param onClose 关闭本页（系统返回键与左上角「返回」同义）
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ImportScreen(
    existing: List<TotpItem>,
    onImport: (List<TotpItem>) -> String?,
    onClose: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var text by remember { mutableStateOf("") }
    // 「粘贴文本」入口被点过才展开输入框（初始只显示两个来源按钮）
    var pasteVisible by remember { mutableStateOf(false) }
    var readingFile by remember { mutableStateOf(false) }
    var sourceError by remember { mutableStateOf<String?>(null) }
    var importError by remember { mutableStateOf<String?>(null) }

    BackHandler { onClose() }

    // 选择文件：用内容 URI 读取 UTF-8 文本，读完立即丢弃流，不落任何缓存文件
    val pickFile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            readingFile = true
            sourceError = null
            importError = null
            val outcome = withContext(Dispatchers.IO) {
                runCatching { readImportText(context.contentResolver, uri) }
            }
            readingFile = false
            outcome.onSuccess { loaded ->
                text = loaded
                pasteVisible = true
            }.onFailure { failure ->
                sourceError = if (failure is ImportTooLargeException) {
                    context.getString(R.string.import_file_too_large, MAX_IMPORT_BYTES / 1024)
                } else {
                    context.getString(R.string.import_file_read_failed, failure.message.orEmpty())
                }
            }
        }
    }

    val result = remember(text, existing) { parseOtpauthImport(text, existing) }
    val importable = result.items

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.import_title)) },
                navigationIcon = {
                    TextButton(onClick = onClose) { Text(stringResource(R.string.action_back)) }
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
            Text(
                text = stringResource(R.string.import_desc),
                style = MaterialTheme.typography.bodyMedium,
            )

            // ---------------- 来源：选择文件 / 粘贴文本 ----------------
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedButton(
                    onClick = { pickFile.launch(arrayOf(IMPORT_MIME_TEXT, IMPORT_MIME_ANY)) },
                    enabled = !readingFile,
                ) { Text(stringResource(R.string.import_source_file)) }
                OutlinedButton(
                    onClick = { pasteVisible = true },
                    enabled = !readingFile,
                ) { Text(stringResource(R.string.import_source_paste)) }
            }

            if (readingFile) {
                Text(
                    text = stringResource(R.string.import_reading_file),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            sourceError?.let { message ->
                Text(
                    text = message,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }

            if (pasteVisible) {
                OutlinedTextField(
                    value = text,
                    onValueChange = {
                        text = it
                        importError = null
                    },
                    label = { Text(stringResource(R.string.import_text_label)) },
                    placeholder = { Text(stringResource(R.string.import_text_placeholder)) },
                    minLines = PASTE_MIN_LINES,
                    maxLines = PASTE_MAX_LINES,
                    modifier = Modifier.fillMaxWidth(),
                )
            }

            // ---------------- 识别结果预览 ----------------
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (text.isBlank()) {
                        Text(
                            text = stringResource(R.string.import_empty_hint),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    } else {
                        Text(
                            text = stringResource(
                                R.string.import_stats,
                                result.recognized,
                                importable.size,
                                result.duplicates,
                                result.hotpSkipped,
                                result.invalid,
                            ),
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        if (importable.isEmpty()) {
                            Text(
                                text = stringResource(R.string.import_none_importable),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error,
                            )
                        } else {
                            importable.take(PREVIEW_LIMIT).forEach { item ->
                                Text(
                                    text = previewLine(item),
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace,
                                )
                            }
                            if (importable.size > PREVIEW_LIMIT) {
                                Text(
                                    text = stringResource(
                                        R.string.import_more_items,
                                        importable.size - PREVIEW_LIMIT,
                                    ),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                }
            }

            Text(
                text = stringResource(R.string.import_security_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            importError?.let { message ->
                Text(
                    text = message,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }

            Button(
                onClick = {
                    if (importable.isEmpty()) return@Button
                    importError = null
                    val error = onImport(importable)
                    if (error == null) {
                        Toast.makeText(
                            context,
                            context.getString(R.string.import_toast_done, importable.size),
                            Toast.LENGTH_SHORT,
                        ).show()
                        onClose()
                    } else {
                        importError = error
                    }
                },
                enabled = importable.isNotEmpty(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text(stringResource(R.string.import_action, importable.size)) }

            Spacer(Modifier.height(8.dp))
        }
    }
}

/** 预览行：`issuer · account`（issuer 为空时只显示账号）。 */
private fun previewLine(item: TotpItem): String =
    if (item.issuer.isBlank()) item.account else "${item.issuer} · ${item.account}"

/** 文件内容超过 [MAX_IMPORT_BYTES] 时抛出（与普通 IO 失败区分文案）。 */
private class ImportTooLargeException : IOException("import file exceeds size limit")

/**
 * 读取内容 URI 的 UTF-8 文本（最多 [MAX_IMPORT_BYTES]）。
 *
 * 只把字节读进内存，不写任何缓存 / 临时文件。
 *
 * @param resolver 内容解析器
 * @param uri 用户选择的文档 URI
 * @return 解码后的文本
 * @throws ImportTooLargeException 超过大小上限
 * @throws IOException 打不开或读取失败
 */
private fun readImportText(resolver: ContentResolver, uri: Uri): String {
    val stream = resolver.openInputStream(uri) ?: throw IOException("openInputStream returned null")
    return stream.use { input ->
        val buffer = ByteArray(MAX_IMPORT_BYTES + 1)
        var total = 0
        while (total < buffer.size) {
            val read = input.read(buffer, total, buffer.size - total)
            if (read < 0) break
            total += read
        }
        if (total > MAX_IMPORT_BYTES) throw ImportTooLargeException()
        String(buffer, 0, total, Charsets.UTF_8)
    }
}
