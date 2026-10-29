package dev.xiaoqiong.vkey.ui

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.RoundRect
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathFillType
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import dev.xiaoqiong.vkey.R
import dev.xiaoqiong.vkey.sync.EnrollTarget
import dev.xiaoqiong.vkey.sync.Links
import dev.xiaoqiong.vkey.sync.ScanLink
import dev.xiaoqiong.vkey.ui.theme.CameraBackground
import dev.xiaoqiong.vkey.ui.theme.CameraOverlayButton
import dev.xiaoqiong.vkey.ui.theme.CameraOverlayButtonSubtle
import dev.xiaoqiong.vkey.ui.theme.CameraOverlayContent
import dev.xiaoqiong.vkey.ui.theme.CameraOverlayContentMuted
import dev.xiaoqiong.vkey.ui.theme.CameraOverlayError
import dev.xiaoqiong.vkey.ui.theme.CameraScrim
import dev.xiaoqiong.vkey.vault.Otpauth
import dev.xiaoqiong.vkey.vault.OtpauthEntry
import dev.xiaoqiong.vkey.vault.TotpItem
import java.util.concurrent.Executors

/** 取景框边长（屏幕短边的 68%，并夹在 200–320dp 之间）。 */
private const val FRAME_RATIO = 0.68f
private val FRAME_MIN = 200.dp
private val FRAME_MAX = 320.dp

/**
 * 扫码页的使用场景：决定标题 / 提示文案、以及**接受哪类二维码**。
 *
 * 同一张二维码的「类别识别」与 mode 无关（[classifyScan] 只跑一次），
 * mode 只决定「这类内容在当前入口是否被接受」：类别不符时不回调、
 * 停留在扫码页并给出该 mode 对应的错误提示，绝不越权处理。
 */
enum class ScanMode {
    /** 设置 → 服务端地址行 / 编辑对话框：只接受 `http(s)://…` 或 `vkey://config?server=…`。 */
    CONFIG_LINK,

    /** 设置 → 「用开户码接入」卡片：接受 `ENROLL-XXXX-XXXX`、`vkey://enroll?…` 与 `/join?c=…`。 */
    ENROLL,

    /** 配对码相关入口：接受配对码（深链或裸码），也接受服务端 /pair 页的地址码。 */
    PAIR,

    /** 主页 FAB：只接受 `otpauth://`。 */
    TOTP,

    /** 兼容路径：接受全部类型（回调未提供时按旧语义提示「换个页面」）。 */
    AUTO,
}

/**
 * 扫一扫：相机铺满全屏，中间镂空取景框。
 *
 * 按 [mode] 区分语义（标题 / 提示 / 错误文案 / 接受的码类型），
 * 识别结果分发到对应回调：TOTP 条目（[onResult]）、服务器地址
 * （[onConfigLink]）、配对码（[onPairCode]）、开户码（[onEnrollCode]）。
 *
 * 回调都可为 null；AUTO 模式下「识别成功但没有对应回调」提示换页面使用，
 * 其余模式下「类别与 mode 不符」直接提示「这不是 XXX」。
 *
 * @param mode 本入口的扫码语义，见 [ScanMode]
 * @param onResult 解析出的 TOTP 条目（null 表示本次扫码不是用来加 TOTP）
 * @param onConfigLink 识别到同步配置深链 / 服务器地址，参数为服务器地址
 * @param onPairCode 识别到配对码（深链或裸码），参数为原文
 * @param onEnrollCode 识别到开户码，参数含规范化代码与（深链 / `/join` 链接才有的）服务端地址、用户名
 * @param onCancel 用户取消
 */
@Composable
fun ScanScreen(
    mode: ScanMode = ScanMode.AUTO,
    onResult: ((TotpItem) -> Unit)? = null,
    onConfigLink: ((String) -> Unit)? = null,
    onPairCode: ((String) -> Unit)? = null,
    onEnrollCode: ((EnrollTarget) -> Unit)? = null,
    onCancel: () -> Unit,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val configuration = LocalConfiguration.current
    val density = LocalDensity.current

    // 系统返回键：关闭扫码页，而不是退出应用
    BackHandler { onCancel() }

    var hasPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED,
        )
    }
    var error by remember { mutableStateOf<String?>(null) }
    var showPaste by remember { mutableStateOf(false) }

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        hasPermission = granted
        if (!granted) error = context.getString(R.string.scan_err_permission)
    }

    LaunchedEffect(Unit) {
        if (!hasPermission) permissionLauncher.launch(Manifest.permission.CAMERA)
    }

    // 相册选图：对静态图片跑一次识别（截图里的二维码也能用）
    val pickImage = rememberLauncherForActivityResult(
        ActivityResultContracts.PickVisualMedia(),
    ) { uri: android.net.Uri? ->
        if (uri != null) {
            runCatching {
                val image = InputImage.fromFilePath(context, uri)
                BarcodeScanning.getClient(
                    BarcodeScannerOptions.Builder()
                        .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
                        .build(),
                ).process(image).addOnSuccessListener { barcodes ->
                    val raw = barcodes.firstOrNull()?.rawValue
                    if (raw == null) {
                        error = context.getString(R.string.scan_err_no_qr_in_image)
                    } else {
                        dispatchRaw(context, raw, mode, onResult, onConfigLink, onPairCode, onEnrollCode) { error = it }
                    }
                }.addOnFailureListener { e ->
                    error = context.getString(R.string.scan_err_image_decode, e.message.orEmpty())
                }
            }.onFailure { error = context.getString(R.string.scan_err_image_read, it.message.orEmpty()) }
        }
    }

    // 取景框边长：按屏幕短边比例计算，并夹在合理范围
    val frameSize = remember(configuration.screenWidthDp, configuration.screenHeightDp) {
        val shortSide = minOf(configuration.screenWidthDp, configuration.screenHeightDp)
        with(density) {
            (shortSide * FRAME_RATIO).dp.coerceIn(FRAME_MIN, FRAME_MAX)
        }
    }

    Box(Modifier.fillMaxSize().background(CameraBackground)) {
        if (!hasPermission) {
            Column(
                modifier = Modifier.fillMaxSize().padding(24.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    error ?: stringResource(R.string.scan_waiting_permission),
                    color = CameraOverlayContent,
                    style = MaterialTheme.typography.bodyMedium,
                    textAlign = TextAlign.Center,
                )
                Button(
                    onClick = onCancel,
                    modifier = Modifier.padding(top = 16.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = CameraOverlayButton,
                        contentColor = CameraOverlayContent,
                    ),
                ) { Text(stringResource(R.string.action_back)) }
            }
            return@Box
        }

        val scanner = remember {
            BarcodeScanning.getClient(
                BarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build(),
            )
        }
        val executor = remember { Executors.newSingleThreadExecutor() }
        var handled by remember { mutableStateOf(false) }

        DisposableEffect(Unit) {
            onDispose {
                scanner.close()
                executor.shutdown()
            }
        }

        // 相机预览铺满
        AndroidView(
            modifier = Modifier.fillMaxSize(),
            factory = { ctx ->
                val previewView = PreviewView(ctx)
                val providerFuture = ProcessCameraProvider.getInstance(ctx)
                providerFuture.addListener({
                    val provider = providerFuture.get()
                    val preview = Preview.Builder().build().also {
                        it.setSurfaceProvider(previewView.surfaceProvider)
                    }
                    val analysis = ImageAnalysis.Builder()
                        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                        // 提高分辨率：默认 640x480 对小二维码/远距离检出率偏低
                        .setTargetResolution(android.util.Size(1280, 720))
                        .build()
                    analysis.setAnalyzer(executor) { proxy: ImageProxy ->
                        // 任何异常都必须 close，否则 KEEP_ONLY_LATEST 会把后续帧全部丢弃，表现为"永远识别不到"
                        try {
                            processProxy(proxy, scanner) { raw ->
                                android.util.Log.i("vkey-scan", "barcode raw=${raw.take(32)}")
                                if (!handled) {
                                    val consumed = dispatchRaw(
                                        context,
                                        raw,
                                        mode,
                                        onResult,
                                        onConfigLink,
                                        onPairCode,
                                        onEnrollCode,
                                    ) { error = it }
                                    if (consumed) handled = true
                                }
                            }
                        } catch (t: Throwable) {
                            android.util.Log.e("vkey-scan", "analyze failed: ${t.message}", t)
                            proxy.close()
                        }
                    }
                    provider.unbindAll()
                    try {
                        provider.bindToLifecycle(
                            lifecycleOwner,
                            CameraSelector.DEFAULT_BACK_CAMERA,
                            preview,
                            analysis,
                        )
                        android.util.Log.i("vkey-scan", "camera bound: preview+analysis")
                    } catch (t: Throwable) {
                        android.util.Log.e("vkey-scan", "camera bind failed: ${t.message}", t)
                        error = context.getString(R.string.scan_err_camera_start, t.message.orEmpty())
                    }
                }, ContextCompat.getMainExecutor(ctx))
                previewView
            },
        )

        // 半透明遮罩：用 EvenOdd 路径一次性画出「带圆角镂空」的整块遮罩。
        // 这样镂空四角也是圆角，不会出现「外侧方正、内侧圆角」的缝隙；纯绘制，不涉及裁剪图层。
        Canvas(Modifier.fillMaxSize()) {
            val frame = frameSize.toPx()
            val left = (size.width - frame) / 2f
            val top = (size.height - frame) / 2f
            val corner = 20.dp.toPx()
            val hole = RoundRect(
                rect = Rect(left, top, left + frame, top + frame),
                cornerRadius = CornerRadius(corner, corner),
            )
            val path = Path().apply {
                fillType = PathFillType.EvenOdd
                addRect(Rect(0f, 0f, size.width, size.height))
                addRoundRect(hole)
            }
            drawPath(path, CameraScrim)
        }

        // 取景框：圆角白边 + 四角高亮
        Box(
            modifier = Modifier
                .align(Alignment.Center)
                .size(frameSize)
                .border(2.dp, CameraOverlayContentMuted, RoundedCornerShape(20.dp)),
        )

        Column(
            modifier = Modifier
                .align(Alignment.TopCenter)
                .padding(top = 48.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                text = stringResource(scanTitleRes(mode)),
                color = CameraOverlayContent,
                style = MaterialTheme.typography.titleMedium,
            )

        }

        Column(
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .fillMaxWidth()
                .padding(horizontal = 24.dp, vertical = 40.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                text = error ?: stringResource(scanHintRes(mode)),
                color = if (error != null) CameraOverlayError else CameraOverlayContentMuted,
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
            )
            Button(
                onClick = { pickImage.launch(androidx.activity.result.PickVisualMediaRequest(androidx.activity.result.contract.ActivityResultContracts.PickVisualMedia.ImageOnly)) },
                modifier = Modifier.padding(top = 16.dp).fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = CameraOverlayButton,
                    contentColor = CameraOverlayContent,
                ),
            ) { Text(stringResource(R.string.scan_pick_from_album)) }
            Row(
                modifier = Modifier.padding(top = 8.dp).fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Button(
                    onClick = { showPaste = true },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = CameraOverlayButtonSubtle,
                        contentColor = CameraOverlayContent,
                    ),
                ) { Text(stringResource(R.string.scan_paste_link)) }
                Button(
                    onClick = onCancel,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = CameraOverlayButtonSubtle,
                        contentColor = CameraOverlayContent,
                    ),
                ) { Text(stringResource(R.string.action_cancel)) }
            }
        }

        // 相机预览之上再画一次遮罩会挡住相机；此处不加额外层
    }

    if (showPaste) {
        var text by remember { mutableStateOf("") }
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { showPaste = false },
            title = { Text(stringResource(scanPasteTitleRes(mode))) },
            text = {
                androidx.compose.foundation.layout.Column {
                    Text(
                        text = stringResource(scanPasteHintRes(mode)),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodySmall,
                    )
                    androidx.compose.material3.OutlinedTextField(
                        value = text,
                        onValueChange = { text = it },
                        singleLine = false,
                        modifier = Modifier.padding(top = 8.dp).fillMaxWidth(),
                    )
                }
            },
            confirmButton = {
                androidx.compose.material3.TextButton(onClick = {
                    showPaste = false
                    dispatchRaw(context, text, mode, onResult, onConfigLink, onPairCode, onEnrollCode) { error = it }
                }) { Text(stringResource(R.string.action_recognize)) }
            },
            dismissButton = {
                androidx.compose.material3.TextButton(onClick = { showPaste = false }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }
}

/** 扫码内容的类别（与 [ScanMode] 无关，同一原文永远落在同一类）。 */
internal enum class ScanKind { SERVER_ADDRESS, PAIR_CODE, ENROLL_CODE, TOTP }

/** 一段扫码/粘贴文本被识别出的内容。 */
internal sealed interface ScanContent {
    /** 本类别，供 [ScanMode] 判定是否接受。 */
    val kind: ScanKind

    /** 服务器地址：`vkey://config?server=…` 深链，或裸 `http(s)://…`。 */
    data class ServerAddress(val url: String) : ScanContent {
        override val kind: ScanKind get() = ScanKind.SERVER_ADDRESS
    }

    /** 配对码：`vkey://pair?code=…` 深链或裸 52 位 base32。 */
    data class PairCode(val code: String) : ScanContent {
        override val kind: ScanKind get() = ScanKind.PAIR_CODE
    }

    /** 开户码 `ENROLL-XXXX-XXXX`（已规范化）；深链 / `/join` 链接还带服务端地址与用户名。 */
    data class EnrollCode(
        val code: String,
        val serverUrl: String? = null,
        val username: String? = null,
    ) : ScanContent {
        override val kind: ScanKind get() = ScanKind.ENROLL_CODE
    }

    /** `otpauth://` 解析出的 TOTP 条目。 */
    data class Totp(val entry: OtpauthEntry) : ScanContent {
        override val kind: ScanKind get() = ScanKind.TOTP
    }
}

/** 「不接受」的原因分类；由 UI 层映射成场景文案。 */
internal enum class ScanReject {
    EMPTY,
    NOT_SERVER_ADDRESS,
    NOT_ENROLL_CODE,
    NOT_PAIR_CODE,
    NOT_TOTP,
    UNRECOGNIZED,
}

/** [dispatchScan] 的结果：接受（带内容）或拒绝（带原因）。 */
internal sealed interface ScanOutcome {
    data class Accepted(val content: ScanContent) : ScanOutcome
    data class Rejected(val reason: ScanReject) : ScanOutcome
}

/**
 * 识别一段扫码/粘贴文本的类别（不做 mode 过滤，也不依赖 Android 环境）。
 *
 * 顺序：同步配置深链 → 配对码深链 → 开户码（`vkey://enroll` 深链 → `/join?c=` 链接 → 裸码）
 * → 裸配对码 → `otpauth://` → 裸 `http(s)://` 地址。
 * 开户码在裸配对码之前；`otpauth://` 在裸地址判定之前（`otpauth:` 不是 http(s) scheme，
 * 顺序只是短路优化，不影响结论）。
 *
 * @param raw 扫码或粘贴的原文
 * @return 识别结果；都不匹配时返回 null
 */
internal fun classifyScan(raw: String): ScanContent? {
    when (val link = Links.classify(raw)) {
        is ScanLink.ServerConfig -> return ScanContent.ServerAddress(link.serverUrl)
        is ScanLink.PairCode -> return ScanContent.PairCode(link.code)
        is ScanLink.EnrollCode -> return ScanContent.EnrollCode(link.code, link.serverUrl, link.username)
        null -> Unit
    }
    Otpauth.parse(raw)?.let { return ScanContent.Totp(it) }
    // 服务端主页 / pair 页的二维码就是裸 http(s) 地址；这里补上（Links.classify 不含此规则）
    val text = raw.trim()
    if (isValidServerUrl(text)) return ScanContent.ServerAddress(text)
    return null
}

/**
 * 按 [mode] 判定这段文本是否「在该入口被接受」（纯函数，便于单测）。
 *
 * - 空文本一律 [ScanReject.EMPTY]；
 * - 未识别、或识别成功但类别与 mode 不符 → 返回该 mode 的专属错误
 *   （例如 ENROLL 模式下扫地址码报「这不是开户码」，绝不越权回调）；
 * - AUTO 接受全部类别。
 *
 * @param raw 扫码或粘贴的原文
 * @param mode 本入口的扫码语义
 * @return [ScanOutcome.Accepted]（附识别内容）或 [ScanOutcome.Rejected]（附错误分类）
 */
internal fun dispatchScan(raw: String, mode: ScanMode): ScanOutcome {
    if (raw.isBlank()) return ScanOutcome.Rejected(ScanReject.EMPTY)
    val content = classifyScan(raw)
    val accepted = content != null && when (mode) {
        ScanMode.CONFIG_LINK -> content.kind == ScanKind.SERVER_ADDRESS
        ScanMode.ENROLL -> content.kind == ScanKind.ENROLL_CODE
        ScanMode.PAIR -> content.kind == ScanKind.PAIR_CODE || content.kind == ScanKind.SERVER_ADDRESS
        ScanMode.TOTP -> content.kind == ScanKind.TOTP
        ScanMode.AUTO -> true
    }
    if (content == null || !accepted) {
        return ScanOutcome.Rejected(
            when (mode) {
                ScanMode.CONFIG_LINK -> ScanReject.NOT_SERVER_ADDRESS
                ScanMode.ENROLL -> ScanReject.NOT_ENROLL_CODE
                ScanMode.PAIR -> ScanReject.NOT_PAIR_CODE
                ScanMode.TOTP -> ScanReject.NOT_TOTP
                ScanMode.AUTO -> ScanReject.UNRECOGNIZED
            },
        )
    }
    return ScanOutcome.Accepted(content)
}

/** mode → 扫码页标题文案。 */
private fun scanTitleRes(mode: ScanMode): Int = when (mode) {
    ScanMode.CONFIG_LINK -> R.string.scan_title_server
    ScanMode.ENROLL -> R.string.scan_title_enroll
    ScanMode.PAIR -> R.string.scan_title_pair
    ScanMode.TOTP -> R.string.scan_title_totp
    ScanMode.AUTO -> R.string.scan_title_auto
}

/** mode → 扫码页底部提示文案。 */
private fun scanHintRes(mode: ScanMode): Int = when (mode) {
    ScanMode.CONFIG_LINK -> R.string.scan_hint_server
    ScanMode.ENROLL -> R.string.scan_hint_enroll
    ScanMode.PAIR -> R.string.scan_hint_pair
    ScanMode.TOTP -> R.string.scan_hint_totp
    ScanMode.AUTO -> R.string.scan_hint_auto
}

/** mode → 「粘贴链接」弹窗标题。 */
private fun scanPasteTitleRes(mode: ScanMode): Int = when (mode) {
    ScanMode.TOTP -> R.string.scan_dialog_paste_otpauth_title
    ScanMode.ENROLL -> R.string.scan_dialog_paste_enroll_title
    else -> R.string.scan_dialog_paste_config_title
}

/** mode → 「粘贴链接」弹窗内提示（应贴什么格式）。 */
private fun scanPasteHintRes(mode: ScanMode): Int = when (mode) {
    ScanMode.TOTP -> R.string.scan_paste_otpauth_hint
    ScanMode.CONFIG_LINK -> R.string.scan_paste_server_hint
    ScanMode.ENROLL -> R.string.scan_paste_enroll_hint
    ScanMode.PAIR -> R.string.scan_paste_pair_hint
    ScanMode.AUTO -> R.string.scan_paste_config_hint
}

/** [ScanReject] → 场景文案。 */
private fun scanErrRes(reason: ScanReject): Int = when (reason) {
    ScanReject.EMPTY -> R.string.scan_err_empty
    ScanReject.NOT_SERVER_ADDRESS -> R.string.scan_err_not_server_qr
    ScanReject.NOT_ENROLL_CODE -> R.string.scan_err_not_enroll_code
    ScanReject.NOT_PAIR_CODE -> R.string.scan_err_not_pair_code
    ScanReject.NOT_TOTP -> R.string.scan_err_not_2fa_qr
    ScanReject.UNRECOGNIZED -> R.string.scan_err_unrecognized
}

/**
 * 把一段扫码/粘贴文本按 [mode] 分发给对应流程（[dispatchScan] 的 Context 薄壳）。
 *
 * 接受 → 调对应回调并返回 true；回调缺失（AUTO 兼容路径）→ 提示「换个页面使用」。
 * 拒绝 → 给出该 mode 的错误文案并返回 false（停留在扫码页）。
 *
 * @param raw 扫码或粘贴的原文
 * @param mode 本入口的扫码语义
 * @param onResult TOTP 回调（可为 null）
 * @param onConfigLink 服务器地址回调（可为 null）
 * @param onPairCode 配对码回调（可为 null）
 * @param onEnrollCode 开户码回调（可为 null）
 * @param onError 无法消费时的提示
 * @return true 表示已被某个流程消费
 */
private fun dispatchRaw(
    context: Context,
    raw: String,
    mode: ScanMode,
    onResult: ((TotpItem) -> Unit)?,
    onConfigLink: ((String) -> Unit)?,
    onPairCode: ((String) -> Unit)?,
    onEnrollCode: ((EnrollTarget) -> Unit)?,
    onError: (String) -> Unit,
): Boolean {
    when (val outcome = dispatchScan(raw, mode)) {
        is ScanOutcome.Rejected -> {
            onError(context.getString(scanErrRes(outcome.reason)))
            return false
        }
        is ScanOutcome.Accepted -> when (val content = outcome.content) {
            is ScanContent.ServerAddress -> {
                val callback = onConfigLink
                if (callback == null) {
                    onError(context.getString(R.string.scan_err_config_qr_wrong_page))
                    return false
                }
                callback(content.url)
                return true
            }
            is ScanContent.PairCode -> {
                val callback = onPairCode
                if (callback == null) {
                    onError(context.getString(R.string.scan_err_pair_code_wrong_page))
                    return false
                }
                callback(content.code)
                return true
            }
            is ScanContent.EnrollCode -> {
                val callback = onEnrollCode
                if (callback == null) {
                    onError(context.getString(R.string.scan_err_enroll_code_wrong_page))
                    return false
                }
                callback(EnrollTarget(content.code, content.serverUrl, content.username))
                return true
            }
            is ScanContent.Totp -> {
                val callback = onResult
                if (callback == null) {
                    onError(context.getString(R.string.scan_err_totp_wrong_page))
                    return false
                }
                callback(content.entry.item)
                return true
            }
        }
    }
}

/** 把一帧交给 ML Kit 识别，识别结束务必 close，否则分析器会被卡住。 */
private var frameCounter = 0

private fun processProxy(
    proxy: ImageProxy,
    scanner: com.google.mlkit.vision.barcode.BarcodeScanner,
    onRaw: (String) -> Unit,
) {
    val mediaImage = proxy.image
    if (mediaImage == null) {
        proxy.close()
        return
    }
    frameCounter++
    if (frameCounter == 1 || frameCounter % 30 == 0) {
        android.util.Log.i(
            "vkey-scan",
            "frame #$frameCounter ${proxy.width}x${proxy.height} fmt=${proxy.format} rot=${proxy.imageInfo.rotationDegrees}",
        )
    }
    val image = InputImage.fromMediaImage(mediaImage, proxy.imageInfo.rotationDegrees)
    scanner.process(image)
        .addOnSuccessListener { barcodes ->
            barcodes.firstOrNull()?.rawValue?.let(onRaw)
        }
        .addOnFailureListener { e ->
            android.util.Log.w("vkey-scan", "mlkit failed: ${e.message}")
        }
        .addOnCompleteListener { proxy.close() }
}
