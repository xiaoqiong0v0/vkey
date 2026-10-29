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
import dev.xiaoqiong.vkey.vault.TotpItem
import java.util.concurrent.Executors

/** 取景框边长（屏幕短边的 68%，并夹在 200–320dp 之间）。 */
private const val FRAME_RATIO = 0.68f
private val FRAME_MIN = 200.dp
private val FRAME_MAX = 320.dp

/**
 * 扫一扫：相机铺满全屏，中间镂空取景框。
 *
 * 一份扫码 UI 服务两种用途：
 * - 添加 TOTP：识别 `otpauth://` 后通过 [onResult] 回条目；
 * - 同步配置：识别 `vkey://config?server=…`（[onConfigLink]）、
 *   `vkey://pair?code=…` 或裸配对码（[onPairCode]）。
 *
 * 三个回调都可为 null；未提供的类型会被判定为「内容不匹配」并给出提示。
 *
 * @param onResult 解析出的 TOTP 条目（null 表示本次扫码不是用来加 TOTP）
 * @param onConfigLink 识别到同步配置深链，参数为服务器地址
 * @param onPairCode 识别到配对码（深链或裸码），参数为原文
 * @param onEnrollCode 识别到开户码（`ENROLL-XXXX-XXXX`），参数为规范化原文
 * @param onCancel 用户取消
 */
@Composable
fun ScanScreen(
    onResult: ((TotpItem) -> Unit)? = null,
    onConfigLink: ((String) -> Unit)? = null,
    onPairCode: ((String) -> Unit)? = null,
    onEnrollCode: ((String) -> Unit)? = null,
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
                        dispatchRaw(context, raw, onResult, onConfigLink, onPairCode, onEnrollCode) { error = it }
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
                                    val consumed = dispatchRaw(context, raw, onResult, onConfigLink, onPairCode, onEnrollCode) {
                                    error = it
                                }
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
                text = if (onResult != null) {
                    stringResource(R.string.scan_title_totp)
                } else {
                    stringResource(R.string.scan_title_config)
                },
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
                text = error ?: if (onResult != null) {
                    stringResource(R.string.scan_hint_totp)
                } else {
                    stringResource(R.string.scan_hint_config)
                },
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
            title = {
                Text(
                    if (onResult != null) {
                        stringResource(R.string.scan_dialog_paste_otpauth_title)
                    } else {
                        stringResource(R.string.scan_dialog_paste_config_title)
                    },
                )
            },
            text = {
                androidx.compose.foundation.layout.Column {
                    Text(
                        text = if (onResult != null) {
                            stringResource(R.string.scan_paste_otpauth_hint)
                        } else {
                            stringResource(R.string.scan_paste_config_hint)
                        },
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
                    dispatchRaw(context, text, onResult, onConfigLink, onPairCode, onEnrollCode) { error = it }
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

/**
 * 把一段扫码/粘贴文本分发给对应流程。
 *
 * 顺序：同步配置深链 → 配对码（深链或裸码） → 开户码 → `otpauth://`。
 * 未提供对应回调时给出明确提示，而不是静默失败。
 *
 * @param raw 扫码或粘贴的原文
 * @param onResult TOTP 回调（可为 null）
 * @param onConfigLink 同步配置回调（可为 null）
 * @param onPairCode 配对码回调（可为 null）
 * @param onEnrollCode 开户码回调（可为 null）
 * @param onError 无法消费时的提示
 * @return true 表示已被某个流程消费
 */
private fun dispatchRaw(
    context: Context,
    raw: String,
    onResult: ((TotpItem) -> Unit)?,
    onConfigLink: ((String) -> Unit)?,
    onPairCode: ((String) -> Unit)?,
    onEnrollCode: ((String) -> Unit)?,
    onError: (String) -> Unit,
): Boolean {
    val text = raw.trim()
    if (text.isEmpty()) {
        onError(context.getString(R.string.scan_err_empty))
        return false
    }
    // 裸配对码只在「同步配置」场景启用，避免把 52 位 TOTP 密钥误判成配对码
    val link = if (onResult != null) {
        Links.parseServerConfig(text)?.let { ScanLink.ServerConfig(it) }
            ?: Links.parsePairCodeLink(text)?.let { ScanLink.PairCode(it) }
    } else {
        Links.classify(text)
    }
    when (link) {
        is ScanLink.ServerConfig -> {
            val callback = onConfigLink
            if (callback == null) {
                onError(context.getString(R.string.scan_err_config_qr_wrong_page))
                return false
            }
            callback(link.serverUrl)
            return true
        }
        is ScanLink.PairCode -> {
            val callback = onPairCode
            if (callback == null) {
                onError(context.getString(R.string.scan_err_pair_code_wrong_page))
                return false
            }
            callback(link.code)
            return true
        }
        is ScanLink.EnrollCode -> {
            val callback = onEnrollCode
            if (callback == null) {
                onError(context.getString(R.string.scan_err_enroll_code_wrong_page))
                return false
            }
            callback(link.code)
            return true
        }
        null -> Unit
    }
    val entry = Otpauth.parse(text)
    val callback = onResult
    if (entry != null && callback != null) {
        callback(entry.item)
        return true
    }
    onError(
        if (callback != null) {
            context.getString(R.string.scan_err_not_otpauth)
        } else {
            context.getString(R.string.scan_err_not_config_qr)
        },
    )
    return false
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
