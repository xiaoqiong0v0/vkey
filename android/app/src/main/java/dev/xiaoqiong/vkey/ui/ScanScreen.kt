package dev.xiaoqiong.vkey.ui

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import dev.xiaoqiong.vkey.vault.Otpauth
import dev.xiaoqiong.vkey.vault.TotpItem
import java.util.concurrent.Executors

/** 取景框边长（屏幕短边的 68%，并夹在 200–320dp 之间）。 */
private const val FRAME_RATIO = 0.68f
private val FRAME_MIN = 200.dp
private val FRAME_MAX = 320.dp

/**
 * 扫一扫添加：相机铺满全屏，中间镂空取景框，识别 `otpauth://` 后回调。
 *
 * @param onResult 解析成功后的条目
 * @param onCancel 用户取消
 */
@Composable
fun ScanScreen(onResult: (TotpItem) -> Unit, onCancel: () -> Unit) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val configuration = LocalConfiguration.current
    val density = LocalDensity.current

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
        if (!granted) error = "需要相机权限才能扫码；也可以返回用手动输入"
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
                    val entry = raw?.let { Otpauth.parse(it) }
                    if (entry != null) onResult(entry.item) else error = "这张图里没有可用的 otpauth 二维码"
                }.addOnFailureListener { e ->
                    error = "图片识别失败：${e.message}"
                }
            }.onFailure { error = "读取图片失败：${it.message}" }
        }
    }

    // 取景框边长：按屏幕短边比例计算，并夹在合理范围
    val frameSize = remember(configuration.screenWidthDp, configuration.screenHeightDp) {
        val shortSide = minOf(configuration.screenWidthDp, configuration.screenHeightDp)
        with(density) {
            (shortSide * FRAME_RATIO).dp.coerceIn(FRAME_MIN, FRAME_MAX)
        }
    }

    Box(Modifier.fillMaxSize().background(Color.Black)) {
        if (!hasPermission) {
            Column(
                modifier = Modifier.fillMaxSize().padding(24.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    error ?: "等待相机权限…",
                    color = Color.White,
                    style = MaterialTheme.typography.bodyMedium,
                    textAlign = TextAlign.Center,
                )
                Button(
                    onClick = onCancel,
                    modifier = Modifier.padding(top = 16.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color.White.copy(alpha = 0.18f),
                        contentColor = Color.White,
                    ),
                ) { Text("返回") }
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
                                    val entry = Otpauth.parse(raw)
                                    if (entry != null) {
                                        handled = true
                                        onResult(entry.item)
                                    } else {
                                        error = "二维码不是有效的 otpauth:// 链接"
                                    }
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
                        error = "相机启动失败：${t.message}"
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
            drawPath(path, Color.Black.copy(alpha = 0.55f))
        }

        // 取景框：圆角白边 + 四角高亮
        Box(
            modifier = Modifier
                .align(Alignment.Center)
                .size(frameSize)
                .border(2.dp, Color.White.copy(alpha = 0.85f), RoundedCornerShape(20.dp)),
        )

        Column(
            modifier = Modifier
                .align(Alignment.TopCenter)
                .padding(top = 48.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                text = "扫描 Authenticator 二维码",
                color = Color.White,
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
                text = error ?: "把二维码放进框内，识别后会自动添加",
                color = if (error != null) Color(0xFFFF8A80) else Color.White.copy(alpha = 0.85f),
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
            )
            Button(
                onClick = { pickImage.launch(androidx.activity.result.PickVisualMediaRequest(androidx.activity.result.contract.ActivityResultContracts.PickVisualMedia.ImageOnly)) },
                modifier = Modifier.padding(top = 16.dp).fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color.White.copy(alpha = 0.18f),
                    contentColor = Color.White,
                ),
            ) { Text("从相册选择二维码") }
            Row(
                modifier = Modifier.padding(top = 8.dp).fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Button(
                    onClick = { showPaste = true },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color.White.copy(alpha = 0.12f),
                        contentColor = Color.White,
                    ),
                ) { Text("粘贴链接") }
                Button(
                    onClick = onCancel,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color.White.copy(alpha = 0.12f),
                        contentColor = Color.White,
                    ),
                ) { Text("取消") }
            }
        }

        // 相机预览之上再画一次遮罩会挡住相机；此处不加额外层
    }

    if (showPaste) {
        var text by remember { mutableStateOf("") }
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { showPaste = false },
            title = { Text("粘贴 otpauth 链接") },
            text = {
                androidx.compose.foundation.layout.Column {
                    Text("形如 otpauth://totp/Issuer:acct?secret=XXXX", color = Color.Gray, style = MaterialTheme.typography.bodySmall)
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
                    val entry = Otpauth.parse(text)
                    if (entry != null) {
                        showPaste = false
                        onResult(entry.item)
                    } else {
                        error = "链接不是有效的 otpauth://totp"
                        showPaste = false
                    }
                }) { Text("识别") }
            },
            dismissButton = {
                androidx.compose.material3.TextButton(onClick = { showPaste = false }) { Text("取消") }
            },
        )
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
