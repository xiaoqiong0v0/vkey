package dev.xiaoqiong.vkey.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import android.graphics.Bitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import dev.xiaoqiong.vkey.R

/**
 * 把字符串渲染成二维码图片（离线生成，用于「配对码」等需要另一台设备扫描的场景）。
 *
 * @param content 二维码内容（如 `vkey://pair?code=…&server=…`）
 * @param size 显示尺寸
 */
@Composable
fun QrCodeImage(content: String, size: Dp = 220.dp) {
    val bitmap = remember(content) {
        val pixels = 512
        val hints = mapOf(
            EncodeHintType.MARGIN to 1,
            EncodeHintType.CHARACTER_SET to "UTF-8",
        )
        val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, pixels, pixels, hints)
        Bitmap.createBitmap(pixels, pixels, Bitmap.Config.ARGB_8888).apply {
            for (x in 0 until pixels) {
                for (y in 0 until pixels) {
                    setPixel(x, y, if (matrix[x, y]) android.graphics.Color.BLACK else android.graphics.Color.WHITE)
                }
            }
        }
    }
    Image(
        bitmap = bitmap.asImageBitmap(),
        contentDescription = stringResource(R.string.qr_code_content_description),
        modifier = Modifier
            .size(size)
            // 二维码是机器可读图案：底色必须纯白、模块纯黑，不能跟随深色主题
            .background(Color.White, RoundedCornerShape(8.dp))
            .padding(6.dp),
    )
}
