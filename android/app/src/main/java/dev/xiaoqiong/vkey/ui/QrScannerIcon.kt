package dev.xiaoqiong.vkey.ui

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.path
import androidx.compose.ui.unit.dp

/**
 * 「扫码」图标：四角取景框（本地构建，避免为单个图标引入 material-icons-extended）。
 *
 * 只描述形状，颜色由 `Icon(tint = …)` 统一着色。
 */
internal val qrScannerIcon: ImageVector by lazy {
    ImageVector.Builder(
        name = "QrCodeScanner",
        defaultWidth = 24.dp,
        defaultHeight = 24.dp,
        viewportWidth = 24f,
        viewportHeight = 24f,
    ).apply {
        path(
            stroke = SolidColor(Color.Black),
            strokeLineWidth = 2f,
            strokeLineCap = StrokeCap.Round,
            strokeLineJoin = StrokeJoin.Round,
        ) {
            // 左上角
            moveTo(4f, 9f)
            verticalLineTo(4f)
            horizontalLineTo(9f)
            // 右上角
            moveTo(15f, 4f)
            horizontalLineTo(20f)
            verticalLineTo(9f)
            // 右下角
            moveTo(20f, 15f)
            verticalLineTo(20f)
            horizontalLineTo(15f)
            // 左下角
            moveTo(9f, 20f)
            horizontalLineTo(4f)
            verticalLineTo(15f)
        }
    }.build()
}
