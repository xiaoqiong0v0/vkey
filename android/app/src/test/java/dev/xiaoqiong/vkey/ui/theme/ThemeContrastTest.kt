package dev.xiaoqiong.vkey.ui.theme

import androidx.compose.material3.ColorScheme
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 品牌色板（动态取色不可用时的回退）的对比度门禁。
 *
 * 校验 `MaterialTheme.colorScheme` 里实际会被用到的「前景/背景」对：
 * 正文类 ≥ 4.5:1（WCAG AA），控件边框 ≥ 3:1。
 * 动态取色（Android 12+）由系统保证对比度，这里只管自定义回退色板。
 */
class ThemeContrastTest {

    /** WCAG 相对亮度对比度。 */
    private fun contrast(a: Color, b: Color): Double {
        val la = a.luminance().toDouble()
        val lb = b.luminance().toDouble()
        return (maxOf(la, lb) + 0.05) / (minOf(la, lb) + 0.05)
    }

    /** 正文级（≥4.5:1）。 */
    private fun assertTextPairs(scheme: ColorScheme) {
        val pairs = listOf(
            "onSurface/surface" to (scheme.onSurface to scheme.surface),
            "onBackground/background" to (scheme.onBackground to scheme.background),
            "onSurfaceVariant/surface" to (scheme.onSurfaceVariant to scheme.surface),
            "onPrimary/primary" to (scheme.onPrimary to scheme.primary),
            "onSecondary/secondary" to (scheme.onSecondary to scheme.secondary),
            "onTertiary/tertiary" to (scheme.onTertiary to scheme.tertiary),
            "onError/error" to (scheme.onError to scheme.error),
            "error/surface" to (scheme.error to scheme.surface),
            "primary/surface" to (scheme.primary to scheme.surface),
            "onPrimaryContainer/primaryContainer" to
                (scheme.onPrimaryContainer to scheme.primaryContainer),
            "onSecondaryContainer/secondaryContainer" to
                (scheme.onSecondaryContainer to scheme.secondaryContainer),
        )
        for ((name, pair) in pairs) {
            val value = contrast(pair.first, pair.second)
            assertTrue("$name 对比度 ${"%.2f".format(value)} < 4.5:1", value >= 4.5)
        }
    }

    /** 控件边框级（≥3:1）。 */
    private fun assertOutlinePairs(scheme: ColorScheme) {
        val value = contrast(scheme.outline, scheme.surface)
        assertTrue("outline/surface 对比度 ${"%.2f".format(value)} < 3:1", value >= 3.0)
    }

    @Test
    fun lightSchemeMeetsWcagAa() {
        assertTextPairs(LightColorScheme)
        assertOutlinePairs(LightColorScheme)
    }

    @Test
    fun darkSchemeMeetsWcagAa() {
        assertTextPairs(DarkColorScheme)
        assertOutlinePairs(DarkColorScheme)
    }

    @Test
    fun cameraOverlayTextReadableOnScrim() {
        // 扫码页文字压在「相机画面 + 55% 黑遮罩」上，按最坏情况（纯白画面）估算
        val worstCase = CameraScrim
        val value = contrast(CameraOverlayContent, worstCase)
        assertTrue("CameraOverlayContent 在遮罩上对比度 ${"%.2f".format(value)} < 4.5:1", value >= 4.5)
    }
}
