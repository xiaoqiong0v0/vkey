package dev.xiaoqiong.vkey.ui.theme

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat
import dev.xiaoqiong.vkey.vault.ThemeMode

/**
 * 应用主题入口：**所有界面（含扫码页、设置页、对话框）都必须包在这里面**。
 *
 * 取色优先级：
 * 1. Android 12+（API 31，`S`）→ Material You 动态取色（`dynamicLight/DarkColorScheme`）；
 * 2. 低版本 → [LightColorScheme] / [DarkColorScheme] 品牌色回退。
 *
 * 深色判定只由 [mode] 决定：[ThemeMode.SYSTEM] 跟随系统（`isSystemInDarkTheme()`），
 * 其余强制浅色 / 深色。模式变化只触发重组，不需要重建 Activity。
 *
 * @param mode 主题模式（跟随系统 / 浅色 / 深色）
 * @param content 页面内容
 */
@Composable
fun VkeyTheme(mode: ThemeMode = ThemeMode.SYSTEM, content: @Composable () -> Unit) {
    val darkTheme = when (mode) {
        ThemeMode.SYSTEM -> isSystemInDarkTheme()
        ThemeMode.LIGHT -> false
        ThemeMode.DARK -> true
    }
    val context = LocalContext.current
    // 动态取色只读取 context 的 configuration，不持有状态，直接取即可（无需 remember）
    val colorScheme = if (supportsDynamicColor()) {
        if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
    } else {
        if (darkTheme) DarkColorScheme else LightColorScheme
    }

    // 系统栏图标明暗：浅色主题用深色图标，深色主题用浅色图标
    val view = LocalView.current
    if (!view.isInEditMode) {
        val activity = context.findActivity()
        if (activity != null) {
            SideEffect {
                val controller = WindowCompat.getInsetsController(activity.window, view)
                controller.isAppearanceLightStatusBars = !darkTheme
                controller.isAppearanceLightNavigationBars = !darkTheme
            }
        }
    }

    MaterialTheme(colorScheme = colorScheme) {
        // 兜底背景：没有 Scaffold 的页面（引导 / 解锁 / 扫码）也不会露出窗口底色
        Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            content()
        }
    }
}

/**
 * 当前设备是否支持 Material You 动态取色（Android 12 / API 31 起）。
 *
 * @return true 表示可以调用 `dynamicLight/DarkColorScheme`
 */
private fun supportsDynamicColor(): Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S

/**
 * 从任意 Context 找回宿主 Activity（用于设置系统栏外观）。
 *
 * @return 找到的 Activity；在预览 / 非 Activity 容器里为 null
 */
private tailrec fun Context.findActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.findActivity()
    else -> null
}
