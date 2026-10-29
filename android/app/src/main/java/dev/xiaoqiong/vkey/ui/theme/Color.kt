package dev.xiaoqiong.vkey.ui.theme

import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color

/**
 * 品牌色板（冷灰蓝系）与语义色。
 *
 * 明暗两套都按「正文 ≥ 4.5:1、控件边框 ≥ 3:1」手调过：
 * - 浅色：primary `#2E5A88` 配白字约 7.2:1，`onSurfaceVariant` 在 surface 上约 8.9:1；
 * - 深色：primary `#A8C8F0` 配深字约 8.8:1，`onSurface` 在 surface 上约 15:1。
 *
 * Android 12+ 走 Material You 动态取色（见 [VkeyTheme]），这里的色板是低版本回退，
 * 也是「品牌一致性」在无动态取色机型上的基线。
 */

// ---------------------------------------------------------------- 品牌色（浅色）

/** 主色：冷灰蓝，用于按钮容器、链接、强调文字。 */
private val BrandBlue = Color(0xFF2E5A88)

/** 次色：冷灰，用于次要强调。 */
private val BrandSlate = Color(0xFF4F5D6E)

/** 第三色：冷紫灰，用于对比强调。 */
private val BrandViolet = Color(0xFF5C5470)

// ---------------------------------------------------------------- 品牌色（深色）

/** 主色（深色）：提亮后的冷蓝，保证在近黑底上可读。 */
private val BrandBlueLight = Color(0xFFA8C8F0)

/** 次色（深色）。 */
private val BrandSlateLight = Color(0xFFB6C2D1)

/** 第三色（深色）。 */
private val BrandVioletLight = Color(0xFFCCC2D9)

// ---------------------------------------------------------------- 语义色

/** 危险/错误（浅色容器）。 */
private val DangerRed = Color(0xFFB3261E)

/** 危险/错误（深色容器）。 */
private val DangerRedLight = Color(0xFFFFB4AB)

// ---------------------------------------------------------------- 相机覆盖层语义色
//
// 扫码页的背景永远是相机预览（深色画面），因此覆盖层不跟随浅色/深色主题：
// 文字固定白、按钮固定半透明白，错误提示用浅红。集中在这里便于统一调整。

/** 扫码页底色（相机预览未就绪时的纯黑底）。 */
val CameraBackground: Color = Color.Black

/** 取景框外的遮罩（55% 黑）。 */
val CameraScrim: Color = Color(0x8C000000)

/** 覆盖层主文字色。 */
val CameraOverlayContent: Color = Color(0xFFFFFFFF)

/** 覆盖层次要文字色（85% 白）。 */
val CameraOverlayContentMuted: Color = Color(0xD9FFFFFF)

/** 覆盖层按钮底色（18% 白）。 */
val CameraOverlayButton: Color = Color(0x2EFFFFFF)

/** 覆盖层次级按钮底色（12% 白）。 */
val CameraOverlayButtonSubtle: Color = Color(0x1FFFFFFF)

/** 覆盖层错误文字（在深色相机画面上可读）。 */
val CameraOverlayError: Color = Color(0xFFFF8A80)

// ---------------------------------------------------------------- 浅色方案

/** 浅色配色（Material You 不可用时的回退）。 */
val LightColorScheme = lightColorScheme(
    primary = BrandBlue,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFD6E4F7),
    onPrimaryContainer = Color(0xFF0B2740),
    inversePrimary = BrandBlueLight,
    secondary = BrandSlate,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFDCE4EE),
    onSecondaryContainer = Color(0xFF101C28),
    tertiary = BrandViolet,
    onTertiary = Color.White,
    tertiaryContainer = Color(0xFFE6E0ED),
    onTertiaryContainer = Color(0xFF1E1A24),
    background = Color(0xFFF7F9FC),
    onBackground = Color(0xFF1A1C1F),
    surface = Color(0xFFF9FAFC),
    onSurface = Color(0xFF1A1C1F),
    surfaceVariant = Color(0xFFDEE3EA),
    onSurfaceVariant = Color(0xFF42474E),
    surfaceTint = BrandBlue,
    inverseSurface = Color(0xFF2F3337),
    inverseOnSurface = Color(0xFFF1F3F5),
    error = DangerRed,
    onError = Color.White,
    errorContainer = Color(0xFFF9DEDC),
    onErrorContainer = Color(0xFF410E0B),
    outline = Color(0xFF737A82),
    outlineVariant = Color(0xFFC3CAD2),
    scrim = Color.Black,
)

// ---------------------------------------------------------------- 深色方案

/** 深色配色（Material You 不可用时的回退）。 */
val DarkColorScheme = darkColorScheme(
    primary = BrandBlueLight,
    onPrimary = Color(0xFF0B2740),
    primaryContainer = Color(0xFF22405E),
    onPrimaryContainer = Color(0xFFD6E4F7),
    inversePrimary = BrandBlue,
    secondary = BrandSlateLight,
    onSecondary = Color(0xFF1B2733),
    secondaryContainer = Color(0xFF36424F),
    onSecondaryContainer = Color(0xFFDCE4EE),
    tertiary = BrandVioletLight,
    onTertiary = Color(0xFF2E2836),
    tertiaryContainer = Color(0xFF453E50),
    onTertiaryContainer = Color(0xFFE6E0ED),
    background = Color(0xFF101418),
    onBackground = Color(0xFFE3E7EC),
    surface = Color(0xFF14181D),
    onSurface = Color(0xFFE3E7EC),
    surfaceVariant = Color(0xFF3F464E),
    onSurfaceVariant = Color(0xFFB6BEC7),
    surfaceTint = BrandBlueLight,
    inverseSurface = Color(0xFFE3E7EC),
    inverseOnSurface = Color(0xFF1A1C1F),
    error = DangerRedLight,
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
    outline = Color(0xFF8C939B),
    outlineVariant = Color(0xFF3F464E),
    scrim = Color.Black,
)

/**
 * 站点图标字母徽标的底色候选（深色、白字可读，与主题明暗无关）。
 *
 * 图标本身是「站点标识」，不应随主题变色；保持固定色板才能让同一站点
 * 在明暗模式下看起来是同一个图标。
 */
val IssuerBadgeColors: List<Color> = listOf(
    Color(0xFF455A64),
    Color(0xFF5D4037),
    Color(0xFF4E342E),
    Color(0xFF37474F),
    Color(0xFF4A148C),
    Color(0xFF1A237E),
    Color(0xFF00695C),
    Color(0xFF283593),
    Color(0xFF6A1B9A),
    Color(0xFF2E7D32),
    Color(0xFFAD1457),
    Color(0xFF00838F),
)
