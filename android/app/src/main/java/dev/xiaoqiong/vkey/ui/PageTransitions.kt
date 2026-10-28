package dev.xiaoqiong.vkey.ui

import android.content.Context
import android.provider.Settings
import androidx.compose.animation.ContentTransform
import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.animation.SizeTransform
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.FiniteAnimationSpec
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.ui.unit.IntOffset

/** 页面转场时长（毫秒）：位移与淡入淡出共用，保证两者同步。 */
internal const val PAGE_TRANSITION_MS = 260

/** 页面转场位移幅度：屏宽的 1/8（幅度再大就会有「飞进来」的廉价感）。 */
internal const val PAGE_SLIDE_WIDTH_DIVISOR = 8

/**
 * 系统动画是否被关闭（无障碍 / 省电场景）。
 *
 * @param context 用于读取系统设置
 * @return true 表示 `ANIMATOR_DURATION_SCALE == 0`，页面切换应当直接无动画
 */
internal fun vkeyPageAnimationsDisabled(context: Context): Boolean =
    Settings.Global.getFloat(
        context.contentResolver,
        Settings.Global.ANIMATOR_DURATION_SCALE,
        1f,
    ) == 0f

/**
 * 构造页面转场：前进时新页从右侧滑入、旧页向左轻移淡出；返回时方向相反。
 *
 * 只做 translate + alpha（不加颜色滤镜、不做缩放），容器不裁剪，避免阴影/圆角被切。
 *
 * @param forward 目标页是否比当前页更深（false 表示返回）
 * @param animated false 时直接无动画切换
 * @return 供 [androidx.compose.animation.AnimatedContent] 使用的 [ContentTransform]
 */
internal fun vkeyPageTransition(forward: Boolean, animated: Boolean): ContentTransform {
    if (!animated) {
        return ContentTransform(
            EnterTransition.None,
            ExitTransition.None,
            0f,
            SizeTransform(clip = false, sizeAnimationSpec = { _, _ -> tween(durationMillis = 0) }),
        )
    }
    val slideSpec: FiniteAnimationSpec<IntOffset> =
        tween(durationMillis = PAGE_TRANSITION_MS, easing = FastOutSlowInEasing)
    val fadeSpec: FiniteAnimationSpec<Float> =
        tween(durationMillis = PAGE_TRANSITION_MS, easing = FastOutSlowInEasing)
    val direction = if (forward) 1 else -1
    val enter = slideInHorizontally(slideSpec) { width ->
        direction * (width / PAGE_SLIDE_WIDTH_DIVISOR)
    } + fadeIn(fadeSpec)
    val exit = slideOutHorizontally(slideSpec) { width ->
        -direction * (width / PAGE_SLIDE_WIDTH_DIVISOR)
    } + fadeOut(fadeSpec)
    return ContentTransform(enter, exit, 0f, SizeTransform(clip = false))
}
