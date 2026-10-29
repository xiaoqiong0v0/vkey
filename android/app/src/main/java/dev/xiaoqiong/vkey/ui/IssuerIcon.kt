package dev.xiaoqiong.vkey.ui

import android.content.Context
import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import dev.xiaoqiong.vkey.net.FaviconCache
import kotlinx.coroutines.delay
import dev.xiaoqiong.vkey.net.FaviconFetcher
import dev.xiaoqiong.vkey.net.IssuerDomains
import dev.xiaoqiong.vkey.ui.theme.IssuerBadgeColors

/** 默认图标边长（与 2FA 卡片行高协调）。 */
private val ICON_SIZE: Dp = 40.dp

/** 圆角：字母徽标与抓到的图标保持一致。 */
private val ICON_CORNER: Dp = 12.dp

/** 图标拉取失败后的重试间隔（略大于负缓存 5 分钟，避免立刻重试仍被拦）。 */
private const val ICON_RETRY_DELAY_MS: Long = 5L * 60 * 1000 + 1_000L

/** 字母字号相对图标边长的比例。 */
private const val INITIAL_TEXT_RATIO: Float = 0.42f

/**
 * 站点图标：按「首帧就有结论」的方式渲染，避免每次进入列表都先闪一下字母。
 *
 * 首帧三态（全部同步判定，不解码、不联网）：
 * 1. 内存缓存命中 → 直接画 favicon，不画字母；
 * 2. 内存未命中但磁盘缓存有效 → 画透明占位（同尺寸），随后异步解码填入；
 * 3. 两者都没有 → 画字母徽标，异步加载成功后替换（首次进入不可避免）。
 *
 * 三种状态尺寸、圆角完全一致（固定 [size] + [ICON_CORNER]），行高不会跳动。
 *
 * @param issuer 条目里的服务名，用于解析域名与选底色
 * @param label 备用文案（issuer 为空时取它做首字母）
 * @param size 图标边长
 */
@Composable
fun IssuerIcon(issuer: String, label: String, size: Dp = ICON_SIZE) {
    val context = LocalContext.current
    val appContext = remember(context) { context.applicationContext }
    val domain = remember(issuer) { IssuerDomains.domainFor(issuer) }

    // 首帧同步判定：只查内存缓存 + 一次磁盘 stat，避免先渲染字母再替换
    val initial = remember(issuer, domain, appContext) { resolveInitialState(appContext, domain) }
    var favicon by remember(issuer) { mutableStateOf(initial.bitmap) }
    var awaitingDisk by remember(issuer) { mutableStateOf(initial.awaitingDisk) }

    LaunchedEffect(issuer, domain) {
        if (domain == null) return@LaunchedEffect
        // 失败后按负缓存有效期重试（最多 3 次）：同步拉到的新条目不必重启 App 也能补上图标
        repeat(3) { attempt ->
            favicon = FaviconFetcher.load(appContext, domain)
            awaitingDisk = false
            if (favicon != null) return@LaunchedEffect
            if (attempt < 2) delay(ICON_RETRY_DELAY_MS)
        }
    }

    val initialText = remember(issuer, label) { initialOf(issuer, label) }
    val badgeColor = remember(issuer) { IssuerBadgeColors[issuer.hashCode().mod(IssuerBadgeColors.size)] }
    val shape = RoundedCornerShape(ICON_CORNER)
    val textSize = with(LocalDensity.current) { (size * INITIAL_TEXT_RATIO).toSp() }
    // 磁盘解码期间保持透明占位：不画字母，也不画底色
    val showBadge = favicon == null && !awaitingDisk

    Box(
        modifier = Modifier
            .size(size)
            .clip(shape)
            .background(if (showBadge) badgeColor else Color.Transparent),
        contentAlignment = Alignment.Center,
    ) {
        if (showBadge) {
            Text(
                text = initialText,
                color = Color.White,
                fontWeight = FontWeight.Bold,
                fontSize = textSize,
            )
        }
        // 图标与字母同尺寸、同圆角：覆盖时不会改变布局
        favicon?.let { bitmap ->
            Image(
                bitmap = bitmap.asImageBitmap(),
                contentDescription = null,
                contentScale = ContentScale.Crop,
                modifier = Modifier.fillMaxSize().clip(shape),
            )
        }
    }
}

/** 首帧渲染状态：已就绪的图标，或「等待磁盘解码」的透明占位。 */
private class InitialIconState(
    /** 内存缓存命中的图标；未命中为 null。 */
    val bitmap: Bitmap?,
    /** 磁盘有有效缓存、需等异步解码（此期间画透明占位）。 */
    val awaitingDisk: Boolean,
)

/**
 * 计算首帧状态（同步、无解码、不联网）。
 *
 * @param context application context（内部只用 `cacheDir`）
 * @param domain 已解析的站点域名；null 表示 issuer 无法识别
 * @return 内存命中 → 图标；磁盘有有效缓存 → 透明占位；否则 → 字母徽标
 */
private fun resolveInitialState(context: Context, domain: String?): InitialIconState {
    if (domain == null) return InitialIconState(bitmap = null, awaitingDisk = false)
    FaviconCache.peek(domain)?.let { return InitialIconState(bitmap = it, awaitingDisk = false) }
    if (FaviconFetcher.hasCached(context, domain)) {
        return InitialIconState(bitmap = null, awaitingDisk = true)
    }
    return InitialIconState(bitmap = null, awaitingDisk = false)
}

/**
 * 取展示用首字母。
 *
 * @param issuer 服务名（优先）
 * @param label 备用文案
 * @return 单个大写字符；两者都为空返回 `?`
 */
private fun initialOf(issuer: String, label: String): String {
    val source = issuer.trim().ifEmpty { label.trim() }
    val first = source.firstOrNull { !it.isWhitespace() } ?: return "?"
    return first.uppercase()
}
