package dev.xiaoqiong.vkey.net

/**
 * issuer → 站点域名解析（纯函数，无 Android 依赖，可单测）。
 *
 * 用途：2FA 条目只保存 issuer 名称（如 "GitHub"），抓站点图标前需要先确定域名。
 * 解析顺序：
 * 1. issuer 本身就是域名（`example.com`）→ 直接使用；
 * 2. issuer 首个词命中内置映射表（大小写不敏感）→ 返回映射域名；
 * 3. 其它情况返回 null，由调用方回退字母徽标。
 */
object IssuerDomains {

    /** 形如域名的 issuer（忽略大小写）。 */
    private val DOMAIN_PATTERN: Regex = Regex("^[a-z0-9.-]+\\.[a-z]{2,}$", RegexOption.IGNORE_CASE)

    /** issuer 首个词的切分符（任意空白）。 */
    private val WHITESPACE: Regex = Regex("\\s+")

    /** 首个词尾部需要去掉的标点（半角 + 常见全角）。 */
    private const val TRAILING_PUNCTUATION: String =
        ".,;:!?'\"()[]{}<>、，。；：！？“”‘’（）【】《》"

    /**
     * 常见服务 issuer → 官方域名映射。
     *
     * 键一律小写；值是不带 scheme 的主机名（抓取时统一用 https）。
     */
    private val BUILTIN: Map<String, String> = mapOf(
        "github" to "github.com",
        "google" to "google.com",
        "gmail" to "google.com",
        "microsoft" to "microsoft.com",
        "outlook" to "microsoft.com",
        "office365" to "microsoft.com",
        "amazon" to "amazon.com",
        "aws" to "amazon.com",
        "npm" to "npmjs.com",
        "cloudflare" to "cloudflare.com",
        "gitlab" to "gitlab.com",
        "apple" to "apple.com",
        "icloud" to "apple.com",
        "dropbox" to "dropbox.com",
        "facebook" to "facebook.com",
        "meta" to "facebook.com",
        "twitter" to "x.com",
        "x" to "x.com",
        "discord" to "discord.com",
        "steam" to "steampowered.com",
        "binance" to "binance.com",
        "okx" to "okx.com",
        "aliyun" to "aliyun.com",
        "alibaba" to "aliyun.com",
        "tencent" to "qq.com",
        "qq" to "qq.com",
        "wechat" to "weixin.qq.com",
        "weixin" to "weixin.qq.com",
        "baidu" to "baidu.com",
        "bilibili" to "bilibili.com",
        "netease" to "163.com",
        "telegram" to "telegram.org",
        "slack" to "slack.com",
        "notion" to "notion.so",
        "figma" to "figma.com",
        "vercel" to "vercel.com",
        "heroku" to "heroku.com",
        "digitalocean" to "digitalocean.com",
        "linode" to "linode.com",
        "vultr" to "vultr.com",
        "namecheap" to "namecheap.com",
        "godaddy" to "godaddy.com",
    )

    /**
     * 把 issuer 解析为站点域名。
     *
     * @param issuer 条目里的服务名（如 `GitHub`、`GitHub Inc.`、`github.com`）
     * @return 小写域名；无法识别（或为空）时返回 null
     */
    fun domainFor(issuer: String): String? {
        val trimmed = issuer.trim()
        if (trimmed.isEmpty()) return null
        if (DOMAIN_PATTERN.matches(trimmed)) return trimmed.lowercase()

        val firstWord = trimmed.split(WHITESPACE, limit = 2).first()
            .trimEnd(*TRAILING_PUNCTUATION.toCharArray())
            .lowercase()
        if (firstWord.isEmpty()) return null
        return BUILTIN[firstWord]
    }
}
