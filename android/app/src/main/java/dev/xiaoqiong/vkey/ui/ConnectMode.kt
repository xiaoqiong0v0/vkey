package dev.xiaoqiong.vkey.ui

import dev.xiaoqiong.vkey.R

/**
 * 账号页「未配置」时的接入方式（三选一，互斥），用下拉框选择。
 *
 * 顺序即下拉框选项顺序，也是「默认选中」的来源（[ConnectFormState.DEFAULT_MODE]）。
 */
internal enum class ConnectMode {
    /** 已有 master_key / 恢复码（52 位）：在其它设备用过，输入恢复码即可。 */
    MASTER_KEY,

    /** 配对码：在已登录设备上生成的一次性码。 */
    PAIR,

    /** 开户码：管理员发放的 `ENROLL-XXXX-XXXX`。 */
    ENROLL,
}

/**
 * 接入方式选择状态机（纯数据 + 纯函数，便于单测）。
 *
 * 不变量：只有 [mode] 对应的输入可能非空 —— 切换方式、深链预填都会整体重建状态，
 * 因此「一屏只渲染一个表单」不会带上另一个方式残留的输入。
 *
 * @property mode 当前选中的接入方式
 * @property masterKey master_key 表单输入
 * @property pairCode 配对码表单输入
 * @property enrollCode 开户码表单输入
 * @property enrollUsername 开户码表单附带的用户名
 */
internal data class ConnectFormState(
    val mode: ConnectMode = DEFAULT_MODE,
    val masterKey: String = "",
    val pairCode: String = "",
    val enrollCode: String = "",
    val enrollUsername: String = "",
) {
    /**
     * 切换接入方式：同一方式原样返回（保留输入）；换方式清空全部输入。
     *
     * @param next 目标方式
     * @return 切换后的状态
     */
    fun select(next: ConnectMode): ConnectFormState =
        if (next == mode) this else ConnectFormState(mode = next)

    /**
     * 配对码预填（深链 / 扫码）：切到「配对码」，只保留该码。
     *
     * @param code 识别到的配对码原文
     * @return 新的表单状态
     */
    fun withPairCode(code: String): ConnectFormState =
        ConnectFormState(mode = ConnectMode.PAIR, pairCode = code)

    /**
     * 开户码预填（深链 / 扫码 / `/join` 链接）：切到「开户码」，只保留该码与用户名。
     *
     * @param code 规范化后的开户码
     * @param username 链接自带用户名（裸码时为 null）
     * @return 新的表单状态
     */
    fun withEnrollCode(code: String, username: String?): ConnectFormState = ConnectFormState(
        mode = ConnectMode.ENROLL,
        enrollCode = code,
        enrollUsername = username.orEmpty(),
    )

    companion object {
        /** 默认方式：master_key（多数用户是从旧设备带过来的恢复码）。 */
        val DEFAULT_MODE: ConnectMode = ConnectMode.MASTER_KEY

        /**
         * 按深链预填决定初始状态。
         *
         * 开户码优先（`vkey://enroll` 是更具体的入口），其次配对码，都没有则停在默认方式。
         *
         * @param pairCode 配对码深链带来的码（可为 null）
         * @param enrollCode 开户深链带来的规范化开户码（可为 null）
         * @param enrollUsername 开户深链附带的用户名（可为 null）
         * @return 初始表单状态
         */
        fun fromPrefill(
            pairCode: String?,
            enrollCode: String?,
            enrollUsername: String?,
        ): ConnectFormState = when {
            enrollCode != null -> ConnectFormState().withEnrollCode(enrollCode, enrollUsername)
            !pairCode.isNullOrBlank() -> ConnectFormState().withPairCode(pairCode)
            else -> ConnectFormState()
        }
    }
}

/** 接入方式 → 下拉框里的选项标题。 */
internal fun ConnectMode.titleRes(): Int = when (this) {
    ConnectMode.MASTER_KEY -> R.string.connect_mode_master_key
    ConnectMode.PAIR -> R.string.connect_mode_pair
    ConnectMode.ENROLL -> R.string.connect_mode_enroll
}

/** 接入方式 → 下拉框里的选项说明（副标题）。 */
internal fun ConnectMode.descRes(): Int = when (this) {
    ConnectMode.MASTER_KEY -> R.string.connect_mode_master_key_desc
    ConnectMode.PAIR -> R.string.connect_mode_pair_desc
    ConnectMode.ENROLL -> R.string.connect_mode_enroll_desc
}

/**
 * 接入方式 → 该方式表单内「扫码」使用的扫码语义：只解析该方式对应的码。
 *
 * master_key 没有专属二维码，因此沿用「服务端地址」语义（扫服务端 /pair 页的地址码）。
 */
internal fun ConnectMode.scanMode(): ScanMode = when (this) {
    ConnectMode.MASTER_KEY -> ScanMode.CONFIG_LINK
    ConnectMode.PAIR -> ScanMode.PAIR
    ConnectMode.ENROLL -> ScanMode.ENROLL
}
