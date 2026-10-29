package dev.xiaoqiong.vkey.ui

/**
 * 首启页面的状态（纯数据，便于单测）。
 *
 * 「跳过」不创建库、不生成主密钥，因此本机仍未配置时二选一页必须反复出现；
 * 状态里区分「首次」与「上次跳过」只影响提示文案与日志，不影响是否显示。
 */
internal enum class OnboardingState {
    /** 从未做过选择：首次启动。 */
    FIRST_RUN,

    /** 上次选了「我已有 master_key / 配对码」，但本机仍未接入任何账号。 */
    SKIPPED_UNCONFIGURED,

    /** 本机已有可用的库：不再出现首启页。 */
    CONFIGURED,
    ;

    /** 是否需要显示「创建新的恢复码 / 我已有 master_key」二选一页。 */
    val needsSetupChoice: Boolean
        get() = this != CONFIGURED
}

/**
 * 计算首启状态。
 *
 * 判定口径：只看本机是否已有可用的库；`onboardingSkipped` 为 true 时**不会**抑制该页
 * （跳过不建库，未配置就必须再选一次），只用来区分提示文案。
 *
 * @param vaultLoaded 本机是否已有可解开的库（`vault.json` 读取成功）
 * @param onboardingSkipped 持久化的「上次选了跳过」记录（`AppSettings.onboardingSkipped`）
 * @return 对应的首启状态
 */
internal fun onboardingState(vaultLoaded: Boolean, onboardingSkipped: Boolean): OnboardingState = when {
    vaultLoaded -> OnboardingState.CONFIGURED
    onboardingSkipped -> OnboardingState.SKIPPED_UNCONFIGURED
    else -> OnboardingState.FIRST_RUN
}
