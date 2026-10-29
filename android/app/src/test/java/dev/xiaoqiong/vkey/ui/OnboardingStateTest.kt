package dev.xiaoqiong.vkey.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 首启二选一页的状态机测试（[onboardingState] / [OnboardingState.needsSetupChoice]）。
 *
 * 口径：跳过「我已有 master_key / 配对码」**不建库、不生成主密钥**，
 * 因此只要本机仍未配置，二选一页必须再次出现（`onboarding_skipped` 不抑制该页）。
 */
class OnboardingStateTest {

    @Test
    fun freshInstallShowsSetupChoice() {
        // 无库 + 从未跳过 → 首启：显示二选一页
        val state = onboardingState(vaultLoaded = false, onboardingSkipped = false)
        assertEquals(OnboardingState.FIRST_RUN, state)
        assertTrue(state.needsSetupChoice)
    }

    @Test
    fun skippedButStillUnconfiguredShowsSetupChoiceAgain() {
        // 无库 + 已跳过（onboarding_skipped=true）但还没接入 → 仍显示二选一页
        val state = onboardingState(vaultLoaded = false, onboardingSkipped = true)
        assertEquals(OnboardingState.SKIPPED_UNCONFIGURED, state)
        assertTrue(state.needsSetupChoice)
    }

    @Test
    fun configuredVaultHidesSetupChoice() {
        // 已有库（device/master_key 已配置）→ 不再出现二选一页
        val state = onboardingState(vaultLoaded = true, onboardingSkipped = false)
        assertEquals(OnboardingState.CONFIGURED, state)
        assertFalse(state.needsSetupChoice)
    }

    @Test
    fun staleSkipFlagDoesNotBringBackSetupChoice() {
        // 配置完成后残留的跳过标记不应让首启页再次出现
        val state = onboardingState(vaultLoaded = true, onboardingSkipped = true)
        assertEquals(OnboardingState.CONFIGURED, state)
        assertFalse(state.needsSetupChoice)
    }
}
