package dev.xiaoqiong.vkey.ui

import dev.xiaoqiong.vkey.R
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * 开户码错误码 → 文案资源的映射测试（[enrollErrorRes]）。
 *
 * 只做纯映射断言（resId 是编译期常量，无需 Android 环境）；
 * 文案本身由 strings.xml（zh / en）承载。
 */
class EnrollErrorMappingTest {

    @Test
    fun enrollCodesMapToDedicatedMessages() {
        assertEquals(R.string.err_enroll_invalid_code, enrollErrorRes("invalid_code"))
        assertEquals(R.string.err_enroll_code_expired, enrollErrorRes("code_expired"))
        assertEquals(R.string.err_enroll_username_taken, enrollErrorRes("username_taken"))
        assertEquals(R.string.err_enroll_invalid_verifier, enrollErrorRes("invalid_verifier"))
        assertEquals(R.string.err_enroll_quota_devices, enrollErrorRes("quota_devices"))
        assertEquals(R.string.err_enroll_disabled, enrollErrorRes("enroll_disabled"))
    }

    @Test
    fun otherCodesFallBackToDescribeFailure() {
        // 0 表示无开户专属文案，交回通用 describeFailure（网络、token、时间偏差等）
        assertEquals(0, enrollErrorRes("network_error"))
        assertEquals(0, enrollErrorRes("invalid_token"))
        assertEquals(0, enrollErrorRes("ts_skew"))
        assertEquals(0, enrollErrorRes(""))
    }
}
