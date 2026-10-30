package dev.xiaoqiong.vkey.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 账号页「未配置」表单的两条纯规则测试：
 *
 * 1. 底部按钮可见性：只有支持扫码的方式（配对码 / 开户码）才显示「扫码」；
 *    master_key 只有一个「确认」（按钮占满宽度由 Compose 的 weight 实现）。
 * 2. 「地址」字段与扫码结果的合并：扫码结果非空即覆盖，空白则保留原值。
 */
class AccountTabScanTest {

    @Test
    fun masterKeyHasNoScanButton() {
        // master_key 没有专属二维码：底部只留「确认」
        assertEquals(false, supportsScanButton(ConnectMode.MASTER_KEY))
    }

    @Test
    fun pairAndEnrollShowScanButton() {
        // 配对码 / 开户码都能扫接入码：底部「确认」+「扫码」各占一半
        assertTrue(supportsScanButton(ConnectMode.PAIR))
        assertTrue(supportsScanButton(ConnectMode.ENROLL))
    }

    @Test
    fun scanButtonFollowsScannableMode() {
        // 有「扫码」按钮的方式，其扫码语义不能是「只认服务端地址」，两者必须一致
        ConnectMode.entries.forEach { mode ->
            val scannable = supportsScanButton(mode)
            assertEquals(!scannable, mode.scanMode() == ScanMode.CONFIG_LINK)
        }
    }

    @Test
    fun scannedAddressReplacesCurrentValue() {
        // 扫码是明确动作：直接覆盖手输值（不拼接）
        assertEquals(
            "https://new.example.com",
            mergeScannedAddress("https://old.example.com", "https://new.example.com"),
        )
        assertEquals(
            "https://new.example.com",
            mergeScannedAddress("https://ol", "https://new.example.com"),
        )
    }

    @Test
    fun scannedAddressIsNormalized() {
        // 去首尾空白与尾部斜杠后再落进字段
        assertEquals(
            "https://vkey.example.com",
            mergeScannedAddress("", "  https://vkey.example.com/  "),
        )
    }

    @Test
    fun blankScanKeepsCurrentAddress() {
        // 取消扫码 / 识别为空：不动字段（原值也做规范化）
        assertEquals("https://old.example.com", mergeScannedAddress("https://old.example.com/", null))
        assertEquals("https://old.example.com", mergeScannedAddress("https://old.example.com", ""))
        assertEquals("https://old.example.com", mergeScannedAddress("https://old.example.com", "   "))
    }

    @Test
    fun blankScanOnEmptyFieldStaysEmpty() {
        // 字段本来空、扫码也没结果：仍是空串（不引入占位文本）
        assertEquals("", mergeScannedAddress("", null))
        assertEquals("", mergeScannedAddress("", "  "))
    }

    @Test
    fun mergeIsIdempotentForSameAddress() {
        // 同一个地址反复扫不改变结果（便于「扫码 → 再扫」）
        val once = mergeScannedAddress("", "https://vkey.example.com/")
        assertEquals(once, mergeScannedAddress(once, "https://vkey.example.com"))
        assertNotEquals("", once)
    }
}
