package dev.xiaoqiong.vkey.ui

import dev.xiaoqiong.vkey.vault.Base32
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [dispatchScan] 在各 [ScanMode] 下的分类矩阵测试（纯函数，无需 Android 环境）。
 *
 * 样例：裸地址 / `vkey://config` 深链 / 裸配对码 / `vkey://pair` 深链 / 开户码 /
 * `otpauth://` / 垃圾文本 / 空白 × 5 个 mode。
 * 断言两类结果：被接受（附类别与规范化内容）或被拒绝（附该 mode 的错误分类）。
 * 核心约定：类别识别与 mode 无关，mode 只决定是否越权处理。
 */
class ScanDispatchTest {

    // ---------------- 样例 ----------------

    /** 服务端主页 / pair 页二维码的内容：裸 http 地址（与验证用 qr-server.png 一致）。 */
    private val plainServer = "http://10.0.2.2:3150"

    /** 同步配置深链。 */
    private val configLink = "vkey://config?server=https://example.com"

    /** 52 位裸配对码。 */
    private val barePair = Base32.encode(ByteArray(32))

    /** 另一台设备生成的配对码二维码：配对码 + 服务器参数。 */
    private val pairLink = "vkey://pair?code=$barePair&server=https://example.com"

    /** 开户码。 */
    private val enroll = "ENROLL-AB12-CD34"

    /** otpauth:// 二维码。 */
    private val otpauth = "otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"

    /** 垃圾文本：不匹配任何已知类别。 */
    private val garbage = "hello world 12345"

    private val allModes = ScanMode.entries.toList()

    // ---------------- 断言助手 ----------------

    /** 断言 [raw] 在 [mode] 下被接受，且类别为 [kind]。 */
    private fun assertAccepted(raw: String, mode: ScanMode, kind: ScanKind) {
        val outcome = dispatchScan(raw, mode)
        assertTrue("应被接受: mode=$mode raw=${raw.take(40)} 实际=$outcome", outcome is ScanOutcome.Accepted)
        assertEquals(kind, (outcome as ScanOutcome.Accepted).content.kind)
    }

    /** 断言 [raw] 在 [mode] 下被拒绝，错误分类为 [reason]。 */
    private fun assertRejected(raw: String, mode: ScanMode, reason: ScanReject) {
        val outcome = dispatchScan(raw, mode)
        assertTrue(
            "应被拒绝($reason): mode=$mode raw=${raw.take(40)} 实际=$outcome",
            outcome is ScanOutcome.Rejected && outcome.reason == reason,
        )
    }

    // ---------------- CONFIG_LINK ----------------

    @Test
    fun `CONFIG_LINK 只接受服务端地址`() {
        for (server in listOf(plainServer, configLink)) {
            assertAccepted(server, ScanMode.CONFIG_LINK, ScanKind.SERVER_ADDRESS)
        }
        for (other in listOf(barePair, pairLink, enroll, otpauth, garbage)) {
            assertRejected(other, ScanMode.CONFIG_LINK, ScanReject.NOT_SERVER_ADDRESS)
        }
    }

    @Test
    fun `CONFIG_LINK 给出的地址内容正确`() {
        val outcome = dispatchScan(plainServer, ScanMode.CONFIG_LINK) as ScanOutcome.Accepted
        assertEquals(plainServer, (outcome.content as ScanContent.ServerAddress).url)
        val deep = dispatchScan(configLink, ScanMode.CONFIG_LINK) as ScanOutcome.Accepted
        assertEquals("https://example.com", (deep.content as ScanContent.ServerAddress).url)
    }

    // ---------------- ENROLL ----------------

    @Test
    fun `ENROLL 只接受开户码`() {
        assertAccepted(enroll, ScanMode.ENROLL, ScanKind.ENROLL_CODE)
        for (other in listOf(plainServer, configLink, barePair, pairLink, otpauth, garbage)) {
            assertRejected(other, ScanMode.ENROLL, ScanReject.NOT_ENROLL_CODE)
        }
    }

    @Test
    fun `ENROLL 容忍小写与空格并规范化`() {
        val outcome = dispatchScan("  enroll-ab12 - cd34 ", ScanMode.ENROLL) as ScanOutcome.Accepted
        assertEquals(enroll, (outcome.content as ScanContent.EnrollCode).code)
    }

    // ---------------- PAIR ----------------

    @Test
    fun `PAIR 接受配对码与服务端地址`() {
        for (code in listOf(barePair, pairLink)) {
            assertAccepted(code, ScanMode.PAIR, ScanKind.PAIR_CODE)
        }
        for (server in listOf(plainServer, configLink)) {
            assertAccepted(server, ScanMode.PAIR, ScanKind.SERVER_ADDRESS)
        }
        for (other in listOf(enroll, otpauth, garbage)) {
            assertRejected(other, ScanMode.PAIR, ScanReject.NOT_PAIR_CODE)
        }
    }

    @Test
    fun `PAIR 深链优先判为配对码而非地址`() {
        // 同一张二维码在任何 mode 下类别一致：vkey://pair?code=…&server=… 是配对码
        assertAccepted(pairLink, ScanMode.PAIR, ScanKind.PAIR_CODE)
        val outcome = dispatchScan(pairLink, ScanMode.PAIR) as ScanOutcome.Accepted
        assertEquals(barePair, (outcome.content as ScanContent.PairCode).code)
    }

    // ---------------- TOTP ----------------

    @Test
    fun `TOTP 只接受 otpauth`() {
        assertAccepted(otpauth, ScanMode.TOTP, ScanKind.TOTP)
        for (other in listOf(plainServer, configLink, barePair, pairLink, enroll, garbage)) {
            assertRejected(other, ScanMode.TOTP, ScanReject.NOT_TOTP)
        }
    }

    // ---------------- AUTO ----------------

    @Test
    fun `AUTO 接受全部已知类别`() {
        assertAccepted(plainServer, ScanMode.AUTO, ScanKind.SERVER_ADDRESS)
        assertAccepted(configLink, ScanMode.AUTO, ScanKind.SERVER_ADDRESS)
        assertAccepted(barePair, ScanMode.AUTO, ScanKind.PAIR_CODE)
        assertAccepted(pairLink, ScanMode.AUTO, ScanKind.PAIR_CODE)
        assertAccepted(enroll, ScanMode.AUTO, ScanKind.ENROLL_CODE)
        assertAccepted(otpauth, ScanMode.AUTO, ScanKind.TOTP)
    }

    @Test
    fun `AUTO 对垃圾文本给通用未识别`() {
        assertRejected(garbage, ScanMode.AUTO, ScanReject.UNRECOGNIZED)
    }

    // ---------------- 空文本 ----------------

    @Test
    fun `空文本在所有 mode 下都是 EMPTY`() {
        for (mode in allModes) {
            assertRejected("", mode, ScanReject.EMPTY)
            assertRejected("   \n ", mode, ScanReject.EMPTY)
        }
    }

    // ---------------- 识别与 mode 无关 ----------------

    @Test
    fun `classifyScan 与 mode 无关且拒绝不越权`() {
        // 类别识别只跑一次、结果稳定
        assertEquals(ScanKind.SERVER_ADDRESS, classifyScan(plainServer)?.kind)
        assertEquals(ScanKind.PAIR_CODE, classifyScan(pairLink)?.kind)
        assertEquals(ScanKind.ENROLL_CODE, classifyScan(enroll)?.kind)
        assertEquals(ScanKind.TOTP, classifyScan(otpauth)?.kind)
        assertEquals(null, classifyScan(garbage))
        // 地址码在 ENROLL 模式下：识别成功但类别不符 → 报「这不是开户码」，绝不回调
        assertRejected(plainServer, ScanMode.ENROLL, ScanReject.NOT_ENROLL_CODE)
    }
}
