package dev.xiaoqiong.vkey.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 账号页「接入方式」选择状态机测试（[ConnectFormState] / [ConnectMode]）。
 *
 * 口径：三种方式互斥，一屏只渲染当前方式的表单；切换方式清空全部输入，
 * 深链 / 扫码只预填对应方式的码，绝不把另一个方式的残留带进表单。
 */
class ConnectModeStateTest {

    @Test
    fun defaultModeIsMasterKey() {
        // 默认停在 master_key（多数用户是从旧设备带恢复码过来）
        val form = ConnectFormState()
        assertEquals(ConnectMode.MASTER_KEY, form.mode)
        assertEquals(ConnectFormState.DEFAULT_MODE, form.mode)
        assertEquals(ConnectMode.MASTER_KEY, ConnectFormState.DEFAULT_MODE)
        assertEquals("", form.masterKey)
        assertEquals("", form.pairCode)
        assertEquals("", form.enrollCode)
        assertEquals("", form.enrollUsername)
    }

    @Test
    fun switchingToAnotherModeClearsAllInputs() {
        // 已填好 master_key 后切到开户码：方式变化且两个方式的输入都被清空（互斥、无残留）
        val filled = ConnectFormState(masterKey = "AAAA", pairCode = "BBBB", enrollCode = "ENROLL-1234-5678", enrollUsername = "alice")
        val switched = filled.select(ConnectMode.ENROLL)
        assertEquals(ConnectMode.ENROLL, switched.mode)
        // 换方式后所有输入清空（互斥表单不会带上另一方式的残留）
        assertEquals(ConnectFormState(mode = ConnectMode.ENROLL), switched)
        assertEquals("", switched.masterKey)
        assertEquals("", switched.enrollCode)
        assertEquals("", switched.enrollUsername)
    }

    @Test
    fun selectingCurrentModeKeepsInput() {
        // 重复点当前方式不重置：避免误触把已输入的码清掉
        val filled = ConnectFormState(mode = ConnectMode.PAIR, pairCode = "ABCD")
        assertEquals(filled, filled.select(ConnectMode.PAIR))
    }

    @Test
    fun enrollPrefillSwitchesToEnrollMode() {
        // 开户深链：方式切到「开户码」，只保留该码与用户名
        val form = ConnectFormState.fromPrefill(
            pairCode = null,
            enrollCode = "ENROLL-1234-5678",
            enrollUsername = "alice",
        )
        assertEquals(ConnectMode.ENROLL, form.mode)
        assertEquals("ENROLL-1234-5678", form.enrollCode)
        assertEquals("alice", form.enrollUsername)
        assertEquals("", form.masterKey)
        assertEquals("", form.pairCode)
    }

    @Test
    fun enrollPrefillWithoutUsernameKeepsItEmpty() {
        // 裸开户码（无用户名）也切方式，但用户名留空由用户填
        val form = ConnectFormState.fromPrefill(pairCode = null, enrollCode = "ENROLL-1234-5678", enrollUsername = null)
        assertEquals(ConnectMode.ENROLL, form.mode)
        assertEquals("ENROLL-1234-5678", form.enrollCode)
        assertEquals("", form.enrollUsername)
    }

    @Test
    fun pairPrefillSwitchesToPairMode() {
        // 配对深链：方式切到「配对码」，其它方式输入为空
        val form = ConnectFormState.fromPrefill(pairCode = "ABCD-EFGH", enrollCode = null, enrollUsername = null)
        assertEquals(ConnectMode.PAIR, form.mode)
        assertEquals("ABCD-EFGH", form.pairCode)
        assertEquals("", form.masterKey)
        assertEquals("", form.enrollCode)
    }

    @Test
    fun blankPairCodeKeepsDefaultMode() {
        // 空配对码不算预填（例如页面复用时 syncPrefill 被清空）
        val form = ConnectFormState.fromPrefill(pairCode = "", enrollCode = null, enrollUsername = "")
        assertEquals(ConnectMode.MASTER_KEY, form.mode)
        assertEquals(ConnectFormState(), form)
    }

    @Test
    fun enrollPrefillWinsOverPairCode() {
        // 两种预填同时存在：开户更具体，优先
        val form = ConnectFormState.fromPrefill(
            pairCode = "ABCD",
            enrollCode = "ENROLL-1234-5678",
            enrollUsername = "alice",
        )
        assertEquals(ConnectMode.ENROLL, form.mode)
        assertEquals("", form.pairCode)
    }

    @Test
    fun everyModeMapsToItsOwnScanMode() {
        // 每种表单内的「扫码」只解析该方式对应的码
        assertEquals(ScanMode.CONFIG_LINK, ConnectMode.MASTER_KEY.scanMode())
        assertEquals(ScanMode.PAIR, ConnectMode.PAIR.scanMode())
        assertEquals(ScanMode.ENROLL, ConnectMode.ENROLL.scanMode())
        assertTrue(ConnectMode.entries.all { it.titleRes() != it.descRes() })
    }
}
