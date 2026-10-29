package dev.xiaoqiong.vkey.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 服务器地址校验测试（[isValidServerUrl]）。
 *
 * 背景：发行版不再内置默认生产域名（[dev.xiaoqiong.vkey.vault.AppSettings] 的
 * serverUrl 默认为空串），所有发起请求前的入口必须先通过该校验。
 */
class ServerUrlValidationTest {

    @Test
    fun acceptsHttpAndHttpsPrefixes() {
        assertTrue(isValidServerUrl("http://10.0.2.2:3150"))
        assertTrue(isValidServerUrl("https://vkey.example.com"))
        // 协议头大小写不限（保存前已 trim）
        assertTrue(isValidServerUrl("HTTPS://VKEY.Example.com"))
    }

    @Test
    fun rejectsEmptyAndForeignSchemes() {
        // 空值 = 未配置：绝不能当作可发起请求的地址
        assertFalse(isValidServerUrl(""))
        assertFalse(isValidServerUrl("vkey.example.com"))
        assertFalse(isValidServerUrl("ftp://vkey.example.com"))
        assertFalse(isValidServerUrl("vkey://config?server=https://a.b"))
    }
}
