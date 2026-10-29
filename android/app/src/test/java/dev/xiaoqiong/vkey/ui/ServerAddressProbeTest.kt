package dev.xiaoqiong.vkey.ui

import dev.xiaoqiong.vkey.ui.ServerProbe.Unreachable.Reason
import java.io.InterruptedIOException
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 服务端地址探测的纯函数测试。
 *
 * 覆盖：超时 / DNS / 其它网络错误 / 非法地址 → 失败原因；HTTP 状态码 → 可用性；
 * 探测 URL 拼接；「已配置且地址变化 → 需要清绑定」的判定。
 */
class ServerAddressProbeTest {

    @Test
    fun timeoutExceptionsMapToTimeout() {
        assertEquals(Reason.TIMEOUT, probeFailureOf(SocketTimeoutException("timeout")))
        // OkHttp 的 callTimeout 抛的是 InterruptedIOException（父类）而非 SocketTimeoutException
        assertEquals(Reason.TIMEOUT, probeFailureOf(InterruptedIOException("timeout")))
    }

    @Test
    fun unknownHostMapsToDns() {
        assertEquals(Reason.DNS, probeFailureOf(UnknownHostException("vkey.invalid")))
    }

    @Test
    fun otherIoErrorsMapToNetwork() {
        assertEquals(Reason.NETWORK, probeFailureOf(ConnectException("Connection refused")))
    }

    @Test
    fun illegalUrlMapsToInvalid() {
        assertEquals(Reason.INVALID_URL, probeFailureOf(IllegalArgumentException("bad url")))
    }

    @Test
    fun probeUrlRequiresHttpScheme() {
        assertNull(policyProbeUrl(""))
        assertNull(policyProbeUrl("vkey.example.com"))
        assertNull(policyProbeUrl("ftp://vkey.example.com"))
        // 只有协议头、没有 host：OkHttp 解析失败，按非法地址处理
        assertNull(policyProbeUrl("http://"))
    }

    @Test
    fun probeUrlJoinsPolicyPathAndDropsTrailingSlash() {
        assertEquals(
            "http://10.0.2.2:3150/api/v1/policy",
            policyProbeUrl(" http://10.0.2.2:3150/ ")?.toString(),
        )
        assertEquals(
            "https://vkey.example.com/api/v1/policy",
            policyProbeUrl("HTTPS://vkey.example.com")?.toString(),
        )
    }

    @Test
    fun twoHundredRangeIsReachable() {
        assertTrue(probeResultOfStatus(200) is ServerProbe.Reachable)
        assertTrue(probeResultOfStatus(204) is ServerProbe.Reachable)
    }

    @Test
    fun non2xxMapsToHttpStatusWithCode() {
        val notFound = probeResultOfStatus(404) as ServerProbe.Unreachable
        assertEquals(Reason.HTTP_STATUS, notFound.reason)
        assertEquals(404, notFound.status ?: 0)
        assertEquals(Reason.HTTP_STATUS, (probeResultOfStatus(500) as ServerProbe.Unreachable).reason)
        assertEquals(Reason.HTTP_STATUS, (probeResultOfStatus(301) as ServerProbe.Unreachable).reason)
    }

    @Test
    fun rebindOnlyWhenConfiguredAndAddressReallyChanged() {
        // 未配置：只保存地址，不动其它状态
        assertFalse(requiresDeviceRebind(null, "https://a.example.com"))
        // 地址没变（只差空白 / 尾部斜杠）：不需要清绑定
        assertFalse(requiresDeviceRebind("https://a.example.com", " https://a.example.com/ "))
        // 主机或协议变化：token 属于旧服务器，必须重新登录 / 配对
        assertTrue(requiresDeviceRebind("https://a.example.com", "https://b.example.com"))
        assertTrue(requiresDeviceRebind("https://a.example.com", "http://a.example.com"))
    }
}
