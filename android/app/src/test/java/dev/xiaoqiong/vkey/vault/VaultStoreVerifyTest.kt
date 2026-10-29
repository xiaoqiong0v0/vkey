package dev.xiaoqiong.vkey.vault

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [persistedMatches]（写盘后读回比对）的单元测试。
 *
 * 这是 `VaultStore.writeAndVerify` 的判定核心：enroll/配对成功后必须
 * 读回比对 master_key 与 device_id 一致，才算真正落盘。
 */
class VaultStoreVerifyTest {

    /** 构造带设备材料的期望库。 */
    private fun expected(deviceId: String = "dev-1"): VaultData = VaultData(
        master_key = "A".repeat(52),
        device = DeviceConfig(
            server_url = "http://10.0.2.2:3150",
            device_id = deviceId,
            device_name = "Android test",
            username = "fix1",
            seed = "s".repeat(43),
            token = "t".repeat(43),
        ),
    )

    /** master_key 与 device_id 都一致时判定通过。 */
    @Test
    fun matchesWhenBothKeysEqual() {
        assertTrue(persistedMatches(expected(), expected()))
    }

    /** 读回失败（null）必须判定不通过，不得静默。 */
    @Test
    fun failsWhenReadBackNull() {
        assertFalse(persistedMatches(expected(), null))
    }

    /** 读回缺少 device（写了个寂寞）判定不通过。 */
    @Test
    fun failsWhenReadBackLostDevice() {
        assertFalse(persistedMatches(expected(), expected().copy(device = null)))
    }

    /** device_id 不一致（磁盘仍是旧配置）判定不通过。 */
    @Test
    fun failsWhenDeviceIdDiffers() {
        assertFalse(persistedMatches(expected("dev-1"), expected("dev-2")))
    }

    /** master_key 不一致（账号密钥没写进去）判定不通过。 */
    @Test
    fun failsWhenMasterKeyDiffers() {
        assertFalse(persistedMatches(expected(), expected().copy(master_key = "B".repeat(52))))
    }

    /** 未配置设备的库（device 两侧都为 null）只要主密钥一致即通过。 */
    @Test
    fun passesWhenBothDeviceNull() {
        val plain = VaultData(master_key = "A".repeat(52))
        assertTrue(persistedMatches(plain, plain.copy(items = listOf(
            TotpItem(id = "i1", issuer = "x", account = "y", secret = "JBSWY3DPEHPK3PXP"),
        ))))
    }
}
