package dev.xiaoqiong.vkey.vault

import kotlinx.serialization.Serializable

/**
 * 本机作为「已登录设备」的同步材料（随 [VaultData] 一起用 Keystore 加密落盘）。
 *
 * 设计说明：设备材料与库共用一个 vault 文件（`vault.json`），因此
 * - 只有一份 Keystore 密钥、一次原子写入，不需要维护第二个加密文件的生命周期；
 * - 与条目一样只在解锁后可用，磁盘上永远没有明文 seed / token。
 *
 * @property server_url 同步服务地址（不含尾部斜杠）
 * @property device_id 服务端设备 id（base64url 16B）
 * @property device_name 设备名（1..128 字节）
 * @property username 账号名原文（verifier 的 HKDF info）
 * @property seed Ed25519 私钥种子（base64url 32B）
 * @property token 设备 token（base64url 32B）
 *
 * 同步游标不在这里：它描述的是「库」的进度而非设备身份，故上移到
 * [VaultData.seq]（旧 vault 里残留的 `device.seq` 在读取时被忽略）。
 */
@Serializable
data class DeviceConfig(
    val server_url: String,
    val device_id: String,
    val device_name: String,
    val username: String,
    val seed: String,
    val token: String,
)
