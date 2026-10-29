package dev.xiaoqiong.vkey.vault

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import kotlinx.serialization.json.Json
import java.io.File
import java.io.IOException
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * 本地库的读写：用 Android Keystore 的 AES-256-GCM 密钥包裹 `VaultData`。
 *
 * 设计说明（对应 docs/android.md §2.3）：
 * - 磁盘上只有 `SealedVault`（nonce + 密文），**任何明文 secret 都不落盘**；
 * - 主密钥与条目都在同一份 vault 里，解锁时一次性解到内存；
 * - Keystore 密钥失效（移除锁屏/恢复出厂）会导致旧 vault 不可解，因此首次引导强制保存恢复码。
 */
class VaultStore(private val dir: File) {

    private companion object {
        const val KEY_ALIAS = "vkey_vault"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val FILE_NAME = "vault.json"
        const val GCM_TAG_BITS = 128
    }

    private val json = Json { ignoreUnknownKeys = true; prettyPrint = false }

    private val file: File get() = File(dir, FILE_NAME)

    /** 是否已有可用于解密的 vault 文件。 */
    fun exists(): Boolean = file.exists()

    /** 生成 32B 主密钥并返回其 Base32 恢复码（52 字符）。 */
    fun generateMasterKey(): String {
        val raw = ByteArray(32)
        SecureRandom().nextBytes(raw)
        return Base32.encode(raw)
    }

    /** 首次创建库。 */
    fun create(masterKeyBase32: String): VaultData {
        val data = VaultData(master_key = masterKeyBase32)
        write(data)
        return data
    }

    /** 读取并解密；失败（Keystore 失效/文件损坏）返回 null。 */
    fun read(): VaultData? {
        if (!file.exists()) return null
        return try {
            val sealed = json.decodeFromString(SealedVault.serializer(), file.readText())
            val nonce = Base64.decode(sealed.nonce, Base64.NO_WRAP)
            val ct = Base64.decode(sealed.ct, Base64.NO_WRAP)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(GCM_TAG_BITS, nonce))
            val plain = cipher.doFinal(ct)
            json.decodeFromString(VaultData.serializer(), String(plain, Charsets.UTF_8))
        } catch (t: Throwable) {
            null
        }
    }

    /** 加密并落盘（原子替换：先写临时文件再 rename）。 */
    fun write(data: VaultData) {
        val plain = json.encodeToString(VaultData.serializer(), data).toByteArray(Charsets.UTF_8)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey())
        val ct = cipher.doFinal(plain)
        val sealed = SealedVault(
            nonce = Base64.encodeToString(cipher.iv, Base64.NO_WRAP),
            ct = Base64.encodeToString(ct, Base64.NO_WRAP),
        )
        val tmp = File(dir, "$FILE_NAME.tmp")
        tmp.writeText(json.encodeToString(SealedVault.serializer(), sealed))
        if (!tmp.renameTo(file)) {
            file.delete()
            // 兜底 rename 仍失败必须抛错：否则磁盘停留在旧内容、调用方却以为已保存
            if (!tmp.renameTo(file)) {
                tmp.delete()
                throw IOException("vault.json replace failed (renameTo=false)")
            }
        }
    }

    /**
     * 落盘并读回校验：任何一步失败都抛异常，**绝不静默**。
     *
     * 校验口径：[write] 成功后重新 [read]，用 [persistedMatches] 比对
     * master_key 与 device_id（device_id 为服务端唯一 id，读回一致即证明
     * 本次配置真正落盘且 Keystore 链路可用）。
     *
     * @param data 期望落盘的库内容
     * @throws IOException 写入失败、读回解密失败或读回内容与期望不一致
     */
    fun writeAndVerify(data: VaultData) {
        write(data)
        val back = read() ?: throw IOException("vault read-back failed after write")
        if (!persistedMatches(data, back)) {
            throw IOException("vault read-back mismatch (master_key or device_id)")
        }
    }

    /** 取（或首次创建）Keystore 里的 AES-256-GCM 密钥。 */
    private fun secretKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (ks.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                // 本轮不做生物识别绑定（M3.3 再开认证绑定），保证首次可用性
                .build(),
        )
        return generator.generateKey()
    }
}

/**
 * 读回校验的纯函数部分：读回库必须与期望库同主密钥，且设备标识一致。
 *
 * @param expected 期望落盘的库
 * @param back 实际读回的库；null（解密/解析失败）视为不匹配
 * @return 一致时 true
 */
internal fun persistedMatches(expected: VaultData, back: VaultData?): Boolean =
    back != null &&
    back.master_key == expected.master_key &&
    back.device?.device_id == expected.device?.device_id
