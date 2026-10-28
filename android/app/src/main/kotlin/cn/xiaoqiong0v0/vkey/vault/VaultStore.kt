package cn.xiaoqiong0v0.vkey.vault

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import kotlinx.serialization.json.Json
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * 功能：vault 的落盘读写。
 * 安全模型：明文 vault JSON 只用内存；磁盘上仅保存用 AndroidKeyStore（alias `vkey_vault`）
 * 的 AES-256-GCM 密钥加密后的 `{"v":1,"nonce":"..","ct":".."}` 封装。
 */
class VaultStore(private val context: Context) {

    /** 磁盘上的 vault 文件（filesDir/vault.json） */
    private val vaultFile: File = File(context.filesDir, VAULT_FILE_NAME)

    /** 引导确认状态用的 SharedPreferences */
    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /** JSON 编解码器（保留未知字段能力留给后续版本） */
    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        prettyPrint = false
    }

    /**
     * 功能：判断本地是否已有 vault。
     * @return 存在且非空时为 true
     */
    fun exists(): Boolean = vaultFile.exists() && vaultFile.length() > 0L

    /**
     * 功能：读取并解密 vault。
     * @return 明文 vault；文件不存在时返回 null
     * @throws IllegalStateException 密钥失效或密文损坏
     */
    fun load(): Vault? {
        if (!exists()) return null
        val envelope = json.decodeFromString(VaultEnvelope.serializer(), vaultFile.readText())
        val plain = unwrap(envelope)
        return json.decodeFromString(Vault.serializer(), plain.decodeToString())
    }

    /**
     * 功能：加密并原子写入 vault。
     * @param vault 待保存的明文 vault
     */
    fun save(vault: Vault) {
        val plain = json.encodeToString(Vault.serializer(), vault).toByteArray(Charsets.UTF_8)
        val envelope = wrap(plain)
        val text = json.encodeToString(VaultEnvelope.serializer(), envelope)
        // 先写临时文件再改名，避免掉电留下半截 JSON
        val tmp = File(vaultFile.parentFile, "$VAULT_FILE_NAME.tmp")
        tmp.writeText(text)
        if (vaultFile.exists() && !vaultFile.delete()) {
            Log.w(TAG, "旧 vault 删除失败，直接覆盖")
        }
        if (!tmp.renameTo(vaultFile)) {
            // 某些文件系统不允许直接改名覆盖，退回复制
            vaultFile.writeText(text)
            tmp.delete()
        }
    }

    /**
     * 功能：生成新的随机主密钥（32 字节）。
     * @return 32 字节随机数
     */
    fun newMasterKey(): ByteArray = ByteArray(MASTER_KEY_BYTES).also { SecureRandom().nextBytes(it) }

    /**
     * 功能：是否已完成恢复码「已保存」确认。
     * @return 已确认返回 true
     */
    fun isRecoveryConfirmed(): Boolean = prefs.getBoolean(KEY_RECOVERY_CONFIRMED, false)

    /**
     * 功能：标记恢复码已确认（强制引导通过后调用）。
     */
    fun markRecoveryConfirmed() {
        prefs.edit().putBoolean(KEY_RECOVERY_CONFIRMED, true).apply()
    }

    /**
     * 功能：获取（或首次创建）AndroidKeyStore 中的 AES-256-GCM 包裹密钥。
     * @return Keystore 内的对称密钥
     */
    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val existing = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
        if (existing != null) return existing.secretKey

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(KEY_SIZE_BITS)
                // 强制随机 IV：加密时不允许外部提供 IV，避免 nonce 复用
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return generator.generateKey()
    }

    /**
     * 功能：用 Keystore 密钥加密明文并封装为 envelope。
     * @param plain 明文字节
     * @return 含 nonce/ct 的封装
     */
    private fun wrap(plain: ByteArray): VaultEnvelope {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val cipherText = cipher.doFinal(plain)
        return VaultEnvelope(
            v = VaultEnvelope.CURRENT_VERSION,
            nonce = Base64.getEncoder().encodeToString(cipher.iv),
            ct = Base64.getEncoder().encodeToString(cipherText),
        )
    }

    /**
     * 功能：解密 envelope 得到明文。
     * @param envelope 磁盘封装
     * @return 明文字节
     * @throws IllegalStateException 密钥失效或认证标签校验失败
     */
    private fun unwrap(envelope: VaultEnvelope): ByteArray {
        val iv = Base64.getDecoder().decode(envelope.nonce)
        val cipherText = Base64.getDecoder().decode(envelope.ct)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
        return try {
            cipher.doFinal(cipherText)
        } catch (e: Exception) {
            // 不打印任何密文/密钥，只记录失败类型
            Log.e(TAG, "vault 解密失败：${e.javaClass.simpleName}")
            throw IllegalStateException("本机密钥已失效或数据损坏（${e.javaClass.simpleName}）", e)
        }
    }

    companion object {
        /** 日志标签 */
        private const val TAG: String = "VaultStore"

        /** 磁盘文件名 */
        const val VAULT_FILE_NAME: String = "vault.json"

        /** Keystore 别名（方案 §2 固定） */
        private const val KEY_ALIAS: String = "vkey_vault"

        /** Keystore provider 名 */
        private const val KEYSTORE_PROVIDER: String = "AndroidKeyStore"

        /** 变换：AES/GCM/NoPadding */
        private const val TRANSFORMATION: String = "AES/GCM/NoPadding"

        /** 密钥长度（位） */
        private const val KEY_SIZE_BITS: Int = 256

        /** GCM 认证标签长度（位） */
        private const val GCM_TAG_BITS: Int = 128

        /** 主密钥字节数（32B = 256bit，编码后 52 个 Base32 字符） */
        const val MASTER_KEY_BYTES: Int = 32

        /** SharedPreferences 文件名 */
        private const val PREFS_NAME: String = "vkey_prefs"

        /** 「恢复码已保存」确认标记 */
        private const val KEY_RECOVERY_CONFIRMED: String = "recovery_confirmed"
    }
}
