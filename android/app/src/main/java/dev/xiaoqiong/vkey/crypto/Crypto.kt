package dev.xiaoqiong.vkey.crypto

import dev.xiaoqiong.vkey.vault.Base32
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/**
 * vkey 协议的密码学原语与编码规则。
 *
 * 本对象是 `shared/protocol.md` 的 Kotlin 实现，与服务端 `server/internal/crypto`
 * 必须逐字节一致；`shared/vectors` 下的 JSON 文件是交叉验证向量。
 *
 * 约定：master_key / verifier / item_key / KEK 均为 32B；AEAD 为 AES-256-GCM，
 * nonce 12B，tag 16B；二进制字段线上编码为 base64url 无填充。
 */
object Crypto {

    /** 对称密钥（master_key / verifier / item_key / KEK）字节长度。 */
    const val KEY_LEN: Int = 32

    /** AES-256-GCM 的 nonce 字节长度。 */
    const val NONCE_LEN: Int = 12

    /** AES-256-GCM 的认证标签字节长度。 */
    const val TAG_LEN: Int = 16

    /** 设备 token 的随机字节长度。 */
    const val TOKEN_LEN: Int = 32

    /** 配对码原始值的字节长度。 */
    const val PAIR_CODE_LEN: Int = 32

    /** Ed25519 私钥种子的字节长度。 */
    const val ED25519_SEED_LEN: Int = 32

    /** Ed25519 原始公钥的字节长度。 */
    const val ED25519_PUBLIC_KEY_LEN: Int = 32

    /** Ed25519 原始签名的字节长度。 */
    const val ED25519_SIGNATURE_LEN: Int = 64

    /** verifier 的 HKDF salt（UTF-8）。 */
    const val SALT_VERIFIER: String = "vkey-verifier"

    /** item_key 的 HKDF salt（UTF-8）。 */
    const val SALT_ITEM: String = "vkey-item"

    /** 配对 KEK 的 HKDF salt（UTF-8）。 */
    const val SALT_PAIR: String = "vkey-pair"

    /** 条目 AEAD 的 AAD 前缀，其后拼接 item_id。 */
    const val AAD_ITEM_PREFIX: String = "vkey-item|"

    private const val HMAC_ALGORITHM = "HmacSHA256"
    private const val AES_TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128
    private const val SHA256_LEN = 32
    private const val HEX_DIGITS = "0123456789abcdef"

    // ------------------------------------------------------------------
    // 密钥派生
    // ------------------------------------------------------------------

    /**
     * 用 HKDF-SHA256（RFC 5869）派生密钥。
     *
     * @param ikm 输入密钥材料
     * @param salt HKDF salt 的原始字节（不做补零/截断；为空时按 RFC 使用 32B 零串）
     * @param info HKDF info 的原始字节
     * @param length 输出长度，取值 1..8160
     * @return 长度为 [length] 的派生密钥
     */
    fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..(255 * SHA256_LEN)) { "HKDF 输出长度非法: $length" }
        val effectiveSalt = if (salt.isEmpty()) ByteArray(SHA256_LEN) else salt
        val prk = hmacSha256(effectiveSalt, ikm)
        val out = ByteArray(length)
        var previous = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            val mac = Mac.getInstance(HMAC_ALGORITHM)
            mac.init(SecretKeySpec(prk, HMAC_ALGORITHM))
            mac.update(previous)
            mac.update(info)
            mac.update(counter.toByte())
            previous = mac.doFinal()
            val n = minOf(previous.size, length - offset)
            System.arraycopy(previous, 0, out, offset, n)
            offset += n
            counter++
        }
        return out
    }

    /**
     * 计算登录校验值：`HKDF-SHA256(master_key, "vkey-verifier", username, 32)`。
     *
     * @param masterKey 32B master_key
     * @param username 账号名原文（UTF-8，不做归一化）
     * @return 32B verifier
     */
    fun verifier(masterKey: ByteArray, username: String): ByteArray {
        requireKey(masterKey, "master_key")
        return hkdfSha256(masterKey, SALT_VERIFIER.toUtf8(), username.toUtf8(), KEY_LEN)
    }

    /**
     * 计算条目密钥：`HKDF-SHA256(master_key, "vkey-item", item_id, 32)`。
     *
     * @param masterKey 32B master_key
     * @param itemId 条目 id（UTF-8）
     * @return 32B item_key
     */
    fun itemKey(masterKey: ByteArray, itemId: String): ByteArray {
        requireKey(masterKey, "master_key")
        require(itemId.isNotEmpty()) { "item_id 不能为空" }
        return hkdfSha256(masterKey, SALT_ITEM.toUtf8(), itemId.toUtf8(), KEY_LEN)
    }

    /**
     * 计算配对密钥：`HKDF-SHA256(code_bytes, "vkey-pair", code_id, 32)`。
     *
     * @param codeBytes 32B 配对码原始值
     * @param codeId 配对会话 id（UTF-8）
     * @return 32B KEK
     */
    fun pairKek(codeBytes: ByteArray, codeId: String): ByteArray {
        require(codeBytes.size == PAIR_CODE_LEN) { "配对码必须 $PAIR_CODE_LEN 字节，实际 ${codeBytes.size}" }
        require(codeId.isNotEmpty()) { "code_id 不能为空" }
        return hkdfSha256(codeBytes, SALT_PAIR.toUtf8(), codeId.toUtf8(), KEY_LEN)
    }

    // ------------------------------------------------------------------
    // 条目 AEAD
    // ------------------------------------------------------------------

    /**
     * 返回条目 AEAD 的附加认证数据：`UTF8("vkey-item|" + itemId)`。
     *
     * @param itemId 条目 id
     * @return AAD 字节
     */
    fun itemAad(itemId: String): ByteArray = (AAD_ITEM_PREFIX + itemId).toUtf8()

    /**
     * 加密条目明文：AES-256-GCM(item_key, nonce, plaintext, aad="vkey-item|"+itemId)。
     *
     * @param masterKey 32B master_key
     * @param itemId 条目 id
     * @param plaintext 条目明文（UTF-8 JSON 字节）
     * @param nonce 12B nonce
     * @return `ciphertext || tag`（不含 nonce）
     */
    fun sealItem(masterKey: ByteArray, itemId: String, plaintext: ByteArray, nonce: ByteArray): ByteArray {
        return seal(itemKey(masterKey, itemId), nonce, plaintext, itemAad(itemId))
    }

    /**
     * 解密条目密文。
     *
     * @param masterKey 32B master_key
     * @param itemId 条目 id
     * @param ciphertext `ciphertext || tag`
     * @param nonce 12B nonce
     * @return 条目明文
     * @throws javax.crypto.AEADBadTagException 密文/AAD 被篡改时
     */
    fun openItem(masterKey: ByteArray, itemId: String, ciphertext: ByteArray, nonce: ByteArray): ByteArray {
        return open(itemKey(masterKey, itemId), nonce, ciphertext, itemAad(itemId))
    }

    // ------------------------------------------------------------------
    // 配对 blob（自包含布局）
    // ------------------------------------------------------------------

    /**
     * 生成配对 blob：`nonce(12B) || AES-256-GCM(kek, nonce, master_key, aad=∅) || tag`。
     *
     * @param kek 32B 配对 KEK
     * @param masterKey 32B master_key
     * @param nonce 12B nonce
     * @return 自包含 blob
     */
    fun sealPairBlob(kek: ByteArray, masterKey: ByteArray, nonce: ByteArray): ByteArray {
        requireKey(masterKey, "master_key")
        val sealed = seal(kek, nonce, masterKey, ByteArray(0))
        return nonce + sealed
    }

    /**
     * 解开配对 blob，返回其中的 master_key。
     *
     * @param kek 32B 配对 KEK
     * @param blob `nonce(12B) || ciphertext || tag`
     * @return 32B master_key
     */
    fun openPairBlob(kek: ByteArray, blob: ByteArray): ByteArray {
        require(blob.size >= NONCE_LEN + TAG_LEN) { "配对 blob 过短: ${blob.size}" }
        val nonce = blob.copyOfRange(0, NONCE_LEN)
        val body = blob.copyOfRange(NONCE_LEN, blob.size)
        val plain = open(kek, nonce, body, ByteArray(0))
        requireKey(plain, "master_key")
        return plain
    }

    // ------------------------------------------------------------------
    // 低层 AEAD
    // ------------------------------------------------------------------

    /**
     * AES-256-GCM 加密。
     *
     * @param key 32B 密钥
     * @param nonce 12B nonce
     * @param plaintext 明文
     * @param aad 附加认证数据（可为空）
     * @return `ciphertext || tag`
     */
    fun seal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        return gcm(Cipher.ENCRYPT_MODE, key, nonce, plaintext, aad)
    }

    /**
     * AES-256-GCM 解密。
     *
     * @param key 32B 密钥
     * @param nonce 12B nonce
     * @param ciphertext `ciphertext || tag`
     * @param aad 必须与加密时一致
     * @return 明文
     */
    fun open(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray {
        return gcm(Cipher.DECRYPT_MODE, key, nonce, ciphertext, aad)
    }

    // ------------------------------------------------------------------
    // 设备签名（Ed25519）
    // ------------------------------------------------------------------

    /**
     * 由 32B 种子派生 Ed25519 原始公钥（不带 SPKI 头）。
     *
     * @param seed 32B 私钥种子
     * @return 32B 原始公钥
     */
    fun ed25519PublicKey(seed: ByteArray): ByteArray {
        require(seed.size == ED25519_SEED_LEN) { "Ed25519 种子必须 $ED25519_SEED_LEN 字节" }
        return Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded
    }

    /**
     * 用 Ed25519 私钥种子签名。
     *
     * @param seed 32B 私钥种子
     * @param message 待签名消息
     * @return 64B 原始签名
     */
    fun ed25519Sign(seed: ByteArray, message: ByteArray): ByteArray {
        require(seed.size == ED25519_SEED_LEN) { "Ed25519 种子必须 $ED25519_SEED_LEN 字节" }
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(seed, 0))
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    /**
     * 校验 Ed25519 签名。
     *
     * @param publicKey 32B 原始公钥
     * @param message 原文
     * @param signature 64B 原始签名
     * @return 长度非法或校验不通过时为 false
     */
    fun ed25519Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != ED25519_PUBLIC_KEY_LEN || signature.size != ED25519_SIGNATURE_LEN) return false
        val signer = Ed25519Signer()
        signer.init(false, Ed25519PublicKeyParameters(publicKey, 0))
        signer.update(message, 0, message.size)
        return signer.verifySignature(signature)
    }

    /**
     * 构造设备签名串（精确格式，各部分之间单个 `\n`，末尾无换行）：
     * `METHOD \n RequestURI \n hex(sha256(body)) \n decimal(ts)`。
     *
     * @param method HTTP 方法原文（大写）
     * @param requestUri 原始 RequestURI（含 query，不含 scheme/host，不重排）
     * @param body 发送的原始请求体；无 body 传空数组
     * @param ts unix 秒
     * @return 签名串文本
     */
    fun signingString(method: String, requestUri: String, body: ByteArray, ts: Long): String {
        return method + "\n" + requestUri + "\n" + hex(sha256(body)) + "\n" + ts.toString()
    }

    // ------------------------------------------------------------------
    // 哈希 / 编码
    // ------------------------------------------------------------------

    /**
     * 计算 SHA-256 摘要。
     *
     * @param data 输入数据
     * @return 32B 摘要
     */
    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    /**
     * 编码为 base64url 无填充（协议中所有二进制字段的线上形式）。
     *
     * @param data 原始字节
     * @return base64url 文本
     */
    fun b64urlEncode(data: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(data)

    /**
     * 解析 base64url 无填充文本（容忍首尾空白）。
     *
     * @param text base64url 文本
     * @return 原始字节
     * @throws IllegalArgumentException 编码非法时
     */
    fun b64urlDecode(text: String): ByteArray = Base64.getUrlDecoder().decode(text.trim())

    /**
     * 编码为 base32 大写无填充（复用 [Base32]）。
     *
     * @param data 原始字节
     * @return base32 文本
     */
    fun base32Encode(data: ByteArray): String = Base32.encode(data)

    /**
     * 解析 base32（容忍小写、`-`、空白与 `=` 填充）。
     *
     * @param text base32 文本
     * @return 原始字节
     * @throws IllegalArgumentException 编码非法时
     */
    fun base32Decode(text: String): ByteArray =
        Base32.decode(text) ?: throw IllegalArgumentException("base32 编码非法")

    /**
     * 解析配对码（容忍分组符/小写/填充），结果必须恰好 32B。
     *
     * @param text 用户输入或线上规范形式
     * @return 32B 配对码原始值
     */
    fun parsePairCode(text: String): ByteArray {
        val code = base32Decode(text)
        require(code.size == PAIR_CODE_LEN) { "配对码必须 $PAIR_CODE_LEN 字节，实际 ${code.size}" }
        return code
    }

    /**
     * 把 32B 配对码格式化为人类可读形式：base32 大写无填充，每 4 字符用 `-` 连接。
     *
     * @param code 32B 配对码
     * @return 展示形式（13 组）
     */
    fun formatPairCode(code: ByteArray): String {
        val encoded = Base32.encode(code)
        return encoded.chunked(4).joinToString("-")
    }

    /**
     * 生成 n 字节密码学随机数。
     *
     * @param n 字节数，必须 > 0
     * @return 随机字节
     */
    fun random(n: Int): ByteArray {
        require(n > 0) { "随机数长度必须 > 0" }
        val out = ByteArray(n)
        java.security.SecureRandom().nextBytes(out)
        return out
    }

    // ------------------------------------------------------------------
    // 私有实现
    // ------------------------------------------------------------------

    /** 计算 HMAC-SHA256。 */
    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        mac.init(SecretKeySpec(key, HMAC_ALGORITHM))
        return mac.doFinal(data)
    }

    /** 执行一次 AES-256-GCM 加/解密。 */
    private fun gcm(mode: Int, key: ByteArray, nonce: ByteArray, input: ByteArray, aad: ByteArray): ByteArray {
        require(key.size == KEY_LEN) { "密钥必须 $KEY_LEN 字节，实际 ${key.size}" }
        require(nonce.size == NONCE_LEN) { "nonce 必须 $NONCE_LEN 字节，实际 ${nonce.size}" }
        val cipher = Cipher.getInstance(AES_TRANSFORMATION)
        cipher.init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        return cipher.doFinal(input)
    }

    /** 校验 32B 定长密钥。 */
    private fun requireKey(key: ByteArray, name: String) {
        require(key.size == KEY_LEN) { "$name 必须 $KEY_LEN 字节，实际 ${key.size}" }
    }

    /** 把字节数组编码为小写十六进制。 */
    private fun hex(data: ByteArray): String {
        val sb = StringBuilder(data.size * 2)
        for (b in data) {
            val v = b.toInt() and 0xFF
            sb.append(HEX_DIGITS[v ushr 4]).append(HEX_DIGITS[v and 0x0F])
        }
        return sb.toString()
    }

    /** 字符串按 UTF-8 转字节（不做 Unicode 归一化）。 */
    private fun String.toUtf8(): ByteArray = toByteArray(Charsets.UTF_8)
}
