package dev.xiaoqiong.vkey.crypto

import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * 用 `shared/vectors` 下的 JSON 向量逐字节验证 [Crypto]。
 *
 * 向量目录由 `app/build.gradle.kts` 通过系统属性 `vkey.vectorsDir` 注入，
 * 直接读仓库原文，不复制副本。
 */
class CryptoVectorsTest {

    @Test
    fun verifierMatchesVector() {
        val v = vector("kdf", "verifier")
        val masterKey = hex(v.inputs.str("master_key_hex"))
        val username = v.inputs.str("username")

        val actual = Crypto.verifier(masterKey, username)

        assertEquals(v.expected.str("verifier_b64url"), Crypto.b64urlEncode(actual))
    }

    @Test
    fun itemKeyMatchesVector() {
        val v = vector("kdf", "item_key")
        val masterKey = hex(v.inputs.str("master_key_hex"))
        val itemId = v.inputs.str("item_id")

        val actual = Crypto.itemKey(masterKey, itemId)

        assertEquals(v.expected.str("item_key_b64url"), Crypto.b64urlEncode(actual))
    }

    @Test
    fun pairKekMatchesVector() {
        val v = vector("kdf", "pair_kek")
        val code = hex(v.inputs.str("code_hex"))
        val codeId = v.inputs.str("code_id")

        val actual = Crypto.pairKek(code, codeId)

        assertEquals(v.expected.str("kek_b64url"), Crypto.b64urlEncode(actual))
    }

    @Test
    fun hkdfMatchesRfc5869TestCaseOne() {
        // RFC 5869 A.1：独立于本项目向量，用于确认 HKDF 实现本身正确。
        val ikm = hex("0b".repeat(22))
        val salt = hex("000102030405060708090a0b0c")
        val info = hex("f0f1f2f3f4f5f6f7f8f9")
        val expected = hex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )

        val actual = Crypto.hkdfSha256(ikm, salt, info, expected.size)

        assertArrayEquals(expected, actual)
    }

    @Test
    fun itemCiphertextMatchesVector() {
        val v = vector("aead", "item_ciphertext")
        val masterKey = hex(v.inputs.str("master_key_hex"))
        val itemId = v.inputs.str("item_id")
        val nonce = hex(v.inputs.str("nonce_hex"))
        val plaintext = v.inputs.str("plaintext_utf8").toByteArray(Charsets.UTF_8)

        assertArrayEquals(v.inputs.str("aad_utf8").toByteArray(Charsets.UTF_8), Crypto.itemAad(itemId))

        val ciphertext = Crypto.sealItem(masterKey, itemId, plaintext, nonce)

        assertEquals(v.expected.str("ciphertext_b64url"), Crypto.b64urlEncode(ciphertext))
        assertArrayEquals(plaintext, Crypto.openItem(masterKey, itemId, ciphertext, nonce))
    }

    @Test
    fun openItemRejectsForeignItemId() {
        val v = vector("aead", "item_ciphertext")
        val masterKey = hex(v.inputs.str("master_key_hex"))
        val nonce = hex(v.inputs.str("nonce_hex"))
        val ciphertext = Crypto.b64urlDecode(v.expected.str("ciphertext_b64url"))

        try {
            Crypto.openItem(masterKey, "01J9Z6Q3R8T5V7X9Y2B4C6D8E0-other", ciphertext, nonce)
            fail("AAD 不匹配时必须解密失败")
        } catch (e: Exception) {
            assertNotNull(e.message)
        }
    }

    @Test
    fun pairBlobMatchesVector() {
        val v = vector("aead", "pair_blob")
        val code = hex(v.inputs.str("code_hex"))
        val codeId = v.inputs.str("code_id")
        val masterKey = hex(v.inputs.str("master_key_hex"))
        val nonce = hex(v.inputs.str("nonce_hex"))

        val blob = Crypto.sealPairBlob(Crypto.pairKek(code, codeId), masterKey, nonce)

        assertEquals(v.expected.str("blob_b64url"), Crypto.b64urlEncode(blob))
        assertArrayEquals(masterKey, Crypto.openPairBlob(Crypto.pairKek(code, codeId), blob))
    }

    @Test
    fun signingStringMatchesVectors() {
        val vectors = vectors("signing")
        assertTrue(vectors.size >= 3)
        for (v in vectors) {
            val body = v.inputs.str("body_utf8").toByteArray(Charsets.UTF_8)
            val actual = Crypto.signingString(
                v.inputs.str("method"),
                v.inputs.str("request_uri"),
                body,
                v.inputs.long("ts"),
            )
            assertEquals(v.name, v.expected.str("signing_string_utf8"), actual)
            assertEquals(v.name, v.expected.str("body_sha256_hex"), hexOf(Crypto.sha256(body)))
        }
    }

    @Test
    fun ed25519SignatureMatchesVectors() {
        for (v in vectors("signing")) {
            val seed = hex(v.inputs.str("device_key_seed_hex"))
            val message = Crypto.signingString(
                v.inputs.str("method"),
                v.inputs.str("request_uri"),
                v.inputs.str("body_utf8").toByteArray(Charsets.UTF_8),
                v.inputs.long("ts"),
            ).toByteArray(Charsets.UTF_8)

            val pubkey = Crypto.ed25519PublicKey(seed)
            assertEquals(v.name, v.expected.str("device_pubkey_b64url"), Crypto.b64urlEncode(pubkey))

            val signature = Crypto.ed25519Sign(seed, message)
            assertEquals(Crypto.ED25519_SIGNATURE_LEN, signature.size)
            assertEquals(v.name, v.expected.str("signature_b64url"), Crypto.b64urlEncode(signature))
            assertTrue(v.name, Crypto.ed25519Verify(pubkey, message, signature))
        }
    }

    @Test
    fun ed25519SelfSignVerifyRejectsTampering() {
        val seed = Crypto.random(Crypto.ED25519_SEED_LEN)
        val pubkey = Crypto.ed25519PublicKey(seed)
        val message = "POST\n/api/v1/items\n00\n1761436800".toByteArray(Charsets.UTF_8)

        val signature = Crypto.ed25519Sign(seed, message)

        assertTrue(Crypto.ed25519Verify(pubkey, message, signature))
        assertTrue(!Crypto.ed25519Verify(pubkey, message + " ".toByteArray(), signature))
        assertTrue(!Crypto.ed25519Verify(pubkey, message, signature.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }))
        assertTrue(!Crypto.ed25519Verify(ByteArray(31), message, signature))
        assertTrue(!Crypto.ed25519Verify(pubkey, message, ByteArray(63)))
    }

    @Test
    fun masterKeyEncodingMatchesVector() {
        val v = vector("encoding", "master_key_encoding")
        val masterKey = hex(v.inputs.str("master_key_hex"))

        assertEquals(v.expected.str("b32_nopad_upper"), Crypto.base32Encode(masterKey))
        assertEquals(v.expected.str("b64url"), Crypto.b64urlEncode(masterKey))
        assertArrayEquals(masterKey, Crypto.b64urlDecode(v.expected.str("b64url")))
        assertArrayEquals(masterKey, Crypto.base32Decode(v.expected.str("b32_nopad_upper")))
    }

    @Test
    fun pairCodeEncodingMatchesVector() {
        val v = vector("encoding", "pair_code_encoding")
        val code = hex(v.inputs.str("code_hex"))
        val encoded = v.expected.str("code_b32_nopad_upper")
        val display = v.expected.str("code_display")

        assertEquals(encoded, Crypto.base32Encode(code))
        assertEquals(display, Crypto.formatPairCode(code))
        assertEquals(v.expected.str("code_hash_hex"), hexOf(Crypto.sha256(code)))

        // 解析必须容忍展示形式（含 '-'、小写与填充）。
        assertArrayEquals(code, Crypto.parsePairCode(display))
        assertArrayEquals(code, Crypto.parsePairCode(display.lowercase()))
        assertArrayEquals(code, Crypto.parsePairCode(encoded + "=="))
    }

    // ------------------------------------------------------------------
    // 向量读取
    // ------------------------------------------------------------------

    /** 一条向量：名称 + 输入 + 期望。 */
    private class Vector(val name: String, val inputs: JsonObject, val expected: JsonObject)

    /** 读取指定向量文件中的全部向量。 */
    private fun vectors(fileName: String): List<Vector> {
        val file = File(vectorsDir(), "$fileName.json")
        assertTrue("缺少向量文件: ${file.absolutePath}", file.isFile)
        val root = Json.parseToJsonElement(file.readText(Charsets.UTF_8)).jsonObject
        val list = root.getValue("vectors").jsonArray.map { it.jsonObject }
        return list.map { item ->
            Vector(
                name = item.getValue("name").jsonPrimitive.content,
                inputs = item.getValue("inputs").jsonObject,
                expected = item.getValue("expected").jsonObject,
            )
        }
    }

    /** 按名称取单条向量。 */
    private fun vector(fileName: String, name: String): Vector {
        return vectors(fileName).firstOrNull { it.name == name }
            ?: throw AssertionError("向量 $fileName/$name 不存在")
    }

    /** 定位 `shared/vectors` 目录。 */
    private fun vectorsDir(): File {
        val candidates = listOfNotNull(
            System.getProperty("vkey.vectorsDir")?.let(::File),
            File("../shared/vectors"),
            File("../../shared/vectors"),
            File("shared/vectors"),
        )
        return candidates.firstOrNull { File(it, "kdf.json").isFile }
            ?: throw AssertionError("找不到 shared/vectors，已尝试: ${candidates.map { it.absolutePath }}")
    }

    /** 取字符串字段。 */
    private fun JsonObject.str(key: String): String = getValue(key).jsonPrimitive.content

    /** 取整数字段。 */
    private fun JsonObject.long(key: String): Long = getValue(key).jsonPrimitive.long

    /** 十六进制转字节。 */
    private fun hex(text: String): ByteArray {
        require(text.length % 2 == 0) { "非法十六进制: $text" }
        return ByteArray(text.length / 2) { index ->
            text.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    /** 字节转小写十六进制。 */
    private fun hexOf(data: ByteArray): String = data.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
}
