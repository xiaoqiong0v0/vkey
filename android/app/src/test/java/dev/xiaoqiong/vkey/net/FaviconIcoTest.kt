package dev.xiaoqiong.vkey.net

import java.io.ByteArrayOutputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** [IcoParser] 测试：ICO 目录内的 PNG 条目提取（内存构造字节，无网络/无文件）。 */
class FaviconIcoTest {

    /** 一个 ICO 条目：尺寸 + 负载。 */
    private class Entry(val width: Int, val height: Int, val data: ByteArray)

    @Test
    fun extractsPngPayloadFromSingleEntryIco() {
        val png = pngPayload()
        val ico = buildIco(listOf(Entry(16, 16, png)))

        assertTrue(IcoParser.isIco(ico))
        assertArrayEquals(png, IcoParser.extractLargestPng(ico))
    }

    @Test
    fun returnsNullWhenLargestEntryIsNotPng() {
        val bmp = byteArrayOf(0x28, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00)
        val ico = buildIco(listOf(Entry(32, 32, bmp)))

        assertTrue(IcoParser.isIco(ico))
        assertNull(IcoParser.extractLargestPng(ico))
    }

    @Test
    fun picksLargestEntry() {
        val smallBmp = byteArrayOf(0x28, 0x00, 0x00, 0x00, 0x00, 0x00)
        val bigPng = pngPayload()
        val ico = buildIco(listOf(Entry(16, 16, smallBmp), Entry(64, 64, bigPng)))

        assertArrayEquals(bigPng, IcoParser.extractLargestPng(ico))
    }

    @Test
    fun treatsZeroSizeFieldAs256Pixels() {
        val smallPng = pngPayload()
        val largeBmp = byteArrayOf(0x28, 0x00, 0x00, 0x00, 0x63, 0x00)
        // 0 表示 256×256：面积最大的是这条（但不是 PNG → null）
        val ico = buildIco(listOf(Entry(16, 16, smallPng), Entry(0, 0, largeBmp)))

        assertNull(IcoParser.extractLargestPng(ico))
    }

    @Test
    fun rejectsNonIcoBytes() {
        val notIco = pngPayload()

        assertFalse(IcoParser.isIco(notIco))
        assertNull(IcoParser.extractLargestPng(notIco))
        assertNull(IcoParser.extractLargestPng(ByteArray(0)))
    }

    @Test
    fun rejectsTruncatedDirectory() {
        val ico = buildIco(listOf(Entry(16, 16, pngPayload())))
        val truncated = ico.copyOfRange(0, ICO_HEADER_BYTES + 4)

        assertEquals(ICO_HEADER_BYTES + 4, truncated.size)
        assertNull(IcoParser.extractLargestPng(truncated))
    }

    // ------------------------------------------------------------------
    // 构造辅助
    // ------------------------------------------------------------------

    /** 8 字节 PNG 文件头 + 少量填充（够校验魔数即可）。 */
    private fun pngPayload(): ByteArray =
        byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x01)

    /** 按 ICO 格式拼出完整文件：ICONDIR + 目录项 + 依次排布的负载。 */
    private fun buildIco(entries: List<Entry>): ByteArray {
        val directoryBytes = ICON_ENTRY_BYTES * entries.size
        var offset = ICO_HEADER_BYTES + directoryBytes

        val directory = ByteArrayOutputStream()
        for (entry in entries) {
            directory.write(if (entry.width >= 256) 0 else entry.width)
            directory.write(if (entry.height >= 256) 0 else entry.height)
            directory.write(0) // colorCount
            directory.write(0) // reserved
            directory.write(le16(1)) // planes
            directory.write(le16(32)) // bitCount
            directory.write(le32(entry.data.size))
            directory.write(le32(offset))
            offset += entry.data.size
        }

        val out = ByteArrayOutputStream()
        out.write(byteArrayOf(0x00, 0x00, 0x01, 0x00)) // reserved + type=1 (icon)
        out.write(le16(entries.size))
        out.write(directory.toByteArray())
        for (entry in entries) out.write(entry.data)
        return out.toByteArray()
    }

    private fun le16(value: Int): ByteArray =
        byteArrayOf((value and 0xFF).toByte(), ((value shr 8) and 0xFF).toByte())

    private fun le32(value: Int): ByteArray = byteArrayOf(
        (value and 0xFF).toByte(),
        ((value shr 8) and 0xFF).toByte(),
        ((value shr 16) and 0xFF).toByte(),
        ((value shr 24) and 0xFF).toByte(),
    )

    private companion object {
        const val ICO_HEADER_BYTES: Int = 6
        const val ICON_ENTRY_BYTES: Int = 16
    }
}
