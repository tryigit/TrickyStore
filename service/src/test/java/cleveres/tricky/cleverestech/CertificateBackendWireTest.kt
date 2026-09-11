package cleveres.tricky.cleverestech

import java.io.ByteArrayOutputStream
import java.io.File
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class CertificateBackendWireTest {
    @Before
    fun setUp() {
        CertificateBackend.resetForTesting()
    }

    @After
    fun tearDown() {
        CertificateBackend.resetForTesting()
    }

    @Test
    fun `default rewrite emits the exact fixture consumed by the Rust parser`() {
        val expected = rewriteFixture()
        var writes = 0
        CertificateBackend.rewriteTransportOverride = { declaredLength, writePayload ->
            val output = ByteArrayOutputStream()
            writePayload(output)
            val actual = output.toByteArray()
            assertEquals(expected.size, declaredLength)
            assertEquals(declaredLength, actual.size)
            assertArrayEquals(expected, actual)
            writes++
            byteArrayOf(0x30, 0x00)
        }

        val result =
            CertificateBackend.rewrite(
                genuineLeafDer = byteArrayOf(1),
                keyId = ByteArray(16) { 0x33 },
                signingAlgorithm = CertificateBackend.SIGNING_EC_P256_SHA256,
                systemDisposition = CertificateBackend.PATCH_KEEP,
                systemValue = 0,
                vendorDisposition = CertificateBackend.PATCH_OMIT,
                vendorValue = 0,
                bootDisposition = CertificateBackend.PATCH_REPLACE,
                bootValue = 20251205,
                idOverrides = mapOf(714 to "imei".toByteArray()),
                moduleHash = "mod".toByteArray(),
                verifiedBootKey = ByteArray(32) { 0x11 },
                verifiedBootHash = ByteArray(32) { 0x22 },
            )

        assertArrayEquals(byteArrayOf(0x30, 0x00), result)
        assertEquals(1, writes)
    }

    @Test
    fun `attest key rewrite propagates platform security level and rejects unknown levels`() {
        var capturedLevel = -1
        var writes = 0
        CertificateBackend.rewriteAttestKeyOverride = { _, _, request ->
            capturedLevel = request.platformSecurityLevel
            writes++
            byteArrayOf(0x30, 0x01, 0x00)
        }

        val attestKeyId = ByteArray(32) { 0x44 }
        val keyId = ByteArray(16) { 0x33 }
        val resultSb =
            CertificateBackend.rewriteAttestKey(
                callingUid = 44_501,
                attestKeyId = attestKeyId,
                genuineLeafDer = byteArrayOf(1),
                keyId = keyId,
                signingAlgorithm = CertificateBackend.SIGNING_EC_P256_SHA256,
                platformSecurityLevel = CertificateBackend.SECURITY_LEVEL_STRONGBOX,
                systemDisposition = CertificateBackend.PATCH_KEEP,
                systemValue = 0,
                vendorDisposition = CertificateBackend.PATCH_KEEP,
                vendorValue = 0,
                bootDisposition = CertificateBackend.PATCH_KEEP,
                bootValue = 0,
                idOverrides = emptyMap(),
                moduleHash = null,
                verifiedBootKey = ByteArray(32) { 0x11 },
                verifiedBootHash = ByteArray(32) { 0x22 },
            )
        assertArrayEquals(byteArrayOf(0x30, 0x01, 0x00), resultSb)
        assertEquals(CertificateBackend.SECURITY_LEVEL_STRONGBOX, capturedLevel)
        assertEquals(1, writes)

        val resultTee =
            CertificateBackend.rewriteAttestKey(
                callingUid = 44_501,
                attestKeyId = attestKeyId,
                genuineLeafDer = byteArrayOf(1),
                keyId = keyId,
                signingAlgorithm = CertificateBackend.SIGNING_EC_P256_SHA256,
                platformSecurityLevel = CertificateBackend.SECURITY_LEVEL_TEE,
                systemDisposition = CertificateBackend.PATCH_KEEP,
                systemValue = 0,
                vendorDisposition = CertificateBackend.PATCH_KEEP,
                vendorValue = 0,
                bootDisposition = CertificateBackend.PATCH_KEEP,
                bootValue = 0,
                idOverrides = emptyMap(),
                moduleHash = null,
                verifiedBootKey = ByteArray(32) { 0x11 },
                verifiedBootHash = ByteArray(32) { 0x22 },
            )
        assertArrayEquals(byteArrayOf(0x30, 0x01, 0x00), resultTee)
        assertEquals(CertificateBackend.SECURITY_LEVEL_TEE, capturedLevel)

        assertNull(
            CertificateBackend.rewriteAttestKey(
                callingUid = 44_501,
                attestKeyId = attestKeyId,
                genuineLeafDer = byteArrayOf(1),
                keyId = keyId,
                signingAlgorithm = CertificateBackend.SIGNING_EC_P256_SHA256,
                platformSecurityLevel = CertificateBackend.SECURITY_LEVEL_SOFTWARE,
                systemDisposition = CertificateBackend.PATCH_KEEP,
                systemValue = 0,
                vendorDisposition = CertificateBackend.PATCH_KEEP,
                vendorValue = 0,
                bootDisposition = CertificateBackend.PATCH_KEEP,
                bootValue = 0,
                idOverrides = emptyMap(),
                moduleHash = null,
                verifiedBootKey = ByteArray(32) { 0x11 },
                verifiedBootHash = ByteArray(32) { 0x22 },
            ),
        )
        assertNull(
            CertificateBackend.rewriteAttestKey(
                callingUid = 44_501,
                attestKeyId = attestKeyId,
                genuineLeafDer = byteArrayOf(1),
                keyId = keyId,
                signingAlgorithm = CertificateBackend.SIGNING_EC_P256_SHA256,
                platformSecurityLevel = 3,
                systemDisposition = CertificateBackend.PATCH_KEEP,
                systemValue = 0,
                vendorDisposition = CertificateBackend.PATCH_KEEP,
                vendorValue = 0,
                bootDisposition = CertificateBackend.PATCH_KEEP,
                bootValue = 0,
                idOverrides = emptyMap(),
                moduleHash = null,
                verifiedBootKey = ByteArray(32) { 0x11 },
                verifiedBootHash = ByteArray(32) { 0x22 },
            ),
        )
    }

    @Test
    fun `child key rewrite propagates platform security level and rejects unknown levels`() {
        var capturedLevel = -1
        CertificateBackend.rewriteChildKeyOverride = { _, _, _, _, level, _, _, _ ->
            capturedLevel = level
            byteArrayOf(0x30, 0x01, 0x00)
        }

        val parentKeyId = ByteArray(32) { 0x55 }
        val childKeyId = ByteArray(32) { 0x66 }
        val result =
            CertificateBackend.rewriteChildKey(
                callingUid = 44_502,
                parentKeyId = parentKeyId,
                childKeyId = childKeyId,
                genuineLeafDer = byteArrayOf(1),
                isAttestKey = true,
                platformSecurityLevel = CertificateBackend.SECURITY_LEVEL_STRONGBOX,
                systemDisposition = CertificateBackend.PATCH_KEEP,
                systemValue = 0,
                vendorDisposition = CertificateBackend.PATCH_KEEP,
                vendorValue = 0,
                bootDisposition = CertificateBackend.PATCH_KEEP,
                bootValue = 0,
                idOverrides = emptyMap(),
                moduleHash = null,
                verifiedBootKey = ByteArray(32) { 0x11 },
                verifiedBootHash = ByteArray(32) { 0x22 },
            )
        assertArrayEquals(byteArrayOf(0x30, 0x01, 0x00), result)
        assertEquals(CertificateBackend.SECURITY_LEVEL_STRONGBOX, capturedLevel)

        assertNull(
            CertificateBackend.rewriteChildKey(
                callingUid = 44_502,
                parentKeyId = parentKeyId,
                childKeyId = childKeyId,
                genuineLeafDer = byteArrayOf(1),
                isAttestKey = true,
                platformSecurityLevel = 0,
                systemDisposition = CertificateBackend.PATCH_KEEP,
                systemValue = 0,
                vendorDisposition = CertificateBackend.PATCH_KEEP,
                vendorValue = 0,
                bootDisposition = CertificateBackend.PATCH_KEEP,
                bootValue = 0,
                idOverrides = emptyMap(),
                moduleHash = null,
                verifiedBootKey = ByteArray(32) { 0x11 },
                verifiedBootHash = ByteArray(32) { 0x22 },
            ),
        )
    }

    @Test
    fun `attest key wire version 3 carries platform level after signing algorithm`() {
        var payload: ByteArray? = null
        CertificateBackend.rewriteTransportOverride = { declaredLength, writePayload ->
            val output = ByteArrayOutputStream()
            writePayload(output)
            payload = output.toByteArray()
            assertEquals(declaredLength, payload!!.size)
            byteArrayOf(0x30, 0x00)
        }
        // Use the transport override path (no rewriteAttestKeyOverride) to capture raw wire bytes.
        CertificateBackend.rewriteAttestKeyOverride = null
        val result =
            CertificateBackend.rewriteAttestKey(
                callingUid = 44_501,
                attestKeyId = ByteArray(32) { 0x44 },
                genuineLeafDer = byteArrayOf(1),
                keyId = ByteArray(16) { 0x33 },
                signingAlgorithm = CertificateBackend.SIGNING_EC_P256_SHA256,
                platformSecurityLevel = CertificateBackend.SECURITY_LEVEL_STRONGBOX,
                systemDisposition = CertificateBackend.PATCH_KEEP,
                systemValue = 0,
                vendorDisposition = CertificateBackend.PATCH_KEEP,
                vendorValue = 0,
                bootDisposition = CertificateBackend.PATCH_KEEP,
                bootValue = 0,
                idOverrides = emptyMap(),
                moduleHash = null,
                verifiedBootKey = ByteArray(32) { 0x11 },
                verifiedBootHash = ByteArray(32) { 0x22 },
            )
        assertArrayEquals(byteArrayOf(0x30, 0x00), result)
        val bytes = requireNotNull(payload)
        assertEquals(3, bytes[0].toInt())
        // version(1) + uid(4) + signingAlg(1) + level(1)
        assertEquals(CertificateBackend.SIGNING_EC_P256_SHA256, bytes[5].toInt())
        assertEquals(CertificateBackend.SECURITY_LEVEL_STRONGBOX, bytes[6].toInt())
    }

    @Test
    fun `inspection response decodes strict fields and wipes transport bytes`() {
        val response = ByteArray(85)
        response[0] = 2
        response[1] = 0x07
        writeU16(response, 2, (1 shl 0) or (1 shl 4) or (1 shl 8))
        writeOptionalI32(response, 4, 20260105)
        writeOptionalI32(response, 9, null)
        writeOptionalI32(response, 14, 20260205)
        for (index in 0 until 32) {
            response[19 + index] = (index + 1).toByte()
            response[51 + index] = (0x40 + index).toByte()
        }
        response[83] = CertificateBackend.SECURITY_LEVEL_STRONGBOX.toByte()
        response[84] = CertificateBackend.SECURITY_LEVEL_STRONGBOX.toByte()

        val inspection = CertificateBackend.decodeInspection(response)

        assertEquals(20260105, inspection.systemPatch)
        assertNull(inspection.vendorPatch)
        assertEquals(20260205, inspection.bootPatch)
        assertEquals((1 shl 0) or (1 shl 4) or (1 shl 8), inspection.presentIdMask)
        assertTrue(inspection.supportsModuleHash)
        assertEquals(CertificateBackend.SECURITY_LEVEL_STRONGBOX, inspection.attestationSecurityLevel)
        assertEquals(CertificateBackend.SECURITY_LEVEL_STRONGBOX, inspection.keymintSecurityLevel)
        assertArrayEquals(ByteArray(32) { (it + 1).toByte() }, inspection.originalBootKey)
        assertArrayEquals(ByteArray(32) { (0x40 + it).toByte() }, inspection.originalBootHash)
        assertTrue(response.all { it == 0.toByte() })

        inspection.wipe()
        assertTrue(requireNotNull(inspection.originalBootKey).all { it == 0.toByte() })
        assertTrue(requireNotNull(inspection.originalBootHash).all { it == 0.toByte() })
    }

    @Test
    fun `reserved flags noncanonical fields and unknown levels fail closed`() {
        val reserved = canonicalResponse()
        reserved[1] = 0x08
        assertThrows(RustBackendUnavailableException::class.java) {
            CertificateBackend.decodeInspection(reserved)
        }
        assertTrue(reserved.all { it == 0.toByte() })

        val noncanonical = canonicalResponse()
        writeI32(noncanonical, 5, 1)
        assertThrows(RustBackendUnavailableException::class.java) {
            CertificateBackend.decodeInspection(noncanonical)
        }
        assertTrue(noncanonical.all { it == 0.toByte() })

        val unknownLevel = canonicalResponse()
        unknownLevel[83] = 3
        assertThrows(RustBackendUnavailableException::class.java) {
            CertificateBackend.decodeInspection(unknownLevel)
        }
        assertTrue(unknownLevel.all { it == 0.toByte() })
    }

    @Test
    fun `absent boot digests remain absent`() {
        val response = canonicalResponse()
        val inspection = CertificateBackend.decodeInspection(response)
        assertFalse(inspection.supportsModuleHash)
        assertNull(inspection.originalBootKey)
        assertNull(inspection.originalBootHash)
        assertEquals(CertificateBackend.SECURITY_LEVEL_TEE, inspection.attestationSecurityLevel)
        assertEquals(CertificateBackend.SECURITY_LEVEL_TEE, inspection.keymintSecurityLevel)
    }

    private fun canonicalResponse(): ByteArray =
        ByteArray(85).also {
            it[0] = 2
            it[83] = CertificateBackend.SECURITY_LEVEL_TEE.toByte()
            it[84] = CertificateBackend.SECURITY_LEVEL_TEE.toByte()
        }

    private fun rewriteFixture(): ByteArray {
        var root = File(requireNotNull(System.getProperty("user.dir"))).canonicalFile
        repeat(6) {
            val fixture = File(root, "rust/backend/tests/fixtures/certificate-rewrite.hex")
            if (fixture.isFile) {
                val hex = fixture.readText().trim()
                return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            }
            root = root.parentFile ?: error("Repository root not found")
        }
        error("Certificate wire fixture not found")
    }

    private fun writeOptionalI32(
        bytes: ByteArray,
        offset: Int,
        value: Int?,
    ) {
        if (value == null) return
        bytes[offset] = 1
        writeI32(bytes, offset + 1, value)
    }

    private fun writeU16(
        bytes: ByteArray,
        offset: Int,
        value: Int,
    ) {
        bytes[offset] = (value ushr 8).toByte()
        bytes[offset + 1] = value.toByte()
    }

    private fun writeI32(
        bytes: ByteArray,
        offset: Int,
        value: Int,
    ) {
        bytes[offset] = (value ushr 24).toByte()
        bytes[offset + 1] = (value ushr 16).toByte()
        bytes[offset + 2] = (value ushr 8).toByte()
        bytes[offset + 3] = value.toByte()
    }
}
