package cleveres.tricky.cleverestech.keystore

import cleveres.tricky.cleverestech.BackendKeyHandle
import cleveres.tricky.cleverestech.CertificateBackend
import cleveres.tricky.cleverestech.KeyboxActivation
import cleveres.tricky.cleverestech.KeyboxLoader
import cleveres.tricky.cleverestech.ManagedOpaqueKeyOracle
import cleveres.tricky.cleverestech.NativeBackend
import cleveres.tricky.cleverestech.TestKeyboxFixtures
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.util.Date
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Generating one attest key must not destroy other pairs: the attest-key path evicts only
 * its own subtree instead of clearing the whole certificate graph. A global clear on every
 * generation wipes unrelated keys, other UIDs, and previously completed pairs that checkers
 * re-read later, which systematically breaks multi-key attest graphs while RKP keys (which
 * never clear here) keep working.
 */
class AttestSubtreeEvictionTest {
    private val uid = 44_601
    private val bootKey = ByteArray(32) { 0x51 }
    private val bootHash = ByteArray(32) { 0x61 }

    private val removeCalls = mutableListOf<Pair<Int, ByteArray>>()
    private var clearCalls = 0
    private val events = mutableListOf<String>()

    @Before
    fun setUp() {
        NativeBackend.resetIdentityForTesting()
        KeyboxActivation.resetForTesting()
        KeyboxLoader.resetForTesting()
        CertificateBackend.resetForTesting()
        ManagedOpaqueKeyOracle.reset()
        CertHack.resetGraphHealthForTesting()
        clearCertificateCache()
        var activeIds = emptyList<ByteArray>()
        KeyboxLoader.activeSetOverride = { ids ->
            activeIds.forEach { it.fill(0) }
            activeIds = ids.map(ByteArray::copyOf)
            true
        }
        NativeBackend.observeBackendIdentityForTesting(NativeBackend.BackendIdentity(101, 0x1111, 0x2222))
        val fixture =
            ManagedOpaqueKeyOracle.parse(
                TestKeyboxFixtures.validEcKeyboxXml.reader(),
                "eviction.xml",
            ).single()
        val box =
            CertHack.KeyBox(
                KeyPair(
                    fixture.keyPair().public,
                    BackendKeyHandle(fixture.keyPair().private.algorithm, fixture.keyPair().private.encoded),
                ),
                fixture.certificates(),
                "eviction.xml",
            )
        assertTrue(KeyboxActivation.commitAndPublish(listOf(box)))
        assertEquals(1, CertHack.getKeyboxCount())
        CertificateBackend.inspectionOverride = {
            CertificateBackend.Inspection(
                systemPatch = null,
                vendorPatch = null,
                bootPatch = null,
                presentIdMask = 0,
                supportsModuleHash = false,
                originalBootKey = bootKey.clone(),
                originalBootHash = bootHash.clone(),
                attestationSecurityLevel = CertificateBackend.SECURITY_LEVEL_TEE,
                keymintSecurityLevel = CertificateBackend.SECURITY_LEVEL_TEE,
            )
        }
        CertificateBackend.rewriteAttestKeyOverride = { _, _, _ ->
            events.add("rewrite")
            byteArrayOf(0x30, 0x01, 0x00)
        }
        CertificateBackend.removeAttestKeyOverride = { callingUid, keyId ->
            removeCalls.add(callingUid to keyId.clone())
            events.add("remove")
            CertificateBackend.AttestKeyRemoveResult.REMOVED
        }
        CertificateBackend.clearAttestKeyStoreOverride = {
            clearCalls++
            events.add("clear")
            true
        }
        // Keybox publication above may run a real backend clear while no override is
        // installed yet, which marks the graph unhealthy. Discard all setup-time side
        // effects so the test observes only the generation under test.
        removeCalls.clear()
        clearCalls = 0
        CertHack.resetGraphHealthForTesting()
    }

    @After
    fun tearDown() {
        CertificateBackend.resetForTesting()
        KeyboxLoader.resetForTesting()
        KeyboxActivation.resetForTesting()
        NativeBackend.resetIdentityForTesting()
        ManagedOpaqueKeyOracle.reset()
        CertHack.resetGraphHealthForTesting()
        clearCertificateCache()
    }

    @Test
    fun `attest key generation evicts only its subtree and never clears the graph`() {
        val victimParent = ByteArray(32) { (it + 3).toByte() }
        val victimKey = cacheKey(byteArrayOf(11, 22, 33))
        putCacheEntry(
            victimKey,
            byteArrayOf(41, 51),
            uid = uid,
            attestKeyId = null,
            parentKeyId = victimParent,
        )

        val freshKeyId = ByteArray(32) { (it + 7).toByte() }
        val leaf = attestedLeaf("fresh-attest-key")
        val original = arrayOf<Certificate>(leaf)
        val rewritten = CertHack.hackAttestKeyCertificateChain(original, uid, true, freshKeyId)

        assertTrue("fresh attest key must be rewritten", rewritten !== original)
        assertTrue("victim pair must survive the generation", containsCacheKey(victimKey))
        assertEquals("backend remove must target exactly the fresh subtree", 1, removeCalls.size)
        assertEquals(uid, removeCalls[0].first)
        assertArrayEquals(freshKeyId, removeCalls[0].second)
        assertEquals("graph-wide clear must not run on attest-key generation", 0, clearCalls)
        assertFalse(CertHack.isGraphStateUnhealthyForTesting())
    }

    @Test
    fun `rotating an attest key evicts the stale root and its descendant`() {
        val rotatedId = ByteArray(32) { (it + 11).toByte() }
        val staleRootKey = cacheKey(byteArrayOf(21, 22, 23))
        putCacheEntry(
            staleRootKey,
            byteArrayOf(51, 52),
            uid = uid,
            attestKeyId = rotatedId,
            parentKeyId = null,
        )
        val descendantKey = cacheKey(byteArrayOf(31, 32, 33))
        putCacheEntry(
            descendantKey,
            byteArrayOf(61, 62),
            uid = uid,
            attestKeyId = null,
            parentKeyId = rotatedId,
        )

        val freshLeaf = attestedLeaf("rotated-attest-key")
        val original = arrayOf<Certificate>(freshLeaf)
        val rewritten = CertHack.hackAttestKeyCertificateChain(original, uid, true, rotatedId)

        assertTrue("rotated attest key must be rewritten", rewritten !== original)
        assertFalse("stale root entry must be evicted", containsCacheKey(staleRootKey))
        assertFalse("stale descendant entry must be evicted", containsCacheKey(descendantKey))
        assertTrue(
            "replacement entry must be published",
            containsCacheKey(cacheKey(freshLeaf.encoded)),
        )
        val removals = removeCalls.filter { it.first == uid && it.second.contentEquals(rotatedId) }
        assertEquals("stale root backend state must be removed", 2, removals.size)
        val rewriteIndex = events.indexOf("rewrite")
        val lastRemovalIndex = events.indexOfLast { it == "remove" }
        assertTrue(rewriteIndex >= 0 && lastRemovalIndex >= 0 && lastRemovalIndex < rewriteIndex)
        assertFalse("rotation must not clear unrelated graph state", events.contains("clear"))
        assertFalse(CertHack.isGraphStateUnhealthyForTesting())
    }

    @Test
    fun `attest key remove transport failure fails closed and marks graph unhealthy`() {
        CertificateBackend.removeAttestKeyOverride = { _, _ ->
            CertificateBackend.AttestKeyRemoveResult.UNAVAILABLE
        }
        val freshKeyId = ByteArray(32) { (it + 9).toByte() }
        val leaf = attestedLeaf("unavailable-attest-key")
        val original = arrayOf<Certificate>(leaf)
        val result = CertHack.hackAttestKeyCertificateChain(original, uid, true, freshKeyId)

        assertSame("backend failure must fail closed to the genuine leaf", original, result)
        assertTrue(CertHack.isGraphStateUnhealthyForTesting())
    }

    private fun attestedLeaf(commonName: String): X509Certificate {
        val provider = BouncyCastleProvider()
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(256)
        val subject = generator.generateKeyPair()
        val issuer = generator.generateKeyPair()
        val builder =
            JcaX509v3CertificateBuilder(
                X500Name("CN=$commonName-issuer"),
                BigInteger.ONE,
                Date(0),
                Date(4_102_444_800_000L),
                X500Name("CN=$commonName"),
                subject.public,
            )
        builder.addExtension(
            ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"),
            false,
            DERSequence(
                arrayOf<ASN1Encodable>(
                    ASN1Integer(400),
                    ASN1Enumerated(1),
                    ASN1Integer(400),
                    ASN1Enumerated(1),
                    DEROctetString(byteArrayOf(1)),
                    DEROctetString(ByteArray(0)),
                    DERSequence(),
                    DERSequence(),
                ),
            ),
        )
        return JcaX509CertificateConverter().setProvider(provider).getCertificate(
            builder.build(
                JcaContentSignerBuilder("SHA256withECDSA").setProvider(provider).build(issuer.private),
            ),
        )
    }

    private fun cacheKey(leafBytes: ByteArray): Any {
        val keyClass = Class.forName("cleveres.tricky.cleverestech.keystore.CertHack\$CacheKey")
        val ctor = keyClass.getDeclaredConstructor(ByteArray::class.java)
        ctor.isAccessible = true
        return ctor.newInstance(leafBytes)
    }

    private fun certificateCache(): MutableMap<Any, Any> {
        val stateField = CertHack::class.java.getDeclaredField("state")
        stateField.isAccessible = true
        val state = stateField.get(null)
        val cacheField = state.javaClass.getDeclaredField("certificateCache")
        cacheField.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        return cacheField.get(state) as MutableMap<Any, Any>
    }

    private fun putCacheEntry(
        key: Any,
        leafBytes: ByteArray,
        uid: Int,
        attestKeyId: ByteArray?,
        parentKeyId: ByteArray?,
    ) {
        val valueClass =
            Class.forName("cleveres.tricky.cleverestech.keystore.CertHack\$CachedCertificateChain")
        val ctor =
            valueClass.getDeclaredConstructor(
                Array<Certificate>::class.java,
                ByteArray::class.java,
                ByteArray::class.java,
                java.lang.Boolean.TYPE,
                java.lang.Boolean.TYPE,
                Integer.TYPE,
                ByteArray::class.java,
                ByteArray::class.java,
            )
        ctor.isAccessible = true
        val value =
            ctor.newInstance(
                emptyArray<Certificate>(),
                leafBytes,
                byteArrayOf(60, 70),
                true,
                false,
                uid,
                attestKeyId,
                parentKeyId,
            )
        certificateCache()[key] = value
    }

    private fun containsCacheKey(key: Any): Boolean = certificateCache().containsKey(key)

    private fun clearCertificateCache() {
        certificateCache().clear()
    }
}
