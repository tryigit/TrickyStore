package cleveres.tricky.cleverestech

import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Security
import java.security.cert.X509Certificate
import java.util.Date

class CertificateBackendProvenanceTest {
    companion object {
        init {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(BouncyCastleProvider())
            }
        }
    }

    @Before
    fun setUp() {
        ManagedCertificateBackendOracle.install()
    }

    @After
    fun tearDown() {
        ManagedCertificateBackendOracle.reset()
    }

    @Test
    fun `provenance inspect preserves authentic security levels without synthetic normalization`() {
        val kp = generateKeyPair()
        val mixedLeaf = generateAttestationCert(
            kp,
            attLevel = CertificateBackend.SECURITY_LEVEL_TEE,
            kmLevel = CertificateBackend.SECURITY_LEVEL_STRONGBOX,
        )

        val inspection = CertificateBackend.inspect(mixedLeaf.encoded)
        assertNotNull(inspection)
        // Must preserve genuine levels and NOT normalize to (STRONGBOX, STRONGBOX)
        assertEquals(CertificateBackend.SECURITY_LEVEL_TEE, inspection?.attestationSecurityLevel)
        assertEquals(CertificateBackend.SECURITY_LEVEL_STRONGBOX, inspection?.keymintSecurityLevel)
    }

    @Test
    fun `provenance rewrite accepts authentic hardware pairings and rejects reversed or software pairings`() {
        val kp = generateKeyPair()
        val issuerCert = generateIssuerCert(kp, "CN=Test CA")
        val box = ManagedOpaqueKeyOracle.wrap(kp, listOf(issuerCert), "keybox.xml")
        val keyId = requireNotNull(box.keyPair().private.encoded)

        fun attemptRewrite(attLevel: Int, kmLevel: Int): ByteArray? {
            val leaf = generateAttestationCert(kp, attLevel, kmLevel)
            return CertificateBackend.rewrite(
                genuineLeafDer = leaf.encoded,
                keyId = keyId,
                signingAlgorithm = CertificateBackend.SIGNING_RSA_PKCS1_SHA256,
                systemDisposition = CertificateBackend.PATCH_KEEP,
                systemValue = 0,
                vendorDisposition = CertificateBackend.PATCH_KEEP,
                vendorValue = 0,
                bootDisposition = CertificateBackend.PATCH_KEEP,
                bootValue = 0,
                idOverrides = emptyMap(),
                moduleHash = null,
                verifiedBootKey = ByteArray(32) { 1 },
                verifiedBootHash = ByteArray(32) { 2 },
            )
        }

        // 1. Authentic (TEE, TEE) must succeed
        assertNotNull(
            attemptRewrite(
                CertificateBackend.SECURITY_LEVEL_TEE,
                CertificateBackend.SECURITY_LEVEL_TEE,
            ),
        )

        // 2. Authentic (StrongBox, StrongBox) must succeed
        assertNotNull(
            attemptRewrite(
                CertificateBackend.SECURITY_LEVEL_STRONGBOX,
                CertificateBackend.SECURITY_LEVEL_STRONGBOX,
            ),
        )

        // 3. Authentic mixed (TEE, StrongBox) - StrongBox KeyMint + TEE attestation signer - must succeed
        assertNotNull(
            attemptRewrite(
                CertificateBackend.SECURITY_LEVEL_TEE,
                CertificateBackend.SECURITY_LEVEL_STRONGBOX,
            ),
        )

        // 4. Reversed unauthentic pairing (StrongBox, TEE) must be rejected (returns null)
        assertNull(
            attemptRewrite(
                CertificateBackend.SECURITY_LEVEL_STRONGBOX,
                CertificateBackend.SECURITY_LEVEL_TEE,
            ),
        )

        // 5. Software pairings must be rejected (returns null)
        assertNull(
            attemptRewrite(
                CertificateBackend.SECURITY_LEVEL_SOFTWARE,
                CertificateBackend.SECURITY_LEVEL_SOFTWARE,
            ),
        )
    }

    @Test
    fun `provenance inspect and rewrite reject malformed or missing root of trust`() {
        val kp = generateKeyPair()
        val issuerCert = generateIssuerCert(kp, "CN=Test CA")
        val box = ManagedOpaqueKeyOracle.wrap(kp, listOf(issuerCert), "keybox.xml")
        val keyId = requireNotNull(box.keyPair().private.encoded)

        fun attemptRewrite(leafDer: ByteArray): ByteArray? {
            return CertificateBackend.rewrite(
                genuineLeafDer = leafDer,
                keyId = keyId,
                signingAlgorithm = CertificateBackend.SIGNING_RSA_PKCS1_SHA256,
                systemDisposition = CertificateBackend.PATCH_KEEP,
                systemValue = 0,
                vendorDisposition = CertificateBackend.PATCH_KEEP,
                vendorValue = 0,
                bootDisposition = CertificateBackend.PATCH_KEEP,
                bootValue = 0,
                idOverrides = emptyMap(),
                moduleHash = null,
                verifiedBootKey = ByteArray(32) { 1 },
                verifiedBootHash = ByteArray(32) { 2 },
            )
        }

        // 1. Missing RootOfTrust: both lists empty
        val noRootLeaf = generateCustomAttestationCert(kp) { _, _ -> }
        assertNull(CertificateBackend.inspect(noRootLeaf.encoded))
        assertNull(attemptRewrite(noRootLeaf.encoded))

        // 2. Duplicate RootOfTrust across lists
        val dupRootLeaf = generateCustomAttestationCert(kp) { sw, tee ->
            val root = validRootOfTrust()
            sw.add(DERTaggedObject(true, 704, root))
            tee.add(DERTaggedObject(true, 704, root))
        }
        assertNull(CertificateBackend.inspect(dupRootLeaf.encoded))
        assertNull(attemptRewrite(dupRootLeaf.encoded))

        // 3. Malformed RootOfTrust: 3 fields instead of 4
        val threeFieldLeaf = generateCustomAttestationCert(kp) { _, tee ->
            val root = ASN1EncodableVector()
            root.add(DEROctetString(ByteArray(32) { 1 }))
            root.add(ASN1Boolean.TRUE)
            root.add(ASN1Enumerated(0))
            tee.add(DERTaggedObject(true, 704, DERSequence(root)))
        }
        assertNull(CertificateBackend.inspect(threeFieldLeaf.encoded))
        assertNull(attemptRewrite(threeFieldLeaf.encoded))

        // 4. Malformed RootOfTrust: invalid bootState (out of 0..3)
        val badStateLeaf = generateCustomAttestationCert(kp) { _, tee ->
            val root = ASN1EncodableVector()
            root.add(DEROctetString(ByteArray(32) { 1 }))
            root.add(ASN1Boolean.TRUE)
            root.add(ASN1Enumerated(4))
            root.add(DEROctetString(ByteArray(32) { 2 }))
            tee.add(DERTaggedObject(true, 704, DERSequence(root)))
        }
        assertNull(CertificateBackend.inspect(badStateLeaf.encoded))
        assertNull(attemptRewrite(badStateLeaf.encoded))

        // 5. Implicitly tagged RootOfTrust: must fail closed (return null)
        val implicitRootLeaf = generateCustomAttestationCert(kp) { _, tee ->
            val root = validRootOfTrust()
            tee.add(DERTaggedObject(false, 704, root))
        }
        assertNull(CertificateBackend.inspect(implicitRootLeaf.encoded))
        assertNull(attemptRewrite(implicitRootLeaf.encoded))
    }

    @Test
    fun `StrongBox provenance is classified before issuer selection but is rewritten normally`() {
        val source =
            File(
                locateRoot(),
                "service/src/main/java/cleveres/tricky/cleverestech/keystore/CertHack.java",
            ).readText()
        val method = source.indexOf("public static Certificate[] hackCertificateChain")
        val inspect = source.indexOf("inspection = CertificateBackend.inspect(leafEncoded)", method)
        val attestationGate =
            source.indexOf("int attLevel = inspection.getAttestationSecurityLevel()", inspect)
        val keymintGate =
            source.indexOf("int kmLevel = inspection.getKeymintSecurityLevel()", attestationGate)
        val checkIsHardware = source.indexOf("boolean isTeeOrStrongbox =", keymintGate)
        val issuerSelection = source.indexOf("selectKeyboxPool(", checkIsHardware)
        val rewrite = source.indexOf("CertificateBackend.rewrite(", issuerSelection)

        assertTrue(method >= 0)
        assertTrue(inspect > method)
        assertTrue(attestationGate > inspect)
        assertTrue(keymintGate > attestationGate)
        assertTrue(checkIsHardware > keymintGate)
        assertTrue(issuerSelection > checkIsHardware)
        assertTrue(rewrite > issuerSelection)
    }

    @Test
    fun `Rust rewrite boundary calls its provenance gate before issuer access`() {
        val rawSource =
            File(
                locateRoot(),
                "rust/backend/src/certificate_wire.rs",
            ).readText()
        val source = rawSource.replace(Regex("\\s+"), " ")
        val rewrite = source.indexOf("pub fn rewrite_and_encode")
        val provenance = source.indexOf("inspect_certificate(parsed.genuine_leaf_der)", rewrite)
        val provenanceGate = source.indexOf("validate_hardware_provenance(&provenance)", provenance)
        val issuerAccess = source.indexOf("key_store::with_prepared_key", provenanceGate)

        assertTrue(rewrite >= 0)
        assertTrue(provenance > rewrite)
        assertTrue(provenanceGate > provenance)
        assertTrue(issuerAccess > provenanceGate)
    }

    @Test
    fun `passthrough cache is marker only and adds no background execution`() {
        val source =
            File(
                locateRoot(),
                "service/src/main/java/cleveres/tricky/cleverestech/keystore/CertHack.java",
            ).readText()

        assertTrue(source.contains("this.certificates = null"))
        assertTrue(source.contains("if (passthrough) return;"))
        assertTrue(source.contains("size() > MAX_CERTIFICATE_CACHE_ENTRIES"))
        assertFalse(source.contains("ScheduledExecutor"))
        assertFalse(source.contains("Timer("))
        assertFalse(source.contains("Thread.sleep"))
        assertFalse(source.contains("while (true)"))
    }

    @Test
    fun `certificate backend rewrite does not repeat managed provenance inspection`() {
        val source =
            File(
                locateRoot(),
                "service/src/main/java/cleveres/tricky/cleverestech/CertificateBackend.kt",
            ).readText()
        val rewrite = source.indexOf("fun rewrite(")
        val decode = source.indexOf("internal fun decodeInspection", rewrite)
        val body = source.substring(rewrite, decode)

        assertFalse(body.contains("inspect(genuineLeafDer)"))
    }

    private fun generateKeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("RSA", "BC")
        kpg.initialize(2048)
        return kpg.generateKeyPair()
    }

    private fun generateAttestationCert(kp: KeyPair, attLevel: Int, kmLevel: Int): X509Certificate {
        val issuer = X500Name("CN=Test Issuer")
        val serial = BigInteger.ONE
        val notBefore = Date()
        val notAfter = Date(System.currentTimeMillis() + 100000)

        val builder = JcaX509v3CertificateBuilder(
            issuer,
            serial,
            notBefore,
            notAfter,
            issuer,
            kp.public,
        )

        val keyDesc = ASN1EncodableVector()
        keyDesc.add(ASN1Integer(100))
        keyDesc.add(ASN1Enumerated(attLevel))
        keyDesc.add(ASN1Integer(100))
        keyDesc.add(ASN1Enumerated(kmLevel))
        keyDesc.add(DEROctetString(ByteArray(0)))
        keyDesc.add(DEROctetString(ByteArray(0)))
        keyDesc.add(DERSequence())

        val teeEnforced = ASN1EncodableVector()
        val rootOfTrust = ASN1EncodableVector()
        val bootKey = ByteArray(32) { 1 }
        val bootHash = ByteArray(32) { 2 }
        rootOfTrust.add(DEROctetString(bootKey))
        rootOfTrust.add(ASN1Boolean.TRUE)
        rootOfTrust.add(ASN1Enumerated(0))
        rootOfTrust.add(DEROctetString(bootHash))
        teeEnforced.add(DERTaggedObject(true, 704, DERSequence(rootOfTrust)))
        keyDesc.add(DERSequence(teeEnforced))

        val oid = ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
        builder.addExtension(oid, false, DERSequence(keyDesc))

        val signer: ContentSigner = JcaContentSignerBuilder("SHA256withRSA").build(kp.private)
        return JcaX509CertificateConverter().getCertificate(builder.build(signer))
    }

    private fun generateIssuerCert(kp: KeyPair, subjectDn: String): X509Certificate {
        val name = X500Name(subjectDn)
        val serial = BigInteger.valueOf(2)
        val notBefore = Date()
        val notAfter = Date(System.currentTimeMillis() + 100000)
        val builder = JcaX509v3CertificateBuilder(
            name,
            serial,
            notBefore,
            notAfter,
            name,
            kp.public,
        )
        val signer: ContentSigner = JcaContentSignerBuilder("SHA256withRSA").build(kp.private)
        return JcaX509CertificateConverter().getCertificate(builder.build(signer))
    }

    private fun validRootOfTrust(): DERSequence {
        val rootOfTrust = ASN1EncodableVector()
        rootOfTrust.add(DEROctetString(ByteArray(32) { 1 }))
        rootOfTrust.add(ASN1Boolean.TRUE)
        rootOfTrust.add(ASN1Enumerated(0))
        rootOfTrust.add(DEROctetString(ByteArray(32) { 2 }))
        return DERSequence(rootOfTrust)
    }

    private fun generateCustomAttestationCert(
        kp: KeyPair,
        configureLists: (ASN1EncodableVector, ASN1EncodableVector) -> Unit,
    ): X509Certificate {
        val issuer = X500Name("CN=Test Issuer")
        val serial = BigInteger.ONE
        val notBefore = Date()
        val notAfter = Date(System.currentTimeMillis() + 100000)

        val builder = JcaX509v3CertificateBuilder(
            issuer,
            serial,
            notBefore,
            notAfter,
            issuer,
            kp.public,
        )

        val keyDesc = ASN1EncodableVector()
        keyDesc.add(ASN1Integer(100))
        keyDesc.add(ASN1Enumerated(CertificateBackend.SECURITY_LEVEL_TEE))
        keyDesc.add(ASN1Integer(100))
        keyDesc.add(ASN1Enumerated(CertificateBackend.SECURITY_LEVEL_TEE))
        keyDesc.add(DEROctetString(ByteArray(0)))
        keyDesc.add(DEROctetString(ByteArray(0)))

        val swList = ASN1EncodableVector()
        val teeList = ASN1EncodableVector()
        configureLists(swList, teeList)
        keyDesc.add(DERSequence(swList))
        keyDesc.add(DERSequence(teeList))

        val oid = ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
        builder.addExtension(oid, false, DERSequence(keyDesc))

        val signer: ContentSigner = JcaContentSignerBuilder("SHA256withRSA").build(kp.private)
        return JcaX509CertificateConverter().getCertificate(builder.build(signer))
    }

    private fun locateRoot(): File {
        var current = File(requireNotNull(System.getProperty("user.dir"))).canonicalFile
        repeat(6) {
            if (File(current, "service").isDirectory && File(current, "rust").isDirectory) return current
            current = current.parentFile ?: return@repeat
        }
        error("Repository root not found")
    }
}
