package cleveres.tricky.cleverestech.keystore;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.StringReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import cleveres.tricky.cleverestech.Logger;
import cleveres.tricky.cleverestech.ManagedCertificateBackendOracle;
import cleveres.tricky.cleverestech.ManagedOpaqueKeyOracle;
import cleveres.tricky.cleverestech.TestKeyboxFixtures;

public class CertHackTest {
    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Before
    public void setUp() {
        ManagedCertificateBackendOracle.install();
    }

    @After
    public void tearDown() {
        ManagedCertificateBackendOracle.reset();
        ManagedKeyboxStateOracle.readFromXml(null);
    }

    private static final String EC_KEY = TestKeyboxFixtures.INSTANCE.getEcPrivateKey();
    private static final String TEST_CERT = TestKeyboxFixtures.INSTANCE.getCertificate();

    @Test
    public void testReadFromXml() {
        Logger.setImpl(new Logger.LogImpl() {
            @Override public void d(String tag, String msg) { /* no-op */ }
            @Override public void e(String tag, String msg) { /* no-op */ }
            @Override public void e(String tag, String msg, Throwable t) { /* no-op */ }
            @Override public void i(String tag, String msg) { /* no-op */ }
        });

        String xml = "<?xml version=\"1.0\"?>\n" +
                "<AndroidAttestation>\n" +
                "<NumberOfKeyboxes>1</NumberOfKeyboxes>\n" +
                "<Keybox>\n" +
                "<Key algorithm=\"ecdsa\">\n" +
                "<PrivateKey>\n" + EC_KEY + "\n</PrivateKey>\n" +
                "<CertificateChain>\n" +
                "<NumberOfCertificates>1</NumberOfCertificates>\n" +
                "<Certificate>\n" + TEST_CERT + "\n</Certificate>\n" +
                "</CertificateChain>\n" +
                "</Key>\n" +
                "</Keybox>\n" +
                "</AndroidAttestation>";

        ManagedKeyboxStateOracle.readFromXml(new StringReader(xml));

        assertTrue("Keybox should be loaded", CertHack.canHack());
    }

    @Test
    public void testMixedValidAndInvalidKeysRejectsWholeDocument() {
        String invalidKey =
                "<Key algorithm=\"ecdsa\">" +
                "<PrivateKey>not-a-private-key</PrivateKey>" +
                "<CertificateChain><NumberOfCertificates>1</NumberOfCertificates>" +
                "<Certificate>not-a-certificate</Certificate></CertificateChain>" +
                "</Key>";
        String mixedXml = TestKeyboxFixtures.INSTANCE.getValidEcKeyboxXml()
                .replace("</Keybox>", invalidKey + "</Keybox>");

        assertEquals(0, ManagedKeyboxStateOracle.parse(new StringReader(mixedXml), "mixed.xml").size());
    }

    @Test
    public void testAttestationIdOverridesRequireOriginalTag() {
        byte[] serial = "serial".getBytes(StandardCharsets.UTF_8);
        byte[] imei = "imei".getBytes(StandardCharsets.UTF_8);
        Map<Integer, byte[]> configured = new HashMap<>();
        configured.put(713, serial);
        configured.put(714, imei);

        Map<Integer, byte[]> selected =
                CertHack.selectPresentAttestationIdOverrides(configured, List.of(714, 716));

        assertEquals(1, selected.size());
        assertTrue(selected.containsKey(714));
        assertArrayEquals(imei, selected.get(714));
    }

    @Test
    public void testSigningKeyAlgorithmUsesCertificateSigner() {
        assertEquals("EC", CertHack.signingKeyAlgorithm("SHA256withECDSA"));
        assertEquals("RSA", CertHack.signingKeyAlgorithm("SHA256withRSA"));
        assertEquals(null, CertHack.signingKeyAlgorithm("Ed25519"));
    }

    @Test
    public void testVerifiedBootDigestSelectionWithFallback() {
        byte[] runtime = new byte[32];
        byte[] original = new byte[32];
        byte[] persistent = new byte[32];
        java.util.Arrays.fill(runtime, (byte) 0x11);
        java.util.Arrays.fill(original, (byte) 0x22);
        java.util.Arrays.fill(persistent, (byte) 0x33);

        assertSame(runtime, CertHack.selectVerifiedBootDigest(runtime, original, persistent));
        assertSame(original, CertHack.selectVerifiedBootDigest(null, original, persistent));
        assertSame(original, CertHack.selectVerifiedBootDigest(new byte[32], original, persistent));
        assertSame(persistent, CertHack.selectVerifiedBootDigest(null, null, persistent));
        assertSame(persistent, CertHack.selectVerifiedBootDigest(new byte[32], new byte[32], persistent));
        assertNull(CertHack.selectVerifiedBootDigest(null, null, null));
        assertNull(CertHack.selectVerifiedBootDigest(new byte[32], new byte[31], new byte[32]));
    }

    @Test
    public void testCertificateCacheClearInvalidatesInFlightPublicationEpoch() {
        Object capturedEpoch = CertHack.captureCertificateCacheEpochForTesting();
        assertTrue(CertHack.isCertificateCacheEpochCurrentForTesting(capturedEpoch));

        CertHack.clearCertificateCache();

        assertFalse(CertHack.isCertificateCacheEpochCurrentForTesting(capturedEpoch));
    }

    @Test
    public void testIsStrongBoxKeybox() {
        assertFalse(CertHack.isStrongBoxKeybox(null));

        java.security.KeyPair keyPair = org.mockito.Mockito.mock(java.security.KeyPair.class);
        CertHack.KeyBox emptyBox = new CertHack.KeyBox(keyPair, List.of(), "empty.xml");
        assertFalse(CertHack.isStrongBoxKeybox(emptyBox));

        java.security.cert.X509Certificate teeCert = org.mockito.Mockito.mock(java.security.cert.X509Certificate.class);
        org.mockito.Mockito.when(teeCert.getSubjectX500Principal())
                .thenReturn(new javax.security.auth.x500.X500Principal("CN=Android KeyMint CA, O=Google LLC, C=US"));
        org.mockito.Mockito.when(teeCert.getIssuerX500Principal())
                .thenReturn(new javax.security.auth.x500.X500Principal("CN=Google Root CA, O=Google LLC, C=US"));
        CertHack.KeyBox teeBox = new CertHack.KeyBox(keyPair, List.of(teeCert), "tee.xml");
        assertFalse(CertHack.isStrongBoxKeybox(teeBox));

        java.security.cert.X509Certificate strongboxCert = org.mockito.Mockito.mock(java.security.cert.X509Certificate.class);
        org.mockito.Mockito.when(strongboxCert.getSubjectX500Principal())
                .thenReturn(new javax.security.auth.x500.X500Principal("CN=Google StrongBox KeyMint CA, O=Google LLC, C=US"));
        CertHack.KeyBox strongBox = new CertHack.KeyBox(keyPair, List.of(strongboxCert), "sb.xml");
        assertTrue(CertHack.isStrongBoxKeybox(strongBox));

        CertHack.KeyBox strongBoxByFilename = new CertHack.KeyBox(keyPair, List.of(teeCert), "keybox_strongbox.xml");
        assertTrue(CertHack.isStrongBoxKeybox(strongBoxByFilename));
    }

    @Test
    public void testGetKeyboxSecurityLevelDefaultsSafely() {
        assertEquals("Unknown", CertHack.getKeyboxSecurityLevel(null));
        assertEquals("Unknown", CertHack.getKeyboxSecurityLevel("non_existent.xml"));
    }

    @Test
    public void testClassifyKeyboxSecurityLevel() {
        assertEquals(CertHack.KeyboxSecurityLevel.UNKNOWN, CertHack.classifyKeyboxSecurityLevel(null));

        java.security.KeyPair keyPair = org.mockito.Mockito.mock(java.security.KeyPair.class);
        CertHack.KeyBox emptyBox = new CertHack.KeyBox(keyPair, List.of(), "empty.xml");
        assertEquals(CertHack.KeyboxSecurityLevel.UNKNOWN, CertHack.classifyKeyboxSecurityLevel(emptyBox));

        java.security.cert.X509Certificate teeCert = org.mockito.Mockito.mock(java.security.cert.X509Certificate.class);
        org.mockito.Mockito.when(teeCert.getSubjectX500Principal())
                .thenReturn(new javax.security.auth.x500.X500Principal("CN=Android KeyMint CA, O=Google LLC, C=US"));
        CertHack.KeyBox teeBox = new CertHack.KeyBox(keyPair, List.of(teeCert), "custom.xml");
        assertEquals(CertHack.KeyboxSecurityLevel.TEE, CertHack.classifyKeyboxSecurityLevel(teeBox));

        java.security.cert.X509Certificate sbCert = org.mockito.Mockito.mock(java.security.cert.X509Certificate.class);
        org.mockito.Mockito.when(sbCert.getSubjectX500Principal())
                .thenReturn(new javax.security.auth.x500.X500Principal("CN=Google StrongBox KeyMint CA, O=Google LLC, C=US"));
        CertHack.KeyBox sbBox = new CertHack.KeyBox(keyPair, List.of(sbCert), "custom.xml");
        assertEquals(CertHack.KeyboxSecurityLevel.STRONGBOX, CertHack.classifyKeyboxSecurityLevel(sbBox));

        java.security.cert.X509Certificate plainCert = org.mockito.Mockito.mock(java.security.cert.X509Certificate.class);
        org.mockito.Mockito.when(plainCert.getSubjectX500Principal())
                .thenReturn(new javax.security.auth.x500.X500Principal("CN=Generic Unbranded CA, O=Custom, C=US"));
        CertHack.KeyBox filenameSbBox = new CertHack.KeyBox(keyPair, List.of(plainCert), "device_strongbox.xml");
        assertEquals(CertHack.KeyboxSecurityLevel.STRONGBOX, CertHack.classifyKeyboxSecurityLevel(filenameSbBox));

        CertHack.KeyBox filenameTeeBox = new CertHack.KeyBox(keyPair, List.of(plainCert), "device_tee.xml");
        assertEquals(CertHack.KeyboxSecurityLevel.TEE, CertHack.classifyKeyboxSecurityLevel(filenameTeeBox));

        CertHack.KeyBox unclassifiedBox = new CertHack.KeyBox(keyPair, List.of(plainCert), "keybox.xml");
        assertEquals(CertHack.KeyboxSecurityLevel.UNKNOWN, CertHack.classifyKeyboxSecurityLevel(unclassifiedBox));
        assertFalse(CertHack.isTeeKeybox(unclassifiedBox));
        assertFalse(CertHack.isStrongBoxKeybox(unclassifiedBox));
        assertTrue(CertHack.filterKeyboxesBySecurityLevel(List.of(unclassifiedBox), false).isEmpty());
        assertTrue(CertHack.filterKeyboxesBySecurityLevel(List.of(unclassifiedBox), true).isEmpty());
    }

    @Test
    public void testFilterKeyboxesBySecurityLevelDoesNotFallback() {
        java.security.KeyPair keyPair = org.mockito.Mockito.mock(java.security.KeyPair.class);
        java.security.cert.X509Certificate strongboxCert = org.mockito.Mockito.mock(java.security.cert.X509Certificate.class);
        org.mockito.Mockito.when(strongboxCert.getSubjectX500Principal())
                .thenReturn(new javax.security.auth.x500.X500Principal("CN=Google StrongBox KeyMint CA, O=Google LLC, C=US"));
        org.mockito.Mockito.when(strongboxCert.getIssuerX500Principal())
                .thenReturn(new javax.security.auth.x500.X500Principal("CN=Google Root CA, O=Google LLC, C=US"));
        CertHack.KeyBox strongBox = new CertHack.KeyBox(keyPair, List.of(strongboxCert), "sb.xml");

        List<CertHack.KeyBox> resultForTee = CertHack.filterKeyboxesBySecurityLevel(List.of(strongBox), false);
        assertTrue("TEE request with only StrongBox candidates must return empty list without falling back", resultForTee.isEmpty());

        List<CertHack.KeyBox> resultForStrongBox = CertHack.filterKeyboxesBySecurityLevel(List.of(strongBox), true);
        assertEquals(1, resultForStrongBox.size());
        assertSame(strongBox, resultForStrongBox.get(0));
    }

    @Test
    public void testScopeAwareKeyboxIdentifiersResolveAccurately() throws Exception {
        java.security.KeyPair keyPair = org.mockito.Mockito.mock(java.security.KeyPair.class);
        java.security.cert.X509Certificate strongboxCert = org.mockito.Mockito.mock(java.security.cert.X509Certificate.class);
        org.mockito.Mockito.when(strongboxCert.getSubjectX500Principal())
                .thenReturn(new javax.security.auth.x500.X500Principal("CN=Google StrongBox KeyMint CA, O=Google LLC, C=US"));
        org.mockito.Mockito.when(strongboxCert.getIssuerX500Principal())
                .thenReturn(new javax.security.auth.x500.X500Principal("CN=Google Root CA, O=Google LLC, C=US"));

        java.security.cert.X509Certificate teeCert = org.mockito.Mockito.mock(java.security.cert.X509Certificate.class);
        org.mockito.Mockito.when(teeCert.getSubjectX500Principal())
                .thenReturn(new javax.security.auth.x500.X500Principal("CN=Android KeyMint CA, O=Google LLC, C=US"));
        org.mockito.Mockito.when(teeCert.getIssuerX500Principal())
                .thenReturn(new javax.security.auth.x500.X500Principal("CN=Google Root CA, O=Google LLC, C=US"));

        CertHack.KeyBox rootKeybox = new CertHack.KeyBox(keyPair, List.of(strongboxCert), "root:keybox.xml");
        CertHack.KeyBox managedKeybox = new CertHack.KeyBox(keyPair, List.of(teeCert), "keyboxes:keybox.xml");

        Map<String, List<CertHack.KeyBox>> keyboxes = new HashMap<>();
        keyboxes.put("EC", List.of(rootKeybox, managedKeybox));
        Map<String, List<CertHack.KeyBox>> keyboxFiles = new HashMap<>();
        keyboxFiles.put("root:keybox.xml", List.of(rootKeybox));
        keyboxFiles.put("keyboxes:keybox.xml", List.of(managedKeybox));
        keyboxFiles.put("keybox.xml", List.of(rootKeybox, managedKeybox));

        Class<?> stateClass = Class.forName("cleveres.tricky.cleverestech.keystore.CertHack$State");
        java.lang.reflect.Constructor<?> ctor = stateClass.getDeclaredConstructor(Map.class, Map.class);
        ctor.setAccessible(true);
        Object newState = ctor.newInstance(keyboxes, keyboxFiles);

        java.lang.reflect.Field stateField = CertHack.class.getDeclaredField("state");
        stateField.setAccessible(true);
        Object previousState = stateField.get(null);
        stateField.set(null, newState);

        try {
            assertEquals("StrongBox", CertHack.getKeyboxSecurityLevel("root:keybox.xml"));
            assertEquals("TEE", CertHack.getKeyboxSecurityLevel("keyboxes:keybox.xml"));
            assertEquals("StrongBox", CertHack.getKeyboxSecurityLevel("keybox.xml"));
            assertTrue(CertHack.hasStrongBoxKeybox());
            assertTrue(CertHack.isStrongBoxKeybox(rootKeybox));
            assertFalse(CertHack.isStrongBoxKeybox(managedKeybox));
        } finally {
            stateField.set(null, previousState);
        }
    }

    @Test
    public void testEmptyStateStrongBoxFastPath() {
        assertFalse(CertHack.hasStrongBoxKeybox());
        assertFalse(CertHack.hasStrongBoxKeybox(1000));
        assertEquals("Unknown", CertHack.getKeyboxSecurityLevel("any.xml"));
    }

    @Test
    public void testHackCertificateChainTeeWithOnlyStrongBoxKeyboxDoesNotRewrite() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X509Certificate strongboxCert = generateIssuerCert(kp, "CN=Google StrongBox KeyMint CA, O=Google LLC, C=US");
        CertHack.KeyBox strongBoxKeybox = ManagedOpaqueKeyOracle.wrap(
                kp, List.of(strongboxCert), "sb.xml");

        Map<String, List<CertHack.KeyBox>> newKeyboxes = new HashMap<>();
        newKeyboxes.put("RSA", List.of(strongBoxKeybox));
        Map<String, List<CertHack.KeyBox>> newKeyboxFiles = new HashMap<>();
        newKeyboxFiles.put("sb.xml", List.of(strongBoxKeybox));

        Class<?> stateClass = Class.forName("cleveres.tricky.cleverestech.keystore.CertHack$State");
        java.lang.reflect.Constructor<?> ctor = stateClass.getDeclaredConstructor(Map.class, Map.class);
        ctor.setAccessible(true);
        Object newState = ctor.newInstance(newKeyboxes, newKeyboxFiles);

        java.lang.reflect.Field stateField = CertHack.class.getDeclaredField("state");
        stateField.setAccessible(true);
        Object previousState = stateField.get(null);
        stateField.set(null, newState);

        try {
            // Genuine TEE leaf (attestation=1, keymint=1)
            X509Certificate teeLeaf = generateAttestationCert(kp, 1, 1);
            Certificate[] inputChain = new Certificate[]{teeLeaf};
            Certificate[] resultChain = CertHack.hackCertificateChain(inputChain, 0);

            // Must NOT rewrite using StrongBox keybox: returns original chain untouched
            assertSame("TEE leaf must not fall back to StrongBox keybox", inputChain, resultChain);
        } finally {
            stateField.set(null, previousState);
        }
    }

    @Test
    public void testHackCertificateChainStrongBoxWithOnlyTeeKeyboxFallsBackToTee() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X509Certificate teeCert = generateIssuerCert(kp, "CN=Android KeyMint CA, O=Google LLC, C=US");
        CertHack.KeyBox teeKeybox = ManagedOpaqueKeyOracle.wrap(
                kp, List.of(teeCert), "tee.xml");

        Map<String, List<CertHack.KeyBox>> newKeyboxes = new HashMap<>();
        newKeyboxes.put("RSA", List.of(teeKeybox));
        Map<String, List<CertHack.KeyBox>> newKeyboxFiles = new HashMap<>();
        newKeyboxFiles.put("tee.xml", List.of(teeKeybox));

        Class<?> stateClass = Class.forName("cleveres.tricky.cleverestech.keystore.CertHack$State");
        java.lang.reflect.Constructor<?> ctor = stateClass.getDeclaredConstructor(Map.class, Map.class);
        ctor.setAccessible(true);
        Object newState = ctor.newInstance(newKeyboxes, newKeyboxFiles);

        java.lang.reflect.Field stateField = CertHack.class.getDeclaredField("state");
        stateField.setAccessible(true);
        Object previousState = stateField.get(null);
        stateField.set(null, newState);

        try {
            // Genuine StrongBox leaf (attestation=2, keymint=2)
            X509Certificate sbLeaf = generateAttestationCert(kp, 2, 2);
            Certificate[] inputChain = new Certificate[]{sbLeaf};
            Certificate[] resultChain = CertHack.hackCertificateChain(inputChain, 0);

            // Asymmetric fallback: StrongBox leaf successfully rewrites using TEE keybox
            assertNotEquals("StrongBox leaf must fall back to TEE keybox and rewrite", inputChain, resultChain);
            assertEquals(2, resultChain.length);
            assertEquals(teeCert, resultChain[1]);
        } finally {
            stateField.set(null, previousState);
        }
    }

    @Test
    public void testHackCertificateChainWithOnlyUnknownKeyboxDoesNotRewrite() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X509Certificate plainCert = generateIssuerCert(kp, "CN=Generic Unbranded CA, O=Custom, C=US");
        CertHack.KeyBox unknownKeybox = ManagedOpaqueKeyOracle.wrap(
                kp, List.of(plainCert), "unknown.xml");

        Map<String, List<CertHack.KeyBox>> newKeyboxes = new HashMap<>();
        newKeyboxes.put("RSA", List.of(unknownKeybox));
        Map<String, List<CertHack.KeyBox>> newKeyboxFiles = new HashMap<>();
        newKeyboxFiles.put("unknown.xml", List.of(unknownKeybox));

        Class<?> stateClass = Class.forName("cleveres.tricky.cleverestech.keystore.CertHack$State");
        java.lang.reflect.Constructor<?> ctor = stateClass.getDeclaredConstructor(Map.class, Map.class);
        ctor.setAccessible(true);
        Object newState = ctor.newInstance(newKeyboxes, newKeyboxFiles);

        java.lang.reflect.Field stateField = CertHack.class.getDeclaredField("state");
        stateField.setAccessible(true);
        Object previousState = stateField.get(null);
        stateField.set(null, newState);

        try {
            // 1. Genuine TEE leaf must NOT rewrite when only UNKNOWN keybox is available
            X509Certificate teeLeaf = generateAttestationCert(kp, 1, 1);
            Certificate[] teeChain = new Certificate[]{teeLeaf};
            Certificate[] teeResult = CertHack.hackCertificateChain(teeChain, 0);
            assertSame("TEE leaf must not rewrite when only UNKNOWN keybox is available", teeChain, teeResult);

            // 2. Genuine StrongBox leaf must NOT rewrite when only UNKNOWN keybox is available
            X509Certificate sbLeaf = generateAttestationCert(kp, 2, 2);
            Certificate[] sbChain = new Certificate[]{sbLeaf};
            Certificate[] sbResult = CertHack.hackCertificateChain(sbChain, 0);
            assertSame("StrongBox leaf must not rewrite when only UNKNOWN keybox is available", sbChain, sbResult);
        } finally {
            stateField.set(null, previousState);
        }
    }

    private X509Certificate generateAttestationCert(KeyPair kp, int attLevel, int kmLevel) throws Exception {
        X500Name issuer = new X500Name("CN=Test Issuer");
        BigInteger serial = BigInteger.ONE;
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 100000);

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, issuer, kp.getPublic());

        ASN1EncodableVector keyDesc = new ASN1EncodableVector();
        keyDesc.add(new ASN1Integer(100));
        keyDesc.add(new ASN1Enumerated(attLevel));
        keyDesc.add(new ASN1Integer(100));
        keyDesc.add(new ASN1Enumerated(kmLevel));
        keyDesc.add(new DEROctetString(new byte[0]));
        keyDesc.add(new DEROctetString(new byte[0]));
        keyDesc.add(new DERSequence());

        ASN1EncodableVector teeEnforced = new ASN1EncodableVector();
        ASN1EncodableVector rootOfTrust = new ASN1EncodableVector();
        byte[] bootKey = new byte[32];
        bootKey[0] = 1;
        byte[] bootHash = new byte[32];
        bootHash[0] = 2;
        rootOfTrust.add(new DEROctetString(bootKey));
        rootOfTrust.add(ASN1Boolean.TRUE);
        rootOfTrust.add(new ASN1Enumerated(0));
        rootOfTrust.add(new DEROctetString(bootHash));
        teeEnforced.add(new DERTaggedObject(true, 704, new DERSequence(rootOfTrust)));
        keyDesc.add(new DERSequence(teeEnforced));

        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17");
        builder.addExtension(oid, false, new DERSequence(keyDesc));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private X509Certificate generateIssuerCert(KeyPair kp, String subjectDn) throws Exception {
        X500Name name = new X500Name(subjectDn);
        BigInteger serial = BigInteger.valueOf(2);
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 100000);
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, serial, notBefore, notAfter, name, kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}
