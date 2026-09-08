package cleveres.tricky.cleverestech.keystore;

import android.hardware.security.keymint.SecurityLevel;
import android.os.Binder;
import android.os.Parcel;
import android.system.keystore2.KeyEntryResponse;
import android.system.keystore2.KeyMetadata;
import cleveres.tricky.cleverestech.Config;
import cleveres.tricky.cleverestech.KeystoreInterceptor;
import cleveres.tricky.cleverestech.SecurityLevelInterceptor;
import cleveres.tricky.cleverestech.binder.BinderInterceptor;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Test;
import org.mockito.MockedStatic;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AttestationInterceptorContractTest {
    @Test
    public void attestedKeyGenerationUniformlyRewritesAcrossDefaultAndCustomAttestKey() throws Exception {
        Binder target = new Binder();
        int code = field(SecurityLevelInterceptor.class, "generateKeyTransaction").getInt(null);
        Field globalModeField = field(Config.class, "isGlobalMode");
        boolean prevGlobalMode = (boolean) globalModeField.get(Config.INSTANCE);
        globalModeField.set(Config.INSTANCE, true);
        Config.INSTANCE.setPackagesForTesting(10_001, new String[] {"com.test.app"});
        try (MockedStatic<CertHack> backend = mockStatic(CertHack.class)) {
            backend.when(CertHack::canHack).thenReturn(true);
            backend.when(() -> CertHack.applyCachedCertificateChain(any())).thenReturn(false);

            KeyPair parent = keyPair("EC");
            KeyPair childKey = keyPair("EC");
            X509Certificate childCert = certificate(childKey, parent, "child", "parent");
            KeyMetadata metadata = metadata(childCert, childCert.getEncoded());
            X509Certificate replacementCert = certificate(childKey, parent, "replacement", "parent");
            Certificate[] rewrittenChain = new Certificate[] {replacementCert};
            backend.when(() -> CertHack.hackCertificateChain(any(), anyInt(), anyBoolean()))
                    .thenReturn(rewrittenChain);
            backend.when(() -> CertHack.hackChildKeyCertificate(any(), anyInt(), anyBoolean(), anyBoolean()))
                    .thenReturn(rewrittenChain);

            // Test both default RKP request (false) and custom AttestKey request (true)
            for (boolean explicitAttestKey : new boolean[] {false, true}) {
                Parcel request = AttestationRequestContractTest.request(explicitAttestKey);
                BinderInterceptor.Result preResult = new SecurityLevelInterceptor().onPreTransact(
                        target, code, 0, 10_001, 42, request);
                assertSame(BinderInterceptor.Continue.INSTANCE, preResult);

                Parcel reply = generatedReply(metadata);
                BinderInterceptor.Result postResult = generate(request, reply);
                assertTrue("Attested key (explicitAttestKey=" + explicitAttestKey + ") must receive OverrideReply",
                        postResult instanceof BinderInterceptor.OverrideReply);
            }

            backend.verify(CertHack::canHack, org.mockito.Mockito.times(2));
            backend.verify(() -> CertHack.hackCertificateChain(any(), anyInt(), anyBoolean()),
                    org.mockito.Mockito.times(1));
            backend.verify(() -> CertHack.hackChildKeyCertificate(any(), anyInt(), anyBoolean(), anyBoolean()),
                    org.mockito.Mockito.times(1));
        } finally {
            globalModeField.set(Config.INSTANCE, prevGlobalMode);
        }
    }

    @Test
    public void attestKeyGenerationWithDefaultAttestationKeyRoutesToHackAttestKeyCertificateChain() throws Exception {
        Binder target = new Binder();
        int code = field(SecurityLevelInterceptor.class, "generateKeyTransaction").getInt(null);
        Field globalModeField = field(Config.class, "isGlobalMode");
        boolean prevGlobalMode = (boolean) globalModeField.get(Config.INSTANCE);
        globalModeField.set(Config.INSTANCE, true);
        Config.INSTANCE.setPackagesForTesting(10_001, new String[] {"com.test.app"});
        try (MockedStatic<CertHack> backend = mockStatic(CertHack.class)) {
            backend.when(CertHack::canHack).thenReturn(true);
            backend.when(() -> CertHack.applyCachedCertificateChain(any())).thenReturn(false);

            KeyPair parent = keyPair("EC");
            KeyPair childKey = keyPair("EC");
            X509Certificate childCert = certificate(childKey, parent, "child", "parent");
            KeyMetadata metadata = metadata(childCert, childCert.getEncoded());
            X509Certificate replacementCert = certificate(childKey, parent, "replacement", "parent");
            Certificate[] rewrittenChain = new Certificate[] {replacementCert};
            backend.when(() -> CertHack.hackAttestKeyCertificateChain(any(), anyInt(), anyBoolean()))
                    .thenReturn(rewrittenChain);

            Parcel request = mock(Parcel.class);
            when(request.dataPosition()).thenReturn(28, 32, 28, 32, 40, 44);
            when(request.dataAvail()).thenReturn(128);
            // 3 ints for usesDefaultAttestationKey (1, 16, 0), then 9 ints for hasAttestKeyPurpose
            when(request.readInt()).thenReturn(1, 16, 0, 1, 16, 0, 1, 1, 20, 536870913, 7, 7);
            when(request.dataSize()).thenReturn(128);

            BinderInterceptor.Result preResult = new SecurityLevelInterceptor().onPreTransact(
                    target, code, 0, 10_001, 42, request);
            assertSame(BinderInterceptor.Continue.INSTANCE, preResult);

            Parcel reply = generatedReply(metadata);
            BinderInterceptor.Result postResult = generate(request, reply);
            assertTrue(postResult instanceof BinderInterceptor.OverrideReply);

            backend.verify(() -> CertHack.hackAttestKeyCertificateChain(any(), anyInt(), anyBoolean()),
                    org.mockito.Mockito.times(1));
            backend.verify(() -> CertHack.hackCertificateChain(any(), anyInt(), anyBoolean()), never());
            backend.verify(() -> CertHack.hackChildKeyCertificate(any(), anyInt(), anyBoolean(), anyBoolean()), never());
        } finally {
            globalModeField.set(Config.INSTANCE, prevGlobalMode);
        }
    }

    @Test
    public void nonAttestedKeysBypassCertHackRewrite() throws Exception {
        KeyPair c = keyPair("EC");
        X509Certificate ordinary = certificate(c, c, "ordinary", "ordinary", false);
        KeyMetadata metadata = metadata(ordinary, new byte[0]);
        Parcel request = AttestationRequestContractTest.request(false);
        Parcel reply = generatedReply(metadata);

        try (MockedStatic<CertHack> backend = mockStatic(CertHack.class)) {
            backend.when(CertHack::canHack).thenReturn(true);
            BinderInterceptor.Result postResult = generate(request, reply);
            assertSame(BinderInterceptor.Skip.INSTANCE, postResult);
            backend.verify(() -> CertHack.hackCertificateChain(any(), anyInt(), anyBoolean()), never());
        }
    }

    @Test
    public void ordinaryNonAttestedKeysSurviveRepeatedReadbackWithoutRewrite() throws Exception {
        KeyPair c = keyPair("EC");
        X509Certificate ordinary = certificate(c, c, "ordinary", "ordinary", false);

        Binder target = new Binder();
        Field keystore = field(KeystoreInterceptor.class, "keystore");
        Object previous = keystore.get(null);
        keystore.set(null, target);
        try (MockedStatic<CertHack> backend = mockStatic(CertHack.class)) {
            backend.when(CertHack::canHack).thenReturn(true);
            backend.when(() -> CertHack.applyCachedCertificateChain(any())).thenReturn(false);
            backend.when(() -> CertHack.hackCertificateChain(any(), anyInt(), anyBoolean()))
                    .thenAnswer(invocation -> invocation.getArgument(0));

            for (byte[] chain : new byte[][] {null, new byte[0]}) {
                KeyMetadata metadata = metadata(ordinary, chain);
                byte[] original = metadata.certificate.clone();

                // Non-attested leaf must be skipped by generateKey without backend interaction.
                assertSame(BinderInterceptor.Skip.INSTANCE,
                        generate(AttestationRequestContractTest.request(false), generatedReply(metadata)));

                for (int read = 0; read < 320; read++) {
                    KeyEntryResponse response = new KeyEntryResponse();
                    response.metadata = metadata;
                    Parcel reply = mock(Parcel.class);
                    when(reply.readTypedObject(KeyEntryResponse.CREATOR)).thenReturn(response);
                    assertSame(BinderInterceptor.Skip.INSTANCE,
                            KeystoreInterceptor.INSTANCE.onPostTransact(target,
                                    field(KeystoreInterceptor.class, "getKeyEntryTransaction").getInt(null),
                                    0, 10_001, 42, mock(Parcel.class), reply, 0));
                }
                assertArrayEquals(original, metadata.certificate);
                assertSame(chain, metadata.certificateChain);
            }
            backend.verify(() -> CertHack.hackCertificateChain(any(), anyInt(), anyBoolean()), never());
        } finally {
            keystore.set(null, previous);
        }
    }

    @Test
    public void leafOnlyAttestKeyGraphAndOrdinaryKeysSurviveRepeatedReadback() throws Exception {
        KeyPair a = keyPair("EC");
        KeyPair b = keyPair("RSA");
        KeyPair c = keyPair("EC");
        X509Certificate ab = certificate(b, a, "B", "A");
        X509Certificate bc = certificate(c, b, "C", "B");
        X509Certificate ordinary = certificate(c, c, "ordinary", "ordinary", false);

        Binder target = new Binder();
        Field keystore = field(KeystoreInterceptor.class, "keystore");
        Object previous = keystore.get(null);
        keystore.set(null, target);
        
        // Inject stale cache entries that simulate a generic key hit (leafOnlySafe = false)
        Field stateField = field(CertHack.class, "state");
        Object stateObj = stateField.get(null);
        Field cacheField = field(stateObj.getClass(), "certificateCache");
        java.util.Map cache = (java.util.Map) cacheField.get(stateObj);
        Class<?> cacheKeyClass = Class.forName("cleveres.tricky.cleverestech.keystore.CertHack$CacheKey");
        java.lang.reflect.Constructor<?> cacheKeyCtor = cacheKeyClass.getDeclaredConstructor(byte[].class);
        cacheKeyCtor.setAccessible(true);
        Class<?> cachedChainClass = Class.forName("cleveres.tricky.cleverestech.keystore.CertHack$CachedCertificateChain");
        java.lang.reflect.Constructor<?> cachedChainCtor = cachedChainClass.getDeclaredConstructor(Certificate[].class, byte[].class, byte[].class, boolean.class);
        cachedChainCtor.setAccessible(true);
        
        Field globalModeField = field(Config.class, "isGlobalMode");
        boolean prevGlobalMode = (boolean) globalModeField.get(Config.INSTANCE);
        globalModeField.set(Config.INSTANCE, true);
        Config.INSTANCE.setPackagesForTesting(10_001, new String[] {"com.test.app"});

        try (MockedStatic<CertHack> backend = mockStatic(CertHack.class, org.mockito.Mockito.CALLS_REAL_METHODS)) {
            backend.when(CertHack::canHack).thenReturn(true);
            backend.when(() -> CertHack.hackCertificateChain(any(), anyInt(), anyBoolean()))
                    .thenReturn(new Certificate[] {ab, ab});

            for (X509Certificate child : new X509Certificate[] {ab, bc, ordinary}) {
                Object cacheKey = cacheKeyCtor.newInstance((Object) child.getEncoded());
                byte[] staleReplacement = new byte[] {9, 9, 9};
                Object cachedChain = cachedChainCtor.newInstance(new Certificate[] {child}, staleReplacement, new byte[0], false);
                cache.put(cacheKey, cachedChain);
                
                for (byte[] chain : new byte[][] {null, new byte[0]}) {
                    KeyMetadata metadata = metadata(child, chain);
                    byte[] original = metadata.certificate.clone();
                    
                    if (child == ordinary) {
                        // Ordinary keys are not attested, so they fail the attestation extension check
                        // even if they pass the request guard.
                        assertSame(BinderInterceptor.Skip.INSTANCE,
                                generate(AttestationRequestContractTest.request(false), generatedReply(metadata)));
                    } else {
                        // Attested keys (including custom AttestKey children) uniformly rewrite in post-transact
                        int code = field(SecurityLevelInterceptor.class, "generateKeyTransaction").getInt(null);
                        BinderInterceptor.Result preResult = new SecurityLevelInterceptor().onPreTransact(
                                target, code, 0, 10_001, 42, AttestationRequestContractTest.request(true));
                        assertSame(BinderInterceptor.Continue.INSTANCE, preResult);
                        assertTrue(
                                generate(AttestationRequestContractTest.request(true), generatedReply(metadata))
                                        instanceof BinderInterceptor.OverrideReply);
                    }

                    for (int read = 0; read < 320; read++) {
                        KeyEntryResponse response = new KeyEntryResponse();
                        KeyMetadata readMetadata = metadata(child, chain);
                        response.metadata = readMetadata;
                        Parcel reply = mock(Parcel.class);
                        when(reply.readTypedObject(KeyEntryResponse.CREATOR)).thenReturn(response);
                        BinderInterceptor.Result result = KeystoreInterceptor.INSTANCE.onPostTransact(target,
                                field(KeystoreInterceptor.class, "getKeyEntryTransaction").getInt(null),
                                0, 10_001, 42, mock(Parcel.class), reply, 0);
                        
                        // All non-hardware issuers (custom AttestKey children and ordinary keys) return Skip
                        // on readback to preserve genuine cross-signatures byte-for-byte.
                        assertSame(BinderInterceptor.Skip.INSTANCE, result);
                        assertArrayEquals(original, readMetadata.certificate);
                        assertSame(chain, readMetadata.certificateChain);
                    }
                }
            }
        } finally {
            keystore.set(null, previous);
            globalModeField.set(Config.INSTANCE, prevGlobalMode);
        }
        ab.verify(a.getPublic());
        bc.verify(b.getPublic());
    }

    @Test
    public void nonAttestedKeyGenerationContinuesPreTransactAndSkipsPostTransact() throws Exception {
        Binder target = new Binder();
        Field globalModeField = field(Config.class, "isGlobalMode");
        boolean prevGlobalMode = (boolean) globalModeField.get(Config.INSTANCE);
        globalModeField.set(Config.INSTANCE, true);
        Config.INSTANCE.setPackagesForTesting(10_001, new String[] {"com.test.app"});
        try {
            Parcel request = AttestationRequestContractTest.request(false);
            try (MockedStatic<CertHack> backend = mockStatic(CertHack.class)) {
                backend.when(CertHack::canHack).thenReturn(true);

                int code = field(SecurityLevelInterceptor.class, "generateKeyTransaction").getInt(null);
                BinderInterceptor.Result result = new SecurityLevelInterceptor().onPreTransact(
                        target, code, 0, 10_001, 42, request);
                assertSame(BinderInterceptor.Continue.INSTANCE, result);
            }
        } finally {
            globalModeField.set(Config.INSTANCE, prevGlobalMode);
        }

        // Post-transact skips non-attested leaf without attestation extension
        KeyPair c = keyPair("EC");
        X509Certificate nonAttested = certificate(c, c, "nonattested", "nonattested", false);
        KeyMetadata metadata = metadata(nonAttested, null);
        Parcel request = AttestationRequestContractTest.request(false);
        Parcel reply = generatedReply(metadata);
        try (MockedStatic<CertHack> backend = mockStatic(CertHack.class)) {
            backend.when(CertHack::canHack).thenReturn(true);
            assertSame(BinderInterceptor.Skip.INSTANCE, generate(request, reply));
            backend.verifyNoInteractions();
        }
    }

    @Test
    public void strongBoxKeyGenerationRewritesNormallyWhenStrongBoxKeyboxAvailable() throws Exception {
        KeyPair issuer = keyPair("EC");
        X509Certificate child = certificate(keyPair("EC"), issuer, "strongbox_child", "issuer");
        KeyMetadata metadata = metadata(child, child.getEncoded());
        metadata.keySecurityLevel = SecurityLevel.STRONGBOX;

        Parcel request = AttestationRequestContractTest.request(false);
        Parcel reply = generatedReply(metadata);
        Certificate[] replacement = new Certificate[] {child, child};

        try (MockedStatic<CertHack> backend = mockStatic(CertHack.class)) {
            backend.when(CertHack::canHack).thenReturn(true);
            backend.when(() -> CertHack.hackCertificateChain(any(), anyInt(), anyBoolean())).thenReturn(replacement);

            BinderInterceptor.Result result = generate(request, reply);
            org.junit.Assert.assertTrue(result instanceof BinderInterceptor.OverrideReply);
            backend.verify(() -> CertHack.hackCertificateChain(any(), anyInt(), anyBoolean()));
            ((BinderInterceptor.OverrideReply) result).getReply().recycle();
        }
    }

    @Test
    public void ordinaryCompleteAttestationStillUsesTheExistingRewritePath() throws Exception {
        KeyPair issuer = keyPair("EC");
        X509Certificate child = certificate(keyPair("EC"), issuer, "child", "issuer");
        KeyMetadata metadata = metadata(child, child.getEncoded());
        Certificate[] replacement = new Certificate[] {child, child};
        try (MockedStatic<CertHack> backend = mockStatic(CertHack.class)) {
            backend.when(() -> CertHack.hackCertificateChain(any(), anyInt(), anyBoolean())).thenReturn(replacement);
            BinderInterceptor.Result result =
                    generate(AttestationRequestContractTest.request(false), generatedReply(metadata));
            org.junit.Assert.assertTrue(result instanceof BinderInterceptor.OverrideReply);
            backend.verify(() -> CertHack.hackCertificateChain(any(), anyInt(), anyBoolean()));
            ((BinderInterceptor.OverrideReply) result).getReply().recycle();
        }
    }

    private static BinderInterceptor.Result generate(Parcel request, Parcel reply) throws Exception {
        return new SecurityLevelInterceptor().onPostTransact(new Binder(),
                field(SecurityLevelInterceptor.class, "generateKeyTransaction").getInt(null),
                0, 10_001, 42, request, reply, 0);
    }

    private static Parcel generatedReply(KeyMetadata metadata) {
        Parcel reply = mock(Parcel.class);
        when(reply.readTypedObject(KeyMetadata.CREATOR)).thenReturn(metadata);
        return reply;
    }

    private static KeyMetadata metadata(X509Certificate leaf, byte[] issuers) throws Exception {
        KeyMetadata metadata = new KeyMetadata();
        metadata.keySecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT;
        metadata.certificate = leaf.getEncoded();
        metadata.certificateChain = issuers;
        return metadata;
    }

    private static Field field(Class<?> owner, String name) throws Exception {
        Field field = owner.getDeclaredField(name);
        field.setAccessible(true);
        return field;
    }

    private static KeyPair keyPair(String algorithm) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        generator.initialize(algorithm.equals("RSA") ? 2048 : 256);
        return generator.generateKeyPair();
    }

    private static X509Certificate certificate(KeyPair subject, KeyPair issuer,
                                               String subjectName, String issuerName) throws Exception {
        return certificate(subject, issuer, subjectName, issuerName, true);
    }

    private static X509Certificate certificate(KeyPair subject, KeyPair issuer,
                                               String subjectName, String issuerName,
                                               boolean attested) throws Exception {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Name("CN=" + issuerName), BigInteger.ONE,
                new Date(0), new Date(4_102_444_800_000L),
                new X500Name("CN=" + subjectName), subject.getPublic());
        if (attested) builder.addExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), false,
                new DERSequence(new ASN1Encodable[] {
                        new ASN1Integer(400), new ASN1Enumerated(1),
                        new ASN1Integer(400), new ASN1Enumerated(1),
                        new DEROctetString(new byte[] {1}), new DEROctetString(new byte[0]),
                        new DERSequence(), new DERSequence()
                }));
        String algorithm = issuer.getPrivate().getAlgorithm().equals("RSA")
                ? "SHA256withRSA" : "SHA256withECDSA";
        return new JcaX509CertificateConverter().setProvider(provider).getCertificate(
                builder.build(new JcaContentSignerBuilder(algorithm).setProvider(provider)
                        .build(issuer.getPrivate())));
    }
}
