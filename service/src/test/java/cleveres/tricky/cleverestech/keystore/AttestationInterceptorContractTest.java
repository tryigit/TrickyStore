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
import static org.junit.Assert.assertFalse;
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
    public void getKeyEntryPostReparsesRetainedRequestWithoutPreThreadLocal() throws Exception {
        Binder target = new Binder();
        Field keystore = field(KeystoreInterceptor.class, "keystore");
        Object previous = keystore.get(null);
        keystore.set(null, target);
        Field globalModeField = field(Config.class, "isGlobalMode");
        boolean prevGlobalMode = (boolean) globalModeField.get(Config.INSTANCE);
        globalModeField.set(Config.INSTANCE, true);
        Config.INSTANCE.setPackagesForTesting(44_501, new String[] {"com.test.postreparse"});
        byte[] expectedKeyId = Utils.computeKeyDescriptorIdentity(44_501, 0, -1L, "post-reparse-k1", null);
        KeyPair parent = keyPair("EC");
        KeyPair subject = keyPair("EC");
        X509Certificate leaf = certificate(subject, parent, "postreparse", "parent");
        X509Certificate replacement = certificate(subject, parent, "replacement", "parent");
        Certificate[] rewrittenChain = new Certificate[] {replacement, replacement};
        java.util.concurrent.atomic.AtomicReference<byte[]> touchedKeyId =
                new java.util.concurrent.atomic.AtomicReference<>();
        cleveres.tricky.cleverestech.CertificateBackend.setTouchAttestKeyOverrideForTesting((uid, id) -> {
            touchedKeyId.set(id.clone());
            return cleveres.tricky.cleverestech.CertificateBackend.AttestKeyTouchResult.PRESENT;
        });
        cleveres.tricky.cleverestech.ManagedAttestKeyRegistry.INSTANCE.remember(
                44_501, expectedKeyId, null, leaf.getEncoded());
        try (MockedStatic<CertHack> backend = mockStatic(CertHack.class);
             MockedStatic<Parcel> parcels = mockStatic(Parcel.class)) {
            backend.when(CertHack::canHack).thenReturn(true);
            backend.when(() -> CertHack.hackCertificateChain(any(), anyInt(), anyBoolean()))
                    .thenReturn(rewrittenChain);
            Parcel obtained = mock(Parcel.class);
            parcels.when(Parcel::obtain).thenReturn(obtained);

            KeyMetadata metadata = metadata(leaf, leaf.getEncoded());
            KeyEntryResponse response = new KeyEntryResponse();
            response.metadata = metadata;
            Parcel reply = mock(Parcel.class);
            when(reply.readTypedObject(KeyEntryResponse.CREATOR)).thenReturn(response);

            BinderInterceptor.Result result = KeystoreInterceptor.INSTANCE.onPostTransact(target,
                    field(KeystoreInterceptor.class, "getKeyEntryTransaction").getInt(null),
                    0, 44_501, 42, descriptorRequest("post-reparse-k1"), reply, 0);
            assertTrue(result instanceof BinderInterceptor.OverrideReply);
            assertNotNull(touchedKeyId.get());
            assertArrayEquals(expectedKeyId, touchedKeyId.get());
        } finally {
            cleveres.tricky.cleverestech.CertificateBackend.resetForTesting();
            keystore.set(null, previous);
            globalModeField.set(Config.INSTANCE, prevGlobalMode);
        }
    }

    @Test
    public void leafOnlyManagedChildReadbackRewritesAgainstRegistryParent() throws Exception {
        Binder target = new Binder();
        Field keystore = field(KeystoreInterceptor.class, "keystore");
        Object previous = keystore.get(null);
        keystore.set(null, target);
        Field globalModeField = field(Config.class, "isGlobalMode");
        boolean prevGlobalMode = (boolean) globalModeField.get(Config.INSTANCE);
        globalModeField.set(Config.INSTANCE, true);
        Config.INSTANCE.setPackagesForTesting(44_502, new String[] {"com.test.managedchild"});
        byte[] parentId = new byte[32];
        parentId[0] = 3;
        parentId[1] = 7;
        byte[] childId = Utils.computeKeyDescriptorIdentity(44_502, 0, -1L, "managed-child", null);
        KeyPair parent = keyPair("EC");
        KeyPair subject = keyPair("EC");
        X509Certificate childLeaf = certificate(subject, parent, "managed-child", "parent");
        X509Certificate replacement = certificate(subject, parent, "replacement", "parent");
        cleveres.tricky.cleverestech.ManagedAttestKeyRegistry.INSTANCE.remember(
                44_502, childId, parentId, null, false);
        cleveres.tricky.cleverestech.CertificateBackend.setTouchAttestKeyOverrideForTesting(
                (uid, id) -> cleveres.tricky.cleverestech.CertificateBackend.AttestKeyTouchResult.PRESENT);
        try (MockedStatic<CertHack> backend = mockStatic(CertHack.class);
             MockedStatic<Parcel> parcels = mockStatic(Parcel.class)) {
            backend.when(CertHack::canHack).thenReturn(true);
            backend.when(() -> CertHack.hackChildKeyCertificate(
                    any(), anyInt(), anyBoolean(), anyBoolean(), any(), any()))
                    .thenReturn(new Certificate[] {replacement});
            Parcel obtained = mock(Parcel.class);
            parcels.when(Parcel::obtain).thenReturn(obtained);

            KeyMetadata metadata = metadata(childLeaf, null);
            KeyEntryResponse response = new KeyEntryResponse();
            response.metadata = metadata;
            Parcel reply = mock(Parcel.class);
            when(reply.readTypedObject(KeyEntryResponse.CREATOR)).thenReturn(response);
            BinderInterceptor.Result result = KeystoreInterceptor.INSTANCE.onPostTransact(target,
                    field(KeystoreInterceptor.class, "getKeyEntryTransaction").getInt(null),
                    0, 44_502, 42, descriptorRequest("managed-child"), reply, 0);
            assertTrue(result instanceof BinderInterceptor.OverrideReply);
            assertArrayEquals(replacement.getEncoded(), metadata.certificate);

            KeyMetadata ordinaryMetadata = metadata(childLeaf, null);
            KeyEntryResponse ordinaryResponse = new KeyEntryResponse();
            ordinaryResponse.metadata = ordinaryMetadata;
            Parcel ordinaryReply = mock(Parcel.class);
            when(ordinaryReply.readTypedObject(KeyEntryResponse.CREATOR)).thenReturn(ordinaryResponse);
            byte[] before = ordinaryMetadata.certificate;
            BinderInterceptor.Result ordinaryResult = KeystoreInterceptor.INSTANCE.onPostTransact(target,
                    field(KeystoreInterceptor.class, "getKeyEntryTransaction").getInt(null),
                    0, 44_502, 42, descriptorRequest("unknown-child"), ordinaryReply, 0);
            assertSame(BinderInterceptor.Skip.INSTANCE, ordinaryResult);
            assertSame(before, ordinaryMetadata.certificate);
        } finally {
            cleveres.tricky.cleverestech.CertificateBackend.resetForTesting();
            keystore.set(null, previous);
            globalModeField.set(Config.INSTANCE, prevGlobalMode);
        }
    }

    @Test
    public void leafOnlyManagedChildReadbackRewritesEvenWhenRegistryIsSaturated() throws Exception {
        Binder target = new Binder();
        Field keystore = field(KeystoreInterceptor.class, "keystore");
        Object previous = keystore.get(null);
        keystore.set(null, target);
        Field globalModeField = field(Config.class, "isGlobalMode");
        boolean prevGlobalMode = (boolean) globalModeField.get(Config.INSTANCE);
        globalModeField.set(Config.INSTANCE, true);
        int uid = 44_508;
        Config.INSTANCE.setPackagesForTesting(uid, new String[] {"com.test.saturated"});
        byte[] parentId = new byte[32];
        parentId[0] = 7;
        parentId[1] = 8;
        byte[] childId = Utils.computeKeyDescriptorIdentity(uid, 0, -1L, "saturated-child", null);
        KeyPair parent = keyPair("EC");
        KeyPair subject = keyPair("EC");
        X509Certificate childLeaf = certificate(subject, parent, "saturated-child", "parent");
        X509Certificate replacement = certificate(subject, parent, "replacement", "parent");

        for (int i = 1; i <= 260; i++) {
            byte[] dummy = new byte[32];
            dummy[0] = (byte) (i >> 8);
            dummy[1] = (byte) i;
            dummy[2] = 5;
            cleveres.tricky.cleverestech.ManagedAttestKeyRegistry.INSTANCE.remember(uid, dummy);
        }

        cleveres.tricky.cleverestech.ManagedAttestKeyRegistry.INSTANCE.remember(
                uid, childId, parentId, null, false);
        cleveres.tricky.cleverestech.CertificateBackend.setTouchAttestKeyOverrideForTesting(
                (u, id) -> cleveres.tricky.cleverestech.CertificateBackend.AttestKeyTouchResult.PRESENT);
        try (MockedStatic<CertHack> backend = mockStatic(CertHack.class);
             MockedStatic<Parcel> parcels = mockStatic(Parcel.class)) {
            backend.when(CertHack::canHack).thenReturn(true);
            backend.when(() -> CertHack.hackChildKeyCertificate(
                    any(), anyInt(), anyBoolean(), anyBoolean(), any(), any()))
                    .thenReturn(new Certificate[] {replacement});
            Parcel obtained = mock(Parcel.class);
            parcels.when(Parcel::obtain).thenReturn(obtained);

            KeyMetadata metadata = metadata(childLeaf, null);
            KeyEntryResponse response = new KeyEntryResponse();
            response.metadata = metadata;
            Parcel reply = mock(Parcel.class);
            when(reply.readTypedObject(KeyEntryResponse.CREATOR)).thenReturn(response);
            BinderInterceptor.Result result = KeystoreInterceptor.INSTANCE.onPostTransact(target,
                    field(KeystoreInterceptor.class, "getKeyEntryTransaction").getInt(null),
                    0, uid, 42, descriptorRequest("saturated-child"), reply, 0);
            assertTrue(result instanceof BinderInterceptor.OverrideReply);
            assertArrayEquals(replacement.getEncoded(), metadata.certificate);
        } finally {
            cleveres.tricky.cleverestech.CertificateBackend.resetForTesting();
            cleveres.tricky.cleverestech.ManagedAttestKeyRegistry.resetForTesting();
            keystore.set(null, previous);
            globalModeField.set(Config.INSTANCE, prevGlobalMode);
        }
    }

    @Test
    public void childKeyReadbackDoesNotTouchRustBackendAndRewritesUsingRegistryParent() throws Exception {
        Binder target = new Binder();
        Field keystore = field(KeystoreInterceptor.class, "keystore");
        Object previous = keystore.get(null);
        keystore.set(null, target);
        Field globalModeField = field(Config.class, "isGlobalMode");
        boolean prevGlobalMode = (boolean) globalModeField.get(Config.INSTANCE);
        globalModeField.set(Config.INSTANCE, true);
        Config.INSTANCE.setPackagesForTesting(44_503, new String[] {"com.test.childnotouch"});
        byte[] parentId = new byte[32];
        parentId[0] = 5;
        parentId[1] = 9;
        byte[] childId = Utils.computeKeyDescriptorIdentity(44_503, 0, -1L, "child-no-touch", null);
        KeyPair parent = keyPair("EC");
        KeyPair subject = keyPair("EC");
        X509Certificate childLeaf = certificate(subject, parent, "child-no-touch", "parent");
        X509Certificate replacement = certificate(subject, parent, "replacement", "parent");

        cleveres.tricky.cleverestech.ManagedAttestKeyRegistry.INSTANCE.remember(
                44_503, childId, parentId, null, false);

        java.util.concurrent.atomic.AtomicBoolean childTouched = new java.util.concurrent.atomic.AtomicBoolean(false);
        cleveres.tricky.cleverestech.CertificateBackend.setTouchAttestKeyOverrideForTesting((uid, id) -> {
            if (java.util.Arrays.equals(id, childId)) {
                childTouched.set(true);
                return cleveres.tricky.cleverestech.CertificateBackend.AttestKeyTouchResult.ABSENT;
            }
            return cleveres.tricky.cleverestech.CertificateBackend.AttestKeyTouchResult.PRESENT;
        });

        try (MockedStatic<CertHack> backend = mockStatic(CertHack.class);
             MockedStatic<Parcel> parcels = mockStatic(Parcel.class)) {
            backend.when(CertHack::canHack).thenReturn(true);
            backend.when(() -> CertHack.hackChildKeyCertificate(
                    any(), anyInt(), anyBoolean(), anyBoolean(), any(), any()))
                    .thenReturn(new Certificate[] {replacement});
            Parcel obtained = mock(Parcel.class);
            parcels.when(Parcel::obtain).thenReturn(obtained);

            KeyMetadata metadata = metadata(childLeaf, null);
            KeyEntryResponse response = new KeyEntryResponse();
            response.metadata = metadata;
            Parcel reply = mock(Parcel.class);
            when(reply.readTypedObject(KeyEntryResponse.CREATOR)).thenReturn(response);

            BinderInterceptor.Result result = KeystoreInterceptor.INSTANCE.onPostTransact(target,
                    field(KeystoreInterceptor.class, "getKeyEntryTransaction").getInt(null),
                    0, 44_503, 42, descriptorRequest("child-no-touch"), reply, 0);

            assertTrue(result instanceof BinderInterceptor.OverrideReply);
            assertArrayEquals(replacement.getEncoded(), metadata.certificate);
            assertFalse("Child key must NOT trigger touchAttestKey on getKeyEntry", childTouched.get());
        } finally {
            cleveres.tricky.cleverestech.CertificateBackend.resetForTesting();
            keystore.set(null, previous);
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
            backend.when(() -> CertHack.hackAttestKeyCertificateChain(any(), anyInt(), anyBoolean(), any()))
                    .thenReturn(rewrittenChain);

            Parcel request = mock(Parcel.class);
            java.util.concurrent.atomic.AtomicInteger pos = new java.util.concurrent.atomic.AtomicInteger(28);
            when(request.dataPosition()).thenAnswer(inv -> pos.get());
            org.mockito.Mockito.doAnswer(inv -> {
                pos.set(inv.getArgument(0));
                return null;
            }).when(request).setDataPosition(anyInt());
            when(request.dataAvail()).thenReturn(128);
            when(request.dataSize()).thenReturn(128);
            java.util.Iterator<Integer> ints = java.util.Arrays.asList(
                    1, 16, 0,
                    0,
                    1, 1, 20, 536870913, 7, 7
            ).iterator();
            when(request.readInt()).thenAnswer(inv -> ints.hasNext() ? ints.next() : 0);

            BinderInterceptor.Result preResult = new SecurityLevelInterceptor().onPreTransact(
                    target, code, 0, 10_001, 42, request);
            assertSame(BinderInterceptor.Continue.INSTANCE, preResult);

            Parcel reply = generatedReply(metadata);
            BinderInterceptor.Result postResult = generate(request, reply);
            assertTrue(postResult instanceof BinderInterceptor.OverrideReply);

            backend.verify(() -> CertHack.hackAttestKeyCertificateChain(any(), anyInt(), anyBoolean(), any()),
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

    private static Parcel descriptorRequest(String alias) {
        Parcel request = mock(Parcel.class);
        when(request.dataPosition()).thenReturn(28);
        when(request.dataAvail()).thenReturn(128);
        when(request.dataSize()).thenReturn(128);
        when(request.readInt()).thenReturn(1, 64, 0);
        when(request.readLong()).thenReturn(-1L);
        when(request.readString()).thenReturn(alias);
        when(request.createByteArray()).thenReturn(null);
        return request;
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
