package cleveres.tricky.cleverestech.keystore;

import android.os.Parcel;
import android.system.keystore2.IKeystoreSecurityLevel;
import android.system.keystore2.KeyMetadata;
import org.junit.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.security.cert.Certificate;
import java.util.Map;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AttestationRequestContractTest {
    @Test
    public void onlyExplicitNullAttestationKeyPermitsGenericRewrite() {
        Parcel request = request(false);
        assertTrue(Utils.usesDefaultAttestationKey(request));
        verify(request).enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR);
        verify(request).setDataPosition(28);

        request = request(true);
        assertFalse(Utils.usesDefaultAttestationKey(request));
        verify(request).setDataPosition(28);
    }

    @Test
    public void missingOrMalformedRequestCannotBecomeDefaultIssuer() {
        Parcel request = request(false);
        when(request.dataAvail()).thenReturn(0);
        assertFalse(Utils.usesDefaultAttestationKey(request));
        verify(request).setDataPosition(28);

        request = request(false);
        when(request.dataAvail()).thenReturn(64, 0);
        assertFalse(Utils.usesDefaultAttestationKey(request));
        verify(request).setDataPosition(28);

        request = request(false);
        when(request.readInt()).thenReturn(0);
        assertFalse(Utils.usesDefaultAttestationKey(request));
        verify(request).setDataPosition(28);

        request = request(false);
        when(request.readInt()).thenReturn(1, Integer.BYTES - 1);
        assertFalse(Utils.usesDefaultAttestationKey(request));
        verify(request).setDataPosition(28);

        request = request(false);
        when(request.dataPosition()).thenReturn(28, Integer.MAX_VALUE - 1);
        when(request.readInt()).thenReturn(1, Integer.BYTES);
        assertFalse(Utils.usesDefaultAttestationKey(request));
        verify(request).setDataPosition(28);

        request = request(false);
        when(request.dataSize()).thenReturn(40);
        assertFalse(Utils.usesDefaultAttestationKey(request));
        verify(request).setDataPosition(28);

        request = request(false);
        doThrow(new SecurityException("wrong interface"))
                .when(request).enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR);
        assertFalse(Utils.usesDefaultAttestationKey(request));
        verify(request).setDataPosition(28);
    }

    @Test
    public void rawChainGateRejectsLeafOnlyAndOverLimitMetadataWithoutMutation() {
        assertFalse(Utils.isCertificateChainRewriteCandidate(null));
        KeyMetadata metadata = new KeyMetadata();
        byte[] leaf = new byte[] {1, 2, 3};
        metadata.certificate = leaf;
        for (byte[] issuers : new byte[][] {null, new byte[0], new byte[512 * 1024 + 1]}) {
            metadata.certificateChain = issuers;
            assertFalse(Utils.isCertificateChainRewriteCandidate(metadata));
            assertFalse(CertHack.applyCachedCertificateChain(metadata));
            assertSame(leaf, metadata.certificate);
            assertSame(issuers, metadata.certificateChain);
        }

        metadata.certificateChain = new byte[512 * 1024];
        metadata.certificate = new byte[64 * 1024];
        assertTrue(Utils.isCertificateChainRewriteCandidate(metadata));
        for (byte[] invalidLeaf : new byte[][] {null, new byte[0], new byte[64 * 1024 + 1]}) {
            metadata.certificate = invalidLeaf;
            assertFalse(Utils.isCertificateChainRewriteCandidate(metadata));
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    public void leafOnlyMetadataCanReuseCachedReplacement() throws Exception {
        Field stateField = CertHack.class.getDeclaredField("state");
        stateField.setAccessible(true);
        Object state = stateField.get(null);
        Field cacheField = state.getClass().getDeclaredField("certificateCache");
        cacheField.setAccessible(true);
        Map<Object, Object> cache = (Map<Object, Object>) cacheField.get(state);
        Constructor<?> keyConstructor = Class.forName(CertHack.class.getName() + "$CacheKey")
                .getDeclaredConstructor(byte[].class);
        keyConstructor.setAccessible(true);
        Constructor<?> valueConstructor = Class.forName(CertHack.class.getName() + "$CachedCertificateChain")
                .getDeclaredConstructor(Certificate[].class, byte[].class, byte[].class, boolean.class);
        valueConstructor.setAccessible(true);
        byte[] original = new byte[] {1, 2, 3};
        Object key = keyConstructor.newInstance((Object) original.clone());
        Object value = valueConstructor.newInstance(new Certificate[0], new byte[] {4}, new byte[] {5}, true);
        Object previous = cache.put(key, value);
        try {
            KeyMetadata metadata = new KeyMetadata();
            metadata.certificate = original.clone();
            metadata.certificateChain = new byte[] {6};
            assertTrue(CertHack.applyCachedCertificateChain(metadata));
            assertArrayEquals(new byte[] {4}, metadata.certificate);
            assertArrayEquals(new byte[] {5}, metadata.certificateChain);

            for (byte[] chain : new byte[][] {null, new byte[0]}) {
                metadata.certificate = original.clone();
                metadata.certificateChain = chain;
                assertTrue(CertHack.applyCachedCertificateChain(metadata));
                assertArrayEquals(new byte[] {4}, metadata.certificate);
                assertArrayEquals(new byte[] {5}, metadata.certificateChain);
            }

            metadata.certificate = null;
            assertFalse(CertHack.applyCachedCertificateChain(metadata));
            metadata.certificate = new byte[0];
            assertFalse(CertHack.applyCachedCertificateChain(metadata));
            metadata.certificate = new byte[64 * 1024 + 1];
            assertFalse(CertHack.applyCachedCertificateChain(metadata));
        } finally {
            if (previous == null) cache.remove(key);
            else cache.put(key, previous);
        }
    }

    @Test
    public void computeKeyDescriptorIdentityIsDeterministicAndDifferentiatesDistinctFields() {
        int uid = 10001;
        int domain = 1;
        long nspace = 42L;
        String alias = "my_key";
        byte[] blob = new byte[] {1, 2, 3};

        byte[] base = Utils.computeKeyDescriptorIdentity(uid, domain, nspace, alias, blob);
        assertEquals(32, base.length);

        // Deterministic
        assertArrayEquals(base, Utils.computeKeyDescriptorIdentity(uid, domain, nspace, alias, blob));

        // Different UID
        assertFalse(java.util.Arrays.equals(base, Utils.computeKeyDescriptorIdentity(uid + 1, domain, nspace, alias, blob)));

        // Different domain
        assertFalse(java.util.Arrays.equals(base, Utils.computeKeyDescriptorIdentity(uid, domain + 1, nspace, alias, blob)));

        // Different nspace
        assertFalse(java.util.Arrays.equals(base, Utils.computeKeyDescriptorIdentity(uid, domain, nspace + 1, alias, blob)));

        // Different alias
        assertFalse(java.util.Arrays.equals(base, Utils.computeKeyDescriptorIdentity(uid, domain, nspace, "other_key", blob)));
        assertFalse(java.util.Arrays.equals(base, Utils.computeKeyDescriptorIdentity(uid, domain, nspace, null, blob)));

        // Different blob
        assertFalse(java.util.Arrays.equals(base, Utils.computeKeyDescriptorIdentity(uid, domain, nspace, alias, new byte[] {1, 2, 4})));
        assertFalse(java.util.Arrays.equals(base, Utils.computeKeyDescriptorIdentity(uid, domain, nspace, alias, null)));
    }

    @Test
    public void parseGenerateKeyRequestExtractsIdentityAndRespectsAttestationKeyPresence() {
        Parcel request = mock(Parcel.class);
        java.util.concurrent.atomic.AtomicInteger pos = new java.util.concurrent.atomic.AtomicInteger(28);
        when(request.dataPosition()).thenAnswer(inv -> pos.get());
        org.mockito.Mockito.doAnswer(inv -> {
            pos.set(inv.getArgument(0));
            return null;
        }).when(request).setDataPosition(anyInt());
        when(request.dataAvail()).thenReturn(128);
        when(request.dataSize()).thenReturn(128);

        // 1. Request with default attestation key (presence = 0) and attestKey purpose
        java.util.Iterator<Integer> defaultAttestInts = java.util.Arrays.asList(
                1, 16, 0, // KeyDescriptor (presence, size, domain)
                0,        // attestationKey (presence = 0, null/default)
                1, 1, 20, 536870913, 7, 7 // params (count, presence, size, tag, unionTag, unionVal)
        ).iterator();
        when(request.readInt()).thenAnswer(inv -> defaultAttestInts.hasNext() ? defaultAttestInts.next() : 0);

        Utils.GenerateKeyRequestInfo info = Utils.parseGenerateKeyRequest(request, 10001);
        assertNotNull(info);
        assertTrue(info.usesDefaultAttestationKey);
        assertTrue(info.isAttestKeyPurpose);
        assertNotNull(info.generatedKeyId);
        assertEquals(32, info.generatedKeyId.length);
        assertNull(info.parentKeyId);

        // 2. Request with explicit parent attest key (presence = 1) and non-attest purpose
        pos.set(28);
        java.util.Iterator<Integer> explicitParentInts = java.util.Arrays.asList(
                1, 16, 0, // Generated KeyDescriptor (presence, size, domain)
                1, 16, 0, // Parent KeyDescriptor (presence, size, domain)
                0         // params (count = 0)
        ).iterator();
        when(request.readInt()).thenAnswer(inv -> explicitParentInts.hasNext() ? explicitParentInts.next() : 0);

        Utils.GenerateKeyRequestInfo childInfo = Utils.parseGenerateKeyRequest(request, 10001);
        assertNotNull(childInfo);
        assertFalse(childInfo.usesDefaultAttestationKey);
        assertFalse(childInfo.isAttestKeyPurpose);
        assertNotNull(childInfo.generatedKeyId);
        assertNotNull(childInfo.parentKeyId);
        assertEquals(32, childInfo.parentKeyId.length);
    }

    static Parcel request(boolean explicitIssuer) {
        Parcel request = mock(Parcel.class);
        when(request.dataPosition()).thenReturn(28, 32);
        when(request.dataAvail()).thenReturn(64);
        when(request.readInt()).thenReturn(1, 16, explicitIssuer ? 1 : 0);
        when(request.dataSize()).thenReturn(128);
        return request;
    }
}
