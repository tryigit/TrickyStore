package cleveres.tricky.cleverestech.keystore;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * The attest failure ring records exactly which fail-closed branch served a
 * genuine chain. Entries are written on cold failure paths only and carry no
 * identities or key material, so the snapshot is safe for support
 * diagnostics.
 */
public class AttestFailureRingTest {
    @Before
    public void setUp() {
        CertHack.resetAttestFailureRingForTesting();
        CertHack.resetGraphHealthForTesting();
        CertHack.setKeyboxes(java.util.Collections.emptyList());
    }

    @After
    public void tearDown() {
        CertHack.resetAttestFailureRingForTesting();
        CertHack.resetGraphHealthForTesting();
        CertHack.setKeyboxes(java.util.Collections.emptyList());
    }

    @Test
    public void emptyRingSnapshotsZero() {
        assertEquals("0:", CertHack.attestFailureSnapshot());
    }

    @Test
    public void extensionlessAttestKeyWithoutPlatformRecordsCodeFive() throws Exception {
        Certificate leaf = mock(Certificate.class);
        when(leaf.getEncoded()).thenReturn(new byte[] {7, 7, 7});
        byte[] attestKeyId = new byte[32];
        attestKeyId[0] = 1;

        Certificate[] input = new Certificate[] {leaf};
        Certificate[] result =
                CertHack.hackAttestKeyCertificateChain(input, 10_001, true, attestKeyId, 0);

        assertSame(input, result);
        assertEquals("1:10001:5", CertHack.attestFailureSnapshot());
    }

    @Test
    public void extensionlessNonAttestChildRecordsCodeTwentyNine() throws Exception {
        Certificate leaf = mock(Certificate.class);
        when(leaf.getEncoded()).thenReturn(new byte[] {9, 9, 9});
        byte[] parentKeyId = new byte[32];
        parentKeyId[0] = 2;

        Certificate[] input = new Certificate[] {leaf};
        Certificate[] result =
                CertHack.hackChildKeyCertificate(
                        input, 10_001, false, true, parentKeyId, null, 0);

        assertSame(input, result);
        assertEquals("1:10001:29", CertHack.attestFailureSnapshot());
    }

    @Test
    public void backendPreconditionsMirrorWireRejects() {
        byte[] validId = new byte[32];
        validId[0] = 1;
        Map<Integer, byte[]> emptyOverrides = Collections.emptyMap();

        assertFalse(
                CertHack.failsBackendWirePreconditions(null, null, false, emptyOverrides, null));
        assertFalse(
                CertHack.failsBackendWirePreconditions(
                        validId, null, false, emptyOverrides, new byte[] {1}));
        assertTrue(
                CertHack.failsBackendWirePreconditions(
                        new byte[32], null, false, emptyOverrides, null));
        assertTrue(
                CertHack.failsBackendWirePreconditions(
                        new byte[31], null, false, emptyOverrides, null));
        assertTrue(
                CertHack.failsBackendWirePreconditions(
                        validId, new byte[32], true, emptyOverrides, null));
        assertFalse(
                CertHack.failsBackendWirePreconditions(
                        validId, null, false, emptyOverrides, null));

        Map<Integer, byte[]> emptyOverride = new HashMap<>();
        emptyOverride.put(714, new byte[0]);
        assertTrue(
                CertHack.failsBackendWirePreconditions(validId, null, false, emptyOverride, null));

        Map<Integer, byte[]> oversizeOverride = new HashMap<>();
        oversizeOverride.put(714, new byte[4 * 1024 + 1]);
        assertTrue(
                CertHack.failsBackendWirePreconditions(
                        validId, null, false, oversizeOverride, null));

        assertTrue(
                CertHack.failsBackendWirePreconditions(
                        validId, null, false, emptyOverrides, new byte[0]));
        assertTrue(
                CertHack.failsBackendWirePreconditions(
                        validId, null, false, emptyOverrides, new byte[1025]));
    }

    @Test
    public void backendPreconditionsRejectSelfParentingAttestKeys() {
        byte[] keyId = new byte[32];
        keyId[0] = 1;
        Map<Integer, byte[]> emptyOverrides = Collections.emptyMap();

        assertTrue(
                CertHack.failsBackendWirePreconditions(
                        keyId, keyId.clone(), true, emptyOverrides, null));
        assertFalse(
                CertHack.failsBackendWirePreconditions(
                        keyId, keyId.clone(), false, emptyOverrides, null));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void staleManagedEntryWithFailedClearRecordsCodeForty() throws Exception {
        Field stateField = CertHack.class.getDeclaredField("state");
        stateField.setAccessible(true);
        Object state = stateField.get(null);
        Field cacheField = state.getClass().getDeclaredField("certificateCache");
        cacheField.setAccessible(true);
        Map<Object, Object> cache = (Map<Object, Object>) cacheField.get(state);

        Constructor<?> keyConstructor =
                Class.forName(CertHack.class.getName() + "$CacheKey")
                        .getDeclaredConstructor(byte[].class);
        keyConstructor.setAccessible(true);
        Constructor<?> valueConstructor =
                Class.forName(CertHack.class.getName() + "$CachedCertificateChain")
                        .getDeclaredConstructor(
                                Certificate[].class,
                                byte[].class,
                                byte[].class,
                                boolean.class,
                                boolean.class,
                                int.class,
                                byte[].class,
                                byte[].class);
        valueConstructor.setAccessible(true);

        int uid = 10_001;
        byte[] attestKeyId = new byte[32];
        attestKeyId[0] = 9;
        Certificate mockCert = mock(Certificate.class);
        Certificate[] mockChain = new Certificate[] {mockCert};
        Object key = keyConstructor.newInstance((Object) new byte[] {5, 5, 5});
        Object value =
                valueConstructor.newInstance(
                        mockChain, new byte[] {5}, new byte[] {6}, true, true, uid, attestKeyId,
                        null);

        cleveres.tricky.cleverestech.CertificateBackend.setTouchAttestKeyOverrideForTesting(
                (u, id) ->
                        cleveres.tricky.cleverestech.CertificateBackend.AttestKeyTouchResult.ABSENT);
        cleveres.tricky.cleverestech.CertificateBackend.setClearAttestKeyStoreOverrideForTesting(
                () -> false);
        cleveres.tricky.cleverestech.CertificateBackend.setRemoveAttestKeyOverrideForTesting(
                (u, id) ->
                        cleveres.tricky.cleverestech.CertificateBackend.AttestKeyRemoveResult
                                .REMOVED);
        try {
            synchronized (cache) {
                cache.put(key, value);
            }

            Certificate leaf = mock(Certificate.class);
            when(leaf.getEncoded()).thenReturn(new byte[] {5, 5, 5});
            Certificate[] input = new Certificate[] {leaf};
            Certificate[] result =
                    CertHack.hackAttestKeyCertificateChain(input, uid, true, attestKeyId, 1);

            assertSame(input, result);
            assertEquals("1:10001:40", CertHack.attestFailureSnapshot());
        } finally {
            cleveres.tricky.cleverestech.CertificateBackend.resetForTesting();
            synchronized (cache) {
                cache.clear();
            }
        }
    }

    @Test
    public void generateKeyPreSkipWithoutKeyboxesRecordsCodeFortyOne() throws Exception {
        android.os.Binder target = new android.os.Binder();
        Field codeField =
                cleveres.tricky.cleverestech.SecurityLevelInterceptor.class.getDeclaredField(
                        "generateKeyTransaction");
        codeField.setAccessible(true);
        int code = codeField.getInt(null);
        android.os.Parcel request = mock(android.os.Parcel.class);

        cleveres.tricky.cleverestech.binder.BinderInterceptor.Result result =
                new cleveres.tricky.cleverestech.SecurityLevelInterceptor()
                        .onPreTransact(target, code, 0, 10_001, 42, request);

        assertSame(cleveres.tricky.cleverestech.binder.BinderInterceptor.Skip.INSTANCE, result);
        assertEquals("1:10001:41", CertHack.attestFailureSnapshot());
    }

    @Test
    public void getKeyEntryPreSkipWithoutKeyboxesRecordsCodeFortyTwo() throws Exception {
        android.os.Binder target = new android.os.Binder();
        Field keystoreField =
                cleveres.tricky.cleverestech.KeystoreInterceptor.class.getDeclaredField("keystore");
        keystoreField.setAccessible(true);
        Object previous;
        try {
            previous = keystoreField.get(null);
        } catch (Exception unavailable) {
            previous = null;
        }
        Field codeField =
                cleveres.tricky.cleverestech.KeystoreInterceptor.class.getDeclaredField(
                        "getKeyEntryTransaction");
        codeField.setAccessible(true);
        int code = codeField.getInt(null);
        android.os.Parcel request = mock(android.os.Parcel.class);
        try {
            keystoreField.set(null, target);
            cleveres.tricky.cleverestech.binder.BinderInterceptor.Result result =
                    cleveres.tricky.cleverestech.KeystoreInterceptor.INSTANCE.onPreTransact(
                            target, code, 0, 10_001, 42, request);

            assertSame(
                    cleveres.tricky.cleverestech.binder.BinderInterceptor.Skip.INSTANCE, result);
            assertEquals("1:10001:42", CertHack.attestFailureSnapshot());
        } finally {
            if (previous != null) {
                keystoreField.set(null, previous);
            }
        }
    }

    @Test
    public void ringKeepsLastEightCodesWithMonotonicTotal() throws Exception {
        Certificate leaf = mock(Certificate.class);
        when(leaf.getEncoded()).thenReturn(new byte[] {7, 7, 7});
        byte[] attestKeyId = new byte[32];
        attestKeyId[0] = 1;

        for (int index = 0; index < 10; index++) {
            CertHack.hackAttestKeyCertificateChain(
                    new Certificate[] {leaf}, 10_001, true, attestKeyId, 0);
        }
        assertEquals(
                "10:10001:5,10001:5,10001:5,10001:5,10001:5",
                CertHack.attestFailureSnapshot());
    }
}
