package cleveres.tricky.cleverestech.keystore;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

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
    }

    @After
    public void tearDown() {
        CertHack.resetAttestFailureRingForTesting();
        CertHack.resetGraphHealthForTesting();
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
        assertEquals("1:5", CertHack.attestFailureSnapshot());
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
        assertEquals("1:29", CertHack.attestFailureSnapshot());
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
    public void ringKeepsLastEightCodesWithMonotonicTotal() throws Exception {
        Certificate leaf = mock(Certificate.class);
        when(leaf.getEncoded()).thenReturn(new byte[] {7, 7, 7});
        byte[] attestKeyId = new byte[32];
        attestKeyId[0] = 1;

        for (int index = 0; index < 10; index++) {
            CertHack.hackAttestKeyCertificateChain(
                    new Certificate[] {leaf}, 10_001, true, attestKeyId, 0);
        }
        assertEquals("10:5,5,5,5,5,5,5,5", CertHack.attestFailureSnapshot());
    }
}
