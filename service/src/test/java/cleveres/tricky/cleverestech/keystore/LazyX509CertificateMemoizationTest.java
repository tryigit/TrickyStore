package cleveres.tricky.cleverestech.keystore;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.lang.reflect.Field;
import org.junit.Test;

public final class LazyX509CertificateMemoizationTest {
    @Test
    public void attestationExtensionAbsenceIsMemoizedWithoutInstantiatingDelegate() throws Exception {
        LazyX509Certificate certificate =
                new LazyX509Certificate(new byte[] {0x30, 0x00}, false);
        Field state = LazyX509Certificate.class.getDeclaredField("attestationExtensionState");
        state.setAccessible(true);

        assertEquals(0, state.getByte(certificate));
        assertFalse(certificate.hasAttestationExtension());
        assertEquals(1, state.getByte(certificate));
        assertFalse(certificate.isDelegateInstantiatedForTesting());

        assertFalse(certificate.hasAttestationExtension());
        assertEquals(1, state.getByte(certificate));
        assertFalse(certificate.isDelegateInstantiatedForTesting());
    }
}
