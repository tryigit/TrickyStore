package cleveres.tricky.cleverestech.keystore;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class LazyX509CertificateTest {

    @BeforeClass
    public static void setUp() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static X509Certificate generateTestCert() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        X500Name name = new X500Name("CN=Test Subject, O=CleveresTricky, C=US");
        BigInteger serial = BigInteger.valueOf(123456789L);
        Date notBefore = new Date(System.currentTimeMillis() - 10_000);
        Date notAfter = new Date(System.currentTimeMillis() + 100_000);
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, serial, notBefore, notAfter, name, kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(kp.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    @Test
    public void getEncodedDoesNotInstantiateDelegate() throws Exception {
        X509Certificate original = generateTestCert();
        byte[] encoded = original.getEncoded();

        LazyX509Certificate lazy = new LazyX509Certificate(encoded);
        assertFalse("Delegate must not be instantiated on construction",
                lazy.isDelegateInstantiatedForTesting());

        byte[] lazyEncoded = lazy.getEncoded();
        assertFalse("getEncoded must NOT trigger delegate instantiation",
                lazy.isDelegateInstantiatedForTesting());
        assertArrayEquals("Encoded bytes must match original exactly", encoded, lazyEncoded);
    }

    @Test
    public void fieldAccessInstantiatesDelegateAndMatchesOriginal() throws Exception {
        X509Certificate original = generateTestCert();
        byte[] encoded = original.getEncoded();

        LazyX509Certificate lazy = new LazyX509Certificate(encoded);
        assertFalse(lazy.isDelegateInstantiatedForTesting());

        assertEquals(original.getSubjectDN().getName(), lazy.getSubjectDN().getName());
        assertTrue("Delegate must be instantiated after field access",
                lazy.isDelegateInstantiatedForTesting());

        assertEquals(original.getIssuerDN().getName(), lazy.getIssuerDN().getName());
        assertEquals(original.getSerialNumber(), lazy.getSerialNumber());
        assertEquals(original.getPublicKey(), lazy.getPublicKey());
        assertEquals(original.getSigAlgName(), lazy.getSigAlgName());
        assertNotNull(lazy.getSignature());
        lazy.checkValidity();
    }

    @Test
    public void equalityAndHashCodeMatch() throws Exception {
        X509Certificate original = generateTestCert();
        byte[] encoded = original.getEncoded();

        LazyX509Certificate lazy1 = new LazyX509Certificate(encoded);
        LazyX509Certificate lazy2 = new LazyX509Certificate(encoded);

        assertEquals("Two LazyX509Certificates with same DER must be equal", lazy1, lazy2);
        assertEquals("Hash codes must match for same DER", lazy1.hashCode(), lazy2.hashCode());
        assertFalse("Equality check between lazy certs must not instantiate delegate",
                lazy1.isDelegateInstantiatedForTesting());
        assertFalse(lazy2.isDelegateInstantiatedForTesting());

        assertTrue("Lazy cert must equal genuine cert with same DER", lazy1.equals(original));
    }

    @Test
    public void concurrentAccessIsThreadSafe() throws Exception {
        X509Certificate original = generateTestCert();
        byte[] encoded = original.getEncoded();
        LazyX509Certificate lazy = new LazyX509Certificate(encoded);

        int threads = 8;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        CountDownLatch latch = new CountDownLatch(threads);
        AtomicBoolean errorOccurred = new AtomicBoolean(false);

        for (int i = 0; i < threads; i++) {
            executor.submit(() -> {
                try {
                    for (int j = 0; j < 50; j++) {
                        assertNotNull(lazy.getSubjectDN());
                        assertEquals(original.getSerialNumber(), lazy.getSerialNumber());
                        assertNotNull(lazy.getEncoded());
                    }
                } catch (Throwable t) {
                    errorOccurred.set(true);
                } finally {
                    latch.countDown();
                }
            });
        }

        assertTrue("All threads should complete within timeout",
                latch.await(5, TimeUnit.SECONDS));
        assertFalse("No concurrent access error should occur", errorOccurred.get());
        executor.shutdown();
    }
}
