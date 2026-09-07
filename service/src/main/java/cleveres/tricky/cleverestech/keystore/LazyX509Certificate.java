package cleveres.tricky.cleverestech.keystore;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import javax.security.auth.x500.X500Principal;

/**
 * An X509Certificate wrapper around pre-encoded DER bytes that defers instantiation
 * of the heavyweight platform X.509 certificate object until one of its parsed accessor
 * methods is actually invoked.
 *
 * On the latency-critical generateKey reply path, SecurityLevelInterceptor directly applies
 * pre-encoded replacement bytes to KeyMetadata without ever inspecting the individual fields
 * of the rewritten leaf. Eagerly invoking CertificateFactory.generateCertificate on that
 * path incurs an unnecessary ~15-25 microsecond parsing overhead, which exposes a measurable
 * timing side-channel distinguishing attested from non-attested key generation.
 */
public final class LazyX509Certificate extends X509Certificate {
    private static final long serialVersionUID = 1L;

    private static final ThreadLocal<CertificateFactory> FACTORY =
            ThreadLocal.withInitial(() -> {
                try {
                    return CertificateFactory.getInstance("X.509");
                } catch (CertificateException error) {
                    throw new IllegalStateException("X.509 certificate factory is unavailable", error);
                }
            });

    private static final byte[] ANDROID_ATTESTATION_OID_DER = new byte[] {
            0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, (byte) 0xd6, 0x79, 0x02, 0x01, 0x11
    };

    private final byte[] der;
    private volatile X509Certificate delegate;

    public LazyX509Certificate(byte[] der) {
        this(der, true);
    }

    public LazyX509Certificate(byte[] der, boolean copy) {
        Objects.requireNonNull(der, "der");
        this.der = copy ? der.clone() : der;
    }

    public boolean hasAttestationExtension() {
        try {
            DerReader certReader = new DerReader(der, 0, der.length);
            DerReader certSeq = certReader.readConstructed(0x30); // Certificate SEQUENCE
            if (certSeq == null) return false;

            DerReader tbsSeq = certSeq.readConstructed(0x30); // TBSCertificate SEQUENCE
            if (tbsSeq == null) return false;

            // 1. version [0] EXPLICIT
            if (tbsSeq.peekTag() == 0xa0) {
                if (!tbsSeq.skipTlv()) return false;
            }
            // 2. serialNumber (0x02 INTEGER)
            if (tbsSeq.peekTag() != 0x02 || !tbsSeq.skipTlv()) return false;
            // 3. signature (0x30 SEQUENCE)
            if (tbsSeq.peekTag() != 0x30 || !tbsSeq.skipTlv()) return false;
            // 4. issuer (0x30 SEQUENCE)
            if (tbsSeq.peekTag() != 0x30 || !tbsSeq.skipTlv()) return false;
            // 5. validity (0x30 SEQUENCE)
            if (tbsSeq.peekTag() != 0x30 || !tbsSeq.skipTlv()) return false;
            // 6. subject (0x30 SEQUENCE)
            if (tbsSeq.peekTag() != 0x30 || !tbsSeq.skipTlv()) return false;
            // 7. subjectPublicKeyInfo (0x30 SEQUENCE)
            if (tbsSeq.peekTag() != 0x30 || !tbsSeq.skipTlv()) return false;

            // Optional issuerUniqueID [1]
            if (tbsSeq.peekTag() == 0x81 || tbsSeq.peekTag() == 0xa1) {
                if (!tbsSeq.skipTlv()) return false;
            }
            // Optional subjectUniqueID [2]
            if (tbsSeq.peekTag() == 0x82 || tbsSeq.peekTag() == 0xa2) {
                if (!tbsSeq.skipTlv()) return false;
            }

            // 8. extensions [3] EXPLICIT (tag 0xa3)
            if (tbsSeq.peekTag() != 0xa3) return false;
            DerReader extContainer = tbsSeq.readConstructed(0xa3);
            if (extContainer == null) return false;

            DerReader extsSeq = extContainer.readConstructed(0x30); // Extensions SEQUENCE
            if (extsSeq == null) return false;

            while (extsSeq.hasNext()) {
                DerReader extSeq = extsSeq.readConstructed(0x30); // Extension SEQUENCE
                if (extSeq == null) return false;

                // First item in Extension SEQUENCE is extnID (OBJECT IDENTIFIER 0x06)
                if (extSeq.peekTag() == 0x06 && extSeq.matchesNextBytes(ANDROID_ATTESTATION_OID_DER)) {
                    return true;
                }
            }
            return false;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static final class DerReader {
        private final byte[] data;
        private int pos;
        private final int limit;

        DerReader(byte[] data, int offset, int length) {
            this.data = data;
            this.pos = offset;
            this.limit = offset + length;
        }

        boolean hasNext() {
            return pos < limit;
        }

        int peekTag() {
            if (pos >= limit) return -1;
            return data[pos] & 0xff;
        }

        DerReader readConstructed(int expectedTag) {
            if (pos >= limit) return null;
            int tag = data[pos++] & 0xff;
            if (tag != expectedTag) return null;
            int len = readLength();
            if (len < 0 || pos + len > limit) return null;
            int start = pos;
            pos += len;
            return new DerReader(data, start, len);
        }

        boolean skipTlv() {
            if (pos >= limit) return false;
            pos++;
            int len = readLength();
            if (len < 0 || pos + len > limit) return false;
            pos += len;
            return true;
        }

        private int readLength() {
            if (pos >= limit) return -1;
            int b = data[pos++] & 0xff;
            if ((b & 0x80) == 0) {
                return b;
            }
            int numBytes = b & 0x7f;
            if (numBytes == 0 || numBytes > 4 || pos + numBytes > limit) {
                return -1;
            }
            int len = 0;
            for (int i = 0; i < numBytes; i++) {
                len = (len << 8) | (data[pos++] & 0xff);
            }
            return len;
        }

        boolean matchesNextBytes(byte[] target) {
            if (limit - pos < target.length) return false;
            for (int i = 0; i < target.length; i++) {
                if (data[pos + i] != target[i]) return false;
            }
            return true;
        }
    }

    public boolean isDelegateInstantiatedForTesting() {
        return delegate != null;
    }

    private X509Certificate delegate() {
        X509Certificate d = delegate;
        if (d == null) {
            synchronized (this) {
                d = delegate;
                if (d == null) {
                    try {
                        CertificateFactory factory = FACTORY.get();
                        d = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
                        delegate = d;
                    } catch (CertificateException error) {
                        throw new IllegalStateException("Failed to parse X.509 certificate", error);
                    }
                }
            }
        }
        return d;
    }

    @Override
    public byte[] getEncoded() {
        return der.clone();
    }

    @Override
    public void verify(PublicKey key)
            throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
            NoSuchProviderException, SignatureException {
        delegate().verify(key);
    }

    @Override
    public void verify(PublicKey key, String sigProvider)
            throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
            NoSuchProviderException, SignatureException {
        delegate().verify(key, sigProvider);
    }

    @Override
    public void verify(PublicKey key, Provider sigProvider)
            throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
            SignatureException {
        delegate().verify(key, sigProvider);
    }

    @Override
    public String toString() {
        return delegate().toString();
    }

    @Override
    public PublicKey getPublicKey() {
        return delegate().getPublicKey();
    }

    @Override
    public boolean hasUnsupportedCriticalExtension() {
        return delegate().hasUnsupportedCriticalExtension();
    }

    @Override
    public Set<String> getCriticalExtensionOIDs() {
        return delegate().getCriticalExtensionOIDs();
    }

    @Override
    public Set<String> getNonCriticalExtensionOIDs() {
        return delegate().getNonCriticalExtensionOIDs();
    }

    @Override
    public byte[] getExtensionValue(String oid) {
        return delegate().getExtensionValue(oid);
    }

    @Override
    public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
        delegate().checkValidity();
    }

    @Override
    public void checkValidity(Date date)
            throws CertificateExpiredException, CertificateNotYetValidException {
        delegate().checkValidity(date);
    }

    @Override
    public int getVersion() {
        return delegate().getVersion();
    }

    @Override
    public BigInteger getSerialNumber() {
        return delegate().getSerialNumber();
    }

    @Override
    public Principal getIssuerDN() {
        return delegate().getIssuerDN();
    }

    @Override
    public X500Principal getIssuerX500Principal() {
        return delegate().getIssuerX500Principal();
    }

    @Override
    public Principal getSubjectDN() {
        return delegate().getSubjectDN();
    }

    @Override
    public X500Principal getSubjectX500Principal() {
        return delegate().getSubjectX500Principal();
    }

    @Override
    public Date getNotBefore() {
        return delegate().getNotBefore();
    }

    @Override
    public Date getNotAfter() {
        return delegate().getNotAfter();
    }

    @Override
    public byte[] getTBSCertificate() throws CertificateEncodingException {
        return delegate().getTBSCertificate();
    }

    @Override
    public byte[] getSignature() {
        return delegate().getSignature();
    }

    @Override
    public String getSigAlgName() {
        return delegate().getSigAlgName();
    }

    @Override
    public String getSigAlgOID() {
        return delegate().getSigAlgOID();
    }

    @Override
    public byte[] getSigAlgParams() {
        return delegate().getSigAlgParams();
    }

    @Override
    public boolean[] getIssuerUniqueID() {
        return delegate().getIssuerUniqueID();
    }

    @Override
    public boolean[] getSubjectUniqueID() {
        return delegate().getSubjectUniqueID();
    }

    @Override
    public boolean[] getKeyUsage() {
        return delegate().getKeyUsage();
    }

    @Override
    public List<String> getExtendedKeyUsage() throws CertificateParsingException {
        return delegate().getExtendedKeyUsage();
    }

    @Override
    public int getBasicConstraints() {
        return delegate().getBasicConstraints();
    }

    @Override
    public Collection<List<?>> getSubjectAlternativeNames() throws CertificateParsingException {
        return delegate().getSubjectAlternativeNames();
    }

    @Override
    public Collection<List<?>> getIssuerAlternativeNames() throws CertificateParsingException {
        return delegate().getIssuerAlternativeNames();
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (other instanceof LazyX509Certificate lazy) {
            return Arrays.equals(this.der, lazy.der);
        }
        if (other instanceof Certificate cert) {
            try {
                return Arrays.equals(this.der, cert.getEncoded());
            } catch (CertificateEncodingException ignored) {
                return false;
            }
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(der);
    }
}
