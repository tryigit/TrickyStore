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
final class LazyX509Certificate extends X509Certificate {
    private static final long serialVersionUID = 1L;

    private static final ThreadLocal<CertificateFactory> FACTORY =
            ThreadLocal.withInitial(() -> {
                try {
                    return CertificateFactory.getInstance("X.509");
                } catch (CertificateException error) {
                    throw new IllegalStateException("X.509 certificate factory is unavailable", error);
                }
            });

    private final byte[] der;
    private volatile X509Certificate delegate;

    LazyX509Certificate(byte[] der) {
        this.der = Objects.requireNonNull(der, "der").clone();
    }

    boolean isDelegateInstantiatedForTesting() {
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
        if (other instanceof Certificate) {
            return delegate().equals(other);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(der);
    }
}
