package cleveres.tricky.cleverestech.keystore;

import android.os.Parcel;
import android.system.keystore2.IKeystoreSecurityLevel;
import android.system.keystore2.KeyEntryResponse;
import android.system.keystore2.KeyMetadata;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import cleveres.tricky.cleverestech.util.FastByteArrayOutputStream;

public final class Utils {
    private static final String TAG = "Utils";
    private static final String ANDROID_ATTESTATION_EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17";
    private static final int MAX_CERTIFICATE_BYTES = 64 * 1024;
    private static final int MAX_CHAIN_BYTES = 512 * 1024;
    private static final int MAX_CERTIFICATES = 16;
    private static final int MAX_AUTHORIZATIONS = 256;
    private static final int MAX_REWRITTEN_PARCEL_BYTES = 8 * 1024 * 1024;
    private static final int MAX_RETAINED_SCRATCH_PARCEL_BYTES = 64 * 1024;
    private static final int TAG_PURPOSE = 0x20000001;
    private static final int KEY_PARAMETER_VALUE_KEY_PURPOSE = 7;
    private static final int KEY_PURPOSE_ATTEST_KEY = 7;

    private static final ThreadLocal<CertificateFactory> CERTIFICATE_FACTORY =
            new ThreadLocal<CertificateFactory>() {
                @Override
                protected CertificateFactory initialValue() {
                    try {
                        return CertificateFactory.getInstance("X.509");
                    } catch (CertificateException error) {
                        Log.e(TAG, "X.509 certificate factory is unavailable");
                        return null;
                    }
                }
            };

    public static final class GenerateKeyRequestInfo {
        public final boolean usesDefaultAttestationKey;
        public final boolean isAttestKeyPurpose;
        public final byte[] generatedKeyId;
        public final byte[] parentKeyId;

        public GenerateKeyRequestInfo(
                boolean usesDefaultAttestationKey,
                boolean isAttestKeyPurpose,
                byte[] generatedKeyId,
                byte[] parentKeyId) {
            this.usesDefaultAttestationKey = usesDefaultAttestationKey;
            this.isAttestKeyPurpose = isAttestKeyPurpose;
            this.generatedKeyId = generatedKeyId;
            this.parentKeyId = parentKeyId;
        }
    }

    private Utils() {
    }

    public static byte[] computeKeyDescriptorIdentity(
            int callingUid, int domain, long nspace, String alias, byte[] blob) {
        try {
            // For Domain.APP (0), Android Keystore2 binds key identity strictly to callingUid
            // and key alias; client-provided namespace (-1 for KeyProperties.NAMESPACE_APPLICATION,
            // 0 for default uninitialized parcelables, or callingUid) is ignored by Keystore2 daemon.
            // Canonicalize namespace to 0L for Domain.APP so generated parent keys and child
            // parent references produce identical identifiers.
            long effectiveNspace = (domain == 0) ? 0L : nspace;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            ByteBuffer buffer = ByteBuffer.allocate(4 + 4 + 8).order(ByteOrder.BIG_ENDIAN);
            buffer.putInt(callingUid);
            buffer.putInt(domain);
            buffer.putLong(effectiveNspace);
            digest.update(buffer.array());

            if (alias == null) {
                digest.update(new byte[] {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF});
            } else {
                byte[] aliasBytes = alias.getBytes(StandardCharsets.UTF_8);
                ByteBuffer lenBuf = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
                lenBuf.putInt(aliasBytes.length);
                digest.update(lenBuf.array());
                digest.update(aliasBytes);
            }

            if (blob == null) {
                digest.update(new byte[] {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF});
            } else {
                ByteBuffer lenBuf = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
                lenBuf.putInt(blob.length);
                digest.update(lenBuf.array());
                digest.update(blob);
            }

            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError("SHA-256 must be available", e);
        }
    }

    public static byte[] extractKeyDescriptorIdentity(Parcel parcel, int callingUid) {
        if (parcel == null || parcel.dataAvail() < Integer.BYTES) {
            return null;
        }
        int presence = parcel.readInt();
        if (presence != 1) {
            return null;
        }
        return extractKeyDescriptorBodyIdentity(parcel, callingUid);
    }

    public static byte[] extractKeyDescriptorBodyIdentity(Parcel parcel, int callingUid) {
        if (parcel == null) return null;
        int parcelableEnd = readStableParcelableEnd(parcel, parcel.dataSize());
        if (parcelableEnd < 0) {
            return null;
        }
        try {
            int domain = 0;
            long nspace = 0L;
            String alias = null;
            byte[] blob = null;

            if (parcel.dataPosition() < parcelableEnd && hasBytes(parcel, parcelableEnd, Integer.BYTES)) {
                domain = parcel.readInt();
            }
            if (parcel.dataPosition() < parcelableEnd && hasBytes(parcel, parcelableEnd, Long.BYTES)) {
                nspace = parcel.readLong();
            }
            if (parcel.dataPosition() < parcelableEnd) {
                alias = parcel.readString();
                if (parcel.dataPosition() > parcelableEnd) {
                    return null;
                }
            }
            if (parcel.dataPosition() < parcelableEnd) {
                blob = parcel.createByteArray();
                if (parcel.dataPosition() > parcelableEnd) {
                    return null;
                }
            }

            return computeKeyDescriptorIdentity(callingUid, domain, nspace, alias, blob);
        } catch (RuntimeException e) {
            return null;
        } finally {
            parcel.setDataPosition(parcelableEnd);
        }
    }

    public static GenerateKeyRequestInfo parseGenerateKeyRequest(Parcel request, int callingUid) {
        if (request == null) return null;
        int position = request.dataPosition();
        try {
            request.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR);
            byte[] generatedKeyId = extractKeyDescriptorIdentity(request, callingUid);
            if (generatedKeyId == null) return null;

            if (request.dataAvail() < Integer.BYTES) return null;
            int attestationKeyPresence = request.readInt();
            boolean usesDefault = attestationKeyPresence == 0;
            byte[] parentKeyId = null;
            if (attestationKeyPresence == 1) {
                parentKeyId = extractKeyDescriptorBodyIdentity(request, callingUid);
                if (parentKeyId == null) return null;
            } else if (attestationKeyPresence != 0) {
                return null;
            }

            boolean isAttestKey = inspectParamsForAttestKeyPurpose(request);
            return new GenerateKeyRequestInfo(usesDefault, isAttestKey, generatedKeyId, parentKeyId);
        } catch (RuntimeException invalidRequest) {
            return null;
        } finally {
            request.setDataPosition(position);
        }
    }

    /** Reads the generateKey AIDL prefix without changing the caller's parcel position. */
    public static boolean usesDefaultAttestationKey(Parcel request) {
        if (request == null) return false;
        int position = request.dataPosition();
        try {
            request.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR);
            if (!skipStableTypedParcelable(request) || request.dataAvail() < Integer.BYTES) {
                return false;
            }
            // Parcel.writeTypedObject writes zero for null and a nonzero presence marker otherwise.
            // We only need to distinguish the optional attestationKey, so do not instantiate its
            // hidden platform class or depend on a generated CREATOR field that may change by API.
            return request.readInt() == 0;
        } catch (RuntimeException invalidRequest) {
            return false;
        } finally {
            request.setDataPosition(position);
        }
    }

    /**
     * Inspects the generateKey KeyParameter array to determine if Tag.PURPOSE includes KeyPurpose.ATTEST_KEY.
     */
    public static boolean hasAttestKeyPurpose(Parcel request) {
        if (request == null) return false;
        int position = request.dataPosition();
        try {
            request.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR);
            if (!skipStableTypedParcelable(request)) return false;
            if (request.dataAvail() < Integer.BYTES) return false;
            int attestationKeyPresence = request.readInt();
            if (attestationKeyPresence == 1) {
                if (!skipStableParcelableBody(request)) return false;
            } else if (attestationKeyPresence != 0) {
                return false;
            }
            return inspectParamsForAttestKeyPurpose(request);
        } catch (RuntimeException invalidRequest) {
            return false;
        } finally {
            request.setDataPosition(position);
        }
    }

    private static boolean inspectParamsForAttestKeyPurpose(Parcel request) {
        if (request.dataAvail() < Integer.BYTES) return false;
        int paramCount = request.readInt();
        if (paramCount <= 0 || paramCount > MAX_AUTHORIZATIONS) return false;
        for (int i = 0; i < paramCount; i++) {
            if (request.dataAvail() < Integer.BYTES) return false;
            int paramPresence = request.readInt();
            if (paramPresence == 0) continue;
            if (paramPresence != 1) return false;

            int parcelableStart = request.dataPosition();
            int parcelableEnd = readStableParcelableEnd(request, request.dataSize());
            if (parcelableEnd < 0) return false;

            if (hasBytes(request, parcelableEnd, 3 * Integer.BYTES)) {
                int tag = request.readInt();
                int unionTag = request.readInt();
                int unionValue = request.readInt();
                if (tag == TAG_PURPOSE &&
                        unionTag == KEY_PARAMETER_VALUE_KEY_PURPOSE &&
                        unionValue == KEY_PURPOSE_ATTEST_KEY) {
                    return true;
                }
            }
            request.setDataPosition(parcelableEnd);
        }
        return false;
    }

    /**
     * Skips one non-null stable-AIDL typed parcelable without allocating or binding to its Java ABI.
     * Stable parcelables are size-prefixed; reject missing, undersized, overflowing, or truncated
     * values instead of allowing an ambiguous prefix to select the default attestation key.
     */
    private static boolean skipStableTypedParcelable(Parcel request) {
        if (request.dataAvail() < Integer.BYTES || request.readInt() != 1) {
            return false;
        }
        return skipStableParcelableBody(request);
    }

    private static boolean skipStableParcelableBody(Parcel request) {
        return skipStableParcelableBody(request, request.dataSize());
    }

    private static boolean skipStableParcelableBody(Parcel request, int enclosingEnd) {
        int parcelableEnd = readStableParcelableEnd(request, enclosingEnd);
        if (parcelableEnd < 0) return false;
        request.setDataPosition(parcelableEnd);
        return true;
    }

    private static int readStableParcelableEnd(Parcel parcel, int enclosingEnd) {
        if (!hasBytes(parcel, enclosingEnd, Integer.BYTES)) return -1;
        int parcelableStart = parcel.dataPosition();
        int parcelableSize = parcel.readInt();
        if (parcelableSize < Integer.BYTES ||
                parcelableStart > Integer.MAX_VALUE - parcelableSize) {
            return -1;
        }
        int parcelableEnd = parcelableStart + parcelableSize;
        return parcelableEnd <= enclosingEnd && parcelableEnd <= parcel.dataSize()
                ? parcelableEnd
                : -1;
    }

    private static boolean hasBytes(Parcel parcel, int end, int byteCount) {
        int position = parcel.dataPosition();
        return byteCount >= 0 && position >= 0 && position <= end && byteCount <= end - position;
    }

    private static int paddedByteCount(int byteCount) {
        if (byteCount < 0 || byteCount > Integer.MAX_VALUE - 3) return -1;
        return (byteCount + 3) & ~3;
    }

    /**
     * KeyCreationResult's caller-provided ATTEST_KEY case returns only the signed leaf; its
     * issuer chain belongs to the caller. Non-attested keys also have no issuer chain.
     * Neither case permits substituting a generic keybox issuer, including after cache eviction
     * or restart. Check the raw metadata before cache lookup, X.509 parsing or backend IPC.
     */
    public static boolean isCertificateChainRewriteCandidate(KeyMetadata metadata) {
        return metadata != null &&
                isCertificateChainRewriteCandidate(metadata.certificate, metadata.certificateChain);
    }

    /** Raw-byte form keeps platform-contract tests independent of hidden KeyMetadata constructors. */
    public static boolean isCertificateChainRewriteCandidate(
            byte[] certificate, byte[] certificateChain) {
        return certificate != null && certificate.length > 0 &&
                certificate.length <= MAX_CERTIFICATE_BYTES &&
                certificateChain != null && certificateChain.length > 0 &&
                certificateChain.length <= MAX_CHAIN_BYTES;
    }

    public static boolean hasRewritableLeafCertificate(KeyMetadata metadata) {
        return metadata != null &&
                hasRewritableLeafCertificate(metadata.certificate, metadata.certificateChain);
    }

    public static boolean hasRewritableLeafCertificate(
            byte[] certificate, byte[] certificateChain) {
        return certificate != null && certificate.length > 0 &&
                certificate.length <= MAX_CERTIFICATE_BYTES &&
                (certificateChain == null || certificateChain.length == 0);
    }


    static X509Certificate toCertificate(byte[] encoded) {
        if (encoded == null || encoded.length == 0 ||
                encoded.length > MAX_CERTIFICATE_BYTES) {
            return null;
        }
        try {
            CertificateFactory factory = CERTIFICATE_FACTORY.get();
            if (factory == null) return null;
            return (X509Certificate) factory.generateCertificate(
                    new ByteArrayInputStream(encoded));
        } catch (CertificateException | ClassCastException error) {
            return null;
        }
    }

    public static final class ParcelParseResult {
        public final byte[] leafEncoded;
        public final int keySecurityLevel;
        public final int chainLength;
        public final int certOffset;
        public final int chainOffset;
        public final int afterChainOffset;
        public final int metadataStart;
        public final int metadataSize;
        public final int outerParcelableStart;
        public final int outerParcelableSize;
        public final int sourceDataSize;
        public final int oldCertPaddedLen;
        public final int oldChainPaddedLen;

        private ParcelParseResult(
                byte[] leafEncoded,
                int keySecurityLevel,
                int chainLength,
                int certOffset,
                int chainOffset,
                int afterChainOffset,
                int metadataStart,
                int metadataSize,
                int outerParcelableStart,
                int outerParcelableSize,
                int sourceDataSize,
                int oldCertPaddedLen,
                int oldChainPaddedLen
        ) {
            this.leafEncoded = leafEncoded;
            this.keySecurityLevel = keySecurityLevel;
            this.chainLength = chainLength;
            this.certOffset = certOffset;
            this.chainOffset = chainOffset;
            this.afterChainOffset = afterChainOffset;
            this.metadataStart = metadataStart;
            this.metadataSize = metadataSize;
            this.outerParcelableStart = outerParcelableStart;
            this.outerParcelableSize = outerParcelableSize;
            this.sourceDataSize = sourceDataSize;
            this.oldCertPaddedLen = oldCertPaddedLen;
            this.oldChainPaddedLen = oldChainPaddedLen;
        }

        public boolean hasFullCertificateChain() {
            return chainLength > 0;
        }

        public boolean hasLeafOnlyCertificate() {
            return chainLength == -1 || chainLength == 0;
        }
    }

    public static ParcelParseResult parseKeyMetadataParcel(Parcel reply) {
        if (reply == null) return null;
        int posBefore = reply.dataPosition();
        try {
            return parseKeyMetadataParcel(reply, reply.dataSize(), -1, 0);
        } catch (RuntimeException e) {
            return null;
        } finally {
            reply.setDataPosition(posBefore);
        }
    }

    /** Parses KeyEntryResponse's stable-AIDL envelope without constructing its object graph. */
    public static ParcelParseResult parseKeyEntryResponseParcel(Parcel reply) {
        if (reply == null) return null;
        int posBefore = reply.dataPosition();
        try {
            if (!hasBytes(reply, reply.dataSize(), Integer.BYTES) || reply.readInt() != 1) {
                return null;
            }
            int responseStart = reply.dataPosition();
            int responseEnd = readStableParcelableEnd(reply, reply.dataSize());
            if (responseEnd < 0) return null;

            if (!hasBytes(reply, responseEnd, Integer.BYTES)) return null;
            reply.readStrongBinder();
            if (reply.dataPosition() > responseEnd) return null;

            return parseKeyMetadataParcel(
                    reply,
                    responseEnd,
                    responseStart,
                    responseEnd - responseStart
            );
        } catch (RuntimeException e) {
            return null;
        } finally {
            reply.setDataPosition(posBefore);
        }
    }

    private static ParcelParseResult parseKeyMetadataParcel(
            Parcel reply,
            int enclosingEnd,
            int outerParcelableStart,
            int outerParcelableSize
    ) {
        if (!hasBytes(reply, enclosingEnd, Integer.BYTES) || reply.readInt() != 1) {
            return null;
        }
        int metadataStart = reply.dataPosition();
        int metadataEnd = readStableParcelableEnd(reply, enclosingEnd);
        if (metadataEnd < 0) return null;

        if (!hasBytes(reply, metadataEnd, Integer.BYTES)) return null;
        int keyPresence = reply.readInt();
        if (keyPresence == 1) {
            if (!skipStableParcelableBody(reply, metadataEnd)) return null;
        } else if (keyPresence != 0) {
            return null;
        }

        if (!hasBytes(reply, metadataEnd, Integer.BYTES)) return null;
        int keySecurityLevel = reply.readInt();

        if (!hasBytes(reply, metadataEnd, Integer.BYTES)) return null;
        int authorizationCount = reply.readInt();
        if (authorizationCount < -1 || authorizationCount > MAX_AUTHORIZATIONS) return null;
        for (int index = 0; index < authorizationCount; index++) {
            if (!hasBytes(reply, metadataEnd, Integer.BYTES)) return null;
            int authorizationPresence = reply.readInt();
            if (authorizationPresence == 1) {
                if (!skipStableParcelableBody(reply, metadataEnd)) return null;
            } else if (authorizationPresence != 0) {
                return null;
            }
        }

        if (!hasBytes(reply, metadataEnd, Integer.BYTES)) return null;
        int certOffset = reply.dataPosition();
        int leafLength = reply.readInt();
        int leafPaddedLength = paddedByteCount(leafLength);
        if (leafLength <= 0 || leafLength > MAX_CERTIFICATE_BYTES ||
                leafPaddedLength < 0 || !hasBytes(reply, metadataEnd, leafPaddedLength)) {
            return null;
        }
        int afterLeafOffset = reply.dataPosition() + leafPaddedLength;
        reply.setDataPosition(certOffset);
        byte[] leafEncoded = reply.createByteArray();
        if (leafEncoded == null || leafEncoded.length != leafLength ||
                reply.dataPosition() != afterLeafOffset) {
            return null;
        }

        if (!hasBytes(reply, metadataEnd, Integer.BYTES)) return null;
        int chainOffset = reply.dataPosition();
        int chainLength = reply.readInt();
        if (chainLength < -1 || chainLength > MAX_CHAIN_BYTES) return null;
        int chainPaddedLength = chainLength < 0 ? 0 : paddedByteCount(chainLength);
        if (chainPaddedLength < 0 || !hasBytes(reply, metadataEnd, chainPaddedLength)) {
            return null;
        }
        int afterChainOffset = reply.dataPosition() + chainPaddedLength;
        reply.setDataPosition(afterChainOffset);

        return new ParcelParseResult(
                leafEncoded,
                keySecurityLevel,
                chainLength,
                certOffset,
                chainOffset,
                afterChainOffset,
                metadataStart,
                metadataEnd - metadataStart,
                outerParcelableStart,
                outerParcelableSize,
                reply.dataSize(),
                afterLeafOffset - certOffset,
                afterChainOffset - chainOffset
        );
    }

    private static final ThreadLocal<Parcel> SCRATCH_PARCEL = ThreadLocal.withInitial(Parcel::obtain);

    public static boolean rewriteKeyMetadataParcel(
            Parcel reply,
            ParcelParseResult parsed,
            byte[] newLeaf,
            byte[] newChain
    ) {
        if (reply == null || parsed == null || newLeaf == null ||
                newLeaf.length == 0 || newLeaf.length > MAX_CERTIFICATE_BYTES ||
                (newChain != null && newChain.length > MAX_CHAIN_BYTES) ||
                reply.dataSize() != parsed.sourceDataSize ||
                parsed.metadataStart < 0 || parsed.certOffset < parsed.metadataStart ||
                parsed.chainOffset < parsed.certOffset ||
                parsed.afterChainOffset < parsed.chainOffset ||
                parsed.afterChainOffset > parsed.sourceDataSize) {
            return false;
        }

        int newCertPaddedLen = Integer.BYTES + paddedByteCount(newLeaf.length);
        int newChainPaddedLen = Integer.BYTES + (newChain == null ? 0 : paddedByteCount(newChain.length));
        long sizeDiff = (long) newCertPaddedLen + newChainPaddedLen -
                parsed.oldCertPaddedLen - parsed.oldChainPaddedLen;
        long newMetadataSize = (long) parsed.metadataSize + sizeDiff;
        long newOuterParcelableSize = (long) parsed.outerParcelableSize + sizeDiff;
        long newReplySize = (long) parsed.sourceDataSize + sizeDiff;
        if (newMetadataSize < Integer.BYTES || newMetadataSize > Integer.MAX_VALUE ||
                (parsed.outerParcelableStart >= 0 &&
                        (newOuterParcelableSize < Integer.BYTES ||
                                newOuterParcelableSize > Integer.MAX_VALUE)) ||
                newReplySize < 0 || newReplySize > MAX_REWRITTEN_PARCEL_BYTES) {
            return false;
        }

        Parcel scratch = SCRATCH_PARCEL.get();
        scratch.setDataSize(0);
        scratch.setDataPosition(0);
        try {
            scratch.appendFrom(reply, 0, parsed.certOffset);
            scratch.writeByteArray(newLeaf);
            scratch.writeByteArray(newChain);

            int remaining = reply.dataSize() - parsed.afterChainOffset;
            if (remaining > 0) {
                scratch.appendFrom(reply, parsed.afterChainOffset, remaining);
            }
            if (scratch.dataSize() != (int) newReplySize) return false;

            scratch.setDataPosition(parsed.metadataStart);
            scratch.writeInt((int) newMetadataSize);
            if (parsed.outerParcelableStart >= 0) {
                scratch.setDataPosition(parsed.outerParcelableStart);
                scratch.writeInt((int) newOuterParcelableSize);
            }

            reply.setDataSize(0);
            reply.setDataPosition(0);
            reply.appendFrom(scratch, 0, scratch.dataSize());
            reply.setDataPosition(0);
            return true;
        } finally {
            scratch.setDataSize(0);
            scratch.setDataPosition(0);
            // Native Parcel capacity only grows; setDataSize(0) releases Binder objects but does
            // not shrink an owned data buffer. Do not pin an exceptional reply on every thread.
            if (scratch.dataCapacity() > MAX_RETAINED_SCRATCH_PARCEL_BYTES) {
                scratch.recycle();
                SCRATCH_PARCEL.remove();
            }
        }
    }

    /**
     * Returns whether the already-parsed leaf carries Android's attestation extension.
     *
     * This check intentionally stays in-process. A normal AndroidKeyStore asymmetric key also
     * carries a self-signed X.509 certificate, but forwarding that certificate to the Rust
     * attestation parser creates a measurable UDS/parser cost on the non-attested generateKey path.
     * The platform X509Certificate implementation has already parsed the certificate, so checking
     * the fixed extension OID is bounded and avoids any backend IPC for that common negative case.
     */
    public static boolean hasAndroidAttestationExtension(Certificate certificate) {
        if (certificate instanceof LazyX509Certificate lazy) {
            return lazy.hasAttestationExtension();
        }
        if (!(certificate instanceof X509Certificate x509Certificate)) return false;
        try {
            return x509Certificate.getExtensionValue(ANDROID_ATTESTATION_EXTENSION_OID) != null;
        } catch (RuntimeException error) {
            return false;
        }
    }


    private static List<X509Certificate> toCertificates(byte[] encoded) {
        if (encoded == null || encoded.length == 0 ||
                encoded.length > MAX_CHAIN_BYTES) {
            return List.of();
        }
        try {
            CertificateFactory factory = CERTIFICATE_FACTORY.get();
            if (factory == null) return List.of();
            Collection<? extends Certificate> parsed = factory.generateCertificates(
                    new ByteArrayInputStream(encoded));
            if (parsed.size() > MAX_CERTIFICATES) return List.of();

            List<X509Certificate> certificates = new ArrayList<>(parsed.size());
            for (Certificate certificate : parsed) {
                if (!(certificate instanceof X509Certificate x509Certificate)) {
                    return List.of();
                }
                certificates.add(x509Certificate);
            }
            return certificates;
        } catch (CertificateException error) {
            return List.of();
        }
    }

    /**
     * Parses only the leaf certificate from KeyMetadata. The attestation rewrite path replaces
     * the issuer chain with the selected keybox chain, so decoding the genuine issuer chain first
     * is unnecessary work on the latency-sensitive generateKey reply path.
     */
    public static X509Certificate getLeafCertificate(KeyMetadata metadata) {
        if (metadata == null || metadata.certificate == null || metadata.certificate.length == 0 ||
                metadata.certificate.length > MAX_CERTIFICATE_BYTES) {
            return null;
        }
        return new LazyX509Certificate(metadata.certificate, false);
    }

    public static Certificate[] getCertificateChain(KeyEntryResponse response) {
        return response == null ? null : getCertificateChain(response.metadata);
    }

    public static Certificate[] getCertificateChain(KeyMetadata metadata) {
        if (metadata == null) return null;
        X509Certificate leaf = getLeafCertificate(metadata);
        if (leaf == null) return null;

        List<X509Certificate> issuers =
                metadata.certificateChain == null
                        ? List.of()
                        : toCertificates(metadata.certificateChain);
        if (metadata.certificateChain != null && metadata.certificateChain.length > 0 && issuers.isEmpty()) return null;

        Certificate[] chain = new Certificate[issuers.size() + 1];
        chain[0] = leaf;
        for (int index = 0; index < issuers.size(); index++) {
            chain[index + 1] = issuers.get(index);
        }
        return chain;
    }

    public static byte[] encodeIssuerChain(Certificate[] chain) throws CertificateException {
        if (chain.length <= 1) return new byte[0];

        FastByteArrayOutputStream output = new FastByteArrayOutputStream(2048);
        try {
            int total = 0;
            for (int index = 1; index < chain.length; index++) {
                Certificate certificate = chain[index];
                byte[] encoded = certificate.getEncoded();
                if (encoded.length == 0 || encoded.length > MAX_CERTIFICATE_BYTES ||
                        encoded.length > MAX_CHAIN_BYTES - total) {
                    throw new CertificateException("Invalid certificate-chain size");
                }
                output.write(encoded, 0, encoded.length);
                total += encoded.length;
            }
            return output.toByteArray();
        } finally {
            output.wipe();
        }
    }

    public static void putCertificateChain(KeyEntryResponse response, Certificate[] chain)
            throws CertificateException {
        if (response == null) throw new CertificateException("Missing key response");
        putCertificateChain(response.metadata, chain);
    }

    public static void putCertificateChain(KeyMetadata metadata, Certificate[] chain)
            throws CertificateException {
        if (metadata == null || chain == null || chain.length == 0 ||
                chain.length > MAX_CERTIFICATES) {
            throw new CertificateException("Invalid certificate chain");
        }

        byte[] leaf = chain[0].getEncoded();
        if (leaf.length == 0 || leaf.length > MAX_CERTIFICATE_BYTES) {
            throw new CertificateException("Invalid leaf certificate size");
        }

        metadata.certificate = leaf;
        metadata.certificateChain = encodeIssuerChain(chain);
    }
}
