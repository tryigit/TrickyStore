package cleveres.tricky.cleverestech.keystore;

import android.os.Parcel;
import android.security.keystore.KeyProperties;
import android.system.keystore2.KeyMetadata;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import cleveres.tricky.cleverestech.CertificateBackend;
import cleveres.tricky.cleverestech.Config;
import cleveres.tricky.cleverestech.KeyboxActivation;
import cleveres.tricky.cleverestech.KeyboxLoader;
import cleveres.tricky.cleverestech.Logger;
import cleveres.tricky.cleverestech.PolicyState;
import cleveres.tricky.cleverestech.UtilKt;
import cleveres.tricky.cleverestech.util.FastByteArrayOutputStream;

public final class CertHack {
    private static final int MAX_CERTIFICATE_CACHE_ENTRIES = 64;
    private static final int MAX_CERTIFICATE_CACHE_RETAINED_BYTES = 4 * 1024 * 1024;
    private static final int MAX_PREPARED_ISSUER_CHAIN_BYTES = 4 * 1024 * 1024;
    private static final int MAX_LEAF_CERTIFICATE_BYTES = 64 * 1024;
    private static final int BACKEND_KEY_ID_BYTES = 16;
    private static final String BACKEND_KEY_FORMAT = "CleveresTricky-KeyId-v1";
    private static final String[] ATTESTATION_ID_NAMES =
            {"BRAND", "DEVICE", "PRODUCT", "SERIAL", "IMEI", "MEID", "MANUFACTURER", "MODEL", "IMEI2"};
    private static final int[] ATTESTATION_ID_TAGS = {710, 711, 712, 713, 714, 715, 716, 717, 723};

    private static final ThreadLocal<CertificateFactory> CERTIFICATE_FACTORY =
            new ThreadLocal<CertificateFactory>() {
                @Override
                protected CertificateFactory initialValue() {
                    try {
                        return CertificateFactory.getInstance("X.509");
                    } catch (Exception e) {
                        throw new IllegalStateException("X.509 certificate factory is unavailable", e);
                    }
                }
            };

    private static final class PreparedKeyBox {
        final String signatureAlgorithm;
        final Certificate[] issuerChain;
        final byte[] keyId;

        PreparedKeyBox(KeyBox keybox) throws Exception {
            if (keybox.certificates.isEmpty()) throw new IOException("Keybox has no certificates");
            this.signatureAlgorithm = signatureAlgorithmForKeybox(keybox);
            if (this.signatureAlgorithm == null) throw new IOException("Unsupported keybox algorithm");
            this.issuerChain = keybox.certificates.toArray(new Certificate[0]);
            if (!BACKEND_KEY_FORMAT.equals(keybox.keyPair.getPrivate().getFormat())) {
                throw new IOException("Production keybox does not use an opaque backend key handle");
            }
            byte[] encoded = keybox.keyPair.getPrivate().getEncoded();
            if (encoded == null || encoded.length != BACKEND_KEY_ID_BYTES) {
                if (encoded != null) Arrays.fill(encoded, (byte) 0);
                throw new IOException("Opaque backend key identifier is invalid");
            }
            int aggregate = 0;
            for (byte value : encoded) aggregate |= value & 0xFF;
            if (aggregate == 0) {
                Arrays.fill(encoded, (byte) 0);
                throw new IOException("Opaque backend key identifier is zero");
            }
            this.keyId = encoded;
        }

        private static byte[] encodeKeyboxIssuers(Certificate[] issuers) throws CertificateException {
            if (issuers == null || issuers.length == 0) return new byte[0];
            FastByteArrayOutputStream output = new FastByteArrayOutputStream(2048);
            try {
                int total = 0;
                for (Certificate cert : issuers) {
                    byte[] encoded = cert.getEncoded();
                    if (encoded.length == 0 || encoded.length > MAX_LEAF_CERTIFICATE_BYTES
                            || encoded.length > 512 * 1024 - total) {
                        throw new CertificateException("Invalid keybox certificate-chain size");
                    }
                    output.write(encoded, 0, encoded.length);
                    total += encoded.length;
                }
                return output.toByteArray();
            } finally {
                output.wipe();
            }
        }
    }

    /**
     * One immutable cache value serves both compatibility APIs and the latency-sensitive raw
     * KeyMetadata readback path. Replacement entries retain public encoded certificate bytes.
     * Passthrough entries are marker-only and deliberately retain no certificate or chain arrays.
     */
    private static final class CachedCertificateChain {
        final Certificate[] certificates;
        final byte[] leafEncoded;
        final byte[] issuerChainEncoded;
        final boolean passthrough;
        final boolean leafOnlySafe;
        final boolean accountIssuerChainBytes;
        final int attestKeyCallingUid;
        final byte[] attestKeyId;

        CachedCertificateChain(
                Certificate[] certificates,
                byte[] leafEncoded,
                byte[] issuerChainEncoded,
                boolean leafOnlySafe
        ) {
            this(certificates, leafEncoded, issuerChainEncoded, leafOnlySafe, false, 0, null);
        }

        CachedCertificateChain(
                Certificate[] certificates,
                byte[] leafEncoded,
                byte[] issuerChainEncoded,
                boolean leafOnlySafe,
                boolean accountIssuerChainBytes
        ) {
            this(certificates, leafEncoded, issuerChainEncoded, leafOnlySafe, accountIssuerChainBytes, 0, null);
        }

        CachedCertificateChain(
                Certificate[] certificates,
                byte[] leafEncoded,
                byte[] issuerChainEncoded,
                boolean leafOnlySafe,
                boolean accountIssuerChainBytes,
                int attestKeyCallingUid,
                byte[] attestKeyId
        ) {
            this.certificates = certificates != null ? certificates.clone() : null;
            this.leafEncoded = Objects.requireNonNull(leafEncoded, "leafEncoded");
            this.issuerChainEncoded = issuerChainEncoded;
            this.passthrough = false;
            this.leafOnlySafe = leafOnlySafe;
            this.accountIssuerChainBytes = accountIssuerChainBytes;
            this.attestKeyCallingUid = attestKeyCallingUid;
            this.attestKeyId = attestKeyId != null ? attestKeyId.clone() : null;
        }

        private CachedCertificateChain() {
            this.certificates = null;
            this.leafEncoded = null;
            this.issuerChainEncoded = null;
            this.passthrough = true;
            this.leafOnlySafe = true; // Passthrough is always safe for leaves (it does nothing)
            this.accountIssuerChainBytes = false;
            this.attestKeyCallingUid = 0;
            this.attestKeyId = null;
        }

        static CachedCertificateChain passthrough() {
            return new CachedCertificateChain();
        }

        Certificate[] certificateCopy() {
            return passthrough ? null : certificates.clone();
        }

        int retainedBytes() {
            if (passthrough) return 0;
            int bytes = leafEncoded != null ? leafEncoded.length : 0;
            if (accountIssuerChainBytes && issuerChainEncoded != null) {
                bytes += issuerChainEncoded.length;
            }
            if (attestKeyId != null) {
                bytes += attestKeyId.length;
            }
            return bytes;
        }

        void applyTo(KeyMetadata metadata) {
            if (passthrough) return;
            // Parcel.writeTypedObject copies these byte arrays synchronously. The transient
            // KeyMetadata object never owns or mutates the cache storage after the reply is built.
            metadata.certificate = leafEncoded;
            metadata.certificateChain = issuerChainEncoded;
        }
    }

    private static class State {
        final Map<String, List<KeyBox>> keyboxes;
        final Map<String, List<KeyBox>> keyboxFiles;
        final Map<KeyBox, PreparedKeyBox> preparedKeyboxes;
        final Map<KeyBox, KeyboxSecurityLevel> keyboxClassifications;
        final Set<KeyBox> strongBoxKeyboxes;
        final Set<KeyBox> teeKeyboxes;
        final Map<String, String> securityLevelByIdentifier;
        final int canonicalSourceCount;

        final List<KeyBox> globalTeeEc;
        final List<KeyBox> globalTeeRsa;
        final List<KeyBox> globalStrongBoxEc;
        final List<KeyBox> globalStrongBoxRsa;

        final PreparedIssuerChainCache preparedIssuerChains;
        final CertificateCache certificateCache;
        volatile Object certificateCacheEpoch;

        State(Map<String, List<KeyBox>> keyboxes, Map<String, List<KeyBox>> keyboxFiles) {
            this(
                    keyboxes,
                    keyboxFiles,
                    prepareKeyboxesForState(keyboxes),
                    classifyKeyboxesForState(keyboxFiles, keyboxes),
                    countCanonicalSources(keyboxFiles)
            );
        }

        State(
                Map<String, List<KeyBox>> keyboxes,
                Map<String, List<KeyBox>> keyboxFiles,
                Map<KeyBox, PreparedKeyBox> preparedKeyboxes,
                Map<KeyBox, KeyboxSecurityLevel> classifications,
                int canonicalSourceCount
        ) {
            this.keyboxes = immutableLists(keyboxes);
            this.keyboxFiles = immutableLists(keyboxFiles);
            this.preparedKeyboxes = Collections.unmodifiableMap(new IdentityHashMap<>(preparedKeyboxes));
            this.keyboxClassifications = Collections.unmodifiableMap(new IdentityHashMap<>(classifications));
            this.canonicalSourceCount = canonicalSourceCount;

            Set<KeyBox> sbKeyboxes = Collections.newSetFromMap(new IdentityHashMap<>());
            Set<KeyBox> tKeyboxes = Collections.newSetFromMap(new IdentityHashMap<>());
            Map<String, String> secLevelById = new HashMap<>();

            for (Map.Entry<KeyBox, KeyboxSecurityLevel> entry : classifications.entrySet()) {
                if (entry.getValue() == KeyboxSecurityLevel.STRONGBOX) {
                    sbKeyboxes.add(entry.getKey());
                } else if (entry.getValue() == KeyboxSecurityLevel.TEE) {
                    tKeyboxes.add(entry.getKey());
                }
            }

            for (Map.Entry<String, List<KeyBox>> entry : this.keyboxFiles.entrySet()) {
                boolean fileHasStrongBox = false;
                boolean fileHasTee = false;
                for (KeyBox box : entry.getValue()) {
                    KeyboxSecurityLevel level = classifications.getOrDefault(box, KeyboxSecurityLevel.UNKNOWN);
                    if (level == KeyboxSecurityLevel.STRONGBOX) {
                        fileHasStrongBox = true;
                    } else if (level == KeyboxSecurityLevel.TEE) {
                        fileHasTee = true;
                    }
                }
                String fileLevel = fileHasStrongBox ? "StrongBox" : (fileHasTee ? "TEE" : "Unknown");
                secLevelById.put(entry.getKey(), fileLevel);
            }

            this.securityLevelByIdentifier = Map.copyOf(secLevelById);
            this.strongBoxKeyboxes = Collections.unmodifiableSet(sbKeyboxes);
            this.teeKeyboxes = Collections.unmodifiableSet(tKeyboxes);

            List<KeyBox> teeEc = new ArrayList<>();
            List<KeyBox> teeRsa = new ArrayList<>();
            List<KeyBox> sbEc = new ArrayList<>();
            List<KeyBox> sbRsa = new ArrayList<>();

            List<KeyBox> ecBoxes = this.keyboxes.get(KeyProperties.KEY_ALGORITHM_EC);
            if (ecBoxes != null) {
                for (KeyBox box : ecBoxes) {
                    if (!this.preparedKeyboxes.containsKey(box)) continue;
                    if (sbKeyboxes.contains(box)) sbEc.add(box);
                    if (tKeyboxes.contains(box)) teeEc.add(box);
                }
            }
            List<KeyBox> rsaBoxes = this.keyboxes.get(KeyProperties.KEY_ALGORITHM_RSA);
            if (rsaBoxes != null) {
                for (KeyBox box : rsaBoxes) {
                    if (!this.preparedKeyboxes.containsKey(box)) continue;
                    if (sbKeyboxes.contains(box)) sbRsa.add(box);
                    if (tKeyboxes.contains(box)) teeRsa.add(box);
                }
            }

            this.globalTeeEc = List.copyOf(teeEc);
            this.globalTeeRsa = List.copyOf(teeRsa);
            this.globalStrongBoxEc = List.copyOf(sbEc);
            this.globalStrongBoxRsa = List.copyOf(sbRsa);

            this.preparedIssuerChains = new PreparedIssuerChainCache();
            this.certificateCache = new CertificateCache();
            this.certificateCacheEpoch = new Object();
        }

        byte[] encodedIssuerChain(PreparedKeyBox prepared) throws CertificateException {
            return preparedIssuerChains.getOrEncode(prepared);
        }

        private static Map<KeyBox, PreparedKeyBox> prepareKeyboxesForState(Map<String, List<KeyBox>> keyboxes) {
            Map<KeyBox, PreparedKeyBox> prepared = new IdentityHashMap<>();
            for (List<KeyBox> list : keyboxes.values()) {
                for (KeyBox keybox : list) {
                    if (prepared.containsKey(keybox)) continue;
                    try {
                        prepared.put(keybox, new PreparedKeyBox(keybox));
                    } catch (Exception error) {
                        Logger.e("Could not prepare opaque keybox metadata", error);
                    }
                }
            }
            return prepared;
        }

        private static Map<KeyBox, KeyboxSecurityLevel> classifyKeyboxesForState(
                Map<String, List<KeyBox>> keyboxFiles,
                Map<String, List<KeyBox>> keyboxes
        ) {
            Map<KeyBox, KeyboxSecurityLevel> classifications = new IdentityHashMap<>();
            for (List<KeyBox> list : keyboxFiles.values()) {
                for (KeyBox box : list) {
                    if (!classifications.containsKey(box)) {
                        classifications.put(box, classifyKeyboxSecurityLevel(box));
                    }
                }
            }
            for (List<KeyBox> list : keyboxes.values()) {
                for (KeyBox box : list) {
                    if (!classifications.containsKey(box)) {
                        classifications.put(box, classifyKeyboxSecurityLevel(box));
                    }
                }
            }
            return classifications;
        }

        private static int countCanonicalSources(Map<String, List<KeyBox>> keyboxFiles) {
            Set<String> canonical = new HashSet<>();
            for (List<KeyBox> list : keyboxFiles.values()) {
                for (KeyBox box : list) {
                    canonical.add(box.filename);
                }
            }
            return canonical.size();
        }

        private static Map<String, List<KeyBox>> immutableLists(Map<String, List<KeyBox>> source) {
            Map<String, List<KeyBox>> copy = new HashMap<>();
            source.forEach((key, value) -> copy.put(key, List.copyOf(value)));
            return Map.copyOf(copy);
        }

        @SuppressWarnings("serial")
        static final class PreparedIssuerChainCache extends LinkedHashMap<PreparedKeyBox, byte[]> {
            private static final long serialVersionUID = 1L;
            private int retainedBytes = 0;

            PreparedIssuerChainCache() {
                super(8, 0.75f, true);
            }

            synchronized byte[] getOrEncode(PreparedKeyBox prepared) throws CertificateException {
                byte[] cached = super.get(prepared);
                if (cached != null) return cached;

                byte[] encoded = PreparedKeyBox.encodeKeyboxIssuers(prepared.issuerChain);
                super.put(prepared, encoded);
                retainedBytes += encoded.length;
                trimLocked();
                return encoded;
            }

            synchronized int retainedBytes() {
                return retainedBytes;
            }

            private void trimLocked() {
                Iterator<Map.Entry<PreparedKeyBox, byte[]>> it = entrySet().iterator();
                while (it.hasNext() && retainedBytes > MAX_PREPARED_ISSUER_CHAIN_BYTES) {
                    Map.Entry<PreparedKeyBox, byte[]> entry = it.next();
                    byte[] bytes = entry.getValue();
                    retainedBytes -= bytes != null ? bytes.length : 0;
                    if (retainedBytes < 0) retainedBytes = 0;
                    it.remove();
                }
            }
        }

        @SuppressWarnings("serial")
        static final class CertificateCache extends LinkedHashMap<CacheKey, CachedCertificateChain> {
            private static final long serialVersionUID = 1L;
            private int retainedBytes = 0;

            CertificateCache() {
                super(32, 0.75f, true);
            }

            private int entryRetainedBytes(CacheKey key, CachedCertificateChain value) {
                int bytes = 0;
                if (key != null) {
                    bytes += key.retainedBytes();
                }
                if (value != null) {
                    bytes += value.retainedBytes();
                }
                return bytes;
            }

            @Override
            public synchronized CachedCertificateChain get(Object key) {
                return super.get(key);
            }

            @Override
            public synchronized CachedCertificateChain put(CacheKey key, CachedCertificateChain value) {
                CachedCertificateChain old = super.put(key, value);
                if (old != null) {
                    retainedBytes -= old.retainedBytes();
                } else if (key != null) {
                    retainedBytes += key.retainedBytes();
                }
                if (value != null) {
                    retainedBytes += value.retainedBytes();
                }
                trimLocked();
                return old;
            }

            @Override
            public synchronized CachedCertificateChain putIfAbsent(CacheKey key, CachedCertificateChain value) {
                CachedCertificateChain existing = super.get(key);
                if (existing == null) {
                    put(key, value);
                    return null;
                }
                return existing;
            }

            @Override
            public synchronized CachedCertificateChain remove(Object key) {
                CachedCertificateChain old = super.remove(key);
                if (old != null) {
                    if (key instanceof CacheKey cacheKey) {
                        retainedBytes -= cacheKey.retainedBytes();
                    }
                    retainedBytes -= old.retainedBytes();
                    if (retainedBytes < 0) {
                        retainedBytes = 0;
                    }
                }
                return old;
            }

            @Override
            public synchronized void clear() {
                super.clear();
                retainedBytes = 0;
            }

            @Override
            public synchronized boolean isEmpty() {
                return super.isEmpty();
            }

            synchronized int retainedBytes() {
                return retainedBytes;
            }

            private void trimLocked() {
                Iterator<Map.Entry<CacheKey, CachedCertificateChain>> it = entrySet().iterator();
                while (it.hasNext() && (size() > MAX_CERTIFICATE_CACHE_ENTRIES
                        || retainedBytes > MAX_CERTIFICATE_CACHE_RETAINED_BYTES)) {
                    Map.Entry<CacheKey, CachedCertificateChain> entry = it.next();
                    retainedBytes -= entryRetainedBytes(entry.getKey(), entry.getValue());
                    if (retainedBytes < 0) {
                        retainedBytes = 0;
                    }
                    it.remove();
                }
            }
        }
    }

    private static volatile State state = new State(Collections.emptyMap(), Collections.emptyMap());
    private static volatile byte[] capturedHardwareBootKey = null;
    private static volatile byte[] capturedHardwareBootHash = null;

    private static final class CacheKey {
        private final byte[] leafEncoded;
        private final int hashCode;

        CacheKey(byte[] leafEncoded) {
            this.leafEncoded = Objects.requireNonNull(leafEncoded, "leafEncoded");
            this.hashCode = Arrays.hashCode(this.leafEncoded);
        }

        int retainedBytes() {
            return leafEncoded != null ? leafEncoded.length : 0;
        }

        int indexForPool(int size) {
            if (size <= 0) throw new IllegalArgumentException("Keybox pool is empty");
            return (hashCode & 0x7FFFFFFF) % size;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            return Arrays.equals(leafEncoded, ((CacheKey) o).leafEncoded);
        }

        @Override
        public int hashCode() {
            return hashCode;
        }
    }

    public static boolean canHack() {
        return !state.keyboxes.isEmpty();
    }

    public enum KeyboxSecurityLevel {
        TEE,
        STRONGBOX,
        UNKNOWN
    }

    public static KeyboxSecurityLevel classifyKeyboxSecurityLevel(KeyBox keybox) {
        if (keybox == null) return KeyboxSecurityLevel.UNKNOWN;
        if (keybox.certificates() != null) {
            for (Certificate cert : keybox.certificates()) {
                if (cert instanceof X509Certificate x509) {
                    byte[] ext = x509.getExtensionValue("1.3.6.1.4.1.11129.2.1.17");
                    if (ext != null) {
                        CertificateBackend.Inspection insp = null;
                        try {
                            insp = CertificateBackend.inspect(x509.getEncoded());
                            if (insp != null) {
                                int att = insp.getAttestationSecurityLevel();
                                int km = insp.getKeymintSecurityLevel();
                                if (att == CertificateBackend.SECURITY_LEVEL_TEE
                                        && km == CertificateBackend.SECURITY_LEVEL_TEE) {
                                    return KeyboxSecurityLevel.TEE;
                                }
                                if (att == CertificateBackend.SECURITY_LEVEL_STRONGBOX
                                        && km == CertificateBackend.SECURITY_LEVEL_STRONGBOX) {
                                    return KeyboxSecurityLevel.STRONGBOX;
                                }
                                if (att == CertificateBackend.SECURITY_LEVEL_TEE
                                        && km == CertificateBackend.SECURITY_LEVEL_STRONGBOX) {
                                    return KeyboxSecurityLevel.STRONGBOX;
                                }
                            }
                        } catch (Throwable error) {
                            Logger.e("Failed to inspect attestation extension for security level", error);
                        } finally {
                            if (insp != null) insp.wipe();
                        }
                        // An attestation extension was present on this certificate.
                        // If inspection failed, threw an error, or the security level pairing
                        // was not authentic hardware (e.g. Software or invalid), fail closed.
                        // Never fall through to filename or DN heuristics.
                        return KeyboxSecurityLevel.UNKNOWN;
                    }
                }
            }

            // Only if NO certificate in the keybox had an Android attestation extension:
            for (Certificate cert : keybox.certificates()) {
                if (cert instanceof X509Certificate x509) {
                    var subject = x509.getSubjectX500Principal();
                    String subjectName = subject != null ? subject.getName().toLowerCase(Locale.ROOT) : "";
                    var issuer = x509.getIssuerX500Principal();
                    String issuerName = issuer != null ? issuer.getName().toLowerCase(Locale.ROOT) : "";

                    if (subjectName.contains("strongbox") || issuerName.contains("strongbox")) {
                        return KeyboxSecurityLevel.STRONGBOX;
                    }
                }
            }
        }
        if (keybox.filename() != null) {
            String lower = keybox.filename().toLowerCase(Locale.ROOT);
            if (lower.contains("strongbox")) {
                return KeyboxSecurityLevel.STRONGBOX;
            }
            if (lower.contains("tee")) {
                return KeyboxSecurityLevel.TEE;
            }
        }
        if (keybox.certificates() != null) {
            for (Certificate cert : keybox.certificates()) {
                if (cert instanceof X509Certificate x509) {
                    var subject = x509.getSubjectX500Principal();
                    String subjectName = subject != null ? subject.getName().toLowerCase(Locale.ROOT) : "";
                    var issuer = x509.getIssuerX500Principal();
                    String issuerName = issuer != null ? issuer.getName().toLowerCase(Locale.ROOT) : "";

                    if (isTeeDn(subjectName) || isTeeDn(issuerName)) {
                        return KeyboxSecurityLevel.TEE;
                    }
                }
            }
        }
        if (keybox.certificates() == null || keybox.certificates().isEmpty()) {
            return KeyboxSecurityLevel.UNKNOWN;
        }
        // In standard Android Keystore architecture, standard keyboxes (such as keybox.xml,
        // OEM provisioned keys, and standard CA chains) do not contain "tee" markers in filenames
        // or DNs and are by definition TEE keyboxes. Unless explicitly identified as StrongBox
        // or failing provenance, valid keyboxes default to TEE.
        return KeyboxSecurityLevel.TEE;
    }

    private static boolean isTeeDn(String dn) {
        if (dn == null || dn.isEmpty()) return false;
        return dn.contains("android keymint ca")
                || dn.contains("google hardware attestation ca")
                || dn.contains("android attestation ca")
                || dn.contains("google root ca")
                || dn.contains("android keystore keymint ca");
    }

    public static boolean isStrongBoxKeybox(KeyBox keybox) {
        if (keybox == null) return false;
        State currentState = state;
        if (currentState.strongBoxKeyboxes.contains(keybox)) {
            return true;
        }
        KeyboxSecurityLevel cachedLevel = currentState.keyboxClassifications.get(keybox);
        if (cachedLevel != null) {
            return cachedLevel == KeyboxSecurityLevel.STRONGBOX;
        }
        return classifyKeyboxSecurityLevel(keybox) == KeyboxSecurityLevel.STRONGBOX;
    }

    public static boolean isTeeKeybox(KeyBox keybox) {
        if (keybox == null) return false;
        State currentState = state;
        if (currentState.teeKeyboxes.contains(keybox)) {
            return true;
        }
        KeyboxSecurityLevel cachedLevel = currentState.keyboxClassifications.get(keybox);
        if (cachedLevel != null) {
            return cachedLevel == KeyboxSecurityLevel.TEE;
        }
        return classifyKeyboxSecurityLevel(keybox) == KeyboxSecurityLevel.TEE;
    }

    public static String getKeyboxSecurityLevel(String identifier) {
        if (identifier == null) return "Unknown";
        State currentState = state;
        String level = currentState.securityLevelByIdentifier.get(identifier);
        return level != null ? level : "Unknown";
    }

    public static int getKeyboxCount() {
        if (!KeyboxLoader.isActiveSetHealthy()) {
            throw new IllegalStateException("Rust keybox backend activation is unavailable");
        }
        return getPublishedKeyboxCountForTesting();
    }

    /** Counts active keybox sources, not EC/RSA key records inside each source. */
    public static int getKeyboxSourceCount() {
        if (!KeyboxLoader.isActiveSetHealthy()) {
            throw new IllegalStateException("Rust keybox backend activation is unavailable");
        }
        return state.canonicalSourceCount;
    }

    public static boolean isRkpKeybox(String identifier) {
        if (identifier == null) return false;
        List<KeyBox> boxes = state.keyboxFiles.get(identifier);
        if (boxes == null) return false;
        for (KeyBox box : boxes) {
            if (isRkpKeybox(box)) return true;
        }
        return false;
    }

    public static boolean isRkpKeybox(KeyBox keybox) {
        if (keybox == null || keybox.certificates() == null) return false;
        for (Certificate cert : keybox.certificates()) {
            if (cert instanceof X509Certificate x509) {
                var subject = x509.getSubjectX500Principal();
                if (subject != null && subject.getName().toLowerCase(Locale.ROOT).contains("droid ca")) {
                    return true;
                }
                var issuer = x509.getIssuerX500Principal();
                if (issuer != null && issuer.getName().toLowerCase(Locale.ROOT).contains("droid ca")) {
                    return true;
                }
            }
        }
        return false;
    }

    public static String getDeviceCertificateSerial(String identifier) {
        if (identifier == null) return null;
        List<KeyBox> boxes = state.keyboxFiles.get(identifier);
        if (boxes == null) return null;
        for (KeyBox box : boxes) {
            String serial = getDeviceCertificateSerial(box);
            if (serial != null) return serial;
        }
        return null;
    }

    public static String getDeviceCertificateSerial(KeyBox keybox) {
        if (keybox == null || keybox.certificates().size() < 3) return null;
        Certificate certificate = keybox.certificates().get(2);
        if (!(certificate instanceof X509Certificate x509)) return null;
        return x509.getSerialNumber().toString(16).toUpperCase(Locale.ROOT);
    }

    /**
     * JVM-unit-test seam for inspecting the already-published managed snapshot without
     * probing backend health or triggering backend recovery.
     */
    public static int getPublishedKeyboxCountForTesting() {
        int count = 0;
        for (List<KeyBox> list : state.keyboxes.values()) count += list.size();
        return count;
    }

    static int getPreparedIssuerChainRetainedBytesForTesting() {
        return state.preparedIssuerChains.retainedBytes();
    }

    /**
     * JVM-unit-test compatibility seam. The managed/BC parser is physically present only in
     * src/test; release builds have no such class and therefore cannot execute a managed parser.
     */
    @SuppressWarnings("unchecked")
    public static List<KeyBox> parseKeyboxXml(java.io.Reader reader, String filename) {
        try {
            Class<?> oracle = Class.forName("cleveres.tricky.cleverestech.keystore.ManagedKeyboxOracle");
            Object parsed = oracle
                    .getMethod("parse", java.io.Reader.class, String.class)
                    .invoke(null, reader, filename);
            return parsed instanceof List<?> ? (List<KeyBox>) parsed : Collections.emptyList();
        } catch (ReflectiveOperationException unavailableOutsideTests) {
            return Collections.emptyList();
        }
    }

    public static synchronized void setKeyboxes(List<KeyBox> boxes) {
        if (boxes == null || boxes.isEmpty()) {
            Logger.i("clear all keyboxes");
            state = new State(Collections.emptyMap(), Collections.emptyMap());
            return;
        }
        Map<String, List<KeyBox>> newKeyboxes = new HashMap<>();
        Map<String, List<KeyBox>> newKeyboxFiles = new HashMap<>();
        Map<KeyBox, PreparedKeyBox> preparedMap = new IdentityHashMap<>();
        Map<KeyBox, KeyboxSecurityLevel> classificationMap = new IdentityHashMap<>();
        Set<String> uniqueCanonicalFiles = new HashSet<>();

        for (KeyBox box : boxes) {
            String algo = normalizeAlgorithm(box.keyPair.getPublic().getAlgorithm());
            if (algo == null) {
                Logger.e("Ignoring unsupported keybox algorithm: " + box.keyPair.getPublic().getAlgorithm());
                continue;
            }
            PreparedKeyBox prepared;
            try {
                prepared = new PreparedKeyBox(box);
            } catch (Exception error) {
                Logger.e("Ignoring keybox without a valid opaque backend handle", error);
                continue;
            }
            preparedMap.put(box, prepared);
            KeyboxSecurityLevel level = classifyKeyboxSecurityLevel(box);
            classificationMap.put(box, level);

            uniqueCanonicalFiles.add(box.filename);
            newKeyboxes.computeIfAbsent(algo, ignored -> new ArrayList<>()).add(box);
            newKeyboxFiles.computeIfAbsent(box.filename, ignored -> new ArrayList<>()).add(box);
            int colonIdx = box.filename.indexOf(':');
            if (colonIdx >= 0 && colonIdx < box.filename.length() - 1) {
                String shortName = box.filename.substring(colonIdx + 1);
                newKeyboxFiles.computeIfAbsent(shortName, ignored -> new ArrayList<>()).add(box);
            }
        }
        int ecCount = newKeyboxes.getOrDefault(KeyProperties.KEY_ALGORITHM_EC, Collections.emptyList()).size();
        int rsaCount = newKeyboxes.getOrDefault(KeyProperties.KEY_ALGORITHM_RSA, Collections.emptyList()).size();
        Logger.i("update keyboxes: total=" + boxes.size() + " (EC=" + ecCount + ", RSA=" + rsaCount + ")");
        state = new State(newKeyboxes, newKeyboxFiles, preparedMap, classificationMap, uniqueCanonicalFiles.size());
    }

    public static void clearCertificateCache() {
        State currentState = state;
        synchronized (currentState.certificateCache) {
            currentState.certificateCacheEpoch = new Object();
            currentState.certificateCache.clear();
        }
        CertificateBackend.clearAttestKeyStore();
    }

    static Object captureCertificateCacheEpochForTesting() {
        State currentState = state;
        synchronized (currentState.certificateCache) {
            return currentState.certificateCacheEpoch;
        }
    }

    static boolean isCertificateCacheEpochCurrentForTesting(Object expectedEpoch) {
        State currentState = state;
        synchronized (currentState.certificateCache) {
            return currentState.certificateCacheEpoch == expectedEpoch;
        }
    }

    public static boolean hasCachedCertificateChains() {
        return !state.certificateCache.isEmpty();
    }

    private static CachedCertificateChain validateAndTouchAttestKey(
            State.CertificateCache cache,
            CacheKey cacheKey,
            CachedCertificateChain cached
    ) {
        if (cached == null || cached.attestKeyId == null) {
            return cached;
        }
        if (CertificateBackend.touchAttestKey(cached.attestKeyCallingUid, cached.attestKeyId)) {
            return cached;
        }
        synchronized (cache) {
            CachedCertificateChain current = cache.get(cacheKey);
            if (current == cached) {
                cache.remove(cacheKey);
            }
        }
        return null;
    }

    /**
     * Applies a cached replacement or passthrough decision directly to raw KeyMetadata bytes.
     * A passthrough hit is intentionally a no-op and still returns true, allowing repeated
     * getKeyEntry calls to avoid X.509 parsing and Rust IPC while preserving the genuine reply.
     */
    public static boolean applyCachedCertificateChain(KeyMetadata metadata) {
        boolean isLeafOnly = Utils.hasRewritableLeafCertificate(metadata);
        if (!Utils.isCertificateChainRewriteCandidate(metadata) && !isLeafOnly) {
            return false;
        }
        State currentState = state;
        CacheKey cacheKey = new CacheKey(metadata.certificate);
        CachedCertificateChain cached;
        synchronized (currentState.certificateCache) {
            cached = currentState.certificateCache.get(cacheKey);
        }
        cached = validateAndTouchAttestKey(currentState.certificateCache, cacheKey, cached);
        if (cached == null) return false;

        if (isLeafOnly && !cached.leafOnlySafe) {
            return false;
        }

        cached.applyTo(metadata);
        return true;
    }

    public enum CachedParcelAction {
        MISS,
        PASSTHROUGH,
        REWRITTEN
    }

    /**
     * Applies a cache hit directly to the stable-AIDL reply bytes. This is the measured
     * getKeyEntry path, so it must not instantiate KeyEntryResponse, KeyMetadata, their
     * authorization graph, or a second reply Parcel.
     */
    public static CachedParcelAction applyCachedCertificateChain(
            Parcel reply,
            Utils.ParcelParseResult parsed
    ) {
        if (reply == null || parsed == null ||
                (!parsed.hasFullCertificateChain() && !parsed.hasLeafOnlyCertificate())) {
            return CachedParcelAction.MISS;
        }

        State currentState = state;
        CacheKey cacheKey = new CacheKey(parsed.leafEncoded);
        CachedCertificateChain cached;
        synchronized (currentState.certificateCache) {
            cached = currentState.certificateCache.get(cacheKey);
        }
        cached = validateAndTouchAttestKey(currentState.certificateCache, cacheKey, cached);
        if (cached == null || (parsed.hasLeafOnlyCertificate() && !cached.leafOnlySafe)) {
            return CachedParcelAction.MISS;
        }
        if (cached.passthrough) return CachedParcelAction.PASSTHROUGH;

        return Utils.rewriteKeyMetadataParcel(
                reply,
                parsed,
                cached.leafEncoded,
                cached.issuerChainEncoded
        ) ? CachedParcelAction.REWRITTEN : CachedParcelAction.MISS;
    }

    public static Certificate[] getCachedCertificateChain(Certificate[] caList) {
        if (caList == null || caList.length == 0 || caList[0] == null) return null;
        try {
            byte[] leafEncoded = caList[0].getEncoded();
            if (leafEncoded.length == 0 || leafEncoded.length > MAX_LEAF_CERTIFICATE_BYTES) return null;
            CacheKey cacheKey = new CacheKey(leafEncoded);
            CachedCertificateChain cached;
            synchronized (state.certificateCache) {
                cached = state.certificateCache.get(cacheKey);
            }
            cached = validateAndTouchAttestKey(state.certificateCache, cacheKey, cached);
            if (cached == null) return null;
            Certificate[] replacement = cached.certificateCopy();
            return replacement == null ? caList : replacement;
        } catch (Throwable error) {
            return null;
        }
    }

    /**
     * Rewrites one key's attestation chain once per policy snapshot. Portable X.509/DER inspection,
     * authorization-list rewriting and signing are performed by the unprivileged Rust backend.
     * Managed code resolves Android-derived policy facts, selects an opaque key handle and
     * materializes the final JCA X.509 object. Private key bytes never enter this process.
     */
    public static Certificate[] hackCertificateChain(Certificate[] caList, int uid) {
        return hackCertificateChain(caList, uid, false);
    }

    public static Certificate[] hackCertificateChain(
            Certificate[] caList, int uid, boolean leafOnlySafe) {
        if (caList == null || caList.length == 0 || caList[0] == null) {
            throw new UnsupportedOperationException("Certificate chain is empty");
        }
        KeyboxActivation.lockPublishedSnapshot();
        CertificateBackend.Inspection inspection = null;
        byte[] keyId = null;
        try {
            State currentState = state;
            byte[] leafEncoded = caList[0].getEncoded();
            if (leafEncoded.length == 0 || leafEncoded.length > MAX_LEAF_CERTIFICATE_BYTES) {
                return caList;
            }
            CacheKey cacheKey = new CacheKey(leafEncoded);
            State.CertificateCache cache = currentState.certificateCache;
            Object cacheEpoch;
            CachedCertificateChain cached;
            synchronized (cache) {
                cached = cache.get(cacheKey);
                cacheEpoch = currentState.certificateCacheEpoch;
            }
            cached = validateAndTouchAttestKey(cache, cacheKey, cached);
            if (cached != null) {
                Certificate[] replacement = cached.certificateCopy();
                return replacement == null ? caList : replacement;
            }

            // Preserve the local non-attested fast path. Only genuine Android attestation leaves
            // cross the Rust certificate-inspection boundary.
            if (!Utils.hasAndroidAttestationExtension(caList[0])) return caList;

            // Security provenance is mandatory before choosing any replacement issuer. This is one
            // bounded inspection for a fresh attested leaf. The existing 64-entry LRU stores both
            // rewrite results and marker-only passthrough decisions, so repeated StrongBox reads do
            // not create recurring IPC, parsing, allocations, timers or background work.
            inspection = CertificateBackend.inspect(leafEncoded);
            if (inspection == null) return caList;
            int attLevel = inspection.getAttestationSecurityLevel();
            int kmLevel = inspection.getKeymintSecurityLevel();
            boolean isTee = attLevel == CertificateBackend.SECURITY_LEVEL_TEE
                    && kmLevel == CertificateBackend.SECURITY_LEVEL_TEE;
            boolean isStrongbox =
                    (attLevel == CertificateBackend.SECURITY_LEVEL_TEE
                            && kmLevel == CertificateBackend.SECURITY_LEVEL_STRONGBOX)
                    || (attLevel == CertificateBackend.SECURITY_LEVEL_STRONGBOX
                            && kmLevel == CertificateBackend.SECURITY_LEVEL_STRONGBOX);
            boolean isTeeOrStrongbox = isTee || isStrongbox;
            if (!isTeeOrStrongbox) {
                synchronized (cache) {
                    if (state == currentState && currentState.certificateCacheEpoch == cacheEpoch) {
                        cache.putIfAbsent(cacheKey, CachedCertificateChain.passthrough());
                    }
                }
                return caList;
            }

            boolean needsCapturedPatchLevels = PolicyState.INSTANCE.isFeatureEnabled(
                    PolicyState.Feature.SECURITY_PATCH, uid);
            byte[] originalBootKey = usableBootDigest(inspection.getOriginalBootKey());
            if (originalBootKey != null) {
                capturedHardwareBootKey = originalBootKey.clone();
            }
            byte[] originalBootHash = usableBootDigest(inspection.getOriginalBootHash());
            if (originalBootHash != null) {
                capturedHardwareBootHash = originalBootHash.clone();
            }
            byte[] verifiedBootKey = selectVerifiedBootDigest(
                    UtilKt.getBootKey(),
                    originalBootKey != null ? originalBootKey : capturedHardwareBootKey,
                    UtilKt.getPersistentBootKey());
            byte[] verifiedBootHash = selectVerifiedBootDigest(
                    UtilKt.getBootHash(),
                    originalBootHash != null ? originalBootHash : capturedHardwareBootHash,
                    UtilKt.getPersistentBootHash());
            Config.AttestationPatchLevels patchLevels = needsCapturedPatchLevels
                    ? PolicyState.INSTANCE.resolveAttestationPatchLevels(
                            uid,
                            inspection.getSystemPatch(),
                            inspection.getVendorPatch(),
                            inspection.getBootPatch())
                    : keepPatchLevels();

            List<KeyBox> list;
            var appConfig = Config.INSTANCE.getAppConfig(uid);
            if (appConfig != null && appConfig.getKeyboxFilename() != null) {
                List<KeyBox> candidates = currentState.keyboxFiles.get(appConfig.getKeyboxFilename());
                List<KeyBox> matchingLevel = filterKeyboxesBySecurityLevel(candidates, isStrongbox);
                if (!matchingLevel.isEmpty()) {
                    candidates = matchingLevel;
                } else if (isStrongbox) {
                    // Asymmetric fallback: StrongBox attestation can fall back to standard TEE keyboxes
                    candidates = filterKeyboxesBySecurityLevel(candidates, false);
                } else {
                    // TEE attestation must NEVER fall back to StrongBox keyboxes
                    candidates = Collections.emptyList();
                }
                list = selectKeyboxPool(candidates, KeyProperties.KEY_ALGORITHM_EC);
            } else {
                if (isStrongbox) {
                    if (!currentState.globalStrongBoxEc.isEmpty()) {
                        list = currentState.globalStrongBoxEc;
                    } else if (!currentState.globalStrongBoxRsa.isEmpty()) {
                        list = currentState.globalStrongBoxRsa;
                    } else if (!currentState.globalTeeEc.isEmpty()) {
                        list = currentState.globalTeeEc;
                    } else {
                        list = currentState.globalTeeRsa;
                    }
                } else {
                    if (!currentState.globalTeeEc.isEmpty()) {
                        list = currentState.globalTeeEc;
                    } else {
                        list = currentState.globalTeeRsa;
                    }
                }
            }
            if (list.isEmpty()) {
                return caList;
            }

            KeyBox keybox = list.get(cacheKey.indexForPool(list.size()));
            PreparedKeyBox prepared = currentState.preparedKeyboxes.get(keybox);
            if (prepared == null) throw new UnsupportedOperationException("Keybox metadata is unavailable");
            int signingAlgorithm = signingWireAlgorithm(prepared.signatureAlgorithm);
            if (signingAlgorithm == 0) return caList;

            if (verifiedBootKey == null || verifiedBootHash == null) {
                return caList;
            }

            Map<Integer, byte[]> idOverrides = presentIdOverrides(uid, inspection.getPresentIdMask());
            byte[] moduleHash = inspection.getSupportsModuleHash()
                    ? Config.INSTANCE.getModuleHash()
                    : null;
            keyId = prepared.keyId.clone();

            byte[] rewrittenDer = CertificateBackend.rewrite(
                    leafEncoded,
                    keyId,
                    signingAlgorithm,
                    patchDisposition(patchLevels.getSystem()), patchLevels.getSystem().getValue(),
                    patchDisposition(patchLevels.getVendor()), patchLevels.getVendor().getValue(),
                    patchDisposition(patchLevels.getBoot()), patchLevels.getBoot().getValue(),
                    idOverrides,
                    moduleHash,
                    verifiedBootKey,
                    verifiedBootHash);
            if (rewrittenDer == null || rewrittenDer.length == 0 || rewrittenDer.length > MAX_LEAF_CERTIFICATE_BYTES) {
                return caList;
            }
            byte[] encodedIssuerChain = currentState.encodedIssuerChain(prepared);
            Certificate rewrittenLeaf = new LazyX509Certificate(rewrittenDer, false);
            Certificate[] result = new Certificate[prepared.issuerChain.length + 1];
            result[0] = rewrittenLeaf;
            System.arraycopy(prepared.issuerChain, 0, result, 1, prepared.issuerChain.length);
            CachedCertificateChain completed = new CachedCertificateChain(
                    result,
                    rewrittenDer,
                    encodedIssuerChain,
                    leafOnlySafe,
                    true
            );
            synchronized (cache) {
                if (state != currentState || currentState.certificateCacheEpoch != cacheEpoch) {
                    return result;
                }
                CachedCertificateChain raced = cache.get(cacheKey);
                if (raced != null) {
                    Certificate[] replacement = raced.certificateCopy();
                    return replacement == null ? caList : replacement;
                }
                cache.put(cacheKey, completed);
            }
            return result;
        } catch (Throwable t) {
            return caList;
        } finally {
            if (keyId != null) Arrays.fill(keyId, (byte) 0);
            if (inspection != null) inspection.wipe();
            KeyboxActivation.unlockPublishedSnapshot();
        }
    }

    public static Certificate[] hackAttestKeyCertificateChain(Certificate[] caList, int uid) {
        return hackAttestKeyCertificateChain(caList, uid, false, null);
    }

    public static Certificate[] hackAttestKeyCertificateChain(
            Certificate[] caList, int uid, boolean leafOnlySafe) {
        return hackAttestKeyCertificateChain(caList, uid, leafOnlySafe, null);
    }

    public static Certificate[] hackAttestKeyCertificateChain(
            Certificate[] caList, int uid, byte[] attestKeyId) {
        return hackAttestKeyCertificateChain(caList, uid, false, attestKeyId);
    }

    public static Certificate[] hackAttestKeyCertificateChain(
            Certificate[] caList, int uid, boolean leafOnlySafe, byte[] attestKeyId) {
        if (caList == null || caList.length == 0 || caList[0] == null) {
            throw new UnsupportedOperationException("Certificate chain is empty");
        }
        KeyboxActivation.lockPublishedSnapshot();
        CertificateBackend.Inspection attestInspection = null;
        byte[] keyId = null;
        try {
            State currentState = state;
            byte[] leafEncoded = caList[0].getEncoded();
            if (leafEncoded.length == 0 || leafEncoded.length > MAX_LEAF_CERTIFICATE_BYTES) {
                return caList;
            }
            CacheKey cacheKey = new CacheKey(leafEncoded);
            State.CertificateCache cache = currentState.certificateCache;
            Object cacheEpoch;
            CachedCertificateChain cached;
            synchronized (cache) {
                cached = cache.get(cacheKey);
                cacheEpoch = currentState.certificateCacheEpoch;
            }
            cached = validateAndTouchAttestKey(cache, cacheKey, cached);
            if (cached != null) {
                Certificate[] replacement = cached.certificateCopy();
                return replacement == null ? caList : replacement;
            }

            if (!Utils.hasAndroidAttestationExtension(caList[0])) return caList;

            attestInspection = CertificateBackend.inspect(leafEncoded);
            if (attestInspection == null) return caList;
            int attLevel = attestInspection.getAttestationSecurityLevel();
            int kmLevel = attestInspection.getKeymintSecurityLevel();
            boolean isTee = attLevel == CertificateBackend.SECURITY_LEVEL_TEE
                    && kmLevel == CertificateBackend.SECURITY_LEVEL_TEE;
            boolean isStrongbox =
                    (attLevel == CertificateBackend.SECURITY_LEVEL_TEE
                            && kmLevel == CertificateBackend.SECURITY_LEVEL_STRONGBOX)
                    || (attLevel == CertificateBackend.SECURITY_LEVEL_STRONGBOX
                            && kmLevel == CertificateBackend.SECURITY_LEVEL_STRONGBOX);
            boolean isTeeOrStrongbox = isTee || isStrongbox;
            if (!isTeeOrStrongbox) {
                synchronized (cache) {
                    if (state == currentState && currentState.certificateCacheEpoch == cacheEpoch) {
                        cache.putIfAbsent(cacheKey, CachedCertificateChain.passthrough());
                    }
                }
                return caList;
            }

            boolean needsCapturedPatchLevels = PolicyState.INSTANCE.isFeatureEnabled(
                    PolicyState.Feature.SECURITY_PATCH, uid);
            byte[] originalBootKey = usableBootDigest(attestInspection.getOriginalBootKey());
            if (originalBootKey != null) {
                capturedHardwareBootKey = originalBootKey.clone();
            }
            byte[] originalBootHash = usableBootDigest(attestInspection.getOriginalBootHash());
            if (originalBootHash != null) {
                capturedHardwareBootHash = originalBootHash.clone();
            }
            byte[] verifiedBootKey = selectVerifiedBootDigest(
                    UtilKt.getBootKey(),
                    originalBootKey != null ? originalBootKey : capturedHardwareBootKey,
                    UtilKt.getPersistentBootKey());
            byte[] verifiedBootHash = selectVerifiedBootDigest(
                    UtilKt.getBootHash(),
                    originalBootHash != null ? originalBootHash : capturedHardwareBootHash,
                    UtilKt.getPersistentBootHash());
            Config.AttestationPatchLevels patchLevels = needsCapturedPatchLevels
                    ? PolicyState.INSTANCE.resolveAttestationPatchLevels(
                            uid,
                            attestInspection.getSystemPatch(),
                            attestInspection.getVendorPatch(),
                            attestInspection.getBootPatch())
                    : keepPatchLevels();

            List<KeyBox> list;
            var appConfig = Config.INSTANCE.getAppConfig(uid);
            if (appConfig != null && appConfig.getKeyboxFilename() != null) {
                List<KeyBox> candidates = currentState.keyboxFiles.get(appConfig.getKeyboxFilename());
                List<KeyBox> matchingLevel = filterKeyboxesBySecurityLevel(candidates, isStrongbox);
                if (!matchingLevel.isEmpty()) {
                    candidates = matchingLevel;
                } else if (isStrongbox) {
                    candidates = filterKeyboxesBySecurityLevel(candidates, false);
                } else {
                    candidates = Collections.emptyList();
                }
                list = selectKeyboxPool(candidates, KeyProperties.KEY_ALGORITHM_EC);
            } else {
                if (isStrongbox) {
                    if (!currentState.globalStrongBoxEc.isEmpty()) {
                        list = currentState.globalStrongBoxEc;
                    } else if (!currentState.globalStrongBoxRsa.isEmpty()) {
                        list = currentState.globalStrongBoxRsa;
                    } else if (!currentState.globalTeeEc.isEmpty()) {
                        list = currentState.globalTeeEc;
                    } else {
                        list = currentState.globalTeeRsa;
                    }
                } else {
                    if (!currentState.globalTeeEc.isEmpty()) {
                        list = currentState.globalTeeEc;
                    } else {
                        list = currentState.globalTeeRsa;
                    }
                }
            }
            if (list.isEmpty()) {
                return caList;
            }

            KeyBox keybox = list.get(cacheKey.indexForPool(list.size()));
            PreparedKeyBox prepared = currentState.preparedKeyboxes.get(keybox);
            if (prepared == null) throw new UnsupportedOperationException("Keybox metadata is unavailable");
            int signingAlgorithm = signingWireAlgorithm(prepared.signatureAlgorithm);
            if (signingAlgorithm == 0) return caList;

            if (verifiedBootKey == null || verifiedBootHash == null) {
                return caList;
            }

            Map<Integer, byte[]> idOverrides = presentIdOverrides(uid, attestInspection.getPresentIdMask());
            byte[] moduleHash = attestInspection.getSupportsModuleHash()
                    ? Config.INSTANCE.getModuleHash()
                    : null;
            if (attestKeyId == null || attestKeyId.length != 32) {
                return caList;
            }
            keyId = prepared.keyId.clone();

            byte[] rewrittenDer = CertificateBackend.rewriteAttestKey(
                    uid,
                    attestKeyId,
                    leafEncoded,
                    keyId,
                    signingAlgorithm,
                    patchDisposition(patchLevels.getSystem()), patchLevels.getSystem().getValue(),
                    patchDisposition(patchLevels.getVendor()), patchLevels.getVendor().getValue(),
                    patchDisposition(patchLevels.getBoot()), patchLevels.getBoot().getValue(),
                    idOverrides,
                    moduleHash,
                    verifiedBootKey,
                    verifiedBootHash);
            if (rewrittenDer == null || rewrittenDer.length == 0 || rewrittenDer.length > MAX_LEAF_CERTIFICATE_BYTES) {
                return caList;
            }
            byte[] encodedIssuerChain = currentState.encodedIssuerChain(prepared);
            Certificate rewrittenLeaf = new LazyX509Certificate(rewrittenDer, false);
            Certificate[] result = new Certificate[prepared.issuerChain.length + 1];
            result[0] = rewrittenLeaf;
            System.arraycopy(prepared.issuerChain, 0, result, 1, prepared.issuerChain.length);
            CachedCertificateChain completed = new CachedCertificateChain(
                    result,
                    rewrittenDer,
                    encodedIssuerChain,
                    leafOnlySafe,
                    true,
                    uid,
                    attestKeyId
            );
            synchronized (cache) {
                if (state != currentState || currentState.certificateCacheEpoch != cacheEpoch) {
                    return result;
                }
                CachedCertificateChain raced = cache.get(cacheKey);
                if (raced != null) {
                    Certificate[] replacement = raced.certificateCopy();
                    return replacement == null ? caList : replacement;
                }
                cache.put(cacheKey, completed);
            }
            return result;
        } catch (Throwable t) {
            return caList;
        } finally {
            if (keyId != null) Arrays.fill(keyId, (byte) 0);
            if (attestInspection != null) attestInspection.wipe();
            KeyboxActivation.unlockPublishedSnapshot();
        }
    }

    public static Certificate[] hackChildKeyCertificate(
            Certificate[] caList, int uid, boolean isAttestKey) {
        return hackChildKeyCertificate(caList, uid, isAttestKey, false, null, null);
    }

    public static Certificate[] hackChildKeyCertificate(
            Certificate[] caList, int uid, boolean isAttestKey, boolean leafOnlySafe) {
        return hackChildKeyCertificate(caList, uid, isAttestKey, leafOnlySafe, null, null);
    }

    public static Certificate[] hackChildKeyCertificate(
            Certificate[] caList, int uid, boolean isAttestKey, byte[] parentKeyId, byte[] childKeyId) {
        return hackChildKeyCertificate(caList, uid, isAttestKey, false, parentKeyId, childKeyId);
    }

    public static Certificate[] hackChildKeyCertificate(
            Certificate[] caList, int uid, boolean isAttestKey, boolean leafOnlySafe, byte[] parentKeyId, byte[] childKeyId) {
        if (caList == null || caList.length == 0 || caList[0] == null) {
            return caList;
        }
        KeyboxActivation.lockPublishedSnapshot();
        CertificateBackend.Inspection childInspection = null;
        try {
            State currentState = state;
            byte[] leafEncoded = caList[0].getEncoded();
            if (leafEncoded.length == 0 || leafEncoded.length > MAX_LEAF_CERTIFICATE_BYTES) {
                return caList;
            }
            CacheKey cacheKey = new CacheKey(leafEncoded);
            State.CertificateCache cache = currentState.certificateCache;
            Object cacheEpoch;
            CachedCertificateChain cached;
            synchronized (cache) {
                cached = cache.get(cacheKey);
                cacheEpoch = currentState.certificateCacheEpoch;
            }
            cached = validateAndTouchAttestKey(cache, cacheKey, cached);
            if (cached != null) {
                Certificate[] replacement = cached.certificateCopy();
                return replacement == null ? caList : replacement;
            }

            if (!Utils.hasAndroidAttestationExtension(caList[0])) return caList;

            childInspection = CertificateBackend.inspect(leafEncoded);
            if (childInspection == null) return caList;
            int attLevel = childInspection.getAttestationSecurityLevel();
            int kmLevel = childInspection.getKeymintSecurityLevel();
            boolean isTee = attLevel == CertificateBackend.SECURITY_LEVEL_TEE
                    && kmLevel == CertificateBackend.SECURITY_LEVEL_TEE;
            boolean isStrongbox =
                    (attLevel == CertificateBackend.SECURITY_LEVEL_TEE
                            && kmLevel == CertificateBackend.SECURITY_LEVEL_STRONGBOX)
                    || (attLevel == CertificateBackend.SECURITY_LEVEL_STRONGBOX
                            && kmLevel == CertificateBackend.SECURITY_LEVEL_STRONGBOX);
            boolean isTeeOrStrongbox = isTee || isStrongbox;
            if (!isTeeOrStrongbox) {
                synchronized (cache) {
                    if (state == currentState && currentState.certificateCacheEpoch == cacheEpoch) {
                        cache.putIfAbsent(cacheKey, CachedCertificateChain.passthrough());
                    }
                }
                return caList;
            }

            boolean needsCapturedPatchLevels = PolicyState.INSTANCE.isFeatureEnabled(
                    PolicyState.Feature.SECURITY_PATCH, uid);
            byte[] originalBootKey = usableBootDigest(childInspection.getOriginalBootKey());
            if (originalBootKey != null) {
                capturedHardwareBootKey = originalBootKey.clone();
            }
            byte[] originalBootHash = usableBootDigest(childInspection.getOriginalBootHash());
            if (originalBootHash != null) {
                capturedHardwareBootHash = originalBootHash.clone();
            }
            byte[] verifiedBootKey = selectVerifiedBootDigest(
                    UtilKt.getBootKey(),
                    originalBootKey != null ? originalBootKey : capturedHardwareBootKey,
                    UtilKt.getPersistentBootKey());
            byte[] verifiedBootHash = selectVerifiedBootDigest(
                    UtilKt.getBootHash(),
                    originalBootHash != null ? originalBootHash : capturedHardwareBootHash,
                    UtilKt.getPersistentBootHash());
            if (verifiedBootKey == null || verifiedBootHash == null) {
                return caList;
            }

            Config.AttestationPatchLevels patchLevels = needsCapturedPatchLevels
                    ? PolicyState.INSTANCE.resolveAttestationPatchLevels(
                            uid,
                            childInspection.getSystemPatch(),
                            childInspection.getVendorPatch(),
                            childInspection.getBootPatch())
                    : keepPatchLevels();

            Map<Integer, byte[]> idOverrides = presentIdOverrides(uid, childInspection.getPresentIdMask());
            byte[] moduleHash = childInspection.getSupportsModuleHash()
                    ? Config.INSTANCE.getModuleHash()
                    : null;

            if (parentKeyId == null || parentKeyId.length != 32) {
                return caList;
            }
            if (isAttestKey && (childKeyId == null || childKeyId.length != 32)) {
                return caList;
            }

            byte[] rewrittenDer = CertificateBackend.rewriteChildKey(
                    uid,
                    parentKeyId,
                    childKeyId,
                    leafEncoded,
                    isAttestKey,
                    patchDisposition(patchLevels.getSystem()), patchLevels.getSystem().getValue(),
                    patchDisposition(patchLevels.getVendor()), patchLevels.getVendor().getValue(),
                    patchDisposition(patchLevels.getBoot()), patchLevels.getBoot().getValue(),
                    idOverrides,
                    moduleHash,
                    verifiedBootKey,
                    verifiedBootHash);
            if (rewrittenDer == null || rewrittenDer.length == 0 || rewrittenDer.length > MAX_LEAF_CERTIFICATE_BYTES) {
                return caList;
            }

            Certificate rewrittenLeaf = new LazyX509Certificate(rewrittenDer, false);
            Certificate[] result = new Certificate[caList.length];
            result[0] = rewrittenLeaf;
            if (caList.length > 1) {
                System.arraycopy(caList, 1, result, 1, caList.length - 1);
            }
            byte[] encodedIssuerChain = null;
            if (caList.length > 1) {
                try {
                    encodedIssuerChain = Utils.encodeIssuerChain(caList);
                } catch (Throwable ignored) {
                }
            }
            CachedCertificateChain completed = new CachedCertificateChain(
                    result,
                    rewrittenDer,
                    encodedIssuerChain,
                    leafOnlySafe,
                    false,
                    isAttestKey ? uid : 0,
                    isAttestKey ? childKeyId : null
            );
            synchronized (cache) {
                if (state != currentState || currentState.certificateCacheEpoch != cacheEpoch) {
                    return result;
                }
                CachedCertificateChain raced = cache.get(cacheKey);
                if (raced != null) {
                    Certificate[] replacement = raced.certificateCopy();
                    return replacement == null ? caList : replacement;
                }
                cache.put(cacheKey, completed);
            }
            return result;
        } catch (Throwable t) {
            return caList;
        } finally {
            if (childInspection != null) childInspection.wipe();
            KeyboxActivation.unlockPublishedSnapshot();
        }
    }

    private static final Config.AttestationPatchLevels KEEP_PATCH_LEVELS =
            new Config.AttestationPatchLevels(
                    new Config.AttestationPatchComponent(Config.PatchDisposition.KEEP, 0),
                    new Config.AttestationPatchComponent(Config.PatchDisposition.KEEP, 0),
                    new Config.AttestationPatchComponent(Config.PatchDisposition.KEEP, 0));

    private static Config.AttestationPatchLevels keepPatchLevels() {
        return KEEP_PATCH_LEVELS;
    }

    private static Map<Integer, byte[]> presentIdOverrides(int uid, int mask) {
        if (mask == 0) return Collections.emptyMap();
        Map<Integer, byte[]> overrides = null;
        for (int index = 0; index < ATTESTATION_ID_TAGS.length; index++) {
            if ((mask & (1 << index)) == 0) continue;
            byte[] value = Config.INSTANCE.getAttestationId(ATTESTATION_ID_NAMES[index], uid);
            if (value != null) {
                if (overrides == null) overrides = new HashMap<>();
                overrides.put(ATTESTATION_ID_TAGS[index], value);
            }
        }
        return overrides == null ? Collections.emptyMap() : overrides;
    }

    private static int patchDisposition(Config.AttestationPatchComponent component) {
        return switch (component.getDisposition()) {
            case KEEP -> 0;
            case OMIT -> 1;
            case REPLACE -> 2;
        };
    }

    private static byte[] usableBootDigest(byte[] digest) {
        if (digest == null || digest.length != 32) return null;
        for (byte b : digest) {
            if (b != 0) return digest;
        }
        return null;
    }

    static byte[] selectVerifiedBootDigest(
            byte[] configured,
            byte[] captured,
            byte[] persistent
    ) {
        byte[] candidate = usableBootDigest(configured);
        if (candidate != null) return candidate;
        candidate = usableBootDigest(captured);
        if (candidate != null) return candidate;
        return usableBootDigest(persistent);
    }

    private static int signingWireAlgorithm(String signatureAlgorithm) {
        if ("SHA256withECDSA".equals(signatureAlgorithm)) return 1;
        if ("SHA256withRSA".equals(signatureAlgorithm)) return 2;
        return 0;
    }

    private static List<KeyBox> selectKeyboxPool(List<KeyBox> candidates, String preferredAlgorithm) {
        if (candidates == null || candidates.isEmpty()) return Collections.emptyList();
        if (preferredAlgorithm != null) {
            List<KeyBox> preferred = filterKeyboxesByAlgorithm(candidates, preferredAlgorithm);
            if (!preferred.isEmpty()) return preferred;
        }
        String fallbackAlgorithm = KeyProperties.KEY_ALGORITHM_EC.equals(preferredAlgorithm)
                ? KeyProperties.KEY_ALGORITHM_RSA : KeyProperties.KEY_ALGORITHM_EC;
        List<KeyBox> fallback = filterKeyboxesByAlgorithm(candidates, fallbackAlgorithm);
        if (!fallback.isEmpty()) return fallback;
        return filterKeyboxesByAlgorithm(candidates, KeyProperties.KEY_ALGORITHM_RSA);
    }

    private static String signatureAlgorithmForKeybox(KeyBox keybox) {
        String algorithm = normalizeAlgorithm(keybox.keyPair.getPrivate().getAlgorithm());
        if (KeyProperties.KEY_ALGORITHM_EC.equals(algorithm)) return "SHA256withECDSA";
        if (KeyProperties.KEY_ALGORITHM_RSA.equals(algorithm)) return "SHA256withRSA";
        return null;
    }

    private static String normalizeAlgorithm(String algorithm) {
        if (algorithm == null) return null;
        if (algorithm.equalsIgnoreCase("EC") || algorithm.equalsIgnoreCase("ECDSA")) {
            return KeyProperties.KEY_ALGORITHM_EC;
        }
        if (algorithm.equalsIgnoreCase("RSA")) {
            return KeyProperties.KEY_ALGORITHM_RSA;
        }
        return null;
    }

    private static List<KeyBox> filterKeyboxesByAlgorithm(List<KeyBox> candidates, String requiredAlgorithm) {
        if (candidates == null || candidates.isEmpty()) return Collections.emptyList();
        List<KeyBox> matches = new ArrayList<>();
        for (KeyBox candidate : candidates) {
            String alg = candidate.keyPair.getPublic().getAlgorithm();
            if (requiredAlgorithm.equals(alg) || requiredAlgorithm.equals(normalizeAlgorithm(alg))) {
                matches.add(candidate);
            }
        }
        return matches;
    }

    static List<KeyBox> filterKeyboxesBySecurityLevel(List<KeyBox> candidates, boolean strongBox) {
        if (candidates == null || candidates.isEmpty()) return Collections.emptyList();
        List<KeyBox> matches = new ArrayList<>();
        for (KeyBox candidate : candidates) {
            if (strongBox) {
                if (isStrongBoxKeybox(candidate)) {
                    matches.add(candidate);
                }
            } else {
                if (isTeeKeybox(candidate)) {
                    matches.add(candidate);
                }
            }
        }
        return matches;
    }

    public record KeyBox(KeyPair keyPair, List<Certificate> certificates, String filename) {
        public KeyBox {
            Objects.requireNonNull(keyPair, "keyPair");
            certificates = List.copyOf(Objects.requireNonNull(certificates, "certificates"));
            filename = Objects.requireNonNull(filename, "filename");
        }
    }
}
