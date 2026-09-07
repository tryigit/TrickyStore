package cleveres.tricky.cleverestech

import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.IKeystoreSecurityLevel
import android.system.keystore2.KeyMetadata
import cleveres.tricky.cleverestech.binder.BinderInterceptor
import cleveres.tricky.cleverestech.keystore.CertHack
import cleveres.tricky.cleverestech.keystore.Utils
import java.security.cert.Certificate

/**
 * Rewrites only the certificate chain returned by a successful, genuine TEE
 * or StrongBox KeyMint key generation. The private key and every later cryptographic
 * operation remain owned by the platform security level.
 *
 * This interceptor is registered on both the TEE and StrongBox child binders.
 * Targeted generateKey and getKeyEntry calls use the same certificate-compatibility
 * path. No synthetic timing delay is added here; certificate caching in
 * CertHack handles repeated reads without parking Keystore threads.
 */
class SecurityLevelInterceptor : BinderInterceptor() {
    companion object {
        private val generateKeyTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "generateKey")

        /** KeyMint Tag.ATTESTATION_CHALLENGE: the tag value we scan for and strip. */
        private const val TAG_ATTESTATION_CHALLENGE = -1879047484

        /** KeyMint Tag.INVALID: overwrites the challenge tag so hardware ignores it. */
        private const val TAG_INVALID = 0

        val INTERCEPTED_CODES = validTransactCodes(generateKeyTransaction)
    }

    override fun onPreTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): Result {
        if (
            code == generateKeyTransaction &&
            CertHack.canHack() &&
            Config.needHack(callingUid)
        ) {
            if (!Utils.usesDefaultAttestationKey(data)) {
                // Explicit AttestKey: strip the attestation challenge so hardware generates a
                // plain key without an attestation extension. This avoids RootOfTrust divergence
                // without crashing the app or breaking cryptographic signatures.
                return stripAttestationChallenge(data)
            }
            return Continue
        }

        return Skip
    }

    /**
     * Copies the request parcel and scans integer-by-integer for [TAG_ATTESTATION_CHALLENGE].
     * When found, overwrites it with [TAG_INVALID] so the hardware treats the parameter as
     * absent. This is immune to OEM-specific Parcel alignment because it does not attempt to
     * parse the full KeyParameter[] AIDL structure.
     */
    private fun stripAttestationChallenge(data: Parcel): Result {
        val size = data.dataSize()
        if (size < Int.SIZE_BYTES) return Continue

        val mutated = Parcel.obtain()
        try {
            mutated.appendFrom(data, 0, size)
            mutated.setDataPosition(0)

            // Scan every 4-byte-aligned integer for the challenge tag.
            val limit = size - Int.SIZE_BYTES
            var pos = 0
            while (pos <= limit) {
                mutated.setDataPosition(pos)
                if (mutated.readInt() == TAG_ATTESTATION_CHALLENGE) {
                    mutated.setDataPosition(pos)
                    mutated.writeInt(TAG_INVALID)
                    break
                }
                pos += Int.SIZE_BYTES
            }

            mutated.setDataPosition(0)
            return OverrideData(mutated)
        } catch (error: Throwable) {
            mutated.recycle()
            Logger.e("Failed to strip attestation challenge: ${error.javaClass.simpleName}")
            return Continue
        }
    }

    override fun onPostTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
        reply: Parcel?,
        resultCode: Int,
    ): Result {
        // The native hook only sends POST_TRANSACT after PRE_TRANSACT returned Continue.
        // Target scope was therefore already resolved above; do not repeat Config.needHack()
        // or CertHack.canHack() on the latency-sensitive generateKey reply path.
        if (
            code != generateKeyTransaction ||
            reply == null ||
            resultCode != 0
        ) {
            return Skip
        }

        val replacement = Parcel.obtain()
        return try {
            reply.readException()
            val metadata = reply.readTypedObject(KeyMetadata.CREATOR)
            if (metadata == null) {
                replacement.recycle()
                return Skip
            }
            val isFullChain = Utils.isCertificateChainRewriteCandidate(metadata)
            val isLeafOnly = Utils.hasRewritableLeafCertificate(metadata)
            if (!isFullChain && !isLeafOnly) {
                replacement.recycle()
                return Skip
            }

            // Parse only the leaf first. A normal asymmetric key without an Android attestation
            // challenge still has a self-signed X.509 leaf, but it must never cross the Rust
            // certificate backend boundary. 2.5.8 rejected that case locally; preserving the same
            // zero-backend fast path avoids a measurable non-attested-only UDS/parser cost.
            val originalLeaf = Utils.getLeafCertificate(metadata)
            if (
                originalLeaf == null ||
                !Utils.hasAndroidAttestationExtension(originalLeaf)
            ) {
                replacement.recycle()
                return Skip
            }

            // A successful TEE or StrongBox attestation rewrite discards Android's genuine issuer chain and
            // replaces it with the selected keybox chain. Parsing every genuine issuer first
            // therefore adds work only to attested generateKey calls. Keep the hot path leaf-only
            // until CertHack confirms that a replacement can actually be produced.
            val originalLeafOnly = arrayOf<Certificate>(originalLeaf)
            val rewritten = CertHack.hackCertificateChain(
                originalLeafOnly,
                callingUid,
                true,
                false,
            )
            if (rewritten === originalLeafOnly) {
                replacement.recycle()
                return Skip
            }

            Utils.putCertificateChain(metadata, rewritten)
            replacement.writeNoException()
            replacement.writeTypedObject(metadata, 0)
            OverrideReply(0, replacement)
        } catch (error: Throwable) {
            replacement.recycle()
            if (error.javaClass.simpleName != "ServiceSpecificException") {
                Logger.e("Could not rewrite a generated attestation chain: ${error.javaClass.simpleName}")
            }
            Skip
        }
    }
}
