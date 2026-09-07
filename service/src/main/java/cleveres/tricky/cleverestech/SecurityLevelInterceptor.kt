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
 */
class SecurityLevelInterceptor : BinderInterceptor() {
    companion object {
        private val generateKeyTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "generateKey")

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
        if (code == generateKeyTransaction) {
            // Caller-selected AttestKeys (!usesDefaultAttestationKey) must execute natively on hardware KeyMint.
            if (!Utils.usesDefaultAttestationKey(data)) {
                return Continue
            }

            if (CertHack.canHack() && Config.needHack(callingUid)) {
                return Continue
            }
        }

        return Skip
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

        // Caller-selected AttestKeys (!usesDefaultAttestationKey) must never be rewritten with a
        // generic keybox chain. Preserving the genuine hardware-signed child certificate preserves
        // its cryptographic parent-child relationship untouched.
        if (!Utils.usesDefaultAttestationKey(data)) {
            return Skip
        }

        return try {
            reply.readException()
            val metadata = reply.readTypedObject(KeyMetadata.CREATOR) ?: return Skip
            val isFullChain = Utils.isCertificateChainRewriteCandidate(metadata)
            val isLeafOnly = Utils.hasRewritableLeafCertificate(metadata)
            if (!isFullChain && !isLeafOnly) {
                return Skip
            }

            // Parse only the leaf first. A normal asymmetric key without an Android attestation
            // challenge still has a self-signed X.509 leaf, but it must never cross the Rust
            // certificate backend boundary. Preserving this zero-backend fast path avoids
            // a measurable non-attested-only UDS/parser cost.
            val originalLeaf = Utils.getLeafCertificate(metadata)
            if (
                originalLeaf == null ||
                !Utils.hasAndroidAttestationExtension(originalLeaf)
            ) {
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
            )
            if (rewritten === originalLeafOnly) {
                return Skip
            }

            if (!CertHack.applyCachedCertificateChain(metadata)) {
                Utils.putCertificateChain(metadata, rewritten)
            }
            val replacement = Parcel.obtain()
            try {
                replacement.writeNoException()
                replacement.writeTypedObject(metadata, 0)
                OverrideReply(0, replacement)
            } catch (t: Throwable) {
                replacement.recycle()
                throw t
            }
        } catch (error: Throwable) {
            if (error.javaClass.simpleName != "ServiceSpecificException") {
                Logger.e("Could not rewrite a generated attestation chain: ${error.javaClass.simpleName}")
            }
            Skip
        }
    }
}
