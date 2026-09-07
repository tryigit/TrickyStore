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
        if (
            code == generateKeyTransaction &&
            CertHack.canHack() &&
            Config.needHack(callingUid)
        ) {
            return Continue
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

        return try {
            reply.readException()
            
            // Fast parcel check: parse just the byte offsets without allocating the full KeyMetadata
            val parsed = Utils.parseKeyMetadataParcel(reply) ?: return Skip

            // Wrap in LazyX509Certificate to check for Android attestation extension without full parsing
            val originalLeaf = cleveres.tricky.cleverestech.keystore.LazyX509Certificate(parsed.leafEncoded)
            if (!originalLeaf.hasAttestationExtension()) {
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

            val newLeaf = rewritten[0].encoded
            val newChain = Utils.encodeIssuerChain(rewritten)
            
            Utils.rewriteKeyMetadataParcel(reply, parsed, newLeaf, newChain)
            
            OverrideReply(0, reply)
        } catch (_: Throwable) {
            Skip
        }
    }
}
