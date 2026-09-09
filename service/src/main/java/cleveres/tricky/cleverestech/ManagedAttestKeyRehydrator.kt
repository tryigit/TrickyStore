package cleveres.tricky.cleverestech

import cleveres.tricky.cleverestech.keystore.CertHack
import cleveres.tricky.cleverestech.keystore.LazyX509Certificate
import java.security.cert.Certificate

/** Rebuilds a previously managed attest-key ancestry after a Rust-only backend restart. */
internal object ManagedAttestKeyRehydrator {
    fun restore(
        callingUid: Int,
        keyId: ByteArray,
    ): Boolean {
        KeyboxActivation.lockPublishedSnapshot()
        return try {
            restoreLocked(callingUid, keyId)
        } finally {
            KeyboxActivation.unlockPublishedSnapshot()
        }
    }

    private fun restoreLocked(
        callingUid: Int,
        keyId: ByteArray,
    ): Boolean {
        val path = ManagedAttestKeyRegistry.rehydrationPath(callingUid, keyId) ?: return false
        if (path.isEmpty()) return false

        // restore() is entered only after the requested signer was authoritatively ABSENT. Rebuild
        // from one clean graph instead of trying to preserve a partially live ancestry: a stale
        // Java child cache can otherwise discover its missing Rust entry, clear the graph inside
        // CertHack validation, and revoke an already-checked parent halfway through reconstruction.
        // The publication lock above makes this clear -> parent-first rebuild atomic with respect to
        // certificate generation, cache eviction and active-keybox publication.
        if (!CertHack.clearCertificateCache()) return false

        for (entry in path) {
            val originalLeaf = LazyX509Certificate(entry.genuineLeafDer, false)
            val original = arrayOf<Certificate>(originalLeaf)
            val rewritten =
                if (entry.parentKeyId == null) {
                    CertHack.hackAttestKeyCertificateChain(
                        original,
                        callingUid,
                        false,
                        entry.keyId,
                    )
                } else {
                    CertHack.hackChildKeyCertificate(
                        original,
                        callingUid,
                        true,
                        true,
                        entry.parentKeyId,
                        entry.keyId,
                    )
                }
            if (rewritten === original) return false

            val confirmed =
                runCatching { CertificateBackend.touchAttestKey(callingUid, entry.keyId) }
                    .getOrElse { return false }
            if (confirmed != CertificateBackend.AttestKeyTouchResult.PRESENT) return false
        }
        return true
    }
}
