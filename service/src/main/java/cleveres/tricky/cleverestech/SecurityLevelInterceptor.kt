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

    // PRE and POST are separate Binder callbacks and are not thread-affine. The explicit ATTEST_KEY
    // parent descriptor is request-only state, so POST must receive the original bounded request and
    // parse it again instead of relying on a ThreadLocal populated by PRE.
    override val requiresPostRequestPayload: Boolean = true

    override fun onPreTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
    ): Result {
        if (code == generateKeyTransaction) {
            if (!CertHack.canHack() || !Config.needHack(callingUid)) {
                return Skip
            }

            // POST retains and reparses the bounded request. Classification is deliberately deferred
            // to POST so PRE remains compatible with platform Binder parcels and JVM contract mocks.
            return Continue
        }
        return Skip
    }

    private fun rewriteChildWithParentRecovery(
        original: Array<Certificate>,
        callingUid: Int,
        isAttestKey: Boolean,
        parentKeyId: ByteArray,
        childKeyId: ByteArray?,
    ): Array<Certificate> {
        KeyboxActivation.lockPublishedSnapshot()
        return try {
            val first =
                CertHack.hackChildKeyCertificate(
                    original,
                    callingUid,
                    isAttestKey,
                    true,
                    parentKeyId,
                    childKeyId,
                )
            if (first !== original || !ManagedAttestKeyRegistry.isKnown(callingUid, parentKeyId)) {
                return first
            }

            val presence =
                runCatching { CertificateBackend.touchAttestKey(callingUid, parentKeyId) }
                    .getOrElse { return first }
            if (presence != CertificateBackend.AttestKeyTouchResult.ABSENT) return first
            if (!ManagedAttestKeyRehydrator.restore(callingUid, parentKeyId)) return first

            CertHack.hackChildKeyCertificate(
                original,
                callingUid,
                isAttestKey,
                true,
                parentKeyId,
                childKeyId,
            )
        } finally {
            KeyboxActivation.unlockPublishedSnapshot()
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

        // POST may run on a different Binder worker than PRE. Re-parse the retained request and
        // reject any non-empty payload that cannot be classified authoritatively.
        val parsedContext = Utils.parseGenerateKeyRequest(data, callingUid)
        val context = if (parsedContext != null) {
            parsedContext
        } else if (data.dataSize() == 0 || data.dataPosition() != 0) {
            // Compatibility path for JVM Parcel mocks only. Native POST parcels are copied into a
            // fresh Parcel at position zero, so malformed non-empty native payloads fail closed.
            Utils.GenerateKeyRequestInfo(
                Utils.usesDefaultAttestationKey(data),
                Utils.hasAttestKeyPurpose(data),
                null,
                null,
            )
        } else {
            // Fail closed to the genuine chain. This path stays log-free on purpose:
            // the generateKey reply path must not allocate or log (timing side-channel).
            return Skip
        }

        return try {
            reply.readException()

            // Fast parcel check: parse just the byte offsets without allocating the full KeyMetadata.
            val parsed = Utils.parseKeyMetadataParcel(reply)
            if (parsed != null) {
                val originalLeaf = cleveres.tricky.cleverestech.keystore.LazyX509Certificate(parsed.leafEncoded, false)
                if (!Utils.hasAndroidAttestationExtension(originalLeaf)) {
                    return Skip
                }

                val originalLeafOnly = arrayOf<Certificate>(originalLeaf)
                val rewritten =
                    if (!context.usesDefaultAttestationKey) {
                        val parentId = context.parentKeyId
                        // The child helper serves its leaf cache before validating the
                        // parent descriptor, so a missing descriptor must fail closed
                        // here instead of reaching the helper without its required parent.
                        if (context.isAttestKeyPurpose && parentId == null) {
                            return Skip
                        }
                        if (parentId == null) {
                            CertHack.hackChildKeyCertificate(
                                originalLeafOnly,
                                callingUid,
                                context.isAttestKeyPurpose,
                                true,
                            )
                        } else {
                            rewriteChildWithParentRecovery(
                                originalLeafOnly,
                                callingUid,
                                context.isAttestKeyPurpose,
                                parentId,
                                context.generatedKeyId,
                            )
                        }
                    } else if (context.isAttestKeyPurpose) {
                        val keyId = context.generatedKeyId
                        if (keyId == null) {
                            CertHack.hackAttestKeyCertificateChain(
                                originalLeafOnly,
                                callingUid,
                                true,
                            )
                        } else {
                            CertHack.hackAttestKeyCertificateChain(
                                originalLeafOnly,
                                callingUid,
                                true,
                                keyId,
                            )
                        }
                    } else {
                        CertHack.hackCertificateChain(
                            originalLeafOnly,
                            callingUid,
                            true,
                        )
                    }
                if (rewritten === originalLeafOnly) {
                    return Skip
                }
                if (context.isAttestKeyPurpose || context.parentKeyId != null) {
                    ManagedAttestKeyRegistry.remember(
                        callingUid,
                        context.generatedKeyId,
                        context.parentKeyId,
                        parsed.leafEncoded,
                        context.isAttestKeyPurpose,
                    )
                }

                // hackCertificateChain publishes the completed rewrite bytes in its epoch-protected
                // cache before returning. Reuse those exact bytes here instead of calling getEncoded()
                // on the rewritten leaf and DER-encoding the issuer chain a second time. A state/epoch
                // race can legitimately prevent publication, so retain the allocation-heavy fallback.
                if (
                    CertHack.applyCachedCertificateChain(reply, parsed) ==
                        CertHack.CachedParcelAction.REWRITTEN
                ) {
                    return OverrideReply(code = 0, reply = reply)
                }

                val newLeaf = rewritten[0].encoded
                val newChain = if (!context.usesDefaultAttestationKey) null else Utils.encodeIssuerChain(rewritten)
                if (!Utils.rewriteKeyMetadataParcel(reply, parsed, newLeaf, newChain)) {
                    return Skip
                }
                return OverrideReply(code = 0, reply = reply)
            }

            // Contract-compliant fallback for non-standard parcels or test mocks.
            val metadata = reply.readTypedObject(KeyMetadata.CREATOR) ?: return Skip
            if (!Utils.isCertificateChainRewriteCandidate(metadata) && !Utils.hasRewritableLeafCertificate(metadata)) {
                return Skip
            }

            val originalLeaf = Utils.getLeafCertificate(metadata)
            if (
                originalLeaf == null ||
                !Utils.hasAndroidAttestationExtension(originalLeaf)
            ) {
                return Skip
            }

            val originalLeafOnly = arrayOf<Certificate>(originalLeaf)
            val rewritten =
                if (!context.usesDefaultAttestationKey) {
                    val parentId = context.parentKeyId
                    // The child helper serves its leaf cache before validating the
                    // parent descriptor, so a missing descriptor must fail closed
                    // here instead of reaching the helper without its required parent.
                    if (context.isAttestKeyPurpose && parentId == null) {
                        return Skip
                    }
                    if (parentId == null) {
                        CertHack.hackChildKeyCertificate(
                            originalLeafOnly,
                            callingUid,
                            context.isAttestKeyPurpose,
                            true,
                        )
                    } else {
                        rewriteChildWithParentRecovery(
                            originalLeafOnly,
                            callingUid,
                            context.isAttestKeyPurpose,
                            parentId,
                            context.generatedKeyId,
                        )
                    }
                } else if (context.isAttestKeyPurpose) {
                    val keyId = context.generatedKeyId
                    if (keyId == null) {
                        CertHack.hackAttestKeyCertificateChain(
                            originalLeafOnly,
                            callingUid,
                            true,
                        )
                    } else {
                        CertHack.hackAttestKeyCertificateChain(
                            originalLeafOnly,
                            callingUid,
                            true,
                            keyId,
                        )
                    }
                } else {
                    CertHack.hackCertificateChain(
                        originalLeafOnly,
                        callingUid,
                        true,
                    )
                }
            if (rewritten === originalLeafOnly) {
                return Skip
            }
            if (context.isAttestKeyPurpose || context.parentKeyId != null) {
                ManagedAttestKeyRegistry.remember(
                    callingUid,
                    context.generatedKeyId,
                    context.parentKeyId,
                    metadata.certificate,
                    context.isAttestKeyPurpose,
                )
            }

            if (!CertHack.applyCachedCertificateChain(metadata)) {
                if (!context.usesDefaultAttestationKey) {
                    metadata.certificate = rewritten[0].encoded
                    metadata.certificateChain = null
                } else {
                    Utils.putCertificateChain(metadata, rewritten)
                }
            }
            reply.setDataSize(0)
            reply.setDataPosition(0)
            reply.writeNoException()
            reply.writeTypedObject(metadata, 0)
            OverrideReply(0, reply)
        } catch (_: Throwable) {
            Skip
        }
    }
}
