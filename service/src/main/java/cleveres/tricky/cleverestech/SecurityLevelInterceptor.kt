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

        private class PreTransactContext(
            val isDefaultAttestationKey: Boolean,
            val isAttestKeyPurpose: Boolean,
            val generatedKeyId: ByteArray?,
            val parentKeyId: ByteArray?,
        )

        private val CURRENT_CONTEXT = ThreadLocal<PreTransactContext?>()
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
            val reqInfo = Utils.parseGenerateKeyRequest(data, callingUid)
            if (reqInfo != null) {
                CURRENT_CONTEXT.set(
                    PreTransactContext(
                        isDefaultAttestationKey = reqInfo.usesDefaultAttestationKey,
                        isAttestKeyPurpose = reqInfo.isAttestKeyPurpose,
                        generatedKeyId = reqInfo.generatedKeyId,
                        parentKeyId = reqInfo.parentKeyId,
                    ),
                )
                return Continue
            }
            val isDefault = Utils.usesDefaultAttestationKey(data)
            val isAttestKey = Utils.hasAttestKeyPurpose(data)
            CURRENT_CONTEXT.set(
                PreTransactContext(
                    isDefaultAttestationKey = isDefault,
                    isAttestKeyPurpose = isAttestKey,
                    generatedKeyId = null,
                    parentKeyId = null,
                ),
            )
            return Continue
        }
        CURRENT_CONTEXT.remove()
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
            CURRENT_CONTEXT.remove()
            return Skip
        }

        val context = CURRENT_CONTEXT.get() ?: run {
            val reqInfo = Utils.parseGenerateKeyRequest(data, callingUid)
            if (reqInfo != null) {
                PreTransactContext(
                    isDefaultAttestationKey = reqInfo.usesDefaultAttestationKey,
                    isAttestKeyPurpose = reqInfo.isAttestKeyPurpose,
                    generatedKeyId = reqInfo.generatedKeyId,
                    parentKeyId = reqInfo.parentKeyId,
                )
            } else {
                PreTransactContext(
                    isDefaultAttestationKey = Utils.usesDefaultAttestationKey(data),
                    isAttestKeyPurpose = Utils.hasAttestKeyPurpose(data),
                    generatedKeyId = null,
                    parentKeyId = null,
                )
            }
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
                    if (!context.isDefaultAttestationKey) {
                        val parentId = context.parentKeyId
                        if (parentId == null) {
                            CertHack.hackChildKeyCertificate(
                                originalLeafOnly,
                                callingUid,
                                context.isAttestKeyPurpose,
                                true,
                            )
                        } else {
                            CertHack.hackChildKeyCertificate(
                                originalLeafOnly,
                                callingUid,
                                context.isAttestKeyPurpose,
                                true,
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
                if (context.isAttestKeyPurpose) {
                    ManagedAttestKeyRegistry.remember(callingUid, context.generatedKeyId)
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
                val newChain = if (!context.isDefaultAttestationKey) null else Utils.encodeIssuerChain(rewritten)
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
                if (!context.isDefaultAttestationKey) {
                    val parentId = context.parentKeyId
                    if (parentId == null) {
                        CertHack.hackChildKeyCertificate(
                            originalLeafOnly,
                            callingUid,
                            context.isAttestKeyPurpose,
                            true,
                        )
                    } else {
                        CertHack.hackChildKeyCertificate(
                            originalLeafOnly,
                            callingUid,
                            context.isAttestKeyPurpose,
                            true,
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
            if (context.isAttestKeyPurpose) {
                ManagedAttestKeyRegistry.remember(callingUid, context.generatedKeyId)
            }

            if (!CertHack.applyCachedCertificateChain(metadata)) {
                if (!context.isDefaultAttestationKey) {
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
        } finally {
            CURRENT_CONTEXT.remove()
        }
    }
}
