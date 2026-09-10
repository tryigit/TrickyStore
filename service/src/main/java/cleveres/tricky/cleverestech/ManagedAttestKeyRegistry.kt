package cleveres.tricky.cleverestech

import androidx.annotation.VisibleForTesting
import java.util.Arrays
import java.util.LinkedHashMap

/**
 * Process-local knowledge of descriptor identities that have successfully entered the managed
 * synthetic ATTEST_KEY graph. This survives a Rust-only backend restart while the Java service is
 * still alive, which lets getKeyEntry distinguish a stale managed cache hit from an ordinary key.
 *
 * This is bounded eligibility metadata, not authority: presence in the live Rust graph is always
 * revalidated with touchAttestKey before a cached managed parent is reused. A bounded copy of the
 * original genuine leaf and parent identity is retained when available so a nested managed graph can
 * be reconstructed parent-first after a Rust-only restart. The registry must never create a false
 * negative while Java may still hold a synthetic cache entry. If the exact identity bound is
 * exhausted, it therefore switches to conservative mode and treats valid descriptors as potentially
 * managed so authoritative KeyMetadata is re-read before cache reuse. Unsupported RSA/non-P256
 * parents remain fail-closed passthrough in the certificate rewrite path.
 */
internal object ManagedAttestKeyRegistry {
    private const val KEY_ID_BYTES = 32
    private const val MAX_ENTRIES = 256
    private const val MAX_LEAF_BYTES = 64 * 1024
    private const val MAX_PROOF_BYTES = 4 * 1024 * 1024
    private const val MAX_ANCESTRY_DEPTH = 64

    internal data class RehydrationEntry(
        val keyId: ByteArray,
        val parentKeyId: ByteArray?,
        val genuineLeafDer: ByteArray,
    )

    private class Identity private constructor(
        val uid: Int,
        val keyId: ByteArray,
        private val cachedHashCode: Int,
    ) {
        override fun equals(other: Any?): Boolean =
            other is Identity && uid == other.uid && Arrays.equals(keyId, other.keyId)

        override fun hashCode(): Int = cachedHashCode

        companion object {
            fun stored(uid: Int, keyId: ByteArray): Identity =
                Identity(uid, keyId.clone(), 31 * uid + Arrays.hashCode(keyId))

            fun lookup(uid: Int, keyId: ByteArray): Identity =
                Identity(uid, keyId, 31 * uid + Arrays.hashCode(keyId))
        }
    }

    private class Entry(
        parentKeyId: ByteArray?,
        genuineLeafDer: ByteArray?,
        val isAttestKey: Boolean,
    ) {
        val parentKeyId = parentKeyId?.clone()
        var genuineLeafDer = genuineLeafDer?.clone()

        fun proofBytes(): Int = genuineLeafDer?.size ?: 0
    }

    private val entries = LinkedHashMap<Identity, Entry>(64, 0.75f, true)
    private var retainedProofBytes = 0
    private var conservativeMode = false

    @Synchronized
    fun remember(callingUid: Int, keyId: ByteArray?) {
        remember(callingUid, keyId, null, null, true)
    }

    @JvmOverloads
    @Synchronized
    fun remember(
        callingUid: Int,
        keyId: ByteArray?,
        parentKeyId: ByteArray?,
        genuineLeafDer: ByteArray?,
        isAttestKey: Boolean = true,
    ) {
        if (!isValid(callingUid, keyId)) return
        if (parentKeyId != null && !isValid(callingUid, parentKeyId)) return
        if (parentKeyId != null && Arrays.equals(keyId, parentKeyId)) return
        val effectiveLeafDer = if (isAttestKey) genuineLeafDer else null
        if (effectiveLeafDer != null && (effectiveLeafDer.isEmpty() || effectiveLeafDer.size > MAX_LEAF_BYTES)) return

        val nonNullKeyId = requireNotNull(keyId)
        val lookup = Identity.lookup(callingUid, nonNullKeyId)
        val old = entries.remove(lookup)
        if (old == null && entries.size >= MAX_ENTRIES) {
            conservativeMode = true
            return
        }
        if (old != null) retainedProofBytes -= old.proofBytes()

        val stored = Entry(parentKeyId, effectiveLeafDer ?: (if (isAttestKey) old?.genuineLeafDer else null), isAttestKey)
        entries[Identity.stored(callingUid, nonNullKeyId)] = stored
        retainedProofBytes += stored.proofBytes()
        trimProofBytesLocked()
    }

    @Synchronized
    fun isKnown(callingUid: Int, keyId: ByteArray?): Boolean {
        if (!isValid(callingUid, keyId)) return false
        return conservativeMode || entries[Identity.lookup(callingUid, requireNotNull(keyId))] != null
    }

    @Synchronized
    fun isAttestKey(callingUid: Int, keyId: ByteArray?): Boolean {
        if (!isValid(callingUid, keyId)) return false
        val entry = entries[Identity.lookup(callingUid, requireNotNull(keyId))] ?: return false
        return entry.isAttestKey
    }

    @Synchronized
    fun getParentKeyId(callingUid: Int, keyId: ByteArray?): ByteArray? {
        if (!isValid(callingUid, keyId)) return null
        if (conservativeMode) return null
        return entries[Identity.lookup(callingUid, requireNotNull(keyId))]?.parentKeyId?.clone()
    }

    @Synchronized
    fun rehydrationPath(callingUid: Int, keyId: ByteArray?): List<RehydrationEntry>? {
        if (!isValid(callingUid, keyId)) return null
        var current = requireNotNull(keyId).clone()
        val seen = HashSet<Identity>()
        val reversed = ArrayList<RehydrationEntry>()

        while (true) {
            if (reversed.size >= MAX_ANCESTRY_DEPTH) return null
            val lookup = Identity.lookup(callingUid, current)
            if (!seen.add(Identity.stored(callingUid, current))) return null
            val entry = entries[lookup] ?: return null
            if (!entry.isAttestKey) return null
            val leaf = entry.genuineLeafDer ?: return null
            reversed.add(
                RehydrationEntry(
                    keyId = current.clone(),
                    parentKeyId = entry.parentKeyId?.clone(),
                    genuineLeafDer = leaf.clone(),
                ),
            )
            val parent = entry.parentKeyId ?: break
            current = parent.clone()
        }

        reversed.reverse()
        return reversed
    }

    private fun trimProofBytesLocked() {
        if (retainedProofBytes <= MAX_PROOF_BYTES) return
        for (entry in entries.values) {
            if (retainedProofBytes <= MAX_PROOF_BYTES) break
            val leaf = entry.genuineLeafDer ?: continue
            retainedProofBytes -= leaf.size
            entry.genuineLeafDer = null
        }
        if (retainedProofBytes < 0) retainedProofBytes = 0
    }

    private fun isValid(callingUid: Int, keyId: ByteArray?): Boolean =
        callingUid >= 0 &&
            keyId != null &&
            keyId.size == KEY_ID_BYTES &&
            keyId.any { it != 0.toByte() }

    @VisibleForTesting
    @Synchronized
    internal fun resetForTesting() {
        entries.clear()
        retainedProofBytes = 0
        conservativeMode = false
    }
}
