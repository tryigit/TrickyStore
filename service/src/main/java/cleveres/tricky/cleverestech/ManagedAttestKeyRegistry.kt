package cleveres.tricky.cleverestech

import androidx.annotation.VisibleForTesting
import java.util.Arrays
import java.util.HashSet

/**
 * Process-local knowledge of descriptor identities that have successfully entered the managed
 * synthetic ATTEST_KEY graph. This survives a Rust-only backend restart while the Java service is
 * still alive, which lets getKeyEntry distinguish a stale managed cache hit from an ordinary key.
 *
 * This is eligibility metadata only; presence in the live Rust graph is always revalidated with
 * touchAttestKey before a cached managed parent is reused. The registry must never produce a false
 * negative while the process-local certificate cache may still contain a synthetic parent. Once the
 * bounded exact set fills, it therefore switches to conservative mode: valid descriptors are treated
 * as potentially managed. False positives only add a bounded graph touch; false negatives could
 * incorrectly reuse stale synthetic cache state after a Rust-only restart.
 */
internal object ManagedAttestKeyRegistry {
    private const val KEY_ID_BYTES = 32
    private const val MAX_EXACT_ENTRIES = 256

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

    private val entries = HashSet<Identity>(MAX_EXACT_ENTRIES)
    private var conservativeMode = false

    @Synchronized
    fun remember(callingUid: Int, keyId: ByteArray?) {
        if (!isValid(callingUid, keyId) || conservativeMode) return
        val nonNullKeyId = requireNotNull(keyId)
        val lookup = Identity.lookup(callingUid, nonNullKeyId)
        if (entries.contains(lookup)) return
        if (entries.size >= MAX_EXACT_ENTRIES) {
            entries.clear()
            conservativeMode = true
            return
        }
        entries.add(Identity.stored(callingUid, nonNullKeyId))
    }

    @Synchronized
    fun isKnown(callingUid: Int, keyId: ByteArray?): Boolean {
        if (!isValid(callingUid, keyId)) return false
        return conservativeMode || entries.contains(Identity.lookup(callingUid, requireNotNull(keyId)))
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
        conservativeMode = false
    }
}
