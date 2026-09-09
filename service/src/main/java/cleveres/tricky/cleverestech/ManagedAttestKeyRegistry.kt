package cleveres.tricky.cleverestech

import androidx.annotation.VisibleForTesting
import java.util.Arrays
import java.util.LinkedHashMap

/**
 * Process-local knowledge of descriptor identities that have successfully entered the managed
 * synthetic ATTEST_KEY graph. This survives a Rust-only backend restart while the Java service is
 * still alive, which lets getKeyEntry distinguish a stale managed cache hit from an ordinary key.
 *
 * This is eligibility metadata only; presence in the live Rust graph is always revalidated with
 * touchAttestKey before a cached managed parent is reused.
 */
internal object ManagedAttestKeyRegistry {
    private const val KEY_ID_BYTES = 32
    private const val MAX_ENTRIES = 256

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

    private val entries =
        object : LinkedHashMap<Identity, Unit>(64, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Identity, Unit>?): Boolean =
                size > MAX_ENTRIES
        }

    @Synchronized
    fun remember(callingUid: Int, keyId: ByteArray?) {
        if (!isValid(callingUid, keyId)) return
        entries[Identity.stored(callingUid, requireNotNull(keyId))] = Unit
    }

    @Synchronized
    fun forget(callingUid: Int, keyId: ByteArray?) {
        if (!isValid(callingUid, keyId)) return
        entries.remove(Identity.lookup(callingUid, requireNotNull(keyId)))
    }

    @Synchronized
    fun isKnown(callingUid: Int, keyId: ByteArray?): Boolean {
        if (!isValid(callingUid, keyId)) return false
        return entries[Identity.lookup(callingUid, requireNotNull(keyId))] != null
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
    }
}
