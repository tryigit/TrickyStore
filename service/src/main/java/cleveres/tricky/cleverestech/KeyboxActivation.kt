package cleveres.tricky.cleverestech

import cleveres.tricky.cleverestech.keystore.CertHack
import java.util.concurrent.locks.ReentrantLock

/** Atomic process-wide publication boundary between Rust secret keys and managed selection state. */
internal object KeyboxActivation {
    internal class RefreshTicket internal constructor(val generation: Long)

    internal enum class PublicationResult {
        COMMITTED,
        SUPERSEDED,
        FAILED,
    }

    private val refreshLock = ReentrantLock()
    private val publicationLock = ReentrantLock()
    private var refreshGeneration = 0L

    @Volatile
    private var committedIdentity: NativeBackend.BackendIdentity? = null

    /**
     * Serializes the complete scan -> parse -> verify -> commit -> publish lifecycle. Besides
     * preventing stale writers, this keeps one refresh from evicting another refresh's transient
     * Rust key registrations before the winning active-set commit.
     *
     * A fresh certificate rewrite owns [publicationLock]. Backend recovery can re-enter this
     * coordinator from that rewrite. Normal refreshes acquire refresh -> publication, so recovery
     * must never block in the opposite publication -> refresh order. If another refresh already
     * owns [refreshLock], fail this exceptional recovery attempt instead; the in-flight refresh or
     * a subsequent retry can rebuild backend state without creating an AB-BA deadlock.
     */
    fun <T> coordinateRefresh(block: () -> T): T {
        val acquired =
            if (publicationLock.isHeldByCurrentThread) {
                refreshLock.tryLock()
            } else {
                refreshLock.lock()
                true
            }
        check(acquired) { "Keybox refresh is already active during publication recovery" }
        return try {
            block()
        } finally {
            refreshLock.unlock()
        }
    }

    /**
     * Starts a new logical refresh. Generation assignment shares the publication mutex so backend
     * invalidation cannot become newer halfway through another refresh's commit boundary.
     */
    fun beginRefresh(): RefreshTicket {
        publicationLock.lock()
        return try {
            refreshGeneration = Math.incrementExact(refreshGeneration)
            RefreshTicket(refreshGeneration)
        } finally {
            publicationLock.unlock()
        }
    }

    /**
     * Commits the Rust active set and publishes the matching managed snapshot as one reader-visible
     * transition. Fresh certificate rewrites hold this same reentrant mutex while selecting and
     * consuming an opaque backend key, so they can observe either the old pair or the new pair but
     * never the Rust-new/managed-old gap. Reentrancy is intentional: an epoch recovery triggered by
     * a fresh rewrite can rebuild publication on the same thread when the refresh coordinator is
     * free, without a read-to-write lock upgrade.
     */
    fun commitAndPublish(
        ticket: RefreshTicket,
        keyboxes: List<CertHack.KeyBox>,
    ): PublicationResult {
        publicationLock.lock()
        return try {
            if (ticket.generation != refreshGeneration) return PublicationResult.SUPERSEDED
            if (!KeyboxLoader.commitActive(keyboxes)) {
                Logger.e("Refusing to publish keyboxes because the Rust active-set commit failed")
                return PublicationResult.FAILED
            }

            // Synthetic attest-key signers are derived from the active backend secret set. Once
            // that set is committed, no signer prepared under the previous set may survive into the
            // newly published Java snapshot. clearCertificateCache() is reentrant on this same
            // publication lock; a transport failure marks the graph unhealthy so child rewrites
            // fail closed until the backend store can be authoritatively reset.
            if (!CertHack.clearCertificateCache()) {
                Logger.w("Active keybox set changed while the attest-key graph could not be reset; graph remains fail-closed")
            }
            CertHack.setKeyboxes(keyboxes)
            committedIdentity = NativeBackend.currentBackendIdentity()
            PublicationResult.COMMITTED
        } finally {
            publicationLock.unlock()
        }
    }

    /** Compatibility entry point for recovery/bootstrap callers that own their own error policy. */
    fun commitAndPublish(keyboxes: List<CertHack.KeyBox>): Boolean =
        coordinateRefresh {
            val ticket = beginRefresh()
            commitAndPublish(ticket, keyboxes) == PublicationResult.COMMITTED
        }

    /**
     * Java-facing guard for certificate rewrites and cache/store lifecycle mutations.
     * Serializes backend key registration, child key rewriting, and certificate cache clears.
     */
    @JvmStatic
    fun lockPublishedSnapshot() {
        publicationLock.lock()
    }

    @JvmStatic
    fun unlockPublishedSnapshot() {
        publicationLock.unlock()
    }

    fun invalidateBackendInstance() {
        publicationLock.lock()
        try {
            refreshGeneration = Math.incrementExact(refreshGeneration)
            committedIdentity = null
            CertHack.clearCertificateCache()
        } finally {
            publicationLock.unlock()
        }
    }

    fun isCommittedForCurrentInstance(): Boolean {
        val committed = committedIdentity ?: return false
        return NativeBackend.isCurrentBackendIdentity(committed)
    }

    @androidx.annotation.VisibleForTesting
    internal fun resetForTesting() {
        publicationLock.lock()
        try {
            refreshGeneration = 0L
            committedIdentity = null
        } finally {
            publicationLock.unlock()
        }
    }
}
