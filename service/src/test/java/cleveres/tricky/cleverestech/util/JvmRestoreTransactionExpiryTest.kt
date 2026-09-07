package cleveres.tricky.cleverestech.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.IOException

class JvmRestoreTransactionExpiryTest {
    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun expiredTransactionsCannotPermanentlyExhaustRestoreCapacity() {
        var nowNanos = 0L
        val backend =
            JvmSecureRestoreFileOperations(
                nowNanos = { nowNanos },
                enableExpiryJanitor = false,
            )
        val configDir = tempFolder.newFolder("config")
        val activeTokens =
            (1..4).map { value ->
                value.toString(16).padStart(32, '0')
            }

        activeTokens.forEach { token ->
            backend.begin(configDir, token, 0L)
        }
        assertEquals(RESTORE_TTL_NANOS, backend.pendingExpiryDelayNanosForTesting())

        val replacementToken = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        assertThrows(IOException::class.java) {
            backend.begin(configDir, replacementToken, 0L)
        }

        nowNanos = 14L * 60L * 1_000_000_000L
        assertEquals(60L * 1_000_000_000L, backend.pendingExpiryDelayNanosForTesting())

        nowNanos = 16L * 60L * 1_000_000_000L
        assertEquals(0L, backend.pendingExpiryDelayNanosForTesting())
        backend.begin(configDir, replacementToken, 0L)
        assertEquals(RESTORE_TTL_NANOS, backend.pendingExpiryDelayNanosForTesting())

        assertThrows(IOException::class.java) {
            backend.abort(configDir, activeTokens.first())
        }
        backend.abort(configDir, replacementToken)
        assertEquals(null, backend.pendingExpiryDelayNanosForTesting())
    }

    @Test
    fun completedReplaceCrossingTtlRemainsRollbackRestorable() {
        var nowNanos = 0L
        var crossTtlAtOperationCompletion = false
        val backend =
            JvmSecureRestoreFileOperations(
                nowNanos = { nowNanos },
                enableExpiryJanitor = false,
                operationCompletionHookForTesting = {
                    if (crossTtlAtOperationCompletion) {
                        nowNanos += RESTORE_TTL_NANOS + 1L
                        crossTtlAtOperationCompletion = false
                    }
                },
            )
        val configDir = tempFolder.newFolder("long-operation")
        val target = configDir.resolve("identity.xml")
        target.writeText("before")
        val token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

        backend.begin(configDir, token, 4096L)
        backend.snapshot(configDir, token, target)

        crossTtlAtOperationCompletion = true
        backend.replace(configDir, token, target, "after".toByteArray())

        assertEquals("after", target.readText())
        assertEquals(RESTORE_TTL_NANOS, backend.pendingExpiryDelayNanosForTesting())

        backend.rollback(configDir, token)
        assertEquals("before", target.readText())
        assertEquals(null, backend.pendingExpiryDelayNanosForTesting())
    }

    private companion object {
        const val RESTORE_TTL_NANOS = 15L * 60L * 1_000_000_000L
    }
}
