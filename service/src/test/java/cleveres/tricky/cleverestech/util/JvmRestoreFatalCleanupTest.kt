package cleveres.tricky.cleverestech.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.IOException

class JvmRestoreFatalCleanupTest {
    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun checkedCleanupFailureEscapesAfterTransactionWasRemoved() {
        val sentinel = IOException("synthetic cleanup exception")
        val backend =
            JvmSecureRestoreFileOperations(
                enableExpiryJanitor = false,
                transactionCleanupHookForTesting = { throw sentinel },
            )
        val configDir = tempFolder.newFolder("checked-cleanup-error")
        val token = "abababababababababababababababab"

        backend.begin(configDir, token, 0L)
        val thrown = assertThrows(IOException::class.java) {
            backend.commit(configDir, token)
        }

        assertSame(sentinel, thrown)
        assertEquals(null, backend.pendingExpiryDelayNanosForTesting())
        assertThrows(IOException::class.java) { backend.abort(configDir, token) }
    }

    @Test
    fun fatalCleanupErrorEscapesAfterTransactionWasRemoved() {
        val sentinel = AssertionError("synthetic cleanup error")
        val backend =
            JvmSecureRestoreFileOperations(
                enableExpiryJanitor = false,
                transactionCleanupHookForTesting = { throw sentinel },
            )
        val configDir = tempFolder.newFolder("fatal-cleanup-error")
        val token = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"

        backend.begin(configDir, token, 0L)
        val thrown = assertThrows(AssertionError::class.java) {
            backend.commit(configDir, token)
        }

        assertSame(sentinel, thrown)
        assertEquals(null, backend.pendingExpiryDelayNanosForTesting())
        assertThrows(IOException::class.java) { backend.abort(configDir, token) }
    }
}
