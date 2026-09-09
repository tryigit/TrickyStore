package cleveres.tricky.cleverestech

import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class ManagedAttestKeyRegistryTest {
    @Before
    fun setUp() {
        ManagedAttestKeyRegistry.resetForTesting()
    }

    @After
    fun tearDown() {
        ManagedAttestKeyRegistry.resetForTesting()
    }

    @Test
    fun `known identity is separated by uid and descriptor and stored defensively`() {
        val uid = 10_123
        val original = ByteArray(32) { 0x5a.toByte() }
        val lookup = original.copyOf()

        ManagedAttestKeyRegistry.remember(uid, original)
        original.fill(0)

        assertTrue(ManagedAttestKeyRegistry.isKnown(uid, lookup))
        assertFalse(ManagedAttestKeyRegistry.isKnown(uid + 1, lookup))
        assertFalse(ManagedAttestKeyRegistry.isKnown(uid, ByteArray(32) { 0x6b.toByte() }))
        assertFalse(ManagedAttestKeyRegistry.isKnown(uid, ByteArray(32)))
        assertFalse(ManagedAttestKeyRegistry.isKnown(uid, ByteArray(31) { 1 }))
    }

    @Test
    fun `registry saturation never creates a managed cache false negative`() {
        val uid = 10_123
        fun descriptor(index: Int): ByteArray =
            ByteArray(32).also {
                it[0] = ((index ushr 8) and 0xff).toByte()
                it[1] = (index and 0xff).toByte()
                it[2] = 1
            }

        for (index in 1..256) {
            ManagedAttestKeyRegistry.remember(uid, descriptor(index))
        }
        assertTrue(ManagedAttestKeyRegistry.isKnown(uid, descriptor(1)))
        assertFalse(ManagedAttestKeyRegistry.isKnown(uid, descriptor(999)))

        ManagedAttestKeyRegistry.remember(uid, descriptor(257))

        assertTrue(ManagedAttestKeyRegistry.isKnown(uid, descriptor(1)))
        assertTrue(ManagedAttestKeyRegistry.isKnown(uid, descriptor(256)))
        assertTrue(ManagedAttestKeyRegistry.isKnown(uid, descriptor(257)))
        assertTrue(ManagedAttestKeyRegistry.isKnown(uid, descriptor(999)))
        assertFalse(ManagedAttestKeyRegistry.isKnown(uid, ByteArray(32)))
        assertNull(ManagedAttestKeyRegistry.rehydrationPath(uid, descriptor(257)))
    }
}
