package cleveres.tricky.cleverestech

import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
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

    @Test
    fun `rehydration path is parent first bounded and defensively copied`() {
        val uid = 10_123
        val root = ByteArray(32) { 0x11 }
        val child = ByteArray(32) { 0x22 }
        val rootLeaf = byteArrayOf(1, 2, 3)
        val childLeaf = byteArrayOf(4, 5, 6)

        ManagedAttestKeyRegistry.remember(uid, root, null, rootLeaf)
        ManagedAttestKeyRegistry.remember(uid, child, root, childLeaf)
        rootLeaf.fill(0)
        childLeaf.fill(0)

        val path = requireNotNull(ManagedAttestKeyRegistry.rehydrationPath(uid, child))
        assertEquals(2, path.size)
        assertArrayEquals(root, path[0].keyId)
        assertNull(path[0].parentKeyId)
        assertArrayEquals(byteArrayOf(1, 2, 3), path[0].genuineLeafDer)
        assertArrayEquals(child, path[1].keyId)
        assertArrayEquals(root, path[1].parentKeyId)
        assertArrayEquals(byteArrayOf(4, 5, 6), path[1].genuineLeafDer)

        path[0].keyId.fill(0)
        path[0].genuineLeafDer.fill(0)
        val secondRead = requireNotNull(ManagedAttestKeyRegistry.rehydrationPath(uid, child))
        assertArrayEquals(root, secondRead[0].keyId)
        assertArrayEquals(byteArrayOf(1, 2, 3), secondRead[0].genuineLeafDer)
    }

    @Test
    fun `explicit top level regeneration clears old parent relation`() {
        val uid = 10_123
        val parent = ByteArray(32) { 0x31 }
        val key = ByteArray(32) { 0x41 }

        ManagedAttestKeyRegistry.remember(uid, parent, null, byteArrayOf(1))
        ManagedAttestKeyRegistry.remember(uid, key, parent, byteArrayOf(2))
        assertEquals(2, requireNotNull(ManagedAttestKeyRegistry.rehydrationPath(uid, key)).size)

        ManagedAttestKeyRegistry.remember(uid, key, null, byteArrayOf(3))
        val path = requireNotNull(ManagedAttestKeyRegistry.rehydrationPath(uid, key))
        assertEquals(1, path.size)
        assertNull(path[0].parentKeyId)
        assertArrayEquals(byteArrayOf(3), path[0].genuineLeafDer)
    }

    @Test
    fun `missing ancestor fails closed`() {
        val uid = 10_123
        val missingParent = ByteArray(32) { 0x51 }
        val child = ByteArray(32) { 0x61 }
        ManagedAttestKeyRegistry.remember(uid, child, missingParent, byteArrayOf(9))
        assertNull(ManagedAttestKeyRegistry.rehydrationPath(uid, child))
    }

    @Test
    fun `child key records parent relation but is not an attest key and cannot be rehydrated`() {
        val uid = 10_123
        val parent = ByteArray(32) { 0x71 }
        val child = ByteArray(32) { 0x72 }
        val childLeaf = byteArrayOf(1, 2, 3)

        ManagedAttestKeyRegistry.remember(uid, parent, null, byteArrayOf(9), true)
        ManagedAttestKeyRegistry.remember(uid, child, parent, childLeaf, false)

        assertTrue(ManagedAttestKeyRegistry.isKnown(uid, child))
        assertTrue(ManagedAttestKeyRegistry.isAttestKey(uid, parent))
        assertFalse(ManagedAttestKeyRegistry.isAttestKey(uid, child))
        assertFalse(ManagedAttestKeyRegistry.isAttestKey(uid, ByteArray(32) { 0x99.toByte() }))
        assertArrayEquals(parent, ManagedAttestKeyRegistry.getParentKeyId(uid, child))
        assertNull(ManagedAttestKeyRegistry.getParentKeyId(uid, parent))
        assertNull(ManagedAttestKeyRegistry.rehydrationPath(uid, child))
    }

    @Test
    fun `registry saturation retains parent key id and admits new children`() {
        val uid = 10_123
        fun descriptor(index: Int): ByteArray =
            ByteArray(32).also {
                it[0] = ((index ushr 8) and 0xff).toByte()
                it[1] = (index and 0xff).toByte()
                it[2] = 2
            }

        val parentBefore = descriptor(10)
        val childBefore = descriptor(11)
        ManagedAttestKeyRegistry.remember(uid, parentBefore, null, byteArrayOf(1), true)
        ManagedAttestKeyRegistry.remember(uid, childBefore, parentBefore, byteArrayOf(2), false)

        for (index in 100..360) {
            ManagedAttestKeyRegistry.remember(uid, descriptor(index))
        }

        val newParent = descriptor(400)
        val newChild = descriptor(401)
        ManagedAttestKeyRegistry.remember(uid, newParent, null, byteArrayOf(3), true)
        ManagedAttestKeyRegistry.remember(uid, newChild, newParent, byteArrayOf(4), false)

        assertArrayEquals(newParent, ManagedAttestKeyRegistry.getParentKeyId(uid, newChild))
    }

    @Test
    fun `subtree eviction removes descendants when oldest parent is evicted`() {
        val uid = 10_123
        fun descriptor(index: Int): ByteArray =
            ByteArray(32).also {
                it[0] = ((index ushr 8) and 0xff).toByte()
                it[1] = (index and 0xff).toByte()
                it[2] = 3
            }

        val root = descriptor(1)
        val child = descriptor(2)
        val grandchild = descriptor(3)

        ManagedAttestKeyRegistry.remember(uid, root, null, byteArrayOf(1), true)
        ManagedAttestKeyRegistry.remember(uid, child, root, byteArrayOf(2), true)
        ManagedAttestKeyRegistry.remember(uid, grandchild, child, byteArrayOf(3), false)

        for (index in 10..265) {
            ManagedAttestKeyRegistry.remember(uid, descriptor(index))
        }

        assertNull(ManagedAttestKeyRegistry.getParentKeyId(uid, grandchild))
        assertNull(ManagedAttestKeyRegistry.rehydrationPath(uid, child))
    }

    @Test
    fun `ancestor cycle is rejected`() {
        val uid = 10_123
        val a = ByteArray(32) { 0x1a }
        val b = ByteArray(32) { 0x1b }
        val c = ByteArray(32) { 0x1c }

        ManagedAttestKeyRegistry.remember(uid, a, null, byteArrayOf(1), true)
        ManagedAttestKeyRegistry.remember(uid, b, a, byteArrayOf(2), true)
        ManagedAttestKeyRegistry.remember(uid, c, b, byteArrayOf(3), true)

        ManagedAttestKeyRegistry.remember(uid, a, c, byteArrayOf(4), true)

        assertNull(ManagedAttestKeyRegistry.getParentKeyId(uid, a))
        val path = requireNotNull(ManagedAttestKeyRegistry.rehydrationPath(uid, c))
        assertEquals(3, path.size)
        assertArrayEquals(a, path[0].keyId)
    }

    @Test
    fun `saturation evicts unrelated subtrees while protecting complete parent ancestry`() {
        val uid = 10_123
        fun descriptor(index: Int): ByteArray =
            ByteArray(32).also {
                it[0] = ((index ushr 8) and 0xff).toByte()
                it[1] = (index and 0xff).toByte()
                it[2] = 2
            }

        val root = descriptor(1)
        val parent = descriptor(2)
        ManagedAttestKeyRegistry.remember(uid, root, null, byteArrayOf(1), true)
        ManagedAttestKeyRegistry.remember(uid, parent, root, byteArrayOf(2), true)

        for (index in 3..256) {
            ManagedAttestKeyRegistry.remember(uid, descriptor(index))
        }

        val child = descriptor(999)
        ManagedAttestKeyRegistry.remember(uid, child, parent, byteArrayOf(3), true)

        assertArrayEquals(root, ManagedAttestKeyRegistry.getParentKeyId(uid, parent))
        assertArrayEquals(parent, ManagedAttestKeyRegistry.getParentKeyId(uid, child))
        val path = requireNotNull(ManagedAttestKeyRegistry.rehydrationPath(uid, child))
        assertEquals(3, path.size)
        assertArrayEquals(root, path[0].keyId)
        assertArrayEquals(parent, path[1].keyId)
        assertArrayEquals(child, path[2].keyId)
    }
}
