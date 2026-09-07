package cleveres.tricky.cleverestech

import android.hardware.security.keymint.SecurityLevel
import android.os.Parcel
import android.system.keystore2.KeyEntryResponse
import androidx.test.ext.junit.runners.AndroidJUnit4
import cleveres.tricky.cleverestech.keystore.CertHack
import cleveres.tricky.cleverestech.keystore.Utils
import java.security.cert.Certificate
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class KeyEntryResponseParcelContractTest {
    @Test
    fun `cached getKeyEntry rewrites stable AIDL envelope without typed response allocation`() {
        val originalLeaf = ByteArray(257) { index -> (index * 17).toByte() }
        val originalChain = ByteArray(513) { index -> (index * 29).toByte() }
        val replacementLeaf = ByteArray(333) { index -> (index * 31).toByte() }
        val replacementChain = ByteArray(777) { index -> (index * 43).toByte() }
        val modificationTime = 1_725_739_200_123L
        val reply = keyEntryReply(originalLeaf, originalChain, modificationTime)
        val bodyPosition = reply.dataPosition()

        val parsed = Utils.parseKeyEntryResponseParcel(reply)
        assertNotNull(parsed)
        requireNotNull(parsed)
        assertEquals(bodyPosition, reply.dataPosition())
        assertArrayEquals(originalLeaf, parsed.leafEncoded)
        assertEquals(SecurityLevel.TRUSTED_ENVIRONMENT, parsed.keySecurityLevel)
        assertEquals(originalChain.size, parsed.chainLength)
        assertTrue(parsed.hasFullCertificateChain())

        val cache = certificateCache()
        val key = cacheKey(originalLeaf)
        val value = cachedChain(replacementLeaf, replacementChain)
        val previous = synchronized(cache) { cache.put(key, value) }
        try {
            assertEquals(
                CertHack.CachedParcelAction.REWRITTEN,
                CertHack.applyCachedCertificateChain(reply, parsed),
            )

            reply.setDataPosition(0)
            reply.readException()
            val decoded = requireNotNull(reply.readTypedObject(KeyEntryResponse.CREATOR))
            val metadata = requireNotNull(decoded.metadata)
            assertArrayEquals(replacementLeaf, metadata.certificate)
            assertArrayEquals(replacementChain, metadata.certificateChain)
            assertEquals(SecurityLevel.TRUSTED_ENVIRONMENT, metadata.keySecurityLevel)
            assertEquals(modificationTime, metadata.modificationTimeMs)
            assertEquals("timing-key", metadata.key.alias)
            assertEquals(reply.dataSize(), reply.dataPosition())
        } finally {
            synchronized(cache) {
                if (previous == null) {
                    cache.remove(key)
                } else {
                    cache[key] = previous
                }
            }
            reply.recycle()
        }
    }

    @Test
    fun `raw parser rejects overflowing response envelope and preserves cursor`() {
        val reply = keyEntryReply(byteArrayOf(1, 2, 3), byteArrayOf(4), 7L)
        val bodyPosition = reply.dataPosition()
        assertEquals(1, reply.readInt())
        reply.writeInt(Int.MAX_VALUE)
        reply.setDataPosition(bodyPosition)

        assertNull(Utils.parseKeyEntryResponseParcel(reply))
        assertEquals(bodyPosition, reply.dataPosition())
        reply.recycle()
    }

    private fun keyEntryReply(
        leaf: ByteArray,
        chain: ByteArray?,
        modificationTime: Long,
    ): Parcel =
        Parcel.obtain().apply {
            writeNoException()
            writeInt(1) // writeTypedObject(KeyEntryResponse) presence marker
            writeStableParcelableBody {
                writeStrongBinder(null) // IKeystoreSecurityLevel
                writeInt(1) // writeTypedObject(KeyMetadata) presence marker
                writeStableParcelableBody {
                    writeInt(1) // writeTypedObject(KeyDescriptor) presence marker
                    writeStableParcelableBody {
                        writeInt(0) // domain
                        writeLong(42L) // nspace
                        writeString("timing-key")
                        writeByteArray(null)
                    }
                    writeInt(SecurityLevel.TRUSTED_ENVIRONMENT)
                    writeInt(0) // empty Authorization[]
                    writeByteArray(leaf)
                    writeByteArray(chain)
                    writeLong(modificationTime)
                }
            }
            setDataPosition(0)
            readException()
        }

    /** Writes a stable-AIDL parcelable body without depending on hidden framework constructors. */
    private fun Parcel.writeStableParcelableBody(body: Parcel.() -> Unit) {
        val start = dataPosition()
        writeInt(0)
        body()
        val end = dataPosition()
        setDataPosition(start)
        writeInt(end - start)
        setDataPosition(end)
    }

    @Suppress("UNCHECKED_CAST")
    private fun certificateCache(): MutableMap<Any, Any> {
        val stateField = CertHack::class.java.getDeclaredField("state").apply { isAccessible = true }
        val state = stateField.get(null)
        val cacheField = state.javaClass.getDeclaredField("certificateCache").apply { isAccessible = true }
        return cacheField.get(state) as MutableMap<Any, Any>
    }

    private fun cacheKey(leaf: ByteArray): Any {
        val constructor =
            Class
                .forName("${CertHack::class.java.name}\$CacheKey")
                .getDeclaredConstructor(ByteArray::class.java)
                .apply { isAccessible = true }
        return constructor.newInstance(leaf.clone())
    }

    private fun cachedChain(
        leaf: ByteArray,
        chain: ByteArray,
    ): Any {
        val constructor =
            Class
                .forName("${CertHack::class.java.name}\$CachedCertificateChain")
                .getDeclaredConstructor(
                    emptyArray<Certificate>().javaClass,
                    ByteArray::class.java,
                    ByteArray::class.java,
                    java.lang.Boolean.TYPE,
                ).apply { isAccessible = true }
        return constructor.newInstance(emptyArray<Certificate>(), leaf, chain, true)
    }
}
