package cleveres.tricky.cleverestech.keystore

import cleveres.tricky.cleverestech.PolicyState
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class PolicyStateCertificateCacheInvalidationTest {
    @get:Rule
    val tempFolder = TemporaryFolder()

    @After
    fun tearDown() {
        PolicyState.resetForTesting()
    }

    @Test
    fun missingPublishedStateInvalidatesCertificateCacheEpoch() {
        val previousEpoch = CertHack.captureCertificateCacheEpochForTesting()
        val configDir = tempFolder.newFolder("missing-state")

        assertTrue(PolicyState.initialize(configDir).isSuccess)

        assertFalse(CertHack.isCertificateCacheEpochCurrentForTesting(previousEpoch))
    }

    @Test
    fun legacySettingsTransitionInvalidatesCertificateCacheEpoch() {
        PolicyState.setRootForTesting(tempFolder.newFolder("legacy-state"))
        val previousEpoch = CertHack.captureCertificateCacheEpochForTesting()

        PolicyState.onLegacySettingsChanged()

        assertFalse(CertHack.isCertificateCacheEpochCurrentForTesting(previousEpoch))
    }
}
