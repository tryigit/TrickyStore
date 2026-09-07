package cleveres.tricky.cleverestech

import cleveres.tricky.cleverestech.util.KeyboxVerifier
import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test
import java.io.File

class WebServerJsonTest {
    @Test
    fun testJsonInjectionVulnerability() {
        // We inject a payload that closes the filename string, adds a new field, and handles the trailing quote.
        // Payload: hack", "injected": "true", "x": "
        // Resulting "filename": "hack", "injected": "true", "x": "" ...
        val payload = "hack\", \"injected\": \"true\", \"x\": \""
        val results =
            listOf(
                KeyboxVerifier.Result(File("dummy"), payload, KeyboxVerifier.Status.INVALID, "Bad"),
            )
        val json = WebServer.createKeyboxVerificationJson(results)

        val array = JSONArray(json)
        val obj = array.getJSONObject(0)

        // In the vulnerable version, "injected" key exists.
        if (obj.has("injected")) {
            fail("Vulnerability detected! JSON Injection successful. Injected key found.")
        }

        // If secure, the filename should be exactly the payload
        assertEquals(payload, obj.getString("filename"))
    }

    @Test
    fun testCertificateSerialSerialized() {
        val results =
            listOf(
                KeyboxVerifier.Result(
                    file = File("box.xml"),
                    filename = "box.xml",
                    status = KeyboxVerifier.Status.VALID,
                    details = "Active",
                    certificateSerial = "1A2B3C4D",
                    securityLevel = "StrongBox",
                ),
            )
        val json = WebServer.createKeyboxVerificationJson(results)
        val array = JSONArray(json)
        val obj = array.getJSONObject(0)
        assertEquals("1A2B3C4D", obj.getString("certificate_serial"))
        assertEquals("StrongBox", obj.getString("security_level"))
        assertEquals(false, obj.getBoolean("is_rkp"))
    }

    @Test
    fun testRkpSerialized() {
        val results =
            listOf(
                KeyboxVerifier.Result(
                    file = File("rkp_box.xml"),
                    filename = "rkp_box.xml",
                    status = KeyboxVerifier.Status.VALID,
                    details = "Active",
                    certificateSerial = "5E6F7A8B",
                    securityLevel = "TEE",
                    isRkp = true,
                ),
            )
        val json = WebServer.createKeyboxVerificationJson(results)
        val array = JSONArray(json)
        val obj = array.getJSONObject(0)
        assertEquals(true, obj.getBoolean("is_rkp"))
        assertEquals("TEE", obj.getString("security_level"))
    }
}
