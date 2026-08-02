package net.kackman.webauthn

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

// Robolectric supplies a real org.json (the stock android.jar stubs throw
// "not mocked"), so these pure PRF-shape transforms can be exercised on the JVM.
@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE, sdk = [34])
class WebauthnPluginTest {
    // --- translateRegistrationRequest -------------------------------------

    @Test
    fun registrationRequestWithoutExtensionsIsUnchanged() {
        val input = """{"challenge":"abc","rp":{"id":"example.com"}}"""
        assertEquals(input, WebauthnPlugin.translateRegistrationRequest(input))
    }

    @Test
    fun registrationRequestAddsPrfWhenHmacCreateSecretTrue() {
        val input = """{"extensions":{"hmacCreateSecret":true}}"""
        val ext = JSONObject(WebauthnPlugin.translateRegistrationRequest(input)).getJSONObject("extensions")
        assertTrue("prf object should be present", ext.has("prf"))
        assertFalse("legacy hmacCreateSecret should be removed", ext.has("hmacCreateSecret"))
    }

    @Test
    fun registrationRequestDropsHmacCreateSecretWhenFalse() {
        val input = """{"extensions":{"hmacCreateSecret":false}}"""
        val ext = JSONObject(WebauthnPlugin.translateRegistrationRequest(input)).getJSONObject("extensions")
        assertFalse("no prf when not requested", ext.has("prf"))
        assertFalse("legacy hmacCreateSecret should be removed", ext.has("hmacCreateSecret"))
    }

    // --- translateAuthenticationRequest -----------------------------------

    @Test
    fun authenticationRequestWithoutExtensionsIsUnchanged() {
        val input = """{"challenge":"abc","rpId":"example.com"}"""
        assertEquals(input, WebauthnPlugin.translateAuthenticationRequest(input))
    }

    @Test
    fun authenticationRequestMapsBothSaltsIntoPrfEval() {
        val input = """{"extensions":{"hmacGetSecret":{"output1":"c2FsdDE","output2":"c2FsdDI"}}}"""
        val ext = JSONObject(WebauthnPlugin.translateAuthenticationRequest(input)).getJSONObject("extensions")
        assertFalse("legacy hmacGetSecret should be removed", ext.has("hmacGetSecret"))
        val eval = ext.getJSONObject("prf").getJSONObject("eval")
        assertEquals("c2FsdDE", eval.getString("first"))
        assertEquals("c2FsdDI", eval.getString("second"))
    }

    @Test
    fun authenticationRequestOmitsSecondSaltWhenAbsent() {
        val input = """{"extensions":{"hmacGetSecret":{"output1":"c2FsdDE"}}}"""
        val ext = JSONObject(WebauthnPlugin.translateAuthenticationRequest(input)).getJSONObject("extensions")
        val eval = ext.getJSONObject("prf").getJSONObject("eval")
        assertEquals("c2FsdDE", eval.getString("first"))
        assertFalse("second salt must be omitted when not supplied", eval.has("second"))
    }

    @Test
    fun authenticationRequestOmitsSecondSaltWhenEmpty() {
        val input = """{"extensions":{"hmacGetSecret":{"output1":"c2FsdDE","output2":""}}}"""
        val ext = JSONObject(WebauthnPlugin.translateAuthenticationRequest(input)).getJSONObject("extensions")
        val eval = ext.getJSONObject("prf").getJSONObject("eval")
        assertFalse("empty second salt must be omitted", eval.has("second"))
    }

    // --- flattenPrfOutput -------------------------------------------------

    @Test
    fun flattenLeavesResponseUnchangedWithoutClientExtensionResults() {
        val input = """{"id":"cred","response":{}}"""
        val result = WebauthnPlugin.flattenPrfOutput(input)
        assertFalse("no top-level prf should be added", result.has("prf"))
        assertEquals("cred", result.getString("id"))
    }

    @Test
    fun flattenExtractsEnabledAfterRegistration() {
        val input = """{"clientExtensionResults":{"prf":{"enabled":true}}}"""
        val prf = WebauthnPlugin.flattenPrfOutput(input).getJSONObject("prf")
        assertTrue(prf.getBoolean("enabled"))
    }

    @Test
    fun flattenExtractsFirstAndSecondAfterAuthentication() {
        val input = """{"clientExtensionResults":{"prf":{"results":{"first":"Rmly","second":"U2Vjb"}}}}"""
        val prf = WebauthnPlugin.flattenPrfOutput(input).getJSONObject("prf")
        assertEquals("Rmly", prf.getString("first"))
        assertEquals("U2Vjb", prf.getString("second"))
    }

    @Test
    fun flattenOmitsSecondWhenOnlyFirstPresent() {
        val input = """{"clientExtensionResults":{"prf":{"results":{"first":"Rmly"}}}}"""
        val prf = WebauthnPlugin.flattenPrfOutput(input).getJSONObject("prf")
        assertEquals("Rmly", prf.getString("first"))
        assertFalse(prf.has("second"))
    }
}
