package net.kackman.webauthn

import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialCancellationException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
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

    @Test
    fun `flattenPrfOutput lifts prf results to the top level`() {
        val response =
            WebauthnPlugin.flattenPrfOutput(
                """{"id":"cred","clientExtensionResults":{"prf":{"results":{"first":"c2VjcmV0"}}}}""",
            )
        val prf = response.getJSONObject("prf")
        assertEquals("c2VjcmV0", prf.getString("first"))
    }

    @Test
    fun flattenOmitsPrfWhenClientExtensionResultsPrfIsEmpty() {
        val input = """{"clientExtensionResults":{"prf":{}}}"""
        val result = WebauthnPlugin.flattenPrfOutput(input)
        assertFalse("an empty prf result must not add a top-level prf", result.has("prf"))
    }

    // --- errorCode --------------------------------------------------------

    @Test
    fun errorCodeMapsCancellationExceptions() {
        assertEquals("cancelled", WebauthnPlugin.errorCode(CreateCredentialCancellationException()))
        assertEquals("cancelled", WebauthnPlugin.errorCode(GetCredentialCancellationException()))
        assertEquals("cancelled", WebauthnPlugin.errorCode(CancellationException("job cancelled")))
    }

    @Test
    fun errorCodeMapsTimeout() {
        val timeout: TimeoutCancellationException =
            try {
                runBlocking { withTimeout(1) { kotlinx.coroutines.delay(1_000) } }
                throw AssertionError("withTimeout did not time out")
            } catch (e: TimeoutCancellationException) {
                e
            }
        assertEquals("timeout", WebauthnPlugin.errorCode(timeout))
    }

    @Test
    fun errorCodeIsNullForOtherExceptions() {
        assertNull(WebauthnPlugin.errorCode(IllegalStateException("boom")))
        assertNull(WebauthnPlugin.errorCode(RuntimeException()))
    }

    // --- timeoutMs --------------------------------------------------------

    @Test
    fun timeoutMsReadsTopLevelTimeout() {
        assertEquals(1234L, WebauthnPlugin.timeoutMs("""{"challenge":"x","timeout":1234}"""))
    }

    @Test
    fun timeoutMsDefaultsWhenAbsentOrInvalid() {
        assertEquals(60_000L, WebauthnPlugin.timeoutMs("""{"challenge":"x"}"""))
        assertEquals(60_000L, WebauthnPlugin.timeoutMs("""{"timeout":0}"""))
        assertEquals(60_000L, WebauthnPlugin.timeoutMs("not json"))
    }
}
