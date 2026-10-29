package net.kackman.webauthn

import android.app.Activity
import androidx.annotation.VisibleForTesting
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialCancellationException
import app.tauri.annotation.Command
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import org.json.JSONObject

@TauriPlugin
class WebauthnPlugin(
    activity: Activity,
) : Plugin(activity) {
    private val scope = CoroutineScope(Dispatchers.Main)
    private val credentialManager = CredentialManager.create(activity)
    private val pluginActivity = activity
    private var currentJob: Job? = null

    @Command
    fun register(invoke: Invoke) {
        val args = invoke.parseArgs(String::class.java)

        val createPublicKeyCredentialRequest =
            CreatePublicKeyCredentialRequest(
                requestJson = args,
            )

        currentJob =
            launchCeremony(scope, InvokeSettler(invoke), timeoutMs(args)) {
                val result =
                    credentialManager.createCredential(
                        pluginActivity,
                        createPublicKeyCredentialRequest,
                    )
                // null -> "Invalid credential type"
                (result as? CreatePublicKeyCredentialResponse)
                    ?.let { flattenPrfOutput(it.registrationResponseJson) }
            }
    }

    @Command
    fun authenticate(invoke: Invoke) {
        val args = invoke.parseArgs(String::class.java)

        val getPublicKeyCredentialOption =
            GetPublicKeyCredentialOption(
                requestJson = args,
            )
        val getCredRequest =
            GetCredentialRequest(
                listOf(getPublicKeyCredentialOption),
            )

        currentJob =
            launchCeremony(scope, InvokeSettler(invoke), timeoutMs(args)) {
                val result =
                    credentialManager
                        .getCredential(
                            pluginActivity,
                            getCredRequest,
                        ).credential
                // null -> "Invalid credential type"
                (result as? PublicKeyCredential)
                    ?.let { flattenPrfOutput(it.authenticationResponseJson) }
            }
    }

    @Command
    fun cancel(invoke: Invoke) {
        currentJob?.cancel()
        currentJob = null
        invoke.resolve()
    }

    internal companion object {
        // Matches the WebAuthn default the Rust side would otherwise send.
        private const val DEFAULT_TIMEOUT_MS = 60_000L

        // Runs one ceremony and settles the invoke exactly once. ATOMIC start
        // means a cancel() that lands before Dispatchers.Main runs the posted
        // body still enters the try, so the first suspension throws
        // CancellationException and takes the "cancelled" reject path; the
        // completion handler is the backstop for anything that still escapes.
        // A null ceremony result means the credential was of an unexpected type.
        @VisibleForTesting
        fun launchCeremony(
            scope: CoroutineScope,
            settler: InvokeSettler,
            timeoutMs: Long,
            ceremony: suspend () -> JSObject?,
        ): Job {
            val job =
                scope.launch(start = CoroutineStart.ATOMIC) {
                    try {
                        val result = withTimeout(timeoutMs) { ceremony() }
                        if (result != null) {
                            settler.resolve(result)
                        } else {
                            settler.reject("Invalid credential type")
                        }
                    } catch (e: TimeoutCancellationException) {
                        // Our own withTimeout fired; the job itself is still live.
                        settler.reject("Operation timed out", errorCode(e))
                    } catch (e: CancellationException) {
                        settler.reject("Operation cancelled", errorCode(e))
                        throw e
                    } catch (e: Exception) {
                        settler.reject(e.message ?: e.javaClass.simpleName, errorCode(e))
                    }
                }
            settler.settleOnCompletion(job)
            return job
        }

        // Machine-readable reject code consumed by mobile.rs `map_invoke_error`.
        // TimeoutCancellationException is a CancellationException, so it is
        // checked first.
        @VisibleForTesting
        fun errorCode(e: Throwable): String? =
            when (e) {
                is TimeoutCancellationException -> "timeout"

                is CreateCredentialCancellationException,
                is GetCredentialCancellationException,
                is CancellationException,
                -> "cancelled"

                else -> null
            }

        // mobile.rs injects the command's timeout as the top-level `timeout`
        // member of the options JSON (a standard WebAuthn options field).
        @VisibleForTesting
        fun timeoutMs(optionsJson: String): Long {
            val timeout =
                try {
                    JSONObject(optionsJson).optLong("timeout", 0L)
                } catch (_: Exception) {
                    0L
                }
            return if (timeout > 0) timeout else DEFAULT_TIMEOUT_MS
        }

        // The shared Rust parser (mobile.rs) expects a flat top-level `prf`
        // object — {"enabled": bool} after registration, {"first"/"second":
        // base64url} after authentication — matching what the Swift bridges
        // emit, while Credential Manager nests it under clientExtensionResults.
        @VisibleForTesting
        fun flattenPrfOutput(responseJson: String): JSObject {
            val response = JSObject(responseJson)
            val prf =
                response
                    .optJSONObject("clientExtensionResults")
                    ?.optJSONObject("prf")
                    ?: return response
            val flat = JSONObject()
            if (prf.has("enabled")) {
                flat.put("enabled", prf.getBoolean("enabled"))
            }
            prf.optJSONObject("results")?.let { results ->
                results
                    .optString("first")
                    .takeIf { it.isNotEmpty() }
                    ?.let { flat.put("first", it) }
                results
                    .optString("second")
                    .takeIf { it.isNotEmpty() }
                    ?.let { flat.put("second", it) }
            }
            // An empty `prf` would read as "extension present, nothing in it";
            // leave it off so Rust sees the same shape as no PRF at all.
            if (flat.length() > 0) {
                response.put("prf", flat)
            }
            return response
        }
    }
}
