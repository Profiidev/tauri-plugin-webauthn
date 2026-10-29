package net.kackman.webauthn

import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import kotlinx.coroutines.Job
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Settles a Tauri [Invoke] exactly once.
 *
 * Rust's `run_mobile_plugin` blocks until the invoke is resolved or rejected and
 * the in-flight guard stays held meanwhile, so an invoke that is never settled
 * wedges every later ceremony as `busy`. Every resolve/reject goes through here;
 * [settleOnCompletion] is the backstop for a job that finishes (e.g. cancelled
 * before its body ever ran) without having settled.
 */
internal class InvokeSettler(
    private val onResolve: (JSObject?) -> Unit,
    private val onReject: (message: String, code: String?) -> Unit,
) {
    constructor(invoke: Invoke) : this(
        onResolve = { invoke.resolve(it) },
        onReject = { message, code -> invoke.reject(message, code) },
    )

    private val settled = AtomicBoolean(false)

    val isSettled: Boolean
        get() = settled.get()

    /** Returns false (and does nothing) if the invoke was already settled. */
    fun resolve(value: JSObject?): Boolean {
        if (!settled.compareAndSet(false, true)) return false
        onResolve(value)
        return true
    }

    /** Returns false (and does nothing) if the invoke was already settled. */
    fun reject(
        message: String,
        code: String? = null,
    ): Boolean {
        if (!settled.compareAndSet(false, true)) return false
        onReject(message, code)
        return true
    }

    fun settleOnCompletion(job: Job) {
        job.invokeOnCompletion { reject("Operation cancelled", "cancelled") }
    }
}
