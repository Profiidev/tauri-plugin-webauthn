package net.kackman.webauthn

import app.tauri.plugin.JSObject
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.awaitCancellation
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import kotlin.coroutines.CoroutineContext

@RunWith(RobolectricTestRunner::class)
@Config(manifest = Config.NONE, sdk = [34])
class InvokeSettlerTest {
    private class Recorder {
        val resolved = mutableListOf<JSObject?>()
        val rejected = mutableListOf<Pair<String, String?>>()

        fun settler() =
            InvokeSettler(
                onResolve = { resolved.add(it) },
                onReject = { message, code -> rejected.add(message to code) },
            )
    }

    // Queues dispatched blocks instead of running them, so a test can cancel a
    // job after launch but before its body has had a chance to start — the
    // same window as Dispatchers.Main posting to the looper.
    private class QueueDispatcher : CoroutineDispatcher() {
        val queue = ArrayDeque<Runnable>()

        override fun dispatch(
            context: CoroutineContext,
            block: Runnable,
        ) {
            queue.addLast(block)
        }

        fun drain() {
            while (queue.isNotEmpty()) queue.removeFirst().run()
        }
    }

    @Test
    fun secondSettleIsIgnored() {
        val recorder = Recorder()
        val settler = recorder.settler()
        assertTrue(settler.resolve(JSObject()))
        assertFalse(settler.reject("late", "cancelled"))
        assertFalse(settler.resolve(JSObject()))
        assertEquals(1, recorder.resolved.size)
        assertTrue(recorder.rejected.isEmpty())
        assertTrue(settler.isSettled)
    }

    @Test
    fun completionWithoutSettleRejectsCancelled() {
        val recorder = Recorder()
        val settler = recorder.settler()
        val job = Job()
        settler.settleOnCompletion(job)
        job.cancel()
        assertEquals(listOf("Operation cancelled" to "cancelled"), recorder.rejected)
        assertTrue(recorder.resolved.isEmpty())
    }

    @Test
    fun completionAfterSettleDoesNothing() {
        val recorder = Recorder()
        val settler = recorder.settler()
        val job = Job()
        settler.settleOnCompletion(job)
        settler.reject("boom", null)
        job.cancel()
        assertEquals(listOf("boom" to null), recorder.rejected)
    }

    @Test
    fun ceremonyCancelledBeforeDispatchStillSettlesCancelled() {
        val recorder = Recorder()
        val dispatcher = QueueDispatcher()
        val job =
            WebauthnPlugin.launchCeremony(
                CoroutineScope(dispatcher),
                recorder.settler(),
                timeoutMs = 60_000L,
            ) { awaitCancellation() }
        // cancel() wins the race against the posted launch.
        job.cancel()
        dispatcher.drain()
        assertTrue(job.isCompleted)
        assertEquals(listOf("Operation cancelled" to "cancelled"), recorder.rejected)
        assertTrue(recorder.resolved.isEmpty())
    }

    @Test
    fun ceremonyResultResolvesOnce() {
        val recorder = Recorder()
        val dispatcher = QueueDispatcher()
        val job =
            WebauthnPlugin.launchCeremony(
                CoroutineScope(dispatcher),
                recorder.settler(),
                timeoutMs = 60_000L,
            ) { JSObject().apply { put("id", "cred") } }
        dispatcher.drain()
        assertTrue(job.isCompleted)
        assertEquals(1, recorder.resolved.size)
        assertEquals("cred", recorder.resolved[0]?.getString("id"))
        assertTrue(recorder.rejected.isEmpty())
    }

    @Test
    fun ceremonyWithoutResultRejectsInvalidCredentialType() {
        val recorder = Recorder()
        val dispatcher = QueueDispatcher()
        WebauthnPlugin.launchCeremony(
            CoroutineScope(dispatcher),
            recorder.settler(),
            timeoutMs = 60_000L,
        ) { null }
        dispatcher.drain()
        assertEquals(listOf("Invalid credential type" to null), recorder.rejected)
    }
}
