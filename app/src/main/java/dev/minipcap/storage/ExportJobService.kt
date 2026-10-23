package dev.minipcap.storage

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.util.Log

/**
 * Moves finalized pairs to Download/MiniPcap. A regular job keeps the process alive
 * while a large file is copied after the Activity and VPN service are gone; if the
 * system stops it, the current move is rolled back and the job is rescheduled.
 */
class ExportJobService : JobService() {

    companion object {
        private const val TAG = "ExportJob"
        const val JOB_ID = 1002
        @Volatile private var rerun = false

        fun schedule(ctx: Context) {
            val js = ctx.getSystemService(JobScheduler::class.java)
            // Re-scheduling the same id would stop a running job: ask it to rescan instead.
            rerun = true
            if (js.getPendingJob(JOB_ID) != null) return
            val job = JobInfo.Builder(JOB_ID, ComponentName(ctx, ExportJobService::class.java))
                .setOverrideDeadline(0)
                .build()
            runCatching { js.schedule(job) }.onFailure { Log.w(TAG, "schedule failed: ${it.javaClass.simpleName}") }
        }
    }

    @Volatile private var stopped = false

    override fun onStartJob(params: JobParameters): Boolean {
        stopped = false
        Thread({ run(params) }, "capture-export").start()
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean {
        stopped = true
        return true // reschedule: the interrupted move was rolled back
    }

    private fun run(params: JobParameters) {
        try {
            // Only this job moves files, so an EXPORTING record here was interrupted.
            runCatching { Exports.mover(this).reconcile() }.onFailure { Log.w(TAG, "reconcile failed: ${it.javaClass.simpleName}") }
            Exports.notifyListeners()
            val skipped = HashSet<String>()
            do {
                rerun = false
                while (!stopped) {
                    val id = Exports.pending(this).firstOrNull { it !in skipped } ?: break
                    if (!Exports.moveOne(this, id) { stopped }) skipped += id
                }
            } while (rerun && !stopped)
        } finally {
            if (!stopped) jobFinished(params, false)
            if (rerun && !stopped) schedule(this)
        }
    }
}
