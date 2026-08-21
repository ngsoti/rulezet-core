import AnsiTerminal from '/static/js/components/ansi-terminal.js';

/**
 * JobTracker
 * Polls job status + logs every 2s.
 * Live log via the shared AnsiTerminal component (same one used on the
 * GitHub update/import pages and the ATT&CK admin updater) instead of a
 * bespoke feed, plus a slim progress bar matching that same style.
 * Supports pause, resume, cancel, delete.
 *
 * Requires css/components/ansi-terminal.css to be loaded on any page using
 * this component (see AttackUpdater.js / update_loading.html for the pattern).
 *
 * Usage:
 *   <job-tracker :job-uuid="uuid" @done="onDone" @failed="onFailed"></job-tracker>
 */
const JobTracker = {
    components: { 'ansi-terminal': AnsiTerminal },
    props: {
        jobUuid: { type: String, required: true },
        pollInterval: { type: Number, default: 2000 },
    },
    emits: ['done', 'failed', 'update', 'deleted'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const { ref, computed, onMounted, onUnmounted } = Vue;

        const job = ref(null);
        const logs = ref([]);
        const loading = ref(true);
        const acting = ref(null);
        let timer = null;
        let lastLogId = 0;

        // ── Status helpers ────────────────────────────────────────────────────

        const statusColor = computed(() => {
            if (!job.value) return 'secondary';
            return {
                pending: 'secondary',
                running: 'primary',
                done: 'success',
                failed: 'danger',
                cancelled: 'warning',
                paused: 'info',
            }[job.value.status] || 'secondary';
        });

        const statusIcon = computed(() => {
            if (!job.value) return 'fas fa-clock';
            return {
                pending: 'fas fa-clock',
                running: 'fas fa-spinner fa-spin',
                done: 'fas fa-check-circle',
                failed: 'fas fa-times-circle',
                cancelled: 'fas fa-ban',
                paused: 'fas fa-pause-circle',
            }[job.value.status] || 'fas fa-clock';
        });

        const isFinished = computed(() =>
            job.value && ['done', 'failed', 'cancelled'].includes(job.value.status)
        );

        const canPause = computed(() => job.value && ['pending', 'running'].includes(job.value.status));
        const canResume = computed(() => job.value && job.value.status === 'paused');
        const canCancel = computed(() => job.value && ['pending', 'running', 'paused'].includes(job.value.status));
        const canDelete = computed(() => job.value && ['done', 'failed', 'cancelled', 'paused'].includes(job.value.status));

        // ── Log feed — AnsiTerminal's expected {ts, level, msg} shape ───────────

        const terminalEntries = computed(() =>
            logs.value.map(l => ({ ts: l.created_at, level: l.level, msg: l.message }))
        );

        // ── Polling ───────────────────────────────────────────────────────────

        async function poll() {
            try {
                // fetch status
                const res = await fetch(`/jobs/status/${props.jobUuid}`);
                const data = await res.json();
                if (res.ok) {
                    job.value = data;
                    emit('update', data);
                    if (data.status === 'done') emit('done', data);
                    if (data.status === 'failed') emit('failed', data);
                    if (isFinished.value) stopPolling();
                }

                // fetch new log lines since last known id
                const logRes = await fetch(`/jobs/logs/${props.jobUuid}?since_id=${lastLogId}`);
                const logData = await logRes.json();
                if (logRes.ok && logData.length > 0) {
                    logs.value.push(...logData);
                    lastLogId = logData[logData.length - 1].id;
                }

            } catch (e) {
                console.error('JobTracker poll error:', e);
            } finally {
                loading.value = false;
            }
        }

        // ── Actions ───────────────────────────────────────────────────────────

        async function doAction(action, confirmMsg = null) {
            if (acting.value) return;
            if (confirmMsg && !confirm(confirmMsg)) return;
            acting.value = action;
            try {
                const csrfToken = document.getElementById('csrf_token')?.value || '';
                const res = await fetch(`/jobs/${action}/${props.jobUuid}`, {
                    method: 'POST',
                    headers: { 'X-CSRFToken': csrfToken },
                });
                const data = await res.json();
                if (res.ok) {
                    if (action === 'delete') {
                        stopPolling();
                        job.value = null;
                        logs.value = [];
                        emit('deleted');
                    } else {
                        await poll();
                        if (action === 'resume') startPolling();
                    }
                } else {
                    console.error('JobTracker action error:', data.message);
                }
            } finally {
                acting.value = null;
            }
        }

        function startPolling() { if (!timer) { poll(); timer = setInterval(poll, props.pollInterval); } }
        function stopPolling() { if (timer) { clearInterval(timer); timer = null; } }

        onMounted(startPolling);
        onUnmounted(stopPolling);

        return {
            job, logs, loading, acting, terminalEntries,
            statusColor, statusIcon, isFinished,
            canPause, canResume, canCancel, canDelete,
            doAction,
        };
    },
    template: `
        <div class="job-tracker">

            <!-- Loading spinner -->
            <div v-if="loading" class="text-center py-2">
                <div class="spinner-border spinner-border-sm text-primary"></div>
            </div>

            <!-- Deleted -->
            <div v-else-if="!job" class="text-muted small text-center py-2">
                <i class="fas fa-check-circle text-success me-1"></i>Job deleted.
            </div>

            <div v-else>

                <!-- ── Header ── -->
                <div class="d-flex align-items-center gap-2 mb-2">
                    <i :class="[statusIcon, 'text-' + statusColor]"></i>
                    <span class="fw-semibold small flex-grow-1" style="color: var(--text-color)">
                        [[ job.label || job.job_type ]]
                    </span>
                    <span class="badge rounded-pill"
                          :class="'bg-' + statusColor + '-subtle text-' + statusColor">
                        [[ job.status ]]
                    </span>
                    <a :href="'/jobs/detail/' + job.uuid" target="_blank" rel="noopener"
                       class="btn btn-sm btn-outline-secondary py-0 px-2"
                       style="font-size:.72rem;" title="Open this job in My Jobs">
                        <i class="fas fa-up-right-from-square me-1"></i>My Jobs
                    </a>
                </div>

                <!-- ── Timestamps row ── -->
                <div class="d-flex flex-wrap gap-3 mb-2" style="font-size:0.75rem; color: var(--subtle-text-color)">
                    <span v-if="job.created_at">
                        <i class="fas fa-plus-circle me-1 opacity-50"></i>Created [[ job.created_at ]]
                    </span>
                    <span v-if="job.started_at">
                        <i class="fas fa-play-circle me-1 opacity-50"></i>Started [[ job.started_at ]]
                    </span>
                    <span v-if="job.finished_at">
                        <i class="fas fa-flag-checkered me-1 opacity-50"></i>Finished [[ job.finished_at ]]
                    </span>
                </div>

                <!-- ── Progress bar — slim style matching update_loading.html / AttackUpdater ── -->
                <div v-if="['running', 'done', 'paused'].includes(job.status)" class="mb-3">
                    <div class="progress mb-1" style="height:6px;">
                        <div class="progress-bar" :class="'bg-' + statusColor"
                             :style="{ width: job.progress_pct + '%' }">
                        </div>
                    </div>
                    <small style="color: var(--subtle-text-color)">
                        [[ job.done.toLocaleString() ]] / [[ job.total.toLocaleString() ]] ([[ job.progress_pct ]]%)
                    </small>
                </div>

                <!-- ── Pending / Paused notices ── -->
                <div v-if="job.status === 'pending'" class="small mb-2"
                     style="color: var(--subtle-text-color)">
                    <i class="fas fa-hourglass-start me-1"></i>Queued — waiting for worker…
                </div>
                <div v-if="job.status === 'paused'" class="small mb-2 text-info">
                    <i class="fas fa-pause-circle me-1"></i>
                    Paused at [[ job.progress_pct ]]% — click Resume to continue.
                </div>

                <!-- ── Error ── -->
                <div v-if="job.status === 'failed'"
                     class="alert alert-danger border-0 py-2 small mb-2">
                    <i class="fas fa-exclamation-triangle me-1"></i>
                    [[ job.error || 'An unknown error occurred.' ]]
                </div>

                <!-- ── Live log — same AnsiTerminal component as the GitHub update/import pages ── -->
                <div v-if="logs.length > 0" class="mb-3">
                    <ansi-terminal
                        :entries="terminalEntries"
                        :live="job.status === 'running' || job.status === 'pending'"
                        title="Live log"
                        @clear="logs = []">
                    </ansi-terminal>
                </div>

                <!-- ── Action buttons ── -->
                <div class="d-flex gap-2 flex-wrap">

                    <button v-if="canPause"
                            class="btn btn-sm btn-outline-info rounded-circle p-0 d-flex align-items-center justify-content-center"
                            style="width:28px;height:28px;"
                            title="Pause"
                            @click="doAction('pause')"
                            :disabled="!!acting">
                        <span v-if="acting === 'pause'"
                              class="spinner-border spinner-border-sm" style="width:.8rem;height:.8rem;"></span>
                        <i v-else class="fas fa-pause" style="font-size:.7rem;"></i>
                    </button>

                    <button v-if="canResume"
                            class="btn btn-sm btn-outline-primary flex-grow-1"
                            @click="doAction('resume')"
                            :disabled="!!acting">
                        <span v-if="acting === 'resume'"
                              class="spinner-border spinner-border-sm me-1"></span>
                        <i v-else class="fas fa-play me-1"></i>Resume
                    </button>

                    <button v-if="canCancel"
                            class="btn btn-sm btn-outline-danger rounded-circle p-0 d-flex align-items-center justify-content-center"
                            style="width:28px;height:28px;"
                            title="Stop"
                            @click="doAction('cancel', 'Stop this job? Progress so far will be kept.')"
                            :disabled="!!acting">
                        <span v-if="acting === 'cancel'"
                              class="spinner-border spinner-border-sm" style="width:.8rem;height:.8rem;"></span>
                        <i v-else class="fas fa-stop" style="font-size:.7rem;"></i>
                    </button>

                    <button v-if="canDelete"
                            class="btn btn-sm btn-outline-secondary flex-grow-1"
                            @click="doAction('delete', 'Permanently delete this job record?')"
                            :disabled="!!acting">
                        <span v-if="acting === 'delete'"
                              class="spinner-border spinner-border-sm me-1"></span>
                        <i v-else class="fas fa-trash me-1"></i>Delete
                    </button>

                </div>

            </div>
        </div>
    `
};

export default JobTracker;