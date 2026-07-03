/**
 * JobTracker
 * Polls job status + logs every 2s.
 * Shows a real-time activity feed with timestamps and level icons.
 * Supports pause, resume, cancel, delete.
 *
 * Usage:
 *   <job-tracker :job-uuid="uuid" @done="onDone" @failed="onFailed"></job-tracker>
 */
const JobTracker = {
    props: {
        jobUuid: { type: String, required: true },
        pollInterval: { type: Number, default: 2000 },
    },
    emits: ['done', 'failed', 'update', 'deleted'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const { ref, computed, onMounted, onUnmounted, nextTick } = Vue;

        const job = ref(null);
        const logs = ref([]);
        const loading = ref(true);
        const acting = ref(null);
        const logsRef = ref(null);  // ref to log container for auto-scroll
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

        // ── Log helpers ───────────────────────────────────────────────────────

        function logLevelColor(level) {
            return { info: 'text-muted', success: 'text-success', warning: 'text-warning', error: 'text-danger' }[level] || 'text-muted';
        }

        function logLevelIcon(level) {
            return { info: 'fas fa-circle-dot', success: 'fas fa-check-circle', warning: 'fas fa-triangle-exclamation', error: 'fas fa-times-circle' }[level] || 'fas fa-circle-dot';
        }

        function shortTime(ts) {
            if (!ts) return '';
            // ts = '2026-04-30 14:32:05' → '14:32:05'
            return ts.split(' ')[1] || ts;
        }

        async function scrollToBottom() {
            await nextTick();
            if (logsRef.value) {
                logsRef.value.scrollTop = logsRef.value.scrollHeight;
            }
        }

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
                    scrollToBottom();
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
            job, logs, loading, acting, logsRef,
            statusColor, statusIcon, isFinished,
            canPause, canResume, canCancel, canDelete,
            logLevelColor, logLevelIcon, shortTime,
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

                <!-- ── Progress bar ── -->
                <div v-if="['running', 'done', 'paused'].includes(job.status)" class="mb-3">
                    <div class="d-flex justify-content-between small mb-1"
                         style="color: var(--subtle-text-color)">
                        <span>[[ job.done.toLocaleString() ]] / [[ job.total.toLocaleString() ]] rules</span>
                        <span class="fw-semibold">[[ job.progress_pct ]]%</span>
                    </div>
                    <div class="progress" style="height:10px; border-radius:5px;">
                        <div class="progress-bar"
                             :class="[
                                job.status === 'running' ? 'progress-bar-animated progress-bar-striped' : '',
                                'bg-' + statusColor
                             ]"
                             :style="{ width: job.progress_pct + '%' }">
                        </div>
                    </div>
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

                <!-- ── Activity log feed ── -->
                <div v-if="logs.length > 0" class="mb-3">
                    <div class="d-flex align-items-center gap-1 mb-1"
                         style="font-size:0.72rem; color: var(--subtle-text-color); font-weight:600; text-transform:uppercase; letter-spacing:0.05em">
                        <i class="fas fa-list-ul me-1"></i>Activity
                    </div>
                    <div ref="logsRef"
                         class="rounded-3 p-2"
                         style="background: var(--code-bg-color);
                                max-height: 220px;
                                overflow-y: auto;
                                font-family: monospace;
                                font-size: 0.75rem;
                                line-height: 1.6;">
                        <div v-for="log in logs" :key="log.id"
                             class="d-flex gap-2 align-items-start">
                            <!-- timestamp -->
                            <span style="color: var(--subtle-text-color); flex-shrink:0; user-select:none">
                                [[ shortTime(log.created_at) ]]
                            </span>
                            <!-- level icon -->
                            <i :class="[logLevelIcon(log.level), logLevelColor(log.level)]"
                               style="flex-shrink:0; margin-top:3px; font-size:0.65rem"></i>
                            <!-- message -->
                            <span :class="logLevelColor(log.level)">[[ log.message ]]</span>
                        </div>
                    </div>
                </div>

                <!-- ── Action buttons ── -->
                <div class="d-flex gap-2 flex-wrap">

                    <button v-if="canPause"
                            class="btn btn-sm btn-outline-info flex-grow-1"
                            @click="doAction('pause')"
                            :disabled="!!acting">
                        <span v-if="acting === 'pause'"
                              class="spinner-border spinner-border-sm me-1"></span>
                        <i v-else class="fas fa-pause me-1"></i>Pause
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
                            class="btn btn-sm btn-outline-danger flex-grow-1"
                            @click="doAction('cancel', 'Stop this job? Progress so far will be kept.')"
                            :disabled="!!acting">
                        <span v-if="acting === 'cancel'"
                              class="spinner-border spinner-border-sm me-1"></span>
                        <i v-else class="fas fa-stop me-1"></i>Stop
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