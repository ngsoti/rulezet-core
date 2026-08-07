/**
 * BulkImportRunner.js
 * Generic "start a background job, watch it live" card — used for the
 * "Add all taxonomies" / "Add all galaxies" buttons. Same job-polling +
 * Live log pattern as MispUpdater.js, but single-step with a real numeric
 * progress bar (job.total/job.done = item count, not step count).
 */

const { ref, computed, watch, nextTick, onUnmounted } = Vue;

export default {
    name: 'BulkImportRunner',
    delimiters: ['[[', ']]'],
    props: {
        csrfToken:   { type: String, required: true },
        endpoint:    { type: String, required: true },   // POST route that queues the job
        title:       { type: String, required: true },
        description: { type: String, required: true },
        icon:        { type: String, default: 'fa-solid fa-download' },
        accentColor: { type: String, default: '#0d6efd' },
        buttonLabel: { type: String, default: 'Add All' },
        itemNoun:    { type: String, default: 'item' },
        // Merged as the POST body's JSON (e.g. { config_id: 3 }) — plain POST
        // with no body when omitted, unchanged from the original MISP usage.
        payload:     { type: Object, default: null },
        // External gate (e.g. "no valid config picked yet") — same idea as
        // the internal `running` disable, just driven by the parent instead.
        disabled:    { type: Boolean, default: false },
    },
    emits: ['notify', 'refresh-main'],
    setup(props, { emit }) {
        const running    = ref(false);
        const jobUuid     = ref(null);
        const jobStatus   = ref('idle');   // idle | pending | running | done | failed | cancelled
        const jobTotal    = ref(0);
        const jobDone     = ref(0);
        const jobPct      = ref(0);
        const allLogs     = ref([]);
        const lastLogId   = ref(0);
        const logBox      = ref(null);
        let   pollTimer   = null;

        watch(allLogs, () => {
            nextTick(() => {
                if (logBox.value) logBox.value.scrollTop = logBox.value.scrollHeight;
            });
        }, { deep: true });

        const isDone = computed(() => ['done', 'failed', 'cancelled'].includes(jobStatus.value));

        function levelClass(level) {
            if (level === 'success') return 'text-success';
            if (level === 'warning') return 'text-warning';
            if (level === 'error')   return 'text-danger';
            return 'text-muted';
        }
        function levelIcon(level) {
            if (level === 'success') return 'fa-solid fa-check';
            if (level === 'warning') return 'fa-solid fa-triangle-exclamation';
            if (level === 'error')   return 'fa-solid fa-xmark';
            return 'fa-solid fa-circle-dot';
        }

        function processNewLogs(entries) {
            for (const log of entries) {
                allLogs.value.push(log);
                lastLogId.value = Math.max(lastLogId.value, log.id);
            }
        }

        async function pollLogs() {
            if (!jobUuid.value) return;
            try {
                const sRes  = await fetch(`/jobs/status/${jobUuid.value}`);
                const sData = await sRes.json();
                jobStatus.value = sData.status || 'running';
                jobTotal.value  = sData.total || 0;
                jobDone.value   = sData.done || 0;
                jobPct.value    = sData.progress_pct || 0;

                const lRes  = await fetch(`/jobs/logs/${jobUuid.value}?since_id=${lastLogId.value}`);
                const lines = await lRes.json();
                if (lines.length) processNewLogs(lines);

                if (isDone.value) {
                    clearInterval(pollTimer);
                    pollTimer = null;
                    running.value = false;
                    if (jobStatus.value === 'done') {
                        emit('notify', `${props.title} complete!`, 'success-subtle');
                        emit('refresh-main');
                    }
                }
            } catch (e) {
                console.error('[BulkImportRunner] poll error:', e);
            }
        }

        async function start() {
            if (running.value || props.disabled) return;

            running.value   = true;
            allLogs.value    = [];
            lastLogId.value  = 0;
            jobUuid.value    = null;
            jobStatus.value  = 'pending';
            jobTotal.value   = 0;
            jobDone.value    = 0;
            jobPct.value     = 0;

            try {
                const fetchOpts = {
                    method: 'POST',
                    headers: { 'X-CSRFToken': props.csrfToken },
                };
                if (props.payload) {
                    fetchOpts.headers['Content-Type'] = 'application/json';
                    fetchOpts.body = JSON.stringify(props.payload);
                }
                const res  = await fetch(props.endpoint, fetchOpts);
                const data = await res.json();

                if (!data.success) {
                    emit('notify', data.message || 'Failed to start job', 'danger-subtle');
                    running.value = false;
                    return;
                }

                jobUuid.value   = data.job.uuid;
                jobStatus.value = 'running';

                pollTimer = setInterval(pollLogs, 2000);
                pollLogs();
            } catch (e) {
                emit('notify', 'Network error: ' + e, 'danger-subtle');
                running.value = false;
            }
        }

        onUnmounted(() => { if (pollTimer) clearInterval(pollTimer); });

        return {
            running, jobUuid, jobStatus, jobTotal, jobDone, jobPct,
            allLogs, logBox, isDone, levelClass, levelIcon, start,
        };
    },

    template: `
<div class="card border-0 shadow-sm rounded-4">
  <div class="card-body p-4">

    <!-- Header -->
    <div class="d-flex align-items-start justify-content-between mb-3 flex-wrap gap-3">
      <div>
        <h6 class="fw-bold mb-1">
          <i :class="icon" class="me-2" :style="'color:' + accentColor"></i>[[ title ]]
        </h6>
        <small class="text-muted">[[ description ]]</small>
      </div>
      <button @click="start" :disabled="running || disabled"
              class="btn fw-semibold px-4 text-white"
              :style="'background:' + accentColor + ';border-color:' + accentColor">
        <i class="fa-solid me-2" :class="running ? 'fa-spinner fa-spin' : 'fa-play'"></i>
        [[ running ? 'Running…' : buttonLabel ]]
      </button>
    </div>

    <!-- Progress bar — only once the job has reported a total -->
    <div v-if="jobUuid && jobTotal > 0" class="mb-3">
      <div class="progress" style="height:8px;">
        <div class="progress-bar" role="progressbar"
             :style="'width:' + jobPct + '%;background:' + accentColor"></div>
      </div>
      <div class="d-flex justify-content-between mt-1">
        <small class="text-muted">[[ jobDone ]] / [[ jobTotal ]] [[ itemNoun ]](s) processed</small>
        <small class="text-muted">[[ jobPct ]]%</small>
      </div>
    </div>

    <!-- Live log feed -->
    <template v-if="allLogs.length > 0">
      <div class="d-flex align-items-center justify-content-between mb-2">
        <span class="fw-semibold small text-muted">
          <i class="fa-solid fa-terminal me-1"></i>Live log
        </span>
        <span v-if="jobUuid" class="text-muted" style="font-size:.7rem;">
          job <code>[[ jobUuid ]]</code>
        </span>
      </div>
      <div class="border rounded-3 p-2"
           style="max-height:300px;overflow-y:auto;background:var(--card-bg-color,#f8f9fa);scroll-behavior:smooth;"
           ref="logBox">
        <div v-for="log in allLogs" :key="log.id"
             class="d-flex align-items-start gap-2 mb-1 small">
          <span class="text-muted text-nowrap" style="font-size:.65rem;min-width:125px;">[[ log.created_at ]]</span>
          <i :class="[levelIcon(log.level), levelClass(log.level)]" style="font-size:.65rem;margin-top:3px;"></i>
          <span :class="levelClass(log.level)" style="font-size:.75rem;white-space:pre-wrap;word-break:break-word;">[[ log.message ]]</span>
        </div>
      </div>
    </template>

    <!-- Idle placeholder -->
    <div v-else class="text-center py-3 text-muted">
      <i :class="icon" class="fa-2x mb-2 d-block opacity-25"></i>
      <small>Click <strong>[[ buttonLabel ]]</strong> to import every [[ itemNoun ]] found on disk — already-imported ones are skipped automatically.</small>
    </div>

  </div>
</div>
    `,
};
