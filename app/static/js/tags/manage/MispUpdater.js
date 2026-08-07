/**
 * MispUpdater.js
 * Admin component — update MISP taxonomies & galaxies in 3 steps.
 *
 * Step 1 : git pull both submodules
 * Step 2 : bulk-import all taxonomies  (skip existing)
 * Step 3 : bulk-import all galaxies    (skip existing)
 *
 * Polls /jobs/logs/<uuid> every 2 s and maps log events to the 3 steps.
 */

import AnsiTerminal from '/static/js/components/ansi-terminal.js';

const { ref, computed, onUnmounted } = Vue;

// ── helpers ──────────────────────────────────────────────────────────────────

const STEP_EVENTS = {
    1: ['step1_start', 'step1_tax_pull', 'step1_gal_pull', 'step1_done'],
    2: ['step2_start', 'step2_progress', 'step2_done'],
    3: ['step3_start', 'step3_progress', 'step3_done'],
};

function stepFromEvent(event) {
    for (const [step, events] of Object.entries(STEP_EVENTS)) {
        if (events.includes(event)) return Number(step);
    }
    return null;
}

function parseSummary(logs, step) {
    const doneEvent = `step${step}_done`;
    const entry = [...logs].reverse().find(l => l.event === doneEvent);
    return entry ? entry.message : null;
}

// ── component ─────────────────────────────────────────────────────────────────

export default {
    name: 'MispUpdater',
    delimiters: ['[[', ']]'],
    components: { AnsiTerminal },
    props: {
        csrfToken: { type: String, required: true },
    },
    emits: ['notify', 'refresh-main'],
    setup(props, { emit }) {
        const running      = ref(false);
        const jobUuid      = ref(null);
        const jobStatus    = ref('idle');   // idle | pending | running | done | failed | cancelled
        const allLogs      = ref([]);
        const lastLogId    = ref(0);
        const activeStep   = ref(0);        // 1 | 2 | 3  (current running step)
        const stepStatus   = ref({ 1: 'idle', 2: 'idle', 3: 'idle' });
        const gitOutputTax = ref('');
        const gitOutputGal = ref('');
        let   pollTimer    = null;

        // ── computed ──────────────────────────────────────────────────────────
        const terminalEntries = computed(() =>
            allLogs.value.map(l => ({ ts: l.created_at, level: l.level, msg: l.message }))
        );
        const gitOutputTaxLines = computed(() => gitOutputTax.value ? gitOutputTax.value.split('\n') : []);
        const gitOutputGalLines = computed(() => gitOutputGal.value ? gitOutputGal.value.split('\n') : []);
        const step1Logs = computed(() => allLogs.value.filter(l => stepFromEvent(l.event) === 1));
        const step2Logs = computed(() => allLogs.value.filter(l => stepFromEvent(l.event) === 2));
        const step3Logs = computed(() => allLogs.value.filter(l => stepFromEvent(l.event) === 3));

        const step2Summary = computed(() => parseSummary(allLogs.value, 2));
        const step3Summary = computed(() => parseSummary(allLogs.value, 3));

        const isDone = computed(() =>
            ['done', 'failed', 'cancelled'].includes(jobStatus.value)
        );

        // ── styling helpers ───────────────────────────────────────────────────
        function stepClass(step) {
            const s = stepStatus.value[step];
            if (s === 'running') return 'border-primary text-primary';
            if (s === 'done')    return 'border-success text-success';
            if (s === 'error')   return 'border-danger text-danger';
            return 'border-secondary text-muted';
        }
        function stepIcon(step) {
            const s = stepStatus.value[step];
            if (s === 'running') return 'fa-solid fa-spinner fa-spin';
            if (s === 'done')    return 'fa-solid fa-circle-check';
            if (s === 'error')   return 'fa-solid fa-circle-xmark';
            return 'fa-regular fa-circle';
        }
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

        // ── log parsing ───────────────────────────────────────────────────────
        function processNewLogs(entries) {
            for (const log of entries) {
                allLogs.value.push(log);
                lastLogId.value = Math.max(lastLogId.value, log.id);

                const step = stepFromEvent(log.event);

                if (log.event === 'step1_start') {
                    stepStatus.value[1] = 'running';
                    activeStep.value = 1;
                }
                if (log.event === 'step1_tax_pull') gitOutputTax.value = log.message.replace(/^misp-taxonomies:\s*/, '');
                if (log.event === 'step1_gal_pull') gitOutputGal.value = log.message.replace(/^misp-galaxy:\s*/, '');
                if (log.event === 'step1_done') {
                    stepStatus.value[1] = 'done';
                }

                if (log.event === 'step2_start') {
                    stepStatus.value[2] = 'running';
                    activeStep.value = 2;
                }
                if (log.event === 'step2_done') stepStatus.value[2] = 'done';

                if (log.event === 'step3_start') {
                    stepStatus.value[3] = 'running';
                    activeStep.value = 3;
                }
                if (log.event === 'step3_done') stepStatus.value[3] = 'done';

                if (log.event === 'done') {
                    emit('refresh-main');
                }
                if (log.event === 'error') {
                    if (step) stepStatus.value[step] = 'error';
                }
            }
        }

        // ── polling ───────────────────────────────────────────────────────────
        async function pollLogs() {
            if (!jobUuid.value) return;
            try {
                // fetch job status
                const sRes  = await fetch(`/jobs/status/${jobUuid.value}`);
                const sData = await sRes.json();
                jobStatus.value = sData.status || 'running';

                // fetch new log lines
                const lRes  = await fetch(`/jobs/logs/${jobUuid.value}?since_id=${lastLogId.value}`);
                const lines = await lRes.json();
                if (lines.length) processNewLogs(lines);

                if (isDone.value) {
                    clearInterval(pollTimer);
                    pollTimer = null;
                    running.value = false;
                    if (jobStatus.value === 'done') {
                        emit('notify', { message: 'MISP update complete!', level: 'success' });
                    }
                }
            } catch (e) {
                console.error('[MispUpdater] poll error:', e);
            }
        }

        // ── start job ─────────────────────────────────────────────────────────
        async function startUpdate() {
            if (running.value) return;

            // reset state
            running.value     = true;
            allLogs.value     = [];
            lastLogId.value   = 0;
            jobUuid.value     = null;
            jobStatus.value   = 'pending';
            activeStep.value  = 0;
            gitOutputTax.value = '';
            gitOutputGal.value = '';
            stepStatus.value  = { 1: 'idle', 2: 'idle', 3: 'idle' };

            try {
                const res  = await fetch('/tags/admin/update_misp', {
                    method: 'POST',
                    headers: { 'X-CSRFToken': props.csrfToken },
                });
                const data = await res.json();

                if (!data.success) {
                    emit('notify', { message: data.message || 'Failed to start job', level: 'error' });
                    running.value = false;
                    return;
                }

                jobUuid.value   = data.job.uuid;
                jobStatus.value = 'running';

                // start polling every 2 s
                pollTimer = setInterval(pollLogs, 2000);
                pollLogs(); // immediate first call
            } catch (e) {
                emit('notify', { message: 'Network error: ' + e, level: 'error' });
                running.value = false;
            }
        }

        onUnmounted(() => { if (pollTimer) clearInterval(pollTimer); });

        return {
            running, jobUuid, jobStatus, allLogs, activeStep, stepStatus,
            gitOutputTax, gitOutputGal, isDone, logBox,
            step1Logs, step2Logs, step3Logs, step2Summary, step3Summary,
            stepClass, stepIcon, levelClass, levelIcon, startUpdate,
        };
    },

    template: `
<div class="card border-0 shadow-sm rounded-4">
  <div class="card-body p-4">

    <!-- Header -->
    <div class="d-flex align-items-start justify-content-between mb-4 flex-wrap gap-3">
      <div>
        <h6 class="fw-bold mb-1">
          <i class="fa-solid fa-rotate me-2 text-primary"></i>Update MISP Data
        </h6>
        <small class="text-muted">
          Pulls the latest commits from <code>misp-taxonomies</code> and <code>misp-galaxy</code>
          submodules, then re-imports everything — existing entries are skipped automatically.
        </small>
      </div>
      <button @click="startUpdate" :disabled="running"
              class="btn btn-primary fw-semibold px-4">
        <i class="fa-solid me-2" :class="running ? 'fa-spinner fa-spin' : 'fa-play'"></i>
        [[ running ? 'Running…' : 'Start Update' ]]
      </button>
    </div>

    <!-- 3 step indicators -->
    <div class="row g-3 mb-4">

      <!-- Step 1 -->
      <div class="col-md-4">
        <div class="border rounded-3 p-3 h-100" :class="stepClass(1)">
          <div class="d-flex align-items-center gap-2 mb-2">
            <i :class="stepIcon(1)" class="fs-5"></i>
            <span class="fw-semibold small">Step 1 — Git Pull</span>
          </div>
          <p class="text-muted small mb-2">Pull latest data from GitHub for both submodules.</p>

          <!-- Git output collapsibles -->
          <template v-if="gitOutputTax || gitOutputGal">
            <details class="mb-1">
              <summary class="small text-muted" style="cursor:pointer;">
                <code>misp-taxonomies</code>
              </summary>
              <pre class="mt-1 p-2 rounded small" style="background:var(--card-bg-color,#f8f9fa);max-height:120px;overflow:auto;font-size:.7rem;white-space:pre-wrap;">[[ gitOutputTax ]]</pre>
            </details>
            <details>
              <summary class="small text-muted" style="cursor:pointer;">
                <code>misp-galaxy</code>
              </summary>
              <pre class="mt-1 p-2 rounded small" style="background:var(--card-bg-color,#f8f9fa);max-height:120px;overflow:auto;font-size:.7rem;white-space:pre-wrap;">[[ gitOutputGal ]]</pre>
            </details>
          </template>
          <p v-else class="text-muted small mb-0 fst-italic">Not started yet.</p>
        </div>
      </div>

      <!-- Step 2 -->
      <div class="col-md-4">
        <div class="border rounded-3 p-3 h-100" :class="stepClass(2)">
          <div class="d-flex align-items-center gap-2 mb-2">
            <i :class="stepIcon(2)" class="fs-5"></i>
            <span class="fw-semibold small">Step 2 — Taxonomies</span>
          </div>
          <p class="text-muted small mb-2">Import all taxonomy namespaces, skip existing ones.</p>
          <template v-if="step2Summary">
            <span class="badge bg-success-subtle text-success small">[[ step2Summary ]]</span>
          </template>
          <div v-else-if="stepStatus[2] === 'running'" class="text-muted small">
            <i class="fa-solid fa-spinner fa-spin me-1"></i>
            [[ step2Logs.filter(l => l.event === 'step2_progress').length ]] processed…
          </div>
          <p v-else class="text-muted small mb-0 fst-italic">Waiting for step 1…</p>
        </div>
      </div>

      <!-- Step 3 -->
      <div class="col-md-4">
        <div class="border rounded-3 p-3 h-100" :class="stepClass(3)">
          <div class="d-flex align-items-center gap-2 mb-2">
            <i :class="stepIcon(3)" class="fs-5"></i>
            <span class="fw-semibold small">Step 3 — Galaxies</span>
          </div>
          <p class="text-muted small mb-2">Import all galaxy clusters, skip existing ones.</p>
          <template v-if="step3Summary">
            <span class="badge bg-success-subtle text-success small">[[ step3Summary ]]</span>
          </template>
          <div v-else-if="stepStatus[3] === 'running'" class="text-muted small">
            <i class="fa-solid fa-spinner fa-spin me-1"></i>
            [[ step3Logs.filter(l => l.event === 'step3_progress').length ]] processed…
          </div>
          <p v-else class="text-muted small mb-0 fst-italic">Waiting for step 2…</p>
        </div>
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
    <div v-else class="text-center py-4 text-muted">
      <i class="fa-solid fa-rotate fa-2x mb-2 d-block opacity-25"></i>
      <small>Click <strong>Start Update</strong> to pull the latest MISP data and re-import everything.</small>
    </div>

  </div>
</div>
    `,
};
