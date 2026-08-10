/**
 * aiRuleAnalysis.js — launch panel for the "AI Analysis" tab on /ia/admin.
 * Phase 1 of AI_RULE_ANALYSIS_PLAN.md: generate a detailed Markdown report
 * per rule via an admin-chosen local Ollama model. Tag/ATT&CK suggestion
 * (Phase 2/3 of the plan) are not implemented yet. Each run creates a new
 * RuleAiAnalysis row — history is kept, never overwritten in place.
 */
import RuleList     from '/static/js/rule/ruleList.js'
import AnsiTerminal from '/static/js/components/ansi-terminal.js'

const { ref, computed, onMounted, onUnmounted } = Vue

export default {
    name: 'AiRuleAnalysisPanel',
    delimiters: ['[[', ']]'],
    components: { 'rule-list': RuleList, 'ansi-terminal': AnsiTerminal },
    props: {
        csrfToken:                { type: String,  required: true },
        currentUserIsAuthenticated: { type: Boolean, default: true },
        currentUserIsAdmin:       { type: Boolean, default: true },
    },
    emits: ['notify'],

    setup(props, { emit }) {
        const regenerateExisting = ref(false)
        const defaultPublic      = ref(true)

        // ── Feature/model state (admin-managed, see /account/admin/ai_rule_analysis) ──
        const featureEnabled = ref(true)
        const modelsLoading  = ref(true)
        const models         = ref([])   // enabled model names only
        const selectedModel  = ref('')

        async function fetchModels() {
            modelsLoading.value = true
            try {
                const res = await fetch('/account/admin/ai_rule_analysis/models')
                const data = await res.json()
                if (data.success) {
                    featureEnabled.value = data.ai_rule_analysis_enabled
                    models.value = (data.models || []).filter(m => m.is_enabled).map(m => m.model_name)
                    if (models.value.length && !selectedModel.value) selectedModel.value = models.value[0]
                }
            } catch (e) {
                emit('notify', 'Could not load the model list: ' + e, 'danger-subtle')
            } finally {
                modelsLoading.value = false
            }
        }

        // ── Job tracking — same shape as FieldParserUpdater's own job state ──
        const running   = ref(false)
        const jobUuid   = ref(null)
        const jobStatus = ref('idle')
        const jobDone   = ref(0)
        const jobTotal  = ref(0)
        const jobPct    = computed(() => jobTotal.value > 0 ? Math.round(jobDone.value / jobTotal.value * 100) : 0)
        const jobLogs   = ref([])
        const lastLogId = ref(0)
        let pollTimer   = null

        const terminalEntries = computed(() =>
            jobLogs.value.map(l => ({ ts: l.created_at, level: l.level, msg: l.message }))
        )

        async function poll() {
            if (!jobUuid.value) return
            try {
                const [sRes, lRes] = await Promise.all([
                    fetch(`/jobs/status/${jobUuid.value}`),
                    fetch(`/jobs/logs/${jobUuid.value}?since_id=${lastLogId.value}`),
                ])
                const sData = await sRes.json()
                const lines = await lRes.json()

                jobStatus.value = sData.status || 'running'
                jobDone.value   = sData.done  ?? 0
                jobTotal.value  = sData.total ?? 0

                for (const log of lines) {
                    jobLogs.value.push(log)
                    lastLogId.value = Math.max(lastLogId.value, log.id)
                }
                if (jobLogs.value.length > 500) jobLogs.value = jobLogs.value.slice(-500)

                if (['done', 'failed', 'cancelled'].includes(jobStatus.value)) {
                    clearInterval(pollTimer); pollTimer = null
                    running.value = false
                    if (jobStatus.value === 'done')   emit('notify', 'AI analysis complete!', 'success-subtle')
                    if (jobStatus.value === 'failed') emit('notify', 'AI analysis job failed — see the log below.', 'danger-subtle')
                }
            } catch (e) { console.error('[AiRuleAnalysisPanel] poll error:', e) }
        }

        async function onSend(ids, filters) {
            if (running.value || !selectedModel.value) return
            running.value   = true
            jobLogs.value   = []
            lastLogId.value = 0
            jobUuid.value   = null
            jobStatus.value = 'pending'
            jobDone.value   = 0
            jobTotal.value  = 0

            try {
                const res = await fetch('/account/admin/bulk_parse_fields/trigger_ai_analysis', {
                    method:  'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrfToken },
                    body: JSON.stringify({
                        rule_ids:      ids,
                        format_filter: ids === 'ALL' ? (filters && filters.format) || null : null,
                        regenerate_existing: regenerateExisting.value,
                        default_public: defaultPublic.value,
                        model: selectedModel.value,
                    }),
                })
                const data = await res.json()
                if (!data.success || !data.job) {
                    emit('notify', data.message || 'Failed to start job', 'danger-subtle')
                    running.value = false
                    return
                }
                jobUuid.value   = data.job.uuid
                jobStatus.value = 'running'
                window.dispatchEvent(new Event('rz:job-created'))
                pollTimer = setInterval(poll, 2000)
                poll()
            } catch (e) {
                emit('notify', 'Network error: ' + e, 'danger-subtle')
                running.value = false
            }
        }

        function clearLogs() { jobLogs.value = [] }

        onMounted(fetchModels)
        onUnmounted(() => { if (pollTimer) clearInterval(pollTimer) })

        return {
            regenerateExisting, defaultPublic,
            featureEnabled, modelsLoading, models, selectedModel,
            running, jobUuid, jobStatus, jobDone, jobTotal, jobPct,
            terminalEntries, onSend, clearLogs,
        }
    },

    template: `
<div>

  <!-- Intro -->
  <div class="card border-0 shadow-sm rounded-4 mb-4">
    <div class="card-body p-4">
      <div class="d-flex align-items-start justify-content-between flex-wrap gap-3 mb-2">
        <div>
          <h6 class="fw-bold mb-1">
            <i class="fa-solid fa-robot me-2" style="color:#0d6efd;"></i>AI Rule Analysis
            <span class="badge bg-secondary-subtle text-secondary-emphasis ms-1" style="font-size:.65rem;">Phase 1 — summary only</span>
          </h6>
          <small class="text-muted">
            Generates a detailed, specialist-style English Markdown report per rule (overview, rule structure, detection logic, security implications, caveats) using a locally-hosted Ollama model — nothing leaves this server.
          </small>
        </div>
        <div class="d-flex gap-2">
          <a href="/rule/ai-analysis/how-it-works" target="_blank" class="btn btn-sm btn-outline-secondary rounded-pill px-3">
            <i class="fa-solid fa-circle-question me-1"></i>How it works
          </a>
        </div>
      </div>

      <div v-if="!modelsLoading && !featureEnabled" class="alert alert-secondary py-2 px-3 mb-3" style="font-size:.82rem;">
        <i class="fa-solid fa-circle-info me-1"></i>
        AI Rule Analysis is disabled instance-wide — enable it in the "Feature status" card above first.
      </div>
      <div v-else-if="!modelsLoading && !models.length" class="alert alert-secondary py-2 px-3 mb-3" style="font-size:.82rem;">
        <i class="fa-solid fa-circle-info me-1"></i>
        No models are enabled — enable one in the "Available models" card above first.
      </div>
      <template v-else>
        <div class="alert alert-warning py-2 px-3 mb-3" style="font-size:.82rem;">
          <i class="fa-solid fa-triangle-exclamation me-1"></i>
          This produces a genuinely detailed, multi-section report — a local model can take
          anywhere from tens of seconds to a few minutes per rule. Running this on
          <strong>all</strong> your rules can take a very long time (hours to days on a large
          instance). Try a small selection first to judge quality and timing.
        </div>

        <div class="row g-3">
          <div class="col-auto">
            <label class="form-label small mb-1">Model</label>
            <select class="form-select form-select-sm" v-model="selectedModel" :disabled="running" style="min-width:200px;">
              <option v-for="m in models" :key="m" :value="m">[[ m ]]</option>
            </select>
          </div>
          <div class="col-auto d-flex flex-column justify-content-end">
            <div class="form-check form-switch mb-1">
              <input class="form-check-input" type="checkbox" id="ai-regenerate-existing" v-model="regenerateExisting" :disabled="running">
              <label class="form-check-label" for="ai-regenerate-existing" style="font-size:.85rem;">
                Regenerate rules that already have an analysis (keeps history)
              </label>
            </div>
            <div class="form-check form-switch">
              <input class="form-check-input" type="checkbox" id="ai-default-public" v-model="defaultPublic" :disabled="running">
              <label class="form-check-label" for="ai-default-public" style="font-size:.85rem;">
                Make results public immediately
              </label>
            </div>
          </div>
        </div>
      </template>
    </div>
  </div>

  <!-- Rule selection -->
  <div v-if="!modelsLoading && featureEnabled && models.length" class="card border-0 shadow-sm rounded-4 mb-4">
    <div class="card-body p-4">
      <div class="d-flex align-items-center gap-2 mb-3">
        <div style="width:3px;height:14px;background:#0d6efd;border-radius:2px;flex-shrink:0;"></div>
        <span class="fw-bold" style="font-size:.75rem;text-transform:uppercase;letter-spacing:.07em;color:var(--subtle-text-color);">
          <i class="fa-solid fa-list-check me-1"></i>Select Rules
        </span>
      </div>
      <rule-list
          mode="select"
          default-view="table"
          fetch-url="/rule/data_table"
          :sync-url="false"
          :show-filters="true"
          :csrf-token="csrfToken"
          :current-user-is-authenticated="currentUserIsAuthenticated"
          :current-user-is-admin="currentUserIsAdmin"
          @send="onSend">
      </rule-list>
    </div>
  </div>

  <!-- Terminal / progress -->
  <div v-if="running || terminalEntries.length" class="card border-0 shadow-sm rounded-4 mb-4">
    <div class="card-body p-4">
      <div class="d-flex align-items-center gap-3 mb-3 flex-wrap">
        <div class="d-flex align-items-center gap-2">
          <i :class="jobStatus === 'running' ? 'fa-solid fa-spinner fa-spin text-primary' : (jobStatus === 'done' ? 'fa-solid fa-circle-check text-success' : (jobStatus === 'failed' ? 'fa-solid fa-circle-xmark text-danger' : 'fa-regular fa-circle text-muted'))" class="fs-5"></i>
          <span class="fw-semibold" style="color:var(--text-color);">[[ jobStatus ]]</span>
        </div>
        <div v-if="jobTotal > 0" class="flex-grow-1" style="min-width:200px;">
          <div class="d-flex justify-content-between small text-muted mb-1">
            <span>[[ jobDone ]] / [[ jobTotal ]] rules</span>
            <span>[[ jobPct ]]%</span>
          </div>
          <div class="progress rounded-pill" style="height:5px;">
            <div class="progress-bar bg-primary" :style="{ width: jobPct + '%' }"></div>
          </div>
        </div>
        <span v-if="jobUuid" class="ms-auto small font-monospace" style="color:#8b949e;font-size:.68rem;">[[ jobUuid ]]</span>
      </div>

      <ansi-terminal
          :entries="terminalEntries"
          :live="jobStatus === 'running' || jobStatus === 'pending'"
          :title="jobUuid ? 'job ' + jobUuid : 'Live log'"
          @clear="clearLogs">
      </ansi-terminal>
    </div>
  </div>

</div>
    `,
}
