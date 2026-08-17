/**
 * ValidationRunner.js
 * Tag Manager / Admin component — runs rulezet-validation's false-positive
 * gate: pulls this instance's rules, scans them against a known-clean
 * binary baseline, and quarantines anything that fires.
 *
 * Launches 'rule_validation_run' (job_handlers.py), streams its log like a
 * terminal while it runs, then renders the quarantined-rule result and lets
 * the user bulk-tag the flagged rules via the existing 'bulk_add_tag_to_rules'
 * job — reusing JobTracker for that second job instead of re-polling by hand.
 */

import JobTracker  from '/static/js/jobs/JobTracker.js';
import AnsiTerminal from '/static/js/components/ansi-terminal.js';

const { ref, computed, onUnmounted } = Vue;

export default {
    name: 'ValidationRunner',
    delimiters: ['[[', ']]'],
    components: { JobTracker, AnsiTerminal },
    props: {
        csrfToken: { type: String, required: true },
    },
    emits: ['notify'],
    setup(props, { emit }) {
        // ── Launch options ──────────────────────────────────────────────────
        const fullSync = ref(false);
        const limit    = ref(null);

        // ── Validation job state ────────────────────────────────────────────
        const running     = ref(false);
        const jobUuid      = ref(null);
        const jobStatus    = ref('idle');   // idle | pending | running | done | failed | cancelled
        const allLogs      = ref([]);
        const lastLogId    = ref(0);
        const quarantined  = ref([]);
        let   pollTimer    = null;

        const isDone = computed(() => ['done', 'failed', 'cancelled'].includes(jobStatus.value));

        // ansi-terminal wants {ts, level, msg} — the job log API returns
        // {id, level, event, message, created_at}.
        const terminalEntries = computed(() =>
            allLogs.value.map(l => ({ ts: l.created_at, level: l.level, msg: l.message }))
        );
        function clearLogs() { allLogs.value = []; }

        // ── Fetch the parsed result once the job is done ───────────────────
        async function loadResult() {
            const res = await fetch(`/jobs/api/${jobUuid.value}`);
            const data = await res.json();
            if (res.ok) {
                quarantined.value = (data.meta && data.meta.result && data.meta.result.quarantined) || [];
            }
        }

        async function pollLogs() {
            if (!jobUuid.value) return;
            try {
                const sRes  = await fetch(`/jobs/status/${jobUuid.value}`);
                const sData = await sRes.json();
                jobStatus.value = sData.status || 'running';

                const lRes  = await fetch(`/jobs/logs/${jobUuid.value}?since_id=${lastLogId.value}`);
                const lines = await lRes.json();
                if (lines.length) {
                    allLogs.value.push(...lines);
                    lastLogId.value = lines[lines.length - 1].id;
                }

                if (isDone.value) {
                    clearInterval(pollTimer);
                    pollTimer = null;
                    running.value = false;
                    await loadResult();
                    if (jobStatus.value === 'done') {
                        emit('notify', { message: `Validation done — ${quarantined.value.length} rule(s) quarantined.`, level: 'success' });
                    } else {
                        emit('notify', { message: 'Validation run did not complete.', level: 'error' });
                    }
                }
            } catch (e) {
                console.error('[ValidationRunner] poll error:', e);
            }
        }

        async function startRun() {
            if (running.value) return;

            running.value     = true;
            allLogs.value      = [];
            lastLogId.value    = 0;
            jobUuid.value      = null;
            jobStatus.value    = 'pending';
            quarantined.value  = [];

            try {
                const res = await fetch('/tags/admin/validation/launch', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrfToken },
                    body: JSON.stringify({ full: fullSync.value, limit: limit.value || null }),
                });
                const data = await res.json();
                if (!data.success) {
                    emit('notify', { message: data.message || 'Failed to start validation run', level: 'error' });
                    running.value = false;
                    return;
                }
                jobUuid.value   = data.job.uuid;
                jobStatus.value = 'running';
                pollTimer = setInterval(pollLogs, 2000);
                pollLogs();
            } catch (e) {
                emit('notify', { message: 'Network error: ' + e, level: 'error' });
                running.value = false;
            }
        }

        onUnmounted(() => { if (pollTimer) clearInterval(pollTimer); });

        // ── Result selection + tag picker ───────────────────────────────────
        const selectedUuids = ref(new Set());
        const allSelected    = computed(() =>
            quarantined.value.length > 0 && selectedUuids.value.size === quarantined.value.length
        );
        function toggleSelectAll() {
            selectedUuids.value = allSelected.value
                ? new Set()
                : new Set(quarantined.value.map(q => q.uuid));
        }
        function toggleRow(uuid) {
            const s = new Set(selectedUuids.value);
            s.has(uuid) ? s.delete(uuid) : s.add(uuid);
            selectedUuids.value = s;
        }

        const allTags      = ref([]);
        const selectedTags = ref([]);
        const tagSearch    = ref('');
        const filteredTagList = computed(() => {
            const q = tagSearch.value.toLowerCase();
            return allTags.value
                .filter(t => !selectedTags.value.some(s => s.id === t.id))
                .filter(t => t.name.toLowerCase().includes(q))
                .slice(0, 40);
        });
        function toggleTagSelection(t) {
            const i = selectedTags.value.findIndex(s => s.id === t.id);
            i === -1 ? selectedTags.value.push(t) : selectedTags.value.splice(i, 1);
        }
        function deselectTag(id) {
            selectedTags.value = selectedTags.value.filter(t => t.id !== id);
        }
        async function loadTags() {
            const res  = await fetch('/tags/get_all_tags');
            const data = await res.json();
            if (res.ok) allTags.value = data.tags || [];
        }

        // ── Bulk-tag the selected quarantined rules ─────────────────────────
        const tagJobUuid = ref(null);
        const tagging     = ref(false);

        async function applyTags() {
            if (tagging.value || selectedUuids.value.size === 0 || selectedTags.value.length === 0) return;
            tagging.value = true;
            const ruleIds = quarantined.value
                .filter(q => selectedUuids.value.has(q.uuid) && q.rule_id)
                .map(q => q.rule_id);
            try {
                const res = await fetch('/jobs/create', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrfToken },
                    body: JSON.stringify({
                        job_type: 'bulk_add_tag_to_rules',
                        payload:  { tag_ids: selectedTags.value.map(t => t.id), filters: { rule_ids: ruleIds } },
                        label:    `Tag ${ruleIds.length} quarantined rule(s) with ${selectedTags.value.map(t => t.name).join(', ')}`,
                    }),
                });
                const data = await res.json();
                if (res.ok) {
                    tagJobUuid.value = data.job.uuid;
                } else {
                    emit('notify', { message: data.error || 'Failed to launch bulk tag job', level: 'error' });
                }
            } finally {
                tagging.value = false;
            }
        }

        return {
            fullSync, limit, running, jobUuid, jobStatus, isDone,
            terminalEntries, clearLogs, startRun, quarantined,
            selectedUuids, allSelected, toggleSelectAll, toggleRow,
            allTags, selectedTags, tagSearch, filteredTagList, toggleTagSelection, deselectTag, loadTags,
            tagJobUuid, tagging, applyTags,
        };
    },

    template: `
<div>
  <!-- Launch card -->
  <div class="card border-0 shadow-sm rounded-4 mb-3">
    <div class="card-body p-4">
      <div class="d-flex align-items-start justify-content-between mb-3 flex-wrap gap-3">
        <div>
          <h6 class="fw-bold mb-1">
            <i class="fa-solid fa-shield-virus me-2 text-primary"></i>Run Validation
          </h6>
          <small class="text-muted">
            Pulls this instance's rules, scans them against a known-clean binary
            baseline, and quarantines anything that fires — a false-positive gate
            powered by <code>rulezet-validation</code>.
          </small>
        </div>
        <button @click="startRun" :disabled="running" class="btn btn-primary fw-semibold px-4">
          <i class="fa-solid me-2" :class="running ? 'fa-spinner fa-spin' : 'fa-play'"></i>
          [[ running ? 'Running…' : 'Start Validation' ]]
        </button>
      </div>

      <div class="d-flex flex-wrap gap-4 align-items-center mb-1" v-if="!running && jobStatus === 'idle'">
        <div class="form-check form-switch">
          <input class="form-check-input" type="checkbox" id="full-sync-switch" v-model="fullSync">
          <label class="form-check-label small" for="full-sync-switch">
            Full re-sync <span class="text-muted">(ignore last-sync date)</span>
          </label>
        </div>
        <div class="d-flex align-items-center gap-2">
          <label class="small text-muted mb-0" for="limit-input">Limit</label>
          <input id="limit-input" type="number" min="1" class="form-control form-control-sm" style="width:110px"
                 v-model.number="limit" placeholder="trial run">
        </div>
      </div>

      <!-- Live log — real terminal component, same one used on the job detail page -->
      <div v-if="terminalEntries.length > 0" class="mt-3">
        <ansi-terminal
            :entries="terminalEntries"
            :live="!isDone"
            title="Rule validation"
            @clear="clearLogs">
        </ansi-terminal>
      </div>
    </div>
  </div>

  <!-- Results card -->
  <div v-if="isDone && quarantined.length > 0" class="card border-0 shadow-sm rounded-4">
    <div class="card-body p-4">
      <h6 class="fw-bold mb-3">
        <i class="fa-solid fa-triangle-exclamation me-2 text-warning"></i>
        [[ quarantined.length ]] rule(s) quarantined
      </h6>

      <div class="table-responsive mb-3" style="max-height:320px;overflow-y:auto;">
        <table class="table table-sm align-middle mb-0">
          <thead>
            <tr>
              <th style="width:32px;"><input type="checkbox" :checked="allSelected" @change="toggleSelectAll"></th>
              <th>Rule</th>
              <th class="text-end">Hits</th>
              <th>First seen</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="q in quarantined" :key="q.uuid">
              <td><input type="checkbox" :checked="selectedUuids.has(q.uuid)" @change="toggleRow(q.uuid)"></td>
              <td>
                <a v-if="q.rule_id" :href="'/rule/detail_rule/' + q.rule_id" target="_blank" class="text-decoration-none">[[ q.title ]]</a>
                <span v-else class="text-muted">[[ q.title ]] <em>(not found locally)</em></span>
                <div class="text-muted" style="font-size:.7rem;font-family:monospace;">[[ q.uuid ]]</div>
              </td>
              <td class="text-end">[[ q.hits ]]</td>
              <td class="text-muted small">[[ q.first_seen ]]</td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Tag picker -->
      <div class="rounded-3 p-3 mb-3" style="background: var(--light-bg-color);">
        <div class="input-group input-group-sm mb-2">
          <span class="input-group-text bg-transparent border-end-0"><i class="fas fa-search text-muted"></i></span>
          <input type="text" class="form-control border-start-0" v-model="tagSearch"
                 @focus="allTags.length === 0 && loadTags()" placeholder="Search tags to apply…">
        </div>
        <div v-if="selectedTags.length > 0" class="d-flex flex-wrap gap-1 mb-2">
          <span v-for="tag in selectedTags" :key="tag.id" class="badge d-flex align-items-center gap-1 px-2"
                :style="{ backgroundColor: tag.color }">
            [[ tag.name ]]
            <i class="fas fa-times ms-1" style="cursor:pointer;font-size:.65rem" @click="deselectTag(tag.id)"></i>
          </span>
        </div>
        <div v-if="tagSearch" style="max-height:140px;overflow-y:auto;">
          <div v-for="tag in filteredTagList" :key="tag.id"
               class="d-flex align-items-center gap-2 p-1 rounded-2"
               style="cursor:pointer;" @click="toggleTagSelection(tag); tagSearch=''">
            <span class="rounded-circle flex-shrink-0" :style="{ background: tag.color, width:'10px', height:'10px' }"></span>
            <span class="small">[[ tag.name ]]</span>
          </div>
        </div>
      </div>

      <button class="btn btn-primary fw-bold rounded-pill px-4"
              :disabled="tagging || selectedUuids.size === 0 || selectedTags.length === 0"
              @click="applyTags">
        <span v-if="tagging" class="spinner-border spinner-border-sm me-2"></span>
        <i v-else class="fas fa-tag me-2"></i>
        Tag [[ selectedUuids.size ]] selected rule(s)
      </button>

      <div v-if="tagJobUuid" class="mt-3 border rounded-3 p-3">
        <job-tracker :job-uuid="tagJobUuid"></job-tracker>
      </div>
    </div>
  </div>

  <!-- Idle placeholder -->
  <div v-if="jobStatus === 'idle'" class="text-center py-4 text-muted">
    <i class="fa-solid fa-shield-virus fa-2x mb-2 d-block opacity-25"></i>
    <small>Click <strong>Start Validation</strong> to check every rule against the known-clean baseline.</small>
  </div>
</div>
    `,
};
