/**
 * bulkParseFields.js — Admin bulk field parser component.
 * Manages config building, saved configs, rule selection and live job terminal.
 */
import RuleList                  from '/static/js/rule/ruleList.js'
import TagsDisplaysList          from '/static/js/tags/tagsDisplaysList.js'
import VulnerabilityDisplaysList from '/static/js/vulnerability/vulnerabilityDisplayList.js'
import CodeViewer                from '/static/js/components/code-viewer.js'
import SmartEditor               from '/static/js/components/smart-editor.js'

const { ref, reactive, computed, onMounted, onUnmounted, nextTick } = Vue;

// Several actions (opening the tester, running a test, collapsing the editor)
// change the height of content above/around the click target, which can make
// the browser shift scroll position. Pin it back to where the user was.
async function withScrollPreserved(fn) {
    const y = window.scrollY;
    await fn();
    await nextTick();
    window.scrollTo({ top: y });
}

const FIELD_COLORS = {
    license:       '#0d6efd',
    author:        '#6f42c1',
    original_uuid: '#e67e22',
    description:   '#198754',
    version:       '#dc3545',
    title:         '#20c997',
};

function levelColor(l) {
    if (l === 'success') return '#3fb950';
    if (l === 'warning') return '#d29922';
    if (l === 'error')   return '#f85149';
    return '#8b949e';
}
function levelPrefix(l) {
    if (l === 'success') return '[OK]  ';
    if (l === 'warning') return '[WARN]';
    if (l === 'error')   return '[ERR] ';
    return '[INFO]';
}
function statusIcon(s) {
    if (s === 'running') return 'fa-solid fa-spinner fa-spin text-primary';
    if (s === 'done')    return 'fa-solid fa-circle-check text-success';
    if (s === 'failed' || s === 'cancelled') return 'fa-solid fa-circle-xmark text-danger';
    return 'fa-regular fa-circle text-muted';
}

const FieldParserUpdater = {
    name: 'FieldParserUpdater',
    delimiters: ['[[', ']]'],
    components: {
        'rule-list':                   RuleList,
        'tags-displays-list':          TagsDisplaysList,
        'vulnerability-displays-list': VulnerabilityDisplaysList,
        'code-viewer':                 CodeViewer,
        'smart-editor':                SmartEditor,
    },
    props: {
        csrfToken:      { type: String,  required: true },
        fieldMeta:      { type: Object,  default: () => ({}) },
        parseableFields:{ type: Array,   default: () => [] },
    },
    emits: ['notify'],

    setup(props, { emit }) {
        // ── Selected rules ────────────────────────────────────────────────
        const selectedIds    = ref([]);
        const selectionMode  = ref('ALL');   // 'ALL' | 'selection'
        const selectionCount = ref(0);
        const allWarning     = ref(false);   // shown when RuleList sends 'ALL'

        // Format filter — only used when selectionMode === 'ALL'
        const formatFilter = ref('');
        const availableFormats = ref([]);

        async function fetchFormats() {
            try {
                const res  = await fetch('/rule/get_rules_formats');
                const data = await res.json();
                availableFormats.value = (data.formats || []).map(f => typeof f === 'string' ? f : f.name);
            } catch { /* silent */ }
        }

        function onSend(ids, filters) {
            if (enabledCount.value === 0) {
                emit('notify', 'Enable at least one field before confirming.');
                return;
            }
            if (ids === 'ALL') {
                selectionMode.value  = 'ALL';
                selectionCount.value = 0;
                formatFilter.value   = (filters && filters.format) ? filters.format : '';
            } else {
                selectionMode.value  = 'selection';
                selectedIds.value    = ids;
                selectionCount.value = ids.length;
                formatFilter.value   = '';
            }
            runJob();
        }

        // ── Field configs ─────────────────────────────────────────────────
        // Each field: { enabled, keywords (comma-string), regex, overwrite }
        const fieldConfigs = reactive({});

        function initFieldConfigs() {
            props.parseableFields.forEach(key => {
                const meta = props.fieldMeta[key] || {};
                fieldConfigs[key] = {
                    enabled:   false,
                    keywords:  (meta.default_keywords || []).join(', '),
                    regex:     '',
                    overwrite: false,
                };
            });
        }

        function buildPayloadConfig() {
            const out = {};
            props.parseableFields.forEach(key => {
                const fc = fieldConfigs[key];
                out[key] = {
                    enabled:   fc.enabled,
                    keywords:  fc.keywords.split(',').map(k => k.trim()).filter(Boolean),
                    regex:     fc.regex.trim(),
                    overwrite: fc.overwrite,
                };
            });
            return out;
        }

        // ── CVE / vulnerability re-scan ──────────────────────────────────────
        // Not keyword/regex-based like the other fields: scans the FULL rule
        // content with the same detect_cve() pattern used at rule creation, and
        // MERGES any newly found identifiers into the existing list — it never
        // overwrites or removes a CVE a rule already has.
        const cveRescanEnabled = ref(false);

        const enabledCount = computed(() =>
            props.parseableFields.filter(k => fieldConfigs[k]?.enabled).length
            + (cveRescanEnabled.value ? 1 : 0)
        );

        // ── Extraction tester (per field) ────────────────────────────────────
        // Runs the EXACT same server-side function the job uses
        // (parse_field_from_content — keyword mode OR regex mode, whichever
        // the field is currently configured with), so "does it work?" always
        // reflects reality instead of a separate/disconnected regex-only preview.
        const testerOpen     = reactive({});
        const testContent    = reactive({});
        const testResult     = reactive({});   // { loading, mode, value, error, matchStart, matchEnd }
        const testCollapsed  = reactive({});   // true once a test has run — hides the editor, shows the highlighted preview

        function toggleTester(key) {
            withScrollPreserved(() => { testerOpen[key] = !testerOpen[key]; });
        }

        function editTest(key) {
            withScrollPreserved(() => { testCollapsed[key] = false; });
        }

        // Manual only — triggered solely by the "Run test" buttons (top & bottom
        // of the editor), never automatically while typing.
        function runExtractionTest(key) {
            withScrollPreserved(async () => {
                const fc = fieldConfigs[key];
                testResult[key] = { ...(testResult[key] || {}), loading: true, error: false };
                try {
                    const res = await fetch('/account/admin/bulk_parse_fields/test_extract', {
                        method:  'POST',
                        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrfToken },
                        body: JSON.stringify({
                            content:  testContent[key] || '',
                            keywords: fc.keywords.split(',').map(k => k.trim()).filter(Boolean),
                            regex:    fc.regex.trim(),
                        }),
                    });
                    const data = await res.json();
                    testResult[key] = {
                        loading: false, error: !data.success, mode: data.mode, value: data.value,
                        matchStart: data.match_start, matchEnd: data.match_end,
                    };
                } catch (e) {
                    testResult[key] = { loading: false, error: true, mode: null, value: null, matchStart: null, matchEnd: null };
                }
                testCollapsed[key] = true;
            });
        }

        // Exact matched substring/line, passed to <code-viewer :extra-highlights>
        // so the preview highlights precisely what the job would have extracted.
        function matchTerms(key) {
            const r = testResult[key];
            if (!r || r.matchStart == null || r.matchEnd == null) return [];
            const term = (testContent[key] || '').slice(r.matchStart, r.matchEnd);
            return term ? [term] : [];
        }

        function toggleAll(val) {
            props.parseableFields.forEach(k => { if (fieldConfigs[k]) fieldConfigs[k].enabled = val; });
            cveRescanEnabled.value = val;
        }

        // ── Saved configs ─────────────────────────────────────────────────
        const savedConfigs   = ref([]);
        const saveConfigName = ref('');
        const savingConfig   = ref(false);
        const loadedConfigId = ref(null);   // id of the config currently loaded

        async function fetchConfigs() {
            try {
                const res  = await fetch('/account/admin/bulk_parse_fields/configs');
                const data = await res.json();
                savedConfigs.value = data.configs || [];
            } catch { /* silent */ }
        }

        async function saveCurrentConfig() {
            const name = saveConfigName.value.trim();
            if (!name) { emit('notify', 'Enter a config name.'); return; }
            savingConfig.value = true;
            try {
                const res = await fetch('/account/admin/bulk_parse_fields/configs', {
                    method:  'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrfToken },
                    body:    JSON.stringify({ name, config: buildPayloadConfig() }),
                });
                const data = await res.json();
                if (data.success) {
                    savedConfigs.value.unshift(data.config);
                    loadedConfigId.value = data.config.id;
                    saveConfigName.value = name;
                    emit('notify', `Config "${name}" saved.`);
                }
            } finally { savingConfig.value = false; }
        }

        async function updateCurrentConfig() {
            const id = loadedConfigId.value;
            if (!id) return;
            const name = saveConfigName.value.trim();
            savingConfig.value = true;
            try {
                const res = await fetch(`/account/admin/bulk_parse_fields/configs/${id}`, {
                    method:  'PATCH',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrfToken },
                    body:    JSON.stringify({ name: name || undefined, config: buildPayloadConfig() }),
                });
                const data = await res.json();
                if (data.success) {
                    const idx = savedConfigs.value.findIndex(c => c.id === id);
                    if (idx !== -1) savedConfigs.value[idx] = data.config;
                    saveConfigName.value = data.config.name;
                    emit('notify', `Config "${data.config.name}" updated.`);
                }
            } finally { savingConfig.value = false; }
        }

        async function deleteConfig(id) {
            if (!confirm('Delete this config?')) return;
            await fetch(`/account/admin/bulk_parse_fields/configs/${id}`, {
                method: 'DELETE', headers: { 'X-CSRFToken': props.csrfToken },
            });
            savedConfigs.value = savedConfigs.value.filter(c => c.id !== id);
            if (loadedConfigId.value === id) {
                loadedConfigId.value = null;
                saveConfigName.value = '';
            }
        }

        function clearLoadedConfig() {
            loadedConfigId.value = null;
            saveConfigName.value = '';
        }

        async function saveAsNewConfig() {
            loadedConfigId.value = null;
            await saveCurrentConfig();
        }

        function loadConfig(cfg) {
            const c = cfg.config || {};
            props.parseableFields.forEach(key => {
                if (!fieldConfigs[key]) return;
                const fc = c[key] || {};
                fieldConfigs[key].enabled   = !!fc.enabled;
                fieldConfigs[key].keywords  = (fc.keywords || []).join(', ');
                fieldConfigs[key].regex     = fc.regex || '';
                fieldConfigs[key].overwrite = !!fc.overwrite;
            });
            loadedConfigId.value = cfg.id;
            saveConfigName.value = cfg.name;
            emit('notify', `Config "${cfg.name}" loaded.`);
        }

        // ── Job / terminal ────────────────────────────────────────────────
        const running   = ref(false);
        const jobUuid   = ref(null);
        const jobStatus = ref('idle');
        const jobLogs   = ref([]);
        const lastLogId = ref(0);
        const jobDone   = ref(0);
        const jobTotal  = ref(0);
        const jobPct    = computed(() =>
            jobTotal.value > 0 ? Math.round(jobDone.value / jobTotal.value * 100) : 0
        );
        let pollTimer = null;

        async function poll() {
            if (!jobUuid.value) return;
            try {
                const [sRes, lRes] = await Promise.all([
                    fetch(`/jobs/status/${jobUuid.value}`),
                    fetch(`/jobs/logs/${jobUuid.value}?since_id=${lastLogId.value}`),
                ]);
                const sData = await sRes.json();
                const lines = await lRes.json();

                jobStatus.value = sData.status || 'running';
                if (sData.done !== undefined) jobDone.value  = sData.done;
                if (sData.total !== undefined) jobTotal.value = sData.total;

                for (const log of lines) {
                    jobLogs.value.push(log);
                    lastLogId.value = Math.max(lastLogId.value, log.id);
                    if (log.event === 'start') {
                        const m = log.message.match(/(\d+) rules/);
                        if (m) jobTotal.value = parseInt(m[1]);
                    }
                    if (log.event === 'progress') {
                        const m = log.message.match(/^(\d+)\/(\d+)/);
                        if (m) { jobDone.value = parseInt(m[1]); jobTotal.value = parseInt(m[2]); }
                    }
                }

                if (['done', 'failed', 'cancelled'].includes(jobStatus.value)) {
                    clearInterval(pollTimer); pollTimer = null;
                    running.value = false;
                    if (jobStatus.value === 'done') emit('notify', 'Parsing complete!');
                }
            } catch (e) { console.error('[FieldParser] poll error:', e); }
        }

        async function runJob() {
            if (running.value) return;
            if (enabledCount.value === 0) { emit('notify', 'Enable at least one field.'); return; }

            running.value   = true;
            jobLogs.value   = [];
            lastLogId.value = 0;
            jobUuid.value   = null;
            jobStatus.value = 'pending';
            jobDone.value   = 0;
            jobTotal.value  = 0;

            const payload = {
                rule_ids:      selectionMode.value === 'ALL' ? 'ALL' : selectedIds.value,
                format_filter: selectionMode.value === 'ALL' ? (formatFilter.value || null) : null,
                fields_config: buildPayloadConfig(),
                rescan_cve:    cveRescanEnabled.value,
            };

            try {
                const res  = await fetch('/account/admin/bulk_parse_fields/trigger', {
                    method:  'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrfToken },
                    body:    JSON.stringify(payload),
                });
                const data = await res.json();
                if (!data.success) { emit('notify', data.message || 'Error'); running.value = false; return; }
                jobUuid.value   = data.job_uuid;
                jobStatus.value = 'running';
                pollTimer = setInterval(poll, 2000);
                poll();
            } catch (e) { emit('notify', 'Network error: ' + e); running.value = false; }
        }

        initFieldConfigs();
        onMounted(() => { fetchConfigs(); fetchFormats(); });
        onUnmounted(() => { if (pollTimer) clearInterval(pollTimer); });

        // JSON preview
        const showJson = ref(false);
        const jsonPreview = computed(() => JSON.stringify(
            { ...buildPayloadConfig(), cve_vulnerability: { enabled: cveRescanEnabled.value, mode: 'merge, never overwrite' } },
            null, 2
        ));

        return {
            selectedIds, selectionMode, selectionCount, onSend,
            fieldConfigs, enabledCount, toggleAll,
            cveRescanEnabled,
            testerOpen, testContent, testResult, testCollapsed, toggleTester, editTest, runExtractionTest, matchTerms,
            savedConfigs, saveConfigName, savingConfig, loadedConfigId,
            saveCurrentConfig, updateCurrentConfig, saveAsNewConfig, clearLoadedConfig, deleteConfig, loadConfig,
            running, jobUuid, jobStatus, jobLogs, jobDone, jobTotal, jobPct,
            showJson, jsonPreview,
            levelColor, levelPrefix, statusIcon,
            FIELD_COLORS,
        };
    },

    template: `
<div class="row g-4">

  <!-- ══ TOP: Field config + Saved configs ════════════════════════════════════ -->
  <div class="col-xl-8 d-flex flex-column gap-4">

    <!-- Field config card -->
    <div class="card border-0 shadow-sm rounded-4">
      <div class="card-body p-4">
        <div class="d-flex align-items-center justify-content-between mb-3 flex-wrap gap-2">
          <div class="d-flex align-items-center gap-2">
            <div style="width:3px;height:14px;background:#0d6efd;border-radius:2px;flex-shrink:0;"></div>
            <span class="fw-bold" style="font-size:.75rem;text-transform:uppercase;letter-spacing:.07em;color:var(--subtle-text-color);">
              <i class="fa-solid fa-sliders me-1"></i>Field Parsing Rules
            </span>
          </div>
          <div class="d-flex gap-2">
            <button @click="toggleAll(true)"  class="btn btn-xs btn-outline-primary"  style="font-size:.72rem;padding:2px 10px;">Enable all</button>
            <button @click="toggleAll(false)" class="btn btn-xs btn-outline-secondary" style="font-size:.72rem;padding:2px 10px;">Disable all</button>
          </div>
        </div>
        <p class="text-muted small mb-3">
          Two mutually-exclusive extraction modes per field — <strong>only one runs</strong>:
        </p>
        <ul class="text-muted small mb-3" style="padding-left:1.2rem;">
          <li><strong>Keyword mode</strong> (used when Regex is empty): scans the rule content line by line for
            <code>keyword: value</code> or <code>keyword = value</code> — first match wins. Indented lines are skipped.</li>
          <li><strong>Regex mode</strong> (used as soon as Regex is filled — keywords are then ignored entirely):
            your pattern is matched against the full content; capture group 1 is used if present, otherwise the whole match.</li>
        </ul>
        <p class="text-muted small mb-3">
          <strong>Overwrite</strong> replaces a value the rule already has; otherwise existing values are left untouched.
          Click <strong>Test</strong> on a field to paste a sample rule and see exactly what would be extracted.
        </p>

        <div class="d-flex flex-column gap-2">
          <div v-for="key in $props.parseableFields" :key="key"
               class="rounded-3 border p-3"
               :style="{ borderColor: fieldConfigs[key]?.enabled ? FIELD_COLORS[key] + '55' : 'var(--border-color)', background: fieldConfigs[key]?.enabled ? FIELD_COLORS[key] + '08' : 'var(--light-bg-color)' }">

            <div class="d-flex align-items-center gap-2 mb-2">
              <div class="form-check form-switch mb-0">
                <input class="form-check-input" type="checkbox" :id="'toggle_' + key"
                       v-model="fieldConfigs[key].enabled" style="cursor:pointer;">
              </div>
              <label :for="'toggle_' + key" class="fw-semibold mb-0 d-flex align-items-center gap-2" style="cursor:pointer;font-size:.9rem;color:var(--text-color);">
                <i :class="['fa-solid', $props.fieldMeta[key]?.icon || 'fa-tag']" :style="{ color: FIELD_COLORS[key] }"></i>
                [[ $props.fieldMeta[key]?.label || key ]]
              </label>
              <div class="ms-auto form-check form-switch mb-0 d-flex align-items-center gap-1">
                <input class="form-check-input" type="checkbox" :id="'ow_' + key"
                       v-model="fieldConfigs[key].overwrite" :disabled="!fieldConfigs[key].enabled">
                <label :for="'ow_' + key" class="form-check-label small text-muted" style="font-size:.72rem;">Overwrite</label>
              </div>
            </div>

            <template v-if="fieldConfigs[key]?.enabled">
              <div class="d-flex align-items-center justify-content-between mb-1">
                <span class="small fw-semibold" style="color:var(--subtle-text-color);">
                  <span :class="fieldConfigs[key].regex.trim() ? 'text-primary' : ''">
                    <i class="fa-solid" :class="fieldConfigs[key].regex.trim() ? 'fa-code' : 'fa-list'"></i>
                    [[ fieldConfigs[key].regex.trim() ? 'Regex mode' : 'Keyword mode' ]]
                  </span>
                  <span class="opacity-50 ms-1">
                    — [[ fieldConfigs[key].regex.trim() ? 'the regex below is used, keywords are ignored' : 'fill Regex to switch to regex mode' ]]
                  </span>
                </span>
                <button type="button" class="btn btn-xs btn-outline-secondary" style="font-size:.68rem;padding:1px 8px;"
                        @click="toggleTester(key)">
                  <i class="fa-solid fa-flask me-1"></i>[[ testerOpen[key] ? 'Hide tester' : 'Test' ]]
                </button>
              </div>

              <div class="mb-2">
                <label class="form-label mb-1" style="font-size:.72rem;color:var(--subtle-text-color);text-transform:uppercase;letter-spacing:.04em;">
                  Keywords <span class="opacity-50">(comma-separated — used when Regex is empty)</span>
                </label>
                <input type="text" class="form-control form-control-sm"
                       v-model="fieldConfigs[key].keywords" placeholder="license, licenses, credit">
              </div>
              <div>
                <label class="form-label mb-1" style="font-size:.72rem;color:var(--subtle-text-color);text-transform:uppercase;letter-spacing:.04em;">
                  Regex <span class="opacity-50">(optional — overrides keywords, capture group 1)</span>
                </label>
                <input type="text" class="form-control form-control-sm font-monospace"
                       v-model="fieldConfigs[key].regex" placeholder='(?i)license[:\\s]+(.+)'>
              </div>

              <!-- Unified tester: runs the exact same extraction the job would run — manual only -->
              <div v-if="testerOpen[key]" class="mt-2 p-2 rounded-3" style="background:var(--card-bg-color);border:1px solid var(--border-color);">

                <!-- ═══ EDITING: shown until "Run test" is clicked ═══ -->
                <template v-if="!testCollapsed[key]">
                  <div class="d-flex align-items-center justify-content-between mb-1">
                    <label class="form-label mb-0" style="font-size:.72rem;color:var(--subtle-text-color);text-transform:uppercase;letter-spacing:.04em;">
                      Paste sample rule content
                    </label>
                    <button type="button" class="btn btn-xs btn-primary" style="font-size:.7rem;padding:2px 10px;"
                            @click="runExtractionTest(key)">
                      <span v-if="testResult[key]?.loading" class="spinner-border spinner-border-sm me-1"></span>
                      <i v-else class="fa-solid fa-play me-1"></i>Run test
                    </button>
                  </div>

                  <smart-editor v-model="testContent[key]" mode="code" language="text"
                                min-height="110px" max-height="220px"
                                placeholder="Paste a rule (or just the relevant lines) here…">
                  </smart-editor>

                  <div class="d-flex justify-content-end mt-2">
                    <button type="button" class="btn btn-xs btn-primary" style="font-size:.7rem;padding:2px 10px;"
                            @click="runExtractionTest(key)">
                      <span v-if="testResult[key]?.loading" class="spinner-border spinner-border-sm me-1"></span>
                      <i v-else class="fa-solid fa-play me-1"></i>Run test
                    </button>
                  </div>
                </template>

                <!-- ═══ RESULT: shown once a test has run — editor collapsed ═══ -->
                <template v-else>
                  <div class="d-flex align-items-center justify-content-between mb-2 flex-wrap gap-2">
                    <template v-if="testResult[key]">
                      <span v-if="testResult[key].error" class="badge rounded-pill bg-danger-subtle text-danger">
                        Error
                      </span>
                      <span v-else-if="testResult[key].value" class="badge rounded-pill bg-success-subtle text-success border border-success-subtle">
                        <i class="fa-solid fa-check me-1"></i>Match ([[ testResult[key].mode ]]): "[[ testResult[key].value ]]"
                      </span>
                      <span v-else class="badge rounded-pill bg-secondary-subtle text-secondary border border-secondary-subtle">
                        <i class="fa-solid fa-xmark me-1"></i>No match ([[ testResult[key].mode ]] mode)
                      </span>
                    </template>
                    <button type="button" class="btn btn-xs btn-outline-secondary" style="font-size:.7rem;padding:2px 10px;"
                            @click="editTest(key)">
                      <i class="fa-solid fa-pen me-1"></i>Edit
                    </button>
                  </div>

                  <!-- Highlighted preview — the matched line/part lit up via CodeViewer's extraHighlights -->
                  <code-viewer v-if="testContent[key]" :code="testContent[key]" language="text" max-height="220px"
                               :show-lines="true" :foldable="false"
                               :extra-highlights="matchTerms(key)">
                  </code-viewer>
                </template>
              </div>
            </template>
          </div>

          <!-- CVE / Vulnerability re-scan — not keyword/regex based, always scans full content -->
          <div class="rounded-3 border p-3"
               :style="{ borderColor: cveRescanEnabled ? '#dc354555' : 'var(--border-color)', background: cveRescanEnabled ? '#dc354508' : 'var(--light-bg-color)' }">
            <div class="d-flex align-items-center gap-2">
              <div class="form-check form-switch mb-0">
                <input class="form-check-input" type="checkbox" id="toggle_cve"
                       v-model="cveRescanEnabled" style="cursor:pointer;">
              </div>
              <label for="toggle_cve" class="fw-semibold mb-0 d-flex align-items-center gap-2" style="cursor:pointer;font-size:.9rem;color:var(--text-color);">
                <i class="fa-solid fa-shield-virus" style="color:#dc3545;"></i>
                CVE / Vulnerability
              </label>
              <span class="ms-auto badge rounded-pill" style="background:#dc354522;color:#dc3545;border:1px solid #dc354544;font-size:.68rem;">
                merge only — never overwrites
              </span>
            </div>
            <p class="text-muted small mb-0 mt-2" style="font-size:.78rem;">
              Re-scans the <strong>entire rule content</strong> (not just description) for CVE/GHSA/PYSEC/…
              identifiers. Any newly found id is <strong>added</strong> to the rule's existing vulnerability list —
              identifiers already associated are kept as-is and never duplicated or removed.
            </p>
          </div>
        </div>

        <div class="mt-3">
          <button @click="showJson = !showJson" class="btn btn-xs btn-outline-secondary w-100" style="font-size:.75rem;">
            <i class="fa-solid fa-code me-1"></i>[[ showJson ? 'Hide' : 'Show' ]] JSON config
          </button>
          <div v-if="showJson" class="mt-2" style="max-height:280px;overflow:auto;">
            <code-viewer :code="jsonPreview" language="json" filename="config.json"></code-viewer>
          </div>
        </div>
      </div>
    </div>

  </div>

  <!-- ══ RIGHT: Saved configs ═════════════════════════════════════════════════ -->
  <div class="col-xl-4">
    <div class="card border-0 shadow-sm rounded-4 h-100">
      <div class="card-body p-4">
        <div class="d-flex align-items-center gap-2 mb-3">
          <div style="width:3px;height:14px;background:#6f42c1;border-radius:2px;flex-shrink:0;"></div>
          <span class="fw-bold" style="font-size:.75rem;text-transform:uppercase;letter-spacing:.07em;color:var(--subtle-text-color);">
            <i class="fa-solid fa-bookmark me-1"></i>Saved Configs
          </span>
        </div>
        <!-- name field + context badge when a config is loaded -->
        <div v-if="loadedConfigId" class="d-flex align-items-center gap-2 mb-2">
          <span class="badge rounded-pill px-2 py-1" style="background:#6f42c122;color:#6f42c1;border:1px solid #6f42c144;font-size:.72rem;">
            <i class="fa-solid fa-bookmark me-1"></i>Editing loaded config
          </span>
          <button @click="clearLoadedConfig" class="btn btn-xs btn-link text-muted p-0" style="font-size:.72rem;">
            clear
          </button>
        </div>
        <div class="input-group input-group-sm mb-2">
          <input type="text" class="form-control" v-model="saveConfigName" placeholder="Config name…"
                 @keyup.enter="loadedConfigId ? updateCurrentConfig() : saveCurrentConfig()">
          <button v-if="loadedConfigId"
                  class="btn btn-outline-primary fw-semibold" @click="updateCurrentConfig" :disabled="savingConfig"
                  title="Overwrite existing config">
            <i class="fa-solid fa-rotate me-1"></i>Update
          </button>
          <button v-if="loadedConfigId"
                  class="btn btn-outline-secondary fw-semibold" @click="saveAsNewConfig" :disabled="savingConfig"
                  title="Save as a new config">
            <i class="fa-solid fa-plus me-1"></i>New
          </button>
          <button v-if="!loadedConfigId"
                  class="btn btn-outline-primary fw-semibold" @click="saveCurrentConfig" :disabled="savingConfig">
            <i class="fa-solid fa-floppy-disk me-1"></i>Save
          </button>
        </div>
        <div v-if="savedConfigs.length === 0" class="text-center py-3 text-muted">
          <i class="fa-solid fa-bookmark fa-2x mb-2 d-block opacity-25"></i>
          <small>No saved configs yet.</small>
        </div>
        <div v-else class="d-flex flex-column gap-2" style="max-height:420px;overflow-y:auto;">
          <div v-for="cfg in savedConfigs" :key="cfg.id"
               class="d-flex align-items-center gap-2 rounded-3 border p-2" style="background:var(--light-bg-color);">
            <div class="flex-grow-1 min-w-0">
              <div class="fw-semibold small text-truncate" style="color:var(--text-color);">[[ cfg.name ]]</div>
              <div style="color:var(--subtle-text-color);font-size:.7rem;">[[ cfg.created_at ]]</div>
            </div>
            <button @click="loadConfig(cfg)" class="btn btn-xs btn-outline-primary flex-shrink-0" style="font-size:.72rem;padding:2px 8px;">
              <i class="fa-solid fa-upload me-1"></i>Load
            </button>
            <button @click="deleteConfig(cfg.id)" class="btn btn-xs btn-outline-danger flex-shrink-0" style="font-size:.72rem;padding:2px 8px;">
              <i class="fa-solid fa-trash"></i>
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- ══ TERMINAL — full width, shows only when job is running/done ══════════ -->
  <div v-if="running || jobLogs.length > 0" class="col-12">
    <div class="card border-0 shadow-sm rounded-4">
      <div class="card-body p-4">

        <!-- Header + progress -->
        <div class="d-flex align-items-center gap-3 mb-3 flex-wrap">
          <div class="d-flex align-items-center gap-2">
            <i :class="statusIcon(jobStatus)" class="fs-5"></i>
            <span class="fw-semibold" style="color:var(--text-color);">[[ jobStatus ]]</span>
          </div>
          <div v-if="jobTotal > 0" class="flex-grow-1" style="min-width:200px;">
            <div class="d-flex justify-content-between small text-muted mb-1">
              <span>[[ jobDone ]] / [[ jobTotal ]] rules</span>
              <span>[[ jobPct ]]%</span>
            </div>
            <div class="progress rounded-pill" style="height:5px;">
              <div class="progress-bar bg-success" :style="{ width: jobPct + '%' }"></div>
            </div>
          </div>
          <span v-if="jobUuid" class="ms-auto small font-monospace" style="color:#8b949e;font-size:.68rem;">[[ jobUuid ]]</span>
        </div>

        <!-- Terminal -->
        <div class="rounded-3 p-3"
             style="max-height:360px;overflow-y:auto;background:#0d1117;border:1px solid #30363d;font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;font-size:.72rem;line-height:1.6;">
          <div v-if="jobLogs.length === 0" class="text-center py-2" style="color:#484f58;">
            Waiting for job to start…
          </div>
          <div v-for="log in jobLogs" :key="log.id" style="display:flex;gap:.5rem;margin-bottom:.15rem;">
            <span style="color:#484f58;flex-shrink:0;min-width:145px;">[[ log.created_at ]]</span>
            <span :style="{ color: levelColor(log.level), flexShrink: 0, minWidth: '3.5rem' }">[[ levelPrefix(log.level) ]]</span>
            <span :style="{ color: levelColor(log.level) }" style="white-space:pre-wrap;word-break:break-all;">[[ log.message ]]</span>
          </div>
        </div>

      </div>
    </div>
  </div>

  <!-- ══ RULE SELECTION — full width ══════════════════════════════════════════ -->
  <div class="col-12">
    <div class="card border-0 shadow-sm rounded-4">
      <div class="card-body p-3">
        <div class="d-flex align-items-center gap-2 mb-3 flex-wrap">
          <div style="width:3px;height:14px;background:#0d6efd;border-radius:2px;flex-shrink:0;"></div>
          <span class="fw-bold" style="font-size:.75rem;text-transform:uppercase;letter-spacing:.07em;color:var(--subtle-text-color);">
            <i class="fa-solid fa-list-check me-1"></i>Select Rules
          </span>
          <small style="color:var(--subtle-text-color);font-size:.78rem;">
            — filter, pick rules, click <strong>Confirm</strong> to launch the job
          </small>
        </div>
        <rule-list
          mode="select"
          default-view="table"
          :show-filters="true"
          :show-create="false"
          :can-vote="false"
          :can-favorite="false"
          :current-user-is-authenticated="true"
          :confirm-disabled="running"
          :csrf-token="csrfToken"
          @send="onSend">
        </rule-list>
      </div>
    </div>
  </div>

</div>
`,
};

export default FieldParserUpdater;
