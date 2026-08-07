import InputEditorByFormat from './InputEditorByFormat.js';
import RuleList            from '/static/js/rule/ruleList.js';
import AnsiTerminal        from '/static/js/components/ansi-terminal.js';
import { create_message }  from '/static/js/toaster.js';

const BulkTesterPanel = {
    name: 'BulkTesterPanel',
    delimiters: ['[[', ']]'],
    components: { InputEditorByFormat, RuleList, AnsiTerminal },
    props: {
        isAuthenticated:    { type: Boolean, default: false },
        csrfToken:          { type: String,  default: '' },
        currentUserId:      { type: [Number, String], default: null },
        currentUserIsAdmin: { type: Boolean, default: false },
    },
    data() {
        return {
            format:     '',
            inputData:  { type: 'string', value: '' },
            inputLabel: '',
            label:      '',
            isPublic:   false,

            // Flags the sample under test as a real malicious/dangerous artifact.
            isDangerous:       false,
            dangerDescription: '',

            // Set once the user confirms a rule set in step 2 (rule-list @send)
            selection:  { mode: null, ids: [], count: null }, // mode: null | 'ids' | 'all'

            // Set once the user explicitly confirms they're done typing the payload
            payloadConfirmed: false,

            // Accordion: which step body is expanded — completed steps collapse automatically
            expandedStep: 1,

            // Steps progress bar stays visible while scrolling (position:sticky is broken
            // globally here — body has overflow-x:hidden — so this pins it manually).
            pinned:       false,
            pinnedStyle:  {},
            pinnedHeight: 0,

            submitting:   false,
            jobUuid:      null,
            testUuid:     null,
            jobStatus:    null,
            jobDone:      0,
            jobTotal:     0,
            jobPct:       0,
            pollTimer:    null,
            logSinceId:   0,
            logs:         [],
            result:       null,
        };
    },
    computed: {
        formats() {
            return ['yara'];
        },
        isRunning() {
            return this.jobStatus === 'pending' || this.jobStatus === 'running';
        },
        selectionSummary() {
            if (this.selection.mode === 'all')  return 'Every rule matching your filters';
            if (this.selection.mode === 'ids')  return `${this.selection.count} rule${this.selection.count === 1 ? '' : 's'} selected`;
            return null;
        },
        hasPayload() {
            return !!this.inputData.value || ['host_json', 'http_request'].includes(this.inputData.type);
        },
        step1Done() { return !!this.format && this.hasPayload && this.payloadConfirmed; },
        step2Done() { return !!this.selection.mode; },
        step3Done() { return !!this.jobUuid; },
        step2Locked() { return !this.step1Done; },
        step3Locked() { return !this.step2Done; },
        progressBarStyle() {
            const pct = this.jobPct;
            let color = '#0d6efd';
            if (pct === 100) color = '#198754';
            return `width:${pct}%;background:${color};transition:width .4s ease;`;
        },
        terminalEntries() {
            return this.logs.map(l => ({ ts: l.created_at, level: l.level, msg: l.message }));
        },
    },
    watch: {
        format() {
            this.resetSelection();
            this.payloadConfirmed = false;
        },
        // Editing the payload again after confirming it un-confirms it — the user must
        // explicitly confirm again before rule selection unlocks.
        inputData() {
            this.payloadConfirmed = false;
        },
    },
    async mounted() {
        // Restore job from URL ?job=<uuid>
        const params   = new URLSearchParams(window.location.search);
        const jobParam = params.get('job');
        if (jobParam) {
            this.jobUuid  = jobParam;
            this.jobStatus = 'running';
            // fetch payload to recover testUuid
            try {
                const r = await fetch(`/jobs/api/${jobParam}`);
                if (r.ok) {
                    const d = await r.json();
                    if (d.meta && d.meta.test_uuid) {
                        this.testUuid = d.meta.test_uuid;
                    }
                }
            } catch (_) {}
            this._startPoll();
        }

        window.addEventListener('scroll', this._onScroll, { passive: true });
        window.addEventListener('resize', this._onScroll);
        this.$nextTick(this._onScroll);
    },
    beforeUnmount() {
        this._stopPoll();
        window.removeEventListener('scroll', this._onScroll);
        window.removeEventListener('resize', this._onScroll);
    },
    methods: {
        _navbarHeight() {
            const v = getComputedStyle(document.body).getPropertyValue('--navbar-h');
            const n = parseFloat(v);
            return isNaN(n) ? 0 : n;
        },
        _onScroll() {
            const sentinel = this.$refs.stepsSentinel;
            const bar      = this.$refs.stepsBar;
            if (!sentinel || !bar) return;
            const navH  = this._navbarHeight();
            const rect  = sentinel.getBoundingClientRect();
            this.pinned = rect.top <= navH;
            if (this.pinned) {
                this.pinnedStyle  = { top: navH + 'px', left: rect.left + 'px', width: rect.width + 'px' };
                this.pinnedHeight = bar.offsetHeight;
            }
        },
        onRuleSelectionConfirmed(ids, filters) {
            if (ids === 'ALL') {
                this.selection = { mode: 'all', ids: [], count: null };
            } else {
                if (!ids.length) { create_message('Select at least one rule.', 'danger'); return; }
                this.selection = { mode: 'ids', ids, count: ids.length };
            }
            create_message('Rule selection confirmed.', 'success');
            if (this.expandedStep === 2) this.expandedStep = 3;
        },
        resetSelection() {
            this.selection = { mode: null, ids: [], count: null };
            if (this.expandedStep === 3) this.expandedStep = 2;
        },
        goToStep(n) {
            // A step can only be (re)opened once it's reachable
            if (n === 2 && !this.step1Done) return;
            if (n === 3 && !this.selection.mode) return;
            this.expandedStep = n;
        },
        confirmPayload() {
            if (!this.format || !this.hasPayload) return;
            this.payloadConfirmed = true;
            if (this.expandedStep === 1) this.expandedStep = 2;
        },

        async submit() {
            if (!this.format) { create_message('Select a format to test.', 'danger'); return; }
            if (!this.selection.mode) { create_message('Confirm which rules to test before launching.', 'danger'); return; }
            if (!this.inputData.value && !['host_json','http_request'].includes(this.inputData.type)) {
                create_message('Enter test input before launching.', 'danger');
                return;
            }
            this.submitting  = true;
            this.jobUuid     = null;
            this.testUuid    = null;
            this.jobStatus   = null;
            this.jobDone     = 0;
            this.jobTotal    = 0;
            this.jobPct      = 0;
            this.logs        = [];
            this.logSinceId  = 0;
            this.result      = null;

            const bulkFilters = this.selection.mode === 'ids'
                ? { rule_ids: this.selection.ids }
                : { format: this.format };

            try {
                const resp = await fetch('/api/rule_tester/private/test', {
                    method:  'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': this.csrfToken },
                    body: JSON.stringify({
                        test_type:    'bulk',
                        format:       this.format,
                        bulk_filters: bulkFilters,
                        input_type:   this.inputData.type,
                        input_data:   this.inputData.value,
                        input_label:  this.inputLabel || null,
                        label:        this.label || null,
                        is_public:    this.isPublic,
                        is_dangerous:       this.isDangerous,
                        danger_description: this.isDangerous ? (this.dangerDescription || null) : null,
                    }),
                });
                const data = await resp.json();
                if (!resp.ok) { create_message(data.message || 'Failed to launch.', 'danger'); return; }

                // redirect immediately to the test detail page
                window.location = '/rule_tester/test/' + data.test_uuid;
            } catch (e) {
                create_message('Network error: ' + e.message, 'danger');
            } finally {
                this.submitting = false;
            }
        },

        _startPoll() {
            this._stopPoll();
            this._poll();
            this.pollTimer = setInterval(this._poll, 2500);
        },
        _stopPoll() {
            if (this.pollTimer) { clearInterval(this.pollTimer); this.pollTimer = null; }
        },

        async _poll() {
            if (!this.jobUuid) return;
            try {
                // job status
                const sResp = await fetch(`/jobs/status/${this.jobUuid}`);
                if (sResp.ok) {
                    const sData = await sResp.json();
                    this.jobStatus = sData.status;
                    this.jobDone   = sData.done   || 0;
                    this.jobTotal  = sData.total  || 0;
                    this.jobPct    = sData.progress_pct || 0;
                }

                // incremental logs
                const lResp = await fetch(`/jobs/logs/${this.jobUuid}?since_id=${this.logSinceId}`);
                if (lResp.ok) {
                    const newLogs = await lResp.json();
                    if (newLogs.length) {
                        this.logs.push(...newLogs);
                        this.logSinceId = newLogs[newLogs.length - 1].id;
                    }
                }

                if (this.jobStatus === 'done' || this.jobStatus === 'failed') {
                    this._stopPoll();
                    this.jobPct = this.jobStatus === 'done' ? 100 : this.jobPct;
                    if (this.jobStatus === 'done') {
                        create_message(`Done — ${this.jobDone} rule(s) processed.`, 'success');
                    } else {
                        create_message('Job failed. See logs below.', 'danger');
                    }
                }
            } catch (e) { /* retry next tick */ }
        },

        statusBadgeClass(s) {
            const m = { pending: 'bg-secondary', running: 'bg-primary', done: 'bg-success', failed: 'bg-danger' };
            return 'badge ' + (m[s] || 'bg-secondary');
        },
        defaultType() {
            const map = {
                yara: 'string', sigma: 'json', suricata: 'text_payload',
                zeek: 'zeek_log_json', wazuh: 'syslog_line', nse: 'host_json',
                crs: 'http_request', atr: 'text', nova: 'text',
            };
            return map[this.format] || 'string';
        },
    },

    template: `
<div class="rtr-bulk">

  <!-- ── Steps progress bar (pinned on scroll via JS — see mounted()/_onScroll) ── -->
  <div ref="stepsSentinel"></div>
  <div ref="stepsBar" class="rtr-steps-progress" :class="{ 'rtr-steps-progress--pinned': pinned }"
       :style="pinned ? pinnedStyle : {}">
    <div class="rtr-steps-progress__item" :class="{ done: step1Done, active: expandedStep === 1 }" @click="goToStep(1)">
      <div class="rtr-steps-progress__circle"><i v-if="step1Done" class="fa-solid fa-check"></i><span v-else>1</span></div>
      <span class="rtr-steps-progress__label">Format &amp; Payload</span>
    </div>
    <div class="rtr-steps-progress__line" :class="{ done: step1Done }"></div>
    <div class="rtr-steps-progress__item" :class="{ done: step2Done, active: expandedStep === 2, locked: step2Locked }" @click="goToStep(2)">
      <div class="rtr-steps-progress__circle"><i v-if="step2Done" class="fa-solid fa-check"></i><span v-else>2</span></div>
      <span class="rtr-steps-progress__label">Select Rules</span>
    </div>
    <div class="rtr-steps-progress__line" :class="{ done: step2Done }"></div>
    <div class="rtr-steps-progress__item" :class="{ done: step3Done, active: expandedStep === 3, locked: step3Locked }" @click="goToStep(3)">
      <div class="rtr-steps-progress__circle"><i v-if="step3Done" class="fa-solid fa-check"></i><span v-else>3</span></div>
      <span class="rtr-steps-progress__label">Launch</span>
    </div>
  </div>
  <div v-if="pinned" :style="{ height: pinnedHeight + 'px', marginBottom: '1.5rem' }"></div>

  <!-- ── Job progress (visible as soon as a job is running) ── -->
  <div v-if="jobUuid" class="pe-card">
    <div class="pe-card__header">
      <div class="pe-card__accent" style="background:#198754;"></div>
      <span class="pe-card__title"><i class="fa-solid fa-gauge-high me-1"></i>Job Progress</span>
      <span v-if="jobStatus" class="ms-auto" :class="statusBadgeClass(jobStatus)">
        [[ jobStatus.toUpperCase() ]]
      </span>
    </div>
    <div class="pe-card__body">

      <!-- Progress bar -->
      <div class="d-flex align-items-center justify-content-between mb-1">
        <span style="font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--subtle-text-color);">
          Progress
        </span>
        <span style="font-size:.72rem;color:var(--subtle-text-color);">
          [[ jobDone ]] / [[ jobTotal ]] rules · [[ jobPct ]]%
        </span>
      </div>
      <div style="height:10px;border-radius:6px;background:var(--border-color);overflow:hidden;">
        <div :style="progressBarStyle" style="height:100%;border-radius:6px;"></div>
      </div>

      <!-- 25 / 50 / 75 / 100 markers -->
      <div class="d-flex justify-content-between mt-1" style="font-size:.6rem;color:var(--subtle-text-color);">
        <span>0%</span><span>25%</span><span>50%</span><span>75%</span><span>100%</span>
      </div>

      <!-- Quick links -->
      <div class="d-flex gap-2 mt-2 flex-wrap">
        <a :href="'/jobs/detail/' + jobUuid" target="_blank"
           class="btn btn-outline-secondary btn-sm" style="font-size:.72rem;">
          <i class="fa-solid fa-chart-line me-1"></i>Job detail
        </a>
        <a v-if="testUuid" :href="'/rule_tester/test/' + testUuid" target="_blank"
           class="btn btn-outline-primary btn-sm" style="font-size:.72rem;">
          <i class="fa-solid fa-list me-1"></i>View results
        </a>
      </div>

      <!-- Live logs -->
      <div v-if="logs.length" class="mt-3">
        <ansi-terminal :entries="terminalEntries" :live="isRunning" title="Live log" @clear="logs = []">
        </ansi-terminal>
      </div>

      <!-- Done summary -->
      <div v-if="jobStatus === 'done'" class="alert alert-success mt-3 mb-0" style="font-size:.85rem;">
        <i class="fa-solid fa-circle-check me-2"></i>
        Completed — [[ jobDone ]] rules processed.
        <a v-if="testUuid" :href="'/rule_tester/test/' + testUuid" class="alert-link ms-2">
          View full results →
        </a>
      </div>
      <div v-if="jobStatus === 'failed'" class="alert alert-danger mt-3 mb-0" style="font-size:.85rem;">
        <i class="fa-solid fa-circle-xmark me-2"></i>Job failed — check the logs above.
      </div>

    </div>
  </div>

  <!-- ── Step 1: format + payload ── -->
  <div class="pe-card">
    <div class="pe-card__header pe-card__header--clickable" @click="goToStep(1)">
      <div class="pe-card__accent"></div>
      <span class="pe-card__title"><i class="fa-solid fa-vial me-1"></i>1 — Test Payload</span>
      <span v-if="expandedStep !== 1 && format" class="ms-auto badge rounded-pill" style="font-size:.7rem;background:rgba(13,110,253,.12);color:#0d6efd;">
        [[ format.toUpperCase() ]]
      </span>
      <i class="fa-solid ms-2" :class="expandedStep === 1 ? 'fa-chevron-up' : 'fa-chevron-down'" style="font-size:.68rem;color:var(--subtle-text-color);"></i>
    </div>
    <div class="pe-card__body" v-show="expandedStep === 1">
      <p class="rtr-step-hint">
        Choose the rule format you want to test, then write or paste the sample input every matching rule will be evaluated against.
      </p>

      <div class="row g-2 mb-3">
        <div class="col-md-4">
          <label class="form-label" style="font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--subtle-text-color);">Format *</label>
          <select v-model="format" class="form-select form-select-sm"
                  @change="inputData = { type: defaultType(), value: '' }"
                  :disabled="isRunning">
            <option value="">— select —</option>
            <option v-for="f in formats" :key="f" :value="f">[[ f.toUpperCase() ]]</option>
          </select>
          <small class="rtr-field-hint">More rule formats will be added soon.</small>
        </div>
      </div>

      <template v-if="format">
        <label class="form-label" style="font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--subtle-text-color);">Test Input</label>
        <InputEditorByFormat :format="format" v-model="inputData" />

        <!-- Dangerous sample flag -->
        <div class="rtr-danger-toggle mt-3" :class="{ 'rtr-danger-toggle--active': isDangerous }">
          <label class="d-flex align-items-center gap-2" style="cursor:pointer;margin-bottom:0;">
            <input type="checkbox" v-model="isDangerous" class="form-check-input m-0" :disabled="payloadConfirmed">
            <i class="fa-solid fa-skull-crossbones" :class="isDangerous ? 'text-danger' : ''" style="opacity:.8;"></i>
            <span class="fw-semibold" style="font-size:.85rem;">This sample is a real malicious/dangerous artifact</span>
          </label>
          <small class="rtr-field-hint d-block mt-1">
            Flags this test so anyone viewing it later — in the test detail, history, or results — sees a warning before handling the sample.
          </small>
          <textarea v-if="isDangerous" v-model="dangerDescription" class="rtr-textarea mt-2" rows="2"
                    :disabled="payloadConfirmed"
                    placeholder="What is it? e.g. &quot;Live BRICKSTORM backdoor sample — do not execute outside an isolated sandbox.&quot;"></textarea>
        </div>

        <div v-if="payloadConfirmed" class="rtr-selection-banner mt-3">
          <i class="fa-solid fa-circle-check text-success me-2"></i>
          <span>Payload confirmed.</span>
          <button type="button" class="btn btn-link btn-sm p-0 ms-auto" @click="payloadConfirmed = false">
            Edit payload
          </button>
        </div>
        <button v-else type="button" class="rtr-run-btn mt-3" style="background:#198754;"
                :disabled="!hasPayload" @click="confirmPayload">
          <i class="fa-solid fa-check me-1"></i>
          [[ hasPayload ? "I'm done typing — continue" : 'Enter a payload above first' ]]
        </button>
      </template>
      <div v-else class="alert alert-secondary mb-0" style="font-size:.82rem;">
        <i class="fa-solid fa-arrow-up me-2"></i>Select a format above to configure the test input.
      </div>
    </div>
  </div>

  <!-- ── Step 2: select rules ── -->
  <div class="pe-card">
    <div class="pe-card__header" :class="step2Locked ? 'pe-card__header--locked' : 'pe-card__header--clickable'" @click="goToStep(2)">
      <div class="pe-card__accent" style="background:#6f42c1;"></div>
      <span class="pe-card__title"><i class="fa-solid fa-list-check me-1"></i>2 — Select Rules to Test</span>
      <span v-if="step2Locked" class="ms-auto" style="font-size:.7rem;color:var(--subtle-text-color);">
        <i class="fa-solid fa-lock me-1"></i>Locked
      </span>
      <span v-else-if="selectionSummary" class="ms-auto badge rounded-pill" style="font-size:.7rem;background:rgba(25,135,84,.12);color:#198754;">
        <i class="fa-solid fa-check me-1"></i>[[ selectionSummary ]]
      </span>
      <i v-if="!step2Locked" class="fa-solid ms-2" :class="expandedStep === 2 ? 'fa-chevron-up' : 'fa-chevron-down'" style="font-size:.68rem;color:var(--subtle-text-color);"></i>
    </div>
    <div class="pe-card__body" v-show="expandedStep === 2 && !step2Locked">
      <p class="rtr-step-hint">
        Filter rules exactly like on the Rules Explorer — by tags, sources, licenses, CVEs, ATT&amp;CK technique, author or keyword.
        Tick individual rules or select every rule matching your filters, then click <strong>Confirm</strong> below the list.
      </p>

      <rule-list
        v-if="!step2Locked && !isRunning"
        :key="format"
        mode="select"
        default-view="table"
        fetch-url="/rule/data_table"
        :hidden-filters="['format']"
        :initial-filters="{ format: format }"
        :current-user-id="currentUserId"
        :current-user-is-admin="currentUserIsAdmin"
        :current-user-is-authenticated="isAuthenticated"
        :csrf-token="csrfToken"
        :sync-url="false"
        @send="onRuleSelectionConfirmed">
      </rule-list>

      <div v-if="selectionSummary" class="rtr-selection-banner mt-3">
        <i class="fa-solid fa-circle-check text-success me-2"></i>
        <span>[[ selectionSummary ]] will be tested.</span>
        <button type="button" class="btn btn-link btn-sm p-0 ms-auto" @click="resetSelection" :disabled="isRunning">
          Change selection
        </button>
      </div>
    </div>
  </div>

  <!-- ── Step 3: metadata + launch ── -->
  <div class="pe-card">
    <div class="pe-card__header" :class="step3Locked ? 'pe-card__header--locked' : 'pe-card__header--clickable'" @click="goToStep(3)">
      <div class="pe-card__accent" style="background:#fd7e14;"></div>
      <span class="pe-card__title"><i class="fa-solid fa-rocket me-1"></i>3 — Launch</span>
      <span v-if="step3Locked" class="ms-auto" style="font-size:.7rem;color:var(--subtle-text-color);">
        <i class="fa-solid fa-lock me-1"></i>Locked
      </span>
      <i v-else class="fa-solid ms-2" :class="expandedStep === 3 ? 'fa-chevron-up' : 'fa-chevron-down'" style="font-size:.68rem;color:var(--subtle-text-color);"></i>
    </div>
    <div class="pe-card__body" v-show="expandedStep === 3 && !step3Locked">

      <div class="rtr-meta-row mb-3">
        <div class="rtr-field">
          <label>Input label</label>
          <input type="text" v-model="inputLabel" placeholder="e.g. EICAR string" :disabled="isRunning">
          <small class="rtr-field-hint">A short name for the payload above — shown next to results so you can recognise it later.</small>
        </div>
        <div class="rtr-field">
          <label>Job label</label>
          <input type="text" v-model="label" placeholder="e.g. YARA test v1" :disabled="isRunning">
          <small class="rtr-field-hint">A name for this test run itself — helps you find it again in your job history.</small>
        </div>
      </div>

      <div class="rtr-privacy-row mb-3 flex-column align-items-start">
        <div class="d-flex align-items-center gap-2">
          <input type="checkbox" id="bulk-public" v-model="isPublic" class="form-check-input m-0"
                 :disabled="isRunning">
          <label for="bulk-public" style="cursor:pointer;">
            <i class="fa-solid" :class="isPublic ? 'fa-globe text-success' : 'fa-lock'"></i>
            [[ isPublic ? 'Results public' : 'Results private' ]]
          </label>
        </div>
        <small class="rtr-field-hint">
          [[ isPublic
            ? 'Anyone can see which rules matched, on the Test History tab of each tested rule.'
            : 'Only you (and admins) can see these results — nobody else will know this test ran.' ]]
        </small>
      </div>

      <!-- Launch button -->
      <button class="rtr-run-btn" :class="{ 'rtr-run-btn--loading': submitting }"
              @click="submit" :disabled="submitting || isRunning || !format || !selection.mode">
        <i class="fa-solid fa-rocket rtr-run-icon"></i>
        <i class="fa-solid fa-circle-notch rtr-spin"></i>
        [[ submitting ? 'Queuing…' : (isRunning ? 'Job running…' : 'Launch Test') ]]
      </button>

    </div>
  </div>

</div>
`,
};

export default BulkTesterPanel;
