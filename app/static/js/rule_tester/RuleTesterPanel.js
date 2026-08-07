import InputEditorByFormat from './InputEditorByFormat.js';
import TestResultDisplay from './TestResultDisplay.js';
import AnsiTerminal from '/static/js/components/ansi-terminal.js';
import { create_message } from '/static/js/toaster.js';

const RuleTesterPanel = {
  name: 'RuleTesterPanel',
  delimiters: ['[[', ']]'],
  components: { InputEditorByFormat, TestResultDisplay, AnsiTerminal },
  props: {
    ruleUuid: { type: String, required: true },
    ruleFormat: { type: String, required: true },
    currentUserId: { type: Number, default: null },
    isAuthenticated: { type: Boolean, default: false },
    csrfToken: { type: String, default: '' },
  },
  data() {
    return {
      inputData: { type: this._defaultInputType(), value: '' },
      inputLabel: '',
      label: '',
      notes: '',
      isPublic: false,
      isDangerous: false,
      dangerDescription: '',
      running: false,
      result: null,
      testUuid: null,
      logs: [],
      error: null,
    };
  },
  computed: {
    formatLower() { return (this.ruleFormat || '').toLowerCase(); },
    formatBadgeClass() { return `rtr-format-badge rtr-format-badge--${this.formatLower}`; },
    isYara() { return this.formatLower === 'yara'; },
    terminalEntries() {
      return this.logs.map(l => ({ level: l.level, msg: l.message }));
    },
  },
  methods: {
    _defaultInputType() {
      const map = {
        yara: 'string', sigma: 'json', suricata: 'text_payload',
        zeek: 'zeek_log_json', wazuh: 'syslog_line', nse: 'host_json',
        crs: 'http_request', atr: 'text', nova: 'text',
      };
      return map[(this.ruleFormat || '').toLowerCase()] || 'string';
    },
    async runTest() {
      if (!this.inputData.value && !['host_json', 'http_request'].includes(this.inputData.type)) {
        create_message('Please enter test input before running.', 'danger');
        return;
      }
      this.running = true;
      this.result = null;
      this.testUuid = null;
      this.logs = [];
      this.error = null;

      try {
        const payload = {
          test_type: 'single',
          rule_uuid: this.ruleUuid,
          format: this.ruleFormat,
          input_type: this.inputData.type,
          input_data: this.inputData.value,
          input_label: this.inputLabel || null,
          label: this.label || null,
          notes: this.notes || null,
          is_public: this.isPublic,
          is_dangerous: this.isDangerous,
          danger_description: this.isDangerous ? (this.dangerDescription || null) : null,
        };

        const resp = await fetch('/api/rule_tester/private/test', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': this.csrfToken,
          },
          body: JSON.stringify(payload),
        });
        const data = await resp.json();

        if (!resp.ok) {
          this.error = data.message || 'Request failed';
          create_message(this.error, 'danger');
          return;
        }

        this.testUuid = data.test_uuid;
        this.logs = data.logs || [];
        this.result = {
          matched: data.matched,
          score: data.score,
          details: data.details || {},
          quality_hints: data.quality_hints || [],
          execution_time_ms: data.execution_time_ms || 0,
          error: data.error || null,
        };

        // redirect to test detail page
        window.location = '/rule_tester/test/' + data.test_uuid;

      } catch (e) {
        this.error = e.message;
        create_message('Network error: ' + e.message, 'danger');
      } finally {
        this.running = false;
      }
    },
  },
  template: `
<div class="rtr-panel">
  <div class="rtr-panel__header">
    <i class="fa-solid fa-flask-vial text-primary"></i>
    <span class="rtr-panel__title">Test this rule</span>
    <span class="ms-auto" :class="formatBadgeClass">
      <i class="fa-solid fa-code me-1"></i>[[ ruleFormat.toUpperCase() ]]
    </span>
  </div>

  <div class="rtr-panel__body">

    <!-- YARA-only notice -->
    <div v-if="!isYara" class="alert mb-0" style="background:rgba(13,110,253,.07);border:1px solid rgba(13,110,253,.2);border-radius:8px;font-size:.85rem;">
      <i class="fa-solid fa-flask-vial me-2 text-primary"></i>
      Testing is currently available for <a href="/rule/rules_list?rule_type=yara" target="_blank"> <span class="badge rounded-pill bg-dark pt-1 shadow-sm">YARA</span> </a> rules only.
      Other formats will be supported in a future release.
    </div>

    <template v-if="isYara">
    <!-- Input editor -->
    <div class="mb-3">
      <label class="form-label" style="font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--subtle-text-color);">
        Test Input
      </label>
      <InputEditorByFormat :format="ruleFormat" v-model="inputData" />
    </div>

    <!-- Optional metadata -->
    <div class="rtr-meta-row">
      <div class="rtr-field">
        <label>Input label</label>
        <input type="text" v-model="inputLabel" placeholder="e.g. EICAR string, SQLi payload #1">
      </div>
      <div class="rtr-field">
        <label>Test label</label>
        <input type="text" v-model="label" placeholder="e.g. My first YARA test">
      </div>
    </div>

    <!-- Dangerous sample flag -->
    <div class="rtr-danger-toggle mb-3" :class="{ 'rtr-danger-toggle--active': isDangerous }">
      <label class="d-flex align-items-center gap-2" style="cursor:pointer;margin-bottom:0;">
        <input type="checkbox" v-model="isDangerous" class="form-check-input m-0">
        <i class="fa-solid fa-skull-crossbones" :class="isDangerous ? 'text-danger' : ''" style="opacity:.8;"></i>
        <span class="fw-semibold" style="font-size:.85rem;">This sample is a real malicious/dangerous artifact</span>
      </label>
      <small class="rtr-field-hint d-block mt-1">
        Flags this test so anyone viewing it later sees a warning before handling the sample.
      </small>
      <textarea v-if="isDangerous" v-model="dangerDescription" class="rtr-textarea mt-2" rows="2"
                placeholder="What is it? e.g. &quot;Live malware sample — do not execute outside an isolated sandbox.&quot;"></textarea>
    </div>

    <!-- Privacy -->
    <div class="rtr-privacy-row mb-3">
      <input type="checkbox" id="rtr-public" v-model="isPublic" class="form-check-input me-2">
      <label for="rtr-public" style="cursor:pointer;">
        <i class="fa-solid" :class="isPublic ? 'fa-globe text-success' : 'fa-lock'"></i>
        [[ isPublic ? 'Public — visible to everyone' : 'Private — only you can see this test' ]]
      </label>
    </div>

    <!-- Run button -->
    <div class="d-flex align-items-center gap-3">
      <button class="rtr-run-btn" :class="{ 'rtr-run-btn--loading': running }"
              @click="runTest" :disabled="running">
        <i class="fa-solid fa-play rtr-run-icon"></i>
        <i class="fa-solid fa-circle-notch rtr-spin"></i>
        [[ running ? 'Running…' : 'Run Test' ]]
      </button>

      <a v-if="testUuid" :href="'/rule_tester/test/' + testUuid"
         class="btn btn-outline-secondary btn-sm">
        <i class="fa-solid fa-arrow-up-right-from-square me-1"></i> View full results
      </a>
    </div>

    <!-- Log stream -->
    <div v-if="logs.length" class="mt-3">
      <ansi-terminal :entries="terminalEntries" :live="false" title="Test log"></ansi-terminal>
    </div>

    <!-- Result -->
    <TestResultDisplay v-if="result" :result="result" :test-uuid="testUuid" class="mt-3" />

    <!-- Error without result -->
    <div v-if="error && !result" class="alert alert-danger mt-3" style="font-size:.82rem;">
      <i class="fa-solid fa-circle-exclamation me-2"></i>[[ error ]]
    </div>
    </template>
  </div>
</div>
`,
};

export default RuleTesterPanel;
