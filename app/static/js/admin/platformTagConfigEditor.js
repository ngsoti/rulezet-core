/**
 * platformTagConfigEditor.js
 * Admin config builder for the "Platform Tags" bulk job: lets an admin define
 * (regex pattern -> existing tag) mappings, enable/disable individual ones,
 * save/load/delete named configs, and edit either through a form or raw JSON.
 *
 * Every tag is picked via <tag-input maxTags="1">, never typed by hand — this
 * is what makes "the config can only ever reference a real, current tag" true
 * by construction on the happy path. The server still re-validates on save
 * and again right before the job runs (a tag can be deleted after this form
 * builds the config), so this is a UX guarantee, not the only enforcement.
 */
import TagInput   from '/static/js/tags/tagInput.js'
import CodeViewer from '/static/js/components/code-viewer.js'
import SmartEditor from '/static/js/components/smart-editor.js'

const { ref, reactive, computed, watch, onMounted } = Vue;

// Starting point offered via "Load example template" — the OS-shaped subset
// of the ms-caro-malware-full taxonomy's malware-platform predicate. Each
// entry's tag is resolved by exact name lookup against the DB when the
// template is loaded; any that don't resolve (taxonomy not imported yet) are
// added with an empty tag picker so the admin can see exactly what's missing.
const EXAMPLE_TEMPLATE = [
    { label: 'Windows', tagName: 'ms-caro-malware-full:malware-platform="Win32"',     regex: '\\bwindows\\b|\\bwin32\\b' },
    { label: 'Linux',   tagName: 'ms-caro-malware-full:malware-platform="Linux"',     regex: '\\blinux\\b' },
    { label: 'macOS',   tagName: 'ms-caro-malware-full:malware-platform="MacOS_X"',   regex: '\\bmac ?os( ?x)?\\b|\\bdarwin\\b' },
    { label: 'Android', tagName: 'ms-caro-malware-full:malware-platform="AndroidOS"', regex: '\\bandroid\\b' },
    { label: 'Unix',    tagName: 'ms-caro-malware-full:malware-platform="Unix"',      regex: '\\bunix\\b' },
    { label: 'FreeBSD', tagName: 'ms-caro-malware-full:malware-platform="FreeBSD"',   regex: '\\bfreebsd\\b' },
    { label: 'Solaris', tagName: 'ms-caro-malware-full:malware-platform="Solaris"',   regex: '\\bsolaris\\b' },
];

let _rowSeq = 0;
function newRow(overrides = {}) {
    return reactive({
        _key:    ++_rowSeq,
        label:   '',
        tags:    [],   // TagInput's array shape, capped at 1 by maxTags
        regex:   '',
        enabled: true,
        ...overrides,
    });
}

const PlatformTagConfigEditor = {
    name: 'PlatformTagConfigEditor',
    delimiters: ['[[', ']]'],
    components: { 'tag-input': TagInput, 'code-viewer': CodeViewer, 'smart-editor': SmartEditor },
    props: {
        csrfToken: { type: String, required: true },
    },
    emits: ['notify', 'config-selected'],
    setup(props, { emit }) {
        const rows           = ref([newRow()]);
        const rawMode         = ref(false);
        const rawJsonText     = ref('{\n  "patterns": []\n}');
        const rawJsonError    = ref('');

        const savedConfigs    = ref([]);
        const configName      = ref('');
        const loadedConfigId  = ref(null);
        const saving          = ref(false);
        const validating      = ref(false);
        const validationError = ref('');
        const validationOk    = ref(null);   // null = not checked yet, true/false after a check
        const loadingTemplate = ref(false);
        const showJson        = ref(false);

        // ── build the config JSON from whichever mode is active ────────────
        function patternsFromRows() {
            return rows.value.map(r => ({
                label:   r.label.trim(),
                tag_id:  r.tags[0]?.id ?? null,
                regex:   r.regex.trim(),
                enabled: r.enabled,
            }));
        }

        function buildConfig() {
            if (rawMode.value) {
                try {
                    const parsed = JSON.parse(rawJsonText.value);
                    rawJsonError.value = '';
                    return parsed;
                } catch (e) {
                    rawJsonError.value = 'Invalid JSON: ' + e.message;
                    return null;
                }
            }
            return { patterns: patternsFromRows() };
        }

        const jsonPreview = computed(() => JSON.stringify(buildConfig() || { patterns: [] }, null, 2));

        // ── row management (form mode) ──────────────────────────────────────
        function addRow() { rows.value.push(newRow()); }
        function removeRow(key) {
            rows.value = rows.value.filter(r => r._key !== key);
            if (!rows.value.length) rows.value = [newRow()];
        }

        // ── mode switch: keep both representations in sync when toggling ────
        function switchToRaw() {
            rawJsonText.value = JSON.stringify({ patterns: patternsFromRows() }, null, 2);
            rawMode.value = true;
        }
        function switchToForm() {
            const cfg = buildConfig();
            if (cfg && Array.isArray(cfg.patterns)) {
                rows.value = cfg.patterns.map(p => newRow({
                    label:   p.label || '',
                    tags:    p.tag_id ? [{ id: p.tag_id, name: p.tag_name || `#${p.tag_id}`, color: '#6c757d', icon: 'tag' }] : [],
                    regex:   p.regex || '',
                    enabled: p.enabled !== false,
                }));
                if (!rows.value.length) rows.value = [newRow()];
            }
            rawMode.value = false;
        }

        // ── server-side validation (re-resolves every tag_id against the DB) ─
        async function runValidation() {
            const config = buildConfig();
            if (!config) { validationOk.value = false; validationError.value = rawJsonError.value; return false; }
            validating.value = true;
            try {
                const res = await fetch('/account/admin/bulk_parse_fields/platform_configs/validate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrfToken },
                    body: JSON.stringify({ config }),
                });
                const data = await res.json();
                validationOk.value    = !!data.valid;
                validationError.value = data.message || '';
                return validationOk.value;
            } catch (e) {
                validationOk.value = false;
                validationError.value = 'Network error while validating: ' + e;
                return false;
            } finally {
                validating.value = false;
            }
        }

        // ── saved configs CRUD — same interaction pattern as the base field
        //    parser's saved configs (bulkParseFields.js) ──────────────────────
        async function fetchConfigs() {
            try {
                const res  = await fetch('/account/admin/bulk_parse_fields/platform_configs');
                const data = await res.json();
                savedConfigs.value = data.configs || [];
            } catch { /* silent */ }
        }

        function selectLoadedConfig(id) {
            loadedConfigId.value = id;
            emit('config-selected', id);
        }

        async function saveCurrentConfig() {
            const name = configName.value.trim();
            if (!name) { emit('notify', 'Enter a config name.', 'danger-subtle'); return; }
            const config = buildConfig();
            if (!config) { emit('notify', rawJsonError.value, 'danger-subtle'); return; }
            saving.value = true;
            try {
                const res = await fetch('/account/admin/bulk_parse_fields/platform_configs', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrfToken },
                    body: JSON.stringify({ name, config }),
                });
                const data = await res.json();
                if (data.success) {
                    savedConfigs.value.unshift(data.config);
                    selectLoadedConfig(data.config.id);
                    configName.value = name;
                    validationOk.value = true;
                    validationError.value = '';
                    emit('notify', `Config "${name}" saved.`, 'success-subtle');
                } else {
                    emit('notify', data.message || 'Could not save config.', 'danger-subtle');
                }
            } finally { saving.value = false; }
        }

        async function updateCurrentConfig() {
            const id = loadedConfigId.value;
            if (!id) return;
            const config = buildConfig();
            if (!config) { emit('notify', rawJsonError.value, 'danger-subtle'); return; }
            saving.value = true;
            try {
                const res = await fetch(`/account/admin/bulk_parse_fields/platform_configs/${id}`, {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrfToken },
                    body: JSON.stringify({ name: configName.value.trim() || undefined, config }),
                });
                const data = await res.json();
                if (data.success) {
                    const idx = savedConfigs.value.findIndex(c => c.id === id);
                    if (idx !== -1) savedConfigs.value[idx] = data.config;
                    configName.value = data.config.name;
                    validationOk.value = true;
                    validationError.value = '';
                    emit('notify', `Config "${data.config.name}" updated.`, 'success-subtle');
                } else {
                    emit('notify', data.message || 'Could not update config.', 'danger-subtle');
                }
            } finally { saving.value = false; }
        }

        function saveAsNewConfig() {
            loadedConfigId.value = null;
            emit('config-selected', null);
            return saveCurrentConfig();
        }

        async function deleteConfig(id) {
            if (!confirm('Delete this platform-tag config?')) return;
            await fetch(`/account/admin/bulk_parse_fields/platform_configs/${id}`, {
                method: 'DELETE', headers: { 'X-CSRFToken': props.csrfToken },
            });
            savedConfigs.value = savedConfigs.value.filter(c => c.id !== id);
            if (loadedConfigId.value === id) {
                loadedConfigId.value = null;
                configName.value = '';
                emit('config-selected', null);
            }
        }

        function loadConfig(cfg) {
            const patterns = (cfg.config && cfg.config.patterns) || [];
            rows.value = patterns.map(p => newRow({
                label:   p.label || '',
                tags:    p.tag_id ? [{ id: p.tag_id, name: p.tag_name || `#${p.tag_id}`, color: '#6c757d', icon: 'tag' }] : [],
                regex:   p.regex || '',
                enabled: p.enabled !== false,
            }));
            if (!rows.value.length) rows.value = [newRow()];
            rawMode.value = false;
            configName.value = cfg.name;
            selectLoadedConfig(cfg.id);
            validationOk.value = null;
            validationError.value = '';
        }

        function clearLoadedConfig() {
            loadedConfigId.value = null;
            configName.value = '';
            emit('config-selected', null);
        }

        // ── example template ─────────────────────────────────────────────────
        async function loadExampleTemplate() {
            loadingTemplate.value = true;
            try {
                // Search the exact "namespace:predicate" prefix, not just the
                // taxonomy name — that taxonomy also has ~35 malware-type and
                // ~457 malware-family values sharing the same "ms-caro-malware-full"
                // substring, and they sort alphabetically before "malware-platform".
                // A plain taxonomy-name search + limit=100 was silently returning
                // 100 malware-family tags and none of the platform ones at all.
                const res  = await fetch('/tags/get_all_tags?' + new URLSearchParams({ search: 'ms-caro-malware-full:malware-platform', limit: '100' }));
                const data = await res.json();
                const byName = new Map((data.tags || []).map(t => [t.name, t]));
                rows.value = EXAMPLE_TEMPLATE.map(entry => {
                    const tag = byName.get(entry.tagName);
                    return newRow({
                        label:   entry.label,
                        regex:   entry.regex,
                        tags:    tag ? [tag] : [],
                        enabled: true,
                    });
                });
                const unresolved = EXAMPLE_TEMPLATE.filter(e => !byName.has(e.tagName));
                if (unresolved.length) {
                    emit('notify',
                        `${unresolved.length} of ${EXAMPLE_TEMPLATE.length} example tags weren't found — ` +
                        `import the "ms-caro-malware-full" taxonomy from /tags/admin/list, then pick those manually.`,
                        'warning-subtle');
                } else {
                    emit('notify', 'Example template loaded — review and save.', 'success-subtle');
                }
                rawMode.value = false;
                loadedConfigId.value = null;
                emit('config-selected', null);
            } finally {
                loadingTemplate.value = false;
            }
        }

        onMounted(fetchConfigs);

        // Re-check validity whenever the shape changes meaningfully, so the
        // Save/Update button's state reflects reality without an extra click.
        watch([rows, rawMode], () => { validationOk.value = null; }, { deep: true });

        return {
            rows, rawMode, rawJsonText, rawJsonError, jsonPreview, showJson,
            addRow, removeRow, switchToRaw, switchToForm,
            validating, validationOk, validationError, runValidation,
            savedConfigs, configName, loadedConfigId, saving,
            saveCurrentConfig, updateCurrentConfig, saveAsNewConfig, deleteConfig,
            loadConfig, clearLoadedConfig,
            loadingTemplate, loadExampleTemplate,
        };
    },

    template: `
<div class="row g-4">

  <!-- ══ Pattern builder ══════════════════════════════════════════════════ -->
  <div class="col-xl-8">
    <div class="card border-0 shadow-sm rounded-4">
      <div class="card-body p-4">
        <div class="d-flex align-items-center justify-content-between mb-3 flex-wrap gap-2">
          <div class="d-flex align-items-center gap-2">
            <div style="width:3px;height:14px;background:#0d6efd;border-radius:2px;flex-shrink:0;"></div>
            <span class="fw-bold" style="font-size:.75rem;text-transform:uppercase;letter-spacing:.07em;color:var(--subtle-text-color);">
              <i class="fa-solid fa-display me-1"></i>Platform Tag Patterns
            </span>
          </div>
          <div class="d-flex gap-2">
            <button class="btn btn-sm rounded-pill px-3" style="background:transparent;border:1px solid #0d6efd55;color:#0d6efd;"
                    @click="loadExampleTemplate" :disabled="loadingTemplate">
              <span v-if="loadingTemplate" class="spinner-border spinner-border-sm me-1"></span>
              <i v-else class="fa-solid fa-wand-magic-sparkles me-1"></i>Load example template
            </button>
            <button class="btn btn-sm rounded-pill px-3" style="background:transparent;border:1px solid var(--border-color);color:var(--subtle-text-color);"
                    @click="rawMode ? switchToForm() : switchToRaw()">
              <i class="fa-solid fa-code me-1"></i>[[ rawMode ? 'Form view' : 'Raw JSON' ]]
            </button>
          </div>
        </div>
        <p class="text-muted small mb-3">
          Each row: pick an <strong>existing tag</strong> (never typed by hand — search picks from
          real tags/taxonomies/galaxies already in your DB) and a regex. Any rule whose title,
          description or content matches the regex gets that tag — already-tagged rules are
          skipped, so re-running is always safe. Disable a row instead of deleting it if you just
          don't want to re-scan for it right now.
        </p>

        <!-- ═══ FORM MODE ═══ -->
        <div v-if="!rawMode" class="d-flex flex-column gap-2">
          <div v-for="row in rows" :key="row._key"
               class="rounded-3 border p-3"
               :style="{ borderColor: row.enabled ? '#0d6efd55' : 'var(--border-color)', background: row.enabled ? '#0d6efd08' : 'var(--light-bg-color)' }">

            <!-- Row 1: on/off, label, regex, delete — always fits on one line -->
            <div class="d-flex align-items-end gap-2">
              <div class="form-check form-switch mb-0 pb-2">
                <input class="form-check-input" type="checkbox" v-model="row.enabled" style="cursor:pointer;">
              </div>
              <div style="width:160px;flex-shrink:0;">
                <label class="form-label mb-1" style="font-size:.7rem;color:var(--subtle-text-color);text-transform:uppercase;">Label</label>
                <input type="text" class="form-control form-control-sm" v-model="row.label" placeholder="Windows">
              </div>
              <div class="flex-grow-1">
                <label class="form-label mb-1" style="font-size:.7rem;color:var(--subtle-text-color);text-transform:uppercase;">Regex</label>
                <input type="text" class="form-control form-control-sm font-monospace" v-model="row.regex" placeholder="\\bwindows\\b|\\bwin32\\b">
              </div>
              <button type="button" class="btn btn-sm rounded-pill flex-shrink-0" style="background:transparent;border:1px solid #dc354555;color:#dc3545;"
                      @click="removeRow(row._key)" title="Remove pattern">
                <i class="fa-solid fa-trash"></i>
              </button>
            </div>

            <!-- Row 2: tag picker gets the full row to itself — it can open a
                 dropdown, cramming it into a narrow column looked broken. -->
            <div class="mt-2">
              <label class="form-label mb-1" style="font-size:.7rem;color:var(--subtle-text-color);text-transform:uppercase;">Tag</label>
              <tag-input v-model="row.tags" :max-tags="1" :show-namespace="true" placeholder="Search a tag…" label=""></tag-input>
            </div>

            <div v-if="!row.tags.length" class="small text-warning mt-1">
              <i class="fa-solid fa-triangle-exclamation me-1"></i>No tag picked — this row will fail validation.
            </div>
          </div>

          <button type="button" class="btn btn-sm rounded-pill px-3 align-self-start"
                  style="background:transparent;border:1px solid #0d6efd55;color:#0d6efd;" @click="addRow">
            <i class="fa-solid fa-plus me-1"></i>Add pattern
          </button>
        </div>

        <!-- ═══ RAW JSON MODE ═══ -->
        <div v-else>
          <smart-editor v-model="rawJsonText" mode="code" language="json" min-height="240px" max-height="480px"></smart-editor>
          <div v-if="rawJsonError" class="text-danger small mt-1">[[ rawJsonError ]]</div>
        </div>

        <!-- ═══ Validation feedback ═══ -->
        <div class="mt-3 d-flex align-items-center gap-2 flex-wrap">
          <button type="button" class="btn btn-sm rounded-pill px-3"
                  style="background:transparent;border:1px solid var(--border-color);color:var(--subtle-text-color);"
                  @click="runValidation" :disabled="validating">
            <span v-if="validating" class="spinner-border spinner-border-sm me-1"></span>
            <i v-else class="fa-solid fa-check-double me-1"></i>Check config against DB
          </button>
          <span v-if="validationOk === true" class="badge rounded-pill bg-success-subtle text-success border border-success-subtle">
            <i class="fa-solid fa-check me-1"></i>All tags resolve — safe to save/launch
          </span>
          <span v-else-if="validationOk === false" class="badge rounded-pill bg-danger-subtle text-danger border border-danger-subtle">
            <i class="fa-solid fa-xmark me-1"></i>[[ validationError ]]
          </span>
        </div>

        <div class="mt-3">
          <button @click="showJson = !showJson" class="btn btn-sm rounded-pill px-3"
                  style="background:transparent;border:1px solid var(--border-color);color:var(--subtle-text-color);">
            <i class="fa-solid fa-code me-1"></i>[[ showJson ? 'Hide' : 'Show' ]] JSON config
          </button>
          <div v-if="showJson" class="mt-2" style="max-height:280px;overflow:auto;">
            <code-viewer :code="jsonPreview" language="json" filename="platform_tags_config.json"></code-viewer>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- ══ Saved configs ══════════════════════════════════════════════════════ -->
  <div class="col-xl-4">
    <div class="card border-0 shadow-sm rounded-4 h-100">
      <div class="card-body p-4">
        <div class="d-flex align-items-center gap-2 mb-3">
          <div style="width:3px;height:14px;background:#6f42c1;border-radius:2px;flex-shrink:0;"></div>
          <span class="fw-bold" style="font-size:.75rem;text-transform:uppercase;letter-spacing:.07em;color:var(--subtle-text-color);">
            <i class="fa-solid fa-bookmark me-1"></i>Saved Configs
          </span>
        </div>
        <div v-if="loadedConfigId" class="d-flex align-items-center gap-2 mb-2">
          <span class="badge rounded-pill px-2 py-1" style="background:#6f42c122;color:#6f42c1;border:1px solid #6f42c144;font-size:.72rem;">
            <i class="fa-solid fa-bookmark me-1"></i>Editing loaded config
          </span>
          <button @click="clearLoadedConfig" class="btn btn-xs btn-link text-muted p-0" style="font-size:.72rem;">clear</button>
        </div>
        <div class="input-group input-group-sm mb-2">
          <input type="text" class="form-control" v-model="configName" placeholder="Config name…"
                 @keyup.enter="loadedConfigId ? updateCurrentConfig() : saveCurrentConfig()">
          <button v-if="loadedConfigId" class="btn btn-outline-primary fw-semibold" @click="updateCurrentConfig" :disabled="saving" title="Overwrite existing config">
            <i class="fa-solid fa-rotate me-1"></i>Update
          </button>
          <button v-if="loadedConfigId" class="btn btn-outline-secondary fw-semibold" @click="saveAsNewConfig" :disabled="saving" title="Save as a new config">
            <i class="fa-solid fa-plus me-1"></i>New
          </button>
          <button v-if="!loadedConfigId" class="btn btn-outline-primary fw-semibold" @click="saveCurrentConfig" :disabled="saving">
            <i class="fa-solid fa-floppy-disk me-1"></i>Save
          </button>
        </div>
        <div v-if="savedConfigs.length === 0" class="text-center py-3 text-muted">
          <i class="fa-solid fa-bookmark fa-2x mb-2 d-block opacity-25"></i>
          <small>No saved configs yet.</small>
        </div>
        <div v-else class="d-flex flex-column gap-2" style="max-height:420px;overflow-y:auto;">
          <div v-for="cfg in savedConfigs" :key="cfg.id"
               class="d-flex align-items-center gap-2 rounded-3 border p-2"
               :class="{ 'border-primary': loadedConfigId === cfg.id }"
               style="background:var(--light-bg-color);">
            <div class="flex-grow-1 min-w-0">
              <div class="fw-semibold small text-truncate" style="color:var(--text-color);">
                [[ cfg.name ]]
                <i v-if="loadedConfigId === cfg.id" class="fa-solid fa-circle-check text-primary ms-1" title="Active for the trigger below"></i>
              </div>
              <div style="color:var(--subtle-text-color);font-size:.7rem;">[[ cfg.created_at ]] · [[ (cfg.config.patterns || []).length ]] pattern(s)</div>
            </div>
            <button @click="loadConfig(cfg)" class="btn btn-sm rounded-pill px-2 flex-shrink-0"
                    style="background:transparent;border:1px solid #0d6efd55;color:#0d6efd;">
              <i class="fa-solid fa-upload me-1"></i>Load
            </button>
            <button @click="deleteConfig(cfg.id)" class="btn btn-sm rounded-pill flex-shrink-0"
                    style="background:transparent;border:1px solid #dc354555;color:#dc3545;">
              <i class="fa-solid fa-trash"></i>
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>

</div>
    `,
};

export default PlatformTagConfigEditor;
