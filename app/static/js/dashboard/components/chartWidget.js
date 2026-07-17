/**
 * ChartWidget — wraps the shared <chart-viewer> component, sourced from any
 * existing JSON endpoint that already returns the {title, categories, series}
 * shape ChartViewer expects (e.g. /platform/insights_data's "charts.*" keys).
 *
 * params: { endpoint, path, view }
 */
import WidgetFrame from '../widgetFrame.js'
import ChartViewer from '/static/js/components/chart-viewer.js'

const { ref, watch, onMounted, computed } = Vue

function getPath(obj, path) {
    return path.split('.').reduce((acc, key) => (acc == null ? undefined : acc[key]), obj)
}

const CHART_VIEWS = ['line', 'area', 'bar', 'bar-h', 'pie', 'donut', 'scatter', 'radar', 'heatmap']

// Known dataset presets from /platform/insights_data — kept in sync by hand
// with the `charts` dict built in app/home.py. Shown as a dropdown so adding
// a chart widget doesn't require knowing the raw dot-path by heart; picking
// "Custom…" falls back to the free-text field for anything not listed yet.
const CHART_PRESETS = [
    { path: 'charts.rules_over_time',       label: 'Rules Added (over time)' },
    { path: 'charts.users_over_time',        label: 'New Users (over time)' },
    { path: 'charts.bundles_over_time',      label: 'Bundles Created (over time)' },
    { path: 'charts.activity_over_time',     label: 'Platform Events (over time)' },
    { path: 'charts.formats',                label: 'Rules by Format' },
    { path: 'charts.top_tags',               label: 'Top Tags' },
    { path: 'charts.top_contribs',           label: 'Top Contributors' },
    { path: 'charts.proposals',              label: 'Edit Proposals' },
    { path: 'charts.rule_health',            label: 'Rule Health (active vs deleted)' },
    { path: 'charts.user_roles',             label: 'User Roles' },
    { path: 'charts.heatmap',                label: 'Activity Heatmap (hour × day)' },
    { path: 'charts.attack_top_techniques',  label: 'ATT&CK — Top Techniques' },
    { path: 'charts.attack_tactic_coverage', label: 'ATT&CK — Tactic Coverage' },
    { path: 'charts.attack_tactic_rules',    label: 'ATT&CK — Rules per Tactic' },
    { path: 'charts.attack_covered_donut',   label: 'ATT&CK — Covered vs Uncovered' },
]

const ChartWidget = {
    components: { 'widget-frame': WidgetFrame, 'chart-viewer': ChartViewer },
    props: {
        params: { type: Object, required: true },
    },
    emits: ['update-params', 'remove'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const data     = ref({})
        const loading  = ref(false)
        const editForm = ref({ ...props.params })

        const isPreset = computed(() => CHART_PRESETS.some(p => p.path === editForm.value.path))

        async function load() {
            loading.value = true
            try {
                const res  = await fetch(props.params.endpoint)
                const json = await res.json()
                data.value = getPath(json, props.params.path) || {}
            } catch {
                data.value = {}
            } finally {
                loading.value = false
            }
        }

        function saveSettings() {
            emit('update-params', { ...editForm.value })
        }

        function onPresetChange(e) {
            if (e.target.value) editForm.value.path = e.target.value
        }

        watch(() => props.params, () => { editForm.value = { ...props.params }; load() })

        onMounted(load)

        return { data, loading, editForm, load, saveSettings, onPresetChange, isPreset, CHART_VIEWS, CHART_PRESETS }
    },
    template: `
    <widget-frame :title="data.title || params.path" icon="fa-chart-line" :loading="loading"
                   @reload="load" @remove="$emit('remove')" @save-settings="saveSettings">
        <chart-viewer v-if="data.categories" :data="data" :views="params.view || 'line'" height="100%"></chart-viewer>
        <div v-else class="text-center text-muted small py-4">
            <i class="fa-solid fa-chart-simple opacity-25 d-block mb-2" style="font-size:1.5rem;"></i>
            No data.
        </div>

        <template #settings>
            <div class="mb-2">
                <label class="form-label small fw-bold text-muted text-uppercase mb-1">Dataset</label>
                <select class="form-select form-select-sm" :value="isPreset ? editForm.path : ''" @change="onPresetChange">
                    <option value="" disabled>Custom…</option>
                    <option v-for="p in CHART_PRESETS" :key="p.path" :value="p.path">[[ p.label ]]</option>
                </select>
            </div>
            <div class="mb-2">
                <label class="form-label small fw-bold text-muted text-uppercase mb-1">Data path</label>
                <input type="text" class="form-control form-control-sm font-monospace" v-model="editForm.path"
                       placeholder="e.g. charts.rules_over_time">
            </div>
            <div>
                <label class="form-label small fw-bold text-muted text-uppercase mb-1">Chart type</label>
                <select class="form-select form-select-sm" v-model="editForm.view">
                    <option v-for="v in CHART_VIEWS" :key="v" :value="v">[[ v ]]</option>
                </select>
            </div>
        </template>
    </widget-frame>
    `,
}

export default ChartWidget
