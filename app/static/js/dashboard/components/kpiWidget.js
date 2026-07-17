/**
 * KpiWidget — a single big number + icon, sourced from any existing JSON
 * endpoint on the platform (no dashboard-specific backend route: it just
 * fetches `params.endpoint` and reads `params.path`, a dot-path into the
 * response, e.g. "kpi.total_rules" against /platform/insights_data).
 *
 * params: { endpoint, path, label, icon, color }
 * color: one of blue/teal/green/gold/purple/orange (mirrors .ud-kpi-card--*)
 */
import WidgetFrame from '../widgetFrame.js'

const { ref, watch, onMounted } = Vue

function getPath(obj, path) {
    return path.split('.').reduce((acc, key) => (acc == null ? undefined : acc[key]), obj)
}

const KpiWidget = {
    components: { 'widget-frame': WidgetFrame },
    props: {
        params: { type: Object, required: true },
    },
    emits: ['update-params', 'remove'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const value       = ref(null)
        const loading     = ref(false)
        const editForm    = ref({ ...props.params })

        async function load() {
            loading.value = true
            try {
                const res  = await fetch(props.params.endpoint)
                const data = await res.json()
                value.value = getPath(data, props.params.path)
            } catch {
                value.value = null
            } finally {
                loading.value = false
            }
        }

        function saveSettings() {
            emit('update-params', { ...editForm.value })
        }

        // The parent replaces `params` with a new object once the saved
        // layout round-trips — refetch whenever that happens, not just on
        // this component's own initial mount.
        watch(() => props.params, () => { editForm.value = { ...props.params }; load() })

        onMounted(load)

        return { value, loading, editForm, load, saveSettings }
    },
    template: `
    <widget-frame :title="params.label" :icon="params.icon" :loading="loading"
                   @reload="load" @remove="$emit('remove')" @save-settings="saveSettings">
        <div class="dw-kpi" :class="'dw-kpi--' + (params.color || 'blue')">
            <div class="dw-kpi-icon"><i :class="'fa-solid ' + params.icon"></i></div>
            <div class="dw-kpi-value">
                <span v-if="value === null && !loading" class="text-muted">—</span>
                <span v-else>[[ value ]]</span>
            </div>
        </div>

        <template #settings>
            <div class="mb-2">
                <label class="form-label small fw-bold text-muted text-uppercase mb-1">Label</label>
                <input type="text" class="form-control form-control-sm" v-model="editForm.label">
            </div>
            <div class="mb-2">
                <label class="form-label small fw-bold text-muted text-uppercase mb-1">Data path</label>
                <input type="text" class="form-control form-control-sm font-monospace" v-model="editForm.path"
                       placeholder="e.g. kpi.total_rules">
            </div>
            <div>
                <label class="form-label small fw-bold text-muted text-uppercase mb-1">Color</label>
                <select class="form-select form-select-sm" v-model="editForm.color">
                    <option v-for="c in ['blue','teal','green','gold','purple','orange']" :key="c" :value="c">[[ c ]]</option>
                </select>
            </div>
        </template>
    </widget-frame>
    `,
}

export default KpiWidget
