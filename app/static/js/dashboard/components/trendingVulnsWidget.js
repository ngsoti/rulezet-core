/**
 * TrendingVulnsWidget — "Trending vulnerabilities" horizontal bar-list.
 * Each row: CVE id, a proportional light-blue bar (width relative to the
 * top count), and the rule count right-aligned. Sourced from the existing
 * /home_charts/top_cve endpoint (top 10 CVEs by rule count).
 * Clicking a row jumps to the rules list filtered to that CVE.
 *
 * params: { limit }
 */
import WidgetFrame from '../widgetFrame.js'

const { ref, watch, onMounted, computed } = Vue

const ENDPOINT = '/home_charts/top_cve'

const TrendingVulnsWidget = {
    components: { 'widget-frame': WidgetFrame },
    props: {
        params: { type: Object, required: true },
    },
    emits: ['update-params', 'remove'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const rows     = ref([])
        const loading  = ref(false)
        const editForm = ref({ ...props.params })

        const maxCount = computed(() => rows.value.reduce((m, r) => Math.max(m, r.count), 0) || 1)

        async function load() {
            loading.value = true
            try {
                const res  = await fetch(ENDPOINT)
                const data = await res.json()
                const cats = data.categories || []
                const vals = (data.series && data.series[0] && data.series[0].values) || []
                const limit = props.params.limit || 10
                rows.value = cats.map((cve, i) => ({ cve, count: vals[i] || 0 })).slice(0, limit)
            } catch {
                rows.value = []
            } finally {
                loading.value = false
            }
        }

        function go(row) {
            window.location.href = '/rule/rules_list?vulnerabilities=' + encodeURIComponent(row.cve)
        }

        function saveSettings() {
            emit('update-params', { ...editForm.value })
        }

        watch(() => props.params, () => { editForm.value = { ...props.params }; load() })
        onMounted(load)

        return { rows, loading, editForm, maxCount, go, load, saveSettings }
    },
    template: `
    <widget-frame title="Trending Vulnerabilities" icon="fa-bug" :loading="loading"
                   @reload="load" @remove="$emit('remove')" @save-settings="saveSettings">
        <div v-if="!loading && rows.length === 0" class="text-center text-muted small py-4">
            <i class="fa-solid fa-bug-slash opacity-25 d-block mb-2" style="font-size:1.5rem;"></i>
            No CVEs tracked yet.
        </div>
        <div class="dw-barlist">
            <div v-for="(row, i) in rows" :key="row.cve" class="dw-barlist-row"
                 :class="{ 'dw-barlist-row--alt': i % 2 === 1 }" @click="go(row)">
                <span class="dw-barlist-label">[[ row.cve ]]</span>
                <span class="dw-barlist-track">
                    <span class="dw-barlist-fill" :style="{ width: (row.count / maxCount * 100) + '%' }"></span>
                </span>
                <span class="dw-barlist-value">[[ row.count ]]</span>
            </div>
        </div>

        <template #settings>
            <div>
                <label class="form-label small fw-bold text-muted text-uppercase mb-1">Rows shown</label>
                <select class="form-select form-select-sm" v-model.number="editForm.limit">
                    <option :value="5">5</option>
                    <option :value="8">8</option>
                    <option :value="10">10</option>
                </select>
            </div>
        </template>
    </widget-frame>
    `,
}

export default TrendingVulnsWidget
