/**
 * StatsRowWidget — MISP-style horizontal strip of small icon/label/number
 * boxes, sourced from /platform/insights_data's "kpi" object. Replaces a
 * handful of single-number KPI tiles with one compact, full-width row.
 *
 * params: { metrics: [{ path, label, icon, href? }] }
 * `path` is a dot-path into the endpoint's JSON (e.g. "kpi.total_rules").
 * `href` (optional) is where clicking that box navigates to.
 */
import WidgetFrame from '../widgetFrame.js'

const { ref, watch, onMounted } = Vue

const ENDPOINT = '/platform/insights_data'

function getPath(obj, path) {
    return path.split('.').reduce((acc, key) => (acc == null ? undefined : acc[key]), obj)
}

const DEFAULT_METRICS = [
    { path: 'kpi.total_rules',     label: 'Rules',     icon: 'fa-shield-halved',     href: '/rule/rules_list' },
    { path: 'kpi.total_cves',      label: 'CVEs',       icon: 'fa-bug',               href: '/rule/rules_list?has_cve=true' },
    { path: 'kpi.total_tags',      label: 'Tags',       icon: 'fa-tags' },
    { path: 'kpi.total_bundles',   label: 'Bundles',    icon: 'fa-boxes-stacked',     href: '/bundle/bundles_list' },
    { path: 'kpi.total_users',     label: 'Users',      icon: 'fa-users' },
    { path: 'kpi.total_comments',  label: 'Comments',   icon: 'fa-comments',          href: '/community/comments' },
]

const StatsRowWidget = {
    components: { 'widget-frame': WidgetFrame },
    props: {
        params: { type: Object, required: true },
    },
    emits: ['update-params', 'remove'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const values  = ref({})
        const loading = ref(false)

        const metrics = () => (props.params.metrics && props.params.metrics.length) ? props.params.metrics : DEFAULT_METRICS

        async function load() {
            loading.value = true
            try {
                const res  = await fetch(ENDPOINT)
                const data = await res.json()
                const next = {}
                metrics().forEach(m => { next[m.path] = getPath(data, m.path) })
                values.value = next
            } catch {
                values.value = {}
            } finally {
                loading.value = false
            }
        }

        function go(m) {
            if (m.href) window.location.href = m.href
        }

        watch(() => props.params, load)
        onMounted(load)

        return { values, loading, metrics, go }
    },
    template: `
    <widget-frame title="New data within time window" icon="fa-chart-simple" :loading="loading"
                   @reload="load" @remove="$emit('remove')" @save-settings="$emit('update-params', params)">
        <div class="dw-statsrow">
            <div v-for="m in metrics()" :key="m.path" class="dw-statsrow-box"
                 :class="{ 'dw-statsrow-box--clickable': !!m.href }" @click="go(m)">
                <i :class="'fa-solid ' + m.icon + ' dw-statsrow-icon'"></i>
                <span class="dw-statsrow-label">[[ m.label ]]</span>
                <span class="dw-statsrow-value">
                    <span v-if="values[m.path] === undefined && !loading" class="text-muted">—</span>
                    <span v-else>[[ (values[m.path] ?? 0).toLocaleString() ]]</span>
                </span>
            </div>
        </div>

        <template #settings>
            <p class="text-muted small mb-0">This widget shows a fixed set of platform counters. No settings yet — remove and re-add to reset.</p>
        </template>
    </widget-frame>
    `,
}

export default StatsRowWidget
