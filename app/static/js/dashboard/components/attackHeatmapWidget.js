/**
 * AttackHeatmapWidget — the exact same rendering as /attack/heatmap's matrix
 * view: reuses the <attack-matrix> component directly (same stats bar,
 * legend, tactic columns, technique chips), same /attack/heatmap_data
 * source. Unlike the full page (which navigates away on click), this widget
 * runs AttackMatrix in its non-navigate mode so clicking a technique opens
 * its rule-chip detail panel in place, right below the grid — better suited
 * to a dashboard where you don't want to leave the page.
 *
 * params: {}
 */
import WidgetFrame  from '../widgetFrame.js'
import AttackMatrix from '/static/js/components/attack-matrix.js'

const { ref, onMounted } = Vue

const ENDPOINT = '/attack/heatmap_data'

const AttackHeatmapWidget = {
    components: { 'widget-frame': WidgetFrame, 'attack-matrix': AttackMatrix },
    props: {
        params: { type: Object, required: true },
    },
    emits: ['update-params', 'remove'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const coverage = ref(null)
        const loading  = ref(false)

        async function load() {
            loading.value = true
            try {
                const res = await fetch(ENDPOINT)
                coverage.value = await res.json()
            } catch {
                coverage.value = null
            } finally {
                loading.value = false
            }
        }

        onMounted(load)

        return { coverage, loading, load }
    },
    template: `
    <widget-frame title="ATT&amp;CK Coverage" icon="fa-crosshairs" :loading="loading"
                   @reload="load" @remove="$emit('remove')" @save-settings="$emit('update-params', params)">
        <attack-matrix :coverage="coverage" :loading="false" :navigate-on-click="false"></attack-matrix>

        <template #settings>
            <p class="text-muted small mb-0">
                Same rendering as <a href="/attack/heatmap">the full ATT&amp;CK heatmap</a> — click a technique to see its rules below. No settings yet.
            </p>
        </template>
    </widget-frame>
    `,
}

export default AttackHeatmapWidget
