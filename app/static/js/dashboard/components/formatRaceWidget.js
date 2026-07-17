/**
 * FormatRaceWidget — animated "bar race" of cumulative rule count per
 * format, month by month (ECharts realtimeSort bar race pattern). Sourced
 * from /platform/insights_data's charts.format_race (pre-computed monthly
 * cumulative counts, see app/home.py).
 *
 * This doesn't fit ChartViewer's contract (one static build_option call per
 * render) — a race needs a running frame-by-frame animation loop — so it
 * drives its own ECharts instance directly, the same low-level way
 * ChartViewer itself does, just with a setInterval stepping through frames.
 *
 * params: { speed: 'slow' | 'normal' | 'fast' }
 */
import WidgetFrame from '../widgetFrame.js'
import { get_theme } from '/static/js/components/charts/chart-utils.js'

const { ref, watch, onMounted, onBeforeUnmount, nextTick } = Vue

const ENDPOINT = '/platform/insights_data'
const SPEEDS = { slow: 2200, normal: 1400, fast: 800 }

const FormatRaceWidget = {
    components: { 'widget-frame': WidgetFrame },
    props: {
        params: { type: Object, required: true },
    },
    emits: ['update-params', 'remove'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const chartEl   = ref(null)
        const loading   = ref(false)
        const editForm  = ref({ ...props.params })
        const playing   = ref(false)
        const frames    = ref([])
        const frameIdx  = ref(0)

        let chart      = null
        let timer       = null
        let waitTimer   = null
        let colorMap    = {}
        let ro          = null

        function speedMs() {
            return SPEEDS[props.params.speed] || SPEEDS.normal
        }

        function assignColors() {
            const theme = get_theme()
            const names = new Set()
            frames.value.forEach(f => f.data.forEach(d => names.add(d.name)))
            colorMap = {}
            ;[...names].sort().forEach((n, i) => { colorMap[n] = theme.palette[i % theme.palette.length] })
        }

        function seriesData(frame) {
            if (!frame) return []
            return frame.data.map(d => ({
                name: d.name, value: d.value,
                itemStyle: { color: colorMap[d.name] || '#0d6efd' },
            }))
        }

        function ensureEcharts(cb) {
            if (window.echarts) { cb(); return }
            waitTimer = setInterval(() => {
                if (window.echarts) { clearInterval(waitTimer); waitTimer = null; cb() }
            }, 60)
        }

        function initChart() {
            if (!chartEl.value || frames.value.length < 2) return
            ensureEcharts(() => {
                const theme = get_theme()
                if (chart) { chart.dispose(); chart = null }
                chart = window.echarts.init(chartEl.value, null, { renderer: 'canvas' })
                const frame = frames.value[frameIdx.value]
                chart.setOption({
                    grid: { top: 10, bottom: 10, left: 110, right: 64 },
                    xAxis: {
                        max: 'dataMax',
                        axisLabel: { color: theme.text_muted, fontSize: 11 },
                        splitLine: { lineStyle: { color: theme.border } },
                    },
                    yAxis: {
                        type: 'category', inverse: true, max: 7,
                        axisLabel: { color: theme.text_main, fontSize: 12, fontWeight: 600 },
                        animationDuration: 300, animationDurationUpdate: 300,
                    },
                    series: [{
                        realtimeSort: true,
                        type: 'bar',
                        data: seriesData(frame),
                        barMaxWidth: 24,
                        label: { show: true, position: 'right', valueAnimation: true, color: theme.text_main, fontSize: 11 },
                    }],
                    animationDuration: 0,
                    animationDurationUpdate: Math.round(speedMs() * 0.9),
                    animationEasing: 'linear',
                    animationEasingUpdate: 'linear',
                    graphic: {
                        elements: [{
                            type: 'text', right: 24, bottom: 16, z: 100,
                            style: { text: frame.month, font: 'bold 22px sans-serif', fill: theme.border },
                        }],
                    },
                })
                if (!ro && window.ResizeObserver) {
                    ro = new ResizeObserver(() => chart && chart.resize())
                    ro.observe(chartEl.value)
                }
            })
        }

        function stepFrame() {
            if (!chart || !frames.value.length) return
            frameIdx.value += 1
            const frame = frames.value[frameIdx.value]
            chart.setOption({
                series: [{ data: seriesData(frame) }],
                graphic: { elements: [{ style: { text: frame.month } }] },
            })
            if (frameIdx.value >= frames.value.length - 1) stop()
        }

        function play() {
            if (frames.value.length < 2) return
            playing.value = true
            clearInterval(timer)
            timer = setInterval(stepFrame, speedMs())
        }
        function stop() {
            playing.value = false
            clearInterval(timer)
            timer = null
        }
        function toggle() {
            if (playing.value) { stop(); return }
            if (frameIdx.value >= frames.value.length - 1) restart()
            else play()
        }
        function restart() {
            frameIdx.value = 0
            const frame = frames.value[0]
            if (chart && frame) {
                chart.setOption({
                    series: [{ data: seriesData(frame) }],
                    graphic: { elements: [{ style: { text: frame.month } }] },
                })
            }
            play()
        }

        async function load() {
            loading.value = true
            stop()
            try {
                const res  = await fetch(ENDPOINT)
                const json = await res.json()
                frames.value = (json.charts && json.charts.format_race && json.charts.format_race.frames) || []
            } catch {
                frames.value = []
            } finally {
                loading.value = false
                frameIdx.value = 0
                assignColors()
                await nextTick()
                initChart()
                if (frames.value.length > 1) play()
            }
        }

        function saveSettings() {
            emit('update-params', { ...editForm.value })
        }

        watch(() => props.params, () => { editForm.value = { ...props.params }; load() })
        onMounted(load)
        onBeforeUnmount(() => {
            stop()
            if (waitTimer) clearInterval(waitTimer)
            if (ro) ro.disconnect()
            if (chart) chart.dispose()
        })

        return { chartEl, loading, editForm, playing, frames, toggle, restart, saveSettings }
    },
    template: `
    <widget-frame title="Format Popularity Race" icon="fa-flag-checkered" :loading="loading"
                   @reload="load" @remove="$emit('remove')" @save-settings="saveSettings">
        <div v-if="!loading && frames.length < 2" class="text-center text-muted small py-4">
            <i class="fa-solid fa-flag-checkered opacity-25 d-block mb-2" style="font-size:1.5rem;"></i>
            Not enough history yet — add rules across a few months to see the race.
        </div>
        <div v-else class="dw-race">
            <button type="button" class="dw-race-toggle" @click="toggle" :title="playing ? 'Pause' : 'Play'">
                <i :class="playing ? 'fa-solid fa-pause' : 'fa-solid fa-play'"></i>
            </button>
            <div ref="chartEl" style="width:100%;height:100%;"></div>
        </div>

        <template #settings>
            <div>
                <label class="form-label small fw-bold text-muted text-uppercase mb-1">Speed</label>
                <select class="form-select form-select-sm" v-model="editForm.speed">
                    <option value="slow">Slow</option>
                    <option value="normal">Normal</option>
                    <option value="fast">Fast</option>
                </select>
            </div>
        </template>
    </widget-frame>
    `,
}

export default FormatRaceWidget
