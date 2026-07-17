/**
 * ActivityCalendarWidget — GitHub-style contribution calendar of platform
 * activity (ActivityLog volume only, no per-entry detail — that's what the
 * Recent Activity widget is for). A dedicated widget rather than a generic
 * Chart preset because it needs its own period switch (month/3 months/year),
 * which the one-shot generic Chart widget has no notion of.
 *
 * Reuses the shared <chart-viewer> + its 'calendar' renderer — only the
 * period control and data source (a lazy /home_charts/activity_calendar
 * endpoint, refetched per period) are specific to this widget.
 *
 * params: { period: 'month' | '3months' | 'year' }
 */
import WidgetFrame from '../widgetFrame.js'
import ChartViewer  from '/static/js/components/chart-viewer.js'

const { ref, watch, onMounted } = Vue

const ENDPOINT = '/home_charts/activity_calendar'
const PERIODS = [
    { key: 'month',   label: 'Month' },
    { key: '3months', label: '3 Months' },
    { key: 'year',    label: 'Year' },
]

const ActivityCalendarWidget = {
    components: { 'widget-frame': WidgetFrame, 'chart-viewer': ChartViewer },
    props: {
        params: { type: Object, required: true },
    },
    emits: ['update-params', 'remove'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const data    = ref({})
        const loading = ref(false)

        function period() {
            return props.params.period || 'year'
        }

        async function load() {
            loading.value = true
            try {
                const res  = await fetch(`${ENDPOINT}?period=${encodeURIComponent(period())}`)
                data.value = await res.json()
            } catch {
                data.value = {}
            } finally {
                loading.value = false
            }
        }

        function setPeriod(key) {
            if (key === period()) return
            emit('update-params', { ...props.params, period: key })
        }

        watch(() => props.params, load)
        onMounted(load)

        return { data, loading, PERIODS, period, setPeriod, load }
    },
    template: `
    <widget-frame title="Platform Activity" icon="fa-calendar-days" :loading="loading"
                   @reload="load" @remove="$emit('remove')" @save-settings="$emit('update-params', params)">
        <div class="dw-calendar">
            <div class="dw-calendar-periods">
                <button v-for="p in PERIODS" :key="p.key" type="button"
                        class="dw-calendar-period-btn" :class="{ 'dw-calendar-period-btn--active': period() === p.key }"
                        @click="setPeriod(p.key)">
                    [[ p.label ]]
                </button>
            </div>
            <div class="dw-calendar-chart">
                <chart-viewer v-if="data.calendar_data" :data="data" views="calendar" height="100%"></chart-viewer>
                <div v-else class="text-center text-muted small py-4">
                    <i class="fa-solid fa-calendar-xmark opacity-25 d-block mb-2" style="font-size:1.5rem;"></i>
                    No activity in this period.
                </div>
            </div>
        </div>

        <template #settings>
            <p class="text-muted small mb-0">Use the Month / 3 Months / Year buttons above the calendar to change the period — no other settings.</p>
        </template>
    </widget-frame>
    `,
}

export default ActivityCalendarWidget
