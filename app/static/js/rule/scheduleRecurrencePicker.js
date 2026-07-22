/**
 * Rich recurrence picker for Sync Schedules — daily / weekly (any subset of
 * weekdays) / monthly (any day, or "last day") / custom cron, at any time of
 * day, with a timezone. Emits 'recurrence-change' with the explicit fields
 * GithubSyncSchedule stores (frequency, days_of_week, day_of_month, hour,
 * minute, cron_expr, timezone) — never a raw cron string unless the user
 * deliberately picks "Custom cron expression".
 */
const WEEKDAYS = [
    { value: 0, label: 'Mon' }, { value: 1, label: 'Tue' }, { value: 2, label: 'Wed' },
    { value: 3, label: 'Thu' }, { value: 4, label: 'Fri' }, { value: 5, label: 'Sat' }, { value: 6, label: 'Sun' },
];

function supportedTimezones() {
    try {
        if (typeof Intl.supportedValuesOf === 'function') return Intl.supportedValuesOf('timeZone');
    } catch (e) { /* fall through */ }
    return ['UTC', 'Europe/Paris', 'Europe/London', 'America/New_York', 'America/Los_Angeles', 'Asia/Tokyo'];
}

const ScheduleRecurrencePicker = {
    props: {
        initial: { type: Object, default: () => ({}) },
    },
    delimiters: ['[[', ']]'],
    data() {
        const i = this.initial || {};
        return {
            frequency: i.frequency || 'weekly',
            daysOfWeek: new Set(i.days_of_week && i.days_of_week.length ? i.days_of_week : [0]),
            dayOfMonth: i.day_of_month != null ? i.day_of_month : 1,
            lastDayOfMonth: i.day_of_month === -1,
            hour: i.hour != null ? i.hour : 3,
            minute: i.minute != null ? i.minute : 0,
            cronExpr: i.cron_expr || '',
            timezone: i.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
            weekdays: WEEKDAYS,
            timezones: supportedTimezones(),
        };
    },
    computed: {
        summary() {
            const time = `${String(this.hour).padStart(2, '0')}:${String(this.minute).padStart(2, '0')}`;
            if (this.frequency === 'daily') return `Every day at ${time} (${this.timezone})`;
            if (this.frequency === 'weekly') {
                const names = this.weekdays.filter(w => this.daysOfWeek.has(w.value)).map(w => w.label);
                return names.length ? `Every ${names.join(', ')} at ${time} (${this.timezone})` : 'Pick at least one weekday';
            }
            if (this.frequency === 'monthly') {
                const day = this.lastDayOfMonth ? 'the last day' : `day ${this.dayOfMonth}`;
                return `Every month on ${day} at ${time} (${this.timezone})`;
            }
            return this.cronExpr ? `Custom: ${this.cronExpr} (${this.timezone})` : 'Enter a cron expression';
        },
    },
    watch: {
        frequency() { this.emitChange(); },
        dayOfMonth() { this.emitChange(); },
        lastDayOfMonth() { this.emitChange(); },
        hour() { this.emitChange(); },
        minute() { this.emitChange(); },
        cronExpr() { this.emitChange(); },
        timezone() { this.emitChange(); },
    },
    mounted() {
        this.emitChange();
    },
    methods: {
        toggleWeekday(value) {
            if (this.daysOfWeek.has(value)) this.daysOfWeek.delete(value);
            else this.daysOfWeek.add(value);
            this.emitChange();
        },
        emitChange() {
            this.$emit('recurrence-change', {
                frequency: this.frequency,
                days_of_week: this.frequency === 'weekly' ? Array.from(this.daysOfWeek).sort() : [],
                day_of_month: this.frequency === 'monthly' ? (this.lastDayOfMonth ? -1 : this.dayOfMonth) : null,
                hour: this.hour,
                minute: this.minute,
                cron_expr: this.frequency === 'cron' ? this.cronExpr : null,
                timezone: this.timezone,
            });
        },
    },
    template: `
    <div class="schedule-recurrence-picker">
        <div class="rl-fp-row">
            <div class="rl-fp-item">
                <label class="form-label mb-1" style="font-size:.78rem;">Frequency</label>
                <select class="rl-fp-select" v-model="frequency">
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                    <option value="monthly">Monthly</option>
                    <option value="cron">Custom cron expression</option>
                </select>
            </div>

            <div class="rl-fp-item">
                <label class="form-label mb-1" style="font-size:.78rem;">Time</label>
                <div class="d-flex gap-2 align-items-center">
                    <select class="rl-fp-select" v-model.number="hour" style="width:80px;">
                        <option v-for="h in 24" :key="h" :value="h - 1">[[ String(h - 1).padStart(2, '0') ]]</option>
                    </select>
                    <span>:</span>
                    <select class="rl-fp-select" v-model.number="minute" style="width:80px;">
                        <option v-for="m in [0, 15, 30, 45]" :key="m" :value="m">[[ String(m).padStart(2, '0') ]]</option>
                    </select>
                </div>
            </div>

            <div class="rl-fp-item">
                <label class="form-label mb-1" style="font-size:.78rem;">Timezone</label>
                <select class="rl-fp-select" v-model="timezone">
                    <option v-for="tz in timezones" :key="tz" :value="tz">[[ tz ]]</option>
                </select>
            </div>
        </div>

        <div v-if="frequency === 'weekly'" class="rl-fp-row mt-2">
            <div class="rl-fp-item">
                <label class="form-label mb-1 d-block" style="font-size:.78rem;">On these days</label>
                <div class="d-flex gap-1">
                    <button v-for="wd in weekdays" :key="wd.value" type="button"
                        class="btn btn-sm rounded-pill px-3"
                        :class="daysOfWeek.has(wd.value) ? 'btn-primary' : 'btn-outline-secondary'"
                        @click="toggleWeekday(wd.value)">
                        [[ wd.label ]]
                    </button>
                </div>
            </div>
        </div>

        <div v-if="frequency === 'monthly'" class="rl-fp-row mt-2">
            <div class="rl-fp-item">
                <label class="form-label mb-1" style="font-size:.78rem;">Day of month</label>
                <div class="d-flex gap-2 align-items-center">
                    <select class="rl-fp-select" v-model.number="dayOfMonth" :disabled="lastDayOfMonth" style="width:90px;">
                        <option v-for="d in 31" :key="d" :value="d">[[ d ]]</option>
                    </select>
                    <div class="form-check mb-0">
                        <input class="form-check-input" type="checkbox" id="lastDayOfMonth" v-model="lastDayOfMonth">
                        <label class="form-check-label" for="lastDayOfMonth" style="font-size:.82rem;">Last day of the month</label>
                    </div>
                </div>
            </div>
        </div>

        <div v-if="frequency === 'cron'" class="rl-fp-row mt-2">
            <div class="rl-fp-item" style="flex:1 1 100%;">
                <label class="form-label mb-1" style="font-size:.78rem;">Cron expression (minute hour day month day_of_week)<span class="required-marker">*</span></label>
                <input class="rl-fp-select" style="width:100%;font-family:monospace;" type="text"
                    placeholder="0 3 * * 1" v-model="cronExpr">
            </div>
        </div>

        <div class="mt-2 text-muted" style="font-size:.82rem;">
            <i class="fa-solid fa-clock me-1"></i>[[ summary ]]
        </div>
    </div>
    `,
};

export default ScheduleRecurrencePicker;
