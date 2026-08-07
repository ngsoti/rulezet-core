/**
 * jobWidget.js — Floating background-job status widget
 * Mounts on #job-widget in base.html.
 *
 * Polling is on-demand, not permanent: one /jobs/my_active call on page load,
 * then a 5 s loop ONLY while at least one job is pending/running/paused.
 * Once every job is terminal (or there are none) the loop stops — an idle
 * user costs a single request per page load.
 *
 * Wake-up signals that restart the loop:
 *   - window event 'rz:job-created' — dispatched by any page right after it
 *     creates a background job (fire-and-forget, no import needed):
 *         window.dispatchEvent(new Event('rz:job-created'))
 *   - tab regaining focus / becoming visible (catches jobs created elsewhere)
 *
 * Dismissed job UUIDs are stored in sessionStorage and survive page
 * navigation within the same tab, but reset on a new session.
 */

const { createApp, ref, computed, watch, onMounted, onUnmounted, nextTick } = Vue

const POLL_INTERVAL = 5000   // ms between polls
const DISMISSED_KEY = 'rz_dismissed_jobs'
const MAX_LOG_LINES = 10
const POSITION_KEY   = 'rz-job-widget-position'
const VISIBILITY_KEY = 'rz-job-widget-visibility'
const CUSTOM_POS_KEY = 'rz-job-widget-custom-pos'

function loadPosition() {
    return localStorage.getItem(POSITION_KEY) || 'bottom-right'
}
function loadAlwaysVisible() {
    return (localStorage.getItem(VISIBILITY_KEY) || 'active-only') === 'always'
}
function loadCustomPos() {
    try {
        const raw = localStorage.getItem(CUSTOM_POS_KEY)
        return raw ? JSON.parse(raw) : null
    } catch { return null }
}
function saveCustomPos(pos) {
    if (pos) localStorage.setItem(CUSTOM_POS_KEY, JSON.stringify(pos))
    else localStorage.removeItem(CUSTOM_POS_KEY)
}

function csrf() {
    return document.getElementById('csrf_token')?.value || ''
}

function postJson(url) {
    return fetch(url, {
        method: 'POST',
        headers: { 'X-CSRFToken': csrf() },
    }).then(r => r.json()).catch(() => ({}))
}

// ── Load / save dismissed UUIDs from sessionStorage ─────────────────────────
function loadDismissed() {
    try { return new Set(JSON.parse(sessionStorage.getItem(DISMISSED_KEY) || '[]')) }
    catch { return new Set() }
}
function saveDismissed(set) {
    sessionStorage.setItem(DISMISSED_KEY, JSON.stringify([...set]))
}

// ── Status helpers ────────────────────────────────────────────────────────────
const STATUS_ICON = {
    running: 'fa-solid fa-circle-notch fa-spin',
    pending: 'fa-solid fa-clock',
    paused:  'fa-solid fa-pause',
    done:    'fa-solid fa-circle-check',
    failed:  'fa-solid fa-circle-xmark',
}
const STATUS_CLASS = {
    running: 'jw-status--running',
    pending: 'jw-status--pending',
    paused:  'jw-status--paused',
    done:    'jw-status--done',
    failed:  'jw-status--failed',
}

// ── Widget component ──────────────────────────────────────────────────────────
const JobWidget = {
    delimiters: ['[[', ']]'],

    setup() {
        const jobs      = ref([])           // all active jobs from server
        const expanded  = ref(false)
        const dismissed = ref(loadDismissed())
        const position      = ref(loadPosition())
        const alwaysVisible  = ref(loadAlwaysVisible())
        const widgetEl   = ref(null)
        const customPos  = ref(loadCustomPos())
        const dragging   = ref(false)
        let dragOffset = { x: 0, y: 0 }

        // Per-job log storage  { uuid: [{...}] }
        const jobLogs   = ref({})
        const lastLogId = ref({})           // { uuid: lastId }
        const logOpen   = ref({})           // { uuid: bool } — per-job log panel

        let timer = null

        // ── Computed ────────────────────────────────────────────────────────
        const visible = computed(() =>
            jobs.value.filter(j => !dismissed.value.has(j.uuid))
        )
        const hasVisible = computed(() => visible.value.length > 0 || alwaysVisible.value)
        const isIdle = computed(() => visible.value.length === 0)
        const positionClass = computed(() => customPos.value ? 'jw-pos--custom' : `jw-pos--${position.value}`)
        const widgetStyle = computed(() => customPos.value
            ? { left: customPos.value.x + 'px', top: customPos.value.y + 'px', right: 'auto', bottom: 'auto' }
            : {})
        const runningCount = computed(() =>
            visible.value.filter(j => j.status === 'running').length
        )
        const allDone = computed(() =>
            visible.value.length > 0 && visible.value.every(j => j.status === 'done' || j.status === 'failed')
        )

        // ── Polling ─────────────────────────────────────────────────────────
        async function pollJobs() {
            try {
                const res = await fetch('/jobs/my_active')
                if (!res.ok) return
                jobs.value = await res.json()
            } catch {}
        }

        async function pollLogs() {
            if (!expanded.value) return
            for (const job of visible.value) {
                if (!logOpen.value[job.uuid]) continue
                try {
                    const since = lastLogId.value[job.uuid] || 0
                    const res = await fetch(`/jobs/logs/${job.uuid}?since_id=${since}`)
                    if (!res.ok) continue
                    const lines = await res.json()
                    if (!lines.length) continue
                    if (!jobLogs.value[job.uuid]) jobLogs.value[job.uuid] = []
                    jobLogs.value[job.uuid].push(...lines)
                    // keep last N lines
                    const arr = jobLogs.value[job.uuid]
                    if (arr.length > MAX_LOG_LINES) {
                        jobLogs.value[job.uuid] = arr.slice(-MAX_LOG_LINES)
                    }
                    lastLogId.value[job.uuid] = lines[lines.length - 1].id
                    // scroll log panel to bottom
                    await nextTick()
                    const el = document.getElementById(`jw-log-${job.uuid}`)
                    if (el) el.scrollTop = el.scrollHeight
                } catch {}
            }
        }

        async function poll() {
            await pollJobs()
            await pollLogs()
            // Stop the loop as soon as nothing can still change state
            if (!jobs.value.some(j => ['pending', 'running', 'paused'].includes(j.status))) {
                stopPolling()
            }
        }

        function startPolling() {
            if (timer) return
            timer = setInterval(poll, POLL_INTERVAL)
        }

        function stopPolling() {
            if (timer) { clearInterval(timer); timer = null }
        }

        // One poll now; keep looping only if something is active
        async function wake() {
            await poll()
            if (jobs.value.some(j => ['pending', 'running', 'paused'].includes(j.status))) {
                startPolling()
            }
        }

        function onVisible() {
            if (document.visibilityState === 'visible') wake()
        }

        // ── Toggle log panel ─────────────────────────────────────────────────
        function toggleLog(uuid) {
            logOpen.value[uuid] = !logOpen.value[uuid]
            if (logOpen.value[uuid] && !jobLogs.value[uuid]) {
                jobLogs.value[uuid] = []
                lastLogId.value[uuid] = 0
                pollLogs()
            }
        }

        // ── Dismiss ──────────────────────────────────────────────────────────
        function dismiss(uuid) {
            dismissed.value.add(uuid)
            saveDismissed(dismissed.value)
        }

        function dismissAll() {
            visible.value.forEach(j => dismissed.value.add(j.uuid))
            saveDismissed(dismissed.value)
            expanded.value = false
        }

        // ── Job controls ─────────────────────────────────────────────────────
        async function pauseJob(uuid)  { await postJson(`/jobs/pause/${uuid}`);  wake() }
        async function resumeJob(uuid) { await postJson(`/jobs/resume/${uuid}`); wake() }
        async function cancelJob(uuid) { await postJson(`/jobs/cancel/${uuid}`); wake() }

        // ── Helpers ──────────────────────────────────────────────────────────
        function progress(job) {
            if (!job.total || job.total === 0) return -1   // indeterminate
            return Math.min(100, Math.round((job.done / job.total) * 100))
        }

        function statusIcon(status) { return STATUS_ICON[status] || 'fa-solid fa-circle' }
        function statusClass(status) { return STATUS_CLASS[status] || 'jw-status--pending' }

        function logLevelClass(level) {
            if (level === 'success') return 'jw-log-line--success'
            if (level === 'warning') return 'jw-log-line--warning'
            if (level === 'error')   return 'jw-log-line--error'
            return ''
        }

        function logIcon(level) {
            if (level === 'success') return 'fa-solid fa-check'
            if (level === 'warning') return 'fa-solid fa-triangle-exclamation'
            if (level === 'error')   return 'fa-solid fa-xmark'
            return 'fa-solid fa-circle text-muted'
        }

        // ── Free-drag positioning ────────────────────────────────────────────
        function clampToViewport(x, y) {
            const el = widgetEl.value
            const w = el ? el.offsetWidth : 380
            const h = el ? el.offsetHeight : 60
            const maxX = Math.max(8, window.innerWidth - w - 8)
            const maxY = Math.max(8, window.innerHeight - h - 8)
            return { x: Math.min(Math.max(8, x), maxX), y: Math.min(Math.max(8, y), maxY) }
        }

        function dragPoint(e) {
            const t = e.touches && e.touches[0]
            return t ? { x: t.clientX, y: t.clientY } : { x: e.clientX, y: e.clientY }
        }

        function startDrag(e) {
            if (e.button !== undefined && e.button !== 0) return
            const el = widgetEl.value
            if (!el) return
            const rect = el.getBoundingClientRect()
            const p = dragPoint(e)
            dragOffset.x = p.x - rect.left
            dragOffset.y = p.y - rect.top
            dragging.value = true
            document.body.classList.add('jw-dragging')
            document.addEventListener('mousemove', onDrag)
            document.addEventListener('mouseup', endDrag)
            document.addEventListener('touchmove', onDrag, { passive: false })
            document.addEventListener('touchend', endDrag)
        }

        function onDrag(e) {
            if (!dragging.value) return
            e.preventDefault()
            const p = dragPoint(e)
            customPos.value = clampToViewport(p.x - dragOffset.x, p.y - dragOffset.y)
        }

        function endDrag() {
            if (!dragging.value) return
            dragging.value = false
            document.body.classList.remove('jw-dragging')
            document.removeEventListener('mousemove', onDrag)
            document.removeEventListener('mouseup', endDrag)
            document.removeEventListener('touchmove', onDrag)
            document.removeEventListener('touchend', endDrag)
            saveCustomPos(customPos.value)
        }

        function resetPosition() {
            customPos.value = null
            saveCustomPos(null)
        }

        // Live-updates position/visibility if changed on the settings page
        // without needing a full reload (settings.html dispatches this after
        // every change, same convention as 'rz:job-created' below).
        function onSettingsChanged() {
            position.value = loadPosition()
            alwaysVisible.value = loadAlwaysVisible()
        }

        // ── Lifecycle ────────────────────────────────────────────────────────
        onMounted(() => {
            wake()
            window.addEventListener('rz:job-created', wake)
            window.addEventListener('rz:job-widget-settings-changed', onSettingsChanged)
            document.addEventListener('visibilitychange', onVisible)
            window.addEventListener('focus', wake)
        })

        onUnmounted(() => {
            stopPolling()
            window.removeEventListener('rz:job-created', wake)
            window.removeEventListener('rz:job-widget-settings-changed', onSettingsChanged)
            document.removeEventListener('visibilitychange', onVisible)
            window.removeEventListener('focus', wake)
        })

        return {
            jobs, expanded, visible, hasVisible, isIdle, positionClass, runningCount, allDone,
            jobLogs, logOpen, toggleLog,
            dismiss, dismissAll,
            pauseJob, resumeJob, cancelJob,
            progress, statusIcon, statusClass, logLevelClass, logIcon,
            widgetEl, widgetStyle, customPos, startDrag, resetPosition,
        }
    },

    template: `
<div v-if="hasVisible" :class="positionClass" :style="widgetStyle" ref="widgetEl">

    <!-- ── Collapsed bar — idle (always-visible mode, nothing running) ── -->
    <div v-if="!expanded && isIdle" class="jw-bar jw-bar--idle" title="No background jobs running"
         @mousedown="startDrag" @touchstart="startDrag">
        <span class="jw-drag-handle" title="Drag to move"><i class="fa-solid fa-grip-vertical"></i></span>
        <i class="fa-regular fa-circle-check text-muted" style="font-size:.85rem;"></i>
        <span class="jw-bar__label">No active jobs</span>
    </div>

    <!-- ── Collapsed bar ── -->
    <div v-else-if="!expanded" class="jw-bar" @click="expanded = true" title="Show background jobs">
        <span class="jw-drag-handle" title="Drag to move" @mousedown="startDrag" @touchstart="startDrag" @click.stop>
            <i class="fa-solid fa-grip-vertical"></i>
        </span>
        <i v-if="allDone" class="fa-solid fa-circle-check" style="font-size:.85rem;color:#198754;"></i>
        <i v-else class="fa-solid fa-circle-notch fa-spin text-primary" style="font-size:.85rem;"></i>
        <span class="jw-bar__label">Background Jobs</span>
        <span class="jw-bar__count">[[ visible.length ]]</span>
        <i class="fa-solid fa-chevron-up text-muted" style="font-size:.72rem;"></i>
        <button class="jw-btn--dismiss" @click.stop="dismissAll" title="Dismiss all">
            <i class="fa-solid fa-xmark"></i>
        </button>
    </div>

    <!-- ── Expanded panel ── -->
    <div v-else class="jw-panel">

        <!-- Header -->
        <div class="jw-header">
            <span class="jw-drag-handle" title="Drag to move" @mousedown="startDrag" @touchstart="startDrag">
                <i class="fa-solid fa-grip-vertical"></i>
            </span>
            <i class="fa-solid fa-circle-notch fa-spin text-primary" style="font-size:.8rem;"></i>
            <span class="jw-header__title">Background Jobs</span>
            <button v-if="customPos" class="jw-btn me-1" @click="resetPosition" title="Reset position">
                <i class="fa-solid fa-anchor"></i>
            </button>
            <a href="/jobs/list" target="_blank" class="jw-btn me-1" title="Open jobs page" @click.stop>
                <i class="fa-solid fa-arrow-up-right-from-square"></i>
            </a>
            <button class="jw-btn" @click="expanded = false" title="Collapse">
                <i class="fa-solid fa-chevron-down"></i>
            </button>
            <button class="jw-btn--dismiss ms-1" @click="dismissAll" title="Dismiss all">
                <i class="fa-solid fa-xmark"></i>
            </button>
        </div>

        <!-- Job list -->
        <div style="max-height:480px;overflow-y:auto;">
            <div v-for="job in visible" :key="job.uuid" class="jw-job">

                <!-- Top row: name + status + dismiss -->
                <div class="jw-job__top">
                    <i :class="statusIcon(job.status)" :style="job.status==='running'?'color:#0d6efd':''"></i>
                    <span class="jw-job__name" :title="job.label">[[ job.label ]]</span>
                    <span :class="['jw-status', statusClass(job.status)]">[[ job.status ]]</span>
                    <button class="jw-btn--dismiss" @click="dismiss(job.uuid)" title="Hide this job">
                        <i class="fa-solid fa-xmark"></i>
                    </button>
                </div>

                <!-- Progress bar -->
                <div v-if="progress(job) >= 0" class="jw-progress">
                    <div class="jw-progress__fill" :style="\`width:\${progress(job)}%\`"></div>
                </div>
                <div v-else-if="job.status === 'running'" class="jw-progress">
                    <div class="jw-progress__fill" style="width:100%;animation:jw-indeterminate 1.4s ease infinite;background:linear-gradient(90deg,transparent,#0d6efd,transparent);background-size:200%"></div>
                </div>

                <!-- Progress text -->
                <div v-if="job.total > 0" style="font-size:.72rem;color:var(--subtle-text-color);">
                    [[ job.done ]] / [[ job.total ]]
                    <span v-if="progress(job) >= 0">([[ progress(job) ]]%)</span>
                </div>

                <!-- Log panel toggle -->
                <div class="jw-controls">
                    <button class="jw-btn" @click="toggleLog(job.uuid)" title="Toggle logs">
                        <i :class="logOpen[job.uuid] ? 'fa-solid fa-chevron-up' : 'fa-solid fa-terminal'"></i>
                        Logs
                    </button>
                    <button v-if="job.status === 'running'" class="jw-btn" @click="pauseJob(job.uuid)" title="Pause">
                        <i class="fa-solid fa-pause"></i>
                    </button>
                    <button v-if="job.status === 'paused'" class="jw-btn" @click="resumeJob(job.uuid)" title="Resume">
                        <i class="fa-solid fa-play"></i>
                    </button>
                    <button v-if="job.status !== 'done'" class="jw-btn jw-btn--danger" @click="cancelJob(job.uuid)" title="Cancel">
                        <i class="fa-solid fa-stop"></i>
                    </button>
                    <a :href="'/jobs/detail/' + job.uuid" class="jw-btn ms-auto" target="_blank" title="Full details">
                        <i class="fa-solid fa-arrow-up-right-from-square"></i>
                    </a>
                </div>

                <!-- Log lines -->
                <div v-if="logOpen[job.uuid]" :id="\`jw-log-\${job.uuid}\`" class="jw-logs mt-1">
                    <div v-if="!jobLogs[job.uuid] || !jobLogs[job.uuid].length"
                         class="jw-log-line" style="color:var(--subtle-text-color);">
                        <i class="fa-solid fa-circle-notch fa-spin me-1"></i>Loading logs…
                    </div>
                    <div v-for="line in jobLogs[job.uuid]" :key="line.id"
                         :class="['jw-log-line', logLevelClass(line.level)]">
                        <i :class="logIcon(line.level)" class="me-1" style="font-size:.65rem;"></i>
                        <span style="opacity:.55;margin-right:.3rem;">[[ line.created_at ? line.created_at.slice(11,19) : '' ]]</span>
                        [[ line.message ]]
                    </div>
                </div>

            </div>
        </div>
    </div>

</div>
    `
}

document.addEventListener('DOMContentLoaded', () => {
    const el = document.getElementById('job-widget')
    if (!el) return
    // Only mount if logged in (widget div is only rendered when authenticated)
    createApp(JobWidget).mount('#job-widget')
})
